# qodercli2api

将 **qodercli 的模型推理能力**中转为标准 API 的本地代理服务。

基于对用户自行合法安装的 Qoder CLI v1.1.5 所做的互操作性分析（见[逆向工程](#6-逆向工程)），
用 Go 实现并内嵌 Qoder CLI 的认证 WASM，对外提供三种兼容端点：

| 端点 | 协议 | 适用客户端 |
|---|---|---|
| `POST /v1/messages` | Anthropic Messages（SSE/非流式） | Claude Code |
| `POST /v1/chat/completions` | OpenAI Chat（SSE/非流式） | 任意 OpenAI 客户端 |
| `POST /v1/responses` | OpenAI Responses（SSE/非流式） | Codex CLI |

特性：sk 鉴权 · 15 个上游模型可切换（含 1M 上下文）· thinking/effort 映射 ·
工具调用双向转换 · token 自动刷新 · 内嵌设备流登录。

> 非官方项目，与 Qoder 或 Alibaba 无隶属、背书或赞助关系。仅使用你自己的合法订阅，并遵守适用的服务条款和法律。第三方 WASM 的许可说明见 [NOTICE](NOTICE)。

## 目录

1. [快速开始](#1-快速开始)
2. [客户端接入](#2-客户端接入)
3. [配置参考](#3-配置参考)
4. [模型与上下文窗口](#4-模型与上下文窗口)
5. [架构与协议转换](#5-架构与协议转换)
6. [逆向工程](#6-逆向工程)
7. [验证记录](#7-验证记录)
8. [项目结构](#8-项目结构)
9. [安全与注意事项](#9-安全与注意事项)
10. [许可证](#10-许可证)

---

## 1. 快速开始

```bash
# 构建（认证 WASM 已 go:embed；第三方许可见 NOTICE）
cd qodercli2api && go build -o qodercli2api .

# 登录（二选一）
# ① 本机已登录过 qodercli —— 无需任何操作，自动复用 ~/.qoder/.auth
# ② 设备流登录（浏览器授权）
./qodercli2api -login

# 仅监听本机并启用客户端鉴权
QODER2API_SK=sk-your-secret ./qodercli2api -addr 127.0.0.1:8377
```

验证：

```bash
curl http://127.0.0.1:8377/health        # {"ok":true,"authenticated":true}
curl -X POST http://127.0.0.1:8377/v1/chat/completions \
  -H "content-type: application/json" -H "Authorization: Bearer sk-your-secret" \
  -d '{"model":"auto","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}'
```

---

## 2. 客户端接入

### 2.1 Claude Code（Anthropic 端点）

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8377
export ANTHROPIC_AUTH_TOKEN=sk-your-secret
export ANTHROPIC_MODEL=auto        # 或 kmodel_latest / ultimate / ...
claude -p "hello"
```

- `~/.claude/settings.json` 里的 `env` 可能覆盖 shell 变量，可用
  `claude --settings <独立文件>` 隔离（参考脱敏示例 `examples/claude-settings.json`）
- `/model` 可切任意 qoder 模型 key；`/effort` 经 `thinking.budget_tokens` 映射为上游 `reasoning_effort`

### 2.2 Codex CLI（Responses 端点）

> codex-cli ≥0.145 仅支持 `wire_api = "responses"`（chat 已移除）。完整示例见 `examples/codex-config.toml`。

```toml
# ~/.codex/config.toml
model = "auto"
model_provider = "q2a"

[model_providers.q2a]
name = "qoder2api"
base_url = "http://127.0.0.1:8377/v1"
wire_api = "responses"
env_key = "Q2A_API_KEY"
```

```bash
Q2A_API_KEY=sk-your-secret codex exec "say hi"
codex exec -m kmodel_latest "..."     # 切换模型
```

**项目级配置**（已实测）：codex 读取 `<项目根>/.codex/config.toml`，但有**信任门槛**——
未信任项目的配置被静默忽略。需在**用户配置**中声明信任（项目配置里写 `trust_level` 无效）：

```toml
# ~/.codex/config.toml
[projects."/abs/path/to/project"]
trust_level = "trusted"
```

```toml
# <项目根>/.codex/config.toml —— 本项目专用设置
model = "kmodel_latest"
model_provider = "q2a"
[model_providers.q2a]
name = "qoder2api"
base_url = "http://127.0.0.1:8377/v1"
wire_api = "responses"
env_key = "Q2A_API_KEY"
```

层级：`session(-c) > project（cwd 到 repo root 可有多层，深优先） > user > system`。

### 2.3 任意客户端（curl 参考）

```bash
# Anthropic 流式
curl -N -X POST http://127.0.0.1:8377/v1/messages \
  -H "content-type: application/json" -H "x-api-key: sk-your-secret" \
  -d '{"model":"auto","max_tokens":256,"stream":true,"messages":[{"role":"user","content":"hi"}]}'

# Anthropic thinking/effort
... -d '{"model":"auto","max_tokens":2048,"thinking":{"type":"enabled","budget_tokens":8192},"messages":[...]}'

# OpenAI Chat 流式（上游 chunk 直通 + [DONE]）
curl -N -X POST http://127.0.0.1:8377/v1/chat/completions \
  -H "content-type: application/json" -H "Authorization: Bearer sk-your-secret" \
  -d '{"model":"auto","stream":true,"messages":[{"role":"user","content":"hi"}]}'

# OpenAI Responses 流式
curl -N -X POST http://127.0.0.1:8377/v1/responses \
  -H "content-type: application/json" -H "Authorization: Bearer sk-your-secret" \
  -d '{"model":"auto","stream":true,"input":"hi","reasoning":{"effort":"medium"}}'
```

鉴权：客户端需带 `x-api-key: <sk>` 或 `Authorization: Bearer <sk>`，缺失/错误返回 401。

---

## 3. 配置参考

### 3.1 启动参数（flag / 环境变量）

| flag | 环境变量 | 默认 | 说明 |
|---|---|---|---|
| `-addr` | `QODER2API_ADDR` | `:8377` | 监听地址；默认绑定所有接口，公开部署时务必设置强 `-sk`，本机使用建议 `127.0.0.1:8377` |
| `-sk` | `QODER2API_SK` | 空 | **客户端 sk 密钥**；为空关闭鉴权（打印警告） |
| `-auth-dir` | `QODER2API_AUTH_DIR` | `~/.qoder/.auth` | 凭证目录 |
| `-endpoint` | `QODER2API_INFER_ENDPOINT` | `https://api2.qoder.sh` | 推理端点 |
| `-openapi-endpoint` | `QODER2API_OPENAPI_ENDPOINT` | `https://openapi.qoder.sh` | OpenAPI 端点 |
| `-web-endpoint` | `QODER2API_WEB_ENDPOINT` | `https://qoder.com` | 设备流授权页端点 |
| `-model-map` | `QODER2API_MODEL_MAP` | 空 | JSON 映射 `{"claude-sonnet-4-5":"auto","*":"auto"}` |
| `-default-model` | `QODER2API_DEFAULT_MODEL` | `auto` | 兜底模型 key |
| `-model-1m` | `QODER2API_MODEL_1M` | `ultimate` | `[1m]` 后缀请求的 1M 模型 key |
| `-catalog` | `QODER2API_CATALOG` | 自动 | 模型目录 JSON（默认自动解密 CLI 缓存） |
| `-login` | — | — | 设备流登录后退出 |
| `-login-pat` | — | — | PAT 登录后退出；参数可能进入 shell history/进程列表，优先使用设备流登录 |
| `-dump-dir` | `QODER2API_DUMP_DIR` | 空 | 将失败请求明文写入 owner-only 文件，仅限本机调试，可能包含提示词和工具数据 |
| `-v` | `QODER2API_LOG=debug` | off | 详细日志；可能包含上游错误详情，仅限受控环境 |

### 3.2 端点

| 端点 | 说明 |
|---|---|
| `POST /v1/messages` | Anthropic Messages（SSE/非流式） |
| `POST /v1/messages/count_tokens` | 粗估 token（Claude Code 压缩上下文用） |
| `POST /v1/chat/completions` | OpenAI Chat（SSE/非流式/工具调用/`reasoning_effort`） |
| `POST /v1/responses` | OpenAI Responses（SSE/非流式，Codex 适用） |
| `GET /v1/models` | 模型列表；`id` 为友好模型名，`qoder_key` 为内部 Qoder key。 |
| `GET /health` | 健康检查 |

`/v1/models` 返回的友好 `id`（例如 `Qwen3.8-Max`）可直接用于三个推理 API；旧内部 key（如 `qmodel_38max`）继续兼容。显示名为空、重名、与内部 key 冲突或以保留后缀 `[1m]` 结尾时，`id` 安全回退为内部 key。`name`/`display_name` 用于展示，`qoder_key` 保留内部键。

### 3.3 systemd 部署

仓库不提交本机 service 或环境文件。部署时请自行创建 owner-only 的环境文件（至少设置强随机 `QODER2API_SK`），并让 user service 仅监听所需网络接口。凭据、环境文件和运行日志均已从版本控制排除。

---

## 4. 模型与上下文窗口

### 4.1 可选模型

| key | 名称 | 推理 | 视觉 | 上下文 |
|---|---|---|---|---|
| `auto` | Auto（默认） | - | ✓ | 180k |
| `ultimate` | Ultimate | ✓ | ✓ | **1M** |
| `performance` | Performance | - | ✓ | **1M** |
| `efficient` | Efficient | - | ✓ | 180k |
| `lite` | Lite | - | ✗ | 180k |
| `cmodel` | Cantus | ✓ | ✓ | **1M** |
| `qmodel_38max` | Qwen3.8-Max | ✓ | ✓ | **1M** |
| `qmodel_latest` | Qwen3.7-Max | - | ✓ | **1M** |
| `qmodel` | Qwen3.7-Plus | - | ✓ | **1M** |
| `kmodel_latest` | Kimi-K3 | - | ✓ | **1M** |
| `kmodel` | Kimi-K2.7-Code | - | ✓ | 256k |
| `gmodel` | GLM-5.3 | ✓ | ✓ | **1M** |
| `gm51model` | GLM-5.2 | ✓ | ✓ | **1M** |
| `dmodel` | DeepSeek-V4-Pro | ✓ | ✓ | **1M** |
| `dfmodel` | DeepSeek-V4-Flash | ✓ | ✓ | **1M** |
| `mmodel` | MiniMax-M3 | - | ✓ | **1M** |

模型选择流程：先识别并移除 `[1m]` 后缀；基础模型按 `-model-map` 精确匹配 > `-model-map["*"]` > 内部 Qoder key 或唯一友好名称 > `-default-model` 兜底选择。若请求带 `[1m]` 且基础模型不足 1M，再尝试升级到 `-model-1m` 指定的 1M 模型。

### 4.2 effort / thinking

| 客户端参数 | 上游 |
|---|---|
| Anthropic `thinking.budget_tokens` | 按官方 CHL 映射为 `reasoning_effort`：`≤0→none, ≤1024→low, ≤8192→medium, ≤24576→high, ≤49152→xhigh, >49152→max` |
| OpenAI `reasoning_effort` | 直接透传（`minimal→low`） |
| Responses `reasoning.effort` | 直接透传 |

上游的思考增量（`reasoning_content`）→ Anthropic `thinking` block / Responses `reasoning` item /
Chat 非流式按 deepseek 风格 `reasoning_content` 字段返回。

### 4.3 使用 1M 上下文

需要**客户端与代理两侧配合**：

**代理侧（已实现）**
- 模型名带 `[1m]` 后缀（如 `auto[1m]`）→ 自动路由到 1M 模型（默认 `ultimate`，`-model-1m` 可换）；
  已选 1M 模型（如 `ultimate[1m]`）则原样使用
- 自动将所选模型的 `max_input_tokens` 作为 `parameters.context_length` 告知上游

**Claude Code 侧**：`ANTHROPIC_MODEL=auto[1m]`（`[1m]` 后缀即其 1M 窗口约定）

**Codex 侧**（config.toml，已实测）：

```toml
model = "ultimate"
model_context_window = 1000000
model_auto_compact_token_limit = 900000   # 可选，自动压缩阈值
```

---

## 5. 架构与协议转换

```
Claude Code / Codex / 任意客户端
        │  Anthropic / OpenAI Chat / OpenAI Responses
        ▼
   qodercli2api
        ├── sk 鉴权中间件
        ├── 客户端请求 → RemoteChatAsk 转换
        ├── wazero 内嵌官方 WASM：prepareInferRequest（URL / 22 个签名头 / 加密 body）
        ├── token 自动刷新（提前 1h + 401 重试 + 30min 定时）
        └── 上游 SSE 信封解析 → 客户端协议事件序列
        ▼
   https://api2.qoder.sh（生产推理端点）
```

### 5.1 请求转换

| 客户端 | 上游（RemoteChatAsk） |
|---|---|
| `model` | `model_config.key`（映射/[1m]/兜底，见 §4.1） |
| `system` / `instructions` | 顶层 `system` 字符串 |
| 文本/图片消息 | OpenAI 消息（image→`image_url` data:URL） |
| `tool_use` / `function_call` | `tool_calls[{id,type:function,function:{name,arguments}}]` |
| `tool_result` / `function_call_output` | `role:"tool"` + `tool_call_id` |
| `tools` | OpenAI function 格式（`input_schema`→`parameters`） |
| thinking / effort | `parameters.reasoning_effort`（见 §4.2） |
| `tool_choice` | `parameters.tool_choice`（auto/any→required/none/tool） |
| `max_tokens` 等 | `parameters.{max_tokens,context_length,temperature,top_p,stop}` |

### 5.2 响应转换

| 上游 chunk | Anthropic | OpenAI Chat | OpenAI Responses |
|---|---|---|---|
| `delta.reasoning_content` | `thinking` block | （直通） | `reasoning` item + summary delta |
| `delta.content` | `text` block + `text_delta` | （直通） | `message` item + `output_text.delta` |
| `delta.tool_calls` | `tool_use` block | （直通） | `function_call` item + args delta |
| `finish_reason`+`usage` | `message_delta`+`message_stop` | 末帧+`[DONE]` | `response.completed`（含 usage） |
| 信封 statusCodeValue≠200 | `error` 事件 | error data+`[DONE]` | `response.failed` |

stop 映射：`stop→end_turn, tool_calls→tool_use, length→max_tokens, content_filter→refusal`。

### 5.3 设计决策

1. **必须内嵌 WASM**：请求体加密与 COSY 签名无法离线重写，wazero 复用官方逻辑，行为与官方天然一致
2. **凭证复用**：直接读写 `~/.qoder/.auth/user`（与 qodercli 兼容的加密格式），也支持独立设备流登录
3. **request_id 每次新 UUID**（服务器防重放，重复返回 103）
4. **单 WASM 上下文 + 互斥锁**：wasm-bindgen 模块非线程安全；打包仅数毫秒，无瓶颈
5. **usage 捕获**：部分模型的 usage 帧在 finish_reason 之后才到，延迟到 `event:finish` 再发最终事件

---

## 6. 逆向工程

> 完整细节：`docs/oauth.md`、`docs/inference-protocol.md`。此处为摘要。

### 6.1 总体结论

| 问题 | 答案 |
|---|---|
| OAuth 机制 | **自定义设备授权流**：浏览器开 `qoder.com/device/selectAccounts`（PKCE 风格 challenge），每秒轮询 `openapi.qoder.sh/api/v1/deviceToken/poll` 换 device token；凭证 WASM 加密存于 `~/.qoder/.auth/user` |
| 推理调用 | `POST api2.qoder.sh/algo/api/v2/service/pro/sse/agent_chat_generation`，22 个 `Cosy-*` 头 + `Bearer COSY.<base64>.<签名>`，请求体 WASM 加密；响应明文 SSE（信封包裹 OpenAI chunk） |
| 加密/签名 | 内嵌 Rust→WASM 模块 `qoder_auth_wasm_bg.wasm`（297KB），不可绕过，本项目用 wazero 复用 |

### 6.2 二进制分析

Qoder CLI v1.1.5 是 Bun 打包的 Node.js 单文件可执行程序。互操作性分析识别出内嵌 JS bundle、认证 WASM、原生 addon 和 tree-sitter 模块。

本仓库不分发 Qoder CLI、完整 JS bundle、原生 addon或 tree-sitter 提取物；只保留代理运行所需的认证 WASM，并在 `NOTICE` 中单独说明其第三方归属和许可边界。

### 6.3 OAuth 要点

- **设备流**：`verifier(43~128随机字符)` + `challenge=base64url(sha256(verifier))` + `nonce=uuid`；
  使用生产公开客户端标识，轮询 404 继续、5 分钟超时
- **PAT**：`POST /api/v1/jobToken/exchange {"personal_token":...}`
- **刷新**：`expire_time-3600<now` 即刷新；`POST /api/v1/deviceToken/refresh {"refresh_token":...}`；
  refresh token 有效期约 4 个月
- **存储**：`~/.qoder/.auth/user`（0600），WASM `credential_storage_encrypt`，key = `machine_id` 前 16 字符
- **端点**：默认生产推理端点为 `api2.qoder.sh`；代码允许运维方通过启动参数覆盖

### 6.4 推理协议要点

- **认证头**：`Authorization: Bearer COSY.{base64({version,requestId,info,cosyVersion,ideVersion})}.{签名}`，
  其中 `info` 即 `encrypt_user_info`；**设备 token 不上链**，服务器靠 `info`+`Cosy-Key` 认证
- **请求体**（RemoteChatAsk）：`request_id`（唯一，重复 403）、`session_id`、`model_config`、
  `system`、`messages`、`tools`、`parameters{max_tokens,reasoning_effort,...}`，整体 WASM 加密
- **响应**：SSE 信封 `{"headers","body","statusCodeValue"}`，`body` 为字符串化 OpenAI chunk
  （`content`/`reasoning_content`/流式 `tool_calls`/`finish_reason`/`usage`），
  `event:finish`（含首 token/总时长）收尾，**无 `[DONE]`**；错误帧 statusCodeValue≠200

### 6.5 qoder_auth_wasm 与分析方法

WASM 导出（wasm-bindgen ABI）：`qodercontext_new` / `qodercontext_prepareInferRequest`（推理打包）/
`prepareRequest`（通用打包）/ `credential_storage_encrypt|decrypt`（凭证）/
`generate_runtime_auth_fields`（运行时签名字段）/ `model_cache_decrypt`（目录）/ `decrypt_server_response`。

**分析方法（本项目原创）**：Python + wasmtime 手写 wasm-bindgen host glue
（堆、free-list、WASM 内存视图和随机数导入等），用于本地、经授权的互操作性分析。公开工具见 `tools/wasm_harness.py`；它只在用户显式提供输入时执行敏感操作。Go 侧在 `wasm.go` 用 wazero 实现同等 glue。

---

## 7. 验证记录

| 测试 | 结果 |
|---|---|
| WASM harness 加载与 ABI 调用 | ✅ 认证、签名和目录相关导出可调用 |
| 使用自有授权账号的端到端互操作验证 | ✅ SSE 流（text/reasoning/tool_calls/usage/event:finish）；仓库不包含凭据、请求或响应抓包 |
| 相同 request_id 重放 | ✅ 403 `{"code":"103","message":"Duplicate request"}` |
| Anthropic 非流式 / 流式事件序列 | ✅ thinking+text blocks、message_start→…→message_stop、usage 正确 |
| 无 sk / 错 sk | ✅ 401 authentication_error |
| 工具调用（非流式+流式+多轮回传） | ✅ tool_use blocks、stop_reason=tool_use |
| thinking budget → reasoning_effort | ✅ 上游返回 reasoning_content 并转为 thinking block |
| Claude Code 对话 / Bash 工具回合 / 模型切换 | ✅ `PROXY_OK` / 正确执行 / 自述 Kimi |
| Chat 非流式/流式/工具调用 | ✅ OpenAI 格式 + usage + [DONE] |
| Responses 流式事件序列 | ✅ created→item.added→delta→done→completed 完整 |
| Codex exec 对话 / shell 工具回合 / 模型切换 | ✅ `CODEX_RESP_OK` / 正确执行 / 自述 Kimi |
| `[1m]` 后缀路由（auto[1m]、ultimate[1m]） | ✅ 正常返回 |
| Codex 1M 配置（model_context_window=1000000） | ✅ `CTX1M_OK` |
| Codex 项目级配置 + 信任门槛 | ✅ 未信任被忽略；用户配置声明信任后生效 |

---

## 8. 项目结构

```
qodercli2api/
├── main.go                     # 入口/flags/启动/目录加载/PAT登录
├── wasm.go                     # wazero host glue + QoderContext API
├── auth.go                     # 凭证读写/刷新/设备流登录
├── convert.go                  # Anthropic ↔ RemoteChatAsk 类型转换
├── proxy.go                    # Anthropic handlers + SSE 解析 + 模型解析
├── openai.go                   # /v1/chat/completions
├── responses.go                # /v1/responses
├── assets/
│   └── qoder_auth_wasm_bg.wasm # 第三方认证 WASM；许可边界见 NOTICE
├── docs/
│   ├── oauth.md
│   └── inference-protocol.md
├── examples/
│   ├── claude-settings.json
│   └── codex-config.toml
├── tools/
│   ├── wasm_harness.py
│   └── requirements.txt
├── LICENSE                     # AGPL-3.0（项目原创代码/文档）
├── NOTICE                      # 第三方组件和商标说明
└── README.md
```

---

## 9. 安全与注意事项

1. **凭证安全**：真实 token、API key、环境文件、模型目录、抓包和调试 dump 均不得提交；相关本机路径已由 `.gitignore` 排除。
2. **监听与鉴权**：程序默认监听 `:8377`；本机使用请显式设置 `-addr 127.0.0.1:8377`。任何非 loopback 部署都必须设置强随机 `QODER2API_SK`。
3. **日志与 dump**：详细日志和 `-dump-dir` 可能包含上游错误、提示词或工具数据，只能写入受控、owner-only 的本机目录。
4. **PAT**：`-login-pat` 的值可能进入 shell history 或进程列表；优先使用设备流登录，并避免在共享主机上传递命令行 secret。
5. **SSRF 面**：`-endpoint` 等覆盖项属于运维配置，不得暴露给不可信输入。
6. **request_id 唯一性**：服务器拒绝重复（103），代理已保证每次生成新 UUID。
7. **token 生命周期**：代理可能自动刷新并回写 `~/.qoder/.auth/user`；运行前确认该目录权限和备份策略。
8. **合规**：仅使用自己的合法账号和订阅，遵守 Qoder 服务条款及适用法律；本项目不提供绕过授权、共享凭据或转售额度的许可。

---

## 10. 许可证

除 `NOTICE` 中单独列出的第三方 WASM 外，本项目采用 [GNU Affero General Public License v3.0](LICENSE)。通过网络向用户提供修改版服务时，AGPL-3.0 要求向这些用户提供对应源码。
