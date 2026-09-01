# qodercli2api

将 **qodercli 的模型推理能力**中转为标准 API 的本地代理服务。

当前互操作基线固定为 **Qoder CLI v1.1.34** 的全合成 frozen fixtures。Production 是 **pure Go native-only**：仓库和生产二进制不包含认证 WASM，root module 不依赖 wazero。经授权的运维方仍可使用外部 oracle（297,238 bytes，SHA-256 `b3ddd7c9235cea51a965582506fa6281bb298ddab782ff3edb3f9015da2468d4`）离线复核兼容性。项目对外提供三种兼容端点：

| 端点 | 协议 | 适用客户端 |
|---|---|---|
| `POST /v1/messages` | Anthropic Messages（SSE/非流式） | Claude Code |
| `POST /v1/chat/completions` | OpenAI Chat（SSE/非流式） | 任意 OpenAI 客户端 |
| `POST /v1/responses` | OpenAI Responses（SSE/非流式） | Codex CLI |

特性：sk 鉴权 · 16 个上游模型可切换（含 1M 上下文）· thinking/effort 映射 ·
工具调用双向转换 · token 自动刷新 · 内嵌设备流登录。

> 非官方项目，与 Qoder 或 Alibaba 无隶属、背书或赞助关系。仅使用你自己的合法订阅，并遵守适用的服务条款和法律。外部 oracle 的授权与商标边界见 [NOTICE](NOTICE)。

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
# 构建（pure Go；无 embedded WASM / root wazero dependency）
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

Production 始终构造 strict native services，不需要也不接受 protocol backend mode 配置。旧的 `-protocol-mode`、`-shadow-capabilities`、`QODER2API_PROTOCOL_MODE` 和 `QODER2API_SHADOW_CAPABILITIES` 已移除；对应 flags 会作为 unknown flag 拒绝，旧环境变量不会被读取。没有运行时 WASM rollback、shadow comparison 或 fallback 路径。

验证证据与授权 E2E 命令见 [§7.1](#71-native-only-验证)。

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
   server                         catalog loading
      │                                 │
      │ 依赖 authManager                │ 依赖 modelCacheDecryptor
      │                                 │
      └──────────────┬──────────────────┘
                     │ 语义接口
                     ▼
   authManager（唯一 active protocolContext owner）
        │  创建、原子替换、关闭 native context；刷新凭证时重建
        ▼
   protocolServices（native-only capabilities）
        ├── nativeCredentialCodec
        ├── nativeRuntimeFieldGenerator
        ├── nativeModelCacheDecryptor
        └── nativeContextFactory → nativeProtocolContext.PrepareInferRequest
```

应用层统一拥有 `protocolServices` 生命周期，并在停止接收请求、等待在途 handler 与刷新任务结束后，依次关闭 auth context 和 services。时钟与安全熵通过 host dependency 注入；生产使用 wall clock/`crypto/rand`。deterministic transcript record/replay 仅存在于 `_test.go`，不会进入生产 binary。`testdata/protocol/1.1.34/` 保存全合成、带 manifest hash 的 credential/runtime/model-cache/infer fixtures，作为普通测试的 byte-exact 兼容基线。

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

1. **语义边界先行**：server 依赖 `authManager`，catalog loading 依赖 `modelCacheDecryptor`；`authManager` 是唯一 active `protocolContext` owner，`protocolServices` 聚合四个 native capabilities
2. **production native-only**：credential、runtime auth、model cache、body codec 与完整 COSY request preparation 均由 pure Go 实现；没有 embedded WASM、wazero、mode selector、shadow 或 fallback runtime
3. **确定性 host 与生命周期**：clock/entropy 可注入；context 深拷贝 immutable state、并发 prepare、幂等关闭并等待在途调用。record/replay 仅用于测试和 external-oracle 证据
4. **frozen compatibility baseline**：普通 root tests 只读取 synthetic v1.1.34 fixtures；可选 external oracle 独立位于 `tools/wasm_oracle`，需要 operator-supplied authorized WASM
5. **协议事实**：body 是确定性的自定义 Base64 字母表替换加 outer-third swap，不是加密；COSY 签名是 canonical 输入的 MD5；响应是明文 SSE
6. **request_id 每次新 UUID**（服务器防重放，重复返回 103）；usage 可能晚于 finish_reason，因此延迟到 `event:finish` 再发最终事件

---

## 6. 逆向工程

> 完整细节：`docs/oauth.md`、`docs/inference-protocol.md`。此处为摘要。

### 6.1 总体结论

| 问题 | 答案 |
|---|---|
| OAuth 机制 | **自定义设备授权流**：浏览器开 `qoder.com/device/selectAccounts`（PKCE 风格 challenge），每秒轮询 `openapi.qoder.sh/api/v1/deviceToken/poll` 换 device token；凭证以 AES-128-CBC 兼容格式存于 `~/.qoder/.auth/user`，由 native credential service 处理 |
| 推理调用 | `POST api2.qoder.sh/algo/api/v2/service/pro/sse/agent_chat_generation`，最多 22 个条件请求头（presence matrix 见 [推理协议文档](docs/inference-protocol.md)）+ `Bearer COSY.<base64>.<签名>`；请求体为确定性 custom-Base64/third-swap 编码，响应为明文 SSE（信封包裹 OpenAI chunk） |
| 编码/签名 | body codec 与 canonical MD5 签名由 byte-exact pure-Go implementation 执行；production 没有其他 backend mode |

### 6.2 二进制分析

最初的历史分析对象是 Qoder CLI v1.1.5：它是 Bun 打包的 Node.js 单文件可执行程序，分析识别出内嵌 JS bundle、认证 WASM、原生 addon 和 tree-sitter 模块。当前兼容性与 fixtures 已重新固定到 v1.1.34 WASM oracle（297,238 bytes；上述 SHA-256），不要把 1.1.5 的历史观察当作当前版本标识。

本仓库不分发 Qoder CLI、认证 WASM、完整 JS bundle、原生 addon 或 tree-sitter 提取物。可选分析工具只读取运维方自行提供且有权执行的外部 oracle；授权和商标边界见 `NOTICE`。

### 6.3 OAuth 要点

- **设备流**：`verifier(43~128随机字符)` + `challenge=base64url(sha256(verifier))` + `nonce=uuid`；
  使用生产公开客户端标识，轮询 404 继续、5 分钟超时
- **PAT**：`POST /api/v1/jobToken/exchange {"personal_token":...}`
- **刷新**：`expire_time-3600<now` 即刷新；`POST /api/v1/deviceToken/refresh {"refresh_token":...}`；
  refresh token 有效期约 4 个月
- **存储**：`~/.qoder/.auth/user`（0600 原子替换）；AES-128-CBC，raw 16-byte UTF-8 key=`machine_id` 前 16 字符，IV=key，PKCS#7 + strict standard padded Base64；production native codec 与 frozen fixtures byte-exact
- **端点**：默认生产推理端点为 `api2.qoder.sh`；代码允许运维方通过启动参数覆盖

### 6.4 推理协议要点

- **认证头**：`Authorization: Bearer COSY.{base64({version,requestId,info,cosyVersion,ideVersion})}.{签名}`，
  其中 `info` 即 `encrypt_user_info`；**设备 token 不上链**，服务器靠 `info`+`Cosy-Key` 认证
- **请求体**（RemoteChatAsk）：`request_id`（唯一，重复 403）、`session_id`、`model_config`、
  `system`、`messages`、`tools`、`parameters{max_tokens,reasoning_effort,...}`；raw JSON 经确定性 custom Base64 + outer-third swap 编码，字段顺序/空白敏感
- **响应**：SSE 信封 `{"headers","body","statusCodeValue"}`，`body` 通常为字符串化 OpenAI chunk
  （`content`/`reasoning_content`/流式 `tool_calls`/`finish_reason`/`usage`）；有效 200 信封的 `body` 也可能是精确 `[DONE]`，
  该标记被忽略且不表示上游完成，仍由后续 `event:finish`（含首 token/总时长）权威收尾。不同下游协议的终止帧由代理分别生成；错误帧 statusCodeValue≠200

### 6.5 qoder_auth_wasm 与分析方法

WASM 导出（wasm-bindgen ABI）：`qodercontext_new` / `qodercontext_prepareInferRequest`（推理打包）/
`prepareRequest`（通用打包）/ `credential_storage_encrypt|decrypt`（凭证）/
`generate_runtime_auth_fields`（运行时签名字段）/ `model_cache_decrypt`（目录）/ `decrypt_server_response`。

**分析方法（本项目原创）**：Python + wasmtime 手写 wasm-bindgen host glue，以及独立 Go/wazero oracle，用于本地、经授权的互操作性分析。可选工具见 [`tools/README.md`](tools/README.md) 与 `tools/wasm_harness.py`：它要求运维方通过 `--wasm PATH` 提供经授权的外部 pinned binary，实例化前校验 size/SHA-256，只对仓库内 synthetic frozen fixtures 做内容静默的 replay/compare。`tools/wasm_oracle` 是独立子模块；root production 构建和普通 Go 测试均不依赖它。

---

## 7. 验证记录

### 7.1 Native-only 验证

Production 无需 backend mode：启动只构造 native services；源码、root module 和生产 binary 中没有 WASM runtime、embedded oracle 或 wazero。普通 root tests 只使用 frozen synthetic fixtures 和 native replay；可选 external oracle 独立位于 `tools/`。

迁移前已完成 shadow/native/rollback parity gates；移除后重新执行 native 全矩阵、refresh/context rebuild、完整测试、race、vet、Windows cross-compile、10,000-operation stress、四个 fuzz target、五项 benchmark，以及 dependency/binary-content audit。benchmark 只作为性能证据，不设绝对 pass/fail 阈值。完整 Native vs WASM 快照、方法与复跑说明见 [BENCHMARK.md](BENCHMARK.md)。

E2E 直接使用当前机器已授权的生产凭证目录、加密模型缓存和默认生产端点；也可用 `QODER2API_E2E_AUTH_DIR`、`QODER2API_E2E_INFER_ENDPOINT`、`QODER2API_E2E_OPENAPI_ENDPOINT`、`QODER2API_E2E_WEB_ENDPOINT` 做内容静默的受控覆盖。harness 强制关闭 dump-dir，输出只含 `backend=native`、route、stream、HTTP/schema 成功状态、时长与安全 upstream shape。普通 native gate 对真实凭证只读；只有同时设置 `QODER2API_E2E=1` 与 `QODER2API_E2E_REFRESH=1` 的 refresh gate 才允许轮换并持久化真实授权 token。

```bash
# 无 mode flags 的只读 smoke 与完整 native route matrix
QODER2API_E2E=1 go test -tags=e2e . -run '^TestProtocolE2EDefaultNative$' -count=1 -v
QODER2API_E2E=1 go test -tags=e2e . -run '^TestProtocolE2ENative$' -count=1 -v

# 显式授权的 refresh/context rebuild gate
QODER2API_E2E=1 QODER2API_E2E_REFRESH=1 go test -tags=e2e . -run '^TestProtocolE2ERefresh$' -count=1 -v

# 10,000 次 native runtime/prepares，加上 rebuild/Close ordering
go test . -run '^TestNative(RuntimeFields|Prepare|ContextRebuild|RepeatedClose)Stress$' -count=1

# 仅报告 Go 标准 benchmark/alloc 指标，不设置任意性能阈值。
go test . -run '^$' -bench '^BenchmarkNative(Body|Credential|Runtime|ModelCache|Infer)$' -benchmem -count=1

# 使用经授权的外部 pinned WASM 复跑 Native vs WASM 对比并更新 BENCHMARK.md。
python3 tools/benchmark.py --wasm /authorized/path/qoder_auth.wasm

# 仅交叉编译 Windows amd64 测试二进制，不在当前主机执行；临时产物自动删除。
windows_test_bin="$(mktemp)"
trap 'rm -f "$windows_test_bin"' EXIT
GOOS=windows GOARCH=amd64 go test -c -tags=e2e -o "$windows_test_bin" .
rm -f "$windows_test_bin"
trap - EXIT
```

| 测试 | 结果 |
|---|---|
| Frozen 1.1.34 兼容基线 | ✅ 五个 manifest/document hash 固定；credential/runtime-fields/model-cache/infer 由 native deterministic replay 验证 |
| Optional external oracle | ✅ operator-supplied WASM 的 size/SHA/ABI/fixtures 可由独立 `tools/wasm_oracle` 内容静默复核；不进入 root dependency graph |
| Native 生命周期与压力 | ✅ concurrent prepare/context rebuild/repeated close；10,000-operation stress；race/fuzz/benchmark evidence |
| 使用自有授权账号的最终端到端验证 | ✅ native-only 三路由 stream/nonstream、encrypted catalog、default smoke 与 refresh/context rebuild；输出和仓库均不包含凭据、请求、响应内容或抓包 |
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
├── main.go                     # 入口与信号交给 app.run
├── app.go                      # flags/env、依赖装配、后台任务与关闭顺序
├── protocol.go                 # 语义 capability/context 接口
├── protocol_error.go           # 安全错误分类与内部 cause 边界
├── protocol_services.go        # native-only service construction/lifecycle
├── protocol_host.go            # production clock/entropy 注入
├── native_body_codec.go        # custom Base64 + outer-third swap
├── native_credential.go        # AES-128-CBC credential compatibility
├── native_model_cache.go       # QMC v1 HKDF + AES-256-GCM
├── native_runtime_fields.go    # UUID/AES/RSA runtime auth fields
├── native_context.go           # immutable concurrent native context
├── native_infer.go             # COSY URL/headers/payload/signature
├── auth.go                     # 凭证读写/刷新；protocol context owner
├── convert.go                  # Anthropic ↔ RemoteChatAsk 类型转换
├── proxy.go                    # handlers + SSE 解析 + 模型解析
├── openai.go / responses.go    # OpenAI 兼容端点
├── testdata/protocol/1.1.34/   # frozen synthetic fixtures + manifest hashes
├── docs/
│   ├── oauth.md
│   └── inference-protocol.md
├── examples/                   # 客户端脱敏配置示例
├── tools/
│   ├── wasm_harness.py         # external-oracle launcher
│   └── wasm_oracle/            # 独立 Go/wazero analysis submodule
├── LICENSE                     # AGPL-3.0
├── NOTICE                      # 外部 oracle 与商标边界
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

本仓库采用 [GNU Affero General Public License v3.0](LICENSE)。通过网络向用户提供修改版服务时，AGPL-3.0 要求向这些用户提供对应源码。运维方自行提供的外部 oracle 不属于本仓库；其授权边界见 `NOTICE`。
