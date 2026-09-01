# qodercli v1.1.34 模型推理协议

> 当前生产实现是 pure Go native-only；`testdata/protocol/1.1.34/` 的全合成 frozen fixtures 固定互操作基线。历史 characterization 使用的 Qoder CLI v1.1.34 authentication WASM 为 297,238 bytes、SHA-256 `b3ddd7c9235cea51a965582506fa6281bb298ddab782ff3edb3f9015da2468d4`，现在仅可由运维方作为外部 oracle 提供。

## 1. URL

```text
POST {inference_endpoint}/algo/api/v2/service/pro/sse/agent_chat_generation
    ?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1
```

默认 endpoint 为 `https://api2.qoder.sh`，可由运维配置覆盖。`AgentId=agent_common` 是 URL 构造的固定常量，**不读取 body 的 `agent_id`**；修改、删除或重排 body 字段不会改变该 query 值。

COSY 签名使用的 path 固定为：

```text
/api/v2/service/pro/sse/agent_chat_generation
```

它不包含 endpoint 的 `/algo` 前缀，也不包含 query string。

## 2. 最多 22 个请求头及条件 presence

normal-user 完整输入（非空 organization ID、至少一个 organization tag、非空 model key）准备后的 header map 精确包含 22 项。pinned WASM 的 header presence 是条件式的，native 实现逐项匹配该行为：

| Header | 值/条件 |
|---|---|
| `Accept` | `text/event-stream` |
| `Authorization` | `Bearer COSY.{payloadB64}.{signatureHex}`，见 §3 |
| `Cache-Control` | `no-cache` |
| `Connection` | `keep-alive` |
| `Content-Type` | `application/json` |
| `Cosy-Business-Product` | scene 的 `business_product`，默认 `cli` |
| `Cosy-Business-Type` | scene 的 `business_type`，默认 `agent` |
| `Cosy-ClientType` | scene 的 `client_type`，默认 `5`；HTTP map 展示时大小写可能被规范化为 `Cosy-Clienttype` |
| `Cosy-Data-Policy` | `data_policy_agreed=true` 时 `agree`，否则 `disagree` |
| `Cosy-Date` | 当前 Unix **秒**的十进制字符串；host clock 以毫秒提供后截为秒 |
| `Cosy-Key` | runtime fields 的 RSA ciphertext Base64 |
| `Cosy-MachineId` | 36 字符 machine UUID |
| `Cosy-MachineToken` | 与 MachineId 相同 |
| `Cosy-MachineType` | `5` |
| `Cosy-Organization-Id` | organization ID；仅当 ID 非空时存在 |
| `Cosy-Organization-Tags` | tags 按原顺序以逗号连接；仅当 slice 长度大于零时存在 |
| `Cosy-Scene` | scene，默认 `assistant` |
| `Cosy-User` | uid |
| `Cosy-Version` | `1.1.34` |
| `Login-Version` | `v2` |
| `X-Model-Key` | `PrepareInferRequest` 的 model key；仅当 model key 非空时存在 |
| `X-Model-Source` | model source，通常 `system` 或 `custom`；与 `X-Model-Key` 同门控，key 非空时即使 source 为空也保留空值 header |

presence matrix 已由独立 WASM characterization 和 native/WASM differential 固化：

| 输入形状 | header 数 | 省略项 |
|---|---:|---|
| organization ID 非空、tags 非空、model key 非空 | 22 | 无 |
| organization ID 空、tags 空、model key 非空 | 20 | `Cosy-Organization-Id`、`Cosy-Organization-Tags` |
| organization ID 非空、tags 空、model key 非空 | 21 | `Cosy-Organization-Tags` |
| organization ID 空、tags 非空、model key 非空 | 21 | `Cosy-Organization-Id` |
| model key 空（无论 model source 是否为空） | 再减 2 | `X-Model-Key`、`X-Model-Source` |
| model key 非空、model source 空 | 不减少 | `X-Model-Source` 存在，值为空 |

`organization_tags=null` 与空 slice 在低层 context API 中不等价：pinned WASM 在 context New 阶段、任何 host entropy/clock 调用之前拒绝 nil tags；native factory 同样 fail closed。auth semantic boundary 会把登录/userinfo/load 得到的 nil tags 克隆为非 nil 空 slice，再生成 runtime fields 与 context config；它不放宽直接调用 factory 时的精确校验。非 nil 空 slice 是有效输入，并触发上表的 tags header omission。

## 3. COSY Authorization

### 3.0 context New 与 Prepare 的 host transcript 分界

外部 v1.1.34 oracle characterization 固定了 context 生命周期的 host 调用分界，production native implementation 与 frozen fixtures 保持该语义：

- `nativeContextFactory.New` 的 redraw-free 基础形状为 `[16,109]`，不读取时钟：16 bytes 用于 runtime UUID，109 bytes 用于 RSA PKCS#1 v1.5 PS。PS 中每遇到一个 zero byte，就按从左到右顺序追加一次或多次 1-byte 重抽，直到该位置非零；因此含 zero 的有效形状可以是 `[16,109,1,...]`。New **保留调用方传入的 `encrypt_user_info` 与 `key`**；生成 runtime fields 只复现 oracle 的 entropy 行为，不替换持久化字段。
- 随后的每次 `PrepareInferRequest` 精确读取一次时钟和一段 16-byte 安全熵，global host-call order 为 **clock → entropy**。该 16-byte tape 用于本节下方的 COSY request UUID；时钟用于 `Cosy-Date` 与签名。
- 测试分别 replay New 与 Prepare 并检查 transcript exhaustion；另有含 zero 的 New tape 固化 1-byte redraw 顺序。`infer-user.json` 为兼容历史 fixture 仍保存 redraw-free 组合形状 `[16,109,16]` 加一次时钟。

### 3.1 request UUID

每次 prepare 读取安全随机 bytes `R[16]`，逐字节反转为 `U[i] = R[15-i]`，再设置 `U[6] = (U[6] & 0x0f) | 0x40`、`U[8] = (U[8] & 0x3f) | 0x80`。将完整 masked `U` 按 lowercase `8-4-4-4-12` 格式化为 COSY UUID；不再反转字段内部字节。该 UUID 是 Authorization payload 的 `requestId`，每次 prepare 都重新生成且不得复用。它与 handler 创建、位于 RemoteChatAsk raw JSON 中的 `request_id` 是不同层次的字段。

### 3.2 payload

payload 是以下 **固定字段顺序**的 raw JSON：

```json
{"version":"v1","requestId":"<uuid>","info":"<encrypt_user_info>","cosyVersion":"<context version>","ideVersion":""}
```

pinned 正常 context 的 version 为 `1.1.34`，因此 official fixture 的 payload 仍逐字节包含 `"cosyVersion":"1.1.34"`。version perturbation characterization 证明该字段读取 context version，而不是另一个独立常量；`Cosy-Version` header 与 payload 同步变化并影响签名。

对这串 raw UTF-8 bytes 使用 **standard padded Base64**；保留标准 `+/` 字母表和 `=` padding，不使用 base64url。

### 3.3 canonical MD5 签名

令：

- `payloadB64`：上一节的标准 padded Base64
- `key`：runtime fields 的 `Cosy-Key` 字符串
- `unixSeconds`：与 `Cosy-Date` 完全相同
- `encodedBody`：§4 最终 POST body 字符串
- `signedPath`：`/api/v2/service/pro/sse/agent_chat_generation`

canonical bytes 精确为：

```text
payloadB64 LF key LF unixSeconds LF encodedBody LF signedPath
```

即五段、四个 `\n`，**末尾没有 LF**。签名是这些 UTF-8 bytes 的 MD5，输出 32 字符 lowercase hex：

```text
signatureHex = lowerhex(MD5(payloadB64 + "\n" + key + "\n" + unixSeconds + "\n" + encodedBody + "\n" + signedPath))
Authorization = "Bearer COSY." + payloadB64 + "." + signatureHex
```

签名 path 不含 `/algo`、不含 query，也不含尾随换行。它是 canonical MD5，不是“由 machine context 派生的未知签名算法”。

## 4. 请求 body codec

输入是调用方提供的 **raw UTF-8 JSON bytes**。codec 不 parse JSON、不规范化字段、不压缩空白，因此字段顺序、空格、转义形式甚至 JSON 语义等价但字节不同的输入都会得到不同 body；算法本身不依赖 user、model、clock 或 randomness，是 context-free deterministic transform。

1. 对 raw bytes 做 standard padded Base64。
2. 将标准 Base64 的 64 个字符按位置映射到以下 64 字符 alphabet：

```text
_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!
```

3. 将标准 Base64 padding `=` 映射为 `$`。
4. 对映射后的字符串做 outer-third swap：令 `k=floor(len/3)`，`A=s[:k]`、`B=s[k:len-k]`、`C=s[len-k:]`，输出 `C || B || A`。中段吸收不能整除 3 的余数。

逆变换为同样交换外侧 thirds，再把 `$` 和 custom alphabet 映回标准 Base64 后严格解码。该 body 是可逆的确定性编码，**不是加密**，也不需要每次调用 WASM 才能计算。native implementation 与 pinned adapter 对该 codec 保持 byte-exact 兼容。

## 5. RemoteChatAsk raw JSON

当前 proxy 使用 `map[string]any` 构造 RemoteChatAsk，并由 Go `encoding/json` 序列化。`encoding/json` 会按 lexical order 输出 string map keys；这里不存在可依赖的 struct declaration order。当前 proxy 产生的紧凑 top-level key 顺序精确为：

```text
agent_id, aliyun_user_type, business, chat_context, chat_record_id, chat_task, custom_model, is_reply, is_retry, messages, model_config, parameters, request_id, request_set_id, session_id, session_type, source, stream, system, task_id, tools, version
```

其中 `business` 是必需对象，当前包含 `begin_at`、`id`、`name`、`product`、`stage`、`type`、`version`；它自己的 map keys 同样按 lexical order 输出。`messages`、`model_config`、`tools`、`parameters` 及其他嵌套 struct/map 分别遵循其自身 Go `encoding/json` 规则：struct 使用声明字段顺序，string-keyed map 使用 lexical key order，`omitempty` 仍可能影响字段存在性。

这描述的是**当前 proxy 生成的 raw bytes**，不声称它必然等同于 official CLI 的字段顺序。raw JSON 随后直接进入 §4 codec 并参与签名，所以 top-level 或 nested serialization 的任何字段、顺序、空值或转义变化都属于 signature-sensitive drift。characterization fixture 使用真实 `remoteChatAskBody` builder 的固定合成输入锁定这些 bytes。

`request_id` 必须全局唯一；服务端对重复值返回 code 103。虽然 body 仍含 `agent_id`，URL 的 AgentId 固定常量不从这里读取。

## 6. model cache：QMC v1

`~/.qoder/.models/{uid}/catalog-v6` 使用 QMC v1 envelope：

1. HKDF-SHA256 的 IKM 为 raw `UTF8(uid)`；salt 为 ASCII `qoder-model-cache-enc`（21 bytes）；info 为 ASCII `model-cache-v1`（14 bytes）；输出精确为 32 bytes，作为 AES-256 key。
2. 使用随机 nonce 12 bytes、authentication tag 16 bytes、**empty AAD** 的 AES-256-GCM 加密 catalog plaintext。
3. 二进制 envelope 精确为 `QMC\x01 || nonce(12) || ciphertext || tag(16)`。
4. 整个 envelope 使用 standard padded Base64 保存。

解密必须校验 magic、version、最小长度和 GCM tag，任何失败均 fail closed。目录加载通过语义解密边界处理 QMC v1；未知 magic/version 等不兼容输入不会被误当作可降级数据，catalog loader 会保留 built-in catalog。

## 7. response：明文 SSE

响应不使用 §4 codec，也不需要 WASM 解密。Content-Type 为 `text/event-stream`，数据帧是明文 JSON 外层信封：

```text
data:{"headers":{"Content-Type":["application/json"]},"body":"<inner JSON string>","statusCodeValue":200,"statusCode":"OK"}
```

`body` 通常再解析一次得到 OpenAI `chat.completion.chunk`，可含 `content`、`reasoning_content`、流式 `tool_calls`、`finish_reason` 和 `usage`。授权 E2E 还确认：一个有效的 `statusCodeValue:200` 外层信封可在 `body` 字符串中携带精确的 `[DONE]` 标记；该标记本身不是上游终止依据。之后仍由独立的权威终止事件收尾：

```text
event:finish
data:{"firstTokenDuration":...,"totalDuration":...,"serverDuration":...}
```

因此，上游的 `[DONE]` 位于外层信封的 `body` 内，不是裸 `data:[DONE]` 帧；代理仅忽略这个精确标记，并继续要求后续 `event:finish`。面向不同下游客户端时，代理仍按目标协议生成各自的终止帧。`statusCodeValue != 200` 是错误信封；代理将其转换为各客户端协议的错误事件。

## 8. 当前 proxy retry 算法

一次 handler 调用最多执行 **4 attempts**。handler 创建并序列化一次 RemoteChatAsk raw JSON；其 body bytes 和内部 `request_id` 在所有 attempts 间保持不变。每个 attempt 都重新调用 `doUpstream` → `PrepareInferRequest`，因此重新生成 COSY UUID、读取当前 Unix seconds，并重新形成 Authorization/header/body wrapper。native 本地 `httptest` integration 锁定这一点：每个网络 attempt 恰好一次 prepare，不同 attempt 使用不同的 request entropy/clock，Authorization 与 COSY request UUID/date 随之更新，而 encoded body 和解码后的内部 `request_id` 保持不变；另有三次 1ms queue 后第四次成功的测试覆盖完整 4-attempt 上限。

- **transport error**：前 3 次失败分别无 jitter 等待 1、2、3 秒；第 4 次直接返回 transport error。
- **401**：只有 **attempt 1 自身返回 401** 才调用 `forceRefresh`；刷新成功后立即进入 attempt 2，不额外 sleep。若 attempt 1 是 transport error、408/429/5xx 或 queue 等其他结果，经过 retry 后 attempt 2/3/4 才返回 401，则直接返回该 response，绝不补做 refresh；attempt 1 的 refresh 失败也直接返回原 401。
- **普通 retryable status**：408、429、500–599 可重试。默认 exponential waits 为 attempt 1 后 1 秒、attempt 2 后 2 秒、attempt 3 后 4 秒。若 `Retry-After` 非空，只按 `time.ParseDuration(value + "s")` 解释为 numeric seconds；解析成功则覆盖默认值，HTTP-date 不支持。等待上限 30 秒，无 jitter。
- **queue response**：JSON `queue.isQueued=true` 时依次选 `queue.waitTime` → 顶层 `retryAfterMs` → 2000ms；顶层 `code="10605"` 时选 `retryAfterMs` → 2000ms。queue wait 同样 cap 30 秒；queue 分支不使用普通 exponential wait 或 `Retry-After` header。
- **取消**：所有等待通过 context-aware sleep；context cancel 立即返回 `ctx.Err()`。
- **response ownership**：非 200 response body 最多读取 8192 bytes 后关闭。需返回给 caller 时以已读取 bytes 构造新的 body；达到第 4 attempt 时返回最后 response，不再等待。200 response 保持开放交给 SSE caller。
- **其他状态**：非 queue 且不属于上述 retryable status 的 response 立即返回。

code 103 duplicate 的准确含义：当前 proxy retry 会保留同一 RemoteChatAsk `request_id`，所以不能把 code 103 当作可安全自动 retry 的状态；它不在 retryable status 集合中，会立即返回。若要形成协议意义上的新请求，必须由 handler/调用方重新创建 RemoteChatAsk 和新的 `request_id`，而不仅是重新 prepare COSY wrapper。

本地 clock/entropy/backend/context 失败发生在 prepare 阶段并 fail closed，不发送半准备请求；它作为 attempt transport-side error 进入上述 1/2/3 秒调度，最终仍失败返回。

## 9. Native-only production 与验证边界

Production 只有一个 native service constructor；没有 backend mode flag、环境变量、WASM adapter、shadow wrapper 或 fallback runtime。root module 和 production binary 不包含 WASM bytes，也不依赖 wazero。验证状态和授权运行命令见 [README §7.1](../README.md#71-native-only-验证)。

native context 的当前语义如下：

- Factory 校验完整的 clock/entropy，以及 machine ID、版本、UID、非 nil organization tags 和四个非空 scene 字段；organization ID 与非 nil tags slice 可为空。配置和 tags 在 New 边界深拷贝。nil tags 按 frozen oracle 行为在任何 runtime/host work 前拒绝。
- New 使用调用 context 中的 host override（存在时优先于 factory host）执行 redraw-free `[16,109]`、零 clock 的 runtime-field 初始化；PS 中出现 zero 时追加 1-byte redraw。它保留调用方已有的两个 runtime fields，生成结果不替换持久化字段。
- `PrepareInferRequest` 在本地构造完整 COSY request：literal endpoint concatenation、native body codec、反转/mask request UUID、固定顺序 payload、standard padded Base64、canonical MD5、条件 header presence，以及 fresh URL/header/body ownership。每次 prepare 按 **clock → 16-byte entropy** 顺序各调用一次；没有隐藏 counter 或 transcript state。
- context 本身不保存 transcript 或隐藏计数器。每次 Prepare 获得独立的不可变状态副本和 body 副本，返回的 header map、header value slices 与 body 也拥有独立 storage。生产 wall clock 与 secure entropy 实现可并发使用；record/replay machinery 仅存在于测试文件。
- Close 幂等并等待在途 Prepare；关闭开始后不再接纳新 Prepare。该本地 context 边界不执行 auth refresh 或网络请求。

普通 root 测试使用 frozen fixtures 和 native deterministic replay，不需要 Python、外部 WASM 或网络。离线证据包括：`infer-user.json` 的 byte-for-byte native match、15 个 pinned lowercase signature vectors、header presence matrix、覆盖 body/model/organization/policy/time/endpoint 变化的 deterministic corpus、native retry regeneration、race/fuzz/stress 和跨平台构建。

可选 external oracle 位于 `tools/wasm_oracle` 独立子模块中，保留其自己的 wazero 依赖。它只接受运维方显式提供且身份匹配的授权 WASM，并以内容静默方式复核 synthetic frozen fixtures；它不属于 production dependency graph。
