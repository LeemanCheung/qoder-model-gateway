# qodercli v1.1.34 OAuth 与本地认证协议

> 当前互操作基线固定为 Qoder CLI v1.1.34 的全合成 frozen fixtures。历史 characterization 使用的认证 WASM 为 297,238 bytes，SHA-256 `b3ddd7c9235cea51a965582506fa6281bb298ddab782ff3edb3f9015da2468d4`；它仅可作为运维方自行提供的外部 oracle 使用。
> 最初的登录流程与二进制结构结论来自对用户自行合法安装的 v1.1.5 的历史分析；当前生产算法是纯 Go native implementation。仓库不分发 Qoder CLI、认证 WASM、完整 JS bundle、凭据或抓包。

qodercli 的“OAuth”是自定义设备授权流（Device Authorization Grant 变体 + PKCE 风格 challenge/verifier），不是标准 OAuth 授权码流程。下文明确区分 **历史 Qoder CLI 行为**与仓库中 **当前代理实现**；两者共享端点和基础 wire format，但错误处理与登录后 enrichment 并不完全相同。

## 1. 登录方式

**历史 Qoder CLI v1.1.5 分析**观察到浏览器设备流、PAT、宿主注入的 job token/access token，以及本地存储恢复等入口；环境变量 `QODER_PERSONAL_ACCESS_TOKEN` 可向历史 CLI 提供 PAT。

**当前代理**公开实现 `-login` 浏览器设备流、`-login-pat` PAT 交换，以及已有本地 credential 恢复；本文不把历史 CLI 的 SDK/宿主注入入口声称为当前代理功能。

## 2. 设备授权流

### 2.1 PKCE 风格参数

```text
verifier  = 43..128 个随机字符，字符集 A-Z a-z 0-9 -._~
challenge = base64url_nopad(SHA256(verifier))
nonce     = random UUID
machineId = ~/.qoder/.auth/machine_id 中的 36 字符 UUID
```

浏览器打开：

```text
GET https://qoder.com/device/selectAccounts
    ?challenge={challenge}
    &challenge_method=S256
    &nonce={nonce}
    &machine_id={machineId}
    &client_id=e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb
```

没有 scope、redirect URI 或本地回调。客户端轮询：

```text
GET https://openapi.qoder.sh/api/v1/deviceToken/poll
    ?nonce={nonce}&verifier={verifier}&challenge_method=S256
Accept: application/json
```

**历史 Qoder CLI 行为**：未授权时 404 每 1 秒重试，总超时 300 秒；分析曾观察到指向网络代理的 ECONNREFUSED/ECONNRESET 连续 3 次后形成硬错误。token 成功后，CLI 会拉取 user info、organization tags 和 data policy，再保存 credential，并启动每 30 分钟一次的刷新检查。

**当前代理行为**：同样把 404 作为 pending 并每 1 秒重试、最多 5 分钟；但任意 transport error 都按 1 秒间隔继续到 deadline 或 context cancellation，**没有“三次代理错误即硬失败”计数器**。非 200/404 状态立即返回错误；200 JSON 缺 token 也立即失败。取得 token 后，代理先创建 runtime context 并保存 credential，再 best-effort 请求 `/api/v1/userinfo` 补充 profile；该 enrichment 失败不使登录失败。当前代理登录路径不调用历史 CLI 的 data-policy endpoint，也不应被描述为已经复制该 hard-error/data-policy 行为。

## 3. PAT 与 token 刷新

PAT 交换：

```http
POST /api/v1/jobToken/exchange
Content-Type: application/json

{"personal_token":"<PAT>"}
```

设备 token 刷新：

```http
POST /api/v1/deviceToken/refresh
Content-Type: application/json

{"refresh_token":"..."}
```

`expire_time - 3600 < now` 时提前刷新；每次用 token 前检查，后台每 30 分钟检查一次。当前 inference retry 只有在 **attempt 1 本身返回 401** 时才调用 `forceRefresh`，刷新成功后立即 retry 一次；如果先前已经发生 transport/status retry，后续 attempt 才返回 401，则直接返回该 401，不触发 refresh。刷新响应中的 token rotation 会先保留在内存中，再原子保存。

首次 browser/PAT login 的 credential publish 仍是 fail-closed，必须成功后才提交登录状态。已接受的新 token 与 replacement context 则以记忆体可用性为优先：后续 credential 保存失败时保留 `credentialDirty`，记录不含 credential 内容的内部原因，并在 30 秒 deadline 前跳过重复写入；deadline 到后由下一次 demand/background freshness check 重试。该持久化失败不会拒绝 inference，也不会重新请求 refresh endpoint。`Close` 忽略 retry deadline，强制执行最后一次 flush 并把失败返回给 operator。

## 4. credential 文件格式

| 项 | 精确格式 |
|---|---|
| 路径 | `~/.qoder/.auth/user`；多 profile 可为 `user.{name}` |
| 明文 | UserInfo 的 UTF-8 JSON |
| key | `machine_id` 前 16 个字符，作为 **raw 16-byte UTF-8 key**，不是 hex/base64 解码值 |
| cipher | AES-128-CBC |
| IV | 与 key 完全相同的 16 bytes |
| padding | PKCS#7，严格校验 |
| envelope | strict standard padded Base64（标准字母表，必须有正确 `=` padding；不接受 URL-safe/缺 padding/尾随垃圾） |

项目加载时保留兼容行为：若去除文件外围空白后内容以 `{` 开头，则按明文 JSON 解析；否则严格按上述格式解密。保存始终写加密格式，不写明文 fallback。

保存是唯一 temp-file 原子路径：在目标目录创建 `.user-*` 临时文件，立即 chmod `0600`，完整写入、`fsync`、关闭后 `rename` 到最终文件；失败时删除 temp。并发保存不会把两个 ciphertext 交叉写入，最终文件仍是一个完整的 `0600` 普通文件。best-effort 只改变刷新成功后的错误传播与重试节流；每一次实际写入仍完整经过这条原子路径。

## 5. runtime auth fields

`generate_runtime_auth_fields(raw)` 对调用方提供的 **raw UTF-8 字符串原样处理，不先 parse/re-marshal JSON**；因此字段顺序、空白和转义都会进入 AES 明文。

1. 读取 RNG bytes `R[16]`，逐字节反转为 `U[i] = R[15-i]`，然后设置 UUID mask：`U[6] = (U[6] & 0x0f) | 0x40`、`U[8] = (U[8] & 0x3f) | 0x80`。
2. runtime AES key `K` 精确为 lowercase `hex(U)[:16]` 的 **16 个 ASCII bytes**，等价于 masked/reversed `U` 的前 8 bytes 写成 16 个小写 hex 字符；不包含 UUID 连字符，也绝不能再做 hex decode。
3. 使用 `K` 执行 AES-128-CBC；IV=`K`，PKCS#7；对 raw input 加密并输出 strict standard padded Base64，作为 `encrypt_user_info`。
4. 用下列 pinned **runtime RSA-1024 SPKI public key**和 PKCS#1 v1.5 加密 `K`。其 modulus 为 1024 bits，public exponent 为 65537；SPKI DER 长 162 bytes，SHA-256 为 `a6a4aa468d90c618966e38122abfb06e566c18c9b21090d61f3e9b796b33e569`：

```pem
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc
4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l
6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17
XcW+ML9FoCI6AOvOzwIDAQAB
-----END PUBLIC KEY-----
```

该 key 直接从 pinned v1.1.34 WASM 提取，是用于互操作复现的非秘密公钥；不要与同一 WASM 中另一个 **2048-bit profile RSA public key**混淆。

5. PKCS#1 v1.5 编码块为 `00 02 || PS || 00 || M`：模长 128 bytes，`M=K` 为 16 bytes，所以 PS 精确为 **109 bytes**；PS 每字节必须非零，RNG 产生 0 时逐字节重试。RSA ciphertext 用 standard padded Base64 表示，作为 `key`。
6. 返回 JSON 的字段顺序固定为：

```json
{"encrypt_user_info":"<base64 AES ciphertext>","key":"<base64 RSA ciphertext>"}
```

该算法由 production pure-Go implementation 提供，并由 frozen fixtures 固定 byte-exact 兼容性。可选外部 oracle 仅用于经授权的离线复核，不进入生产构建或普通测试。当前验证证据见 [README §7.1](../README.md#71-native-only-验证)。

## 6. runtime context 与凭证携带

代理认证层是 active protocol context 的唯一 owner。加载或刷新凭证后，它补齐 runtime fields、创建新的 native context，再原子替换并关闭旧 context；server 和 catalog 只依赖语义接口。

- OpenAPI：`Authorization: Bearer {security_oauth_token ?? access_token}`，`User-Agent: qoder/1.1.34`
- 推理：设备 token 不直接进入 COSY token；native context 使用 `encrypt_user_info`、RSA `key`、machine/org/scene 字段准备请求，详见 [inference-protocol.md](inference-protocol.md)
- 认证语义边界：设备登录、PAT userinfo 与 credential reload 若得到 nil `organization_tags`，会在 runtime/context typed input 边界克隆为非 nil 空 slice；持久化 JSON 不必因此改写。直接调用低层 native context factory 仍按 frozen oracle 行为拒绝 nil tags
- credential codec 只返回 ciphertext；实际落盘仍由 §4 的单一原子保存路径执行
- production services 仅构造 native capabilities；clock/entropy 可注入，deterministic transcript record/replay 只存在于测试；`testdata/protocol/1.1.34/` 保存合成 fixtures

生产路径没有 backend mode、WASM rollback 或 fallback。验证与可选外部 oracle 命令见 [README §7.1](../README.md#71-native-only-验证)。

## 7. 生产端点与错误

| 用途 | 默认端点 |
|---|---|
| inference | `https://api2.qoder.sh` |
| openapi | `https://openapi.qoder.sh` |
| browser authorization | `https://qoder.com` |

代理允许运维方通过启动参数覆盖端点。当前代理的轮询超时、credential 格式/PKCS#7/Base64 错误均 fail closed；轮询 transport error 的当前处理见 §2。**历史 Qoder CLI SDK 行为**中，`storagePolicy=readOnly` 模式不刷新、不落盘；当前代理不实现 SDK mode，不能把该约束描述为当前代理策略。当前验证状态和授权运行要求统一见 [README §7.1](../README.md#71-native-默认与已完成迁移-gates)。
