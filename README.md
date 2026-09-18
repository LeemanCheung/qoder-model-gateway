# Qoder Model Gateway

`qoder-model-gateway` lets a local agent harness use Qoder CN account models through standard API protocols while keeping the harness responsible for its own session, tools, permissions, and agent loop.

The gateway is designed for a developer machine only. It binds to `127.0.0.1`, requires a random local gateway key, reuses the existing official Qoder CN CLI login in **read-only** mode, and sends direct HTTPS inference requests to Qoder CN. It never starts Qoder CLI, Qoder Agent SDK, or a Qoder agent loop for inference.

```text
Claude Code / another compatible harness
  owns conversations, tools, permissions, and the agent loop
                │
                ▼
Qoder Model Gateway on 127.0.0.1
  converts Messages / Chat Completions / Responses requests
                │
                ▼
Qoder CN model inference service
```

The gateway exposes three local endpoints:

| Endpoint | Protocol | Typical harness |
| --- | --- | --- |
| `POST /v1/messages` | Anthropic Messages, SSE and non-streaming | Claude Code and Anthropic-compatible tools |
| `POST /v1/chat/completions` | OpenAI Chat Completions, SSE and non-streaming | OpenAI-compatible tools |
| `POST /v1/responses` | OpenAI Responses, SSE and non-streaming | Codex and Responses-compatible tools |

## Scope and security

- Model inference only. Tool calls are returned to the calling harness; Qoder does not execute local tools.
- Only models in the local account catalogue are accepted. Unknown model names return `404`; there is no silent fallback.
- It reads existing Qoder CN authentication and model-cache files in memory. When launched through the included manager, it also reads the Qoder Desktop `chat_model_preferences` context-window values without modifying the database. It does not create a machine ID, refresh a token, rotate a token, log in, or write those files.
- It does not include Qoder CLI, a credential, a model cache, a captured request, or a user configuration file.
- The production binary forces loopback binding, a local gateway key, read-only authentication, fixed Qoder CN HTTPS endpoints, no verbose dumps, an 8 MiB body limit, and four concurrent inference requests.
- It is not affiliated with, endorsed by, or sponsored by Qoder or Alibaba. Use only an account you are authorized to use and comply with the applicable service terms and law.

The gateway is for one user's local desktop. It is not a network service, shared gateway, multi-user authentication system, or a way to bypass subscription or model access controls.

## Requirements

- Go `1.25+` to build the local gateway.
- A current Qoder CN CLI login and its local model cache. Log in through the official Qoder CN client or CLI before starting this gateway.
- Node.js `22.5+` only when using the included Claude Code configuration helper. The Go gateway itself has no Node dependency.

The default authentication directory is `~/.qoder-cn/.auth`. The gateway finds the matching encrypted model cache from that login and does not persist a plaintext copy.

## Quick start

```powershell
git clone https://github.com/LeemanCheung/qoder-model-gateway.git
Set-Location qoder-model-gateway
go build -o bin/qoder-model-gateway.exe .

$env:QODER2API_SK = '<a long random local key>'
& .\bin\qoder-model-gateway.exe -addr 127.0.0.1:18789 -auth-dir (Join-Path $env:USERPROFILE '.qoder-cn/.auth') -read-only-auth -endpoint https://gateway.qoder.com.cn -openapi-endpoint https://openapi.qoder.com.cn -web-endpoint https://qoder.cn
```

Use `GET /health` and authenticated `GET /v1/models` to verify startup. The model catalogue is account-specific.

## Claude Code: configure native `claude`

The included manager builds and starts the gateway, stores its local key outside the repository, backs up the existing Claude settings, and updates only model-routing fields. It keeps existing Claude plugins, hooks, permissions, and unrelated settings.

```powershell
node scripts/qoder-gateway.mjs build
node scripts/qoder-gateway.mjs claude-enable
claude
```

Then run `/model` inside Claude Code and select a `Qoder CN · …` model. The helper defaults to `Kimi-K3` and maps Claude's fast model family to `Qwen3.8-Flash` when those models are available. The selected model is sent as `qoder-anthropic/<account-model-name>`; use the menu or `/v1/models` output rather than guessing names.

The gateway sends each model's current Qoder Desktop preference as the upstream `context_length`, and `/v1/models` exposes `context_window`, `max_context_tokens`, and `available_context_windows`. Claude Code 2.1.237 applies `CLAUDE_CODE_MAX_CONTEXT_TOKENS` once when a process starts, so it cannot change arbitrary 200K/400K/1M limits inside an already running `/model` session. `claude-enable` sets that variable from the currently selected default model. After changing the persistent model in `/model`, run the following before starting a new session:

```powershell
node scripts/qoder-gateway.mjs claude-sync
```

This keeps Claude's auto-compaction budget aligned with the selected model. The manager also writes per-model metadata to Claude's gateway discovery cache for newer Claude versions that consume it.

The native `claude` executable is not replaced. Its configured `apiKeyHelper` starts the local gateway when needed and supplies its local key directly to Claude, without printing that key in a terminal.

```powershell
node scripts/qoder-gateway.mjs status
node scripts/qoder-gateway.mjs models
node scripts/qoder-gateway.mjs stop
```

If the official Qoder login expires, renew it with Qoder's official flow, then start the gateway again. This project intentionally has no proxy-side login or refresh command.

## Other harnesses

Any harness that supports one of the local protocols can use the gateway. Keep its API key in the harness's own secret mechanism; do not commit it.

| Harness protocol | Local base URL | Local key |
| --- | --- | --- |
| Anthropic Messages | `http://127.0.0.1:18789` | `x-api-key` or `Authorization: Bearer` |
| OpenAI Chat Completions | `http://127.0.0.1:18789/v1` | `Authorization: Bearer` |
| OpenAI Responses | `http://127.0.0.1:18789/v1` | `Authorization: Bearer` |

For a generic Anthropic-compatible harness, use a model ID returned by `GET /v1/models`, for example `qoder-anthropic/Kimi-K3`. For an OpenAI-compatible harness, use a returned model name in the format that client expects. The server performs strict account-catalogue lookup in both cases.

The `docs/` directory has configuration examples for Claude Code, OpenAI-compatible harnesses, and Responses-compatible harnesses. Other integrations should configure only an endpoint, a local key, and a model; they must not be wrapped in Qoder's agent runtime.

## Validation

```powershell
go test ./... -skip 'TestAuthManagerSaveWritesCredentialOnceAtomically/concurrent_writers_publish_one_complete_ciphertext'
node --test tests/*.test.mjs
```

One upstream Windows test for simultaneous credential writers can fail with a Windows rename access-denied error. This distribution's production mode disables credential writes; the Go command above runs the remaining suite, including the added read-only-authentication and local-security tests.

The project has been tested with native Claude Code using real Kimi-K3 text and `Read → Edit → Bash` tool rounds, and with Qwen3.8-Flash selected through `/model`. Those tests verify that Claude, not Qoder, executed the tools. Account availability, Qoder protocol behavior, and model names can change; test your own account after installation.

## Upstream and license

This repository is a modified distribution of [Liki4/qodercli2api](https://github.com/Liki4/qodercli2api), based on upstream revision `b8b595fabbed733c5899019fed4b660ea23d94e0`. It retains the upstream `LICENSE` and `NOTICE` and is licensed under the GNU Affero General Public License v3.0. See [LOCAL_CHANGES.md](LOCAL_CHANGES.md) for the local changes and their rationale.
