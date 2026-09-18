# Other agent harnesses

Start the local service with `node scripts/qoder-gateway.mjs start`, then configure the harness to call only a loopback standard API endpoint. The harness remains responsible for its own prompt loop, tool execution, approval policy, and files.

| API style | Base URL | Route |
| --- | --- | --- |
| Anthropic Messages | `http://127.0.0.1:18789` | `/v1/messages` |
| OpenAI Chat Completions | `http://127.0.0.1:18789/v1` | `/chat/completions` |
| OpenAI Responses | `http://127.0.0.1:18789/v1` | `/responses` |

Authenticate each request with the local gateway key using `x-api-key` or `Authorization: Bearer`. Store the key in the harness's local secret facility. It is generated at first start and is intentionally not printed by the normal management commands or included in examples.

Use `node scripts/qoder-gateway.mjs models` to view the safe model IDs and display names. Unknown models return `404`; do not invent a fallback model name.

For a program that cannot read a local secret file but has an API-key helper mechanism, invoke `node <absolute-path>/scripts/qoder-gateway.mjs credentials` from that helper. The command writes only the local key to standard output. Treat that output as a secret: do not run it interactively, log it, paste it into a chat, or add it to a repository.

This project does not provide an MCP tool that delegates work to Qoder. It is a model endpoint only.
