# Local changes

Upstream project: [Liki4/qodercli2api](https://github.com/Liki4/qodercli2api) at `b8b595fabbed733c5899019fed4b660ea23d94e0`.

This repository changes the upstream project into a model-only, local Qoder CN gateway:

- The production `main` function forces local locked-down mode before parsing options.
- Local mode permits only IPv4 loopback binding, a local gateway key, verified Qoder CN HTTPS endpoints, read-only Qoder authentication, bounded request bodies, and bounded concurrent inference.
- Read-only authentication consumes an existing official Qoder CN login without device login, PAT login, network refresh, token rotation, credential creation, or credential writes. Invalid and changed files fail closed.
- The account model cache is read in memory. Disabled models are excluded, aliases are labeled `qoder-anthropic/<model>`, and unknown model names fail with `404` rather than selecting a fallback.
- The local endpoint reports model-only health and sanitizes upstream errors.
- `scripts/qoder-gateway.mjs` adds an optional, dependency-free manager for local build/start/stop/model discovery and safe Claude Code routing setup.

The source does not contain an official Qoder CLI package, credential, model cache, traffic capture, or local gateway configuration.
