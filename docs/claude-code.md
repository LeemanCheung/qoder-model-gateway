# Claude Code

Run the safe local setup from a clone of this project:

```powershell
node scripts/qoder-gateway.mjs build
node scripts/qoder-gateway.mjs claude-enable
claude
```

`claude-enable` reads the account models from the running local gateway, saves a private backup of the current Claude settings, and updates the routing fields only. It does not replace the `claude` executable or turn on bypass permissions. Existing hooks, plugins, permissions, and unrelated settings remain in place.

The resulting flow is:

```text
claude → apiKeyHelper → local Qoder Model Gateway → Qoder CN inference
```

In Claude Code, use `/model` to select a current account model. The displayed IDs are prefixed with `qoder-anthropic/`; the backend resolves them strictly against the account catalogue. Do not set a global `ANTHROPIC_MODEL` afterwards, because it overrides model-menu selection.

When moving the repository, run `node scripts/qoder-gateway.mjs claude-enable` once again so the absolute `apiKeyHelper` path is updated. The local gateway key stays in the user state directory and is not written to this repository.
