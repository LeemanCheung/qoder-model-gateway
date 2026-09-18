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

The gateway reads Qoder Desktop's non-secret `chat_model_preferences.context_window` for each model when it starts. It uses a valid selected value first, then the model catalogue's `context_config.is_default` window, then the descriptor capability as a final fallback. The effective values are exposed at `/v1/models` as `context_window`, `max_context_tokens`, and `available_context_windows`.

Claude Code 2.1.237 has one process-wide `CLAUDE_CODE_MAX_CONTEXT_TOKENS` setting for unknown custom models. It cannot update an arbitrary 200K/400K/1M context budget instantly when `/model` changes a running session. `claude-enable` and `claude-sync` set the budget from the current saved model and write the per-model metadata to the gateway model cache. After choosing another persistent model, run this command and start a new Claude session:

```powershell
node scripts/qoder-gateway.mjs claude-sync
```

The upstream model request itself always uses that model's effective Qoder context window, even before Claude is restarted.

When moving the repository, run `node scripts/qoder-gateway.mjs claude-enable` once again so the absolute `apiKeyHelper` path is updated. The local gateway key stays in the user state directory and is not written to this repository.
