import test from 'node:test';
import assert from 'node:assert/strict';
import { buildClaudeSettings } from '../scripts/qoder-gateway.mjs';

test('Claude setup preserves integrations and clears conflicting model credentials', () => {
  const original = { model: 'previous', hooks: { SessionEnd: [{ hooks: [] }] }, enabledPlugins: { local: true }, permissions: { allow: ['Read'] }, env: { ANTHROPIC_API_KEY: 'previous-key', ANTHROPIC_MODEL: 'forced', HTTP_PROXY: 'http://proxy', CUSTOM: 'preserve' } };
  const snapshot = structuredClone(original);
  const settings = buildClaudeSettings(original, { baseUrl: 'http://127.0.0.1:18789', helper: 'node manager credentials', models: [{ id: 'qoder-anthropic/Kimi-K3' }, { id: 'qoder-anthropic/Qwen3.8-Flash' }] });
  assert.deepEqual(original, snapshot);
  assert.deepEqual(settings.hooks, original.hooks);
  assert.deepEqual(settings.enabledPlugins, original.enabledPlugins);
  assert.deepEqual(settings.permissions, original.permissions);
  assert.equal(settings.env.ANTHROPIC_API_KEY, undefined);
  assert.equal(settings.env.ANTHROPIC_MODEL, undefined);
  assert.equal(settings.env.HTTP_PROXY, 'http://proxy');
  assert.equal(settings.env.CUSTOM, 'preserve');
  assert.equal(settings.model, 'qoder-anthropic/Kimi-K3');
  assert.equal(settings.env.ANTHROPIC_DEFAULT_HAIKU_MODEL, 'qoder-anthropic/Qwen3.8-Flash');
});

test('Claude setup uses an available account model when preferred names are absent', () => {
  const settings = buildClaudeSettings({}, { baseUrl: 'http://127.0.0.1:18789', helper: 'node manager credentials', models: [{ id: 'qoder-anthropic/Account-Only' }] });
  assert.equal(settings.model, 'qoder-anthropic/Account-Only');
  assert.equal(settings.env.ANTHROPIC_DEFAULT_HAIKU_MODEL, 'qoder-anthropic/Account-Only');
});
