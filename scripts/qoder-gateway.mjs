#!/usr/bin/env node
import { promises as fs } from 'node:fs';
import { spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const entry = fileURLToPath(import.meta.url);
const repository = path.resolve(path.dirname(entry), '..');
const state = path.resolve(process.env.QODER_GATEWAY_STATE_DIR || path.join(
  process.platform === 'win32' ? (process.env.LOCALAPPDATA || os.tmpdir()) : (process.env.XDG_STATE_HOME || path.join(os.homedir(), '.local', 'state')),
  'qoder-model-gateway',
));
const configFile = path.join(state, 'config.json');
const statusFile = path.join(state, 'status.json');
const nativeBinary = path.join(repository, 'bin', process.platform === 'win32' ? 'qoder-model-gateway.exe' : 'qoder-model-gateway');
const output = value => console.log(JSON.stringify(value, null, 2));
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

async function exists(file) { try { await fs.access(file); return true; } catch { return false; } }
async function readJson(file) { return JSON.parse(await fs.readFile(file, 'utf8')); }
async function writeJson(file, value) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${randomUUID()}.tmp`;
  await fs.writeFile(temporary, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
  await fs.rename(temporary, file);
}
function processAlive(pid) { try { process.kill(pid, 0); return true; } catch (error) { return error.code === 'EPERM'; } }
async function withLock(action) {
  const lock = path.join(state, 'control.lock');
  await fs.mkdir(state, { recursive: true, mode: 0o700 });
  let handle;
  try { handle = await fs.open(lock, 'wx', 0o600); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    let owner; try { owner = await readJson(lock); } catch { /* an active owner may still be writing */ }
    if (owner?.pid && !processAlive(owner.pid)) throw new Error('STALE_CONTROL_LOCK: verify no gateway command is active, then remove only the displayed control.lock file.');
    throw new Error('GATEWAY_COMMAND_IN_PROGRESS');
  }
  await handle.writeFile(JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() }));
  try { return await action(); } finally { await handle.close(); await fs.unlink(lock).catch(() => {}); }
}
async function config() {
  if (!await exists(configFile)) await withLock(async () => {
    if (!await exists(configFile)) await writeJson(configFile, {
      version: 1, port: Number(process.env.QODER_GATEWAY_PORT || 18789), token: randomBytes(32).toString('hex'),
      authDir: path.join(os.homedir(), '.qoder-cn', '.auth'),
      startedFrom: repository,
    });
  });
  const value = await readJson(configFile);
  if (!Number.isInteger(value.port) || value.port < 1024 || value.port > 65535 || typeof value.token !== 'string' || value.token.length < 32 || typeof value.authDir !== 'string') throw new Error('INVALID_LOCAL_GATEWAY_CONFIGURATION');
  return value;
}
async function health(c) {
  try {
    const response = await fetch(`http://127.0.0.1:${c.port}/health`, { signal: AbortSignal.timeout(1500) });
    return response.ok ? await response.json() : null;
  } catch { return null; }
}
async function current(c) {
  try {
    const [saved, live] = await Promise.all([readJson(statusFile), health(c)]);
    if (live?.service === 'qoder-model-gateway' && live.mode === 'model-only' && live.instanceId === saved.instanceId) return saved;
  } catch { /* stopped is an expected condition */ }
  return null;
}
async function build() {
  await fs.mkdir(path.dirname(nativeBinary), { recursive: true, mode: 0o700 });
  const child = spawn('go', ['build', '-o', nativeBinary, '.'], { cwd: repository, shell: false, windowsHide: true, stdio: 'inherit' });
  const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve); });
  if (code !== 0) throw new Error('GO_BUILD_FAILED');
  output({ status: 'built', binary: nativeBinary });
}
async function serve() {
  const c = await config();
  if (!await exists(nativeBinary)) throw new Error('GATEWAY_BINARY_MISSING: run build first.');
  const instanceId = randomUUID();
  const child = spawn(nativeBinary, [
    '-addr', `127.0.0.1:${c.port}`, '-auth-dir', c.authDir, '-read-only-auth',
    '-endpoint', 'https://gateway.qoder.com.cn', '-openapi-endpoint', 'https://openapi.qoder.com.cn', '-web-endpoint', 'https://qoder.cn',
  ], {
    cwd: repository, windowsHide: true, stdio: 'ignore',
    env: { ...process.env, QODER2API_SK: c.token, QODER2API_INSTANCE_ID: instanceId, QODER2API_LOG: '', QODER2API_DUMP_DIR: '', QODER2API_MODEL_MAP: '' },
  });
  const closed = new Promise(resolve => child.once('close', resolve));
  await new Promise((resolve, reject) => { child.once('spawn', resolve); child.once('error', reject); });
  for (let index = 0; index < 80; index++) {
    const live = await health(c);
    if (live?.mode === 'model-only' && live.instanceId === instanceId) {
      await writeJson(statusFile, { service: 'qoder-model-gateway', mode: 'model-only', instanceId, pid: process.pid, nativePid: child.pid, url: `http://127.0.0.1:${c.port}`, startedAt: new Date().toISOString() });
      output({ status: 'listening', mode: 'model-only', url: `http://127.0.0.1:${c.port}` });
      await closed;
      try { if ((await readJson(statusFile)).instanceId === instanceId) await fs.unlink(statusFile); } catch { /* already gone */ }
      return;
    }
    if (child.exitCode !== null || child.signalCode !== null) break;
    await pause(100);
  }
  child.kill();
  await closed;
  throw new Error('GATEWAY_START_FAILED: check official Qoder login, account model cache, and port availability.');
}
async function ensureRunning() {
  const c = await config();
  const live = await current(c);
  if (live) return { c, live };
  return withLock(async () => {
    const active = await current(c);
    if (active) return { c, live: active };
    const child = spawn(process.execPath, [entry, 'serve'], { detached: true, windowsHide: true, stdio: 'ignore', cwd: repository, env: process.env });
    await new Promise((resolve, reject) => { child.once('spawn', resolve); child.once('error', reject); });
    child.unref();
    for (let index = 0; index < 120; index++) {
      const started = await current(c);
      if (started) return { c, live: started };
      if (child.exitCode !== null || child.signalCode !== null) break;
      await pause(500);
    }
    throw new Error('GATEWAY_START_TIMEOUT');
  });
}
async function models(c, live) {
  const response = await fetch(`${live.url}/v1/models?limit=1000`, { headers: { 'x-api-key': c.token }, signal: AbortSignal.timeout(5000) });
  if (!response.ok) throw new Error('MODEL_DISCOVERY_FAILED');
  const value = await response.json();
  if (!Array.isArray(value.data) || !value.data.length || value.data.some(model => typeof model.id !== 'string' || !model.id.startsWith('qoder-anthropic/'))) throw new Error('MODEL_DISCOVERY_INVALID');
  return value.data.map(({ id, display_name }) => ({ id, display_name }));
}
export function buildClaudeSettings(existing, { baseUrl, helper, models }) {
  const next = structuredClone(existing);
  next.env ??= {};
  for (const key of Object.keys(next.env)) if (/^ANTHROPIC_(?:API_KEY|AUTH_TOKEN|MODEL|CUSTOM_HEADERS|SMALL_FAST_MODEL|CUSTOM_MODEL_OPTION(?:_NAME|_DESCRIPTION)?)$|^CLAUDE_CODE_USE_|^CLAUDE_CODE_OAUTH_TOKEN$/.test(key)) delete next.env[key];
  const available = models.map(model => model.id);
  const pick = name => available.includes(`qoder-anthropic/${name}`) ? name : models[0].id.slice('qoder-anthropic/'.length);
  const primary = pick('Kimi-K3');
  const fast = pick('Qwen3.8-Flash');
  const route = name => `qoder-anthropic/${name}`;
  Object.assign(next.env, {
    ANTHROPIC_BASE_URL: baseUrl,
    ANTHROPIC_DEFAULT_OPUS_MODEL: route(primary), ANTHROPIC_DEFAULT_SONNET_MODEL: route(primary), ANTHROPIC_DEFAULT_FABLE_MODEL: route(primary), ANTHROPIC_DEFAULT_HAIKU_MODEL: route(fast),
    ANTHROPIC_CUSTOM_MODEL_OPTION: route(primary), ANTHROPIC_CUSTOM_MODEL_OPTION_NAME: `Qoder CN · ${primary}`,
    ANTHROPIC_CUSTOM_MODEL_OPTION_DESCRIPTION: 'Local Qoder CN model-only gateway.',
    CLAUDE_CODE_SUBAGENT_MODEL: route(primary), CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY: '1',
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '0', DISABLE_TELEMETRY: '1', DISABLE_ERROR_REPORTING: '1', ENABLE_TOOL_SEARCH: 'false', CLAUDE_CODE_ATTRIBUTION_HEADER: '0',
    CLAUDE_CODE_MAX_CONTEXT_TOKENS: '200000', CLAUDE_CODE_AUTO_COMPACT_WINDOW: '160000',
    NO_PROXY: [...new Set(`${next.env.NO_PROXY || ''},127.0.0.1,localhost,::1`.split(',').filter(Boolean))].join(','),
  });
  next.model = route(primary);
  next.availableModels = available;
  next.apiKeyHelper = helper;
  return next;
}
async function claudeEnable() {
  const { c, live } = await ensureRunning();
  const available = await models(c, live);
  const claudeRoot = process.env.CLAUDE_CONFIG_DIR || path.join(os.homedir(), '.claude');
  const settings = path.join(claudeRoot, 'settings.json');
  const cache = path.join(claudeRoot, 'cache', 'gateway-models.json');
  const before = await exists(settings) ? await fs.readFile(settings) : Buffer.from('{}\n');
  const existing = JSON.parse(before.toString('utf8').replace(/^\uFEFF/, ''));
  const helper = `"${process.execPath.replaceAll('\\', '/')}" "${entry.replaceAll('\\', '/')}" credentials`;
  const next = buildClaudeSettings(existing, { baseUrl: live.url, helper, models: available });
  const backup = path.join(state, 'backups', `claude-${Date.now()}`);
  await fs.mkdir(backup, { recursive: true, mode: 0o700 });
  await fs.writeFile(path.join(backup, 'settings.json'), before, { mode: 0o600 });
  if (await exists(cache)) await fs.copyFile(cache, path.join(backup, 'gateway-models.json'));
  if (await exists(settings) && !before.equals(await fs.readFile(settings))) throw new Error('CLAUDE_SETTINGS_CHANGED_DURING_CONFIGURATION');
  await writeJson(settings, next);
  await writeJson(cache, { baseUrl: live.url, fetchedAt: Date.now(), models: available });
  await writeJson(path.join(state, 'claude-configuration.json'), { configuredAt: new Date().toISOString(), backup, settings, modelCount: available.length });
  output({ status: 'configured', command: 'claude', picker: '/model', models: available.length, backup });
}
async function stop() {
  const c = await config();
  const live = await current(c);
  if (!live) return output({ status: 'stopped' });
  const response = await fetch(`${live.url}/_qoder/shutdown`, { method: 'POST', headers: { 'x-api-key': c.token }, signal: AbortSignal.timeout(5000) });
  if (!response.ok) throw new Error('GATEWAY_SHUTDOWN_NOT_ACCEPTED');
  for (let index = 0; index < 40; index++) {
    if (!await current(c) && !processAlive(live.pid)) return output({ status: 'stopped' });
    await pause(250);
  }
  throw new Error('GATEWAY_SHUTDOWN_IN_PROGRESS');
}
async function main() {
  const [action = 'status'] = process.argv.slice(2);
  if (action === 'build') return build();
  if (action === 'serve') return serve();
  if (action === 'start') { const { live } = await ensureRunning(); return output({ status: 'ready', ...live }); }
  if (action === 'stop') return stop();
  if (action === 'status') { const c = await config(); const live = await current(c); return output(live ? { status: 'ready', ...live } : { status: 'stopped', url: `http://127.0.0.1:${c.port}` }); }
  if (action === 'models') { const { c, live } = await ensureRunning(); return output({ mode: 'model-only', models: await models(c, live) }); }
  if (action === 'claude-enable') return claudeEnable();
  if (action === 'credentials') { const { c } = await ensureRunning(); process.stdout.write(c.token); return; }
  throw new Error('UNKNOWN_COMMAND: build, start, stop, status, models, or claude-enable');
}
if (path.resolve(process.argv[1] || '') === entry) main().catch(error => { console.error(JSON.stringify({ status: 'error', code: error.message })); process.exitCode = 1; });
