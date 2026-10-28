// ReportScout Windows release gate: downloads the draft-release ZIP, then runs the packaged app on a real Windows machine.
// Public file (release-checks/windows-smoke.mjs). It uses only synthetic reports it writes itself and no dependency beyond Node 22.
//
// Inputs (environment, never shell-interpolated):
//   GITHUB_TOKEN        the workflow's ephemeral token (read only); never printed, never given to a child process
//   GITHUB_REPOSITORY   owner/name holding the draft release
//   RS_RELEASE_TAG      tag of the DRAFT release
//   RS_ASSET_NAME       exact asset file name (a .zip)
//   RS_SHA256           expected SHA-256 of the asset (64 hex characters)
//   RS_EXPECTED_VERSION optional, default 0.3.3
//   RS_LOCAL_ZIP        optional: use this ZIP instead of the API (for a build check before publishing); RS_SHA256 still applies
//   RS_REPORT_FILE      optional: also write the JSON report here
// `node windows-smoke.mjs --self-test` checks the parsers on any OS without a release.
// Exit 0 only when every assertion passed. The JSON report on stdout lists versions, commands, exit codes and assertions.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import http from 'node:http';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createWriteStream} from 'node:fs';
import {pipeline} from 'node:stream/promises';
import {Readable} from 'node:stream';
import {spawn} from 'node:child_process';

const WIN = process.platform === 'win32';
const SYS = process.env.SystemRoot || 'C:\\Windows';
const sleep = ms => new Promise(r => setTimeout(r, ms));
const TOTAL_MS = 12 * 60 * 1000; // the workflow allows 15 minutes: this leaves time to clean up and report

// ---------- parsers (checked by --self-test) ----------

// The PE header facts that matter for "unsigned x64 Windows program".
export function readPE(buf) {
  if (buf.length < 0x100 || buf.toString('latin1', 0, 2) !== 'MZ') throw new Error('not a PE file (no MZ header)');
  const pe = buf.readUInt32LE(0x3c);
  if (pe + 0x100 > buf.length || buf.toString('latin1', pe, pe + 4) !== 'PE\0\0') throw new Error('not a PE file (no PE signature)');
  const machine = buf.readUInt16LE(pe + 4), characteristics = buf.readUInt16LE(pe + 22), opt = pe + 24, magic = buf.readUInt16LE(opt);
  const pe32plus = magic === 0x20b;
  const dirs = pe32plus ? opt + 112 : opt + 96;
  const security = {offset: buf.readUInt32LE(dirs + 4 * 8), size: buf.readUInt32LE(dirs + 4 * 8 + 4)};
  return {machine: '0x' + machine.toString(16), x64: machine === 0x8664, pe32plus, isDll: !!(characteristics & 0x2000), executable: !!(characteristics & 2),
    subsystem: buf.readUInt16LE(opt + 68), certificateTableBytes: security.size};
}

// Reads one file out of an Electron asar archive: 16 bytes of size fields, a JSON index, then the file data.
export function readAsarFile(asarPath, name) {
  const fd = fs.openSync(asarPath, 'r');
  try {
    const head = Buffer.alloc(16);
    fs.readSync(fd, head, 0, 16, 0);
    const indexLength = head.readUInt32LE(12), base = 8 + head.readUInt32LE(4);
    const json = Buffer.alloc(indexLength);
    fs.readSync(fd, json, 0, indexLength, 16);
    let node = JSON.parse(json.toString('utf8'));
    for (const part of name.split('/')) node = node?.files?.[part];
    if (!node || node.files || node.unpacked) throw new Error(`${name} is not packed in ${path.basename(asarPath)}`);
    const out = Buffer.alloc(node.size);
    fs.readSync(fd, out, 0, node.size, base + Number(node.offset));
    return out;
  } finally { fs.closeSync(fd); }
}

// A ZIP listing must not name an absolute path, a drive, or a ".." part.
export function unsafeZipEntries(lines) {
  return lines.filter(l => l && (/^[/\\]/.test(l) || /^[A-Za-z]:/.test(l) || l.split(/[/\\]/).includes('..')));
}

export const comparable = p => String(p).replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase();

// ---------- run state ----------

const report = {tool: 'reportscout-windows-smoke', startedAt: new Date().toISOString(), platform: {os: process.platform, arch: process.arch, release: os.release(), version: os.version?.()},
  node: process.version, inputs: {}, release: null, download: null, binary: {}, versions: {}, commands: [], assertions: [], passed: false};
const children = new Set();
let token = '';
let scratch = '';
let finished = false;

// Never let a token or a URL (which can carry a signature) reach the log or the report.
export function redact(text) {
  let s = String(text);
  if (token) s = s.split(token).join('<token>');
  return s.replace(/https?:\/\/[^\s"'<>)]+/g, '<url>').replace(/(Authorization:?\s*)\S+(\s+\S+)?/gi, '$1<redacted>');
}
const log = line => process.stderr.write(redact(line) + '\n');
function assertion(name, pass, evidence) {
  report.assertions.push({name, pass: !!pass, evidence: evidence === undefined ? undefined : JSON.parse(redact(JSON.stringify(evidence)))});
  log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) throw new Error(`Assertion failed: ${name}`);
}

function killTree(child) {
  if (!child?.pid) return;
  try {
    if (WIN) spawn(path.join(SYS, 'System32', 'taskkill.exe'), ['/PID', String(child.pid), '/T', '/F'], {stdio: 'ignore', windowsHide: true});
    else child.kill('SIGKILL');
  } catch {}
}

// Runs one program to completion (killing its tree at the deadline) and records the command, exit code and output.
function run(label, exe, args, {env, cwd, timeoutMs = 120000, show = args} = {}) {
  return new Promise(resolve => {
    const started = Date.now();
    const child = spawn(exe, args, {env, cwd, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe']});
    children.add(child);
    let stdout = '', stderr = '', timedOut = false;
    child.stdout.on('data', d => { if (stdout.length < 400000) stdout += d; });
    child.stderr.on('data', d => { if (stderr.length < 400000) stderr += d; });
    const timer = setTimeout(() => { timedOut = true; killTree(child); }, timeoutMs);
    const done = (code, signal, error) => {
      clearTimeout(timer); children.delete(child);
      const result = {label, command: [path.basename(exe), ...show.map(String)], exit: code, signal, timedOut, ms: Date.now() - started, stdout, stderr, error: error?.message};
      report.commands.push({...result, command: result.command.map(redact), stdout: redact(stdout).slice(0, 1500), stderr: redact(stderr).slice(0, 1500)});
      log(`run   ${label} -> exit ${code ?? signal ?? error?.message} (${result.ms} ms)`);
      resolve(result);
    };
    child.once('error', e => done(null, null, e));
    child.once('close', (code, signal) => done(code, signal));
  });
}

// ---------- input and GitHub ----------

function inputs() {
  const env = process.env, get = k => (env[k] || '').trim();
  const out = {repo: get('GITHUB_REPOSITORY'), tag: get('RS_RELEASE_TAG'), asset: get('RS_ASSET_NAME'), sha256: get('RS_SHA256').toLowerCase(),
    version: get('RS_EXPECTED_VERSION') || '0.3.3', localZip: get('RS_LOCAL_ZIP')};
  if (!out.localZip) assert.match(out.repo, /^[\w.-]+\/[\w.-]+$/, 'GITHUB_REPOSITORY must be owner/name');
  assert.match(out.tag, /^[\w.\/-]{1,100}$/, 'RS_RELEASE_TAG has unexpected characters');
  assert.match(out.asset, /^[\w.-]{1,150}\.zip$/, 'RS_ASSET_NAME must be a plain .zip file name');
  assert.match(out.sha256, /^[0-9a-f]{64}$/, 'RS_SHA256 must be 64 hex characters');
  assert.match(out.version, /^\d+\.\d+\.\d+$/, 'RS_EXPECTED_VERSION must look like 0.3.3');
  return out;
}

async function gh(pathname, {accept = 'application/vnd.github+json', redirect = 'follow'} = {}) {
  return fetch(`https://api.github.com${pathname}`, {redirect, signal: AbortSignal.timeout(60000),
    headers: {Authorization: `Bearer ${token}`, Accept: accept, 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'reportscout-windows-smoke'}});
}

async function findDraftAsset(want) {
  let drafts = 0, seen = 0;
  const matches = [];
  for (let page = 1; page <= 10; page++) {
    const res = await gh(`/repos/${want.repo}/releases?per_page=100&page=${page}`);
    if (!res.ok) throw new Error(`Listing releases failed: HTTP ${res.status}`);
    const list = await res.json();
    for (const r of list) { seen++; if (r.draft) drafts++; if (r.tag_name === want.tag && r.draft === true) matches.push(r); }
    if (list.length < 100) break;
  }
  if (matches.length !== 1) throw new Error(`Expected exactly one DRAFT release tagged ${want.tag}; found ${matches.length} (${seen} releases visible, ${drafts} of them drafts). If no drafts are visible at all, the token cannot list drafts.`);
  const release = matches[0], assets = release.assets.filter(a => a.name === want.asset);
  if (assets.length !== 1) throw new Error(`Expected exactly one asset named ${want.asset}; the draft has: ${release.assets.map(a => a.name).join(', ') || 'none'}`);
  return {release, asset: assets[0], visible: {releases: seen, drafts}};
}

// The API answers an asset request with a redirect to a signed storage URL. That URL is followed without the token, only on GitHub's asset hosts, and never logged.
async function downloadAsset(want, asset, dest) {
  const first = await gh(`/repos/${want.repo}/releases/assets/${asset.id}`, {accept: 'application/octet-stream', redirect: 'manual'});
  let res = first;
  if (first.status >= 300 && first.status < 400) {
    const target = new URL(first.headers.get('location') || '');
    if (target.protocol !== 'https:' || !(target.hostname === 'githubusercontent.com' || target.hostname.endsWith('.githubusercontent.com'))) throw new Error(`Refusing to follow the asset redirect to host ${target.hostname}`);
    res = await fetch(target, {signal: AbortSignal.timeout(6 * 60 * 1000)});
  }
  if (!res.ok || !res.body) throw new Error(`Downloading the asset failed: HTTP ${res.status}`);
  const hash = createHash('sha256');
  let bytes = 0;
  await pipeline(Readable.fromWeb(res.body), async function* (src) {
    for await (const chunk of src) { bytes += chunk.length; if (bytes > 1.5 * 1024 ** 3) throw new Error('Asset larger than 1.5 GiB'); hash.update(chunk); yield chunk; }
  }, createWriteStream(dest));
  return {bytes, sha256: hash.digest('hex')};
}

function hashFile(file) {
  return new Promise((resolve, reject) => {
    const h = createHash('sha256'); let bytes = 0;
    fs.createReadStream(file).on('data', d => { bytes += d.length; h.update(d); }).on('end', () => resolve({bytes, sha256: h.digest('hex')})).on('error', reject);
  });
}

// ---------- packaged app ----------

function findExe(root, depth = 0) {
  const found = [];
  for (const e of fs.readdirSync(root, {withFileTypes: true})) {
    const p = path.join(root, e.name);
    if (e.isFile() && e.name.toLowerCase() === 'reportscout.exe') found.push(p);
    else if (e.isDirectory() && depth < 3) found.push(...findExe(p, depth + 1));
  }
  return found;
}

// A plain environment for the packaged app: a scratch profile and a PATH of Windows system folders only, so nothing
// (Git, Python, Node, an installed ReportScout, the runner's profile) can help it. `where.exe` proves the PATH is bare.
function appEnv(home, extra = {}) {
  const env = {SystemRoot: SYS, windir: SYS, ComSpec: process.env.ComSpec || path.join(SYS, 'System32', 'cmd.exe'), PATH: WIN ? `${SYS}\\System32;${SYS}` : '/usr/bin:/bin',
    USERPROFILE: home, HOME: home, APPDATA: path.join(home, 'AppData', 'Roaming'), LOCALAPPDATA: path.join(home, 'AppData', 'Local'), TEMP: path.join(home, 'tmp'), TMP: path.join(home, 'tmp'), ...extra};
  for (const d of [env.APPDATA, env.LOCALAPPDATA, env.TEMP]) fs.mkdirSync(d, {recursive: true});
  return env;
}

const freePort = () => new Promise((resolve, reject) => { const s = net.createServer(); s.once('error', reject); s.listen(0, '127.0.0.1', () => { const {port} = s.address(); s.close(() => resolve(port)); }); });
const until = async (test, what, ms = 20000) => { for (const end = Date.now() + ms; Date.now() < end; await sleep(150)) { const v = await test(); if (v) return v; } throw new Error(`Timed out after ${ms} ms waiting for ${what}`); };

// The main process's inspector, over Node's built-in WebSocket. Only the main process is attached, never a page: the report view has
// nothing loaded until a report is opened and would never answer.
async function attachInspector(port, child, exited) {
  const list = await until(async () => {
    if (exited.done) throw new Error(`ReportScout exited (${exited.code ?? exited.signal}) before its inspector opened`);
    return new Promise(resolve => http.get({host: '127.0.0.1', port, path: '/json/list', timeout: 2000}, res => { let b = ''; res.on('data', d => (b += d)); res.on('end', () => { try { const j = JSON.parse(b); resolve(Array.isArray(j) && j.length ? j : null); } catch { resolve(null); } }); }).on('error', () => resolve(null)).on('timeout', function () { this.destroy(); }));
  }, 'the main-process inspector', 90000);
  const ws = new WebSocket(list[0].webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = () => reject(new Error('inspector connection failed')); });
  const waiting = new Map();
  let id = 0;
  ws.onmessage = e => { const m = JSON.parse(e.data); waiting.get(m.id)?.(m); waiting.delete(m.id); };
  ws.onclose = () => { for (const w of waiting.values()) w({error: {message: 'inspector closed'}}); waiting.clear(); };
  const raw = (method, params, ms = 20000) => new Promise((resolve, reject) => {
    const n = ++id, timer = setTimeout(() => { waiting.delete(n); reject(new Error(`No answer within ${ms} ms to ${method}`)); }, ms);
    waiting.set(n, m => { clearTimeout(timer); resolve(m); });
    ws.send(JSON.stringify({id: n, method, params}));
  });
  const value = async (expression, ms) => {
    const reply = await raw('Runtime.evaluate', {expression, awaitPromise: true, returnByValue: true}, ms);
    if (reply.error || reply.result?.exceptionDetails) throw new Error(`In the app: ${reply.error?.message || reply.result.exceptionDetails.exception?.description || reply.result.exceptionDetails.text}`);
    return reply.result.result.value;
  };
  return {raw, value, close: () => { try { ws.close(); } catch {} }};
}

// ---------- the synthetic reports (Czech text and a folder with spaces: the paths real users have) ----------

const CAPTURE = {title: 'Příběh půdního průzkumu', body: 'žluťoučký-kůň-4172', project: 'Zahrada Čechy'};
const SCANNED = {title: 'Kvartální přehled zálivky', body: 'úrodný-déšť-9038'};
const html = (title, body) => `<!doctype html>\n<html lang="cs"><head><meta charset="utf-8"><title>${title}</title></head><body><h1>${title}</h1><p>${body}</p></body></html>\n`;

// ---------- settings-write diagnostic (records only; it never passes or fails the check) ----------

// Run by ReportScout.exe as Node. "full" repeats each step of the settings package's write in a fresh folder, then runs the
// packaged SettingsFile in a second fresh folder with its documented test hooks, which only observe: openDir opens the folder
// exactly as the package does and notes how the handle's fsync ends. "inspect" lists an existing folder and fsyncs it, nothing more.
const SETTINGS_PROBE = String.raw`
import fs from 'node:fs'; import fsp from 'node:fs/promises'; import path from 'node:path'; import {pathToFileURL} from 'node:url';
const [mode, dir, expect, asar] = process.argv.slice(2);
const C = fs.constants, out = {mode, platform: process.platform, electron: process.versions.electron, oNoFollow: C.O_NOFOLLOW ?? null, steps: []};
const err = e => ({code: e?.code, errno: e?.errno, syscall: e?.syscall, message: String(e?.message ?? e).split(dir).join('<dir>').slice(0, 300)});
const plain = v => v === undefined || v === null || typeof v !== 'object' || Array.isArray(v) || Object.getPrototypeOf(v) === Object.prototype;
const step = async (name, fn) => { try { const v = await fn(); out.steps.push({name, ok: true, ...(v !== undefined && plain(v) ? {v} : {})}); return v; } catch (e) { out.steps.push({name, ok: false, error: err(e)}); return undefined; } };
const id = s => ({dev: String(s.dev), ino: String(s.ino)});
const writeTemp = async (name, text) => {
  const fh = await step(name + ' open (O_WRONLY|O_CREAT|O_EXCL)', () => fsp.open(path.join(dir, name), C.O_WRONLY | C.O_CREAT | C.O_EXCL | (C.O_NOFOLLOW ?? 0), 384));
  if (!fh) return undefined;
  await step(name + ' write', () => fh.writeFile(text, 'utf8')); await step(name + ' fsync', () => fh.sync());
  const st = await step(name + ' fstat', async () => id(await fh.stat())); await step(name + ' close', () => fh.close()); return st;
};
const dirSync = async (d, tag) => { const fh = await step(tag + ': open folder read-only', () => fsp.open(d, C.O_RDONLY)); if (!fh) return; await step(tag + ': fsync folder handle', () => fh.sync()); await step(tag + ': close folder handle', () => fh.close()); };
try {
  if (mode === 'inspect') {
    await step('folder entries', async () => (await fsp.readdir(dir)).filter(n => /settings|tmp|lock|damaged/i.test(n)).slice(0, 40));
    await step('settings.json', async () => { const t = await fsp.readFile(path.join(dir, 'settings.json'), 'utf8'); return {bytes: t.length, containsSavedFolder: !!expect && t.includes(JSON.stringify(expect).slice(1, -1))}; });
    await dirSync(dir, 'data folder');
  } else {
    const target = path.join(dir, 'settings.json');
    await step('mkdir', () => fsp.mkdir(dir, {recursive: true, mode: 448}));
    await step('realpath equals folder', async () => (await fsp.realpath(dir)) === dir);
    await writeTemp('lock-tmp', '{}');
    await step('lock: hard link', () => fsp.link(path.join(dir, 'lock-tmp'), target + '.lock'));
    await step('lock: unlink temp', () => fsp.unlink(path.join(dir, 'lock-tmp')));
    await step('lock: rename aside', () => fsp.rename(target + '.lock', target + '.aside'));
    await step('lock: unlink aside', () => fsp.unlink(target + '.aside'));
    const a = await writeTemp('t1', '{"n":1}\n');
    await step('rename onto a new file', () => fsp.rename(path.join(dir, 't1'), target));
    await step('lstat matches the written handle (new)', async () => ({same: !!a && JSON.stringify(id(await fsp.lstat(target))) === JSON.stringify(a)}));
    const b = await writeTemp('t2', '{"n":2}\n');
    await step('rename over the existing file', () => fsp.rename(path.join(dir, 't2'), target));
    await step('lstat matches the written handle (replace)', async () => ({same: !!b && JSON.stringify(id(await fsp.lstat(target))) === JSON.stringify(b)}));
    let watcher;
    await step('fs.watch on the folder', () => { watcher = fs.watch(dir, () => {}); watcher.on('error', () => {}); });
    await writeTemp('t3', '{"n":3}\n');
    await step('rename over the existing file while watched', () => fsp.rename(path.join(dir, 't3'), target));
    await dirSync(dir, 'raw');
    watcher?.close();
    await step('read back', async () => (await fsp.readFile(target, 'utf8')) === '{"n":3}\n');
    // The packaged package, observed through its own hooks, in a sibling folder that exists as the app's data folder does
    const vdir = dir + ' package', events = [], ev = (e, x) => events.push(x ? {e, ...x} : {e});
    const url = pathToFileURL(path.join(asar, 'node_modules', '@app-patterns', 'settings', 'dist', 'node', 'index.js')).href;
    const mod = await step('import the packaged settings package', async () => (await import(url)).SettingsFile ? 'SettingsFile found' : 'SettingsFile missing');
    if (mod === 'SettingsFile found') {
      const {SettingsFile} = await import(url);
      await step('mkdir package folder', () => fsp.mkdir(vdir, {recursive: true, mode: 448}));
      const file = new SettingsFile(path.join(vdir, 'settings.json'), {testHooks: {
        beforeCommit: () => ev('temp written and fsynced'), beforeRename: () => ev('about to rename'),
        openDir: async d => { ev('renamed and checked; opening folder'); let fh; try { fh = await fsp.open(d, C.O_RDONLY); } catch (e) { ev('folder open threw', err(e)); throw e; }
          const sync = fh.sync.bind(fh); fh.sync = async () => { try { await sync(); ev('folder fsync ok'); } catch (e) { ev('folder fsync threw', err(e)); throw e; } }; return fh; }}});
      for (const n of [1, 2]) await step('SettingsFile.update #' + n, async () => { const r = await file.update(read => ({write: {probe: n}, result: read.kind})); return {ok: r.ok, code: r.code, error: r.error, result: r.result, written: r.written, events: events.splice(0)}; });
      await step('package folder entries', async () => (await fsp.readdir(vdir)).slice(0, 20));
    }
  }
} catch (e) { out.fatal = err(e); }
process.stdout.write(JSON.stringify(out), () => process.exit(0));
`;

async function settingsWriteProbe(label, exe, asar, env, cwd, toolsDir, args) {
  try {
    const probe = path.join(toolsDir, 'settings-write-probe.mjs');
    if (!fs.existsSync(probe)) fs.writeFileSync(probe, SETTINGS_PROBE);
    const r = await run(`settings-write diagnostic: ${label}`, exe, [probe, ...args, asar], {env, cwd, timeoutMs: 90000, show: ['<settings-write-probe.mjs>', args[0], '<folder>']});
    let parsed; try { parsed = JSON.parse(r.stdout); } catch { parsed = {unparsed: r.stdout.slice(0, 2000)}; }
    (report.diagnostics ??= {})[label] = JSON.parse(redact(JSON.stringify({exit: r.exit, timedOut: r.timedOut, stderr: r.stderr.slice(0, 1500), ...parsed}).split(JSON.stringify(scratch).slice(1, -1)).join('<scratch>')));
  } catch (e) { (report.diagnostics ??= {})[label] = {error: redact(e.message)}; }
}

// ---------- the gate ----------

async function main() {
  assert.ok(typeof WebSocket === 'function', `This Node (${process.version}) has no built-in WebSocket; Node 22 or later is required.`);
  token = process.env.GITHUB_TOKEN || '';
  delete process.env.GITHUB_TOKEN; // nothing started from here on can inherit it
  const want = inputs();
  report.inputs = {repo: want.localZip ? '(local zip)' : want.repo, tag: want.tag, asset: want.asset, expectedSha256: want.sha256, expectedVersion: want.version};
  if (!want.localZip) assert.ok(token, 'GITHUB_TOKEN is not set');

  // The real (long, not 8.3-short) temporary folder: RUNNER_TEMP can sit on D:, the temp folder is on C:, which is where users' files are.
  scratch = fs.mkdtempSync(path.join(fs.realpathSync.native(os.tmpdir()), 'rs-windows-smoke-'));
  const dirs = {zip: path.join(scratch, 'download'), app: path.join(scratch, 'extracted'), tools: path.join(scratch, 'tools'), work: path.join(scratch, 'work'), home: path.join(scratch, 'home'),
    reports: path.join(scratch, 'Zprávy a přehledy'), source: path.join(scratch, 'Zdroj zpráv č. 1'), data: path.join(scratch, 'ReportScout Data složka')};
  for (const d of [dirs.zip, dirs.app, dirs.tools, dirs.work, dirs.home, dirs.reports, dirs.source]) fs.mkdirSync(d, {recursive: true});
  report.scratchRootIsDriveLetterPath = !WIN || /^[A-Za-z]:\\/.test(scratch);

  // 1. The release asset
  let zip = want.localZip ? path.resolve(want.localZip) : path.join(dirs.zip, want.asset);
  if (!want.localZip) {
    const {release, asset, visible} = await findDraftAsset(want);
    assertion('the draft release and the exact asset were found through the API', release.draft === true && asset.state === 'uploaded' && asset.size > 1e6,
      {releaseId: release.id, draft: release.draft, assetId: asset.id, assetName: asset.name, size: asset.size, apiDigest: asset.digest, visible});
    report.release = {id: release.id, tag: release.tag_name, draft: release.draft, prerelease: release.prerelease, assetId: asset.id, assetSize: asset.size, otherAssets: release.assets.length - 1};
    report.download = await downloadAsset(want, asset, zip);
  } else report.download = await hashFile(zip);
  assertion('the downloaded file has the SHA-256 given to the workflow', report.download.sha256 === want.sha256 && report.download.bytes > 1e6, {bytes: report.download.bytes, sha256: report.download.sha256});

  // 2. Extract with the system tar (bsdtar reads ZIP; Git's GNU tar on PATH does not, so the Windows one is named in full)
  const tar = WIN ? path.join(SYS, 'System32', 'tar.exe') : 'tar';
  const toolEnv = {...process.env, PATH: process.env.PATH};
  const listing = await run('list the ZIP', tar, ['-tf', zip], {env: toolEnv, cwd: dirs.work, timeoutMs: 120000});
  const entries = listing.stdout.split(/\r?\n/).filter(Boolean);
  assertion('the ZIP lists cleanly with no absolute or ".." entries', listing.exit === 0 && entries.length > 10 && unsafeZipEntries(entries).length === 0, {entries: entries.length, unsafe: unsafeZipEntries(entries).slice(0, 5)});
  const extract = await run('extract the ZIP', tar, ['-xf', zip, '-C', dirs.app], {env: toolEnv, cwd: dirs.work, timeoutMs: 300000});
  assertion('the ZIP extracted', extract.exit === 0, {exit: extract.exit});
  const exes = findExe(dirs.app);
  assertion('exactly one ReportScout.exe with resources/app.asar beside it', exes.length === 1 && fs.existsSync(path.join(path.dirname(exes[0]), 'resources', 'app.asar')), {found: exes.map(p => path.relative(dirs.app, p))});
  const exe = exes[0], appDir = path.dirname(exe), asar = path.join(appDir, 'resources', 'app.asar');

  // 3. Static facts: a 64-bit Windows program, version, no signature
  const peBuf = Buffer.alloc(8192);
  const fd = fs.openSync(exe, 'r'); fs.readSync(fd, peBuf, 0, 8192, 0); fs.closeSync(fd);
  const pe = readPE(peBuf);
  report.binary = {exe: path.relative(dirs.app, exe), bytes: fs.statSync(exe).size, ...pe};
  assertion('ReportScout.exe is an x64 PE executable program (not a DLL)', pe.x64 && pe.pe32plus && pe.executable && !pe.isDll && pe.subsystem === 2, pe);
  const manifest = JSON.parse(readAsarFile(asar, 'package.json').toString('utf8'));
  report.versions.packageJson = {name: manifest.name, version: manifest.version, main: manifest.main};
  assertion(`the packaged app is version ${want.version}`, manifest.version === want.version, {version: manifest.version});
  assertion('the file carries no Authenticode certificate table (unsigned launcher)', pe.certificateTableBytes === 0, {certificateTableBytes: pe.certificateTableBytes});
  if (WIN) {
    const ps = await run('Get-AuthenticodeSignature', path.join(SYS, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', '$s = Get-AuthenticodeSignature -LiteralPath $env:RS_PE; $v = (Get-Item -LiteralPath $env:RS_PE).VersionInfo; [pscustomobject]@{Status = $s.Status.ToString(); HasSigner = ($null -ne $s.SignerCertificate); ProductVersion = $v.ProductVersion; FileVersion = $v.FileVersion; ProductName = $v.ProductName} | ConvertTo-Json -Compress'],
      {env: {...process.env, RS_PE: exe}, cwd: dirs.work, timeoutMs: 120000, show: ['<Get-AuthenticodeSignature on ReportScout.exe>']});
    const sig = JSON.parse(ps.stdout.trim() || '{}');
    report.binary.authenticode = sig;
    assertion('Windows reports the launcher as NotSigned', ps.exit === 0 && sig.Status === 'NotSigned' && sig.HasSigner === false, sig);
  }

  // 4. Packaged command line: the app's own Node, no Node/Python/Git installed for it
  const cliEnv = appEnv(dirs.home, {ELECTRON_RUN_AS_NODE: '1'});
  const cli = path.join(asar, 'scripts', 'report-scout.mjs');
  for (const tool of ['git', 'python', 'node']) {
    const w = await run(`where ${tool} on the app's PATH`, path.join(SYS, 'System32', 'where.exe'), [tool], {env: cliEnv, cwd: dirs.work, timeoutMs: 30000});
    assertion(`the app's PATH has no ${tool}`, w.exit === 1, {exit: w.exit});
  }
  const probe = path.join(dirs.tools, 'probe.cjs');
  fs.writeFileSync(probe, "const v = process.versions; let sqlite = false; try { sqlite = typeof require('node:sqlite').DatabaseSync === 'function'; } catch {} process.stdout.write(JSON.stringify({node: v.node, electron: v.electron, chrome: v.chrome, arch: process.arch, platform: process.platform, sqlite}));\n");
  const pv = await run('packaged runtime versions', exe, [probe], {env: cliEnv, cwd: dirs.work, timeoutMs: 120000});
  const rt = JSON.parse(pv.stdout || '{}');
  report.versions.packagedRuntime = rt;
  assertion('ReportScout.exe runs as Node and is a 64-bit Windows Electron with node:sqlite', pv.exit === 0 && rt.platform === 'win32' && rt.arch === 'x64' && !!rt.electron && rt.sqlite === true, rt);
  const help = await run('report-scout --help', exe, [cli, '--help'], {env: cliEnv, cwd: dirs.work});
  assertion('the packaged command line prints its help', help.exit === 0 && /report-scout add/.test(help.stdout) && /report-scout search/.test(help.stdout) && /--data-dir/.test(help.stdout), {exit: help.exit});

  // 5. Capture, search, star and starred search against an explicit absolute data folder, on a Czech path with spaces, with no Git
  const sourceFile = path.join(dirs.source, 'Půdní průzkum – podzim.html');
  fs.writeFileSync(sourceFile, html(CAPTURE.title, CAPTURE.body));
  const c = (label, args) => run(label, exe, [cli, ...args, '--data-dir', dirs.data], {env: cliEnv, cwd: dirs.work});
  assertion('the data folder is absolute and does not exist yet (a first run)', path.isAbsolute(dirs.data) && !fs.existsSync(dirs.data), {data: path.basename(dirs.data)});
  const add = await c('report-scout add', ['add', sourceFile, '--title', CAPTURE.title, '--keywords', 'půda,průzkum', '--project', CAPTURE.project, '--by', 'windows-smoke']);
  const [captured, capturedTitle] = add.stdout.trim().split('\t');
  const inbox = path.join(dirs.data, 'report-inbox');
  assertion('add captured the report into the inbox inside the data folder', add.exit === 0 && capturedTitle === CAPTURE.title && comparable(captured).startsWith(comparable(inbox)) && fs.existsSync(captured), {exit: add.exit, stderr: add.stderr.slice(0, 300)});
  assertion('the data folder is not a Git repository', !fs.existsSync(path.join(inbox, '.git')) && !fs.existsSync(path.join(dirs.data, '.git')));
  const byTitle = await c('search by title word', ['search', 'půdního']);
  assertion('search finds the captured report by a Czech title word', byTitle.exit === 0 && byTitle.stdout.includes(CAPTURE.title) && comparable(byTitle.stdout).includes(comparable(captured)), {exit: byTitle.exit});
  const byBody = await c('search full text', ['search', '--scope', 'full', 'žluťoučký-kůň-4172']);
  assertion('full-text search finds the report by a word only in its body', byBody.exit === 0 && byBody.stdout.includes(CAPTURE.title), {exit: byBody.exit});
  const none = await c('search for nothing', ['search', 'nesmyslneslovo7731']);
  assertion('search for an absent word returns nothing', none.exit === 0 && none.stdout.trim() === '');
  const starredBefore = await c('search --starred before starring', ['search', '--starred']);
  assertion('starred search is empty before the star', starredBefore.exit === 0 && starredBefore.stdout.trim() === '');
  const star = await c('report-scout mark --star', ['mark', captured, '--star']);
  assertion('mark --star succeeds with no Git on the machine', star.exit === 0, {exit: star.exit, stderr: star.stderr.slice(0, 300)});
  const starredAfter = await c('search --starred after starring', ['search', '--starred']);
  assertion('starred search now finds the report', starredAfter.exit === 0 && starredAfter.stdout.includes(CAPTURE.title), {exit: starredAfter.exit});
  const marks = JSON.parse(fs.readFileSync(path.join(inbox, 'report-marks.json'), 'utf8'));
  assertion('the star is stored in the data folder inbox', marks.reports?.some(r => r.starred === true), {entries: marks.reports?.length});

  // Diagnostic only: how each step of a settings write ends on this machine, from the app's own runtime, in a fresh scratch folder
  await settingsWriteProbe('before the window', exe, asar, cliEnv, dirs.work, dirs.tools, ['full', path.join(scratch, 'Nastavení sonda č. 1'), '']);

  // 6. The window, hidden: --report-scout-data is the only data-folder switch the app reads (it ignores --data-dir)
  fs.writeFileSync(path.join(dirs.reports, 'Čtvrtletní přehled.html'), html(SCANNED.title, SCANNED.body));
  const guiEnv = appEnv(dirs.home);
  const port = await freePort();
  const guiArgs = [`--inspect=127.0.0.1:${port}`, `--user-data-dir=${path.join(dirs.work, 'chromium-profile')}`, '--report-scout-check', '--report-scout-commit-ms=300', `--report-scout-data=${dirs.data}`];
  const gui = spawn(exe, guiArgs, {env: guiEnv, cwd: dirs.work, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe']});
  children.add(gui);
  const exited = {done: false}, tail = {out: '', err: ''};
  gui.stdout.on('data', d => (tail.out = (tail.out + d).slice(-6000)));
  gui.stderr.on('data', d => (tail.err = (tail.err + d).slice(-6000)));
  gui.once('exit', (code, signal) => Object.assign(exited, {done: true, code, signal, at: Date.now()}));
  gui.once('error', e => Object.assign(exited, {done: true, code: null, signal: e.message}));
  const guiRecord = {label: 'ReportScout.exe hidden window', command: ['ReportScout.exe', ...guiArgs.map(a => a.replace(dirs.scratch || scratch, '<scratch>'))]};
  let ins;
  try {
    ins = await attachInspector(port, gui, exited);
    // Nothing touches electron before the app has built its window and Settings host: an earlier require loads the wrong module.
    await until(() => ins.value('globalThis.__settingsHost !== undefined').catch(() => false), 'the app to finish starting', 90000);
    const electron = `const electron = (() => { const m = process.getBuiltinModule('module'); try { return m.createRequire(${JSON.stringify(path.join(asar, 'package.json'))})('electron'); } catch (e1) { try { return process.mainModule.require('electron'); } catch (e2) { throw new Error('cannot load electron: ' + e1.message + ' / ' + e2.message); } } })();`;
    const ev = (source, ms) => ins.value(`(async () => { ${electron} ${source} })()`, ms);
    const mainWin = 'electron.BrowserWindow.getAllWindows().find(w => w.webContents.getURL().endsWith("/index.html"))';
    const inMain = (js, ms = 20000) => ev(`const w = ${mainWin}; return w ? await w.webContents.executeJavaScript(${JSON.stringify(js)}) : null;`, ms);
    const settingsWin = 'globalThis.__settingsHost.settingsWindow()';
    const inSettings = (js, ms = 20000) => ev(`const w = ${settingsWin}; return w && !w.isDestroyed() ? await w.webContents.executeJavaScript(${JSON.stringify(js)}) : null;`, ms);

    const facts = await ev('return {version: electron.app.getVersion(), packaged: electron.app.isPackaged, userData: electron.app.getPath("userData"), electron: process.versions.electron, chrome: process.versions.chrome, node: process.versions.node, platform: process.platform, arch: process.arch, name: electron.app.getName()};');
    report.versions.runningApp = facts;
    assertion('the running app is the packaged 0.3.3 Windows x64 build using the explicit data folder', facts.packaged === true && facts.version === want.version && facts.platform === 'win32' && facts.arch === 'x64' && comparable(facts.userData) === comparable(dirs.data), facts);

    await until(() => ev(`const w = ${mainWin}; return !!w && !w.webContents.isLoading();`).catch(() => false), 'the main window to load index.html', 60000);
    const shown = await until(async () => { const r = await inMain('window.reportScout.call("reports").then(x => ({total: x.total, reports: x.reports.map(r => ({id: r.id, title: r.title, starred: !!r.starred, path: r.path}))}))').catch(() => null); return r?.total >= 1 && r; }, 'the captured report to be listed', 60000);
    const ui = await inMain('({root: document.querySelector("#root")?.childElementCount || 0, rows: document.querySelectorAll(".report-row").length, text: document.body.innerText.slice(0, 400)})');
    assertion('the renderer loaded and lists the report captured from the command line, still starred', ui.root > 0 && shown.reports.some(r => r.title === CAPTURE.title && r.starred === true) && !/could not be read/.test(ui.text), {rows: ui.rows, reports: shown.reports.map(r => ({title: r.title, starred: r.starred}))});

    // 0.3.3 regression coverage: real key events in the hidden Windows renderer; synthetic inbox only.
    const capturedBytesBeforeArchive = fs.readFileSync(captured);
    const marksBeforeTyping = fs.readFileSync(path.join(inbox, 'report-marks.json'), 'utf8');
    await inMain('(() => { const i = document.querySelector("input[type=search]"); i.focus(); return true; })()');
    await ev(`const w = ${mainWin}; for (const ch of 'stclg ') { w.webContents.sendInputEvent({type:'keyDown',keyCode:ch}); w.webContents.sendInputEvent({type:'char',keyCode:ch}); w.webContents.sendInputEvent({type:'keyUp',keyCode:ch}); await new Promise(r => setTimeout(r,30)); } return true;`);
    const typed = await inMain('({q:document.querySelector("input[type=search]").value, focused:document.activeElement === document.querySelector("input[type=search]"), dialog:!!document.querySelector("[role=dialog]"), gallery:document.querySelector(".app").classList.contains("gallery")})');
    assertion('Windows key events for single-key shortcuts stay in the search field without changing marks', typed.q === 'stclg ' && typed.focused && !typed.dialog && !typed.gallery && fs.readFileSync(path.join(inbox, 'report-marks.json'), 'utf8') === marksBeforeTyping, typed);
    await inMain('(() => { const i = document.querySelector("input[type=search]"); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,"value").set.call(i, ""); i.dispatchEvent(new Event("input",{bubbles:true})); i.blur(); return true; })()');
    await until(() => inMain('!!document.querySelector(".report-row")'), 'reports after clearing the search');
    const captureRow = shown.reports.find(r => r.title === CAPTURE.title);
    // The trusted renderer bridge is the same route used by Archive. No workflow token reaches it.
    const archived = await inMain(`window.reportScout.call("mark", ${JSON.stringify(captureRow.id)}, "archive", true)`);
    const archiveBrowse = await inMain('window.reportScout.call("search", "", {archive:"only"}).then(x=>x.map(r=>r.title))');
    const normalBrowse = await inMain('window.reportScout.call("search", "", {}).then(x=>x.map(r=>r.title))');
    assertion('Archive hides the synthetic report from ordinary search and retains its star in the Archive', archived.archived === true && archived.starred === true && archiveBrowse.includes(CAPTURE.title) && !normalBrowse.includes(CAPTURE.title), {archived:archived.archived, starred:archived.starred, archiveBrowse, normalBrowse});
    const restored = await inMain(`window.reportScout.call("mark", ${JSON.stringify(captureRow.id)}, "archive", false)`);
    const restoredBrowse = await inMain('window.reportScout.call("search", "", {}).then(x=>x.map(r=>r.title))');
    assertion('Restore returns the synthetic report with its star and leaves its HTML bytes unchanged', !restored.archived && restored.starred === true && restoredBrowse.includes(CAPTURE.title) && fs.readFileSync(captured).equals(capturedBytesBeforeArchive), {restored:!restored.archived, starred:restored.starred});

    // Settings window, driven through its own page: the Report folders page and the settings bridge, as a person would
    await ev('globalThis.__settingsHost.openSettingsWindow("folders"); return true;');
    await until(() => inSettings('!!document.querySelector("section[aria-label=\\"Report folders\\"]")').catch(() => false), 'the Report folders page in the Settings window', 60000);
    const page = await inSettings(`({sections: [...document.querySelectorAll('nav[aria-label="Settings sections"] button[data-section]')].map(b => b.dataset.section), reportBridge: typeof window.reportScout})`);
    assertion('the Settings window opened on Report folders with all six pages and no access to the report bridge', ['general', 'search', 'folders', 'shortcuts', 'changes', 'about'].every(s => page.sections.includes(s)) && page.reportBridge === 'undefined', page);
    const fill = value => inSettings(`(() => { const i = document.querySelector('input[aria-label="Folder path"]'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(i, ${JSON.stringify(value)}); i.dispatchEvent(new Event('input', {bubbles: true})); return true; })()`);
    const press = label => inSettings(`(() => { const b = [...document.querySelectorAll('button')].find(b => b.textContent.trim() === ${JSON.stringify(label)} && !b.disabled); if (!b) return false; b.click(); return true; })()`);
    const folderState = () => inSettings('({items: [...document.querySelectorAll(".rs-folder:not(.fixed):not(.empty) span")].map(s => s.title), alerts: [...document.querySelectorAll("[role=alert]")].map(a => a.textContent), status: [...document.querySelectorAll("[role=status]")].map(t => t.textContent).find(t => /^Saved/.test(t)) || "", saveEnabled: !![...document.querySelectorAll("button")].find(b => b.textContent.trim() === "Save and refresh" && !b.disabled)})');
    await fill('relative\\folder'); await until(() => press('Add'), 'the Add button', 10000);
    const refused = await until(async () => { const s = await folderState(); return s.alerts.length && s; }, 'a refusal of a relative folder', 10000);
    assertion('a relative folder is refused and nothing is queued to save', refused.alerts[0].length > 0 && refused.items.length === 0 && !refused.saveEnabled, refused);

    await fill(dirs.reports); await until(() => press('Add'), 'the Add button for the drive-letter folder', 10000);
    const queued = await until(async () => { const s = await folderState(); return (s.items.length || s.alerts.length) && s; }, 'the folder to be queued or refused', 10000);
    assertion(`a native Windows folder (${/^[A-Za-z]:\\/.test(dirs.reports) ? 'drive-letter' : 'absolute'} path with spaces and Czech letters) is accepted by the Settings page`, queued.alerts.length === 0 && queued.items.length === 1 && comparable(queued.items[0]) === comparable(dirs.reports) && queued.saveEnabled, queued);
    await until(() => press('Save and refresh'), 'Save and refresh', 10000);
    const saved = await until(async () => { const s = await folderState(); return (/^Saved/.test(s.status) || s.alerts.length) && s; }, 'the save to finish', 20000);
    if (!(/^Saved/.test(saved.status) && saved.alerts.length === 0)) await settingsWriteProbe('after the failed save', exe, asar, cliEnv, dirs.work, dirs.tools, ['inspect', dirs.data, dirs.reports]);
    assertion('Save and refresh saved the folder through the settings bridge', /^Saved/.test(saved.status) && saved.alerts.length === 0, saved);

    // The setting started a scan: the report in that folder is listed, searchable and opens in the viewer
    const listed = await until(async () => { const r = await inMain('window.reportScout.call("reports").then(x => x.reports.map(r => r.title))').catch(() => null); return r?.includes(SCANNED.title) && r; }, 'the scan of the new folder', 90000);
    const found = await inMain(`window.reportScout.call("search", "Kvartální", {}).then(x => x.map(r => r.title))`);
    assertion('the scan listed the report from the Windows folder and search finds it', found.includes(SCANNED.title) && listed.includes(CAPTURE.title), {listed, found});
    await until(() => inMain(`[...document.querySelectorAll(".report-row")].some(r => r.innerText.includes(${JSON.stringify(SCANNED.title)}))`), 'the new report in the list', 30000);
    await inMain(`[...document.querySelectorAll(".report-row")].find(r => r.innerText.includes(${JSON.stringify(SCANNED.title)})).click(); true`);
    const reader = await until(() => ev(`const v = electron.webContents.getAllWebContents().find(c => !c.isDestroyed() && c.getURL().startsWith("report://")); return v && !v.isLoading() && v.getTitle() ? {url: v.getURL().replace(/^report:\\/\\/[^/]+/, "report://<id>"), title: v.getTitle()} : null;`), 'the report to open in the viewer', 30000);
    assertion('opening the report loads its file into the viewer', reader.title === SCANNED.title, reader);

    const windows = await ev('const all = electron.BaseWindow.getAllWindows(); const main = electron.BrowserWindow.getAllWindows().find(w => w.webContents.getURL().endsWith("/index.html")); const settings = globalThis.__settingsHost.settingsWindow(); const describe = w => w && !w.isDestroyed() ? {id: w.id, url: w.webContents?.getURL() || null, visible: w.isVisible(), minimized: w.isMinimized()} : null; return {all: all.map(w => ({id: w.id, url: w.webContents?.getURL() || null, visible: w.isVisible(), minimized: w.isMinimized()})), main: describe(main), settings: describe(settings), mainInInventory: all.includes(main), settingsInInventory: all.includes(settings)};');
    assertion('the main and Settings windows are alive in the full window inventory and none is visible', !!windows.main && windows.main.url?.endsWith('/index.html') && !!windows.settings && windows.settings.url?.endsWith('/settings.html') && windows.mainInInventory && windows.settingsInInventory && windows.all.every(w => !w.visible), windows);

    // Let Electron evaluate app.quit before detaching this verifier's inspector.
    await ev('setTimeout(() => electron.app.quit(), 100); return true;');
    ins.close(); ins = undefined;
    await until(() => exited.done, 'the app to quit by itself', 20000).catch(() => {});
    guiRecord.exit = exited.code; guiRecord.signal = exited.signal; guiRecord.stderrTail = redact(tail.err).slice(-1500);
    report.commands.push(guiRecord);
    assertion('the app exits by itself with code 0 after the quit request', exited.done && exited.code === 0, {exit: exited.code, signal: exited.signal});
  } catch (e) {
    guiRecord.error = e.message; guiRecord.exit = exited.code; guiRecord.signal = exited.signal; guiRecord.stderrTail = redact(tail.err).slice(-1500); guiRecord.stdoutTail = redact(tail.out).slice(-800);
    if (!report.commands.includes(guiRecord)) report.commands.push(guiRecord);
    throw e;
  } finally { ins?.close(); killTree(gui); children.delete(gui); }

  // 7. The setting the window saved is the one the command line (the agents' route) reads, and its scan finds the folder's report
  await sleep(1000);
  const roots = await c('settings get folders.roots', ['settings', 'get', 'folders.roots', '--json']);
  const rootsValue = JSON.parse(roots.stdout || '{}').value;
  assertion('the command line reads back the folder the Settings window saved', roots.exit === 0 && comparable(rootsValue) === comparable(dirs.reports), {exit: roots.exit, value: typeof rootsValue === 'string' ? rootsValue.replace(scratch, '<scratch>') : rootsValue});
  const after = await c('search the scanned folder', ['search', 'Kvartální']);
  assertion('command-line search finds the report in the saved Windows folder', after.exit === 0 && after.stdout.includes(SCANNED.title), {exit: after.exit});
  assertion('no Git repository appeared and the data folder holds the settings file', !fs.existsSync(path.join(inbox, '.git')) && fs.existsSync(path.join(dirs.data, 'settings.json')));
  report.passed = true;
}

// ---------- end of run ----------

async function cleanup() {
  for (const child of children) killTree(child);
  await sleep(WIN ? 1500 : 200);
  if (scratch) { try { fs.rmSync(scratch, {recursive: true, force: true, maxRetries: 12, retryDelay: 500}); } catch (e) { report.cleanupError = redact(e.message); } report.scratchRemoved = !fs.existsSync(scratch); }
}

async function finish(error) {
  if (finished) return;
  finished = true;
  if (error) { report.error = redact(error.stack?.split('\n').slice(0, 3).join(' | ') || error.message); report.passed = false; }
  await cleanup();
  report.finishedAt = new Date().toISOString();
  const json = JSON.stringify(report, null, 2);
  if (process.env.RS_REPORT_FILE) try { fs.writeFileSync(process.env.RS_REPORT_FILE, json + '\n'); } catch {}
  if (process.env.GITHUB_STEP_SUMMARY) try {
    const failed = report.assertions.filter(a => !a.pass).map(a => `- FAILED: ${a.name}`).join('\n');
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `## ReportScout Windows release check: ${report.passed ? 'passed' : 'FAILED'}\n\n${report.assertions.filter(a => a.pass).length} assertions passed.${error ? `\n\n${redact(error.message)}` : ''}\n${failed}\n\n\`\`\`json\n${json.length < 900000 ? json : json.slice(0, 900000)}\n\`\`\`\n`);
  } catch {}
  process.stdout.write(json + '\n', () => process.exit(report.passed ? 0 : 1));
}

// ---------- self-test of the parsers (any OS) ----------

function selfTest() {
  const pe = Buffer.alloc(8192); pe.write('MZ'); pe.writeUInt32LE(0x80, 0x3c); pe.write('PE\0\0', 0x80, 'latin1'); pe.writeUInt16LE(0x8664, 0x84); pe.writeUInt16LE(0x22, 0x80 + 22);
  pe.writeUInt16LE(0x20b, 0x80 + 24); pe.writeUInt16LE(2, 0x80 + 24 + 68);
  assert.deepEqual({...readPE(pe)}, {machine: '0x8664', x64: true, pe32plus: true, isDll: false, executable: true, subsystem: 2, certificateTableBytes: 0});
  pe.writeUInt32LE(4096, 0x80 + 24 + 112 + 36); assert.equal(readPE(pe).certificateTableBytes, 4096);
  assert.throws(() => readPE(Buffer.alloc(8192)), /no MZ/);
  const tmp = fs.mkdtempSync(path.join(fs.realpathSync.native(os.tmpdir()), 'rs-selftest-'));
  try {
    const body = Buffer.from('{"name":"x","version":"0.3.3"}');
    const index = Buffer.from(JSON.stringify({files: {'package.json': {size: body.length, offset: '0'}, src: {files: {'a.js': {size: 1, offset: String(body.length)}}}}}));
    const head = Buffer.alloc(16); const pad = (index.length + 3) & ~3; head.writeUInt32LE(4, 0); head.writeUInt32LE(8 + pad, 4); head.writeUInt32LE(4 + pad, 8); head.writeUInt32LE(index.length, 12);
    fs.writeFileSync(path.join(tmp, 'app.asar'), Buffer.concat([head, index, Buffer.alloc(pad - index.length), body, Buffer.from('z')]));
    assert.equal(JSON.parse(readAsarFile(path.join(tmp, 'app.asar'), 'package.json')).version, '0.3.3');
    assert.equal(readAsarFile(path.join(tmp, 'app.asar'), 'src/a.js').toString(), 'z');
    assert.throws(() => readAsarFile(path.join(tmp, 'app.asar'), 'src'), /not packed/);
  } finally { fs.rmSync(tmp, {recursive: true, force: true}); }
  assert.deepEqual(unsafeZipEntries(['ReportScout.exe', 'resources/app.asar', '../x', 'a/../b', '/etc/x', 'C:\\x', 'a\\..\\b']), ['../x', 'a/../b', '/etc/x', 'C:\\x', 'a\\..\\b']);
  token = 'ghs_SECRET';
  assert.equal(redact('Bearer ghs_SECRET at https://objects.githubusercontent.com/x?sig=abc ok'), 'Bearer <token> at <url> ok');
  assert.equal(comparable('C:\\Users\\Zprávy\\'), 'c:/users/zprávy');
  assert.match(html('T', 'B'), /<title>T<\/title>/);
  console.log(JSON.stringify({selfTest: 'passed'}));
}

if (process.argv.includes('--self-test')) selfTest();
else {
  const deadline = setTimeout(() => { void finish(new Error(`The check ran past its ${TOTAL_MS / 60000}-minute limit`)); }, TOTAL_MS);
  deadline.unref();
  for (const sig of ['SIGINT', 'SIGTERM']) process.once(sig, () => void finish(new Error(`Interrupted by ${sig}`)));
  main().then(() => finish(), e => finish(e));
}
