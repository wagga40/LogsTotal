// Exercise the actual queue shipped to the browser, including reordered responses.
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { it } from 'node:test';
import vm from 'node:vm';

const source = readFileSync(new URL('../../app/static/upload.js', import.meta.url), 'utf8');
const file = (name, size = 1024) => ({ name, size, slice: () => ({}) });
const flush = async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); };

function setup() {
  const requests = [], xhrs = [], timers = new Map();
  let timerId = 0;
  class XHR {
    upload = {}; headers = {}; responseHeaders = {};
    constructor() { xhrs.push(this); }
    open(method, url) { this.method = method; this.url = url; }
    setRequestHeader(k, v) { this.headers[k] = v; }
    getResponseHeader(k) { return this.responseHeaders[k]; }
    send(body) { this.body = body; }
    abort() { return this.onabort(); }
    respond(status, data, headers = {}) {
      this.status = status; this.responseText = JSON.stringify(data); this.responseHeaders = headers;
      return this.onload();
    }
  }
  const context = vm.createContext({
    document: { hidden: false, getElementById: id => id === 'workflows-data' ? { textContent: JSON.stringify([
      { id: 1, name: 'Windows', log_types: ['evtx'], is_default: true },
      { id: 2, name: 'Syslog', log_types: ['syslog'] },
    ]) } : null },
    window: { location: {}, addEventListener() {}, removeEventListener() {} },
    crypto: webcrypto, Uint8Array, AbortController, XMLHttpRequest: XHR,
    setTimeout: (fn, delay) => { timers.set(++timerId, { fn, delay }); return timerId; },
    clearTimeout: id => timers.delete(id),
    FormData: class { values = []; append(...args) { this.values.push(args); } },
    fetch: (url, options) => new Promise((resolve, reject) => requests.push({ url, options, resolve, reject })),
  });
  vm.runInContext(source, context);
  const uploader = context.uploader();
  uploader.maxBytes = 1024 * 1024; uploader.$nextTick = fn => fn();
  const respond = (index, type) => requests[index].resolve({ ok: true, json: async () => ({ log_type: type, label: type.toUpperCase() }) });
  const start = () => uploader.submitUpload({ target: { getAttribute: () => '/upload' } });
  return { uploader, requests, xhrs, timers, respond, start, context };
}

it('detects mixed files independently even when responses arrive out of order', async () => {
  const { uploader, respond } = setup();
  uploader.addFiles([file('windows.evtx'), file('linux.log')]);
  respond(1, 'syslog'); await flush();
  respond(0, 'evtx'); await flush();
  assert.deepEqual(Array.from(uploader.rows, r => r.workflowId), ['1', '2']);
  assert.equal(uploader.readyCount, 2);
});

it('ignores a preview after its row is removed and does not overwrite another file', async () => {
  const { uploader, respond } = setup();
  uploader.addFiles([file('old.evtx'), file('current.log')]);
  const old = uploader.rows[0]; uploader.remove(old);
  respond(1, 'syslog'); await flush(); respond(0, 'unknown'); await flush();
  assert.equal(uploader.rows.length, 1);
  assert.equal(uploader.rows[0].detectedType, 'syslog');
});

it('bounds previews to two, selection to fifty, and keeps equal filenames separate', async () => {
  const { uploader, requests, respond } = setup();
  uploader.addFiles(Array.from({ length: 55 }, () => file('Security.evtx')));
  assert.equal(uploader.rows.length, 50); assert.equal(requests.length, 2);
  assert.equal(new Set(uploader.rows.map(r => r.id)).size, 50);
  assert.match(uploader.error, /5 extra files/);
  respond(0, 'evtx'); await flush();
  assert.equal(requests.length, 3); assert.equal(uploader.previewActive, 2);
});

it('uses the configured selection limit for both the picker and cumulative drops', () => {
  const { uploader } = setup();
  uploader.$el = { dataset: { maxFiles: '3', maxBytes: '1048576' } };
  uploader.init();
  const target = { files: [file('one.evtx'), file('two.evtx')], value: 'chosen' };
  uploader.onFileChange({ target });
  assert.equal(target.value, '');
  uploader.onDrop({ dataTransfer: { files: [file('three.evtx'), file('four.evtx')] } });
  assert.equal(uploader.rows.length, 3);
  assert.match(uploader.error, /Select up to 3 files\. 1 extra file was not added/);
  uploader.remove(uploader.rows[0]);
  uploader.onDrop({ dataTransfer: { files: [file('replacement.evtx')] } });
  assert.equal(uploader.rows.length, 3); assert.equal(uploader.error, '');
});

it('can raise the file limit above fifty or restrict it to one', () => {
  for (const limit of [1, 125]) {
    const { uploader } = setup();
    uploader.$el = { dataset: { maxFiles: String(limit), maxBytes: '1048576' } };
    uploader.init();
    uploader.addFiles(Array.from({ length: limit + 1 }, (_, i) => file(`${i}.evtx`)));
    assert.equal(uploader.rows.length, limit);
    assert.equal(uploader.previewActive, Math.min(2, limit));
  }
});

it('preview failure allows server detection while unknown types need a compatible workflow', async () => {
  const { uploader, requests, respond } = setup();
  uploader.addFiles([file('unavailable.evtx'), file('unknown.bin')]);
  requests[0].reject(new Error('network')); respond(1, 'unknown'); await flush();
  assert.equal(uploader.rows[0].state, 'ready');
  assert.equal(uploader.rows[0].override, 'auto');
  assert.equal(uploader.rows[1].state, 'invalid');
  uploader.rows[1].override = 'syslog'; uploader.syncWorkflow(uploader.rows[1]);
  assert.equal(uploader.rows[1].state, 'ready'); assert.equal(uploader.rows[1].workflowId, '2');
});

it('preserves a manual type override while a preview is in flight', async () => {
  const { uploader, respond } = setup();
  uploader.addFiles([file('manual.log')]);
  uploader.rows[0].override = 'syslog'; uploader.syncWorkflow(uploader.rows[0]);
  respond(0, 'evtx'); await flush();
  assert.equal(uploader.rows[0].workflowId, '2');
});

it('does not start a partial selection while previews are still running', async () => {
  const { uploader, respond, start, xhrs } = setup();
  uploader.addFiles([file('a.evtx'), file('b.evtx')]);
  respond(0, 'evtx'); await flush(); await start();
  assert.equal(xhrs.length, 0);
});

it('uploads at most two files, keeps successes, and continues after a file rejection', async () => {
  const { uploader, respond, start, xhrs } = setup();
  uploader.addFiles([file('a.evtx'), file('b.evtx'), file('c.evtx')]);
  respond(0, 'evtx'); respond(1, 'evtx'); await flush(); respond(2, 'evtx'); await flush();
  await start(); assert.equal(xhrs.length, 2);
  await xhrs[0].respond(202, { job_id: 1, status: 'pending', reused: false }); await flush();
  assert.equal(xhrs.length, 3); assert.equal(uploader.acceptedCount, 1);
  await xhrs[1].respond(400, { detail: 'Workflow changed.' }); await flush();
  await xhrs[2].respond(200, { job_id: 3, status: 'completed', reused: true }); await flush();
  assert.equal(uploader.submitting, false); assert.equal(uploader.acceptedCount, 2);
  assert.equal(uploader.rows[1].state, 'error'); assert.equal(uploader.rows[2].reused, true);
  assert.equal(uploader.retryCount, 1);
});

it('weights transfer progress by bytes and labels server acceptance separately', async () => {
  const { uploader, respond, start, xhrs } = setup();
  uploader.addFiles([file('small.evtx', 100), file('large.evtx', 900)]);
  respond(0, 'evtx'); respond(1, 'evtx'); await flush(); await start();
  xhrs[0].upload.onprogress({ lengthComputable: true, loaded: 1000, total: 1000 });
  assert.equal(uploader.percent, 10);
  xhrs[1].upload.onprogress({ lengthComputable: true, loaded: 500, total: 1000 });
  assert.equal(uploader.percent, 55);
  xhrs[1].upload.onload();
  assert.equal(uploader.rows[1].state, 'accepting'); assert.equal(uploader.acceptedCount, 0);
});

it('a 429 pauses the collection and honours Retry-After', async () => {
  const { uploader, respond, start, xhrs, timers } = setup();
  uploader.addFiles([file('a.evtx'), file('b.evtx'), file('c.evtx')]);
  respond(0, 'evtx'); respond(1, 'evtx'); await flush(); respond(2, 'evtx'); await flush(); await start();
  await xhrs[0].respond(429, { detail: 'busy' }, { 'Retry-After': '20' }); await flush();
  await xhrs[1].respond(202, { job_id: 2, status: 'completed' }); await flush();
  assert.equal(xhrs.length, 2); assert.equal(uploader.rows[0].state, 'waiting');
  assert.ok([...timers.values()].some(t => t.delay > 19000 && t.delay <= 20000));
  uploader.pauseUntil = 0; uploader.pump(); assert.equal(xhrs.length, 4);
});

it('stopping uploads leaves accepted jobs and identifies uncertain outcomes', async () => {
  const { uploader, respond, start, xhrs } = setup();
  uploader.addFiles([file('a.evtx'), file('b.evtx'), file('c.evtx'), file('d.evtx')]);
  respond(0, 'evtx'); respond(1, 'evtx'); await flush(); respond(2, 'evtx'); respond(3, 'evtx'); await flush(); await start();
  await xhrs[0].respond(202, { job_id: 1, status: 'running' }); await flush();
  uploader.cancelUpload(); await flush();
  assert.equal(uploader.rows[0].jobId, 1);
  assert.equal(uploader.rows[1].state, 'uncertain'); assert.equal(uploader.rows[3].state, 'stopped');
  assert.equal(uploader.submitting, false); assert.equal(xhrs.length, 3);
});

it('reconciles a lost authenticated response without uploading a second job', async () => {
  const { uploader, respond, start, xhrs, requests } = setup();
  uploader.signedIn = true;
  uploader.addFiles([file('a.evtx'), file('b.evtx')]);
  respond(0, 'evtx'); respond(1, 'evtx'); await flush(); await start();
  const originalKey = uploader.rows[0].key;
  const pending = xhrs[0].onerror(); await flush();
  assert.equal(requests[2].url, '/api/v1/submissions/' + originalKey);
  requests[2].resolve({ ok: true, json: async () => ({ job_id: 9, status: 'running', reused: false }) });
  await pending; await flush();
  assert.equal(uploader.rows[0].jobId, 9); assert.equal(xhrs.length, 2);
});

it('polls all active jobs together and stops at terminal states', async () => {
  const { uploader, respond, start, xhrs, requests, timers } = setup();
  uploader.addFiles([file('a.evtx'), file('b.evtx')]);
  respond(0, 'evtx'); respond(1, 'evtx'); await flush(); await start();
  await xhrs[0].respond(202, { job_id: 10, status: 'pending' });
  await xhrs[1].respond(202, { job_id: 11, status: 'running' }); await flush();
  assert.equal(timers.size, 1);
  const [id, timer] = [...timers][0]; timers.delete(id); timer.fn(); await flush();
  assert.equal(requests[2].url, '/api/v1/jobs?ids=10,11');
  requests[2].resolve({ ok: true, json: async () => ({ jobs: [{ job_id: 10, status: 'completed' }, { job_id: 11, status: 'partial' }], unavailable_ids: [] }) });
  await flush(); assert.equal(timers.size, 0); assert.equal(uploader.rows[1].jobStatus, 'partial');
});

it('rotates large selections through bounded status requests as earlier jobs finish', async () => {
  const { uploader, requests } = setup();
  uploader.rows = Array.from({ length: 125 }, (_, i) => ({jobId: i + 1, jobStatus: 'running'}));
  for (const [index, start, end] of [[0, 1, 50], [1, 51, 100], [2, 101, 125], [3, 51, 100]]) {
    const pending = uploader.poll(); await flush();
    const ids = requests[index].url.split('=')[1].split(',').map(Number);
    assert.equal(ids[0], start); assert.equal(ids.at(-1), end); assert.ok(ids.length <= 50);
    requests[index].resolve({ ok: true, json: async () => ({
      jobs: ids.map(job_id => ({ job_id, status: index === 0 ? 'completed' : 'running' })), unavailable_ids: []
    }) });
    await pending;
  }
});

it('keeps the original key when a server error and receipt lookup both fail', async () => {
  const { uploader, respond, start, xhrs, requests } = setup();
  uploader.signedIn = true;
  uploader.addFiles([file('a.evtx'), file('b.evtx')]);
  respond(0, 'evtx'); respond(1, 'evtx'); await flush(); await start();
  const originalKey = uploader.rows[0].key;
  const failed = xhrs[0].respond(502, {}); await flush();
  requests[2].reject(new Error('offline')); await failed; await flush();
  assert.equal(uploader.rows[0].state, 'uncertain');
  assert.equal(uploader.rows[0].key, originalKey);
  assert.equal(uploader.retryCount, 0, 'bulk retry must not turn an uncertain response into a fresh submission');
});

it('freezes selection until case creation and stopped requests have settled', async () => {
  const { uploader, respond, start, requests } = setup();
  uploader.addFiles([file('a.evtx')]); respond(0, 'evtx'); await flush();
  uploader.caseMode = 'new'; uploader.caseName = 'Investigation';
  const pending = start(); await flush();
  const row = uploader.rows[0];
  assert.equal(uploader.caseBusy, true);
  uploader.addFiles([file('b.evtx')]); uploader.remove(row);
  assert.equal(uploader.rows.length, 1); assert.equal(uploader.editable(row), false);
  requests[1].resolve({ ok: true, json: async () => ({ case_id: 42 }) });
  await pending; await flush();
  assert.equal(row.snapshot.case_id, 42);
  uploader.cancelUpload();
  uploader.addFiles([file('c.evtx')]); uploader.remove(row);
  assert.equal(uploader.rows.length, 1);
  await flush();
  assert.equal(uploader.selectionLocked, false);
});

it('submits the whole selection together after invalid files are resolved', async () => {
  const { uploader, respond, start, xhrs } = setup();
  uploader.addFiles([file('a.evtx'), file('unknown.bin')]);
  respond(0, 'evtx'); respond(1, 'unknown'); await flush();
  await start();
  assert.equal(xhrs.length, 0);
  assert.equal(uploader.canSubmit, false);
  uploader.issuesOnly = true;
  assert.equal(uploader.visibleRows.length, 1);
  uploader.rows[1].override = 'syslog'; uploader.syncWorkflow(uploader.rows[1]);
  assert.equal(uploader.canSubmit, true);
  await start();
  assert.equal(xhrs.length, 2); assert.equal(uploader.hasSubmitted, true);
  assert.equal(uploader.issuesOnly, false);
});

it('starts the next transfer before receipt confirmation, with at most four requests', async () => {
  const { uploader, respond, start, xhrs } = setup();
  uploader.addFiles(Array.from({ length: 6 }, (_, i) => file(`${i}.evtx`)));
  for (let i = 0; i < 6; i++) { respond(i, 'evtx'); await flush(); }
  await start(); assert.equal(xhrs.length, 2);
  xhrs[0].upload.onload();
  assert.equal(xhrs.length, 3); assert.equal(uploader.acceptedCount, 0);
  xhrs[1].upload.onload();
  assert.equal(xhrs.length, 4); assert.equal(uploader.transferringCount, 2);
  xhrs[2].upload.onload();
  assert.equal(xhrs.length, 4); assert.equal(uploader.active, 4);
  await xhrs[0].respond(202, { job_id: 1, status: 'pending' }); await flush();
  assert.equal(xhrs.length, 5); assert.equal(uploader.transferringCount, 2);
  assert.equal(uploader.active, 4);
});

it('respects a server configured for one upload slot', async () => {
  const { uploader, respond, start, xhrs } = setup();
  uploader.requestSlots = 1;
  uploader.addFiles([file('a.evtx'), file('b.evtx')]);
  respond(0, 'evtx'); respond(1, 'evtx'); await flush(); await start();
  assert.equal(xhrs.length, 1);
  xhrs[0].upload.onload(); assert.equal(xhrs.length, 1);
  await xhrs[0].respond(202, { job_id: 1, status: 'pending' }); await flush();
  assert.equal(xhrs.length, 2);
});

it('only says it is safe to close after every receipt, without waiting for analysis', async () => {
  const { uploader, respond, start, xhrs } = setup();
  uploader.addFiles([file('a.evtx'), file('b.evtx')]);
  respond(0, 'evtx'); respond(1, 'evtx'); await flush(); await start();
  xhrs[0].upload.onload(); xhrs[1].upload.onload();
  assert.equal(uploader.percent, 100); assert.equal(uploader.allSubmitted, false);
  assert.equal(uploader.submissionTitle, 'Finalizing submissions…');
  assert.match(uploader.submissionHint, /Waiting for the server to confirm/);
  await xhrs[0].respond(202, { job_id: 1, status: 'running' }); await flush();
  assert.equal(uploader.allSubmitted, false);
  await xhrs[1].respond(202, { job_id: 2, status: 'pending' }); await flush();
  assert.equal(uploader.allSubmitted, true); assert.equal(uploader.selectionLocked, false);
  assert.match(uploader.submissionHint, /You can close this tab/);
  assert.equal(uploader.submissionTitle, '2 files submitted');
  uploader.startOver();
  assert.equal(uploader.hasSubmitted, false); assert.equal(uploader.rows.length, 0);
  assert.equal(uploader.caseLocked, false);
});

it('does not call a partially failed selection complete even when all bytes were sent', async () => {
  const { uploader, respond, start, xhrs } = setup();
  uploader.addFiles([file('a.evtx'), file('b.evtx')]);
  respond(0, 'evtx'); respond(1, 'evtx'); await flush(); await start();
  xhrs[0].upload.onload(); xhrs[1].upload.onload();
  await xhrs[0].respond(202, { job_id: 1, status: 'pending' });
  await xhrs[1].respond(400, { detail: 'Incompatible workflow' }); await flush();
  assert.equal(uploader.percent, 100); assert.equal(uploader.allSubmitted, false);
  assert.equal(uploader.submissionTitle, '1 of 2 files submitted');
  assert.match(uploader.submissionHint, /Review the remaining files/);
});

// ── How a row presents its state ────────────────────────────────────────────
//
// The template colours a row from `tone()` alone, draws `glyph()` through the shared icon
// dictionary and reuses the job-status `.badge-*` classes. These tables are the contract:
// a state that maps to the wrong tone renders a perfectly styled row in the wrong colour,
// which no route test can see.

const row = (state, extra = {}) => ({ id: state + Math.random(), name: `${state}.log`, file: file(`${state}.log`, 2048),
  state, override: 'auto', detectedType: 'syslog', workflowId: '2', loaded: 0, message: '', jobId: null, jobStatus: '', ...extra });

it('maps every upload state to one tone, glyph and status badge', () => {
  const { uploader } = setup();
  const expected = {
    preview: ['busy', 'spinner', 'badge-running'],
    ready: ['idle', 'file', 'badge-pending'],
    invalid: ['warn', 'alert', 'badge-partial'],
    queued: ['idle', 'clock', 'badge-pending'],
    waiting: ['idle', 'clock', 'badge-pending'],
    uploading: ['busy', 'spinner', 'badge-running'],
    accepting: ['busy', 'spinner', 'badge-running'],
    stopped: ['warn', 'alert', 'badge-partial'],
    error: ['bad', 'fail', 'badge-failed'],
    uncertain: ['warn', 'alert', 'badge-partial'],
  };
  for (const [state, [tone, glyph, badge]] of Object.entries(expected)) {
    const r = row(state);
    assert.deepEqual([uploader.tone(r), uploader.glyph(r), uploader.badge(r)], [tone, glyph, badge], state);
  }
  const tooLarge = row('invalid', { file: file('huge.evtx', uploader.maxBytes + 1) });
  assert.deepEqual([uploader.tone(tooLarge), uploader.glyph(tooLarge), uploader.badge(tooLarge)], ['bad', 'fail', 'badge-failed']);
});

it('reports an accepted file by its job status, using the /jobs badge palette', () => {
  const { uploader } = setup();
  const expected = {
    pending: ['ok', 'check', 'badge-pending'],
    running: ['ok', 'check', 'badge-running'],
    completed: ['ok', 'check', 'badge-completed'],
    partial: ['warn', 'alert', 'badge-partial'],
    failed: ['bad', 'fail', 'badge-failed'],
    cancelled: ['idle', 'file', 'badge-cancelled'],
    unavailable: ['bad', 'fail', 'badge-failed'],
    '': ['ok', 'check', 'badge-completed'],
  };
  for (const [jobStatus, [tone, glyph, badge]] of Object.entries(expected)) {
    const r = row('accepted', { jobId: 7, jobStatus });
    assert.deepEqual([uploader.tone(r), uploader.glyph(r), uploader.badge(r)], [tone, glyph, badge], jobStatus || '(no status yet)');
  }
});

it('labels fit a pill, and the note never repeats the label', () => {
  const { uploader } = setup();
  assert.equal(uploader.label(row('uploading', { loaded: 1024 })), 'Uploading 50%');
  assert.equal(uploader.label(row('invalid', { detectedType: 'unknown' })), 'Needs a log type');
  assert.equal(uploader.label(row('invalid', { override: 'auditd' })), 'No workflow');
  assert.equal(uploader.label(row('invalid', { file: file('huge.evtx', uploader.maxBytes + 1) })), 'Too large');
  for (const state of ['preview', 'ready', 'queued', 'waiting', 'uploading', 'accepting', 'stopped', 'error', 'uncertain']) {
    const r = row(state);
    assert.ok(uploader.label(r) && uploader.label(r).length <= 24, `${state}: ${uploader.label(r)}`);
  }
  const waiting = row('waiting', { message: 'The server is busy; retrying automatically.' });
  assert.notEqual(uploader.note(waiting), uploader.label(waiting));
  assert.match(uploader.note(row('invalid', { detectedType: 'unknown' })), /Choose a log type/);
  assert.match(uploader.note(row('invalid', { override: 'auditd' })), /No workflow accepts/);
  assert.equal(uploader.note(row('ready')), '');
});

it('formats sizes from bytes to gigabytes', () => {
  const { uploader } = setup();
  assert.equal(uploader.formatBytes(0), '0 B');
  assert.equal(uploader.formatBytes(29), '29 B');
  assert.equal(uploader.formatBytes(1536), '1.5 KB');
  assert.equal(uploader.formatBytes(5 * 1048576), '5.0 MB');
  assert.equal(uploader.formatBytes(3 * 1073741824), '3.00 GB');
});

it('the badge count, the legend and the progress bar agree about every row', () => {
  const { uploader } = setup();
  uploader.rows = [row('accepted', { jobId: 1, jobStatus: 'failed' }), row('accepted', { jobId: 2, jobStatus: 'running' }),
    row('uploading', { loaded: 512 }), row('accepting'), row('queued'), row('waiting'), row('stopped'), row('uncertain'),
    row('invalid', { detectedType: 'unknown' }), row('error'), row('invalid', { file: file('huge.evtx', uploader.maxBytes + 1) })];
  const tones = ['idle', 'busy', 'ok', 'warn', 'bad'];
  // An accepted file counts as submitted in the bar whatever its analysis did.
  assert.equal(tones.reduce((n, t) => n + uploader.phaseCount(t), 0), uploader.rows.length);
  assert.equal(uploader.phaseCount('ok'), uploader.acceptedCount);
  assert.equal(uploader.phaseCount('warn') + uploader.phaseCount('bad'), uploader.attentionCount);
  const widths = tones.filter(t => t !== 'idle').map(t => Number(uploader.segment(t).match(/width:([\d.]+)%/)[1]));
  assert.ok(Math.abs(widths.reduce((a, b) => a + b, 0) - (1 - uploader.phaseCount('idle') / uploader.rows.length) * 100) < 1e-9);
  const legend = Array.from(uploader.summaryParts, p => `${p.tone}:${p.text}`);
  assert.deepEqual(legend, ['ok:2 submitted', 'busy:1 uploading', 'busy:1 finalizing', 'idle:2 queued', 'warn:3 need attention', 'bad:2 failed']);
  uploader.rows = [row('uncertain')];
  assert.deepEqual(Array.from(uploader.summaryParts, p => p.text), ['0 submitted', '1 needs attention']);
});

it('gives the submission panel one tone for the batch', async () => {
  const { uploader, respond, start, xhrs } = setup();
  uploader.addFiles([file('a.evtx'), file('b.evtx')]);
  respond(0, 'evtx'); respond(1, 'evtx'); await flush();
  assert.equal(uploader.panelTone, 'idle');
  await start();
  assert.equal(uploader.panelTone, 'busy');
  xhrs[0].upload.onload(); xhrs[1].upload.onload();
  await xhrs[0].respond(202, { job_id: 1, status: 'pending' });
  await xhrs[1].respond(400, { detail: 'Incompatible workflow' }); await flush();
  assert.equal(uploader.panelTone, 'warn');
  assert.equal(uploader.tone(uploader.rows[1]), 'bad');
});

// A browser runs `beforeunload` listeners synchronously when a script assigns
// `location.href`, so the guard sees the uploader exactly as it is at that assignment.
function withUnloadGuard(context, uploader) {
  const listeners = [], blocked = [];
  context.window.addEventListener = (type, fn) => { if (type === 'beforeunload') listeners.push(fn); };
  const unload = () => {
    let prevented = false;
    const event = { preventDefault() { prevented = true; }, returnValue: undefined };
    for (const fn of listeners) fn(event);
    return prevented || event.returnValue !== undefined;
  };
  let href = '';
  Object.defineProperty(context.window.location, 'href', {
    get: () => href,
    set: url => { if (unload()) blocked.push(url); else href = url; },
  });
  uploader.$el = { dataset: { maxFiles: '50', maxBytes: '1048576' } };
  uploader.init();
  return { unload, blocked, href: () => href };
}

it('a single-file submission opens its job without a leave-page prompt', async () => {
  const { uploader, respond, start, xhrs, context } = setup();
  const guard = withUnloadGuard(context, uploader);
  uploader.addFiles([file('a.evtx')]);
  respond(0, 'evtx'); await flush(); await start();
  await xhrs[0].respond(202, { job_id: 7, status: 'pending', reused: false, job_url: '/jobs/7' }); await flush();
  assert.deepEqual(guard.blocked, []);
  assert.equal(guard.href(), '/jobs/7');
});

it('a single-file receipt recovered after a lost response also opens its job unprompted', async () => {
  const { uploader, respond, start, xhrs, requests, context } = setup();
  const guard = withUnloadGuard(context, uploader);
  uploader.signedIn = true;
  uploader.addFiles([file('a.evtx')]);
  respond(0, 'evtx'); await flush(); await start();
  const pending = xhrs[0].onerror(); await flush();
  requests[1].resolve({ ok: true, json: async () => ({ job_id: 9, status: 'running', reused: false, job_url: '/jobs/9' }) });
  await pending; await flush();
  assert.deepEqual(guard.blocked, []);
  assert.equal(guard.href(), '/jobs/9');
});

it('still asks before leaving while a multi-file submission is in flight', async () => {
  const { uploader, respond, start, xhrs, context } = setup();
  const guard = withUnloadGuard(context, uploader);
  uploader.addFiles([file('a.evtx'), file('b.evtx')]);
  respond(0, 'evtx'); respond(1, 'evtx'); await flush(); await start();
  await xhrs[0].respond(202, { job_id: 1, status: 'pending', job_url: '/jobs/1' }); await flush();
  assert.equal(guard.href(), '', 'a multi-file submission stays on the page');
  assert.equal(guard.unload(), true, 'the second file is still uploading');
  await xhrs[1].respond(202, { job_id: 2, status: 'pending', job_url: '/jobs/2' }); await flush();
  assert.equal(guard.unload(), false, 'every file was accepted');
});
