// Loads the browser-targeted graph modules into a Node test process.
//
// They are classic scripts that assign one namespace to `window`, so there is no import to
// resolve — evaluating them against a stub global is enough, and it means the tests run the
// exact bytes the browser gets rather than a parallel ES-module copy that could drift.
//
// No package.json, no npm install: `node --test` is in the standard toolchain, and
// `task test:js` skips cleanly when node is absent (see Taskfile.yml).

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const STATIC = join(HERE, '..', '..', 'app', 'static');

// Deliberately `new Function` rather than `node:vm`. A vm context is a separate realm with
// its own intrinsics, so an array built inside it fails `deepStrictEqual` against one built
// out here — the assertion reports "same structure but not reference-equal", which is a
// property of the harness and not of the code under test. Same realm, same `Array`.
function loadModules() {
  const sandbox = {};
  sandbox.window = sandbox;
  const raf = (fn) => setTimeout(fn, 0);
  for (const name of ['graph-view.js', 'graph-algo.js']) {
    const src = readFileSync(join(STATIC, name), 'utf8');
    // eslint-disable-next-line no-new-func
    new Function('window', 'performance', 'requestAnimationFrame', 'cancelAnimationFrame', src)(sandbox, performance, raf, clearTimeout);
  }
  return sandbox;
}

const sandbox = loadModules();
export const View = sandbox.LogsTotalGraphView;
export const Algo = sandbox.LogsTotalGraphAlgo;

// `app.js` is the same kind of file — a classic script that hangs factories off `window` —
// but unlike the graph modules it wires a few listeners at load. Stub just enough `document`
// for those to attach and nothing more: the point is to run the exact bytes the browser
// gets, not a copy.
function loadAppJs() {
  const box = {};
  box.window = box;
  const noop = () => {};
  box.document = {
    readyState: 'complete',
    addEventListener: noop,
    body: { addEventListener: noop },
    querySelectorAll: () => [],
    // `setupConfirmDialog` runs at load and looks for its <dialog>; returning null is the
    // same "no dialog on this page" branch the browser takes on most pages.
    getElementById: () => null,
  };
  const src = readFileSync(join(STATIC, 'app.js'), 'utf8');
  // eslint-disable-next-line no-new-func
  new Function('window', 'document', 'fetch', src)(box, box.document, () => Promise.resolve({ ok: false }));
  return box;
}

const app = loadAppJs();

// ── A scriptable app.js sandbox, for the clipboard tests ─────────────────────
//
// Those need a *fresh* one each: they differ in whether `navigator.clipboard` exists at
// all, which is the entire subject. They also need `document.addEventListener` to record
// rather than drop, so the delegated copy handler can be handed a synthetic click, and a
// `createElement` that produces something the legacy copy path can select and remove.

/** The smallest element that behaves like one for the code under test. */
export function el(tag, attrs = {}) {
  const node = {
    tagName: (tag || 'div').toUpperCase(),
    children: [],
    parentElement: null,
    textContent: attrs.textContent || '',
    dataset: attrs.dataset || {},
    style: {},
    value: '',
    classes: new Set(attrs.classes || []),
    selected: false,
    selectionRange: null,
    focused: false,
    removed: false,
  };
  node.classList = {
    add: (c) => node.classes.add(c),
    remove: (c) => node.classes.delete(c),
    contains: (c) => node.classes.has(c),
  };
  node.setAttribute = () => {};
  node.select = () => {
    node.selected = true;
  };
  node.setSelectionRange = (a, b) => {
    node.selectionRange = [a, b];
  };
  node.focus = () => {
    node.focused = true;
  };
  node.remove = () => {
    node.removed = true;
    if (node.parentElement) {
      node.parentElement.children = node.parentElement.children.filter((c) => c !== node);
      node.parentElement = null;
    }
  };
  node.append = (...kids) => {
    for (const kid of kids) {
      kid.parentElement = node;
      node.children.push(kid);
    }
    return node;
  };
  node.appendChild = (kid) => {
    node.append(kid);
    return kid;
  };
  // Selectors here are only ever a tag name or one of the two copy-icon marker classes —
  // enough for what app.js asks, and deliberately not a CSS engine.
  node.querySelector = (sel) => {
    const match = (n) =>
      sel.startsWith('.') ? n.classes.has(sel.slice(1)) : n.tagName === sel.toUpperCase();
    const walk = (n) => {
      for (const kid of n.children) {
        if (match(kid)) return kid;
        const deeper = walk(kid);
        if (deeper) return deeper;
      }
      return null;
    };
    return walk(node);
  };
  node.closest = (sel) => {
    let cur = node;
    while (cur) {
      if (sel.startsWith('.') ? cur.classes.has(sel.slice(1)) : cur.tagName === sel.toUpperCase()) return cur;
      cur = cur.parentElement;
    }
    return null;
  };
  return node;
}

/** A fresh app.js evaluation with a scriptable `navigator` and `document`.
 *
 *  `opts.clipboard`  — the object to expose as `navigator.clipboard` (omit for the
 *                      insecure-context case, which is what this all exists for).
 *  `opts.execCommand`— what `document.execCommand('copy')` should do (omit for `false`;
 *                      pass `null` to remove the method entirely, as an old engine would).
 */
export function appSandbox(opts = {}) {
  const box = {};
  box.window = box;
  const listeners = {};
  const created = [];
  const body = el('body');
  const toastMessage = el('p', { classes: ['toast-message'] });
  const toast = el('div', { classes: ['hidden'] });
  toast.append(toastMessage);
  toast.querySelector = (sel) => (sel === '[data-toast-message]' ? toastMessage : null);

  const byId = { 'htmx-error-toast': toast, ...(opts.elements || {}) };

  const doc = {
    readyState: 'complete',
    activeElement: opts.activeElement || null,
    body: Object.assign(body, { addEventListener: () => {} }),
    addEventListener: (name, fn) => {
      (listeners[name] = listeners[name] || []).push(fn);
    },
    querySelectorAll: () => [],
    getElementById: (id) => byId[id] || null,
    createElement: (tag) => {
      const node = el(tag);
      created.push(node);
      return node;
    },
  };
  if (opts.execCommand !== null) {
    doc.execCommand = opts.execCommand || (() => false);
  }

  const navigator = opts.clipboard ? { clipboard: opts.clipboard } : {};

  // Timers are injected rather than borrowed from Node so the icon reset and the toast's
  // auto-dismiss are *assertable* — and so a test does not hold the process open for the
  // six seconds the real toast waits.
  const timers = [];
  const fakeSetTimeout = (fn, ms) => {
    timers.push({ fn, ms });
    return timers.length;
  };
  const fakeClearTimeout = (id) => {
    if (timers[id - 1]) timers[id - 1].cleared = true;
  };

  const src = readFileSync(join(STATIC, 'app.js'), 'utf8');
  // eslint-disable-next-line no-new-func
  new Function('window', 'document', 'navigator', 'fetch', 'setTimeout', 'clearTimeout', src)(
    box,
    doc,
    navigator,
    () => Promise.resolve({ ok: false }),
    fakeSetTimeout,
    fakeClearTimeout,
  );

  return {
    app: box,
    document: doc,
    timers,
    /** Run every timer scheduled so far that has not been cleared. */
    runTimers() {
      const due = timers.splice(0, timers.length);
      for (const t of due) if (!t.cleared) t.fn();
    },
    /** Every <textarea> the legacy path made, in order — including the removed ones. */
    created,
    /** Fire the delegated click handler at `target`. */
    click(target) {
      for (const fn of listeners.click || []) fn({ target });
    },
    toastText: () => toastMessage.textContent,
    toastHidden: () => toast.classes.has('hidden'),
  };
}

/** A `tagCombobox` instance with the Alpine/DOM surface it touches stubbed out.
 *
 *  `$refs.value` / `$refs.colorValue` are the two hidden inputs the component writes its
 *  submission into — reading them back is exactly what the server would receive. */
export function combobox(opts, known) {
  const c = app.tagCombobox(opts);
  c.$refs = { value: { value: '' }, colorValue: { value: '' }, tagInput: { focus: () => {} } };
  c.$nextTick = (fn) => fn();
  c.known = known || [];
  c.loaded = true;
  c.generation = 0;
  c.init();
  return c;
}

/** A `listValuesDrop` instance wrapped around a stub `values` textarea.
 *
 *  Reading that textarea back is reading exactly what the form would post — there is no
 *  upload route, so the box is the whole contract. */
export function valuesDrop(initial = '') {
  const d = app.listValuesDrop();
  const box = { value: initial, dispatchEvent: () => {} };
  d.$refs = { values: box, picker: {} };
  d.box = box;
  return d;
}

/** A `conditionEditor` instance with just enough scope to tokenise.
 *
 *  `scope` is set on the instance here because in the browser it is inherited from the
 *  enclosing form's `x-data` through Alpine's scope chain, which this harness has no
 *  reason to model — the tokenizer only ever reads it. */
export function condition(scope, grammar) {
  const c = app.conditionEditor({ grammar });
  c.scope = scope || 'entity';
  c.$refs = {};
  c.$nextTick = (fn) => fn();
  return c;
}

/** `[text, cssClass]` per token, which is what the overlay actually paints. */
export function painted(c, raw) {
  return c.tokenize(raw).map((t) => [t.text, t.cls]);
}

/** What the form would post: `[names, colours]`. */
export function submitted(c) {
  return [c.$refs.value.value, c.$refs.colorValue.value];
}

// A schema shaped exactly like `graph_payload.client_schema()`. Regenerated — and checked
// against the real thing — by `test_graph_client_contract.py::test_js_fixture_schema_matches_client_schema`,
// so a new entity type or attribute cannot silently desynchronise the JS tests.
export const schema = JSON.parse(readFileSync(join(HERE, 'schema.fixture.json'), 'utf8'));

// Build a columnar payload the way the server would, from readable specs.
export function payload(spec) {
  const nodes = spec.nodes || [];
  const edges = spec.edges || [];
  const words = [];
  const tg = [];
  nodes.forEach((n, i) => {
    if (!n.tags || !n.tags.length) return;
    const row = [i];
    for (const tag of n.tags) {
      let slot = words.indexOf(tag);
      if (slot === -1) {
        slot = words.length;
        words.push(tag);
      }
      row.push(slot);
    }
    tg.push(row);
  });

  const n = {
    id: nodes.map((_x, i) => i + 1),
    lb: nodes.map((x) => x.label),
    ty: nodes.map((x) => schema.types.indexOf(x.type)),
    sub: nodes.map((x) => (x.subtype ? schema.subtypes.indexOf(x.subtype) + 1 : 0)),
    fl: nodes.map((x) => (x.flags || []).reduce((acc, f) => acc | schema.flags[f], 0)),
    jc: nodes.map((x) => x.jobCount || 0),
  };
  if (nodes.some((x) => x.severity !== undefined)) {
    n.sv = nodes.map((x) => (x.severity ? schema.severities.indexOf(x.severity) + 1 : 0));
  }
  if (nodes.some((x) => x.tactic !== undefined)) {
    n.tc = nodes.map((x) => (x.tactic ? schema.tactics.indexOf(x.tactic) + 1 : 0));
  }
  if (tg.length) n.tg = tg;
  if (spec.matches) n.mt = spec.matches;
  if (spec.matchesPartial) n.mt_partial = true;

  const out = {
    v: 1,
    scope: spec.scope || 'entity',
    focal: spec.focal === undefined ? null : spec.focal,
    n: n,
    e: {
      s: edges.map((x) => x[0]),
      t: edges.map((x) => x[1]),
      k: edges.map((x) => codeFor(x[2])),
      w: edges.map((x) => x[3] || 1),
    },
    defaults: { hidden_types: spec.hiddenTypes || [] },
    stats: spec.stats || {},
  };
  if (words.length) out.dict = { tags: words };
  return out;
}

function codeFor(kind) {
  const plain = schema.edge_kinds.indexOf(kind);
  if (plain !== -1) return plain;
  return schema.typed_base + schema.rels.indexOf(kind);
}

// A view state with the schema attached and the given overrides applied.
export function state(overrides) {
  return Object.assign(View.defaultState(), { schema: schema }, overrides || {});
}
