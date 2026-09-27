// LogsTotal — minimal helpers

// ── Copying to the clipboard ─────────────────────────────────────────────────
//
// `navigator.clipboard` exists only in a **secure context** — HTTPS, or http on
// localhost/127.0.0.1. LogsTotal is deliberately runnable over plain HTTP on a real
// hostname (`COOKIE_INSECURE=true`, Docker without the `proxy` profile), and there the
// whole API is `undefined`: a direct `navigator.clipboard.writeText(…)` throws
// `TypeError: can't access property "writeText"`, and a guarded one silently does nothing.
//
// So the API is tried, and `document.execCommand('copy')` over an off-screen <textarea>
// is the fallback: deprecated, and the only thing that works outside a secure context.
// It needs transient user activation, which every element-sourced call site has (they
// are click handlers). The two IOC packs copy *after* a `fetch`, where the activation
// may have lapsed — that is what the rejection path is for, and why it is a rejection
// and not a silent return.
function ltCopy(text) {
  const value = text == null ? '' : String(text);
  const clip = navigator.clipboard;
  const attempt =
    clip && typeof clip.writeText === 'function'
      // `.catch` rather than a bare availability check: a browser can expose the API and
      // still reject the write — denied permission, or a document that is not focused.
      ? clip.writeText(value).catch(() => legacyCopy(value))
      : legacyCopy(value);
  return attempt.catch((err) => {
    ltToast("Couldn't copy — this browser blocks clipboard access on an insecure page. Select the text and press Ctrl/⌘-C.");
    throw err;
  });
}
window.ltCopy = ltCopy;

// The <textarea> has to be *selectable*, so it cannot be `hidden` or `display:none`.
// Off-screen and transparent is the compromise; `position:fixed` keeps it out of the
// scroll flow so the page cannot jump.
//
// **This runs synchronously inside the click handler, and it has to.** Firefox allows
// `execCommand('copy')` only from a user-generated event handler; a `new Promise`
// executor runs synchronously, so `execCommand` below is still inside the handler's own
// call stack. Awaiting anything before reaching it — a fetch, or even a stray `await` —
// spends the user activation and turns every copy into a refusal.
function legacyCopy(value) {
  return new Promise((resolve, reject) => {
    if (typeof document.execCommand !== 'function') {
      reject(new Error('clipboard-unavailable'));
      return;
    }
    const restore = document.activeElement;
    const ta = document.createElement('textarea');
    ta.value = value;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.top = '-1000px';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    let ok = false;
    try {
      ta.select();
      // iOS Safari ignores select() on a readonly field; the explicit range is what it
      // honours.
      if (typeof ta.setSelectionRange === 'function') ta.setSelectionRange(0, value.length);
      ok = document.execCommand('copy') === true;
    } catch (e) {
      ok = false;
    } finally {
      // Removed on every path, the throw included: a leaked textarea accumulates one per
      // click, and would keep a copy of whatever was in it — an API token, say — alive in
      // the DOM.
      ta.remove();
      if (restore && typeof restore.focus === 'function') restore.focus();
    }
    if (ok) resolve();
    else reject(new Error('clipboard-unavailable'));
  });
}

// Delegated click handler for every copy button in the app; they all come from
// `partials/_copy_button.html`. The source is named either by id (`data-copy-target`) or
// by a selector resolved among the button's siblings (`data-copy-from`) — the second
// exists for `_process_tree.html`, whose buttons are rendered per node by a macro and so
// have nothing unique to point an id at.
//
// The two icons are `.logstotal-copy-icon-default` (clipboard) and
// `.logstotal-copy-icon-done` (check).
document.addEventListener('click', (event) => {
  const btn = event.target.closest('.logstotal-copy-btn');
  if (!btn) return;
  const source = copySourceFor(btn);
  if (!source) return;
  ltCopy(source.textContent || '').then(
    // Inside the fulfil handler, so the check mark means it *copied*. Swapped
    // unconditionally, on an insecure page it would confirm a write that threw.
    () => {
      const def = btn.querySelector('.logstotal-copy-icon-default');
      const done = btn.querySelector('.logstotal-copy-icon-done');
      if (def) def.classList.add('hidden');
      if (done) done.classList.remove('hidden');
      setTimeout(() => {
        if (def) def.classList.remove('hidden');
        if (done) done.classList.add('hidden');
      }, 2000);
    },
    // `ltCopy` has already raised the toast; swallowing here only keeps an unhandled
    // rejection out of the console.
    () => {},
  );
});

function copySourceFor(btn) {
  const id = btn.dataset.copyTarget;
  if (id) return document.getElementById(id);
  const selector = btn.dataset.copyFrom;
  if (!selector || !btn.parentElement) return null;
  return btn.parentElement.querySelector(selector);
}

// Show loading cursor only for user-initiated HTMX requests, not background polls.
document.body.addEventListener('htmx:beforeRequest', (e) => {
  const trig = (e.detail.elt?.getAttribute('hx-trigger') || '').toLowerCase();
  if (trig.includes('every') || trig === 'load') return;
  document.body.style.cursor = 'wait';
});
document.body.addEventListener('htmx:afterRequest', () => {
  document.body.style.cursor = '';
});

// Surface failed HTMX requests. htmx suppresses the swap on any 4xx/5xx and on a
// network error, so without this a lazy-loaded tab or a rejected form just sits there
// — the pane keeps its spinner or its stale content and the user is told nothing.
// Same class of silent failure as the DOMContentLoaded latch below, and as a copy
// button that does nothing: `ltCopy` raises this toast too, because "the thing you
// asked for did not happen, with nothing on screen to say so" is one problem.
//
// The toast's styling lives in base.html, not here: `task css:build` only scans
// app/templates/**/*.html, so a class name applied from JS would never reach the
// production stylesheet. This block only toggles `hidden`.
const TOAST_AUTO_DISMISS_MS = 6000;
let toastHideTimer = null;

function ltToast(message) {
  const box = document.getElementById('htmx-error-toast');
  if (!box) return;
  box.querySelector('[data-toast-message]').textContent = message;
  box.classList.remove('hidden');
  clearTimeout(toastHideTimer);
  toastHideTimer = setTimeout(() => box.classList.add('hidden'), TOAST_AUTO_DISMISS_MS);
}
window.ltToast = ltToast;

window.dismissHtmxError = () => {
  clearTimeout(toastHideTimer);
  document.getElementById('htmx-error-toast')?.classList.add('hidden');
};

document.body.addEventListener('htmx:responseError', (e) => {
  const status = e.detail.xhr?.status;
  // 286 is our own "stop polling" signal, not a failure.
  if (status === 286) return;
  const messages = {
    403: 'Not allowed — you may need to sign in again.',
    404: 'That resource no longer exists.',
    429: 'Too many requests — try again in a moment.',
    503: 'The service is temporarily unavailable.',
  };
  ltToast(messages[status] || `Request failed (${status || 'error'}).`);
});

document.body.addEventListener('htmx:sendError', () => {
  ltToast('Network error — check your connection and try again.');
});

// Unified confirm dialog for destructive/expensive actions.
// Two interception paths share the same <dialog>:
//  - native form submits (data-confirm-* on a plain form)
//  - htmx-driven requests (data-confirm-* on the element carrying hx-post/hx-get/…)
(() => {
  let onConfirm = null;
  // Set only by the accept button, read (and cleared) by the `close` handler. Reading
  // `dialog.returnValue` instead was subtly wrong: older engines do not reset it on
  // showModal(), so after one confirmed action the value stayed 'confirm' and dismissing
  // the *next* dialog with Escape ran that action anyway. An explicit flag makes the
  // accept path the only path, on every engine.
  let accepted = false;

  const HX_VERB_ATTRS = ['hx-post', 'hx-get', 'hx-put', 'hx-delete', 'hx-patch'];
  const isHtmxDriven = (el) => HX_VERB_ATTRS.some((a) => el.hasAttribute(a));

  function setupConfirmDialog() {
    const dialog = document.getElementById('confirm-dialog');
    if (!dialog) return;

    const titleEl = document.getElementById('confirm-dialog-title');
    const messageEl = document.getElementById('confirm-dialog-message');
    const acceptBtn = document.getElementById('confirm-dialog-accept');
    if (!titleEl || !messageEl || !acceptBtn) return;

    function show(source, confirmFn) {
      onConfirm = confirmFn;
      accepted = false;
      titleEl.textContent = source.dataset.confirmTitle || 'Confirm action';
      messageEl.textContent = source.dataset.confirmMessage;
      acceptBtn.textContent = source.dataset.confirmAccept || 'Continue';
      dialog.showModal();
    }

    // A polled/OOB-swapped region can replace the form while the dialog is
    // open (e.g. the job page refreshes its header every 3s). Submitting the
    // captured-but-detached element is a silent no-op per the HTML spec, so
    // re-resolve the form's current incarnation by action+method on confirm.
    function resolveLiveForm(form) {
      if (form.isConnected) return form;
      const action = form.getAttribute('action');
      const method = (form.getAttribute('method') || 'get').toLowerCase();
      for (const candidate of document.querySelectorAll('form[data-confirm-message]')) {
        if (candidate.getAttribute('action') === action && (candidate.getAttribute('method') || 'get').toLowerCase() === method) {
          return candidate;
        }
      }
      return null; // action legitimately gone (e.g. job went terminal) — drop it
    }

    // Native (non-htmx) forms.
    document.addEventListener(
      'submit',
      (event) => {
        const form = event.target;
        if (!(form instanceof HTMLFormElement)) return;
        if (isHtmxDriven(form)) return; // htmx:confirm path handles these
        if (form.dataset.confirmBypass === '1') {
          delete form.dataset.confirmBypass;
          return;
        }
        if (!form.dataset.confirmMessage) return;

        event.preventDefault();
        show(form, () => {
          const live = resolveLiveForm(form);
          if (!live) return;
          live.dataset.confirmBypass = '1';
          live.requestSubmit();
        });
      },
      true,
    );

    // htmx-driven elements: pause the request, resume via issueRequest(true).
    document.body.addEventListener('htmx:confirm', (event) => {
      const elt = event.detail.elt;
      if (!(elt instanceof HTMLElement) || !elt.dataset.confirmMessage) return;
      event.preventDefault();
      show(elt, () => event.detail.issueRequest(true));
    });

    // `method="dialog"` submit closes the dialog and sets returnValue from the button's
    // value; we latch our own flag on the accept button instead so the decision cannot
    // survive into the next dialog.
    acceptBtn.addEventListener('click', () => {
      accepted = true;
    });

    dialog.addEventListener('close', () => {
      const fn = onConfirm;
      const run = accepted;
      onConfirm = null;
      accepted = false;
      if (run && fn) fn();
    });
  }

  // Deliberately NOT the DOMContentLoaded latch below: this only needs the document
  // parsed (so #confirm-dialog exists), which readyState does answer. Nothing here has to
  // queue behind another library's DOMContentLoaded handler.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', setupConfirmDialog, { once: true });
  } else {
    setupConfirmDialog();
  }
})();

// ── DOMContentLoaded latch ───────────────────────────────────────────────────
// `document.readyState` cannot answer "have DOMContentLoaded handlers run yet?". The spec
// sets readyState to "interactive" *before* deferred scripts run and fires
// DOMContentLoaded *after* them, so a deferred script always reads "interactive" and a
// `readyState === 'loading'` gate falls straight through.
// "complete" is the only value that implies the event has fired; for the rest, only the
// event itself, latched, answers the question.
//
// Registration order is the payload. htmx.min.js is a blocking <script> in <head>
// (base.html), so by the time this deferred file runs htmx has already registered the
// DOMContentLoaded handler that calls htmx.process(document.body) and attaches every
// `hx-trigger="… from:body"` listener. Same-target listeners fire in registration order,
// so anything registered from here runs after htmx has processed the document.
let domContentLoaded = document.readyState === 'complete';
document.addEventListener('DOMContentLoaded', () => { domContentLoaded = true; }, { once: true });

// Dispatch a `from:body` lazy-load event once htmx is guaranteed to be listening.
//
// Exported because inline page scripts need it too, and the obvious hand-rolled version is
// wrong in a way that only shows up sometimes:
//
//   if (document.readyState === 'complete') fire();
//   else document.addEventListener('DOMContentLoaded', fire, { once: true });
//
// `readyState` goes 'loading' → 'interactive' → 'complete', and DOMContentLoaded fires
// while it is still 'interactive'; it only reaches 'complete' at the `load` event, after
// images and fonts. Click a lazy tab in that window and the code above takes the else
// branch, registering a listener for an event that has already fired — so the pane never
// loads at all. The latch above has no such window because it is set by the event itself.
function dispatchWhenReady(eventName) {
  const dispatch = () => document.body.dispatchEvent(new CustomEvent(eventName));
  if (domContentLoaded) dispatch();
  else document.addEventListener('DOMContentLoaded', dispatch, { once: true });
}
window.dispatchWhenReady = dispatchWhenReady;

// ── ← and → turn the page ────────────────────────────────────────────────────
//
// Only on a list whose pager opts in with `data-pager-keys` (partials/_pager.html, `keys=`),
// so a page with several paged panes never guesses which one the arrows mean. It presses
// the pager's own Prev/Next, so the navigation verb — a link, an htmx swap, an Alpine
// refresh — is whatever that pager already does.
//
// Returns the control to press, or null. Every null is a place an arrow already means
// something: a field's caret, a select's options, a table that scrolls sideways, an open
// dialog, and modifier chords (Alt+← is the browser's Back).
function ltPagerKeyTarget(event, doc) {
  if (event.defaultPrevented || event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return null;
  const which = { ArrowLeft: 'prev', ArrowRight: 'next' }[event.key];
  if (!which) return null;
  const t = event.target;
  if (t && (t.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(t.tagName))) return null;
  if (t && t.tagName !== 'BODY' && t.tagName !== 'HTML' && t.scrollWidth > t.clientWidth) return null;
  if (doc.querySelector('dialog[open]')) return null;
  const control = doc.querySelector(`[data-pager-keys] [data-pager-${which}]`);
  if (!control || control.hasAttribute('disabled') || control.getAttribute('aria-disabled') === 'true') return null;
  return control;
}
window.ltPagerKeyTarget = ltPagerKeyTarget;
document.addEventListener('keydown', (event) => {
  const control = ltPagerKeyTarget(event, document);
  if (!control) return;
  event.preventDefault();
  control.click();
});

// ── Worker Fleet: capacity edits vs the 5s poll ──────────────────────────────
// `/admin/workers` polls its own region every 5s, gated on `__workersPriorityDirty` so a
// swap cannot wipe a half-typed capacity value. The gate must not LATCH on the first
// keystroke: anything outside `#workers-region` — which is all `/admin/workers/partial`
// swaps — is reached only by a form submit or a full page load, so one digit typed and
// walked away would stop the page refreshing for good, freezing the fleet table, the
// queue depth and every heartbeat TTL at whatever was on screen.
//
// So track the values instead of the first keystroke, per host, and give up on an edit
// nobody came back to. Reverting a value resumes the poll immediately; abandoning one
// resumes it after the deadline. Losing an abandoned digit is the cheaper mistake — this
// is a live monitoring page, and one that has silently stopped monitoring is the failure
// it exists to prevent.
const WORKERS_ABANDON_MS = 60000;
const workersDirtyHosts = new Set();
let workersAbandonTimer = null;

function workersGateSync() {
  window.__workersPriorityDirty = workersDirtyHosts.size > 0;
  if (workersAbandonTimer !== null) clearTimeout(workersAbandonTimer);
  // Re-armed on every edit, so typing is never interrupted mid-value: the deadline is
  // "nobody has touched this for a minute", not "a minute since the first keystroke".
  workersAbandonTimer = workersDirtyHosts.size ? setTimeout(() => window.ltWorkersCapacity.reset(), WORKERS_ABANDON_MS) : null;
}

window.ltWorkersCapacity = {
  /** Record whether *hostname*'s capacity control still differs from its saved value. */
  mark(hostname, isDirty) {
    if (isDirty) workersDirtyHosts.add(hostname);
    else workersDirtyHosts.delete(hostname);
    workersGateSync();
  },
  /** Forget every pending edit — the form was submitted, or nobody came back. */
  reset() {
    workersDirtyHosts.clear();
    workersGateSync();
  },
};

// ── Shared tabbed-workbench component ────────────────────────────────────────
// One implementation for the entity, case, and job detail pages. `tabs` is the
// server-built list of {key, label, badge, lazy_event} dicts (see
// routers/intel.py::_build_entity_tabs and its siblings); the valid key set is
// derived from it, so pages can append tabs with no JS change.
//
// A tab whose dict carries `lazy_event` dispatches that event on document.body
// when the tab is first shown, which is what HTMX partials listen for.
//
// Assigned to `window` explicitly at the bottom. Alpine resolves an `x-data`
// expression against the global object, and a top-level `const`/`let` in a classic
// script lands in script scope, NOT on window — so an alias declared with `const`
// is invisible to Alpine even though it looks global.
function resourceTabs(tabs) {
  const validKeys = tabs.map(t => t.key);
  const eventMap = Object.fromEntries(
    tabs.filter(t => t.lazy_event).map(t => [t.key, t.lazy_event])
  );
  function fireLoad(name) {
    // htmx attaches the `from:body` listener for a lazy pane from its own DOMContentLoaded
    // handler. This runs from Alpine's init (or a click), and Alpine schedules $nextTick on
    // a 0 ms timer — whether that timer or the queued DOMContentLoaded task runs first is
    // not ours to know. Dispatching on a guess is how a deep link to a lazy tab (#timeline,
    // #graph) shouted into an empty room and the pane spun forever, loading only once a tab
    // switch re-fired the event. Queue behind htmx instead of racing it.
    const ev = eventMap[name];
    if (ev) dispatchWhenReady(ev);
  }
  return {
    tab: validKeys[0] || '',
    init() {
      const h = window.location.hash.replace('#', '');
      if (validKeys.includes(h)) {
        this.tab = h;
      }
      this.$nextTick(() => fireLoad(this.tab));
    },
    select(name) {
      this.tab = name;
      history.replaceState({}, '', '#' + name);
      this.$nextTick(() => fireLoad(name));
    }
  };
}

// Expose on window so Alpine's expression evaluator can find it. Every page calls it by
// this one name — no aliases — leaving one name to grep for.
window.resourceTabs = resourceTabs;

// ── Case timeline: entity search box ─────────────────────────────────────────
// Backs the key-events entity filter. A case can carry thousands of linked entities, so
// this queries `/intel/cases/{id}/entities.json` (capped, case-scoped) instead of the
// page shipping every one into a <select>.
//
// Lives here rather than in an inline <script> inside the partial because this file is
// guaranteed to execute before Alpine starts; a factory defined in swapped-in markup is
// hostage to script/init ordering.
// `types` is an optional CSV narrowing the picker to entity types the caller can use —
// the Processes tab passes the five a lineage node can match, so an analyst cannot pick an
// ip_address and get an unexplained empty tree. `jobId` narrows it again, to entities the
// selected job actually saw: the case's entity set and one job's are not the same list, and
// offering the difference is how you pick something that anchors nothing. Both are optional
// and trailing, so every existing three-argument call site (the Timeline tab) is unchanged.
function caseEntityFilter(caseId, initialId, initialLabel, types, jobId) {
  return {
    entityId: initialId || 0,
    label: initialLabel || '',
    open: false,
    close() {
      this.open = false;
      if (this.$refs.results) this.$refs.results.innerHTML = '';
    },
    _refetch() {
      // The filter form re-fetches the timeline partial on `change`.
      const form = this.$el.closest('form');
      if (!form) return;
      // Write the hidden field directly instead of trusting Alpine's `:value` binding to
      // have flushed. Alpine applies bindings on its own scheduler, but htmx serializes
      // the form synchronously inside this dispatch — so the binding lost the race and
      // htmx sent the *previous* entity_id, which came back as an unfiltered partial and
      // wiped the selection. Do not replace this with $nextTick: the correctness of the
      // request must not depend on two libraries' scheduling agreeing.
      const hidden = form.querySelector('input[name="entity_id"]');
      if (hidden) hidden.value = String(this.entityId || 0);
      form.dispatchEvent(new Event('change', { bubbles: true }));
    },
    clear() {
      this.entityId = 0;
      this.label = '';
      this.close();
      this._refetch();
    },
    search() {
      const q = (this.label || '').trim();
      const typeParam = types ? '&types=' + encodeURIComponent(types) : '';
      const jobParam = jobId ? '&job=' + encodeURIComponent(jobId) : '';
      fetch('/intel/cases/' + caseId + '/entities.json?q=' + encodeURIComponent(q) + typeParam + jobParam, { credentials: 'same-origin' })
        .then(r => (r.ok ? r.json() : []))
        .then(items => this.render(items, q))
        .catch(() => this.close());
    },
    render(items, q) {
      const box = this.$refs.results;
      if (!box) return;
      box.innerHTML = '';
      // An empty result stays *open*, saying so. Closing the panel instead made the box
      // read as broken rather than as empty — and it fired on every first keystroke back
      // when a one-character query was answered with `[]`, so the list disappeared as soon
      // as you started typing and returned on the second character.
      if (!items.length) {
        const empty = document.createElement('p');
        empty.className = 'px-3 py-2 text-xs text-gray-500';
        const where = jobId ? ' in this job' : ' in this case';
        empty.textContent = (q ? 'No match' : 'Nothing to pick') + where + '.';
        box.appendChild(empty);
        this.open = true;
        return;
      }
      items.forEach(item => {
        // DOM-built: entity values are member-controlled, never innerHTML.
        const row = document.createElement('button');
        row.type = 'button';
        row.className = 'w-full text-left px-3 py-1.5 text-xs hover:bg-gray-800/60 transition flex items-center gap-2';
        const type = document.createElement('span');
        type.className = 'text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 flex-shrink-0';
        type.textContent = item.entity_type;
        const value = document.createElement('span');
        value.className = 'font-mono text-gray-200 truncate';
        value.textContent = item.value;
        row.appendChild(type);
        row.appendChild(value);
        row.addEventListener('click', () => this.choose(item));
        box.appendChild(row);
      });
      this.open = true;
    },
    choose(item) {
      this.entityId = item.id;
      this.label = item.value;
      this.close();
      this._refetch();
    },
  };
}
window.caseEntityFilter = caseEntityFilter;

// ── Tag combobox ────────────────────────────────────────────────────────────
// Search-as-you-type over the tags that already exist, each shown as its own coloured
// chip, with "create" as an explicit last resort.
//
// Replaces a native <datalist>, which could not work here: a datalist renders plain text
// in browser chrome, so it could not show a tag's colour, could not show usage counts as
// anything but a label hack, and gave no way to distinguish "pick the existing apt28" from
// "coin a new apt-28". Coining near-duplicates is the failure mode that makes a tag
// vocabulary useless, so reuse has to be the easy path.
//
// Lives here rather than in an inline <script>: this markup is swapped in by HTMX, and a
// factory defined in swapped content is hostage to script/init ordering. app.js is
// guaranteed to run before Alpine starts.
// `max` is the whole single/multi distinction. At `max: 1` this behaves exactly as it
// always did — pick a tag and the input disappears behind its pill — which is what keeps
// the tag manager's *rename* and *merge* fields correct, since those genuinely take one
// name. Everywhere an analyst is labelling something, `max` is TAG_WRITE_MAX and the
// input stays put so the next tag can be typed straight away. One code path, not a
// `multiple` branch: two branches is how the single case quietly stops being tested.
function tagCombobox(opts) {
  opts = opts || {};
  const MAX = Math.max(1, opts.max || 1);
  return {
    open: false,
    query: '',
    // The colour offered to the *next* tag coined here. Picking an existing tag adopts its
    // colour into its own pill and leaves this alone.
    color: opts.color || 'gray',
    // The chosen tags, in the order they were added, as `{tag, color}`. Each carries its own
    // colour: submitting one colour for the whole field would repaint every existing tag you
    // picked, and a tag's colour is instance-wide.
    values: [],
    max: MAX,
    known: [],
    loaded: false,
    // The vocabulary generation this instance's `known[]` was fetched at. `load()` refetches
    // whenever the shared counter has moved on.
    generation: -1,
    highlight: 0,

    init() {
      if (opts.eager) this.load();
      // Seed from a server-rendered value: the rename field starts on the current name, and
      // a watch rule's auto-tag field starts on whatever it already applies.
      (opts.value || '').split(',').map(s => s.trim()).filter(Boolean).slice(0, MAX)
        .forEach((tag, i) => this.values.push({ tag, color: (opts.colors || [])[i] || this.color }));
      this.sync();
    },

    // What the form posts: two index-aligned CSVs, names and colours. Written into hidden
    // inputs rather than bound with `:value` — htmx serialises synchronously inside the
    // submit event while Alpine applies bindings on its own scheduler, so a binding can hand
    // the server the previous selection. Every state change calls this, so the DOM is always
    // what will be sent.
    //
    // The half-typed query still counts when nothing is committed yet: otherwise submitting a
    // field you typed into and never pressed Enter on would post nothing at all.
    sync() {
      const names = this.values.map(v => v.tag);
      const colors = this.values.map(v => v.color || 'gray');
      if (!names.length && this.normalized()) { names.push(this.normalized()); colors.push(this.color); }
      if (this.$refs.value) this.$refs.value.value = names.join(',');
      if (this.$refs.colorValue) this.$refs.colorValue.value = colors.join(',');
    },

    // Is there anything to submit? The gate on every Create / Save / Merge / Add / Tag
    // button in the app, so a click on an empty field never becomes a request the server
    // has to refuse with a 400.
    //
    // It mirrors `sync()` above deliberately, **including** that a half-typed name nobody
    // pressed Enter on still counts. A gate written on the pills alone (`!values.length`)
    // reads as obviously right and dims the button over a field the reader can see they
    // filled in; the opposite slip posts an empty string from a live button. So the JS test
    // asserts the *agreement* between this and the hidden input rather than either answer.
    //
    // `required` cannot do this job: the value is posted through a hidden input, and hidden
    // inputs are barred from constraint validation by spec.
    isEmpty() {
      return !this.values.length && !this.normalized();
    },

    // True while the input should still be shown. At max: 1 this is exactly
    // `x-show="!selected"`.
    canAdd() {
      return this.values.length < this.max;
    },
    has(tag) {
      return this.values.some(v => v.tag === tag);
    },
    // Commit a name into a pill. The one place a tag joins the field, so the cap, the
    // de-duplication and clearing the query are all stated once.
    add(tag, color) {
      const name = (tag || '').trim().toLowerCase().slice(0, 50);
      if (!name || this.has(name) || !this.canAdd()) { this.query = ''; return; }
      this.values.push({ tag: name, color: color || this.color || 'gray' });
      this.query = '';
      this.highlight = 0;
      this.open = this.canAdd();
      this.sync();
    },
    removeAt(i) {
      this.values.splice(i, 1);
      this.sync();
      this.focusInput();
    },

    focusInput() {
      // `$refs` resolves from this component's own root outward, and `tagInput` is
      // registered here, so this one works. The *outer* component cannot reach it — see
      // entityTagInput.open().
      this.$nextTick(() => this.$refs.tagInput && this.$refs.tagInput.focus());
    },

    load() {
      const gen = window.__ltTagGeneration || 0;
      if (this.loaded && this.generation === gen) return;
      this.loaded = true;
      this.generation = gen;
      fetch('/intel/tags.json?limit=200', { credentials: 'same-origin' })
        .then(r => (r.ok ? r.json() : []))
        .then(items => { this.known = items; })
        // Un-latch the generation too, not just `loaded`: leaving it set would mark this
        // instance as holding a fetch that never landed.
        .catch(() => { this.loaded = false; this.generation = -1; });
    },
    show() {
      this.load();
      this.open = true;
      this.highlight = 0;
    },
    // No hide()-on-blur: the panel closes from a `focusout` on the container that checks
    // `relatedTarget`. Closing on the input's own blur is what broke colour picking —
    // clicking anything in the panel blurs the input, and the deferred close unmounted the
    // control before it could be used.
    normalized() {
      return (this.query || '').trim().toLowerCase().slice(0, 50);
    },
    matches() {
      const q = this.normalized();
      let list = q ? this.known.filter(t => t.tag.includes(q)) : this.known;
      // The exact name first. Otherwise a more-used tag that merely contains what was typed
      // sits at the top, highlighted, and Enter commits it instead of the tag named.
      if (q) list = [...list.filter(t => t.tag === q), ...list.filter(t => t.tag !== q)];
      // Already-picked tags drop out of the list: offering a chip that does nothing when
      // clicked reads as a broken control.
      return list.filter(t => !this.has(t.tag)).slice(0, 8);
    },
    exact() {
      const q = this.normalized();
      return this.known.find(t => t.tag === q) || null;
    },
    canCreate() {
      const q = this.normalized();
      return q.length > 0 && !this.exact() && !this.has(q) && this.canAdd();
    },
    pick(tag) {
      this.add(tag.tag, tag.color || 'gray');
    },
    // Commit a name nobody has used yet. A separate act from picking an existing one, so
    // the two can never be confused at the moment it matters.
    create() {
      if (!this.normalized()) return;
      this.add(this.normalized(), this.color);
    },
    clear() {
      this.values = [];
      this.query = '';
      this.color = opts.color || 'gray';
      this.sync();
      this.focusInput();
    },
    setColor(c) {
      this.color = c;
      this.sync();
    },
    onInput() {
      // A comma is a separator, not a tag character: typing or pasting `a, b, c` commits
      // each name as it is completed. `normalize_tag` on the server would otherwise store a
      // literal `a,b` — the one input that looks like it should obviously work.
      if (this.query.includes(',')) {
        const parts = this.query.split(',');
        this.query = parts.pop();
        parts.forEach(p => {
          const hit = this.known.find(t => t.tag === p.trim().toLowerCase());
          this.add(p, hit ? hit.color : this.color);
        });
      }
      this.show();
      // Typing the full name of an existing tag adopts its colour, so the common path
      // preserves it and only a deliberate change recolours instance-wide.
      const hit = this.exact();
      if (hit) this.color = hit.color || 'gray';
      this.sync();
    },
    onKey(e) {
      // Backspace on an empty box removes the last pill — the universal multi-select
      // gesture, and it works whether or not the panel happens to be open.
      if (e.key === 'Backspace' && !this.query && this.values.length) {
        this.removeAt(this.values.length - 1);
        return;
      }
      if (!this.open) return;
      const rows = this.matches();
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        // `rows.length - 1` is -1 on an empty list, which would park the highlight on a row
        // that does not exist and make Enter do nothing.
        if (rows.length) this.highlight = Math.min(this.highlight + 1, rows.length - 1);
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        this.highlight = Math.max(this.highlight - 1, 0);
      } else if (e.key === 'Enter' || e.key === 'Tab') {
        // Enter commits: the highlighted existing tag if there is one, otherwise the name
        // being typed. Without this it submitted the surrounding form with raw text. Tab
        // does the same rather than moving focus and losing what was typed.
        if (rows[this.highlight]) { e.preventDefault(); this.pick(rows[this.highlight]); }
        else if (this.canCreate()) { e.preventDefault(); this.create(); }
      } else if (e.key === 'Escape') {
        this.open = false;
      }
    },
    reset() {
      this.query = '';
      this.values = [];
      this.color = opts.color || 'gray';
      this.open = false;
      this.sync();
    },
  };
}
window.tagCombobox = tagCombobox;

// Bump after any successful tag write. Each `tagCombobox()` caches its own `known[]` and
// latches `loaded`, so a tag created from one control was invisible to every other control
// on the page — and to itself on the next open — until a full reload. That is exactly the
// bulk-tag flow: coin a name, apply it to twelve rows, then find it missing from the box
// you just typed it into.
//
// A counter rather than a body-level CustomEvent: every instance compares against one
// number on its next open, so there is no listener to attach (these partials are
// HTMX-swapped, so listeners come and go), nothing to clean up, and no ordering surface.
window.__ltTagGeneration = 0;
function tagVocabChanged() {
  window.__ltTagGeneration += 1;
}
window.tagVocabChanged = tagVocabChanged;

// The entity and job header tag regions: the combobox plus the show/hide of the add form.
function entityTagInput() {
  return {
    adding: false,
    open() {
      this.adding = true;
      // A DOM query, not `$refs`. Alpine resolves `$refs` from the component's own root
      // *outwards*, and `x-ref="tagInput"` is registered on the nested `tagCombobox()`
      // form — a descendant — so `this.$refs.tagInput` was always undefined here and the
      // add form opened with no caret in it.
      this.$nextTick(() => {
        const input = this.$el.querySelector('.lt-combo-input');
        if (input) input.focus();
      });
    },
    cancel() {
      this.adding = false;
    },
  };
}
window.entityTagInput = entityTagInput;

// ---------------------------------------------------------------------------
// Search autocomplete for the Intel query box.
//
// All grammar knowledge lives on the server: `/intel/search-suggest` runs the caret
// through `queries.caret_token`, which shares its scanner with the parser, and answers
// with the character span to replace plus the completions for it. That is why this file
// has no notion of `re:/…/`, quoting or parentheses — duplicating those rules in JS is
// exactly how a picker starts disagreeing with the thing it is picking for.
//
// Two callers, and they differ only in where the value lives. On the Intel dashboard the
// box is one field of a filter state the parent x-data owns, so a pick writes `searchQuery`
// through Alpine's scope proxy and asks the table to refetch. On the jobs list the box is a
// plain GET form with no scope around it, so a pick writes the input itself and the analyst
// presses Enter — passing `standalone: true` selects that.
//
// The endpoint is an option for the same reason the two exist at all: both grammars share
// one tokenizer on the server, and neither client knows anything about either grammar.
function searchSuggest(opts) {
  opts = opts || {};
  return {
    url: opts.url || '/intel/search-suggest',
    standalone: !!opts.standalone,
    open: false,
    items: [],
    highlight: -1,
    span: { start: 0, end: 0 },
    // Monotonic request id. Completions are fetched on every keystroke, so a slow early
    // response must not overwrite a fast later one and re-open a stale list.
    _seq: 0,
    _timer: null,

    schedule() {
      clearTimeout(this._timer);
      // Shorter than the 300ms table debounce: a picker that lags behind the keystrokes
      // gets used once and then ignored.
      this._timer = setTimeout(() => this.load(), 120);
    },

    close() {
      clearTimeout(this._timer);
      this.open = false;
      this.items = [];
      this.highlight = -1;
    },

    load() {
      const input = this.$refs.search;
      if (!input) return;
      const seq = ++this._seq;
      const url = this.url + '?q=' + encodeURIComponent(input.value) + '&pos=' + (input.selectionStart ?? input.value.length);
      fetch(url, { credentials: 'same-origin' })
        .then((r) => (r.ok ? r.json() : null))
        .then((data) => {
          if (!data || seq !== this._seq) return; // superseded by a later keystroke
          this.span = { start: data.start, end: data.end };
          this.items = data.suggestions || [];
          this.open = this.items.length > 0;
          this.highlight = this.items.length ? 0 : -1;
        })
        .catch(() => this.close());
    },

    pick(item) {
      const input = this.$refs.search;
      if (!input || !item) return;
      const value = input.value;
      const next = value.slice(0, this.span.start) + item.insert + value.slice(this.span.end);
      const caret = this.span.start + item.insert.length;

      if (this.standalone) {
        // No scope to write through: the input IS the state, and the form is submitted by
        // the analyst. Setting `.value` directly is also what keeps this safe next to htmx —
        // the value is in the DOM before anything can serialise it.
        input.value = next;
      } else {
        // Write through the shared scope so the URL sync and the table both see it. Alpine's
        // scope proxy forwards the set to the root component that owns the property.
        this.searchQuery = next;
        // The parent's @input already scheduled a refresh for the keystroke that opened this
        // list; picking supersedes it, so cancel it rather than firing twice.
        clearTimeout(this.searchTimeout);
      }
      this.close();

      // Accepting a *key* (`tag:`) is half a term, not a query. Re-open onto its values
      // instead of closing and refreshing on `tag:`, which matches nothing and would make
      // the picker feel like it had cancelled itself. Accepting a value does refresh.
      const isKeyOnly = item.insert.endsWith(':') || item.insert.endsWith(':/');
      this.$nextTick(() => {
        input.setSelectionRange(caret, caret);
        input.focus();
        if (isKeyOnly) this.load();
        else if (!this.standalone) this.triggerRefresh(true);
      });
    },

    onKey(event) {
      if (!this.open) {
        // Down-arrow on a closed box is a request to see what is available.
        if (event.key === 'ArrowDown') { event.preventDefault(); this.load(); }
        return;
      }
      if (event.key === 'ArrowDown') {
        event.preventDefault();
        this.highlight = (this.highlight + 1) % this.items.length;
      } else if (event.key === 'ArrowUp') {
        event.preventDefault();
        this.highlight = (this.highlight - 1 + this.items.length) % this.items.length;
      } else if (event.key === 'Enter' || event.key === 'Tab') {
        if (this.highlight >= 0) {
          // Enter would otherwise submit, Tab would move focus — both lose the selection.
          event.preventDefault();
          this.pick(this.items[this.highlight]);
        }
      } else if (event.key === 'Escape') {
        event.preventDefault();
        this.close();
      }
    },
  };
}
window.searchSuggest = searchSuggest;

// ── Condition editor ─────────────────────────────────────────────────────────
// The rule condition field on /intel/rules: a syntax-highlighted overlay behind a real
// <textarea>, plus the same caret-aware completion the two search boxes use.
//
// **The textarea is still the field.** It keeps its `name` and every htmx attribute, and
// nothing is copied into a hidden input — so what the form serialises is what the analyst
// typed, and the 400 ms preview and the dry-run (`hx-include="closest form"`) keep working
// untouched. Writing to a mirror would put a serializer on Alpine's scheduler, which is
// the race `caseEntityFilter._refetch` exists to avoid.
//
// **The grammar comes from the server** (`condition_grammar`, built from `queries._PREFIXES`
// and `jobs_query.PREFIXES`), never from a list written here. Only structure crosses over:
// which prefixes exist and the two boolean words.
//
// **Nothing here may call a term invalid.** In both grammars an unrecognised `word:value`
// is a deliberate literal search — filenames and rule ids contain colons — so `lt-cond-bad`
// is reserved for what is structurally certain: an unclosed quote, an unclosed regex, an
// unbalanced paren. Everything else is the server preview's job; it is the only thing that
// actually parses.
// The page-level grammar block. Missing is a real state — a template that forgets it gets a
// tokenizer that colours nothing rather than one that throws inside every Alpine effect.
function readConditionGrammar() {
  const empty = { entity: { prefixes: [] }, job: { prefixes: [] }, operators: [], regex_prefix: 're:/' };
  const node = document.getElementById('condition-grammar');
  if (!node) return empty;
  try {
    return JSON.parse(node.textContent) || empty;
  } catch (err) {
    return empty;
  }
}

function conditionEditor(opts) {
  opts = opts || {};
  // One copy per page, read from a JSON block, rather than interpolated into each form's
  // x-data — the rules page renders up to 37 of these and the grammar is the same for all
  // of them. `opts.grammar` still wins, which is how the unit tests hand it a fixture.
  const grammar = opts.grammar || readConditionGrammar();
  const suggest = searchSuggest({ standalone: true });
  // Captured before the spread so the override can extend it rather than replace it.
  const basePick = suggest.pick;
  const baseOnKey = suggest.onKey;

  return {
    ...suggest,
    grammar,

    // Reactive, and it has to be. `x-text="termCount()"` reads the textarea's `.value`,
    // which is a DOM property Alpine cannot observe — so the expression was evaluated once,
    // at init, against an empty field, and the line under the editor said "0 terms" forever.
    // `paint()` runs on every keystroke and is the natural place to publish it.
    terms: 0,

    // `scope` is deliberately NOT declared here. It lives on the enclosing form's x-data,
    // where the Applies-to radios write it; declaring it would shadow that and the two
    // would silently diverge — the radio moving one copy and the highlighter reading the
    // other. Alpine's scope chain resolves it outward.
    get url() {
      const g = grammar[this.scope] || grammar.entity;
      return g.suggest_url || '/intel/search-suggest';
    },

    init() {
      this.paint();
    },

    // Called from x-effect with `scope` passed in. The argument is unused; reading it in
    // the template is what registers the dependency, so switching Entities ⇄ Jobs repaints
    // against the other grammar.
    repaint() {
      this.paint();
    },

    onInput() {
      this.paint();
      this.schedule();
    },

    // A closed list leaves the arrow keys to the caret. The search boxes open completions
    // on ArrowDown, but this is a multi-line field written one term per line, and taking
    // the key there meant the caret could never move down. Typing still opens the list.
    onKey(event) {
      if (!this.open && event.key === 'ArrowDown') return;
      baseOnKey.call(this, event);
    },

    pick(item) {
      basePick.call(this, item);
      this.$nextTick(() => {
        this.paint();
        // A pick changes the value without a keystroke, so htmx's `keyup changed` trigger
        // never fires and the preview would keep describing the term before the completion.
        const input = this.$refs.search;
        if (input) input.dispatchEvent(new Event('keyup', { bubbles: true }));
      });
    },

    paint() {
      const input = this.$refs.search;
      const layer = this.$refs.hl;
      if (!input || !layer) return;
      layer.textContent = '';
      for (const tok of this.tokenize(input.value)) {
        if (tok.cls) {
          const span = document.createElement('span');
          span.className = tok.cls;
          // textContent, never innerHTML: this string is whatever the analyst typed, and
          // it is about to be put back into the document.
          span.textContent = tok.text;
          layer.appendChild(span);
        } else {
          layer.appendChild(document.createTextNode(tok.text));
        }
      }
      // A trailing newline is not rendered by a <pre>-style box, so the overlay comes up
      // one line short of the textarea whenever the value ends in one. It is also what
      // gives the container its height, since the overlay is the layer in normal flow —
      // there is no grow() to call: a <pre> sizes itself, which is the whole point of
      // putting it underneath rather than on top.
      layer.appendChild(document.createTextNode('\n'));
      this.terms = this.termCount();
    },

    tokenize(raw) {
      raw = raw || '';
      const g = this.grammar[this.scope] || this.grammar.entity;
      const prefixes = g.prefixes || [];
      const ops = this.grammar.operators || [];
      const rp = this.grammar.regex_prefix || 're:/';
      const out = [];
      const openParens = [];
      const push = (text, cls) => { if (text) out.push({ text, cls: cls || '' }); };
      let i = 0;

      while (i < raw.length) {
        const ch = raw[i];

        if (/\s/.test(ch)) {
          let j = i;
          while (j < raw.length && /\s/.test(raw[j])) j++;
          push(raw.slice(i, j));
          i = j;
          continue;
        }
        if (ch === '(') {
          openParens.push(out.length);
          push('(', 'lt-cond-paren');
          i++;
          continue;
        }
        if (ch === ')') {
          // A close with nothing open is certainly wrong; one that matches is not.
          push(')', openParens.length ? 'lt-cond-paren' : 'lt-cond-bad');
          openParens.pop();
          i++;
          continue;
        }

        const start = i;
        let neg = '';
        if (ch === '-') { neg = '-'; i++; }

        if (raw[i] === '"') {
          const close = raw.indexOf('"', i + 1);
          if (close === -1) { push(raw.slice(start), 'lt-cond-bad'); i = raw.length; continue; }
          if (neg) push(neg, 'lt-cond-neg');
          push(raw.slice(i, close + 1), 'lt-cond-str');
          i = close + 1;
          continue;
        }

        // `in:(a,b)` before the generic scan: the walk below ends a term at a paren, so
        // the set would come out as a key, two grouping parens and a stray literal — and
        // the paren balance check would then count parens that are not grammar at all.
        if (raw.slice(i).toLowerCase().startsWith('in:(')) {
          const close = raw.indexOf(')', i);
          if (close === -1) { push(raw.slice(start), 'lt-cond-bad'); i = raw.length; continue; }
          if (neg) push(neg, 'lt-cond-neg');
          push(raw.slice(i, i + 3), 'lt-cond-key');
          push(raw.slice(i + 3, close + 1), 'lt-cond-val');
          i = close + 1;
          continue;
        }

        // Regex before the generic prefix scan: `re:/^svc a/` may contain spaces, so the
        // word-boundary walk below would shred one valid pattern into two junk terms —
        // the same reason `scan_query` gives it its own pass on the server.
        if (raw.slice(i).toLowerCase().startsWith(rp)) {
          let j = i + rp.length;
          while (j < raw.length && !(raw[j] === '/' && raw[j - 1] !== '\\')) j++;
          if (j >= raw.length) { push(raw.slice(start), 'lt-cond-bad'); i = raw.length; continue; }
          if (neg) push(neg, 'lt-cond-neg');
          push(raw.slice(i, i + rp.length), 'lt-cond-key');
          push(raw.slice(i + rp.length, j + 1), 'lt-cond-re');
          i = j + 1;
          continue;
        }

        let j = i;
        while (j < raw.length && !/[\s()]/.test(raw[j])) j++;
        const word = raw.slice(i, j);

        // Operators are bare uppercase words only, and a negated one is not an operator.
        if (!neg && ops.includes(word)) { push(word, 'lt-cond-bool'); i = j; continue; }

        if (neg) push(neg, 'lt-cond-neg');
        const pre = prefixes.find((p) => word.toLowerCase().startsWith(p));
        if (pre) {
          push(word.slice(0, pre.length), 'lt-cond-key');
          push(word.slice(pre.length), 'lt-cond-val');
        } else {
          // A bare word, or an unknown `word:value` — both are literal searches. Plain.
          push(word);
        }
        i = j;
      }

      // Whatever never closed. Re-marked at the end rather than guessed at the time: a `(`
      // is only wrong once the string has run out without its partner.
      for (const idx of openParens) if (out[idx]) out[idx].cls = 'lt-cond-bad';
      return out;
    },

    // How many terms this condition carries, for the line under the field. Counted off the
    // same tokenizer that colours it, so the two cannot disagree about where a term ends.
    //
    // Exactly one token opens each term: a prefix key (`tag:` … its value follows), a whole
    // quoted phrase, a bare literal, or a structurally broken run. `-` attaches to the term
    // after it, `val`/`re` trail a key they belong to, and parens and OR/AND are grammar
    // rather than terms — so none of those are counted.
    termCount() {
      const opensATerm = (t) =>
        t.cls === 'lt-cond-key' ||
        t.cls === 'lt-cond-str' ||
        t.cls === 'lt-cond-bad' ||
        (t.cls === '' && t.text.trim() !== '');
      return this.tokenize(this.$refs.search ? this.$refs.search.value : '').filter(opensATerm).length;
    },
  };
}
window.conditionEditor = conditionEditor;

// ── List values from a file ──────────────────────────────────────────────────
// The drop zone on the Rules page's list form.
//
// **No backend.** A dropped file is read here and written into the `values` textarea the
// form already posts, so the save path, its validation and its activity row are untouched.
// Adding an upload endpoint would have meant a second way to write a list, with its own
// size cap and its own bugs, to do what a textarea already does.
//
// The parse mirrors `rule_lists.normalize_values` — split on newlines *and* commas,
// lowercase, trim, drop blanks and duplicates, keep order. That is not a nicety: this
// reports "68 new, 4 already present" before you commit, and a client that counted
// differently from the server would be quietly lying about what is about to happen.
//
// Defined here rather than in the swapped-in partial: a factory declared inside HTMX-swapped
// markup is hostage to init ordering.
function listValuesDrop() {
  return {
    dragging: false,
    fileName: '',
    parsed: [],
    fresh: 0,
    dupes: 0,
    error: '',

    // The one parser. Mirrors rule_lists.normalize_values.
    normalize(text) {
      const out = [];
      const seen = new Set();
      for (const part of String(text || '').split(/[\n,]/)) {
        const v = part.trim().toLowerCase();
        if (!v || seen.has(v)) continue;
        seen.add(v);
        out.push(v);
      }
      return out;
    },

    current() {
      return this.normalize(this.$refs.values ? this.$refs.values.value : '');
    },

    reset() {
      this.fileName = '';
      this.parsed = [];
      this.fresh = 0;
      this.dupes = 0;
      this.error = '';
    },

    onDrop(event) {
      this.dragging = false;
      const file = event.dataTransfer && event.dataTransfer.files ? event.dataTransfer.files[0] : null;
      if (file) this.read(file);
    },

    onPick(event) {
      const file = event.target.files ? event.target.files[0] : null;
      if (file) this.read(file);
      // Clear it, or picking the same file twice in a row fires no change event.
      event.target.value = '';
    },

    read(file) {
      this.reset();
      // A list is capped at 2,000 values of 200 characters; anything of this order is not a
      // value list and reading it would hang the tab rather than fail.
      if (file.size > 2 * 1024 * 1024) {
        this.error = 'that file is larger than 2 MB — this takes a list of values, one per line';
        return;
      }
      const reader = new FileReader();
      reader.onerror = () => { this.error = 'that file could not be read'; };
      reader.onload = () => {
        this.fileName = file.name;
        this.parsed = this.normalize(reader.result);
        if (!this.parsed.length) { this.error = 'no values in that file'; return; }
        const have = new Set(this.current());
        this.dupes = this.parsed.filter((v) => have.has(v)).length;
        this.fresh = this.parsed.length - this.dupes;
      };
      reader.readAsText(file);
    },

    apply(mode) {
      const box = this.$refs.values;
      if (!box || !this.parsed.length) return;
      const merged = mode === 'replace' ? this.parsed : this.normalize(box.value + '\n' + this.parsed.join('\n'));
      box.value = merged.join('\n');
      // The textarea is what the form posts; tell anything watching it that it changed.
      box.dispatchEvent(new Event('input', { bubbles: true }));
      this.reset();
    },
  };
}
window.listValuesDrop = listValuesDrop;

// ── Starting a rule from an existing one ─────────────────────────────────────
// Backs "Start a rule from this" on a shared rule. Thirty-six of those ship, a member may
// not edit any, and "like that but mine" is the commonest thing to want from one.
//
// It seeds the *condition* and the scope — the part that took the thought — and leaves the
// actions alone, because what to tag or alert on is the decision the analyst is making.
//
// A factory rather than an inline expression: this is five statements, and Alpine's event
// handler evaluator would not parse them in an attribute. It is also the house rule, and
// the reason for it — an expression that fails to compile fails *silently*, leaving a
// button that looks fine and does nothing.
function newRuleSeed() {
  return {
    seed(detail) {
      const box = this.$refs.newRule;
      if (!box || !detail) return;
      box.open = true;
      this.$nextTick(() => {
        const form = box.querySelector('form');
        if (!form) return;
        const name = form.querySelector('[name=name]');
        if (name) name.value = detail.name || '';

        // The scope radios are `x-model`-bound, so the change event is what moves Alpine's
        // copy; setting `.checked` alone leaves the entity-type block and the two help
        // popovers showing the other scope.
        const scope = form.querySelector('input[name=scope][value="' + (detail.scope || 'entity') + '"]');
        if (scope) {
          scope.checked = true;
          scope.dispatchEvent(new Event('change', { bubbles: true }));
        }

        const query = form.querySelector('textarea[name=query]');
        if (query) {
          query.value = detail.query || '';
          // `input` repaints the highlighter; without it the overlay still shows whatever
          // was in the box before, in colour, under the new text.
          query.dispatchEvent(new Event('input', { bubbles: true }));
          // And `keyup` is what the live preview listens for.
          query.dispatchEvent(new Event('keyup', { bubbles: true }));
        }
        box.scrollIntoView({ block: 'center' });
      });
    },
  };
}
window.newRuleSeed = newRuleSeed;
