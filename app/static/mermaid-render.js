/*
 * Renders ```mermaid blocks inside analyst prose — AI analyses, case notes, comments.
 *
 * THREE THINGS THIS FILE EXISTS TO GET RIGHT:
 *
 * 1. The bundle is 3.5 MB. It is fetched **only** when a `pre.mermaid` actually appears, so
 *    a job page with no diagram — which is most of them — pays nothing. `docs/index.html`
 *    loads mermaid eagerly instead, and should: on that page diagrams are the content.
 *
 * 2. This renders text a language model wrote while summarising **untrusted log data**.
 *    That is a different trust level from the hand-authored diagrams on the docs page, so
 *    the config here is deliberately stricter than that page's and the two must not be
 *    merged: `securityLevel: 'strict'` encodes HTML in labels and disables click handlers,
 *    and `htmlLabels: false` renders labels as SVG <text> so no HTML from the diagram
 *    reaches the DOM at all.
 *
 *    **`htmlLabels` has to be set at the TOP level, not under `flowchart`.**
 *    `flowchart.htmlLabels` is deprecated in mermaid 11: the node-label helper reads the
 *    global one, and an unset global evaluates to *true*. Measured on the vendored 11.16.0
 *    in Chromium 151 and Firefox 153, a three-node flowchart emits 4 <foreignObject>
 *    wrappers with the nested key alone and 0 with the global key — so the label of
 *    `A["<img src=x onerror=alert(1)>"]` arrives as a live <img> element rather than as
 *    text. Not exploitable on its own (mermaid's bundled DOMPurify strips the handler and
 *    `img-src 'self' data:` blocks the fetch), but that is the two-libraries-must-agree
 *    posture `app/markdown_render.py` argues against. Verified across 13 diagram families:
 *    setting the global key changes nothing except the foreignObject count.
 *
 *    `secure` pins the keys an `%%{init:...}%%` directive in the diagram source cannot
 *    reach. It **replaces** mermaid's default list rather than extending it, so every key
 *    already in that default is re-listed below — dropping one silently gives model-written
 *    text back the ability to set it. `theme` is added because it is *not* in the default:
 *    without it a model can emit `%%{init: {'theme':'default'}}%%` and paint a
 *    light-on-white diagram into a dark page (measured, both engines).
 *
 * 3. Models emit invalid mermaid regularly. Every diagram is parsed before it is rendered
 *    and failures degrade to the source as a code block — never a mermaid error card, and
 *    never a blank space where a reader cannot tell whether anything was meant to be there.
 */
(function () {
  'use strict';

  // The palette matches docs/index.html. Kept separate on purpose — see note 2 above; the
  // security-relevant keys differ, and merging the objects would invite someone to reunify
  // those too. If the colours change, change both.
  var THEME_VARIABLES = {
    darkMode: true,
    background: '#030712',
    primaryColor: '#1e3a5f',
    primaryTextColor: '#e5e7eb',
    primaryBorderColor: '#374151',
    lineColor: '#6b7280',
    secondaryColor: '#1c1917',
    tertiaryColor: '#111827',
    fontFamily: 'ui-sans-serif, system-ui, sans-serif',
    fontSize: '13px'
  };

  // A diagram longer than this is not a diagram, it is a paste. mermaid's own maxTextSize
  // would reject it too, but late and with an error card.
  var MAX_DIAGRAM_CHARS = 20000;

  var loadPromise = null;
  var seq = 0;

  function scriptUrl() {
    var tag = document.querySelector('script[data-mermaid-src]');
    return tag ? tag.getAttribute('data-mermaid-src') : null;
  }

  /* Inject the vendor bundle once. Resolves to the mermaid global, or rejects. */
  function ensureMermaid() {
    if (loadPromise) return loadPromise;
    loadPromise = new Promise(function (resolve, reject) {
      if (window.mermaid) return resolve(window.mermaid);
      var url = scriptUrl();
      if (!url) return reject(new Error('no mermaid source configured'));
      var el = document.createElement('script');
      el.src = url;
      el.async = true;
      el.onload = function () {
        if (!window.mermaid) return reject(new Error('mermaid did not define itself'));
        window.mermaid.initialize({
          startOnLoad: false,
          securityLevel: 'strict',
          theme: 'dark',
          themeVariables: THEME_VARIABLES,
          maxTextSize: MAX_DIAGRAM_CHARS,
          // Global, not just `flowchart.htmlLabels` — see note 2. The nested key is kept
          // because it is what the edge and cluster label paths still read.
          htmlLabels: false,
          flowchart: { curve: 'basis', padding: 16, htmlLabels: false },
          // Replaces mermaid's default secure list, so all of it is repeated here. `theme`
          // is the addition; everything else is what the default already protected.
          secure: [
            'secure',
            'securityLevel',
            'startOnLoad',
            'maxTextSize',
            'suppressErrorRendering',
            'maxEdges',
            'theme'
          ],
          // Suppresses mermaid's own error diagram; we render our own fallback, which keeps
          // the source readable instead of replacing it with a red cross.
          suppressErrorRendering: true
        });
        resolve(window.mermaid);
      };
      el.onerror = function () { reject(new Error('mermaid failed to load')); };
      document.head.appendChild(el);
    });
    return loadPromise;
  }

  /* Put the source back as a plain code block, with a quiet note saying why. */
  function degrade(node, reason) {
    var source = node.getAttribute('data-mermaid-source') || node.textContent;
    var wrapper = document.createElement('div');

    var note = document.createElement('p');
    note.className = 'lt-mermaid-note';
    note.textContent = reason;

    var pre = document.createElement('pre');
    var code = document.createElement('code');
    // textContent, never innerHTML: this is the one path that handles the source after a
    // failure, and it must not become the hole the escaped rendering above closed.
    code.textContent = source;
    pre.appendChild(code);

    wrapper.appendChild(note);
    wrapper.appendChild(pre);
    node.replaceWith(wrapper);
  }

  /* Fix the one thing models reliably write that this renderer cannot show.
   *
   * `<br/>` inside a label is idiomatic mermaid — but only under `htmlLabels: true`, which
   * this file deliberately does not use (note 2). Left alone it does not error; it renders
   * the literal characters "<br/>" in the middle of a node, which reads as a bug in the
   * product rather than in the diagram. Enabling HTML labels would fix it by putting a
   * sanitiser in the trust chain, which is exactly the dependency `app/markdown_render.py`
   * argues against. Replacing it with a space costs a line break and keeps the label true.
   *
   * **This substitutes; it does not tidy.** Collapsing whitespace runs
   * (`.replace(/[ \t]{2,}/g, ' ')`) does two kinds of damage. It breaks every
   * indentation-derived diagram outright — `mindmap` reads hierarchy from leading
   * whitespace, so collapsing it flattens every level to depth 1 and mermaid rejects the
   * result with "There can be only one root"; a diagram that parses raw degrades to a source
   * block (measured, both engines). And on the AI pane it rewrites evidence:
   * `app/ai/digest.py` asks the model to put real process names and command lines in the
   * diagram, so `A["cmd.exe  /c  whoami"]` would be drawn as `cmd.exe /c whoami` — silently,
   * with no note, in a tool whose job is to report what the log said. Whitespace inside a
   * label is content here, not formatting.
   */
  function normalizeSource(source) {
    return source.replace(/<br\s*\/?>/gi, ' ');
  }

  function renderOne(mermaid, node) {
    var source = node.textContent || '';
    // The ORIGINAL source is stored, not the normalised one: this attribute is what the
    // degrade path shows the reader, and it should show what the model actually wrote.
    node.setAttribute('data-mermaid-source', source);
    // The claim has served its purpose; `data-mermaid-source` is the durable marker.
    node.removeAttribute('data-mermaid-pending');

    if (source.length > MAX_DIAGRAM_CHARS) {
      degrade(node, 'Diagram too large to render — source below.');
      return Promise.resolve();
    }

    var prepared = normalizeSource(source);
    seq += 1;
    var id = 'lt-mermaid-' + seq;

    return Promise.resolve()
      .then(function () { return mermaid.parse(prepared, { suppressErrors: true }); })
      .then(function (ok) {
        if (!ok) throw new Error('invalid diagram syntax');
        return mermaid.render(id, prepared);
      })
      .then(function (result) {
        // mermaid sanitises its own output at securityLevel 'strict'; this is its
        // documented render API, not a hand-assembled string.
        node.innerHTML = result.svg;
        node.classList.add('lt-mermaid-rendered');
      })
      .catch(function () {
        degrade(node, 'This diagram could not be rendered — showing the source instead.');
      });
  }

  // Scoped to `.lt-prose` — rendered Markdown — and that scope is load-bearing, not tidiness.
  // docs/index.html also contains `pre.mermaid`, initialises mermaid itself with
  // `startOnLoad: true`, and its diagrams use `<br/>` inside labels, which only renders
  // under `htmlLabels: true`. An unscoped selector would find those, re-render them under
  // this file's stricter config, and break them — while racing that page's own init.
  // Filtered with `closest` rather than queried as `.lt-prose pre.mermaid`, because htmx may
  // swap the `.lt-prose` element itself — and an element is not its own descendant, so a
  // descendant selector would silently find nothing in exactly that case.
  // Two exclusions, and the second one is the fix for a visible flicker.
  //
  // `data-mermaid-source` marks a diagram that has been rendered — but it is only set once
  // `renderOne` runs, which is *after* `ensureMermaid()` resolves. On the first diagram that
  // means after a 3.5 MB script fetch, and every htmx swap arriving in that window re-entered
  // `renderIn`, found the same still-unmarked node, and queued another render of it. Lazy
  // tabs, a comment thread and a polling region make several swaps in a few hundred
  // milliseconds routine, so one diagram got drawn repeatedly and flickered as each chain
  // overwrote the last. `data-mermaid-pending` is claimed synchronously below, before any
  // await, which is the only place that can close the gap.
  var SELECTOR = 'pre.mermaid:not([data-mermaid-source]):not([data-mermaid-pending])';
  var PROSE = '.lt-prose';

  // Serialises render work across *calls*, not just within one. mermaid.render mutates a
  // shared DOM sandbox, so two chains running at once interleave their temporary nodes.
  var queue = Promise.resolve();

  function diagramsIn(root) {
    var found = Array.prototype.slice.call(root.querySelectorAll(SELECTOR));
    if (root.matches && root.matches(SELECTOR)) found.push(root);
    return found.filter(function (n) { return n.closest && n.closest(PROSE); });
  }

  /* Render every unrendered diagram inside `root`. Safe to call repeatedly. */
  function renderIn(root) {
    if (!root || !root.querySelectorAll) return;
    var nodes = diagramsIn(root);
    if (!nodes.length) return;

    // Claim them now, synchronously. See the SELECTOR comment: everything below this line
    // is asynchronous, and an unclaimed node is a node another swap will pick up too.
    nodes.forEach(function (node) { node.setAttribute('data-mermaid-pending', '1'); });

    queue = queue
      .then(function () { return ensureMermaid(); })
      .then(function (mermaid) {
        return nodes.reduce(function (chain, node) {
          return chain.then(function () { return renderOne(mermaid, node); });
        }, Promise.resolve());
      })
      .catch(function () {
        nodes.forEach(function (node) {
          degrade(node, 'Diagram rendering is unavailable — showing the source instead.');
        });
      });
  }

  window.renderMermaidIn = renderIn;

  function boot() { renderIn(document.body); }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

  // Prose arrives by htmx more often than by page load: the AI pane, comment threads and
  // case notes are all swapped in. afterSettle rather than afterSwap so the nodes are in
  // their final position before mermaid measures them.
  //
  // Scanned from `document.body`, NOT from `ev.detail.target`. Under `hx-swap="outerHTML"`,
  // which every self-contained region in this app uses including the AI pane,
  // `detail.target` is the element that was *replaced*: detached from the document and
  // containing none of the new content. Scanning it finds zero diagrams every time, so the
  // vendor bundle is never requested and the block sits on screen as raw `flowchart TD`
  // source. Re-scanning the document is cheap, and
  // `:not([data-mermaid-source])` in the selector makes the work idempotent — an
  // already-rendered diagram is skipped before any DOM is touched.
  document.body.addEventListener('htmx:afterSettle', function () {
    renderIn(document.body);
  });
})();
