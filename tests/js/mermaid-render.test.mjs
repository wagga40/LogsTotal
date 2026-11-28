/*
 * `mermaid-render.js` renders the diagrams a language model writes into an AI job analysis,
 * and the ones analysts write into case notes and comment threads.
 *
 * This pins `normalizeSource`, which is the only place the file rewrites what the author
 * actually wrote — and therefore the only place it can silently lie. Collapsing whitespace
 * there (`.replace(/[ \t]{2,}/g, ' ')`) breaks two things, measured in Chromium 151 and
 * Firefox 153 against the vendored mermaid 11.16.0:
 *
 *   - `mindmap` derives hierarchy from leading whitespace. Collapsing it flattens every
 *     level to depth 1 and mermaid rejects the diagram ("There can be only one root"), so
 *     a diagram that parses raw degrades to a source block.
 *   - `app/ai/digest.py` asks the model to name real processes and command lines, so
 *     `A["cmd.exe  /c  whoami"]` would be drawn as `cmd.exe /c whoami` — an artefact of the
 *     log rewritten, with no note, in a tool whose job is to report what the log said.
 *
 * The file is an IIFE exporting only `window.renderMermaidIn`, so the pure helper is lifted
 * out of the shipped bytes by name. A rename fails loudly rather than leaving the
 * assertions vacuously green.
 */
import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = readFileSync(path.resolve(HERE, '../../app/static/mermaid-render.js'), 'utf8');

function lift(name) {
  const head = SRC.indexOf('function ' + name + '(');
  assert.notEqual(head, -1, `${name}() is gone from mermaid-render.js — retarget this test`);
  let depth = 0;
  let i = SRC.indexOf('{', head);
  const start = i;
  for (; i < SRC.length; i += 1) {
    if (SRC[i] === '{') depth += 1;
    else if (SRC[i] === '}') { depth -= 1; if (depth === 0) break; }
  }
  return new Function(`${SRC.slice(head, start)}${SRC.slice(start, i + 1)}; return ${name};`)();
}

describe('normalizeSource', () => {
  const normalizeSource = lift('normalizeSource');

  it('replaces <br/> with a space, in every spelling', () => {
    assert.equal(normalizeSource('A["one<br/>two"]'), 'A["one two"]');
    assert.equal(normalizeSource('A["one<br>two"]'), 'A["one two"]');
    assert.equal(normalizeSource('A["one<BR />two"]'), 'A["one two"]');
  });

  it('preserves indentation — mermaid derives hierarchy from it', () => {
    const mindmap = 'mindmap\n  root((incident))\n    Initial Access\n      phishing\n';
    assert.equal(normalizeSource(mindmap), mindmap);
  });

  it('preserves runs of spaces inside a label — they are evidence, not formatting', () => {
    const src = 'flowchart TD\n  A["cmd.exe  /c  whoami"]\n';
    assert.equal(normalizeSource(src), src);
  });

  it('preserves tabs', () => {
    const src = 'flowchart TD\n\t\tA["x"]\n';
    assert.equal(normalizeSource(src), src);
  });

  it('leaves a diagram with neither <br/> nor runs of whitespace byte-identical', () => {
    const src = 'sequenceDiagram\n  A->>B: SMB auth\n  B-->>A: token\n';
    assert.equal(normalizeSource(src), src);
  });
});

describe('mermaid initialize() config', () => {
  /* `flowchart.htmlLabels` alone does not suppress foreignObject in mermaid 11 — the node
     label helper reads the TOP-LEVEL key, and an unset global evaluates to true. Measured:
     4 <foreignObject> with the nested key alone, 0 with the global one. The file's security
     note claims no HTML from a diagram reaches the DOM, which is only true with the global
     key set. */
  it('sets htmlLabels at the top level, not only under flowchart', () => {
    const init = SRC.slice(SRC.indexOf('.initialize({'));
    const body = init.slice(0, init.indexOf('\n        });'));
    assert.match(body, /^\s*htmlLabels:\s*false,/m,
      'htmlLabels must be set globally — `flowchart.htmlLabels` is deprecated and reaches only edge/cluster labels');
  });

  /* `secure` REPLACES mermaid's default list rather than extending it, so every key the
     default protected has to be re-listed. Dropping one silently hands it back to an
     `%%{init:...}%%` directive in model-written text. `theme` is the addition: without it a
     model can paint a light-on-white diagram into a dark page. */
  it('re-lists every default-secure key and adds theme', () => {
    const m = SRC.match(/secure:\s*\[([^\]]*)\]/);
    assert.ok(m, 'the secure allowlist is gone — an %%{init}%% directive can now set anything');
    const keys = new Set(m[1].match(/'([^']+)'/g).map((s) => s.slice(1, -1)));
    for (const k of ['secure', 'securityLevel', 'startOnLoad', 'maxTextSize', 'suppressErrorRendering', 'maxEdges']) {
      assert.ok(keys.has(k), `'${k}' is in mermaid's default secure list and must be repeated — the array replaces it`);
    }
    assert.ok(keys.has('theme'), "'theme' is not in mermaid's default secure list, so it must be added explicitly");
  });

  /* Mermaid 12 made ELK the default layout and `neo` the default look. Both are pinned back
     to the 11 rendering, and both are secured: a model-written `%%{init}%%` directive must
     not be able to switch the layout engine or the look back on. */
  it('pins the dagre layout and classic look, and secures both', () => {
    assert.match(SRC, /layout:\s*'dagre'/);
    assert.match(SRC, /look:\s*'classic'/);
    const keys = new Set(SRC.match(/secure:\s*\[([^\]]*)\]/)[1].match(/'([^']+)'/g).map((s) => s.slice(1, -1)));
    assert.ok(keys.has('layout') && keys.has('look'), 'layout/look must be in the secure list');
    // 12's 120px flowchart minimum made every short label an identical oversized box.
    assert.match(SRC, /flowchart:\s*\{[^}]*minNodeWidth:\s*0/);
  });

  /* `themeCSS` is compiled into the diagram's own <style>, scoped under `#lt-mermaid-N`, but
     a `&` selector is that id itself: `%%{init: {"themeCSS": "&{position:fixed;width:100vw;
     height:100vh;z-index:2147483647}"}}%%` lifts the SVG out of its box and over the whole
     page (measured on the vendored 11.16.0 in Chromium: an opaque 1280x800 layer). And
     `%%{init: {"htmlLabels": true}}%%` brings back the <foreignObject> labels note 2 turns
     off. Diagrams come from comments and case notes other members read, and from model
     output over attacker-written logs, so no key that feeds the stylesheet or undoes the
     label hardening may be settable from the diagram source. */
  it('pins every CSS-bearing key and htmlLabels', () => {
    const m = SRC.match(/secure:\s*\[([^\]]*)\]/);
    const keys = new Set(m[1].match(/'([^']+)'/g).map((s) => s.slice(1, -1)));
    for (const k of ['themeCSS', 'themeVariables', 'fontFamily', 'altFontFamily', 'htmlLabels', 'dompurifyConfig']) {
      assert.ok(keys.has(k), `'${k}' must be in the secure list, or a diagram's %%{init}%% directive can set it`);
    }
  });
});
