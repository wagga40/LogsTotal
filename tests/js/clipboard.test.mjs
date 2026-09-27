// Copying, on a page that is not a secure context.
//
// `navigator.clipboard` exists only over HTTPS or on localhost. LogsTotal ships a
// supported plain-HTTP mode, and there the whole API is `undefined`: a bare
// `navigator.clipboard.writeText(…)` throws a TypeError, and a guarded one does nothing.
//
// This is the file that can see it. A route test renders a perfect button either way, and
// no Python grep can tell a working copy path from a dead one — the same reason
// `tag-combobox.test.mjs` exists.

import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';

import { appSandbox, el } from './harness.mjs';

/** `navigator.clipboard` that records what it was asked to write. */
function nativeClipboard(behaviour = 'resolve') {
  const wrote = [];
  return {
    wrote,
    writeText(text) {
      wrote.push(text);
      return behaviour === 'resolve' ? Promise.resolve() : Promise.reject(new Error('denied'));
    },
  };
}

/** Drain the microtask queue. `ltCopy` is three `.then`/`.catch` links deep, so
 *  counting `await Promise.resolve()` by hand is a way to write a test that passes
 *  for the wrong reason. */
const flush = () => new Promise((r) => setImmediate(r));

/** The textareas the legacy path made — it is supposed to leave none behind. */
const textareas = (box) => box.created.filter((n) => n.tagName === 'TEXTAREA');

describe('ltCopy: the secure-context path', () => {
  it('uses navigator.clipboard when the page has one', async () => {
    const clip = nativeClipboard();
    const box = appSandbox({ clipboard: clip });

    await box.app.ltCopy('powershell -enc SQBFAFgA');

    assert.deepEqual(clip.wrote, ['powershell -enc SQBFAFgA']);
    assert.equal(textareas(box).length, 0, 'the fallback must not run when the API works');
  });
});

describe('ltCopy: the insecure-context path (the reported bug)', () => {
  it('falls back to execCommand when navigator.clipboard is undefined', async () => {
    const copied = [];
    const box = appSandbox({
      execCommand: function () {
        copied.push(this === undefined ? null : 'called');
        return true;
      },
    });

    await box.app.ltCopy('C:\\Windows\\System32\\cmd.exe /c whoami');

    const [ta] = textareas(box);
    assert.ok(ta, 'a <textarea> is the only way to reach execCommand');
    assert.equal(ta.value, 'C:\\Windows\\System32\\cmd.exe /c whoami');
    assert.equal(copied.length, 1);
  });

  it('selects the whole value — select() alone is ignored by iOS Safari on a readonly field', async () => {
    const box = appSandbox({ execCommand: () => true });
    await box.app.ltCopy('abcdef');
    const [ta] = textareas(box);
    assert.equal(ta.selected, true);
    assert.deepEqual(ta.selectionRange, [0, 6]);
  });

  it('keeps the textarea off-screen rather than hidden, because hidden cannot be selected', async () => {
    const box = appSandbox({ execCommand: () => true });
    await box.app.ltCopy('x');
    const [ta] = textareas(box);
    assert.equal(ta.style.position, 'fixed');
    assert.notEqual(ta.style.display, 'none');
    assert.equal(ta.style.opacity, '0');
  });

  it('removes the textarea and restores focus', async () => {
    const focused = el('input');
    const box = appSandbox({ execCommand: () => true, activeElement: focused });
    await box.app.ltCopy('x');
    assert.equal(textareas(box)[0].removed, true);
    assert.equal(focused.focused, true, 'stealing focus to copy and not giving it back loses the caret');
  });

  it('falls back when the API is present but the write is refused', async () => {
    const clip = nativeClipboard('reject');
    const box = appSandbox({ clipboard: clip, execCommand: () => true });

    await box.app.ltCopy('denied-then-copied');

    assert.deepEqual(clip.wrote, ['denied-then-copied'], 'the native path is still tried first');
    assert.equal(textareas(box)[0].value, 'denied-then-copied');
  });
});

describe('ltCopy: when it genuinely cannot copy', () => {
  it('rejects, and says so out loud', async () => {
    const box = appSandbox({ execCommand: () => false });

    await assert.rejects(box.app.ltCopy('x'));

    assert.equal(box.toastHidden(), false, 'a copy button that does nothing is the bug, not the fix');
    assert.match(box.toastText(), /Ctrl/);
  });

  it('removes the textarea even when execCommand throws', async () => {
    const box = appSandbox({
      execCommand: () => {
        throw new Error('nope');
      },
    });
    await assert.rejects(box.app.ltCopy('secret-token'));
    assert.equal(textareas(box)[0].removed, true, 'a leaked textarea keeps the value alive in the DOM');
  });

  it('rejects cleanly on an engine with no execCommand at all', async () => {
    const box = appSandbox({ execCommand: null });
    await assert.rejects(box.app.ltCopy('x'));
    assert.equal(textareas(box).length, 0);
  });
});

describe('ltCopy: what actually gets written', () => {
  it('coerces rather than writing "undefined" or throwing', async () => {
    const clip = nativeClipboard();
    const box = appSandbox({ clipboard: clip });
    await box.app.ltCopy(null);
    await box.app.ltCopy(42);
    assert.deepEqual(clip.wrote, ['', '42']);
  });
});

// ── The delegated button handler ─────────────────────────────────────────────

/** A copy button with its two marker icons, inside a parent holding the source. */
function buttonAndSource({ target, from, sourceTag = 'pre', text = 'the source text' }) {
  const btn = el('button', { classes: ['logstotal-copy-btn'], dataset: {} });
  if (target) btn.dataset.copyTarget = target;
  if (from) btn.dataset.copyFrom = from;
  const def = el('svg', { classes: ['logstotal-copy-icon-default'] });
  const done = el('svg', { classes: ['logstotal-copy-icon-done', 'hidden'] });
  btn.append(def, done);

  const source = el(sourceTag, { textContent: text });
  const parent = el('div');
  parent.append(btn, source);
  return { btn, def, done, source, parent };
}

describe('the delegated copy handler', () => {
  it('resolves the source by id (data-copy-target)', async () => {
    const clip = nativeClipboard();
    const { btn, source } = buttonAndSource({ target: 'ruleCode7' });
    const box = appSandbox({ clipboard: clip, elements: { ruleCode7: source } });

    box.click(btn);
    await flush();

    assert.deepEqual(clip.wrote, ['the source text']);
  });

  it('resolves the source by selector among the button\u2019s siblings (data-copy-from)', async () => {
    const clip = nativeClipboard();
    const { btn } = buttonAndSource({ from: 'pre', text: 'sibling text' });
    const box = appSandbox({ clipboard: clip });

    box.click(btn);
    await flush();

    // This is the process tree's case: buttons rendered per node by a macro, with no
    // unique id to point at.
    assert.deepEqual(clip.wrote, ['sibling text']);
  });

  it('swaps to the check mark only once the copy has actually happened', async () => {
    const clip = nativeClipboard();
    const { btn, def, done } = buttonAndSource({ from: 'pre' });
    const box = appSandbox({ clipboard: clip });

    box.click(btn);
    assert.equal(def.classes.has('hidden'), false, 'nothing may change before the write resolves');

    await flush();

    assert.equal(def.classes.has('hidden'), true);
    assert.equal(done.classes.has('hidden'), false);

    box.runTimers();
    assert.equal(def.classes.has('hidden'), false, 'and it goes back');
    assert.equal(done.classes.has('hidden'), true);
  });

  it('does NOT show a check mark when the copy failed', async () => {
    const { btn, def, done } = buttonAndSource({ from: 'pre' });
    const box = appSandbox({ execCommand: () => false });

    box.click(btn);
    await flush();

    assert.equal(done.classes.has('hidden'), true, 'a check mark over a failed copy is a lie');
    assert.equal(def.classes.has('hidden'), false);
    assert.equal(box.toastHidden(), false);
  });

  it('ignores a click that is not on a copy button, and a button whose source is gone', async () => {
    const clip = nativeClipboard();
    const box = appSandbox({ clipboard: clip });

    box.click(el('div'));
    const orphan = el('button', { classes: ['logstotal-copy-btn'], dataset: { copyTarget: 'nope' } });
    el('div').append(orphan);
    box.click(orphan);
    await flush();

    assert.deepEqual(clip.wrote, []);
  });
});
