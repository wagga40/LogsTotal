// The tag picker, which takes several tags.
//
// This is the other half of `tests/test_tag_multi_write.py`: the server parser is pinned
// there, and what reaches it is decided entirely here. A mistake in this file produces a
// perfectly good-looking field that posts the wrong string — a route test cannot see it,
// and neither can a Jinja grep.
//
// Two things are worth the harness on their own:
//   * the submission is written into hidden inputs imperatively, never bound, because htmx
//     serialises a form synchronously inside the submit event while Alpine applies bindings
//     on its own scheduler. Reading those inputs back is reading what the server gets.
//   * `max: 1` has to stay byte-for-byte a single-value control, because that is what the
//     tag manager's rename and merge fields are.

import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';

import { combobox, submitted } from './harness.mjs';

const KNOWN = [
  { tag: 'apt28', color: 'red', count: 12 },
  { tag: 'apt29', color: 'blue', count: 4 },
  { tag: 'ransomware', color: 'purple', count: 2 },
];

describe('single-value mode (max: 1)', () => {
  it('is the control it always was: one pill, and the input goes away', () => {
    const c = combobox({ max: 1 }, KNOWN);
    assert.equal(c.canAdd(), true);
    c.pick(KNOWN[0]);
    assert.deepEqual(c.values, [{ tag: 'apt28', color: 'red' }]);
    assert.equal(c.canAdd(), false, 'the input must hide once the single slot is filled');
    assert.deepEqual(submitted(c), ['apt28', 'red']);
  });

  it('refuses a second tag rather than replacing the first', () => {
    const c = combobox({ max: 1 }, KNOWN);
    c.pick(KNOWN[0]);
    c.pick(KNOWN[1]);
    assert.deepEqual(submitted(c), ['apt28', 'red']);
  });

  it('seeds from a server-rendered value (the rename field starts on the current name)', () => {
    const c = combobox({ max: 1, value: 'apt28', color: 'red' }, KNOWN);
    assert.deepEqual(submitted(c), ['apt28', 'red']);
  });
});

describe('multi-value mode', () => {
  it('collects several tags, each keeping its own colour', () => {
    const c = combobox({ max: 10 }, KNOWN);
    c.pick(KNOWN[0]);
    c.pick(KNOWN[1]);
    // One colour for the whole field would repaint both of these, and a tag name carries
    // one colour instance-wide.
    assert.deepEqual(submitted(c), ['apt28,apt29', 'red,blue']);
  });

  it('creates a new name with the swatch colour, beside picked ones', () => {
    const c = combobox({ max: 10 }, KNOWN);
    c.pick(KNOWN[0]);
    c.query = 'brand-new';
    c.setColor('green');
    c.create();
    assert.deepEqual(submitted(c), ['apt28,brand-new', 'red,green']);
  });

  it('splits on a comma as you type', () => {
    // The single most obvious thing to type into a tag box, and it must not store the
    // literal tag `a,b`: `normalize_tag` does not treat a comma as anything special.
    const c = combobox({ max: 10 }, KNOWN);
    c.query = 'alpha,beta,';
    c.onInput();
    assert.deepEqual(c.values.map((v) => v.tag), ['alpha', 'beta']);
    assert.equal(c.query, '', 'the trailing empty fragment is not a tag');
  });

  it('adopts a known tag colour when its name arrives via a comma', () => {
    const c = combobox({ max: 10 }, KNOWN);
    c.query = 'apt28,';
    c.onInput();
    assert.deepEqual(submitted(c), ['apt28', 'red']);
  });

  it('never adds the same tag twice', () => {
    const c = combobox({ max: 10 }, KNOWN);
    c.pick(KNOWN[0]);
    c.pick(KNOWN[0]);
    c.query = 'apt28';
    c.create();
    assert.deepEqual(submitted(c), ['apt28', 'red']);
  });

  it('drops already-picked tags out of the suggestion list', () => {
    // Offering a chip that does nothing when clicked reads as a broken control.
    const c = combobox({ max: 10 }, KNOWN);
    c.pick(KNOWN[0]);
    assert.deepEqual(c.matches().map((t) => t.tag), ['apt29', 'ransomware']);
    assert.equal(c.canCreate(), false, 'nothing is being typed');
  });

  it('stops at max and does not silently drop the rest', () => {
    const c = combobox({ max: 2 }, KNOWN);
    c.pick(KNOWN[0]);
    c.pick(KNOWN[1]);
    c.pick(KNOWN[2]);
    assert.equal(c.canAdd(), false);
    assert.deepEqual(submitted(c), ['apt28,apt29', 'red,blue']);
  });

  it('removes a pill and keeps the rest aligned with their colours', () => {
    const c = combobox({ max: 10 }, KNOWN);
    c.pick(KNOWN[0]);
    c.pick(KNOWN[1]);
    c.pick(KNOWN[2]);
    c.removeAt(1);
    assert.deepEqual(submitted(c), ['apt28,ransomware', 'red,purple']);
  });

  it('backspace on an empty box removes the last pill', () => {
    const c = combobox({ max: 10 }, KNOWN);
    c.pick(KNOWN[0]);
    c.pick(KNOWN[1]);
    c.onKey({ key: 'Backspace', preventDefault() {} });
    assert.deepEqual(submitted(c), ['apt28', 'red']);
  });

  it('backspace does nothing while there is something typed', () => {
    const c = combobox({ max: 10 }, KNOWN);
    c.pick(KNOWN[0]);
    c.query = 'ap';
    c.onKey({ key: 'Backspace', preventDefault() {} });
    assert.deepEqual(submitted(c), ['apt28', 'red']);
  });

  it('Enter and Tab both commit rather than submitting or moving focus', () => {
    for (const key of ['Enter', 'Tab']) {
      const c = combobox({ max: 10 }, KNOWN);
      c.query = 'fresh';
      c.show();
      let prevented = false;
      c.onKey({ key, preventDefault() { prevented = true; } });
      assert.equal(prevented, true, `${key} must not fall through to the form`);
      assert.deepEqual(c.values.map((v) => v.tag), ['fresh']);
    }
  });

  it('Enter on the exact name of an existing tag commits that tag, not a longer one', () => {
    // The list keeps the vocabulary's usage order, so a more-used tag that merely contains
    // the typed name sat at the top — highlighted — and Enter wrote it instead. A merge field
    // doing that folds a tag into the wrong one.
    const known = [
      { tag: 'apt28-infra', color: 'red', count: 40 },
      { tag: 'apt28', color: 'blue', count: 3 },
    ];
    for (const max of [1, 10]) {
      const c = combobox({ max }, known);
      c.query = 'apt28';
      c.onInput();
      c.onKey({ key: 'Enter', preventDefault() {} });
      assert.deepEqual(submitted(c), ['apt28', 'blue'], `max: ${max}`);
    }
  });

  it('submits what was typed even if nothing was committed', () => {
    // Typing a name and pressing the button without pressing Enter first must not post an
    // empty field — the field looks filled in and would do nothing.
    const c = combobox({ max: 10 }, KNOWN);
    c.query = 'half-typed';
    c.sync();
    assert.deepEqual(submitted(c), ['half-typed', 'gray']);
  });

  it('reset clears everything, including what was typed', () => {
    const c = combobox({ max: 10 }, KNOWN);
    c.pick(KNOWN[0]);
    c.query = 'leftover';
    c.reset();
    assert.deepEqual(submitted(c), ['', '']);
  });

  it('seeds several values with their colours (a watch rule reopened for editing)', () => {
    const c = combobox({ max: 10, value: 'apt28,apt29', colors: ['red', 'blue'] }, KNOWN);
    assert.deepEqual(submitted(c), ['apt28,apt29', 'red,blue']);
  });
});

describe('the submit button cannot lie about what the field would post', () => {
  // `isEmpty()` is what disables Tag / Add / Create / Save / Merge, so that a click with
  // nothing in the field never becomes a request the server has to refuse with a 400. The
  // only way it can be wrong is by disagreeing with `sync()` — and it disagrees silently:
  // a button dimmed over a field holding `half-typed`, or an enabled button that posts an
  // empty string. So the assertion is the agreement itself, in every state this suite can
  // reach, rather than a handful of hand-picked answers.
  const STATES = {
    'fresh': (c) => c,
    'typed, never committed': (c) => { c.query = 'half-typed'; c.sync(); return c; },
    'typed only whitespace': (c) => { c.query = '   '; c.sync(); return c; },
    'one pill picked': (c) => { c.pick(KNOWN[0]); return c; },
    'a pill and more typing': (c) => { c.pick(KNOWN[0]); c.query = 'also'; c.sync(); return c; },
    'picked then removed': (c) => { c.pick(KNOWN[0]); c.removeAt(0); return c; },
    'coined by typing and committing': (c) => { c.query = 'coined'; c.create(); return c; },
    'filled to the cap': (c) => { KNOWN.forEach((t) => c.pick(t)); return c; },
    'after reset': (c) => { c.pick(KNOWN[0]); c.query = 'leftover'; c.reset(); return c; },
  };

  for (const [label, drive] of Object.entries(STATES)) {
    it(`agrees with the hidden input: ${label}`, () => {
      for (const max of [1, 10]) {
        const c = drive(combobox({ max }, KNOWN));
        const posted = submitted(c)[0];
        assert.equal(
          c.isEmpty(),
          posted === '',
          `max: ${max} — isEmpty() said ${c.isEmpty()} while the form would post ${JSON.stringify(posted)}`,
        );
      }
    });
  }

  it('a half-typed name is enough to submit, so the button must be live', () => {
    // The one case worth stating on its own: `sync()` deliberately posts what was typed but
    // never committed, so a button gated on the pills alone would refuse a field the user
    // can see they have filled in.
    const c = combobox({ max: 10 }, KNOWN);
    c.query = 'half-typed';
    c.sync();
    assert.equal(c.isEmpty(), false);
  });
});
