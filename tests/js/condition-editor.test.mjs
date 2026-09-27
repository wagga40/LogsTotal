// The rule condition editor's tokenizer.
//
// This is the half of the highlighter no Python test can reach. The server renders the same
// bytes whatever this file does; a mistake here paints a working condition as broken, or a
// broken one as fine, and the only symptom is a colour.
//
// The load-bearing rule, and most of what is asserted below: **an unknown `word:value` is
// not an error.** Both grammars treat it as a literal search, because filenames and rule
// ids contain colons. `lt-cond-bad` is reserved for what is structurally certain — an
// unclosed quote, an unclosed regex, an unbalanced paren.

import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import { condition, painted } from './harness.mjs';

// The real `condition_grammar` global, written out by
// `tests/test_condition_grammar.py::test_the_js_fixture_matches_the_shipped_grammar` — so a
// prefix added to either parser cannot silently desynchronise these tests from the browser.
const GRAMMAR = JSON.parse(readFileSync(new URL('./condition-grammar.fixture.json', import.meta.url), 'utf8'));

const classesFor = (c, raw) => painted(c, raw).filter(([t]) => t.trim()).map(([, cls]) => cls);
const textOf = (c, raw) => painted(c, raw).map(([t]) => t).join('');

describe('the text always survives the round trip', () => {
  it('reassembles byte-for-byte, whatever it is', () => {
    const c = condition('entity', GRAMMAR);
    for (const raw of [
      'list:lolbas -tag:known-good',
      '(tag:a OR tag:b) -tag:x',
      're:/^svc a.*/ cidr:10.0.0.0/8',
      '  spaced   out  ',
      '"an exact phrase" plain',
      'unclosed "quote',
      'weird:::value',
      '',
    ]) {
      assert.equal(textOf(c, raw), raw, `lost or invented characters in: ${raw}`);
    }
  });
});

describe('an unknown prefix is a literal, never an error', () => {
  it('leaves a bare word plain', () => {
    const c = condition('entity', GRAMMAR);
    assert.deepEqual(classesFor(c, 'svchost'), ['']);
  });

  it('leaves `word:value` plain rather than flagging it', () => {
    const c = condition('entity', GRAMMAR);
    // A rule id or a path — the commonest search on its most distinctive input.
    assert.deepEqual(classesFor(c, 'sigma:proc_creation'), ['']);
  });

  it('does not colour a jobs-only prefix while the rule applies to entities', () => {
    const c = condition('entity', GRAMMAR);
    assert.deepEqual(classesFor(c, 'status:failed'), ['']);
  });

  it('…and does colour it once the scope says jobs', () => {
    const c = condition('job', GRAMMAR);
    assert.deepEqual(classesFor(c, 'status:failed'), ['lt-cond-key', 'lt-cond-val']);
  });
});

describe('known prefixes split into key and value', () => {
  it('colours the key and the value separately', () => {
    const c = condition('entity', GRAMMAR);
    assert.deepEqual(painted(c, 'tag:apt28'), [['tag:', 'lt-cond-key'], ['apt28', 'lt-cond-val']]);
  });

  it('carries the negation as its own token', () => {
    const c = condition('entity', GRAMMAR);
    assert.deepEqual(painted(c, '-tag:known-good'), [
      ['-', 'lt-cond-neg'], ['tag:', 'lt-cond-key'], ['known-good', 'lt-cond-val'],
    ]);
  });

  it('handles a half-typed key with no value yet', () => {
    const c = condition('entity', GRAMMAR);
    assert.deepEqual(painted(c, 'list:'), [['list:', 'lt-cond-key']]);
  });

  it('matches the key case-insensitively, as the parser lowercases first', () => {
    const c = condition('entity', GRAMMAR);
    assert.deepEqual(classesFor(c, 'TAG:apt28'), ['lt-cond-key', 'lt-cond-val']);
  });
});

describe('a regex is one token even when it contains spaces', () => {
  it('does not shred `re:/^svc a/` into two junk terms', () => {
    const c = condition('entity', GRAMMAR);
    assert.deepEqual(painted(c, 're:/^svc a/'), [['re:/', 'lt-cond-key'], ['^svc a/', 'lt-cond-re']]);
  });

  it('keeps an escaped slash inside the pattern', () => {
    const c = condition('entity', GRAMMAR);
    assert.deepEqual(painted(c, 're:/a\\/b/ tag:x').slice(0, 2), [['re:/', 'lt-cond-key'], ['a\\/b/', 'lt-cond-re']]);
  });

  it('flags one that never closes', () => {
    const c = condition('entity', GRAMMAR);
    assert.deepEqual(classesFor(c, 're:/^admin'), ['lt-cond-bad']);
  });

  it('does not let a regex full of parens reach the grouping rules', () => {
    const c = condition('entity', GRAMMAR);
    assert.deepEqual(classesFor(c, 're:/(a|b)/'), ['lt-cond-key', 'lt-cond-re']);
  });
});

describe('quoting', () => {
  it('takes a quoted phrase whole, spaces and all', () => {
    const c = condition('entity', GRAMMAR);
    assert.deepEqual(painted(c, '"exact phrase"'), [['"exact phrase"', 'lt-cond-str']]);
  });

  it('flags one that never closes', () => {
    const c = condition('entity', GRAMMAR);
    assert.deepEqual(classesFor(c, 'tag:a "oops').slice(-1), ['lt-cond-bad']);
  });

  it('keeps a negated quote together', () => {
    const c = condition('entity', GRAMMAR);
    assert.deepEqual(painted(c, '-"enc"'), [['-', 'lt-cond-neg'], ['"enc"', 'lt-cond-str']]);
  });
});

describe('booleans and grouping', () => {
  it('colours bare uppercase operators only', () => {
    const c = condition('entity', GRAMMAR);
    assert.deepEqual(classesFor(c, 'tag:a OR tag:b'), ['lt-cond-key', 'lt-cond-val', 'lt-cond-bool', 'lt-cond-key', 'lt-cond-val']);
    // lowercase `or` is a literal search term, and the parser agrees.
    assert.deepEqual(classesFor(c, 'a or b'), ['', '', '']);
  });

  it('balances parens', () => {
    const c = condition('entity', GRAMMAR);
    assert.deepEqual(classesFor(c, '(tag:a OR tag:b)').filter((k) => k === 'lt-cond-paren').length, 2);
  });

  it('flags an opener that never closes', () => {
    const c = condition('entity', GRAMMAR);
    assert.deepEqual(classesFor(c, '(tag:a'), ['lt-cond-bad', 'lt-cond-key', 'lt-cond-val']);
  });

  it('flags a closer with nothing open', () => {
    const c = condition('entity', GRAMMAR);
    assert.deepEqual(classesFor(c, 'tag:a)').slice(-1), ['lt-cond-bad']);
  });
});

describe('the term count under the field', () => {
  const count = (raw, scope = 'entity') => {
    const c = condition(scope, GRAMMAR);
    c.$refs = { search: { value: raw } };
    return c.termCount();
  };

  it('counts one per term, not one per token', () => {
    assert.equal(count('list:lolbas -tag:known-good'), 2);
    assert.equal(count('svchost'), 1);
    assert.equal(count('"exact phrase"'), 1);
    assert.equal(count('re:/^a/ tag:b cidr:10.0.0.0/8'), 3);
  });

  it('does not count grammar as terms', () => {
    assert.equal(count('(tag:a OR tag:b)'), 2);
  });

  it('is zero for an empty or blank condition', () => {
    assert.equal(count(''), 0);
    assert.equal(count('   '), 0);
  });
});

describe('in:(a,b) is one term, not a key and a group', () => {
  it('keeps the whole set together', () => {
    const c = condition('entity', GRAMMAR);
    assert.deepEqual(painted(c, 'in:(psexec.exe,wmic.exe)'), [
      ['in:', 'lt-cond-key'], ['(psexec.exe,wmic.exe)', 'lt-cond-val'],
    ]);
  });

  it('does not let its parens reach the balance check', () => {
    // Without its own pass the walk ends the term at '(', and the closing ')' of a set
    // inside a real group would then look like the group's own — so a balanced query would
    // be flagged, or an unbalanced one would not.
    const c = condition('entity', GRAMMAR);
    assert.deepEqual(painted(c, '(in:(a,b) OR tag:x)').map(([, k]) => k).filter(Boolean), [
      'lt-cond-paren', 'lt-cond-key', 'lt-cond-val', 'lt-cond-bool', 'lt-cond-key', 'lt-cond-val', 'lt-cond-paren',
    ]);
  });

  it('is negatable', () => {
    const c = condition('entity', GRAMMAR);
    assert.deepEqual(painted(c, '-in:(a)'), [['-', 'lt-cond-neg'], ['in:', 'lt-cond-key'], ['(a)', 'lt-cond-val']]);
  });

  it('flags a set that never closes', () => {
    const c = condition('entity', GRAMMAR);
    assert.deepEqual(painted(c, 'in:(a,b'), [['in:(a,b', 'lt-cond-bad']]);
  });

  it('counts as one term', () => {
    const c = condition('entity', GRAMMAR);
    c.$refs = { search: { value: 'in:(a,b,c) tag:x' } };
    assert.equal(c.termCount(), 2);
  });
});

describe('the arrow keys belong to the caret while no list is open', () => {
  // The condition is a multi-line textarea whose help text invites one term per line.
  // `searchSuggest.onKey` treats ArrowDown on a closed list as "show me completions" and
  // prevents it, which is right for the one-line search boxes and meant the caret could
  // never move down a line here.
  const key = (k) => {
    const e = { key: k, prevented: false, preventDefault() { this.prevented = true; } };
    return e;
  };

  it('lets ArrowDown move the caret when the list is closed', () => {
    const c = condition('entity', GRAMMAR);
    let loads = 0;
    c.load = () => { loads += 1; };
    c.open = false;
    const e = key('ArrowDown');
    c.onKey(e);
    assert.equal(e.prevented, false);
    assert.equal(loads, 0);
  });

  it('still cycles an open list', () => {
    const c = condition('entity', GRAMMAR);
    c.open = true;
    c.items = [{ insert: 'a' }, { insert: 'b' }];
    c.highlight = 0;
    const e = key('ArrowDown');
    c.onKey(e);
    assert.equal(e.prevented, true);
    assert.equal(c.highlight, 1);
  });
});
