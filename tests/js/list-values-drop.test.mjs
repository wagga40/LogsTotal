// Loading a list's values from a file.
//
// There is no upload route: a dropped file is parsed here and written into the `values`
// textarea the form already posts. So this file is the whole contract, and a Python test
// cannot see any of it.
//
// The parse mirrors `rule_lists.normalize_values`, and that is load-bearing rather than
// tidy: the zone reports "68 new, 4 already here" *before* you choose Replace or Add, and a
// client counting differently from the server would be lying about what is about to happen.
// `tests/test_list_values_drop.py` runs the same cases through the real Python.

import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';

import { valuesDrop } from './harness.mjs';

describe('the parse mirrors normalize_values', () => {
  const cases = [
    ['a\nb\nc', ['a', 'b', 'c']],
    ['a,b,c', ['a', 'b', 'c'], 'commas count too'],
    ['A\nB', ['a', 'b'], 'lowercased'],
    ['  a  \n\tb\t', ['a', 'b'], 'trimmed'],
    ['a\n\n\nb', ['a', 'b'], 'blanks dropped'],
    ['a\nb\na', ['a', 'b'], 'duplicates dropped, first position kept'],
    ['b\na', ['b', 'a'], 'order preserved'],
    ['', [], 'empty is empty'],
    ['a\r\nb', ['a', 'b'], 'CRLF — a .txt from Windows is the common case'],
  ];
  for (const [input, expected, why] of cases) {
    it(why || JSON.stringify(input), () => {
      assert.deepEqual(valuesDrop().normalize(input), expected);
    });
  }
});

describe('the count it reports before you commit', () => {
  const load = (existing, fileText) => {
    const d = valuesDrop(existing);
    d.fileName = 'f.txt';
    d.parsed = d.normalize(fileText);
    const have = new Set(d.current());
    d.dupes = d.parsed.filter((v) => have.has(v)).length;
    d.fresh = d.parsed.length - d.dupes;
    return d;
  };

  it('separates what is new from what is already there', () => {
    const d = load('a\nb', 'b\nc\nd');
    assert.equal(d.parsed.length, 3);
    assert.equal(d.fresh, 2);
    assert.equal(d.dupes, 1);
  });

  it('counts case-insensitively, because the list does', () => {
    const d = load('psexec.exe', 'PSEXEC.EXE\nwmic.exe');
    assert.equal(d.dupes, 1);
    assert.equal(d.fresh, 1);
  });

  it('is all-new against an empty box', () => {
    const d = load('', 'a\nb');
    assert.equal(d.fresh, 2);
    assert.equal(d.dupes, 0);
  });
});

describe('what it writes into the textarea', () => {
  const loaded = (existing, fileText) => {
    const d = valuesDrop(existing);
    d.parsed = d.normalize(fileText);
    return d;
  };

  it('Add merges without duplicating', () => {
    const d = loaded('a\nb', 'b\nc');
    d.apply('add');
    assert.equal(d.box.value, 'a\nb\nc');
  });

  it('Add keeps what was there first', () => {
    const d = loaded('z\ny', 'a');
    d.apply('add');
    assert.equal(d.box.value, 'z\ny\na');
  });

  it('Replace discards what was there', () => {
    const d = loaded('a\nb\nc', 'x\ny');
    d.apply('replace');
    assert.equal(d.box.value, 'x\ny');
  });

  it('normalises what it writes, so the box always holds one value per line', () => {
    const d = loaded('', 'A, b ,,a');
    d.apply('replace');
    assert.equal(d.box.value, 'a\nb');
  });

  it('clears itself after applying, so a second file starts fresh', () => {
    const d = loaded('a', 'b');
    d.apply('add');
    assert.deepEqual(d.parsed, []);
    assert.equal(d.fileName, '');
  });

  it('does nothing with no file loaded', () => {
    const d = valuesDrop('a\nb');
    d.apply('replace');
    assert.equal(d.box.value, 'a\nb', 'an empty apply must not wipe the list');
  });
});

describe('refusing a file that is not a value list', () => {
  it('refuses one too large to be one, rather than hanging the tab', () => {
    const d = valuesDrop();
    d.read({ size: 3 * 1024 * 1024, name: 'huge.bin' });
    assert.match(d.error, /larger than 2 MB/);
    assert.deepEqual(d.parsed, []);
  });
});
