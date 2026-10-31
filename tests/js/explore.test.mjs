// Explore's histogram maths and keyboard gate, run on the exact bytes the browser gets.
//
// `layout` turns per-bar counts into canvas rectangles (events above the axis, detected
// events below, both sqrt-scaled so one busy minute does not flatten the rest), and
// `brushRange` turns a drag into the [from, to) range the search then filters by. Both are
// pure; a bug in either draws a plausible chart that zooms to the wrong time.

import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { appSandbox } from './harness.mjs';

const STATIC = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'app', 'static');
const box = {};
box.window = box;
// eslint-disable-next-line no-new-func
new Function('window', readFileSync(join(STATIC, 'explore.js'), 'utf8'))(box);
const { layout, brushRange, bucketLabel } = box.ltExplore;

describe('the histogram layout', () => {
  it('draws nothing without bars or room', () => {
    assert.deepEqual(layout([], [], 100, 50), { axis: 0, bars: [] });
    assert.deepEqual(layout([1], [0], 0, 50).bars, []);
  });

  it('puts events above the axis and detections below, sqrt-scaled', () => {
    const { axis, bars } = layout([100, 25, 0], [4, 0, 0], 300, 100);
    assert.equal(axis, 70);
    assert.equal(bars.length, 3);
    assert.equal(bars[0].up, axis - 2, 'the tallest bar fills the space above the axis');
    assert.equal(bars[1].up, Math.round(0.5 * (axis - 2)), 'sqrt: a quarter of the events is half the height');
    assert.equal(bars[2].up, 0);
    assert.equal(bars[0].down, 100 - axis - 1);
    assert.equal(bars[1].down, 0);
  });

  it('never hides a non-empty bar, however small', () => {
    const { bars } = layout([1_000_000, 1], [1_000_000, 1], 200, 100);
    assert.ok(bars[1].up >= 1 && bars[1].down >= 1);
  });

  it('spreads the bars over the width', () => {
    const { bars } = layout([1, 1, 1, 1], [0, 0, 0, 0], 400, 100);
    assert.deepEqual(bars.map((b) => b.x), [0, 100, 200, 300]);
    assert.equal(bars[0].w, 99, 'a pixel apart when there is room');
  });
});

describe('a drag across the chart', () => {
  const origin = '2026-01-01T00:00:00';

  it('snaps to whole bars', () => {
    assert.deepEqual(brushRange(150, 250, 400, origin, 3600, 4), { from: '2026-01-01T01:00:00', to: '2026-01-01T03:00:00' });
  });

  it('reads the same right to left', () => {
    assert.deepEqual(brushRange(250, 150, 400, origin, 3600, 4), brushRange(150, 250, 400, origin, 3600, 4));
  });

  it('stays inside the axis', () => {
    assert.deepEqual(brushRange(-50, 900, 400, origin, 60, 4), { from: '2026-01-01T00:00:00', to: '2026-01-01T00:04:00' });
  });

  it('covers at least the bar it started in', () => {
    assert.deepEqual(brushRange(10, 11, 400, origin, 60, 4), { from: '2026-01-01T00:00:00', to: '2026-01-01T00:01:00' });
  });

  it('refuses what it cannot place', () => {
    assert.equal(brushRange(0, 10, 400, 'not a time', 60, 4), null);
    assert.equal(brushRange(0, 10, 0, origin, 60, 4), null);
  });
});

describe('bucket labels', () => {
  it('names the largest whole unit', () => {
    assert.equal(bucketLabel(1), '1 second');
    assert.equal(bucketLabel(900), '15 minutes');
    assert.equal(bucketLabel(3600), '1 hour');
    assert.equal(bucketLabel(86400 * 7), '1 week');
    assert.equal(bucketLabel(86400 * 30), '30 days');
  });
});

describe('page shortcuts stand down', () => {
  const { app } = appSandbox();
  const standsDown = app.ltKeyStandsDown;
  const doc = (dialog = false) => ({ querySelector: (sel) => (sel === 'dialog[open]' && dialog ? {} : null) });
  const key = (extra = {}) => ({ key: 'j', target: { tagName: 'BODY', isContentEditable: false }, defaultPrevented: false, altKey: false, ctrlKey: false, metaKey: false, ...extra });

  it('takes a plain key on the page', () => assert.equal(standsDown(key(), doc()), false));
  it('leaves typing alone', () => {
    for (const tagName of ['INPUT', 'TEXTAREA', 'SELECT']) assert.equal(standsDown(key({ target: { tagName } }), doc()), true, tagName);
    assert.equal(standsDown(key({ target: { tagName: 'DIV', isContentEditable: true } }), doc()), true);
  });
  it('leaves chords and handled keys alone', () => {
    for (const mod of ['altKey', 'ctrlKey', 'metaKey', 'defaultPrevented']) assert.equal(standsDown(key({ [mod]: true }), doc()), true, mod);
  });
  it('leaves an open dialog alone', () => assert.equal(standsDown(key(), doc(true)), true));
});
