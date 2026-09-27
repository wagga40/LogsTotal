// The Worker Fleet page's 5s poll, and the capacity edits that pause it.
//
// The gate exists so a swap cannot wipe a half-typed capacity value, and it must not
// LATCH: set `window.__workersPriorityDirty = true` on the first keystroke and only a form
// submit or a full page load could clear it — anything outside `#workers-region`, which is
// all `/admin/workers/partial` swaps, is unreachable to a poll. One digit typed and walked
// away would stop the page refreshing for good: the fleet table, the queue depth and every
// heartbeat TTL on it frozen at whatever was on screen.
//
// A Python test cannot see any of this — the server renders identically either way.

import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';

import { appSandbox } from './harness.mjs';

/** The exact expression `hx-trigger="every 5s[!window.__workersPriorityDirty]"` evaluates. */
const polling = (box) => !box.app.__workersPriorityDirty;

describe('the poll gate tracks the values, not the first keystroke', () => {
  it('polls on a page nobody has touched', () => {
    const box = appSandbox();
    assert.equal(polling(box), true);
  });

  it('pauses while an edit differs from the saved value', () => {
    const box = appSandbox();
    box.app.ltWorkersCapacity.mark('host-a', true);
    assert.equal(polling(box), false);
  });

  it('resumes when the edit is reverted, with no submit and no reload', () => {
    const box = appSandbox();
    box.app.ltWorkersCapacity.mark('host-a', true);
    box.app.ltWorkersCapacity.mark('host-a', false);
    assert.equal(polling(box), true);
  });

  it('keeps pausing while another host is still edited', () => {
    const box = appSandbox();
    box.app.ltWorkersCapacity.mark('host-a', true);
    box.app.ltWorkersCapacity.mark('host-b', true);
    box.app.ltWorkersCapacity.mark('host-a', false);
    assert.equal(polling(box), false, 'host-b still has an unsaved capacity');
    box.app.ltWorkersCapacity.mark('host-b', false);
    assert.equal(polling(box), true);
  });

  it('gives the page back when nobody comes back to the edit', () => {
    const box = appSandbox();
    box.app.ltWorkersCapacity.mark('host-a', true);
    assert.equal(polling(box), false);
    box.runTimers();
    assert.equal(polling(box), true, 'an abandoned edit must not freeze the page for good');
  });

  it('re-arms the give-up timer on every edit, so typing is never interrupted', () => {
    const box = appSandbox();
    box.app.ltWorkersCapacity.mark('host-a', true);
    const first = box.timers.length;
    box.app.ltWorkersCapacity.mark('host-a', true);
    assert.equal(box.timers[first - 1].cleared, true, 'the earlier deadline must be cancelled');
    assert.ok(box.timers.length > first, 'a fresh deadline must replace it');
  });

  it('schedules nothing once every edit is reverted', () => {
    const box = appSandbox();
    box.app.ltWorkersCapacity.mark('host-a', true);
    box.app.ltWorkersCapacity.mark('host-a', false);
    box.runTimers();
    assert.equal(polling(box), true);
  });

  it('clears everything on submit', () => {
    const box = appSandbox();
    box.app.ltWorkersCapacity.mark('host-a', true);
    box.app.ltWorkersCapacity.mark('host-b', true);
    box.app.ltWorkersCapacity.reset();
    assert.equal(polling(box), true);
  });
});
