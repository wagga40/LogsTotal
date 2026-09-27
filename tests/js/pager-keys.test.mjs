// ← and → turn the page on a list whose pager opts in with `data-pager-keys`.
//
// The decision is `ltPagerKeyTarget(event, doc)` in app.js — pure given a document, so it is
// tested here against stubs rather than a browser. Every "no" below is a place an arrow key
// already means something else, and taking it over there would break the page: a text
// field's caret, a select's options, a horizontally scrolling table, an open dialog, and
// the browser's own Alt+← (back).

import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';

import { appSandbox } from './harness.mjs';

const { app } = appSandbox();
const target = app.ltPagerKeyTarget;

function control({ disabled = false, ariaDisabled = false } = {}) {
  return {
    hasAttribute: (name) => name === 'disabled' && disabled,
    getAttribute: (name) => (name === 'aria-disabled' && ariaDisabled ? 'true' : null),
  };
}

function doc({ prev = control(), next = control(), dialog = false } = {}) {
  return {
    querySelector: (sel) => {
      if (sel === 'dialog[open]') return dialog ? {} : null;
      if (sel === '[data-pager-keys] [data-pager-prev]') return prev;
      if (sel === '[data-pager-keys] [data-pager-next]') return next;
      return null;
    },
  };
}

const body = { tagName: 'BODY', isContentEditable: false, scrollWidth: 0, clientWidth: 0 };
const key = (k, extra = {}) => ({ key: k, target: body, defaultPrevented: false, altKey: false, ctrlKey: false, metaKey: false, shiftKey: false, ...extra });

describe('the arrows turn the page', () => {
  it('→ presses Next and ← presses Prev', () => {
    const d = doc();
    assert.equal(target(key('ArrowRight'), d), d.querySelector('[data-pager-keys] [data-pager-next]'));
    assert.equal(target(key('ArrowLeft'), d), d.querySelector('[data-pager-keys] [data-pager-prev]'));
  });

  it('ignores every other key', () => {
    for (const k of ['ArrowUp', 'ArrowDown', 'Enter', 'j', 'PageDown']) assert.equal(target(key(k), doc()), null, k);
  });

  it('does nothing at either end', () => {
    assert.equal(target(key('ArrowLeft'), doc({ prev: control({ ariaDisabled: true }) })), null, 'a link pager ends in an aria-disabled span');
    assert.equal(target(key('ArrowRight'), doc({ next: control({ disabled: true }) })), null, 'a button pager ends disabled');
  });

  it('does nothing on a page without an opted-in pager', () => {
    assert.equal(target(key('ArrowRight'), doc({ next: null })), null);
  });
});

describe('where an arrow already means something else', () => {
  it('leaves fields alone', () => {
    for (const tagName of ['INPUT', 'TEXTAREA', 'SELECT']) {
      assert.equal(target(key('ArrowRight', { target: { ...body, tagName } }), doc()), null, tagName);
    }
    assert.equal(target(key('ArrowRight', { target: { ...body, tagName: 'DIV', isContentEditable: true } }), doc()), null);
  });

  it('leaves a horizontally scrolling region alone', () => {
    const table = { tagName: 'DIV', isContentEditable: false, scrollWidth: 1400, clientWidth: 900 };
    assert.equal(target(key('ArrowRight', { target: table }), doc()), null);
  });

  it('leaves modifier chords to the browser', () => {
    for (const mod of ['altKey', 'ctrlKey', 'metaKey', 'shiftKey']) {
      assert.equal(target(key('ArrowLeft', { [mod]: true }), doc()), null, mod);
    }
  });

  it('stays out of an open dialog and a handled event', () => {
    assert.equal(target(key('ArrowRight'), doc({ dialog: true })), null);
    assert.equal(target(key('ArrowRight', { defaultPrevented: true }), doc()), null);
  });
});
