// The login form's failure message, run from the attribute the template actually ships.
//
// `hx-on::after-request` said "Invalid email or password." for every unsuccessful
// response — so once AuthRateLimitMiddleware started answering 429, the correct password
// was reported as wrong, beside a toast saying "Too many requests". A server test cannot
// see this: the 429 is right, only the words on the page are not.

import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

const html = readFileSync(new URL('../../app/templates/auth/login.html', import.meta.url), 'utf8');
const handler = html.match(/hx-on::after-request="([^"]*)"/)[1];

/** The message the box shows after a response with this status (0 = no response at all). */
function messageFor(status) {
  const box = { textContent: '', classList: { remove() {} } };
  const document = { getElementById: () => box };
  const window = { location: { href: '' } };
  new Function('event', 'document', 'window', handler)({ detail: { successful: false, xhr: { status } } }, document, window);
  return box.textContent;
}

describe('a failed login names what actually failed', () => {
  it('blames the credentials on a bad-credentials answer', () => {
    assert.equal(messageFor(400), 'Invalid email or password.');
  });

  it('names the rate limit, never the password, on a 429', () => {
    assert.match(messageFor(429), /too many/i);
    assert.doesNotMatch(messageFor(429), /invalid/i);
  });

  for (const status of [0, 403, 500, 502]) {
    it(`does not call the password wrong on ${status || 'a network failure'}`, () => {
      assert.ok(messageFor(status));
      assert.doesNotMatch(messageFor(status), /invalid/i);
    });
  }
});
