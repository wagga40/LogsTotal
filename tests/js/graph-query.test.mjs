// The client half of the shared search grammar.
//
// `app/intel/queries.py` is the source of truth for what a query *means*; this is a port of
// its term semantics, evaluated against decoded node attributes so filtering a graph you
// are already looking at costs no round trip. The two must agree, or clicking a chip on
// /intel and typing the same token into the graph would answer different questions.
//
// `re:` and `job:` are the two kinds that deliberately do NOT evaluate here — see the
// `needsServer` tests at the bottom.

import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';

import { View, payload, schema } from './harness.mjs';

function nodes(spec) {
  return View.decodePayload(payload({ nodes: spec }), schema).nodes;
}

function matching(query, spec) {
  const parsed = View.parseQuery(query, schema);
  return nodes(spec)
    .filter((n) => View.queryMatches(parsed, n, schema))
    .map((n) => n.label);
}

const CORPUS = [
  { label: 'certutil.exe', type: 'executable', flags: ['lolbin'], tags: ['living-off-the-land'] },
  { label: 'svc-backup', type: 'user', flags: ['privileged'], tags: ['apt28'] },
  { label: 'WIN-DC01$', type: 'user', flags: ['machine'] },
  { label: '10.0.0.7', type: 'ip_address', subtype: 'rfc1918', flags: ['private'] },
  { label: '8.8.8.8', type: 'ip_address', subtype: 'public', flags: [] },
  { label: 'evil-c2.tk', type: 'domain', flags: ['suspicious_tld', 'dga'], tags: ['apt28', 'c2'] },
];

describe('literal and wildcard', () => {
  it('matches a case-insensitive substring', () => {
    assert.deepEqual(matching('SVC', CORPUS), ['svc-backup']);
  });

  it('treats an unstructured multi-word query as one phrase', () => {
    // Back-compat that is load-bearing on the server too: a saved search written before
    // whitespace meant AND must keep matching what it always matched.
    assert.deepEqual(matching('svc backup', CORPUS), []);
    assert.deepEqual(matching('svc-backup', CORPUS), ['svc-backup']);
  });

  it('expands * to a wildcard without letting other regex metacharacters through', () => {
    assert.deepEqual(matching('10.0.*', CORPUS), ['10.0.0.7']);
    // The dots are literal, so this must not match 10.0.0.7 via `.` = any char.
    assert.deepEqual(matching('1x.0.*', CORPUS), []);
  });
});

describe('label: / attr:', () => {
  it('resolves a boolean attribute through the flag bitfield', () => {
    assert.deepEqual(matching('label:lolbin', CORPUS), ['certutil.exe']);
    assert.deepEqual(matching('attr:machine', CORPUS), ['WIN-DC01$']);
  });

  it('resolves a categorical attribute through the subtype slot', () => {
    assert.deepEqual(matching('label:rfc1918', CORPUS), ['10.0.0.7']);
    assert.deepEqual(matching('attr:public', CORPUS), ['8.8.8.8']);
  });

  it('applies the same aliases the server does', () => {
    assert.deepEqual(matching('attr:suspicious', CORPUS), ['evil-c2.tk']);
    assert.deepEqual(matching('attr:priv', CORPUS), ['svc-backup']);
  });

  it('falls back to a tag when the key is not a system label', () => {
    assert.deepEqual(matching('label:apt28', CORPUS), ['svc-backup', 'evil-c2.tk']);
  });

  it('every attr key in the schema is reachable', () => {
    // The Python side pins flags ∪ subtypes ≡ ATTR_FILTERS; this pins that the client can
    // actually evaluate each one rather than silently treating it as a tag.
    for (const key of [...schema.attr_flags, ...schema.subtypes]) {
      const parsed = View.parseQuery('label:' + key, schema);
      assert.equal(parsed.terms[0].kind, 'attr', `label:${key} was not recognised as an attribute`);
    }
  });
});

describe('tag: and type:', () => {
  it('tag: is any-of', () => {
    assert.deepEqual(matching('tag:apt28,c2', CORPUS), ['svc-backup', 'evil-c2.tk']);
  });

  it('type: accepts the aliases', () => {
    assert.deepEqual(matching('type:ip', CORPUS), ['10.0.0.7', '8.8.8.8']);
    assert.deepEqual(matching('type:exe', CORPUS), ['certutil.exe']);
  });

  it('reports an unknown type instead of matching nothing silently', () => {
    const parsed = View.parseQuery('type:widget', schema);
    assert.ok(parsed.errors.length);
  });
});

describe('cidr:', () => {
  it('matches IPv4 inside the network and nothing else', () => {
    assert.deepEqual(matching('cidr:10.0.0.0/24', CORPUS), ['10.0.0.7']);
    assert.deepEqual(matching('cidr:8.8.8.0/24', CORPUS), ['8.8.8.8']);
  });

  it('never matches a non-IP entity', () => {
    assert.deepEqual(matching('cidr:0.0.0.0/0', CORPUS), ['10.0.0.7', '8.8.8.8']);
  });

  it('handles IPv6 including :: expansion', () => {
    const v6 = [
      { label: '2001:db8::1', type: 'ip_address' },
      { label: '2001:db9::1', type: 'ip_address' },
      { label: 'fe80::1', type: 'ip_address' },
    ];
    assert.deepEqual(matching('cidr:2001:db8::/32', v6), ['2001:db8::1']);
    assert.deepEqual(matching('cidr:fe80::/10', v6), ['fe80::1']);
  });

  it('rejects malformed input rather than throwing', () => {
    assert.equal(View.parseCidr('nonsense'), null);
    assert.equal(View.parseCidr('999.1.1.1/24'), null);
    assert.equal(View.parseCidr('10.0.0.0/99'), null);
  });
});

describe('negation and conjunction', () => {
  it('a leading - negates one term', () => {
    assert.deepEqual(matching('type:user -attr:machine', CORPUS), ['svc-backup']);
  });

  it('a bare leading - in an unstructured query is NOT a negation', () => {
    // `powershell -enc payload` is a real search where `-enc` is part of the phrase.
    // Treating it as structured would silently change every such saved search.
    assert.deepEqual(matching('svc -backup', CORPUS), []);
  });

  it('juxtaposition is AND', () => {
    assert.deepEqual(matching('type:domain label:dga', CORPUS), ['evil-c2.tk']);
    assert.deepEqual(matching('type:domain label:lolbin', CORPUS), []);
  });
});

describe('boolean grammar', () => {
  it('OR widens', () => {
    assert.deepEqual(matching('label:lolbin OR label:machine', CORPUS), ['certutil.exe', 'WIN-DC01$']);
  });

  it('parentheses group when the query is already structured', () => {
    assert.deepEqual(matching('type:user (label:machine OR label:privileged)', CORPUS), ['svc-backup', 'WIN-DC01$']);
  });

  it('parentheses in an unstructured query stay literal', () => {
    const parsed = View.parseQuery('powershell (encoded)', schema);
    assert.equal(parsed.terms.length, 1);
    assert.equal(parsed.terms[0].kind, 'literal');
  });

  it('lowercase or is left alone', () => {
    const parsed = View.parseQuery('powershell or cmd', schema);
    assert.equal(parsed.terms.length, 1, 'lowercase "or" is a word, not an operator');
  });
});

describe('server-evaluated terms', () => {
  it('re: and job: flag the query as needing a round trip', () => {
    assert.equal(View.parseQuery('re:/^svc-/', schema).needsServer, true);
    assert.equal(View.parseQuery('job:12', schema).needsServer, true);
    assert.equal(View.parseQuery('label:lolbin tag:apt28 cidr:10.0.0.0/8', schema).needsServer, false);
  });

  it('re: reads the answer the server put on the node', () => {
    // A JS RegExp has no timeout, so a deliberately catastrophic pattern has to stay on the
    // server side of the wall-clock budget. `n.mt` is that verdict.
    const decoded = View.decodePayload(payload({ nodes: CORPUS, matches: [1] }), schema);
    const parsed = View.parseQuery('re:/^svc-/', schema);
    const hits = decoded.nodes.filter((n) => View.queryMatches(parsed, n, schema)).map((n) => n.label);
    assert.deepEqual(hits, ['svc-backup']);
  });

  it('a negated server term is negated once — by the server that already applied it', () => {
    // `match_entity_rows` folds each term's own negation into `n.mt`, so for `-re:/^svc-/`
    // the server marks every node that does NOT start with svc-. The client negated that
    // verdict a second time and highlighted exactly the complement of the right set; with a
    // positive and a negative server term together it matched nothing at all.
    const notSvc = CORPUS.map((_n, i) => i).filter((i) => !CORPUS[i].label.startsWith('svc-'));
    const decoded = View.decodePayload(payload({ nodes: CORPUS, matches: notSvc }), schema);
    for (const raw of ['-re:/^svc-/', 're:/e/ -re:/^svc-/', '-list:lolbas']) {
      const parsed = View.parseQuery(raw, schema);
      const hits = decoded.nodes.filter((n) => View.queryMatches(parsed, n, schema)).map((n) => n.label);
      assert.deepEqual(hits, notSvc.map((i) => CORPUS[i].label), raw);
    }
  });

  it('a regex spanning spaces is one token, not two', () => {
    const parsed = View.parseQuery('re:/^svc a/ type:user', schema);
    assert.equal(parsed.terms.length, 2);
    assert.equal(parsed.terms[0].kind, 'regex');
  });
});

describe('bounds', () => {
  it('caps the number of terms and says so', () => {
    const long = Array.from({ length: 20 }, (_x, i) => 'tag:t' + i).join(' ');
    const parsed = View.parseQuery(long, schema);
    assert.equal(parsed.terms.length, 12);
    assert.ok(parsed.errors.some((e) => e.includes('only the first')));
  });

  it('an empty query matches everything', () => {
    assert.equal(matching('', CORPUS).length, CORPUS.length);
    assert.equal(matching('   ', CORPUS).length, CORPUS.length);
  });
});

describe('cidr: comma lists', () => {
  it('matches an IP inside any of the networks, and negated means inside none', () => {
    assert.deepEqual(matching('cidr:10.0.0.0/8,8.8.8.0/24', CORPUS), ['10.0.0.7', '8.8.8.8']);
    assert.deepEqual(matching('-cidr:10.0.0.0/8,8.8.8.0/24', CORPUS).filter((l) => /^\d/.test(l)), []);
  });

  it('one bad network fails the whole term', () => {
    assert.ok(View.parseQuery('cidr:10.0.0.0/8,nonsense', schema).errors.length);
  });
});

describe('list:', () => {
  it('is answered by the server, like job:', () => {
    const parsed = View.parseQuery('list:lolbas', schema);
    assert.equal(parsed.terms[0].kind, 'server');
    assert.equal(parsed.needsServer, true);
  });
});

describe('in:(a,b) — a set too small to name', () => {
  // Unlike `list:` and `job:`, this one IS answered here: the values travel in the term, so
  // a round trip would buy nothing. Kept in step with `queries._parse_inset_term` by
  // `tests/test_inset_term.py`, which asserts the same cases against real SQL.
  const SET = [
    { label: 'psexec.exe', type: 'executable' },
    { label: 'wmic.exe', type: 'executable' },
    { label: 'notpsexec.exe', type: 'executable' },
    { label: 'svchost.exe', type: 'executable' },
  ];

  it('matches the whole value, never a substring', () => {
    assert.deepEqual(matching('in:(psexec.exe)', SET), ['psexec.exe']);
  });

  it('is a union over its values', () => {
    assert.deepEqual(matching('in:(psexec.exe,svchost.exe)', SET).sort(), ['psexec.exe', 'svchost.exe']);
  });

  it('lowercases, trims and dedupes like the write path', () => {
    const parsed = View.parseQuery('in:( PsExec.exe , wmic.exe ,psexec.EXE )', schema);
    assert.deepEqual(parsed.terms[0].values, ['psexec.exe', 'wmic.exe']);
  });

  it('can be negated', () => {
    assert.deepEqual(matching('-in:(psexec.exe,wmic.exe)', SET).sort(), ['notpsexec.exe', 'svchost.exe']);
  });

  it('needs no round trip, unlike list: and job:', () => {
    assert.equal(View.parseQuery('in:(a,b)', schema).needsServer, false);
    assert.equal(View.parseQuery('list:lolbas', schema).needsServer, true);
  });

  it('keeps its parens out of the boolean parser', () => {
    // What this pass exists to stop: the generic walk ends a term at '(' when groups are
    // being split, which shreds the set AND feeds its paren to the grouping rules.
    const parsed = View.parseQuery('(in:(psexec.exe) OR tag:apt28)', schema);
    assert.deepEqual(parsed.terms.map((t) => t.kind), ['inset', 'tag']);
    assert.deepEqual(parsed.errors, []);
  });

  it('sits under an OR, which re: and cidr: may not', () => {
    assert.deepEqual(matching('(in:(psexec.exe) OR in:(svchost.exe))', SET).sort(), ['psexec.exe', 'svchost.exe']);
  });

  it('explains itself rather than matching everything', () => {
    for (const [raw, fragment] of [
      ['in:foo', 'parenthesised'],
      ['in:()', 'at least one'],
    ]) {
      const t = View.parseQuery(raw, schema).terms[0];
      assert.equal(t.kind, 'literal', `${raw} should degrade to a literal`);
      assert.ok(t.error.includes(fragment), `${raw}: ${t.error}`);
    }
  });
});
