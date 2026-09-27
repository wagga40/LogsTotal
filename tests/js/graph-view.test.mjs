// The emphasis precedence table — the riskiest logic in the graph rewrite, and the one
// place no Python grep can reach. Both traps it guards produce a *working-looking* server
// response and a broken frame.

import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';

import { View, payload, schema, state } from './harness.mjs';

const { HIDDEN, MUTED, NORMAL, MATCH, FOCUS } = View;

function graph(spec) {
  return View.decodePayload(payload(spec), schema);
}

const SAMPLE = {
  nodes: [
    { label: 'cmd.exe', type: 'executable', flags: ['focal', 'lolbin'], jobCount: 9, severity: 'critical' },
    { label: 'ADMIN$', type: 'user', flags: ['privileged'], jobCount: 4, severity: 'low', tags: ['apt28'] },
    { label: 'AB'.repeat(32), type: 'hash', flags: [], jobCount: 1 },
    { label: '10.0.0.7', type: 'ip_address', subtype: 'rfc1918', flags: ['private', 'watchlist'], jobCount: 2 },
  ],
  edges: [
    [0, 1, 'job', 3],
    [0, 2, 'hashes_to', 7],
    [1, 3, 'logs_on_from', 2],
    [2, 3, 'finding', 1],
  ],
  focal: 1,
};

describe('decodePayload', () => {
  it('resolves every index against the schema', () => {
    const g = graph(SAMPLE);
    assert.equal(g.nodes[0].type, 'executable');
    assert.equal(g.nodes[3].subtype, 'rfc1918');
    assert.equal(g.nodes[0].severity, 'critical');
    assert.deepEqual(g.nodes[1].tags, ['apt28']);
  });

  it('splits typed edges from the two undirected kinds', () => {
    const g = graph(SAMPLE);
    assert.deepEqual(
      g.edges.map((e) => [e.kind, e.rel]),
      [
        ['job', null],
        ['typed', 'hashes_to'],
        ['typed', 'logs_on_from'],
        ['finding', null],
      ],
    );
  });

  it('gives every edge a key unique by construction', () => {
    const g = graph({
      nodes: [
        { label: 'a', type: 'executable' },
        { label: 'b', type: 'executable' },
      ],
      // Two parallel typed edges between one pair, plus a co-occurrence edge.
      edges: [
        [0, 1, 'parent_of', 2],
        [0, 1, 'loads', 1],
        [0, 1, 'job', 5],
      ],
    });
    const keys = g.edges.map(View.edgeKey);
    assert.equal(new Set(keys).size, 3);
  });

  it('reports whether a sparse column was computed at all', () => {
    assert.equal(graph(SAMPLE).hasTags, true);
    assert.equal(graph({ nodes: [{ label: 'a', type: 'user' }] }).hasTags, false);
  });
});

describe('emphasis: structural exclusion', () => {
  it('always hides, whatever else is on', () => {
    const g = graph(SAMPLE);
    const st = state({ hiddenTypes: new Set(['hash']) });
    const d = View.computeDecisions(g, st);
    assert.equal(d.nodeLevels.get(2), HIDDEN);
  });

  it('is not softened by dimMode', () => {
    const g = graph(SAMPLE);
    for (const dimMode of ['dim', 'hide']) {
      const d = View.computeDecisions(g, state({ hiddenTypes: new Set(['hash']), dimMode }));
      assert.equal(d.nodeLevels.get(2), HIDDEN, `dimMode=${dimMode}`);
    }
  });
});

describe('emphasis: lenses intersect', () => {
  it('a matching node is MATCH and a non-matching one is MUTED', () => {
    const g = graph(SAMPLE);
    const st = state({ query: View.parseQuery('label:lolbin', schema) });
    const d = View.computeDecisions(g, st);
    assert.equal(d.nodeLevels.get(0), MATCH);
    assert.equal(d.nodeLevels.get(1), MUTED);
  });

  it('every node is NORMAL when no lens is active', () => {
    const d = View.computeDecisions(graph(SAMPLE), state({}));
    assert.deepEqual([...d.nodeLevels.values()], [NORMAL, NORMAL, NORMAL, NORMAL]);
  });

  it('two lenses narrow rather than widen', () => {
    const g = graph(SAMPLE);
    const both = View.computeDecisions(g, state({ query: View.parseQuery('type:user', schema), severityFloor: 'critical' }));
    // The user node matches the query but not the severity floor, so nothing matches.
    assert.equal([...both.nodeLevels.values()].filter((l) => l === MATCH).length, 0);
  });

  it("dimMode:'hide' turns a non-match into HIDDEN, not MUTED", () => {
    const d = View.computeDecisions(graph(SAMPLE), state({ query: View.parseQuery('label:lolbin', schema), dimMode: 'hide' }));
    assert.equal(d.nodeLevels.get(1), HIDDEN);
  });
});

describe('emphasis: overlays union and only promote', () => {
  it('promotes a member and demotes everything else to MUTED', () => {
    const g = graph(SAMPLE);
    const d = View.computeDecisions(g, state({ overlay: new Set([0, 1]) }));
    assert.equal(d.nodeLevels.get(0), FOCUS);
    assert.equal(d.nodeLevels.get(1), FOCUS);
    assert.equal(d.nodeLevels.get(2), MUTED);
  });

  it('NEVER resurrects a structurally hidden node', () => {
    // Hovering must not repopulate a canvas the analyst deliberately emptied.
    const g = graph(SAMPLE);
    const d = View.computeDecisions(g, state({ hiddenTypes: new Set(['hash']), overlay: new Set([2]) }));
    assert.equal(d.nodeLevels.get(2), HIDDEN);
  });

  it("never resurrects a node hidden by dimMode:'hide' either", () => {
    const g = graph(SAMPLE);
    const st = state({ query: View.parseQuery('label:lolbin', schema), dimMode: 'hide', overlay: new Set([1]) });
    assert.equal(View.computeDecisions(g, st).nodeLevels.get(1), HIDDEN);
  });
});

describe('emphasis: edges', () => {
  it('is never brighter than its dimmest endpoint', () => {
    const g = graph(SAMPLE);
    const st = state({ query: View.parseQuery('label:lolbin', schema) });
    const d = View.computeDecisions(g, st);
    for (const edge of g.edges) {
      const level = d.edgeLevels.get(View.edgeKey(edge));
      const endpoints = Math.min(d.nodeLevels.get(edge.source), d.nodeLevels.get(edge.target));
      assert.ok(level <= endpoints, `${View.edgeKey(edge)}: ${level} > ${endpoints}`);
    }
  });

  it('disappears entirely when either endpoint is hidden', () => {
    const g = graph(SAMPLE);
    const d = View.computeDecisions(g, state({ hiddenTypes: new Set(['hash']) }));
    assert.equal(d.edgeLevels.get('t:hashes_to:0:2'), HIDDEN);
    assert.equal(d.edgeLevels.get('f:2:3'), HIDDEN);
  });

  it('honours an edge-kind filter independently of its endpoints', () => {
    const g = graph(SAMPLE);
    const d = View.computeDecisions(g, state({ hiddenKinds: new Set(['job']) }));
    assert.equal(d.edgeLevels.get('j:0:1'), HIDDEN);
    assert.equal(d.nodeLevels.get(0), NORMAL, 'hiding a kind must not hide its endpoints');
  });

  it('honours a relationship-type filter', () => {
    const g = graph(SAMPLE);
    const d = View.computeDecisions(g, state({ hiddenRels: new Set(['hashes_to']) }));
    assert.equal(d.edgeLevels.get('t:hashes_to:0:2'), HIDDEN);
    assert.notEqual(d.edgeLevels.get('t:logs_on_from:1:3'), HIDDEN);
  });
});

describe('emphasis: labels are decoupled from level', () => {
  it('a MATCH does not force its label', () => {
    // Forcing bypasses labelRenderedSizeThreshold / labelDensity / labelGridCellSize —
    // the three settings that bound label cost — so a filter matching thousands of nodes
    // would force-draw thousands of labels per frame.
    const d = View.computeDecisions(graph(SAMPLE), state({ query: View.parseQuery('type:executable', schema) }));
    assert.equal(d.forced.size, 0);
  });

  it('forces only overlay and selection, and caps the total', () => {
    const nodes = [];
    for (let i = 0; i < View.MAX_FORCED_LABELS + 50; i++) nodes.push({ label: 'n' + i, type: 'user' });
    const g = graph({ nodes });
    const overlay = new Set(nodes.map((_x, i) => i));
    const d = View.computeDecisions(g, state({ overlay }));
    assert.equal(d.forced.size, View.MAX_FORCED_LABELS);
  });

  it('a MUTED node can still be force-labelled', () => {
    // MUTED is 0, so a `(nodeLevels.get(i) || HIDDEN) > HIDDEN` guard resolves to
    // `-1 > -1` — false — for every muted node. That is precisely the selected node
    // whenever a lens is on and the selection fails it, so the label would disappear from
    // the one node being read. Dimming means "not what you asked for", not "gone".
    const d = View.computeDecisions(graph(SAMPLE), state({ query: View.parseQuery('type:user', schema), selection: 2 }));
    assert.equal(d.nodeLevels.get(2), MUTED, 'the executable fails the lens');
    assert.ok(d.forced.has(2), 'and still keeps its name');
  });

  it('the cap can never starve the selection', () => {
    // `candidates` is [selection, ...overlay] and the loop breaks at the cap, so hovering
    // a hub with more neighbours than the budget would otherwise spend all of it on the ego
    // and leave the deliberately-clicked node anonymous.
    const nodes = [];
    for (let i = 0; i < View.MAX_FORCED_LABELS + 50; i++) nodes.push({ label: 'n' + i, type: 'user' });
    const g = graph({ nodes });
    const overlay = new Set(nodes.map((_x, i) => i + 1).slice(0, View.MAX_FORCED_LABELS + 40));
    const d = View.computeDecisions(g, state({ overlay, selection: 0 }));
    assert.equal(d.forced.size, View.MAX_FORCED_LABELS);
    assert.ok(d.forced.has(0), 'the selected node is first in the queue, not last');
  });
});

describe('counts', () => {
  it('separates what is hidden from what is dimmed', () => {
    const g = graph(SAMPLE);
    const d = View.computeDecisions(g, state({ hiddenTypes: new Set(['hash']), query: View.parseQuery('type:user', schema) }));
    assert.equal(d.counts.totalNodes, 4);
    assert.equal(d.counts.visibleNodes, 3, 'the hash is structurally gone');
    assert.equal(d.counts.dimmedNodes, 2, 'the executable and the IP fail the lens');
  });

  it('flags a lens that matches nothing', () => {
    // An all-grey canvas reads as a crash, so the component shows a chip and leaves
    // emphasis alone instead.
    const d = View.computeDecisions(graph(SAMPLE), state({ query: View.parseQuery('label:gtfobin', schema) }));
    assert.equal(d.counts.zeroMatches, true);
  });

  it('does not flag zero matches when something matched', () => {
    const d = View.computeDecisions(graph(SAMPLE), state({ query: View.parseQuery('label:lolbin', schema) }));
    assert.equal(d.counts.zeroMatches, false);
  });
});

describe('selection is an orthogonal channel', () => {
  it('does not dim anything', () => {
    const d = View.computeDecisions(graph(SAMPLE), state({ selection: 1 }));
    assert.deepEqual([...d.nodeLevels.values()], [NORMAL, NORMAL, NORMAL, NORMAL]);
    assert.equal(d.selection, 1);
    assert.ok(d.forced.has(1), 'the selected node keeps its label');
  });
});

describe('counts do not react to a hover', () => {
  it('an overlay does not add to the dimmed count', () => {
    // The status line above the canvas is sized from these counts. Counting overlay
    // demotion as "dimmed by your filters" made that line appear on mouse-over and vanish
    // on mouse-out, so the graph jumped under the cursor on every hover — and the claim was
    // untrue as well: hovering is not a filter.
    const g = graph(SAMPLE);
    const atRest = View.computeDecisions(g, state({}));
    const hovering = View.computeDecisions(g, state({ overlay: new Set([0, 1]) }));
    assert.equal(atRest.counts.dimmedNodes, 0);
    assert.equal(hovering.counts.dimmedNodes, 0);
  });

  it('a lens still counts, and counts the same whether or not something is hovered', () => {
    const g = graph(SAMPLE);
    const st = { query: View.parseQuery('type:executable', schema) };
    const plain = View.computeDecisions(g, state(st));
    const hovered = View.computeDecisions(g, state({ ...st, overlay: new Set([2]) }));
    assert.equal(plain.counts.dimmedNodes, 3);
    assert.equal(hovered.counts.dimmedNodes, 3);
  });

  it("counts lens failures under dimMode:'hide' too", () => {
    // They are hidden rather than dimmed, but they are still "removed by your filters" and
    // the readout must not silently drop to zero just because the mode changed.
    const g = graph(SAMPLE);
    const d = View.computeDecisions(g, state({ query: View.parseQuery('type:executable', schema), dimMode: 'hide' }));
    assert.equal(d.counts.dimmedNodes, 3);
    assert.equal(d.counts.visibleNodes, 1);
  });

  it('zero matches is derived from lens hits, not from dimmed === visible', () => {
    // Under dimMode:'hide' a lens failure leaves `visibleNodes` *and* enters `dimmedNodes`,
    // so the two can never be equal and a derivation comparing them silently never fires.
    const g = graph(SAMPLE);
    for (const dimMode of ['dim', 'hide']) {
      const d = View.computeDecisions(g, state({ query: View.parseQuery('label:gtfobin', schema), dimMode }));
      assert.equal(d.counts.zeroMatches, true, `dimMode=${dimMode}`);
    }
  });
});
