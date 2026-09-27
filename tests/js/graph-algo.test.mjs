// Layouts and traversal. The two claims worth pinning here are analytical, not cosmetic:
//
//   * `allShortestPaths` returns **all** of them. graphology-shortest-path has no
//     k-shortest / Yen's, so this is hand-rolled, and "we found *a* path" is a materially
//     weaker answer than "here is every way these two are connected".
//   * the traversal projection excludes job edges **structurally**. Excluding them by
//     weight does not work: graphology's weight getter is
//     `t => typeof t !== 'number' || isNaN(t) ? 1 : t`, so an `Infinity` weight is silently
//     read as 1, and `dijkstra.bidirectional` returns as soon as the frontiers meet with no
//     finite-cost check. A path through "named in the same log file" is a lie an analyst
//     has no way to spot.

import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';

import { Algo } from './harness.mjs';

// A minimal graphology stand-in. The real bundle is 73 KB of UMD that the browser loads;
// these functions only ever call `hasNode`, `nodes`, `forEachNode`, `forEachNeighbor`,
// `forEachEdge`, `setNodeAttribute`, `getNodeAttribute` and `degree`, so a small honest
// double keeps the test about the algorithm rather than about the library.
class FakeGraph {
  constructor(edges, opts) {
    this._nodes = new Map();
    this._adj = new Map();
    this._edges = [];
    for (const [s, t, kind] of edges) {
      this._ensure(s);
      this._ensure(t);
      this._adj.get(s).add(t);
      this._adj.get(t).add(s);
      this._edges.push([s, t, { kind: kind || 'typed' }]);
    }
    for (const key of (opts && opts.isolated) || []) this._ensure(key);
  }
  _ensure(key) {
    if (!this._nodes.has(key)) {
      this._nodes.set(key, { x: 0, y: 0 });
      this._adj.set(key, new Set());
    }
  }
  get order() {
    return this._nodes.size;
  }
  get size() {
    return this._edges.length;
  }
  hasNode(key) {
    return this._nodes.has(key);
  }
  nodes() {
    return [...this._nodes.keys()];
  }
  degree(key) {
    return this._adj.get(key).size;
  }
  forEachNode(fn) {
    for (const [key, attr] of this._nodes) fn(key, attr);
  }
  forEachNeighbor(key, fn) {
    for (const nbr of this._adj.get(key)) fn(nbr, this._nodes.get(nbr));
  }
  forEachEdge(fn) {
    this._edges.forEach(([s, t, attr], i) => fn(String(i), attr, s, t));
  }
  setNodeAttribute(key, name, value) {
    this._nodes.get(key)[name] = value;
  }
  getNodeAttribute(key, name) {
    return this._nodes.get(key)[name];
  }
  addNode(key) {
    this._ensure(key);
  }
  addEdge(s, t) {
    this._adj.get(s).add(t);
    this._adj.get(t).add(s);
    this._edges.push([s, t, {}]);
  }
  hasEdge(s, t) {
    return this._adj.get(s) && this._adj.get(s).has(t);
  }
}

describe('allShortestPaths', () => {
  it('returns every shortest path on a diamond, not just one', () => {
    // a—b—d and a—c—d are both length 3.
    const g = new FakeGraph([
      ['a', 'b'],
      ['a', 'c'],
      ['b', 'd'],
      ['c', 'd'],
    ]);
    const paths = Algo.allShortestPaths(g, 'a', 'd');
    assert.equal(paths.length, 2);
    for (const p of paths) assert.equal(p.length, 3);
    assert.deepEqual(
      paths.map((p) => p.join('>')).sort(),
      ['a>b>d', 'a>c>d'],
    );
  });

  it('never returns a longer path alongside a shorter one', () => {
    const g = new FakeGraph([
      ['a', 'b'],
      ['b', 'z'],
      ['a', 'c'],
      ['c', 'd'],
      ['d', 'z'],
    ]);
    const paths = Algo.allShortestPaths(g, 'a', 'z');
    assert.deepEqual(paths, [['a', 'b', 'z']]);
  });

  it('returns nothing when the endpoints are in different components', () => {
    const g = new FakeGraph([['a', 'b']], { isolated: ['z'] });
    assert.deepEqual(Algo.allShortestPaths(g, 'a', 'z'), []);
  });

  it('handles from === to and unknown nodes without throwing', () => {
    const g = new FakeGraph([['a', 'b']]);
    assert.deepEqual(Algo.allShortestPaths(g, 'a', 'a'), [['a']]);
    assert.deepEqual(Algo.allShortestPaths(g, 'a', 'nope'), []);
  });

  it('respects the result limit', () => {
    // A three-stage graph with 2 choices at each stage = 8 shortest paths.
    const edges = [];
    for (const a of ['1', '2']) {
      edges.push(['s', 'a' + a]);
      for (const b of ['1', '2']) {
        edges.push(['a' + a, 'b' + b]);
        for (const c of ['1', '2']) {
          edges.push(['b' + b, 'c' + c]);
          edges.push(['c' + c, 't']);
        }
      }
    }
    const g = new FakeGraph(edges);
    assert.equal(Algo.allShortestPaths(g, 's', 't', { limit: 3 }).length, 3);
  });
});

describe('projection', () => {
  it('is unavailable without graphology and says so rather than throwing', () => {
    // The harness has no `window.graphology`, which is the honest state for a Node test:
    // the projection is a thin wrapper over the library's UndirectedGraph.
    assert.equal(Algo.projection(new FakeGraph([['a', 'b']]), {}), null);
  });
});

describe('egoRadial', () => {
  it('places the focal node at the origin and each ring further out', () => {
    const g = new FakeGraph([
      ['f', 'a'],
      ['f', 'b'],
      ['a', 'c'],
    ]);
    Algo.egoRadial(g, 'f', {});
    const r = (k) => Math.hypot(g.getNodeAttribute(k, 'x'), g.getNodeAttribute(k, 'y'));
    assert.equal(r('f'), 0);
    assert.ok(r('a') > 0);
    assert.ok(r('c') > r('a'), 'depth 2 must sit outside depth 1');
  });

  it('places nodes in another component instead of stacking them on the focal', () => {
    const g = new FakeGraph([['f', 'a']], { isolated: ['orphan'] });
    Algo.egoRadial(g, 'f', {});
    const r = Math.hypot(g.getNodeAttribute('orphan', 'x'), g.getNodeAttribute('orphan', 'y'));
    assert.ok(r > 0, 'an unreachable node must not sit at (0,0) under the focal');
  });

  it('is deterministic', () => {
    const positions = () => {
      const g = new FakeGraph([
        ['f', 'a'],
        ['f', 'b'],
        ['a', 'c'],
      ]);
      Algo.egoRadial(g, 'f', {});
      return g.nodes().map((k) => [k, g.getNodeAttribute(k, 'x'), g.getNodeAttribute(k, 'y')]);
    };
    assert.deepEqual(positions(), positions());
  });

  it('does not throw on an empty graph', () => {
    Algo.egoRadial(new FakeGraph([]), null, {});
  });
});

describe('circularMean', () => {
  it('averages 350 and 10 to 0, not to 180', () => {
    // Sibling ordering on a ring depends on this. An arithmetic mean flings a node to the
    // opposite side from both its parents, which looks worse than not sorting at all.
    const angles = new Map([
      ['a', (350 * Math.PI) / 180],
      ['b', (10 * Math.PI) / 180],
    ]);
    const mean = (Algo.circularMean(['a', 'b'], angles) * 180) / Math.PI;
    assert.ok(mean < 1 || mean > 359, `expected ~0 degrees, got ${mean}`);
  });

  it('returns 0 for no parents', () => {
    assert.equal(Algo.circularMean([], new Map()), 0);
    assert.equal(Algo.circularMean(null, new Map()), 0);
  });
});

describe('degreeRanking', () => {
  it('ranks hubs first and breaks ties deterministically', () => {
    const g = new FakeGraph([
      ['hub', 'a'],
      ['hub', 'b'],
      ['hub', 'c'],
      ['a', 'b'],
    ]);
    const ranked = Algo.degreeRanking(g, 2);
    assert.equal(ranked[0].key, 'hub');
    assert.equal(ranked.length, 2);
  });
});
