// `mergePayload` — the part progressive expansion gets subtly wrong.
//
// A columnar payload cannot be concatenated: `e.s`/`e.t` are per-payload node *indices* and
// `dict.tags` is a per-payload dictionary. Merging therefore means remapping both index
// spaces against the live graph, and recomputing every edge key from the *merged* indices —
// carrying an incoming key over produces an edge that looks duplicated and then vanishes on
// the next filter.
//
// Node-index edges are still the right call (a dangling edge becomes structurally
// impossible), but the remap has to be explicit, which is why it lives in a pure function
// with tests rather than inline in the fetch handler.

import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';

import { View, payload, schema } from './harness.mjs';

const BASE = {
  nodes: [
    { label: 'cmd.exe', type: 'executable', flags: ['focal'] },
    { label: 'alice', type: 'user' },
  ],
  edges: [[0, 1, 'runs_as', 4]],
  focal: 1,
};

function decoded(spec) {
  return View.decodePayload(payload(spec), schema);
}

describe('mergePayload', () => {
  it('remaps incoming indices onto the live graph', () => {
    const g = decoded(BASE);
    // A payload centred on `alice` (its own index 0) that also brings a new host.
    const incoming = payload({
      nodes: [
        { label: 'alice', type: 'user', flags: ['focal'] },
        { label: 'WIN01', type: 'computer' },
      ],
      edges: [[0, 1, 'logs_on_to', 2]],
    });
    // Entity ids are positional in the fixture builder, so make them line up: `alice` is
    // entity 2 in both payloads.
    incoming.n.id = [2, 3];

    const result = View.mergePayload(g, incoming, schema, 'expand:2');
    assert.equal(g.nodes.length, 3, 'alice must not be added twice');
    assert.deepEqual(result.addedNodes, [2]);
    assert.equal(g.nodes[2].label, 'WIN01');

    const added = result.addedEdges[0];
    assert.deepEqual([added.source, added.target], [1, 2], 'edge endpoints must be MERGED indices');
    assert.equal(g.edges.length, 2);
  });

  it('never produces a dangling edge', () => {
    const g = decoded(BASE);
    const incoming = payload({
      nodes: [{ label: 'alice', type: 'user' }],
      edges: [],
    });
    incoming.n.id = [2];
    View.mergePayload(g, incoming, schema, 'expand:2');
    for (const edge of g.edges) {
      assert.ok(edge.source >= 0 && edge.source < g.nodes.length);
      assert.ok(edge.target >= 0 && edge.target < g.nodes.length);
    }
  });

  it('recomputes edge keys from merged indices and drops true duplicates', () => {
    const g = decoded(BASE);
    // The same runs_as edge arrives again, but with different local indices.
    const incoming = payload({
      nodes: [
        { label: 'alice', type: 'user' },
        { label: 'cmd.exe', type: 'executable' },
      ],
      edges: [[1, 0, 'runs_as', 9]],
    });
    incoming.n.id = [2, 1];

    const result = View.mergePayload(g, incoming, schema, 'expand:2');
    assert.deepEqual(result.addedNodes, []);
    assert.deepEqual(result.addedEdges, [], 'the same edge under different local indices is not a new edge');
    assert.equal(g.edges.length, 1);
    assert.equal(new Set(g.edges.map(View.edgeKey)).size, 1);
  });

  it('keeps parallel typed edges distinct', () => {
    const g = decoded(BASE);
    const incoming = payload({
      nodes: [
        { label: 'cmd.exe', type: 'executable' },
        { label: 'alice', type: 'user' },
      ],
      // A *different* relationship between the same pair is a real new edge.
      edges: [[0, 1, 'logs_on_to', 1]],
    });
    incoming.n.id = [1, 2];

    const result = View.mergePayload(g, incoming, schema, 'expand:1');
    assert.equal(result.addedEdges.length, 1);
    assert.equal(new Set(g.edges.map(View.edgeKey)).size, 2);
  });

  it('remaps the tag dictionary rather than reusing incoming slots', () => {
    const g = decoded({ nodes: [{ label: 'a', type: 'user', tags: ['apt28'] }] });
    // Incoming dictionary has a different ordering, so slot 0 means something else.
    const incoming = payload({
      nodes: [
        { label: 'a', type: 'user', tags: ['apt28'] },
        { label: 'b', type: 'user', tags: ['ransomware', 'apt28'] },
      ],
    });
    incoming.n.id = [1, 2];

    View.mergePayload(g, incoming, schema, 'expand:1');
    assert.deepEqual(g.nodes[0].tags, ['apt28']);
    assert.deepEqual(g.nodes[1].tags, ['ransomware', 'apt28']);
  });

  it('strips the focal flag from merged nodes', () => {
    // The focal marker belongs to the graph's own centre, not to whatever entity happened
    // to be the focus of the expansion request.
    const g = decoded(BASE);
    const incoming = payload({ nodes: [{ label: 'WIN01', type: 'computer', flags: ['focal'] }] });
    incoming.n.id = [9];

    View.mergePayload(g, incoming, schema, 'expand:9');
    assert.equal(g.nodes[2].flags & schema.flags.focal, 0);
    assert.notEqual(g.nodes[0].flags & schema.flags.focal, 0, 'the original focal keeps its flag');
  });

  it('records provenance on every added node', () => {
    const g = decoded(BASE);
    const incoming = payload({ nodes: [{ label: 'WIN01', type: 'computer' }] });
    incoming.n.id = [9];
    View.mergePayload(g, incoming, schema, 'expand:2');
    assert.equal(g.nodes[2].addedBy, 'expand:2');
    assert.equal(g.nodes[0].addedBy, undefined, 'initial nodes are not relabelled');
  });

  it('survives two expansions from different nodes without duplicating anything', () => {
    const g = decoded(BASE);
    for (const [ids, spec] of [
      [
        [2, 3],
        { nodes: [{ label: 'alice', type: 'user' }, { label: 'WIN01', type: 'computer' }], edges: [[0, 1, 'logs_on_to', 1]] },
      ],
      [
        [1, 3],
        { nodes: [{ label: 'cmd.exe', type: 'executable' }, { label: 'WIN01', type: 'computer' }], edges: [[0, 1, 'runs_on', 5]] },
      ],
    ]) {
      const incoming = payload(spec);
      incoming.n.id = ids;
      View.mergePayload(g, incoming, schema, 'expand');
    }
    assert.equal(g.nodes.length, 3);
    assert.equal(new Set(g.nodes.map((n) => n.entityId)).size, 3);
    assert.equal(new Set(g.edges.map(View.edgeKey)).size, g.edges.length);
    for (const edge of g.edges) {
      assert.ok(edge.source < g.nodes.length && edge.target < g.nodes.length);
    }
  });
});
