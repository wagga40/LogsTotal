// Relationship graph — layouts and graph algorithms.
//
// Everything here reads a `graphology` graph and writes `x`/`y` node attributes (layouts)
// or returns plain data (algorithms). Nothing here touches Sigma, the DOM, or view state.
//
// Two decisions worth knowing before changing anything:
//
// 1. **Force Atlas 2 is run synchronously and chunked over requestAnimationFrame, never in
//    a worker.** Every graphology example reaches for `FA2Layout`, which builds its worker
//    from a `blob:` URL. Our CSP declares no `worker-src`/`child-src`, so `blob:` falls
//    back to `default-src 'self'` and the worker is blocked — **silently**. A contributor
//    copying the docs would ship a layout that simply never runs.
//    `test_layout_never_uses_a_blob_worker` exists for exactly that reason.
//
// 2. **No betweenness centrality.** Brandes is O(V·E) — about 7.5x10^7 edge relaxations at
//    5,000/15,000, single-threaded, on the main thread, with no worker escape hatch under
//    the CSP above. Degree (O(E)) plus PageRank (O(E) per iteration) plus Louvain
//    (near-linear) cover pivot ranking, and PageRank is the better hub ranking here anyway:
//    raw degree is dominated by how big a log file happened to be.
//
// Loaded as a classic script before alpine.min.js; exposes one namespace on `window`.

(function () {
  'use strict';

  function lib() {
    return window.graphologyLibrary || {};
  }

  // ── Layouts ─────────────────────────────────────────────────────────────

  // Concentric rings by traversal depth from the focal node. Deterministic, O(V+E), and
  // the layout the entity scope opens with.
  //
  // Siblings are ordered by the **circular mean** of their parents' angles. That detail is
  // what makes the picture readable: a naive arithmetic mean averages 350° and 10° to 180°
  // and flings a node to the opposite side of the ring from both its parents, which looks
  // worse than no sorting at all.
  function egoRadial(graph, focalKey, opts) {
    const options = opts || {};
    const ringGap = options.ringGap || 160;
    const minArc = options.minArc || 42;

    const depth = new Map();
    const parents = new Map();
    const order = [];
    const start = focalKey != null && graph.hasNode(focalKey) ? focalKey : graph.nodes()[0];
    if (start === undefined) return;

    // BFS from the focal node, then sweep up anything in another component so a
    // disconnected node is placed rather than left at (0,0).
    const queue = [start];
    depth.set(start, 0);
    order.push(start);
    for (let head = 0; head < queue.length; head++) {
      const node = queue[head];
      const d = depth.get(node);
      graph.forEachNeighbor(node, (nbr) => {
        if (depth.has(nbr)) {
          if (depth.get(nbr) === d + 1) {
            if (!parents.has(nbr)) parents.set(nbr, []);
            parents.get(nbr).push(node);
          }
          return;
        }
        depth.set(nbr, d + 1);
        parents.set(nbr, [node]);
        order.push(nbr);
        queue.push(nbr);
      });
    }
    // Anything in another component still needs a position, or it sits at (0,0) under the
    // focal node. One extra ring, computed without a spread over 5,000 values.
    let maxDepth = 0;
    depth.forEach((d) => {
      if (d > maxDepth) maxDepth = d;
    });
    graph.forEachNode((node) => {
      if (depth.has(node)) return;
      depth.set(node, maxDepth + 1);
      order.push(node);
    });

    const rings = new Map();
    for (const node of order) {
      const d = depth.get(node);
      if (!rings.has(d)) rings.set(d, []);
      rings.get(d).push(node);
    }

    const angles = new Map();
    const sortedDepths = Array.from(rings.keys()).sort((a, b) => a - b);
    for (const d of sortedDepths) {
      const ring = rings.get(d);
      if (d === 0) {
        for (const node of ring) {
          angles.set(node, 0);
          graph.setNodeAttribute(node, 'x', 0);
          graph.setNodeAttribute(node, 'y', 0);
        }
        continue;
      }
      ring.sort((a, b) => circularMean(parents.get(a), angles) - circularMean(parents.get(b), angles) || String(a).localeCompare(String(b)));
      // Radius is the larger of "one gap per ring" and "enough circumference for the
      // labels", so a crowded ring pushes outward instead of overprinting itself.
      const radius = Math.max(d * ringGap, (ring.length * minArc) / (2 * Math.PI));
      for (let i = 0; i < ring.length; i++) {
        const angle = (2 * Math.PI * i) / ring.length;
        angles.set(ring[i], angle);
        graph.setNodeAttribute(ring[i], 'x', Math.cos(angle) * radius);
        graph.setNodeAttribute(ring[i], 'y', Math.sin(angle) * radius);
      }
    }
  }

  function circularMean(nodes, angles) {
    if (!nodes || !nodes.length) return 0;
    let sx = 0;
    let sy = 0;
    for (const n of nodes) {
      const a = angles.get(n) || 0;
      sx += Math.cos(a);
      sy += Math.sin(a);
    }
    if (sx === 0 && sy === 0) return 0;
    const mean = Math.atan2(sy, sx);
    return mean < 0 ? mean + 2 * Math.PI : mean;
  }

  // Circle-pack by community — instant, and the best *first* picture of a large case:
  // structure is legible before a single force iteration has run.
  function circlepack(graph, attribute) {
    const layout = lib().layout;
    if (!layout || !layout.circlepack) return false;
    layout.circlepack.assign(graph, { hierarchyAttributes: attribute ? [attribute] : [], scale: 220 });
    return true;
  }

  // How many iterations are worth running, and how many to run per frame.
  //
  // **Measured, not guessed.** On a 997-node / 3,670-edge graph in Chromium one FA2
  // iteration costs ~140 ms *with* `barnesHutOptimize` — setup is ~15 ms of that, so per-
  // iteration work dominates and a fixed chunk of 10 blocks the main thread for 1.4 s per
  // frame. At 31 nodes an iteration is well under a millisecond and a chunk of 1 would
  // spend the whole budget on rAF round trips. So both numbers scale with the graph, and
  // the adaptive floor is 1 rather than 5.
  const FA2_FRAME_BUDGET_MS = 12;
  const FA2_WALL_CLOCK_MS = 8000;

  function fa2Iterations(order) {
    if (order <= 200) return 300;
    // ~60k node-iterations total, floored at something that still improves the picture.
    return Math.max(40, Math.round(60000 / order));
  }

  // Force Atlas 2, synchronous and chunked over requestAnimationFrame. Never a worker: the
  // `blob:` worker every graphology example uses is blocked by our CSP, silently. Returns a
  // handle with `cancel()`.
  function forceAtlas2(graph, opts) {
    const fa2 = lib().layoutForceAtlas2;
    const options = opts || {};
    if (!fa2 || !graph.order) {
      if (options.onDone) options.onDone(false);
      return { cancel: function () {} };
    }
    const total = options.iterations || fa2Iterations(graph.order);
    const settings = Object.assign(fa2.inferSettings ? fa2.inferSettings(graph) : {}, { barnesHutOptimize: graph.order > 300 }, options.settings || {});
    const pinned = options.pinned || new Set();
    const deadline = options.maxMs === undefined ? FA2_WALL_CLOCK_MS : options.maxMs;

    let done = 0;
    let chunk = graph.order > 400 ? 1 : 10;
    let cancelled = false;
    let raf = 0;
    let startedAt = 0;

    const finish = function (converged) {
      if (options.onDone) options.onDone(converged);
    };

    const step = function () {
      if (cancelled) return;
      if (!startedAt) startedAt = performance.now();
      const pins = [];
      pinned.forEach(function (key) {
        if (graph.hasNode(key)) pins.push([key, graph.getNodeAttribute(key, 'x'), graph.getNodeAttribute(key, 'y')]);
      });
      const t0 = performance.now();
      fa2.assign(graph, { iterations: Math.min(chunk, total - done), settings: settings });
      const elapsed = performance.now() - t0;
      // Pins are restored per chunk rather than once at the end: FA2 has no concept of a
      // fixed node, so a dragged node would drift away and snap back at the finish.
      for (const [key, x, y] of pins) {
        graph.setNodeAttribute(key, 'x', x);
        graph.setNodeAttribute(key, 'y', y);
      }
      done += Math.min(chunk, total - done);
      chunk = Math.max(1, Math.min(120, Math.round((chunk * FA2_FRAME_BUDGET_MS) / Math.max(elapsed, 0.5))));
      if (options.onProgress) options.onProgress(done / total);
      // A wall-clock stop, not just an iteration count. A partially-converged layout is
      // still an improvement, and an analyst watching a progress bar crawl for thirty
      // seconds is worse than one that finishes and says it stopped early.
      if (done >= total || (deadline && performance.now() - startedAt > deadline)) {
        finish(done >= total);
        return;
      }
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return {
      cancel: function () {
        cancelled = true;
        if (raf) cancelAnimationFrame(raf);
      },
    };
  }

  // ── Algorithms ──────────────────────────────────────────────────────────

  // The traversal graph: simple, undirected, and built from **typed edges only** (plus
  // finding edges on opt-in). Job edges are excluded *structurally*, never by weight — an
  // `Infinity` weight excludes nothing in graphology-shortest-path, whose weight getter is
  // `t => typeof t !== 'number' || isNaN(t) ? 1 : t` and whose `dijkstra.bidirectional`
  // returns as soon as the frontiers meet, with no finite-cost check.
  //
  // "Named in the same log file" is not a connection, and a path that leans on one is a
  // lie the analyst has no way to spot.
  function projection(graph, opts) {
    const includeFindings = !!(opts && opts.includeFindings);
    const Graph = window.graphology;
    if (!Graph) return null;
    const out = new Graph.UndirectedGraph();
    graph.forEachNode(function (key) {
      out.addNode(key);
    });
    graph.forEachEdge(function (_key, attr, source, target) {
      if (attr.kind === 'typed' || (includeFindings && attr.kind === 'finding')) {
        if (!out.hasEdge(source, target)) out.addEdge(source, target, { kind: attr.kind });
      }
    });
    return out;
  }

  // Every shortest path between two nodes, not just one.
  //
  // graphology-shortest-path exposes `unweighted.bidirectional`, `singleSource`, `dijkstra`
  // and `astar` — no k-shortest / Yen's. A BFS recording predecessor lists and backtracking
  // from the target is O(V+E), returns every shortest path up to `limit` (default 24 — full
  // enumeration is exponential), and naturally lights every parallel multi-edge between
  // consecutive path nodes.
  function allShortestPaths(graph, from, to, opts) {
    const limit = (opts && opts.limit) || 24;
    if (!graph.hasNode(from) || !graph.hasNode(to)) return [];
    if (from === to) return [[from]];

    const dist = new Map([[from, 0]]);
    const preds = new Map();
    let frontier = [from];
    let found = false;
    while (frontier.length && !found) {
      const next = [];
      for (const node of frontier) {
        const d = dist.get(node);
        graph.forEachNeighbor(node, function (nbr) {
          const seen = dist.get(nbr);
          if (seen === undefined) {
            dist.set(nbr, d + 1);
            preds.set(nbr, [node]);
            next.push(nbr);
            if (nbr === to) found = true;
          } else if (seen === d + 1) {
            preds.get(nbr).push(node);
          }
        });
      }
      frontier = next;
    }
    if (!dist.has(to)) return [];

    const paths = [];
    const walk = function (node, tail) {
      if (paths.length >= limit) return;
      if (node === from) {
        paths.push([from].concat(tail));
        return;
      }
      for (const parent of preds.get(node) || []) walk(parent, [node].concat(tail));
    };
    walk(to, []);
    return paths;
  }

  // A simple undirected copy of the whole graph, cached per call site.
  //
  // **Load-bearing, not a nicety.** The render graph is a `MultiGraph({type: 'mixed'})` —
  // undirected co-occurrence edges plus directed typed ones — and `communitiesLouvain`
  // throws outright on a true mixed graph ("cannot run the algorithm on a true mixed
  // graph"). Passing it the live graph is a runtime exception, not a wrong answer, and it
  // took a browser run to find because no unit test builds a mixed graph.
  //
  // Unlike `projection()`, this keeps **every** edge kind: clustering is a question about
  // the whole picture, whereas pathfinding is a question about evidence.
  function flatten(graph) {
    const ops = lib().operators;
    if (!ops || !ops.toUndirected || !ops.toSimple || !graph.order) return null;
    try {
      return ops.toSimple(ops.toUndirected(graph));
    } catch (err) {
      return null;
    }
  }

  // Louvain communities, written onto a node attribute so the renderer, the community lens
  // and circlepack all read one value instead of recomputing three.
  function communities(graph, attribute) {
    const louvain = lib().communitiesLouvain;
    const key = attribute || 'community';
    const flat = flatten(graph);
    if (!louvain || !flat || !flat.order) return 0;
    try {
      louvain.assign(flat, { nodeCommunityAttribute: key });
    } catch (err) {
      return 0;
    }
    const seen = new Set();
    flat.forEachNode(function (node, attrs) {
      seen.add(attrs[key]);
      if (graph.hasNode(node)) graph.setNodeAttribute(node, key, attrs[key]);
    });
    return seen.size;
  }

  function degreeRanking(graph, limit) {
    const rows = [];
    graph.forEachNode(function (key) {
      rows.push({ key: key, score: graph.degree(key) });
    });
    rows.sort(function (a, b) {
      return b.score - a.score || String(a.key).localeCompare(String(b.key));
    });
    return rows.slice(0, limit || 10);
  }

  // PageRank rather than betweenness — see the module header for the complexity argument,
  // and because raw degree here is dominated by how big a log file happened to be.
  //
  // Runs on the flattened copy for the same reason Louvain does, and swallows the library's
  // "failed to converge" error: a missing pivot list is a degraded panel, not a broken page.
  function pagerankRanking(graph, limit) {
    const metrics = lib().metrics;
    const fn = metrics && (metrics.pagerank || (metrics.centrality && metrics.centrality.pagerank));
    const flat = flatten(graph);
    if (!fn || !flat || !flat.order) return [];
    let scores;
    try {
      scores = typeof fn === 'function' ? fn(flat) : fn.pagerank(flat);
    } catch (err) {
      return [];
    }
    const rows = Object.keys(scores).map(function (key) {
      return { key: key, score: scores[key] };
    });
    rows.sort(function (a, b) {
      return b.score - a.score || String(a.key).localeCompare(String(b.key));
    });
    return rows.slice(0, limit || 10);
  }

  // Canvas2D render for PNG export. Not `preserveDrawingBuffer` on the WebGL context —
  // that costs every frame for the sake of an occasional screenshot, and a plain
  // `canvas.toDataURL()` on a non-preserved WebGL buffer returns blank.
  //
  // **The graph passed in must be an export graph, not the render graph.**
  // `graphology-canvas` resolves each element's renderer by `renderers.edges[attr.type]`,
  // and our edges carry Sigma's renderer names (`arrow`, `curve`, `line`) — none of which
  // exist in its registry, so handing it the live graph throws
  // `renderers.edges[type] is not a function`. `graph-render.js::buildExportGraph` produces
  // a plain, already-styled copy instead, which is also what makes the export reproduce
  // exactly what the analyst filtered: it is built from the same materialised decision map
  // the renderer draws from, rather than re-running a style engine that could disagree
  // with the screen.
  function renderToCanvas(graph, canvas, opts) {
    const canvasLib = lib().canvas;
    if (!canvasLib || !canvasLib.render) return false;
    try {
      canvasLib.render(graph, canvas.getContext('2d'), opts || {});
    } catch (err) {
      return false;
    }
    return true;
  }

  window.LogsTotalGraphAlgo = {
    egoRadial: egoRadial,
    fa2Iterations: fa2Iterations,
    circlepack: circlepack,
    forceAtlas2: forceAtlas2,
    projection: projection,
    allShortestPaths: allShortestPaths,
    communities: communities,
    degreeRanking: degreeRanking,
    pagerankRanking: pagerankRanking,
    renderToCanvas: renderToCanvas,
    circularMean: circularMean,
  };
})();
