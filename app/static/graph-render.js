// Relationship graph — the renderer. Owns the Sigma instance, the reducers, the camera,
// drag, and the WebGL lifecycle. Knows nothing about fetching, filters or Alpine.
//
// The core idea lives here: styling is a **reducer**, a pure function from (element, its
// attributes) to display attributes, evaluated per frame. Emphasis therefore never touches
// the graph, and the graph is where positions live — so changing what is emphasised cannot
// move a node, and no filter change needs a layout re-run.
//
// Reducers run for *every* element on *every* refresh, and hovering triggers refreshes, so
// they only ever read a pre-computed decision Map (see graph-view.js). Doing the work
// inside the reducer would re-derive the entire decision set sixty times a second.
//
// Loaded as a classic script before alpine.min.js; exposes one namespace on `window`.

(function () {
  'use strict';

  const View = function () {
    return window.LogsTotalGraphView;
  };

  // Level -> rendering. HIDDEN is handled separately (the element is `hidden`).
  const MUTED_ALPHA = '55'; // appended to a 6-digit hex; sigma parses #rrggbbaa

  // Node radius: a gentle curve on job_count so a hub reads as bigger without a single
  // 5,000-job entity swallowing the canvas.
  function nodeSize(node, isFocal) {
    const base = 4 + Math.min(9, Math.sqrt(node.jobCount || 0) * 1.6);
    return isFocal ? base * 1.9 : base;
  }

  // Node-label policy. Sigma draws a label only when `size / sqrt(cameraRatio)` clears
  // `labelRenderedSizeThreshold`, and at the default camera (ratio 1, which is where
  // `fit()` leaves it) that is just `size`. Feed `nodeSize` above into that and a threshold
  // of 7 resolves to **job_count >= 4** — so a first-seen entity, size 5.6, would never be
  // named at rest on any graph, at any density, on an otherwise empty canvas. The entity
  // Graph tab is always job-scoped, where most neighbours are exactly that, so it would read
  // as "names are missing" rather than "names are prioritised".
  //
  // 5 admits job_count >= 1 while the 70px label grid still decides how many actually draw,
  // so density stays bounded by geometry rather than by an accidental size cutoff.
  // `always` only drops the size threshold. The 70px label grid still applies — sigma draws
  // `ceil(labelDensity / cameraRatio²)` labels per cell — so at rest (ratio 1) `always` and
  // `auto` both come to one per cell; `always` only widens as you zoom in. Looser, never
  // unbounded, and density 1 is sigma's own default.
  const NODE_LABEL_MODES = {
    auto: { threshold: 5, density: 0.5, render: true },
    always: { threshold: 0, density: 1, render: true },
    never: { threshold: 0, density: 0.5, render: false },
  };

  // Stroke width. The floor that keeps a typed edge with no co-occurrence visible is a
  // *rendering constant*, so it belongs here — added server-side it would travel into the
  // GraphML export as though it were evidence.
  function edgeSize(edge) {
    const floor = edge.kind === 'typed' ? 1.6 : 0.6;
    return floor + Math.min(3.4, Math.log2(1 + (edge.weight || 1)) * 0.9);
  }

  function withAlpha(hex, alpha) {
    return typeof hex === 'string' && hex.length === 7 ? hex + alpha : hex;
  }

  function create(opts) {
    const schema = opts.schema;
    const V = View();
    const state = {
      sigma: null,
      graph: null,
      decoded: null,
      decisions: null,
      colorBy: 'type',
      pinned: new Set(),
      container: opts.container,
      recoveries: 0,
      suspended: false,
      _ro: null,
      _dragging: null,
      _hoverRaf: 0,
      edgeLabelsAtRest: false,
      handlers: opts.handlers || {},
    };

    function nodeColor(node) {
      if (state.colorBy === 'severity') return schema.colors.severity[node.severity || 'unknown'];
      if (state.colorBy === 'tactic') return schema.colors.tactic[node.tactic || '_other'];
      if (state.colorBy === 'verdict') return verdictColor(node.verdict);
      if (state.colorBy === 'community' && node.community != null) return communityColor(node.community);
      return schema.colors.type[node.type] || schema.colors.ui.label;
    }

    // Verdict reuses the severity ramp deliberately: an analyst already reads that ramp,
    // and a fifth palette for four values would be four more things to learn.
    function verdictColor(verdict) {
      const map = {
        malicious: schema.colors.severity.critical,
        suspicious: schema.colors.severity.high,
        unknown: schema.colors.severity.informational,
        clean: schema.colors.severity.low,
      };
      return map[verdict] || schema.colors.ui.muted;
    }

    // Communities are unbounded in number, so they cannot come from a fixed palette. A
    // golden-ratio hue walk gives stable, well-separated colours for any count.
    function communityColor(index) {
      const hue = Math.round((index * 137.508) % 360);
      return 'hsl(' + hue + ', 62%, 58%)';
    }

    // Border-channel precedence: one ring, four claimants. Selection is an *orthogonal*
    // channel — selecting a node must never dim the rest of the world — so it wins.
    function borderColor(index, node) {
      if (state.decisions && state.decisions.selection === index) return schema.colors.ui.selection;
      if (V.hasFlag(node, schema, 'focal')) return schema.colors.ui.focal;
      if (V.hasFlag(node, schema, 'watchlist')) return schema.colors.ui.watchlist;
      if (node.severity === 'critical' || node.severity === 'high') return schema.colors.severity[node.severity];
      return null;
    }

    function nodeReducer(key, data) {
      const index = data.index;
      const node = state.decoded ? state.decoded.nodes[index] : null;
      const level = state.decisions ? state.decisions.nodeLevels.get(index) : V.NORMAL;
      if (!node || level === V.HIDDEN) return Object.assign({}, data, { hidden: true, label: '' });

      const isFocal = V.hasFlag(node, schema, 'focal');
      const muted = level === V.MUTED;
      const color = nodeColor(node);
      const out = Object.assign({}, data, {
        label: node.label,
        size: nodeSize(node, isFocal) * (level === V.FOCUS ? 1.25 : 1),
        color: muted ? withAlpha(color, MUTED_ALPHA) : color,
        zIndex: level,
      });
      // `forceLabel` is decoupled from level on purpose: a MATCH changes colour and size
      // only. Forcing it would bypass labelRenderedSizeThreshold / labelDensity /
      // labelGridCellSize — the three settings that bound label cost — so a filter matching
      // 3,000 nodes would force-draw 3,000 labels every frame.
      if (state.decisions && state.decisions.forced.has(index)) out.forceLabel = true;
      if (muted) out.labelColor = schema.colors.ui.mutedLabel || schema.colors.ui.muted;

      const ring = borderColor(index, node);
      if (ring && !muted) {
        out.type = 'bordered';
        out.borderColor = ring;
      }
      if (V.hasFlag(node, schema, 'allowlisted')) out.color = withAlpha(out.color, MUTED_ALPHA);
      return out;
    }

    function edgeReducer(key, data) {
      const edge = data.edge;
      const level = state.decisions ? state.decisions.edgeLevels.get(key) : V.NORMAL;
      if (!edge || level === V.HIDDEN) return Object.assign({}, data, { hidden: true, label: '' });
      const base = edge.kind === 'typed' ? schema.colors.kind.typed : schema.colors.kind[edge.kind] || schema.colors.kind.job;
      const muted = level === V.MUTED;
      const out = Object.assign({}, data, {
        size: edgeSize(edge) * (level === V.FOCUS ? 1.8 : 1),
        color: muted ? withAlpha(base, MUTED_ALPHA) : base,
        zIndex: level,
      });
      // A typed edge's whole value is *which* relationship it is — an unlabelled arrow
      // makes `runs_as` and `parent_of` indistinguishable, which is most of the point of
      // having typed edges at all. So relationship names are drawn at rest whenever the
      // graph is small enough to read them (see `showEdgeLabels` in graph.js), and always
      // on the edge the analyst is pointing at or the path they pinned. Muted edges stay
      // silent regardless: a label is exactly as loud whether its line is dimmed or not.
      if (!edge.rel || muted) {
        out.label = '';
      } else if (level >= V.FOCUS) {
        out.forceLabel = true;
      } else if (!state.edgeLabelsAtRest) {
        out.label = '';
      }
      return out;
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────

    function webglAvailable() {
      try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('webgl2') || canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (!ctx) return false;
        // Release the probe context immediately. Browsers cap live WebGL contexts (~16),
        // and leaking one per page load is how a long session ends up unable to draw.
        const lose = ctx.getExtension('WEBGL_lose_context');
        if (lose) lose.loseContext();
        return true;
      } catch (err) {
        return false;
      }
    }

    // Sigma's UMD bundle hangs its renderers off `Sigma.rendering`. Three are registered:
    //
    //   line   EdgeRectangleProgram — job / finding. Undirected, so no arrowhead.
    //   arrow  EdgeArrowProgram     — a typed relationship. The arrowhead is the point.
    //   curve  EdgeCurveProgram     — the 2nd+ typed edge between the same pair.
    //
    // The bundle builds arrow-headed *curve* programs internally but does not export them,
    // so a curved edge cannot carry an arrowhead here. That is why the split exists rather
    // than curving everything: the overwhelmingly common case is one typed edge per pair,
    // which gets a straight line and a real arrow, and only the rare parallel case trades
    // its arrowhead for not being drawn underneath its sibling. The side panel lists every
    // relationship on a pair with its direction spelled out, so nothing is only inferable
    // from the arrowhead.
    function programs() {
      const r = (window.Sigma && window.Sigma.rendering) || {};
      const node = {};
      const edge = {};
      if (r.NodeCircleProgram) node.circle = r.NodeCircleProgram;
      if (r.createNodeBorderProgram) {
        node.bordered = r.createNodeBorderProgram({
          borders: [
            { size: { value: 0.12 }, color: { attribute: 'borderColor' } },
            { size: { fill: true }, color: { attribute: 'color' } },
          ],
        });
      }
      if (r.EdgeRectangleProgram) edge.line = r.EdgeRectangleProgram;
      if (r.EdgeArrowProgram) edge.arrow = r.EdgeArrowProgram;
      if (r.EdgeCurveProgram) edge.curve = r.EdgeCurveProgram;
      return { nodeProgramClasses: node, edgeProgramClasses: edge };
    }

    function construct() {
      const Sigma = window.Sigma;
      const Graph = window.graphology;
      if (!Sigma || !Graph || state.sigma) return;
      state.graph = state.graph || new Graph.MultiGraph({ type: 'mixed' });
      const progs = programs();
      state.sigma = new Sigma(state.graph, state.container, {
        nodeProgramClasses: progs.nodeProgramClasses,
        edgeProgramClasses: progs.edgeProgramClasses,
        defaultNodeType: 'circle',
        // A zero-size container throws "Container has no width/height", and this pane lives
        // inside an `x-show` tab that can legitimately be display:none when the partial
        // lands. Constructing anyway and letting the ResizeObserver call `resize()` is
        // simpler and more reliable than guessing at a frame to defer to.
        allowInvalidContainer: true,
        renderEdgeLabels: true,
        labelColor: { color: schema.colors.ui.label },
        // See NODE_LABEL_MODES: these are the 'auto' values, and `setNodeLabels` swaps
        // them at runtime. The threshold in particular is not a free knob — node size is
        // derived from job_count, so it decides which entities can ever be named.
        labelDensity: NODE_LABEL_MODES.auto.density,
        labelGridCellSize: 70,
        labelRenderedSizeThreshold: NODE_LABEL_MODES.auto.threshold,
        edgeLabelColor: { color: schema.colors.kind.typed },
        edgeLabelSize: 9,
        defaultEdgeType: 'line',
        zIndex: true,
        minCameraRatio: 0.05,
        maxCameraRatio: 12,
        nodeReducer: nodeReducer,
        edgeReducer: edgeReducer,
      });
      wireEvents();
      observe();
    }

    function wireEvents() {
      const s = state.sigma;
      s.on('clickNode', function (e) {
        if (state.handlers.onNodeClick) state.handlers.onNodeClick(indexOf(e.node), e);
      });
      s.on('rightClickNode', function (e) {
        // Sigma composes event names (`rightClick` + `"Node"`), which is why grepping the
        // minified bundle for `rightClickNode` finds nothing. It is not missing.
        if (e.event && e.event.original) e.event.original.preventDefault();
        if (state.handlers.onNodeContext) state.handlers.onNodeContext(indexOf(e.node), e);
      });
      s.on('clickEdge', function (e) {
        if (state.handlers.onEdgeClick) state.handlers.onEdgeClick(e.edge, e);
      });
      s.on('clickStage', function () {
        if (state.handlers.onStageClick) state.handlers.onStageClick();
      });
      s.on('enterNode', function (e) {
        scheduleHover(indexOf(e.node), e);
      });
      s.on('leaveNode', function () {
        scheduleHover(null, null);
      });

      // Drag. Sigma gives none of this for free, and all three cancellations are needed or
      // the stage pans underneath the node being dragged.
      s.on('downNode', function (e) {
        state._dragging = e.node;
        state.graph.setNodeAttribute(e.node, 'highlighted', true);
      });
      s.getMouseCaptor().on('mousemovebody', function (e) {
        if (!state._dragging) return;
        const pos = s.viewportToGraph(e);
        state.graph.setNodeAttribute(state._dragging, 'x', pos.x);
        state.graph.setNodeAttribute(state._dragging, 'y', pos.y);
        state.pinned.add(state._dragging);
        e.preventSigmaDefault();
        e.original.preventDefault();
        e.original.stopPropagation();
      });
      const drop = function () {
        if (state._dragging) state.graph.removeNodeAttribute(state._dragging, 'highlighted');
        state._dragging = null;
      };
      s.getMouseCaptor().on('mouseup', drop);
      s.on('upNode', drop);
      s.on('upStage', drop);

      // Context loss. Unhandled upstream (sigma#1321, open since 2022) and fatal without
      // this: the canvas goes black and never comes back. `preventDefault()` is mandatory
      // or no restore event fires at all. The rebuild is lossless because graph,
      // positions, pins and the decision map all live outside the renderer.
      //
      // `owner` is why a *single* loss counts as one recovery. `kill()` detaches the old
      // canvases but does not silence them: each one fires its own `webglcontextlost` as it
      // is torn down, those listeners are still attached, and each call rebuilt the
      // renderer again — one real GPU loss tripped the `recoveries > 3` guard and showed the
      // give-up message on a graph that had already recovered fine.
      const owner = s;
      const canvases = s.getCanvases ? s.getCanvases() : {};
      Object.keys(canvases).forEach(function (name) {
        canvases[name].addEventListener('webglcontextlost', function (ev) {
          ev.preventDefault();
          if (state.sigma !== owner) return; // a dead renderer's canvas losing its context
          scheduleRecovery();
        });
      });
    }

    let recoveryRaf = 0;
    function scheduleRecovery() {
      if (recoveryRaf) return;
      recoveryRaf = requestAnimationFrame(function () {
        recoveryRaf = 0;
        state.recoveries += 1;
        if (state.recoveries > 3) {
          if (state.handlers.onFatal) state.handlers.onFatal('The graph renderer lost its GPU context repeatedly. Reload the page to try again.');
          return;
        }
        const camera = state.sigma ? state.sigma.getCamera().getState() : null;
        try {
          state.sigma.kill();
        } catch (err) {
          /* already dead */
        }
        state.sigma = null;
        construct();
        if (camera && state.sigma) state.sigma.getCamera().setState(camera);
        refresh(true);
      });
    }

    function observe() {
      if (!window.ResizeObserver || state._ro) return;
      // **Size, not visibility.** An IntersectionObserver would kill the renderer whenever
      // the pane left the viewport — but "scrolled past" is not "hidden", and the graph pane
      // sits ~840 px down the entity page, so it would be suspended before the analyst ever
      // reached it and churn a WebGL context on every scroll by. What the suspension is
      // actually for is the `x-show` tab being switched away,
      // which collapses the container to 0x0 — and that is what this watches.
      state._ro = new ResizeObserver(function (entries) {
        const box = entries[0] && entries[0].contentRect;
        if (!box) return;
        if (box.width < 2 || box.height < 2) {
          suspend();
          return;
        }
        resume();
        if (state.sigma) state.sigma.resize();
      });
      state._ro.observe(state.container);
    }

    // Frees the WebGL context while the pane is collapsed — see the context cap in
    // `webglAvailable`. Lossless for the same reason the context-loss rebuild is.
    function suspend() {
      if (!state.sigma || state.suspended) return;
      state.suspended = true;
      state._camera = state.sigma.getCamera().getState();
      state.sigma.kill();
      state.sigma = null;
    }

    function resume() {
      if (!state.suspended) return;
      state.suspended = false;
      construct();
      if (state._camera && state.sigma) state.sigma.getCamera().setState(state._camera);
      refresh(true);
    }

    // Hover enter/leave are coalesced into one frame: a fast sweep across a dense graph
    // fires dozens of enter/leave pairs, each of which would otherwise trigger a full
    // decision recompute and a refresh.
    function scheduleHover(index, event) {
      state._pendingHover = { index: index, event: event };
      if (state._hoverRaf) return;
      state._hoverRaf = requestAnimationFrame(function () {
        state._hoverRaf = 0;
        const pending = state._pendingHover;
        state._pendingHover = null;
        if (state.handlers.onHover) state.handlers.onHover(pending.index, pending.event);
      });
    }

    function indexOf(key) {
      return parseInt(key, 10);
    }

    // ── Data ──────────────────────────────────────────────────────────────

    // Node keys are the *node index* as a string, so an edge's endpoints resolve with no
    // lookup table and a merge only has to remap indices once (see graph-view.mergePayload).
    function setGraph(decoded) {
      state.decoded = decoded;
      const Graph = window.graphology;
      if (!Graph) return;
      const graph = new Graph.MultiGraph({ type: 'mixed' });
      for (let i = 0; i < decoded.nodes.length; i++) {
        graph.addNode(String(i), { index: i, x: 0, y: 0, size: 5, label: decoded.nodes[i].label });
      }
      const seen = new Map();
      for (const edge of decoded.edges) addEdge(graph, edge, seen);
      state.graph = graph;
      state.pinned = new Set();
      if (state.sigma) state.sigma.setGraph(graph);
      else construct();
      applyCountDependentSettings();
    }

    function addEdge(graph, edge, seen) {
      const key = View().edgeKey(edge);
      if (graph.hasEdge(key)) return;
      const attrs = { edge: edge, kind: edge.kind, weight: edge.weight, label: edge.rel ? schema.labels.rels[edge.rel] || edge.rel : '' };
      // Undirected for the two co-occurrence kinds — "named in the same log file" is a
      // symmetric statement — and directed for typed relationships, so centrality and
      // traversal treat them correctly rather than pretending a mixed graph is one thing.
      if (!edge.rel) {
        graph.addUndirectedEdgeWithKey(key, String(edge.source), String(edge.target), Object.assign({ type: 'line' }, attrs));
        return;
      }
      const pair = Math.min(edge.source, edge.target) + '-' + Math.max(edge.source, edge.target);
      const nth = seen ? seen.get(pair) || 0 : 0;
      if (seen) seen.set(pair, nth + 1);
      if (nth === 0) {
        graph.addDirectedEdgeWithKey(key, String(edge.source), String(edge.target), Object.assign({ type: 'arrow' }, attrs));
      } else {
        // Alternating sign so a third parallel edge bows the other way instead of landing
        // on top of the second.
        const curvature = 0.25 * Math.ceil(nth / 2) * (nth % 2 === 1 ? 1 : -1);
        graph.addDirectedEdgeWithKey(key, String(edge.source), String(edge.target), Object.assign({ type: 'curve', curvature: curvature }, attrs));
      }
    }

    // Count-dependent settings are applied *after* the payload lands. At construction the
    // graph is empty, so both gates below would read zero and never engage.
    function applyCountDependentSettings() {
      if (!state.sigma || !state.graph) return;
      state.sigma.setSetting('hideEdgesOnMove', state.graph.size > 3000);
      state.sigma.setSetting('enableEdgeEvents', state.graph.size <= 3000);
    }

    function mergeInto(payload, addedBy) {
      const result = View().mergePayload(state.decoded, payload, schema, addedBy);
      for (let k = 0; k < result.addedNodes.length; k++) {
        const i = result.addedNodes[k];
        state.graph.addNode(String(i), { index: i, x: 0, y: 0, size: 5, label: state.decoded.nodes[i].label });
      }
      // A fresh `seen` per merge: an added parallel edge only needs to avoid the siblings
      // arriving with it, and re-deriving the whole map would mean walking every edge.
      const seen = new Map();
      for (const edge of result.addedEdges) addEdge(state.graph, edge, seen);
      applyCountDependentSettings();
      return result;
    }

    // `indexation` is the expensive half of a refresh. Sigma only needs it when **size or
    // position** changed; colour, label and hidden do not move anything in its spatial
    // index. Positions live in the graph rather than in view state, so the caller is the
    // one who knows — hence the explicit argument.
    function refresh(indexation) {
      if (state.sigma) state.sigma.refresh({ skipIndexation: !indexation });
    }

    function setDecisions(decisions) {
      state.decisions = decisions;
    }

    function setColorBy(mode) {
      state.colorBy = mode;
    }

    function setEdgeLabels(on) {
      state.edgeLabelsAtRest = !!on;
    }

    // Node labels are a *setting* change, not a reducer change — which is the whole reason
    // this is the right lever for the "small node, empty canvas" case. `forceLabel` can
    // only rescue nodes the analyst has already pointed at, and it is capped precisely
    // because it bypasses the three settings that bound label cost. Changing the bound
    // itself is cheap, global, and needs no per-node decision. Same shape as
    // `applyCountDependentSettings`.
    function setNodeLabels(mode) {
      const cfg = NODE_LABEL_MODES[mode] || NODE_LABEL_MODES.auto;
      state.nodeLabelMode = mode in NODE_LABEL_MODES ? mode : 'auto';
      if (!state.sigma) return;
      state.sigma.setSetting('renderLabels', cfg.render);
      state.sigma.setSetting('labelRenderedSizeThreshold', cfg.threshold);
      state.sigma.setSetting('labelDensity', cfg.density);
    }

    // `autoRescale` is on (Sigma's default), which is what makes framing free: the camera
    // works in normalised space, so "fit" is a camera reset rather than a bounding-box pass
    // over every node.
    function fit(animate) {
      if (!state.sigma) return;
      const camera = state.sigma.getCamera();
      const target = { x: 0.5, y: 0.5, ratio: 1, angle: 0 };
      if (animate) camera.animate(target, { duration: 220 });
      else camera.setState(target);
    }

    function centerOn(index, ratio) {
      if (!state.sigma || !state.graph || !state.graph.hasNode(String(index))) return;
      const display = state.sigma.getNodeDisplayData(String(index));
      if (!display) return;
      state.sigma.getCamera().animate({ x: display.x, y: display.y, ratio: ratio || 0.4 }, { duration: 250 });
    }

    function zoom(factor) {
      if (!state.sigma) return;
      const camera = state.sigma.getCamera();
      camera.animate({ ratio: camera.ratio * factor }, { duration: 150 });
    }

    // A plain, already-styled copy for PNG export.
    //
    // Two reasons it cannot be the render graph. First, `graphology-canvas` resolves each
    // element's renderer by `renderers.edges[attr.type]`, and ours carry Sigma's names
    // (`arrow`, `curve`, `line`), which throws. Second — and more to the point — the export
    // must reproduce what the analyst filtered, so it is built by running the *same*
    // materialised decision map through the *same* reducers the screen uses. Hidden
    // elements are simply absent.
    //
    // Parallel typed edges collapse here, because the canvas renderer draws every edge
    // straight and two straight parallels are one line. The label carries both names.
    function buildExportGraph() {
      const Graph = window.graphology;
      if (!Graph || !state.graph) return null;
      const out = new Graph.UndirectedGraph();
      state.graph.forEachNode(function (key, attrs) {
        const display = nodeReducer(key, attrs);
        if (display.hidden) return;
        out.addNode(key, {
          x: attrs.x,
          y: attrs.y,
          size: display.size,
          color: display.color,
          label: display.label,
        });
      });
      state.graph.forEachEdge(function (key, attrs, source, target) {
        if (!out.hasNode(source) || !out.hasNode(target)) return;
        const display = edgeReducer(key, attrs);
        if (display.hidden) return;
        const existing = out.hasEdge(source, target) ? out.edge(source, target) : null;
        if (existing) {
          const label = out.getEdgeAttribute(existing, 'label');
          const extra = attrs.label;
          if (extra && label !== extra) out.setEdgeAttribute(existing, 'label', label ? label + ', ' + extra : extra);
          return;
        }
        out.addEdge(source, target, { size: display.size, color: display.color, label: attrs.label || '' });
      });
      return out;
    }

    function setInteractive(enabled) {
      if (!state.sigma) return;
      state.sigma.setSetting('enableCameraPanning', enabled);
      state.sigma.setSetting('enableCameraZooming', enabled);
    }

    function destroy() {
      if (state._ro) {
        state._ro.disconnect();
        state._ro = null;
      }
      if (state.sigma) {
        state.sigma.kill();
        state.sigma = null;
      }
    }

    return {
      state: state,
      webglAvailable: webglAvailable,
      construct: construct,
      setGraph: setGraph,
      mergeInto: mergeInto,
      setDecisions: setDecisions,
      setColorBy: setColorBy,
      setEdgeLabels: setEdgeLabels,
      setNodeLabels: setNodeLabels,
      refresh: refresh,
      fit: fit,
      centerOn: centerOn,
      zoom: zoom,
      buildExportGraph: buildExportGraph,
      setInteractive: setInteractive,
      destroy: destroy,
      nodeSize: nodeSize,
      edgeSize: edgeSize,
      communityColor: communityColor,
    };
  }

  window.LogsTotalGraphRender = { create: create };
})();
