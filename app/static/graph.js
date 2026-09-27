// Shared relationship-graph component for the Intel entity Graph tab and the Cases Graph
// view. Both render the same graph; the differences are scope-conditional controls
// (hops/expand for entities, a job-edge toggle and the time link for cases).
//
// This file is the *glue*: Alpine state, fetch/abort discipline, and the wiring between
// the three modules it sits on top of —
//
//   graph-view.js    pure: decode, the emphasis stack, the query engine, payload merge
//   graph-algo.js    layouts + graphology algorithms
//   graph-render.js  the Sigma instance, reducers, camera, drag, WebGL lifecycle
//
// Nothing here declares a colour. The whole palette arrives from the server in
// `opts.schema` (`app/intel/graph_payload.py::client_schema`), which is also what the
// legend renders from, so a node and its legend swatch cannot disagree.
//
// Loaded in <head> before alpine.min.js — see the note in base.html. The factory is a
// top-level `function` declaration on purpose: a top-level `const` lands in script scope,
// not on `window`, and Alpine would not find it.

// opts: { scope, focalId?, caseId?, jsonUrl, graphmlBase, pngPrefix, schema, activeUrl? }
function graphComponent(opts) {
  const isEntity = opts.scope === 'entity';
  const schema = opts.schema;
  const View = window.LogsTotalGraphView;
  const Algo = window.LogsTotalGraphAlgo;
  const Render = window.LogsTotalGraphRender;

  return {
    scope: opts.scope,
    focalId: opts.focalId || null,
    caseId: opts.caseId || null,
    jsonUrl: opts.jsonUrl,
    graphmlBase: opts.graphmlBase,
    pngPrefix: opts.pngPrefix,
    activeUrl: opts.activeUrl || null,
    schema: schema,

    // Entity scope: fixed for the life of the instance. The shell does not render this
    // component at all until a job is chosen, and changing the scope reloads the page —
    // the tab badges are server-computed, so the scope has to be a page-level fact.
    // Case scope: an ordinary control (0 = every job in the case), because a case renders
    // unfiltered by default and narrowing it is a question you ask in place.
    jobId: opts.jobId || 0,

    // ── Server-side controls (a change here refetches) ─────────────────────
    hops: 1,
    limit: 30,
    showJobEdges: false,
    includeAllowlisted: false,

    // ── Client-side controls (a change here only re-runs the emphasis stack) ─
    search: '',
    queryError: '',
    dimMode: 'dim',
    colorBy: 'type',
    layout: isEntity ? 'rings' : 'communities',
    severityFloor: '',
    communityFilter: null,
    selectedTypes: new Set(),
    hiddenKinds: new Set(),
    hiddenRels: new Set(),

    // ── View state ────────────────────────────────────────────────────────
    ready: false,
    loading: false,
    error: '',
    fatal: '',
    exporting: false,
    locked: false,
    // The three floating panels are mutually exclusive. They all live in the same corner of
    // the canvas, and two open at once meant the Pivots card sat on top of the Legend's own
    // toggle — so the legend could be opened and then not closed.
    //
    // **Do not rename this back to `panel` without re-checking it in a browser.** With the
    // property named `panel`, reads were correct (`Alpine.evaluate(el, 'panel')` returned
    // the new value) but the `x-show` effect never re-ran: `_x_isShown` stayed false and the
    // inline `display: none` was never cleared. Renaming to `activePanel` — nothing else —
    // fixed it. The working theory is a scope-resolution collision in Alpine's evaluator;
    // that is a theory, not a diagnosis, which is exactly why the guard is a distinctive
    // name plus a test rather than a clever workaround.
    activePanel: '',
    // 'auto' draws a typed edge's relationship name whenever the graph is small enough to
    // read; 'always' and 'never' are the escape hatches. Labels only on hover would make
    // `runs_as` and `parent_of` indistinguishable at rest — the whole point of having typed
    // edges.
    edgeLabels: 'auto',
    // Node names. 'auto' is the tuned default; 'always' drops both bounds (slow on a big
    // graph, and says so); 'never' is for reading structure alone. Separate from
    // `edgeLabels` because they answer different questions and cost differently — an entity
    // name is the thing you came to read, a relationship name is context.
    nodeLabels: 'auto',
    tall: false,
    webgl: true,
    stats: null,
    counts: { visibleNodes: 0, totalNodes: 0, visibleEdges: 0, totalEdges: 0, dimmedNodes: 0, lensActive: false, zeroMatches: false },
    matchesPartial: false,
    communityCount: 0,
    layoutProgress: 0,
    layoutRunning: false,
    layoutStoppedEarly: false,
    pivots: [],
    pivotMode: 'pagerank',
    trail: [],
    menu: { visible: false, x: 0, y: 0, index: null },
    hover: { visible: false, x: 0, y: 0, node: null },
    selected: { visible: false, index: null, node: null, edge: null },
    path: { from: null, to: null, results: [], searched: false, includeFindings: false, message: '' },
    timeWindow: null,
    isolateWindow: null,
    timespan: null,
    timeState: { active: false, usable: false, jobs: 0, withoutIndex: 0, legacy: 0 },
    fallbackRows: [],

    // ── Internals ─────────────────────────────────────────────────────────
    renderer: null,
    decoded: null,
    _inflight: null,
    _abort: null,
    _expandAbort: null,
    _activeAbort: null,
    _layoutHandle: null,
    _projection: null,
    _searchTimer: 0,
    _typedEdgeCount: 0,
    _serverQuery: '',
    _overlay: null,
    _overlayEdges: null,
    _projectionFindings: false,

    // ── Query string ──────────────────────────────────────────────────────

    // One place the job scope is spelled, because there are three URL builders and a
    // fourth (`_expandNode`) that does not call `_query()`. A builder that forgets it
    // returns a perfectly valid unscoped graph — no error, wrong picture.
    _jobParam() {
      return this.jobId ? '&job=' + this.jobId : '';
    },
    _query() {
      const a = 'include_allowlisted=' + (this.includeAllowlisted ? 1 : 0);
      // Only the server-evaluated half of the search reaches the URL. Round-tripping the
      // whole box would make every keystroke a request and defeat the point of a filter
      // evaluated against a graph already in memory.
      const q = this._serverQuery ? '&q=' + encodeURIComponent(this._serverQuery) : '';
      if (isEntity) return '?hops=' + this.hops + '&limit=' + this.limit + '&' + a + q + this._jobParam();
      return '?' + a + '&job_edges=' + (this.showJobEdges ? 1 : 0) + q + this._jobParam();
    },
    graphmlUrl() {
      return this.graphmlBase + this._query();
    },
    searchAllUrl() {
      // Discovery is a different act from filtering: the graph can only emphasise nodes it
      // already holds, so a query that finds nothing here may well find plenty on /intel.
      return '/intel?q=' + encodeURIComponent(this.search);
    },

    // ── Lifecycle ─────────────────────────────────────────────────────────

    init() {
      if (!View || !Algo || !Render) {
        // A bare return here would leave ready:false / loading:false / error:'' — a blank
        // pane with no message, indistinguishable from an entity with no neighbours.
        this.fatal = 'The graph libraries failed to load. Reload the page, or use the GraphML export.';
        return;
      }
      this.selectedTypes = new Set(schema.types);
      this.renderer = Render.create({
        container: this.$refs.graph,
        schema: schema,
        handlers: {
          onNodeClick: (i) => this.selectNode(i),
          onNodeContext: (i, e) => this.openMenu(i, e),
          onEdgeClick: (key) => this.selectEdge(key),
          onStageClick: () => this.closePanel(),
          onHover: (i, e) => this.onHover(i, e),
          onFatal: (msg) => {
            this.fatal = msg;
          },
        },
      });
      this.webgl = this.renderer.webglAvailable();
      if (!this.webgl) {
        // Not a static re-render: a picture with no hover, click or zoom is worse than a
        // weight-ordered table with working links. The rows come from the same payload.
        this.reload();
        return;
      }
      this.renderer.construct();
      if (this.activeUrl) this._subscribeToTimeline();
      this.reload();
    },

    destroy() {
      if (this._abort) this._abort.abort();
      if (this._expandAbort) this._expandAbort.abort();
      if (this._activeAbort) this._activeAbort.abort();
      if (this._layoutHandle) this._layoutHandle.cancel();
      if (this.renderer) this.renderer.destroy();
    },

    reload() {
      const query = this._query();
      // Swapped-in markup is initialized twice (Alpine's MutationObserver sees the inserted
      // nodes, and base.html's htmx:afterSwap hook calls Alpine.initTree too), so init()
      // fires twice and would otherwise issue two identical requests — each expensive on a
      // large case. Collapse the duplicate.
      if (this.loading && this._inflight === query) return;
      // A *different* query while one is in flight is a real reload, not a duplicate, and
      // races: change hops 1->3->1 quickly and both requests run, whichever resolves last
      // winning, so the canvas could show hops=3 while the dropdown reads 1.
      if (this._abort) this._abort.abort();
      // A pending expansion would merge neighbours into a graph this reload is about to
      // replace. Aborting is one-directional on purpose: an expand must never cancel a
      // reload, or the reload's `loading` flag would have no one left to clear it.
      if (this._expandAbort) this._expandAbort.abort();
      if (this._layoutHandle) this._layoutHandle.cancel();
      const controller = new AbortController();
      this._abort = controller;
      this._inflight = query;
      this.loading = true;
      this.ready = false;
      this.error = '';

      fetch(this.jsonUrl + query, { credentials: 'same-origin', signal: controller.signal })
        .then((r) => (r.ok ? r.json() : Promise.reject(r)))
        .then((payload) => {
          this.decoded = View.decodePayload(payload, schema);
          this.stats = payload.stats || null;
          this.matchesPartial = this.decoded.matchesPartial;
          this.trail = [{ label: 'Initial view', count: this.decoded.nodes.length }];
          this.path = { from: null, to: null, results: [], searched: false, includeFindings: false, message: '' };
          this._projection = null;
          // Server-chosen defaults, not a scope conditional in the client. A case opens
          // with hashes hidden (one per file touched, crowding out the structure); an
          // entity graph keeps every type, since the focal entity is often the hash.
          this.selectedTypes = new Set(schema.types.filter((t) => this.decoded.hiddenTypes.indexOf(t) === -1));
          this.hiddenKinds = new Set(this.decoded.hiddenKinds);
          this._typedEdgeCount = this.decoded.edges.filter((e) => e.rel).length;
          if (!this.webgl) {
            this.fallbackRows = this._buildFallback();
            this.ready = true;
            return;
          }
          this.renderer.setGraph(this.decoded);
          this.renderer.setEdgeLabels(this.showEdgeLabels());
          // Re-asserted here, not just at construction: a WebGL context loss rebuilds the
          // Sigma instance from scratch, and it would come back with the default bounds
          // while the toolbar still read 'always'.
          this.renderer.setNodeLabels(this.nodeLabels);
          this.ready = true;
          // Post-processing is guarded separately. It runs *after* the graph is on screen,
          // so a failure here — a layout, a clustering algorithm, a ranking — degrades one
          // panel; reporting it as "could not load the graph" would be a plain lie, and
          // that is exactly what a single shared .catch() did: Louvain threw on the mixed
          // graph and the whole tab claimed the fetch had failed while 31 nodes were drawn.
          try {
            this.communityCount = Algo.communities(this.renderer.state.graph, 'community');
            this._syncCommunityAttribute();
            this.refreshPivots();
          } catch (err) {
            this.communityCount = 0;
            this.pivots = [];
          }
          this.runLayout(true);
          this.apply(true);
        })
        .catch((err) => {
          if (err && err.name === 'AbortError') return;
          // Never swallowed: a 403/500 would leave an empty canvas, no message and a stale
          // `ready`, indistinguishable from an entity with no neighbours.
          this.ready = false;
          this.stats = null;
          this.error = err && err.status ? 'Could not load the graph (HTTP ' + err.status + ').' : 'Could not load the graph.';
        })
        .finally(() => {
          if (this._abort !== controller) return;
          this.loading = false;
          this._inflight = null;
          this._abort = null;
        });
    },

    togglePanel(name) {
      this.activePanel = this.activePanel === name ? '' : name;
    },

    // Relationship names are worth drawing at rest, but not at any size: every typed edge
    // label is a text draw per frame, and sigma's label-collision grid only thins them, it
    // does not make them free. The threshold is the point past which they stop being
    // readable anyway.
    showEdgeLabels() {
      if (this.edgeLabels === 'always') return true;
      if (this.edgeLabels === 'never') return false;
      return this._typedEdgeCount > 0 && this._typedEdgeCount <= 80;
    },

    setEdgeLabels(mode) {
      this.edgeLabels = mode;
      this.renderer.setEdgeLabels(this.showEdgeLabels());
      this.apply(false);
    },

    setNodeLabels(mode) {
      this.nodeLabels = mode;
      this.renderer.setNodeLabels(mode);
      // A settings change does not move anything, so no re-indexation — but it does have
      // to reach the canvas, and `apply` is the one path that refreshes.
      this.apply(false);
    },

    // Expand takes the whole viewport, toolbar included. A taller *canvas* does not help:
    // on the entity page the graph starts 838 px down, so on a 900 px screen the box is
    // below the fold whatever height it has — the page above it is the constraint.
    toggleTall() {
      this.tall = !this.tall;
      // The container changes size, so the renderer must re-read its box. The
      // ResizeObserver does that; fit() has to come after it, one frame later.
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          if (this.renderer) this.renderer.fit(true);
        });
      });
    },

    // ── Emphasis ──────────────────────────────────────────────────────────

    // The single entry point for "something about the view changed". `indexation` says
    // whether **size or position** moved — Sigma only needs to rebuild its spatial index
    // then. Colour, label and hidden do not move anything, which is why filtering is cheap
    // and, more importantly, why it cannot rearrange the picture.
    apply(indexation) {
      if (!this.decoded || !this.renderer || !this.webgl) return;
      const st = View.defaultState();
      st.schema = schema;
      st.hiddenTypes = new Set(schema.types.filter((t) => !this.selectedTypes.has(t)));
      st.hiddenKinds = new Set(this.hiddenKinds);
      st.hiddenRels = new Set(this.hiddenRels);
      st.showAllowlisted = true;
      st.dimMode = this.dimMode;
      st.severityFloor = this.severityFloor || null;
      st.community = this.communityFilter;
      st.activeIds = this.timeWindow;
      st.isolateIds = this.isolateWindow;
      st.selection = this.selected.index;
      st.query = this._parsedQuery();
      st.overlay = this._overlay;
      st.overlayEdges = this._overlayEdges;

      const decisions = View.computeDecisions(this.decoded, st);
      // An all-grey canvas reads as a crash. When a lens matches nothing, say so in a chip
      // and leave emphasis alone rather than dimming the world.
      if (decisions.counts.zeroMatches) {
        st.query = null;
        st.severityFloor = null;
        st.community = null;
        st.activeIds = null;
        st.isolateIds = null;
        const relaxed = View.computeDecisions(this.decoded, st);
        relaxed.counts.zeroMatches = true;
        this.counts = relaxed.counts;
        this.renderer.setDecisions(relaxed);
      } else {
        this.counts = decisions.counts;
        this.renderer.setDecisions(decisions);
      }
      this.renderer.setColorBy(this.colorBy);
      this.renderer.refresh(!!indexation);
    },

    _parsedQuery() {
      if (!this.search.trim()) return null;
      const parsed = View.parseQuery(this.search, schema);
      this.queryError = parsed.errors.join(' · ');
      return parsed;
    },

    onSearchInput() {
      // Local terms apply on the next frame; only `re:`/`job:` cost a request, and those
      // are debounced.
      clearTimeout(this._searchTimer);
      this.apply(false);
      this._searchTimer = setTimeout(() => {
        const parsed = this.search.trim() ? View.parseQuery(this.search, schema) : null;
        const wanted = parsed && parsed.needsServer ? this.search.trim() : '';
        if (wanted !== this._serverQuery) {
          this._serverQuery = wanted;
          this.reload();
        }
      }, 350);
    },

    clearSearch() {
      this.search = '';
      this.queryError = '';
      if (this._serverQuery) {
        this._serverQuery = '';
        this.reload();
      } else {
        this.apply(false);
      }
    },

    // ── Type / kind / relationship filters ────────────────────────────────

    typeChips() {
      return schema.types.map((key) => ({ key: key, label: schema.labels.types[key] || key, color: schema.colors.type[key] }));
    },
    kindChips() {
      // The hints are the difference between three coloured lines and three *claims* of
      // very different strength. They belong on the chip, not only in the legend.
      return [
        {
          key: 'job',
          label: schema.labels.kinds.job,
          color: schema.colors.kind.job,
          hint: 'Weakest: the two entities were named in the same log file. Never carries a path.',
        },
        {
          key: 'finding',
          label: schema.labels.kinds.finding,
          color: schema.colors.kind.finding,
          hint: 'Both entities were named inside one Sigma rule match.',
        },
        {
          key: 'typed',
          label: schema.labels.kinds.typed,
          color: schema.colors.kind.typed,
          hint: 'Strongest: an evidence-backed, directed relationship read out of the events.',
        },
      ];
    },
    relChips() {
      const present = new Set();
      for (const e of (this.decoded && this.decoded.edges) || []) if (e.rel) present.add(e.rel);
      return Array.from(present)
        .sort()
        .map((key) => ({ key: key, label: schema.labels.rels[key] || key }));
    },
    toggleType(key) {
      if (this.selectedTypes.has(key)) this.selectedTypes.delete(key);
      else this.selectedTypes.add(key);
      this.selectedTypes = new Set(this.selectedTypes);
      this.apply(false);
    },
    allTypesSelected() {
      return this.selectedTypes.size === schema.types.length;
    },
    toggleAllTypes() {
      this.selectedTypes = this.allTypesSelected() ? new Set() : new Set(schema.types);
      this.apply(false);
    },
    toggleKind(key) {
      if (this.hiddenKinds.has(key)) this.hiddenKinds.delete(key);
      else this.hiddenKinds.add(key);
      this.hiddenKinds = new Set(this.hiddenKinds);
      this.apply(false);
    },
    toggleRel(key) {
      if (this.hiddenRels.has(key)) this.hiddenRels.delete(key);
      else this.hiddenRels.add(key);
      this.hiddenRels = new Set(this.hiddenRels);
      this.apply(false);
    },
    setColorBy(mode) {
      this.colorBy = mode;
      this.apply(false);
    },
    setDimMode(mode) {
      this.dimMode = mode;
      this.apply(false);
    },
    setSeverityFloor(value) {
      this.severityFloor = value;
      this.apply(false);
    },
    filterCommunity(index) {
      this.communityFilter = this.communityFilter === index ? null : index;
      this.apply(false);
    },

    // ── Layout ────────────────────────────────────────────────────────────

    runLayout(initial) {
      if (!this.renderer || !this.webgl) return;
      const graph = this.renderer.state.graph;
      if (!graph || !graph.order) return;
      if (this._layoutHandle) {
        this._layoutHandle.cancel();
        this._layoutHandle = null;
      }
      this.layoutRunning = false;
      this.layoutProgress = 0;
      this.layoutStoppedEarly = false;

      if (this.layout === 'rings') {
        Algo.egoRadial(graph, this._focalKey(), {});
      } else if (this.layout === 'communities') {
        if (!Algo.circlepack(graph, 'community')) Algo.egoRadial(graph, this._focalKey(), {});
      } else if (this.layout === 'force') {
        // Seed from rings so the first frames of the simulation are not a random cloud —
        // but restore pins immediately afterwards. `egoRadial` re-places *every* node, so
        // without this the seeding pass silently undoes every drag before FA2 has run a
        // single iteration, and the per-chunk pin restore then holds the wrong position.
        const pins = [];
        this.renderer.state.pinned.forEach((key) => {
          if (graph.hasNode(key)) pins.push([key, graph.getNodeAttribute(key, 'x'), graph.getNodeAttribute(key, 'y')]);
        });
        Algo.egoRadial(graph, this._focalKey(), {});
        for (const [key, x, y] of pins) {
          graph.setNodeAttribute(key, 'x', x);
          graph.setNodeAttribute(key, 'y', y);
        }
        this.layoutRunning = true;
        this._layoutHandle = Algo.forceAtlas2(graph, {
          // Iteration count scales with the graph; see fa2Iterations for the measurement.
          pinned: this.renderer.state.pinned,
          onProgress: (p) => {
            this.layoutProgress = p;
            this.renderer.refresh(true);
          },
          onDone: (converged) => {
            this.layoutRunning = false;
            this._layoutHandle = null;
            this.layoutStoppedEarly = !converged;
            this.renderer.refresh(true);
            if (initial) this.renderer.fit(false);
          },
        });
      }
      this.renderer.refresh(true);
      if (initial && this.layout !== 'force') this.renderer.fit(false);
    },

    cancelLayout() {
      if (this._layoutHandle) this._layoutHandle.cancel();
      this._layoutHandle = null;
      this.layoutRunning = false;
    },

    setLayout(name) {
      this.layout = name;
      this.runLayout(false);
    },

    _focalKey() {
      if (!isEntity || !this.decoded) return null;
      const i = this.decoded.nodes.findIndex((n) => n.entityId === this.focalId);
      return i === -1 ? null : String(i);
    },

    _syncCommunityAttribute() {
      // Mirror the graph attribute onto the decoded nodes so the community *lens* and the
      // colour-by mode read one value rather than two that can drift.
      const graph = this.renderer.state.graph;
      graph.forEachNode((key, attr) => {
        const node = this.decoded.nodes[attr.index];
        if (node) node.community = attr.community;
      });
    },

    // ── Pivots ────────────────────────────────────────────────────────────

    refreshPivots() {
      if (!this.renderer || !this.decoded) return;
      const graph = this.renderer.state.graph;
      const rows = this.pivotMode === 'degree' ? Algo.degreeRanking(graph, 8) : Algo.pagerankRanking(graph, 8);
      this.pivots = rows
        .map((r) => {
          const node = this.decoded.nodes[parseInt(r.key, 10)];
          return node ? { index: parseInt(r.key, 10), label: node.label, type: node.type, score: r.score } : null;
        })
        .filter(Boolean);
    },

    setPivotMode(mode) {
      this.pivotMode = mode;
      this.refreshPivots();
    },

    // ── Paths ─────────────────────────────────────────────────────────────

    // The traversal graph is a simple undirected projection built from typed edges only
    // (plus finding edges on opt-in). Job edges are excluded *structurally* — "named in the
    // same log file" is not a connection, and a path that leans on one is a lie an analyst
    // has no way to spot. Cached and invalidated on structure changes only; invalidating on
    // attribute updates would rebuild it on every layout tick.
    _traversal() {
      const wanted = this.path.includeFindings;
      if (this._projection && this._projectionFindings === wanted) return this._projection;
      this._projection = Algo.projection(this.renderer.state.graph, { includeFindings: wanted });
      this._projectionFindings = wanted;
      return this._projection;
    },

    setPathEnd(which) {
      if (this.selected.index == null) return;
      this.path[which] = this.selected.index;
      this.path.searched = false;
      this.path.message = '';
      if (this.path.from != null && this.path.to != null) this.findPaths();
    },

    findPaths() {
      const proj = this._traversal();
      if (!proj || this.path.from == null || this.path.to == null) return;
      const from = String(this.path.from);
      const to = String(this.path.to);
      const paths = Algo.allShortestPaths(proj, from, to, { limit: 12 });
      this.path.results = paths;
      this.path.searched = true;
      this.path.message = '';
      if (!paths.length) {
        // Three genuinely different "no path" states. Collapsing them into one message is
        // how a bounded slice gets read as a statement about the data.
        if (!this.path.includeFindings) {
          const withFindings = Algo.allShortestPaths(Algo.projection(this.renderer.state.graph, { includeFindings: true }), from, to, { limit: 1 });
          if (withFindings.length) {
            this.path.message = 'No typed-relationship path. There is one if you allow "same Sigma finding" hops.';
            return;
          }
        }
        this.path.message =
          this.scope === 'entity'
            ? 'No path within the loaded slice. Try more hops or more neighbours per hop.'
            : 'No path — these entities are in different components of this case.';
        return;
      }
      this.showPath(0);
    },

    showPath(i) {
      const path = this.path.results[i];
      if (!path) return;
      const nodes = new Set(path.map((k) => parseInt(k, 10)));
      const edges = new Set();
      // Light *every* parallel edge between consecutive path nodes: the path is a sequence
      // of hops, and which of two relationship types carried the hop is exactly what the
      // analyst is about to ask.
      for (const edge of this.decoded.edges) {
        if (nodes.has(edge.source) && nodes.has(edge.target)) edges.add(View.edgeKey(edge));
      }
      this._overlay = nodes;
      this._overlayEdges = edges;
      this.apply(false);
    },

    clearPath() {
      this.path = { from: null, to: null, results: [], searched: false, includeFindings: this.path.includeFindings, message: '' };
      this._overlay = null;
      this._overlayEdges = null;
      this.apply(false);
    },

    pathLabel(path) {
      return path.map((k) => (this.decoded.nodes[parseInt(k, 10)] || {}).label || '?').join(' → ');
    },

    // ── Hover / selection ─────────────────────────────────────────────────

    onHover(index, event) {
      if (index == null) {
        this.hover.visible = false;
        if (!this.path.searched) {
          this._overlay = null;
          this._overlayEdges = null;
          this.apply(false);
        }
        return;
      }
      const node = this.decoded.nodes[index];
      if (!node) return;
      const pos = event && event.event ? event.event : { x: 0, y: 0 };
      this.hover = { visible: true, x: pos.x, y: pos.y, node: node };
      if (this.path.searched) return; // a pinned path outranks a transient hover
      const nodes = new Set([index]);
      const edges = new Set();
      for (const edge of this.decoded.edges) {
        if (edge.source === index || edge.target === index) {
          nodes.add(edge.source);
          nodes.add(edge.target);
          edges.add(View.edgeKey(edge));
        }
      }
      this._overlay = nodes;
      this._overlayEdges = edges;
      this.apply(false);
    },

    selectNode(index) {
      const node = this.decoded ? this.decoded.nodes[index] : null;
      if (!node) return;
      this.selected = { visible: true, index: index, node: node, edge: null };
      this.menu.visible = false;
      this.apply(false);
    },

    selectEdge(key) {
      const edge = (this.decoded.edges || []).find((e) => View.edgeKey(e) === key);
      if (!edge) return;
      this.selected = {
        visible: true,
        index: null,
        node: null,
        edge: {
          key: key,
          kind: edge.kind,
          rel: edge.rel,
          relLabel: edge.rel ? schema.labels.rels[edge.rel] || edge.rel : schema.labels.kinds[edge.kind],
          relId: edge.relId,
          weight: edge.weight,
          source: this.decoded.nodes[edge.source],
          target: this.decoded.nodes[edge.target],
        },
      };
      this.timespan = null;
      this.loadTimespan();
      this.apply(false);
    },

    // Observed window for a typed edge, fetched on demand rather than shipped with every
    // payload: it costs a query per edge and almost no edge is ever selected.
    //
    // The response carries `time_source` and the component renders it verbatim. An edge
    // whose evidence has no parseable event timestamp reports *ingest* time — when the
    // worker happened to run — and saying "first seen" over that number would be a lie the
    // analyst has no way to detect.
    loadTimespan() {
      const edge = this.selected.edge;
      if (!edge || !edge.relId || this.timespan) return;
      fetch('/intel/relationships/' + edge.relId + '/timespan.json', { credentials: 'same-origin' })
        .then((r) => (r.ok ? r.json() : Promise.reject(r)))
        .then((span) => {
          this.timespan = span;
        })
        .catch(() => {
          this.timespan = { unavailable: true };
        });
    },

    formatTimespan() {
      const t = this.timespan;
      if (!t || t.unavailable || t.from == null) return '';
      const f = new Date(t.from).toISOString().slice(0, 16).replace('T', ' ');
      const to = new Date(t.to).toISOString().slice(0, 16).replace('T', ' ');
      return f === to ? f + ' UTC' : f + ' → ' + to + ' UTC';
    },

    closePanel() {
      this.selected = { visible: false, index: null, node: null, edge: null };
      this.menu.visible = false;
      this.apply(false);
    },

    onEscape() {
      if (this.menu.visible) {
        this.menu.visible = false;
        return;
      }
      if (this.activePanel) {
        this.activePanel = '';
        return;
      }
      if (this.tall) {
        this.toggleTall();
        return;
      }
      if (this.path.searched) {
        this.clearPath();
        return;
      }
      if (this.selected.visible) {
        this.closePanel();
        return;
      }
      if (this.search) this.clearSearch();
    },

    nodeChips(node) {
      if (!node) return [];
      const chips = [];
      if (node.subtype) chips.push({ label: node.subtype, tone: 'muted' });
      for (const key of schema.attr_flags) if (View.hasFlag(node, schema, key)) chips.push({ label: key, tone: 'attr' });
      for (const tag of node.tags) chips.push({ label: tag, tone: 'tag' });
      return chips;
    },

    // ── Context menu ──────────────────────────────────────────────────────

    openMenu(index, event) {
      const rect = this.$refs.graph.getBoundingClientRect();
      const raw = (event && event.event && event.event.original) || null;
      this.selectNode(index);
      this.menu = {
        visible: true,
        x: raw ? raw.clientX - rect.left : 0,
        y: raw ? raw.clientY - rect.top : 0,
        index: index,
      };
    },

    menuRels() {
      // "Expand by shared job" is deliberately absent: it bulk-adds entities connected by
      // the edge kind with the least analytic worth, and the Jobs tab already answers
      // "what else was in this log file".
      if (this.menu.index == null) return [];
      const present = new Set();
      for (const edge of this.decoded.edges) {
        if (edge.rel && (edge.source === this.menu.index || edge.target === this.menu.index)) present.add(edge.rel);
      }
      return Array.from(present)
        .sort()
        .map((r) => ({ key: r, label: schema.labels.rels[r] || r }));
    },

    isolateEgo() {
      if (this.menu.index == null) return;
      const keep = new Set([this.menu.index]);
      for (const edge of this.decoded.edges) {
        if (edge.source === this.menu.index) keep.add(edge.target);
        else if (edge.target === this.menu.index) keep.add(edge.source);
      }
      this.isolateWindow = new Set(Array.from(keep).map((i) => this.decoded.nodes[i].entityId));
      this.menu.visible = false;
      this.apply(false);
    },

    clearIsolate() {
      this.isolateWindow = null;
      this.apply(false);
    },

    copyValue() {
      const node = this.selected.node;
      if (!node) return;
      // `ltCopy` (app.js), never `navigator.clipboard` directly: the API does not exist on
      // a page served over plain HTTP, and guarding on it would make the menu item
      // silently do nothing there. The `.catch` is only to keep an already-reported
      // failure from surfacing again as an unhandled rejection.
      ltCopy(node.label).catch(() => {});
      this.menu.visible = false;
    },

    // ── Expansion ─────────────────────────────────────────────────────────

    expandSelected(relType) {
      if (!isEntity || this.selected.index == null) return;
      const node = this.decoded.nodes[this.selected.index];
      if (node) this._expandNode(node.entityId, node.label, relType || null);
      this.menu.visible = false;
    },

    _expandNode(entityId, label, relType) {
      // Builds its own query rather than calling _query() — it always asks for one hop
      // from a different entity — so it needs _jobParam() explicitly.
      const q = '?hops=1&limit=' + this.limit + '&include_allowlisted=' + (this.includeAllowlisted ? 1 : 0) + this._jobParam();
      if (this._expandAbort) this._expandAbort.abort();
      const controller = new AbortController();
      this._expandAbort = controller;
      this.error = '';
      fetch('/intel/entities/' + entityId + '/graph.json' + q, { credentials: 'same-origin', signal: controller.signal })
        .then((r) => (r.ok ? r.json() : Promise.reject(r)))
        .then((payload) => {
          const before = this.decoded.nodes.length;
          const result = this.renderer.mergeInto(payload, 'expand:' + entityId);
          let added = result.addedNodes;
          if (relType) added = this._pruneToRelType(result, relType);
          // New nodes are *placed*, not laid out: re-running the layout over everything
          // moves the whole picture, which is the exact bug this redesign argues against.
          this._placeAround(entityId, added);
          this._projection = null;
          this._typedEdgeCount = this.decoded.edges.filter((e) => e.rel).length;
          this.renderer.setEdgeLabels(this.showEdgeLabels());
          try {
            this.communityCount = Algo.communities(this.renderer.state.graph, 'community');
            this._syncCommunityAttribute();
            this.refreshPivots();
          } catch (err) {
            /* the merged graph stands; only the pivots panel degrades */
          }
          this.trail.push({ label: '+' + (this.decoded.nodes.length - before) + ' from ' + label, count: before, addedBy: 'expand:' + entityId });
          if (this.stats && payload.stats && payload.stats.truncated) {
            this.error = 'That expansion hit the server cap — some neighbours were not added.';
          } else if (this.jobId && this.decoded.nodes.length === before) {
            // Reachable under a job scope: the node was reached over a *typed* edge, which
            // is not job-filtered, so it can be present in the picture without appearing
            // in the job. "+0" with no explanation reads as a bug.
            this.error = 'That entity does not appear in job #' + this.jobId + ', so there was nothing to add.';
          }
          this.apply(true);
        })
        .catch((err) => {
          if (err && err.name === 'AbortError') return;
          // The existing graph is still valid, so `stats`/`ready` stand and the message
          // renders beside the counts rather than replacing them.
          this.error = 'Could not expand that node.';
        })
        .finally(() => {
          if (this._expandAbort === controller) this._expandAbort = null;
        });
    },

    _pruneToRelType(result, relType) {
      const keep = new Set();
      for (const edge of result.addedEdges) {
        if (edge.rel !== relType) continue;
        keep.add(edge.source);
        keep.add(edge.target);
      }
      for (const index of result.addedNodes) {
        if (keep.has(index)) continue;
        const key = String(index);
        if (this.renderer.state.graph.hasNode(key)) this.renderer.state.graph.dropNode(key);
      }
      return result.addedNodes.filter((i) => keep.has(i));
    },

    _placeAround(entityId, indices) {
      const graph = this.renderer.state.graph;
      const anchorIndex = this.decoded.nodes.findIndex((n) => n.entityId === entityId);
      const key = String(anchorIndex);
      if (anchorIndex === -1 || !graph.hasNode(key)) return;
      const cx = graph.getNodeAttribute(key, 'x') || 0;
      const cy = graph.getNodeAttribute(key, 'y') || 0;
      const radius = 90;
      indices.forEach((index, i) => {
        const nodeKey = String(index);
        if (!graph.hasNode(nodeKey)) return;
        const angle = (2 * Math.PI * i) / Math.max(1, indices.length);
        // A little deterministic jitter so two nodes at the same ring slot do not stack.
        const jitter = 1 + ((index % 7) - 3) * 0.04;
        graph.setNodeAttribute(nodeKey, 'x', cx + Math.cos(angle) * radius * jitter);
        graph.setNodeAttribute(nodeKey, 'y', cy + Math.sin(angle) * radius * jitter);
      });
    },

    undoExpansion() {
      if (this.trail.length < 2) return;
      const step = this.trail.pop();
      const keep = step.count;
      const graph = this.renderer.state.graph;
      for (let i = this.decoded.nodes.length - 1; i >= keep; i--) {
        if (graph.hasNode(String(i))) graph.dropNode(String(i));
      }
      this.decoded.nodes.length = keep;
      this.decoded.edges = this.decoded.edges.filter((e) => e.source < keep && e.target < keep);
      this._projection = null;
      this.refreshPivots();
      this.apply(true);
    },

    resetToFocal() {
      this.isolateWindow = null;
      this.clearPath();
      this.reload();
    },

    // ── Time link (case scope) ────────────────────────────────────────────

    _subscribeToTimeline() {
      // Reads the existing `timelineRange` store the events-timeline panel writes. The
      // graph never writes it back: two writers on one store diverge, which is why there is
      // no second timeline strip under the canvas.
      this._timelineKey = 'case:' + this.caseId;
      this.$watch('$store.timelineRange.ranges', () => this._fetchActive());
    },

    _fetchActive() {
      const store = this.$store.timelineRange;
      // The store holds `[fromMs, toMs]` keyed by surface ("case:3"), written by the
      // events-timeline panel.
      const range = store && store.get ? store.get(this._timelineKey) : null;
      if (!Array.isArray(range) || range.length !== 2) {
        this.timeWindow = null;
        this.timeState = { active: false, usable: false, jobs: 0, withoutIndex: 0, legacy: 0 };
        this.apply(false);
        return;
      }
      if (this._activeAbort) this._activeAbort.abort();
      const controller = new AbortController();
      this._activeAbort = controller;
      fetch(this.activeUrl + '?frm=' + Math.round(range[0]) + '&to=' + Math.round(range[1]), {
        credentials: 'same-origin',
        signal: controller.signal,
      })
        .then((r) => (r.ok ? r.json() : Promise.reject(r)))
        .then((data) => {
          // `index_missing` means there is nothing to brush *at all* — no job in the case
          // has a marker index. Applying an empty lens there would dim the whole canvas and
          // report "0 matches", which reads as "nothing happened in this window". It did
          // not: we simply cannot say. No lens, and the chip explains why.
          const usable = !data.index_missing;
          this.timeWindow = usable ? new Set(data.entity_ids || []) : null;
          this.timeState = {
            active: true,
            usable: usable,
            jobs: data.jobs || 0,
            withoutIndex: data.jobs_without_index || 0,
            legacy: data.jobs_without_finding_ids || 0,
            from: range[0],
            to: range[1],
          };
          this.apply(false);
        })
        .catch((err) => {
          if (err && err.name === 'AbortError') return;
          this.error = 'Could not read the active window.';
        })
        .finally(() => {
          if (this._activeAbort === controller) this._activeAbort = null;
        });
    },

    clearTimeWindow() {
      this.timeWindow = null;
      this.timeState = { active: false, usable: false, jobs: 0, withoutIndex: 0, legacy: 0 };
      this.apply(false);
    },

    formatRange() {
      if (!this.timeState.active) return '';
      const f = new Date(this.timeState.from);
      const t = new Date(this.timeState.to);
      return f.toISOString().slice(0, 16).replace('T', ' ') + ' → ' + t.toISOString().slice(0, 16).replace('T', ' ');
    },

    // ── Camera ────────────────────────────────────────────────────────────

    // Each of these guards `renderer` the way `exportPng` already does, and for a reason
    // that is not defensive padding: `init()` bare-returns after setting `fatal` when the
    // graph libraries fail to load, so `renderer` stays null — while `webgl` is still its
    // initial `true`, which is the flag the overlay is shown under (`_entity_graph.html`
    // and `_case_graph.html` both `x-show="webgl"`). The camera buttons are therefore on
    // screen and clickable in exactly the state where there is nothing to drive.
    zoomIn() {
      if (!this.renderer) return;
      this.renderer.zoom(0.75);
    },
    zoomOut() {
      if (!this.renderer) return;
      this.renderer.zoom(1.35);
    },
    fitToView() {
      if (!this.renderer) return;
      this.renderer.fit(true);
    },
    recenter() {
      if (!this.renderer) return;
      const key = this._focalKey();
      if (key !== null) this.renderer.centerOn(parseInt(key, 10), 0.4);
      else this.renderer.fit(true);
    },
    toggleLock() {
      if (!this.renderer) return;
      this.locked = !this.locked;
      this.renderer.setInteractive(!this.locked);
    },

    // ── Banner predicates (shared with _graph_stats.html) ──────────────────

    nodesCapped() {
      return !!(this.stats && String(this.stats.truncated_reason || '').includes('nodes'));
    },
    edgesCapped() {
      return !!(this.stats && String(this.stats.truncated_reason || '').includes('edges'));
    },
    nodeTotalKnown() {
      // `total_nodes` is `int | null`: the entity traversal never learns the true node
      // total, so it emits null rather than mirroring the emitted count and calling it a
      // total. A node cap there can only be reported as a budget, not a ratio.
      return this.stats != null && this.stats.total_nodes !== null && this.stats.total_nodes !== undefined;
    },
    totalEdgesLabel() {
      if (!this.stats) return '0';
      return this.stats.total_edges_is_floor ? this.stats.total_edges.toLocaleString() + '+' : this.stats.total_edges.toLocaleString();
    },

    // ── Export ────────────────────────────────────────────────────────────

    exportPng(scale) {
      if (!this.renderer || this.exporting || !this.webgl) return;
      // A Canvas2D re-render rather than reading the WebGL buffer: `preserveDrawingBuffer`
      // costs every frame for the sake of an occasional screenshot, and without it a
      // `toDataURL` on the live context returns blank. It also consumes the same decision
      // map the renderer does, so the export reproduces exactly what is filtered on screen.
      this.exporting = true;
      requestAnimationFrame(() => {
        try {
          // The *export* graph, not the render graph: `graphology-canvas` resolves each
          // element's renderer by `attr.type` and ours carry Sigma's names.
          const graph = this.renderer.buildExportGraph();
          if (!graph) {
            this.error = 'PNG export is unavailable in this browser — use the GraphML download.';
            return;
          }
          const canvas = document.createElement('canvas');
          canvas.width = this.$refs.graph.clientWidth * scale;
          canvas.height = this.$refs.graph.clientHeight * scale;
          const ctx = canvas.getContext('2d');
          ctx.fillStyle = schema.colors.ui.bg;
          ctx.fillRect(0, 0, canvas.width, canvas.height);
          const ok = Algo.renderToCanvas(graph, canvas, {
            width: canvas.width,
            height: canvas.height,
            nodes: { defaultColor: schema.colors.ui.label },
            edges: { defaultColor: schema.colors.kind.job },
          });
          if (!ok) {
            this.error = 'PNG export is unavailable in this browser — use the GraphML download.';
            return;
          }
          canvas.toBlob((blob) => {
            if (!blob) return;
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = this.pngPrefix + '-graph.png';
            document.body.appendChild(a);
            a.click();
            a.remove();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
          });
        } finally {
          this.exporting = false;
        }
      });
    },

    // ── WebGL-unavailable fallback ────────────────────────────────────────

    _buildFallback() {
      if (!this.decoded) return [];
      const byNode = new Map();
      for (const edge of this.decoded.edges) {
        for (const [a, b] of [
          [edge.source, edge.target],
          [edge.target, edge.source],
        ]) {
          if (!byNode.has(a)) byNode.set(a, []);
          byNode.get(a).push({ other: b, edge: edge });
        }
      }
      const focalIndex = this.decoded.nodes.findIndex((n) => View.hasFlag(n, schema, 'focal'));
      const seed = focalIndex === -1 ? Array.from(byNode.keys()) : [focalIndex];
      const rows = [];
      for (const index of seed) {
        for (const link of byNode.get(index) || []) {
          const node = this.decoded.nodes[link.other];
          if (!node) continue;
          rows.push({
            entityId: node.entityId,
            label: node.label,
            type: schema.labels.types[node.type] || node.type,
            relation: link.edge.rel ? schema.labels.rels[link.edge.rel] : schema.labels.kinds[link.edge.kind],
            weight: link.edge.weight,
            jobCount: node.jobCount,
          });
        }
      }
      rows.sort((a, b) => b.weight - a.weight || a.label.localeCompare(b.label));
      return rows.slice(0, 200);
    },
  };
}
