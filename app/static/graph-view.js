// Relationship graph — the pure half. No DOM, no Sigma, no graphology, no fetch.
//
// Everything here is a function of (payload, view state) -> data. That is what makes the
// central property possible: **emphasis never moves a node**. Setting `display:none` on
// filtered nodes and re-running the layout over the survivors would make unticking "Hash"
// rearrange the entire picture and destroy whatever mental map the analyst had built.
// Here, filtering produces a decision Map that the renderer's reducers read per frame;
// positions live in the graph and are untouched.
//
// Also home to `mergePayload`, because a columnar payload cannot be concatenated: `e.s`/
// `e.t` are per-payload node *indices* and `dict.tags` is a per-payload dictionary, so
// merging an expansion means remapping both index spaces against the live graph. That
// remap is the part progressive expansion gets subtly wrong (duplicate entities, dangling
// edges, tag collisions), so it lives here where `tests/js/graph-merge.test.mjs` can reach
// it.
//
// Loaded as a classic script before alpine.min.js; exposes one namespace on `window`.

(function () {
  'use strict';

  // Emphasis levels, weakest to strongest. Ordering is load-bearing: an edge is never
  // brighter than its dimmest endpoint, which is `Math.min` over these.
  const HIDDEN = -1;
  const MUTED = 0;
  const NORMAL = 1;
  const MATCH = 2;
  const FOCUS = 3;

  // Forcing a label bypasses labelRenderedSizeThreshold / labelDensity / labelGridCellSize
  // — the three settings that bound label cost. `attr:machine` matching 3,000 nodes would
  // otherwise force-draw 3,000 labels every frame. Labels are forced for overlay and
  // selection only, and even then capped.
  const MAX_FORCED_LABELS = 150;

  // ── Decoding ────────────────────────────────────────────────────────────

  // A decoded node. Flat, mutable, and keyed the way the reducers want to read it — the
  // columnar format is a wire format, not a working representation.
  function decodePayload(payload, schema) {
    const n = (payload && payload.n) || {};
    const e = (payload && payload.e) || {};
    const ids = n.id || [];
    const words = ((payload && payload.dict) || {}).tags || [];
    const tagsByIndex = new Map();
    for (const row of n.tg || []) {
      tagsByIndex.set(row[0], row.slice(1).map((i) => words[i]).filter(Boolean));
    }
    const casesByIndex = new Map();
    for (const row of n.ca || []) casesByIndex.set(row[0], row.slice(1));
    const matched = new Set(n.mt || []);

    const nodes = [];
    for (let i = 0; i < ids.length; i++) {
      nodes.push({
        entityId: ids[i],
        label: (n.lb || [])[i] || '',
        type: schema.types[(n.ty || [])[i]] || '',
        subtype: (n.sub || [])[i] ? schema.subtypes[n.sub[i] - 1] : null,
        flags: (n.fl || [])[i] || 0,
        jobCount: (n.jc || [])[i] || 0,
        severity: (n.sv || [])[i] ? schema.severities[n.sv[i] - 1] : null,
        tactic: (n.tc || [])[i] ? schema.tactics[n.tc[i] - 1] : null,
        verdict: schema.verdicts[(n.en || [])[i] || 0] || 'none',
        tags: tagsByIndex.get(i) || [],
        cases: casesByIndex.get(i) || [],
        matched: matched.has(i),
      });
    }

    const base = schema.typed_base;
    const edges = [];
    const s = e.s || [];
    for (let i = 0; i < s.length; i++) {
      const code = (e.k || [])[i];
      const rel = code >= base ? schema.rels[code - base] : null;
      edges.push({
        source: s[i],
        target: (e.t || [])[i],
        kind: rel ? 'typed' : schema.edge_kinds[code] || 'job',
        rel: rel,
        weight: (e.w || [])[i] || 1,
        // `EntityRelationship.id`, so the edge panel can fetch its observed window without
        // a lookup endpoint keyed on (source, target, type).
        relId: (e.rid || [])[i] || 0,
      });
    }

    return {
      nodes: nodes,
      edges: edges,
      scope: (payload && payload.scope) || 'entity',
      focal: payload ? payload.focal : null,
      stats: (payload && payload.stats) || null,
      hiddenTypes: (((payload && payload.defaults) || {}).hidden_types) || [],
      hiddenKinds: (((payload && payload.defaults) || {}).hidden_kinds) || [],
      matchesPartial: !!n.mt_partial,
      hasTags: 'tg' in n,
    };
  }

  // Edge keys are derived from node indices, so they are unique by construction and a
  // parallel typed edge between the same pair keeps its own identity.
  function edgeKey(edge) {
    const tag = edge.rel ? 't:' + edge.rel : edge.kind[0];
    return tag + ':' + edge.source + ':' + edge.target;
  }

  function hasFlag(node, schema, name) {
    const bit = schema.flags[name];
    return !!bit && (node.flags & bit) !== 0;
  }

  // ── Query engine (client-side half of the shared grammar) ───────────────
  //
  // A port of app/intel/queries.py's *term semantics*, not its SQL. `literal`, `wildcard`,
  // `attr:`/`label:`, `tag:`, `type:` and `cidr:` all evaluate here against decoded node
  // attributes: instantly, with no network, which is the whole point of a filter on a graph
  // you are already looking at. `re:/…/` is the one kind that round-trips — a JS RegExp has
  // no timeout, and the nested-quantifier pre-check catches accidents but not a
  // deliberately catastrophic pattern, so the server evaluates it under a wall-clock budget
  // and ships the answer back as `n.mt`.
  //
  // The *parse* is deliberately a faithful port so both surfaces agree on what a query
  // means. The engines still differ (Python `regex` vs `RegExp`), so a regex error is shown
  // verbatim from the server rather than reproduced here.

  const PREFIXES = ['label:', 'tag:', 'attr:', 'list:', 'cidr:', 're:/', 'job:', 'type:'];
  const TYPE_ALIASES = { ip: 'ip_address', ips: 'ip_address', exe: 'executable', cmdline: 'cmdline_file' };
  const ATTR_ALIASES = { suspicious: 'suspicious_tld', machine_account: 'machine', priv: 'privileged' };
  const MAX_TERMS = 12;
  // Mirrors queries.MAX_INSET_VALUES. Past it the editor offers to promote the set to a
  // real list, which is versioned, described and reusable — none of which a literal in one
  // condition is.
  const MAX_INSET_VALUES = 20;

  function scanQuery(raw) {
    // Mirrors queries.scan_query(split_groups=True): quoted runs keep their spaces, a
    // `re:/…/` keeps its own (a pattern may legitimately contain one), and parentheses
    // become their own tokens only after those two passes.
    const spans = [];
    let i = 0;
    const n = raw.length;
    while (i < n) {
      if (/\s/.test(raw[i])) { i++; continue; }
      if (raw[i] === '(' || raw[i] === ')') { spans.push(raw[i]); i++; continue; }
      const quoteAt = raw[i] === '-' && raw[i + 1] === '"' ? i + 1 : (raw[i] === '"' ? i : -1);
      if (quoteAt !== -1) {
        const neg = quoteAt !== i ? '-' : '';
        const j = raw.indexOf('"', quoteAt + 1);
        if (j === -1) { spans.push(neg + raw.slice(quoteAt + 1)); break; }
        spans.push(neg + raw.slice(quoteAt + 1, j));
        i = j + 1;
        continue;
      }
      const rest = raw.slice(i);
      const neg = rest.startsWith('-');
      const probe = neg ? rest.slice(1) : rest;
      if (probe.toLowerCase().startsWith('in:(')) {
        // One token, parens and all — the same pass the server's scanner has, and for the
        // same reason: the walk below ends a term at a parenthesis, which would shred one
        // valid set into junk and feed its '(' to the grouping rules.
        const close = raw.indexOf(')', i);
        const end = close === -1 ? n : close + 1;
        spans.push(raw.slice(i, end));
        i = end;
        continue;
      }
      if (probe.toLowerCase().startsWith('re:/')) {
        let j = i + (neg ? 1 : 0) + 4;
        while (j < n) {
          if (raw[j] === '\\') { j += 2; continue; }
          if (raw[j] === '/') break;
          j++;
        }
        const end = Math.min(j + 1, n);
        spans.push(raw.slice(i, end));
        i = end;
        continue;
      }
      let j = i;
      while (j < n && !/\s/.test(raw[j]) && raw[j] !== '(' && raw[j] !== ')') j++;
      spans.push(raw.slice(i, j));
      i = j;
    }
    return spans;
  }

  function isStructured(raw) {
    // A bare leading `-` deliberately does NOT count: `powershell -enc payload` is a real
    // phrase where `-enc` is part of the search, not a negation. Same rule as the server.
    if (raw.indexOf('"') !== -1) return true;
    return raw.split(/\s+/).some((tok) => {
      const body = tok.startsWith('-') ? tok.slice(1) : tok;
      return PREFIXES.some((p) => body.toLowerCase().startsWith(p));
    });
  }

  function isBoolean(raw) {
    const toks = scanQuery(raw);
    if (toks.some((t) => t === 'OR' || t === 'AND')) return true;
    return (toks.indexOf('(') !== -1 || toks.indexOf(')') !== -1) && isStructured(raw);
  }

  function escapeRegExp(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function parseTerm(raw, schema) {
    raw = (raw || '').trim();
    if (!raw) return { kind: 'literal', value: '' };
    const lowered = raw.toLowerCase();

    const tagsOf = (s) =>
      s.split(',').map((t) => t.trim().toLowerCase().slice(0, 50)).filter(Boolean).slice(0, 10);

    if (lowered.startsWith('label:')) {
      // One token, two sources — resolved syntactically exactly as the server does: a key
      // the attribute registry knows is a system label, anything else is an analyst tag.
      const key = normaliseAttr(raw.slice(6).trim().toLowerCase());
      if (isKnownAttr(key, schema)) return { kind: 'attr', key: key };
      const tags = tagsOf(raw.slice(6));
      return tags.length ? { kind: 'tag', tags: tags } : { kind: 'literal', value: raw, error: 'label: needs a value' };
    }
    if (lowered.startsWith('tag:')) {
      const tags = tagsOf(raw.slice(4));
      return tags.length ? { kind: 'tag', tags: tags } : { kind: 'literal', value: raw, error: 'tag: needs a value' };
    }
    if (lowered.startsWith('attr:')) {
      const key = normaliseAttr(raw.slice(5).trim().toLowerCase());
      return isKnownAttr(key, schema) ? { kind: 'attr', key: key } : { kind: 'literal', value: raw, error: 'unknown attr: ' + key };
    }
    if (lowered.startsWith('type:')) {
      const wanted = raw
        .slice(5)
        .split(',')
        .map((p) => p.trim().toLowerCase())
        .map((p) => TYPE_ALIASES[p] || p)
        .filter(Boolean);
      const unknown = wanted.filter((t) => schema.types.indexOf(t) === -1);
      if (!wanted.length) return { kind: 'literal', value: raw, error: 'type: needs an entity type' };
      if (unknown.length) return { kind: 'literal', value: raw, error: 'unknown type: ' + unknown[0] };
      return { kind: 'type', types: wanted };
    }
    if (lowered.startsWith('cidr:')) {
      // Any-of over a comma list, the `tag:a,b` idiom; one bad network fails the term.
      const nets = raw.slice(5).split(',').map((s) => s.trim()).filter(Boolean).map(parseCidr);
      return nets.length && nets.every(Boolean) ? { kind: 'cidr', networks: nets } : { kind: 'literal', value: raw, error: 'invalid CIDR' };
    }
    if (lowered.startsWith('in:')) {
      // Unlike `list:` below, this one is answered *here*: the values are in the term, so a
      // round trip would buy nothing. The server keeps its own copy in `match_entity_rows`
      // anyway, because a query mixing `in:` with `re:` is evaluated there as a whole and
      // would otherwise come back a superset.
      const body = raw.slice(3);
      if (!(body.startsWith('(') && body.endsWith(')'))) {
        return { kind: 'literal', value: raw, error: 'in: needs a parenthesised set, as in:(a,b,c)' };
      }
      const seen = [];
      for (const part of body.slice(1, -1).split(',')) {
        const v = part.trim().toLowerCase();
        if (v && seen.indexOf(v) === -1) seen.push(v);
      }
      if (!seen.length) return { kind: 'literal', value: raw, error: 'in: needs at least one value' };
      if (seen.length > MAX_INSET_VALUES) {
        return { kind: 'literal', value: raw, error: 'in: takes at most ' + MAX_INSET_VALUES + ' values — make it a list instead' };
      }
      return { kind: 'inset', values: seen };
    }
    if (lowered.startsWith('job:') || lowered.startsWith('list:')) {
      // Neither is on the wire. Job membership: narrowing a graph to one job is a
      // different question, and answering it here would mean shipping every node's job
      // set. Named lists: they live in the server's config, and a round trip costs less
      // than shipping a hundred and sixty names with every payload.
      return { kind: 'server', value: raw };
    }
    if (lowered.startsWith('re:/') && raw.endsWith('/') && raw.length > 5) {
      return { kind: 'regex', value: raw };
    }
    if (raw.indexOf('*') !== -1) {
      const body = raw.split('*').map(escapeRegExp).join('.*');
      return { kind: 'wildcard', re: new RegExp(body, 'i') };
    }
    return { kind: 'literal', value: raw.toLowerCase() };
  }

  function normaliseAttr(key) {
    return ATTR_ALIASES[key] || key;
  }

  function isKnownAttr(key, schema) {
    return schema.attr_flags.indexOf(key) !== -1 || schema.subtypes.indexOf(key) !== -1;
  }

  function parseQuery(raw, schema) {
    raw = (raw || '').trim();
    if (!raw) return { raw: '', terms: [], tree: null, errors: [], needsServer: false };

    const errors = [];
    const leaves = [];
    const mk = (tok) => {
      const negated = tok.startsWith('-') && tok.length > 1;
      const term = parseTerm(negated ? tok.slice(1) : tok, schema);
      term.negated = negated;
      if (term.error) errors.push(term.error);
      leaves.push(term);
      return term;
    };

    let tree = null;
    if (isBoolean(raw)) {
      const toks = scanQuery(raw);
      let i = 0;
      const peek = () => (i < toks.length ? toks[i] : null);
      const parseOr = (depth) => {
        const nodes = [parseAnd(depth)];
        while (peek() === 'OR') { i++; nodes.push(parseAnd(depth)); }
        const kept = nodes.filter(Boolean);
        if (!kept.length) return null;
        return kept.length === 1 ? kept[0] : { op: 'or', nodes: kept };
      };
      const parseAnd = (depth) => {
        const nodes = [];
        for (;;) {
          const tok = peek();
          if (tok === null || tok === 'OR' || tok === ')') break;
          if (tok === 'AND') { i++; continue; }
          const node = parseUnary(depth);
          if (node) nodes.push(node);
        }
        if (!nodes.length) return null;
        return nodes.length === 1 ? nodes[0] : { op: 'and', nodes: nodes };
      };
      const parseUnary = (depth) => {
        const tok = peek();
        if (tok === null) return null;
        if (tok === '(') {
          if (depth >= 8) { errors.push('groups nested deeper than 8 were ignored'); i++; return null; }
          i++;
          const inner = parseOr(depth + 1);
          if (peek() === ')') i++;
          else errors.push("unbalanced '(' in query");
          return inner;
        }
        i++;
        if (leaves.length >= MAX_TERMS) {
          if (!errors.some((e) => e.indexOf('only the first') === 0)) errors.push('only the first ' + MAX_TERMS + ' terms were applied');
          return null;
        }
        return mk(tok);
      };
      tree = parseOr(0);
    } else if (!isStructured(raw)) {
      // Phrase-mode back-compat, same as the server: an unstructured query is one literal
      // term, so a saved multi-word search keeps matching what it always matched.
      mk(raw);
    } else {
      for (const tok of scanQuery(raw)) {
        if (leaves.length >= MAX_TERMS) { errors.push('only the first ' + MAX_TERMS + ' terms were applied'); break; }
        if (tok === '(' || tok === ')') continue;
        mk(tok);
      }
    }

    return {
      raw: raw,
      terms: leaves,
      tree: tree,
      errors: errors,
      // `re:`, `list:` and `job:` cannot be answered locally; the component refetches for those.
      needsServer: leaves.some((t) => t.kind === 'regex' || t.kind === 'server'),
    };
  }

  function parseCidr(spec) {
    const slash = spec.lastIndexOf('/');
    if (slash === -1) return null;
    const addr = spec.slice(0, slash);
    const bits = parseInt(spec.slice(slash + 1), 10);
    if (!isFinite(bits) || bits < 0) return null;
    if (addr.indexOf(':') !== -1) {
      const words = expandV6(addr);
      return words && bits <= 128 ? { v: 6, words: words, bits: bits } : null;
    }
    const octets = addr.split('.').map((o) => parseInt(o, 10));
    if (octets.length !== 4 || octets.some((o) => !isFinite(o) || o < 0 || o > 255) || bits > 32) return null;
    return { v: 4, value: ((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3], bits: bits };
  }

  function expandV6(addr) {
    const halves = addr.split('::');
    if (halves.length > 2) return null;
    const head = halves[0] ? halves[0].split(':') : [];
    const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
    const fill = 8 - head.length - tail.length;
    if (halves.length === 1 && head.length !== 8) return null;
    if (fill < 0) return null;
    const parts = halves.length === 2 ? head.concat(new Array(fill).fill('0'), tail) : head;
    const words = parts.map((p) => parseInt(p || '0', 16));
    return words.length === 8 && words.every((w) => isFinite(w) && w >= 0 && w <= 0xffff) ? words : null;
  }

  function inCidr(value, net) {
    if (net.v === 4) {
      const octets = value.split('.').map((o) => parseInt(o, 10));
      if (octets.length !== 4 || octets.some((o) => !isFinite(o) || o < 0 || o > 255)) return false;
      const ip = ((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3];
      if (net.bits === 0) return true;
      const mask = net.bits === 32 ? 0xffffffff : (0xffffffff << (32 - net.bits)) >>> 0;
      return ((ip & mask) >>> 0) === ((net.value & mask) >>> 0);
    }
    const words = expandV6(value);
    if (!words) return false;
    let left = net.bits;
    for (let i = 0; i < 8 && left > 0; i++) {
      const take = Math.min(16, left);
      const mask = take === 16 ? 0xffff : (0xffff << (16 - take)) & 0xffff;
      if ((words[i] & mask) !== (net.words[i] & mask)) return false;
      left -= take;
    }
    return true;
  }

  function termMatches(term, node, schema) {
    let hit;
    switch (term.kind) {
      case 'literal':
        hit = !term.value || node.label.toLowerCase().indexOf(term.value) !== -1;
        break;
      case 'wildcard':
        hit = term.re.test(node.label);
        break;
      case 'attr':
        hit = node.subtype === term.key || hasFlag(node, schema, term.key);
        break;
      case 'tag':
        hit = term.tags.some((t) => node.tags.indexOf(t) !== -1);
        break;
      case 'type':
        hit = term.types.indexOf(node.type) !== -1;
        break;
      case 'cidr':
        hit = node.type === 'ip_address' && term.networks.some((net) => inCidr(node.label, net));
        break;
      case 'inset':
        // Whole value, not substring — `in:` is the anonymous form of a `list:` at its
        // default match kind, and `notpsexec.exe` must not answer `in:(psexec.exe)`.
        hit = term.values.indexOf(node.label.toLowerCase()) !== -1;
        break;
      case 'regex':
      case 'server':
        // Answered by the server; `node.matched` carries the verdict for the whole
        // server-evaluated half of the query, each term's own negation already applied
        // (`match_entity_rows`). Negating it again here inverted `-re:` into its complement.
        return node.matched;
      default:
        hit = true;
    }
    return term.negated ? !hit : hit;
  }

  function treeMatches(node, entity, schema) {
    if (!node) return true;
    if (!node.op) return termMatches(node, entity, schema);
    return node.op === 'or'
      ? node.nodes.some((c) => treeMatches(c, entity, schema))
      : node.nodes.every((c) => treeMatches(c, entity, schema));
  }

  function queryMatches(query, node, schema) {
    if (!query || (!query.terms.length && !query.tree)) return true;
    if (query.tree) return treeMatches(query.tree, node, schema);
    return query.terms.every((t) => termMatches(t, node, schema));
  }

  // ── Emphasis stack ──────────────────────────────────────────────────────
  //
  // Three layers with explicit precedence, arbitrated in one place so no control can
  // quietly reinterpret another:
  //
  //   0. Structural exclusion ALWAYS hides. Unticking "Hash" removes hashes, full stop —
  //      the semantics of display:none, minus the relayout.
  //   1. Lenses INTERSECT (query, severity floor, time window, community, isolate ego).
  //   2. Overlays UNION and only ever PROMOTE (hover ego, pinned path).
  //
  // Two properties a naive implementation gets wrong, both pinned by tests/js:
  //   * a HIDDEN node stays HIDDEN under an overlay — hovering must not repopulate a
  //     canvas the analyst deliberately emptied with dimMode:'hide';
  //   * `forceLabel` is decoupled from level, so a MATCH changes colour and size only.

  function defaultState() {
    return {
      hiddenTypes: new Set(),
      hiddenKinds: new Set(),
      hiddenRels: new Set(),
      showAllowlisted: true,
      query: null,
      severityFloor: null,
      community: null,
      activeIds: null, // time window: Set of entity ids, or null for "no window"
      isolateIds: null, // "isolate ego": Set of entity ids. Its own slot, not activeIds —
      // two lenses sharing a slot silently cancel each other, and both can be on at once.
      dimMode: 'dim', // 'dim' | 'hide'
      overlay: null, // Set of node indices
      overlayEdges: null, // Set of edge keys
      selection: null, // node index
      schema: null,
    };
  }

  function structuralPass(node, st) {
    if (st.hiddenTypes.has(node.type)) return false;
    if (!st.showAllowlisted && hasFlag(node, st.schema, 'allowlisted')) return false;
    return true;
  }

  function lensPass(node, st) {
    if (st.query && !queryMatches(st.query, node, st.schema)) return false;
    if (st.severityFloor && !severityAtLeast(node.severity, st.severityFloor, st.schema)) return false;
    if (st.community !== null && st.community !== undefined && node.community !== st.community) return false;
    if (st.activeIds && !st.activeIds.has(node.entityId)) return false;
    if (st.isolateIds && !st.isolateIds.has(node.entityId)) return false;
    return true;
  }

  function severityAtLeast(severity, floor, schema) {
    if (!severity) return false;
    const order = schema.severities;
    const a = order.indexOf(severity);
    const b = order.indexOf(floor);
    return a !== -1 && b !== -1 && a <= b;
  }

  function anyLensActive(st) {
    return (
      !!(st.query && (st.query.terms.length || st.query.tree)) ||
      !!st.severityFloor ||
      st.community != null ||
      !!st.activeIds ||
      !!st.isolateIds
    );
  }

  // Returns the level *and* the two facts it was derived from. The caller needs them apart:
  // "dimmed by your filters" must count nodes that failed a **lens**, not nodes an overlay
  // demoted. Hovering demotes everything outside the ego to MUTED, so counting MUTED made a
  // "+30 dimmed by your filters" line appear on every hover — untrue, and it pushed the
  // canvas down as it appeared and vanished.
  function nodeState(index, node, st, lensActive) {
    if (!structuralPass(node, st)) return { level: HIDDEN, structural: false, lens: false };
    const lens = lensPass(node, st);
    const base = lens ? (lensActive ? MATCH : NORMAL) : st.dimMode === 'hide' ? HIDDEN : MUTED;
    if (!st.overlay) return { level: base, structural: true, lens: lens };
    if (st.overlay.has(index)) return { level: base === HIDDEN ? HIDDEN : FOCUS, structural: true, lens: lens };
    return { level: Math.min(base, MUTED), structural: true, lens: lens };
  }

  function nodeLevel(index, node, st, lensActive) {
    return nodeState(index, node, st, lensActive).level;
  }

  function edgeLevel(edge, key, st, srcLevel, tgtLevel) {
    if (srcLevel === HIDDEN || tgtLevel === HIDDEN) return HIDDEN;
    if (st.hiddenKinds.has(edge.kind)) return HIDDEN;
    if (edge.rel && st.hiddenRels.has(edge.rel)) return HIDDEN;
    if (st.overlay) return st.overlayEdges && st.overlayEdges.has(key) ? FOCUS : MUTED;
    return Math.min(srcLevel, tgtLevel);
  }

  // One pass over the graph, materialised into Maps the reducers can `get`. Reducers run
  // for every element on every refresh() and hover triggers refreshes, so evaluating the
  // stack inside a reducer would re-derive the whole decision set 60 times a second.
  function computeDecisions(decoded, st) {
    const lensActive = anyLensActive(st);
    const nodeLevels = new Map();
    const forced = new Set();
    let visibleNodes = 0;
    let dimmedNodes = 0;
    let lensMatches = 0;
    let structuralNodes = 0;

    for (let i = 0; i < decoded.nodes.length; i++) {
      const state = nodeState(i, decoded.nodes[i], st, lensActive);
      nodeLevels.set(i, state.level);
      if (state.level > HIDDEN) visibleNodes++;
      // Lens failures only — an overlay demoting a node is a transient hover, not a filter.
      if (state.structural) structuralNodes++;
      if (state.structural && state.lens) lensMatches++;
      if (state.structural && !state.lens) dimmedNodes++;
    }

    // Labels are forced only where the analyst has actively pointed: overlay and selection.
    //
    // **The selection goes first, before the overlay.** The loop stops at
    // MAX_FORCED_LABELS, so hovering a hub with more neighbours than the cap would otherwise
    // spend the entire budget on the ego and leave the node the analyst had clicked with no
    // name.
    // The thing they picked deliberately outranks the thing they happened to point at.
    const candidates = [];
    if (st.selection != null) candidates.push(st.selection);
    if (st.overlay) for (const i of st.overlay) candidates.push(i);
    for (const i of candidates) {
      if (forced.size >= MAX_FORCED_LABELS) break;
      // `!== undefined`, not a falsy test: MUTED is 0, so `(level || HIDDEN)` evaluated to
      // HIDDEN for every muted node and `-1 > -1` is false — a MUTED node could never be
      // force-labelled. That is exactly the selected node whenever a hover overlay is
      // active elsewhere, or whenever a lens is on and the selection fails it, so the
      // label vanished from the one node the analyst was reading.
      const level = nodeLevels.get(i);
      if (level !== undefined && level > HIDDEN) forced.add(i);
    }

    const edgeLevels = new Map();
    let visibleEdges = 0;
    for (const edge of decoded.edges) {
      const key = edgeKey(edge);
      const level = edgeLevel(edge, key, st, nodeLevels.get(edge.source), nodeLevels.get(edge.target));
      edgeLevels.set(key, level);
      if (level > HIDDEN) visibleEdges++;
    }

    return {
      nodeLevels: nodeLevels,
      edgeLevels: edgeLevels,
      forced: forced,
      selection: st.selection,
      counts: {
        visibleNodes: visibleNodes,
        totalNodes: decoded.nodes.length,
        visibleEdges: visibleEdges,
        totalEdges: decoded.edges.length,
        dimmedNodes: dimmedNodes,
        lensActive: lensActive,
        // Zero matches with a lens active is the "all-grey canvas" case. It reads as a
        // crash, so the component shows a chip and leaves emphasis alone rather than
        // dimming everything. Derived from lens matches, not from `dimmedNodes ===
        // visibleNodes`: under dimMode:'hide' a lens failure is HIDDEN, so it leaves
        // `visibleNodes` as well as entering `dimmedNodes` and the two can never be equal.
        zeroMatches: lensActive && structuralNodes > 0 && lensMatches === 0,
      },
    };
  }

  // ── Payload merge (progressive expansion) ───────────────────────────────

  // Merge an incoming payload into an already-decoded one. NOT a concatenation: `e.s`/`e.t`
  // are per-payload node indices and `dict.tags` is a per-payload dictionary, so both index
  // spaces have to be remapped against the live graph first. Edge keys are recomputed from
  // the *merged* indices — carrying an incoming key over produces a duplicate-looking edge
  // that then vanishes on the next filter.
  //
  // `addedBy` is provenance, not decoration: without it a 400-node accumulated graph is
  // unreadable, because an analyst cannot tell why anything is on screen.
  function mergePayload(decoded, payload, schema, addedBy) {
    const incoming = decodePayload(payload, schema);
    const indexOf = new Map();
    for (let i = 0; i < decoded.nodes.length; i++) indexOf.set(decoded.nodes[i].entityId, i);

    const remap = new Map();
    const addedNodes = [];
    for (let i = 0; i < incoming.nodes.length; i++) {
      const node = incoming.nodes[i];
      const existing = indexOf.get(node.entityId);
      if (existing !== undefined) {
        remap.set(i, existing);
        continue;
      }
      // The focal flag belongs to the graph's own centre, not to whatever entity happened
      // to be the focus of the expansion request.
      const focalBit = schema.flags.focal || 0;
      node.flags &= ~focalBit;
      node.addedBy = addedBy || 'expand';
      const slot = decoded.nodes.length;
      decoded.nodes.push(node);
      indexOf.set(node.entityId, slot);
      remap.set(i, slot);
      addedNodes.push(slot);
    }

    const seen = new Set(decoded.edges.map(edgeKey));
    const addedEdges = [];
    for (const edge of incoming.edges) {
      const s = remap.get(edge.source);
      const t = remap.get(edge.target);
      if (s === undefined || t === undefined || s === t) continue;
      const merged = { source: s, target: t, kind: edge.kind, rel: edge.rel, weight: edge.weight, relId: edge.relId };
      const key = edgeKey(merged);
      if (seen.has(key)) continue;
      seen.add(key);
      decoded.edges.push(merged);
      addedEdges.push(merged);
    }

    return { addedNodes: addedNodes, addedEdges: addedEdges, incoming: incoming };
  }

  window.LogsTotalGraphView = {
    HIDDEN: HIDDEN,
    MUTED: MUTED,
    NORMAL: NORMAL,
    MATCH: MATCH,
    FOCUS: FOCUS,
    MAX_FORCED_LABELS: MAX_FORCED_LABELS,
    decodePayload: decodePayload,
    mergePayload: mergePayload,
    edgeKey: edgeKey,
    hasFlag: hasFlag,
    parseQuery: parseQuery,
    queryMatches: queryMatches,
    parseCidr: parseCidr,
    inCidr: inCidr,
    defaultState: defaultState,
    computeDecisions: computeDecisions,
    nodeLevel: nodeLevel,
    nodeState: nodeState,
    edgeLevel: edgeLevel,
    severityAtLeast: severityAtLeast,
  };
})();
