// Explore: the job page's Explore pane (app/templates/partials/_explore.html).
//
// Loaded BEFORE alpine.min.js, like every factory Alpine evaluates at start (CLAUDE.md,
// "Alpine: two rules"). Two factories:
//
//   exploreView(cfg)       — the pane: columns, sort, the drawer, terms added from facets and
//                            the drawer, and the keyboard (j/k move, Enter opens, Esc closes,
//                            / focuses the search box).
//   exploreHistogram(cfg)  — the canvas: events above the axis, detected events below,
//                            sqrt-scaled; drag across it to zoom into a time range.
//
// The search form owns the state. Every control writes a hidden field imperatively and then
// submits — never through an Alpine binding, which htmx would race when it serializes the
// form (Alpine/htmx rule 4). Values from the log arrive in data-* attributes only.
//
// `window.ltExplore` holds the pure parts (bar layout, brush → time range) so
// tests/js/explore.test.mjs can run them without a browser.
(function () {
  'use strict';

  function exploreForm() {
    return document.getElementById('explore-form');
  }

  function submitExplore() {
    const form = exploreForm();
    if (form) form.requestSubmit();
  }

  function setUrlParam(name, value) {
    try {
      const url = new URL(window.location.href);
      if (value === null || value === undefined || value === '') url.searchParams.delete(name);
      else url.searchParams.set(name, String(value));
      window.history.replaceState(window.history.state, '', url.toString());
    } catch (_err) {
      // A sandboxed or file: page; the address bar is a convenience here.
    }
  }

  // ── pure ────────────────────────────────────────────────────────────────

  /** Bars for *counts* (above the axis) and *detected* (below), in canvas pixels. */
  function layout(counts, detected, width, height) {
    const n = counts.length;
    if (!n || width <= 0 || height <= 0) return { axis: 0, bars: [] };
    const axis = Math.round(height * 0.7);
    const below = height - axis - 1;
    const maxUp = Math.sqrt(Math.max(1, ...counts));
    const maxDown = Math.sqrt(Math.max(1, ...detected));
    const step = width / n;
    const gap = step > 4 ? 1 : 0;
    const bars = [];
    for (let i = 0; i < n; i++) {
      const x = i * step;
      const w = Math.max(1, step - gap);
      const up = counts[i] ? Math.max(1, Math.round((Math.sqrt(counts[i]) / maxUp) * (axis - 2))) : 0;
      const down = detected[i] ? Math.max(1, Math.round((Math.sqrt(detected[i]) / maxDown) * below)) : 0;
      bars.push({ i, x, w, up, down });
    }
    return { axis, bars };
  }

  /** The [from, to) ISO range a drag from x0 to x1 covers, snapped to whole bars. */
  function brushRange(x0, x1, width, originIso, bucketSeconds, bins) {
    if (!bins || width <= 0) return null;
    const lo = Math.max(0, Math.min(x0, x1));
    const hi = Math.min(width, Math.max(x0, x1));
    const first = Math.max(0, Math.floor((lo / width) * bins));
    const last = Math.min(bins - 1, Math.max(first, Math.ceil((hi / width) * bins) - 1));
    const origin = Date.parse(originIso.endsWith('Z') ? originIso : `${originIso}Z`);
    if (Number.isNaN(origin)) return null;
    const iso = (ms) => new Date(ms).toISOString().replace('.000Z', '').replace('Z', '');
    return { from: iso(origin + first * bucketSeconds * 1000), to: iso(origin + (last + 1) * bucketSeconds * 1000) };
  }

  function bucketLabel(seconds) {
    const units = [[86400 * 365, 'year'], [86400 * 7, 'week'], [86400, 'day'], [3600, 'hour'], [60, 'minute'], [1, 'second']];
    for (const [size, name] of units) {
      if (seconds >= size && seconds % size === 0) {
        const n = seconds / size;
        return `${n} ${name}${n === 1 ? '' : 's'}`;
      }
    }
    return `${seconds} s`;
  }

  window.ltExplore = { layout, brushRange, bucketLabel };

  // ── the pane ────────────────────────────────────────────────────────────

  window.exploreView = function (cfg) {
    return {
      selected: null,
      drawerOpen: false,

      init() {
        if (cfg.ev !== null && cfg.ev !== undefined) this.open(cfg.ev);
        // The results route reports the query it ran; a filter-row cell rewrote it, so the
        // search box must show it.
        this._onResults = (event) => {
          const detail = event.detail || {};
          const box = document.getElementById('explore-q');
          if (box && typeof detail.q === 'string' && box.value !== detail.q) box.value = detail.q;
          this.selected = null;
        };
        document.body.addEventListener('exploreResults', this._onResults);
      },

      destroy() {
        document.body.removeEventListener('exploreResults', this._onResults);
      },

      submit: submitExplore,

      addTerm(term) {
        const box = document.getElementById('explore-q');
        if (!box || !term) return;
        box.value = `${box.value.trim()} ${term}`.trim();
        submitExplore();
      },

      currentColumns() {
        const raw = this.$refs.cols.value;
        return raw ? raw.split(',') : [...cfg.columns];
      },

      toggleColumn(name, on) {
        const cols = this.currentColumns().filter((c) => c !== name);
        if (on) cols.push(name);
        this.$refs.cols.value = cols.join(',');
        submitExplore();
      },

      sortBy(name) {
        const sort = this.$refs.sort;
        const dir = this.$refs.dir;
        if (sort.value !== name) {
          sort.value = name;
          dir.value = '';
        } else if (dir.value !== 'desc') {
          dir.value = 'desc';
        } else {
          sort.value = '';
          dir.value = '';
        }
        submitExplore();
      },

      around(data) {
        const box = document.getElementById('explore-q');
        if (box) box.value = data.term || '';
        this.$refs.from.value = data.from || '';
        this.$refs.to.value = data.to || '';
        this.closeDrawer();
        submitExplore();
      },

      open(uid) {
        this.selected = Number(uid);
        this.drawerOpen = true;
        setUrlParam('ev', uid);
        window.htmx.ajax('GET', `${cfg.base}/event?uid=${encodeURIComponent(uid)}`, { target: '#explore-drawer', swap: 'innerHTML' });
      },

      closeDrawer() {
        const drawer = document.getElementById('explore-drawer');
        if (drawer) drawer.innerHTML = '';
        this.drawerOpen = false;
        setUrlParam('ev', null);
      },

      rows() {
        return Array.from(document.querySelectorAll('#explore-results tbody tr[data-uid]'));
      },

      move(delta) {
        const rows = this.rows();
        if (!rows.length) return;
        const at = rows.findIndex((r) => Number(r.dataset.uid) === this.selected);
        const next = rows[at < 0 ? 0 : Math.max(0, Math.min(rows.length - 1, at + delta))];
        this.selected = Number(next.dataset.uid);
        next.scrollIntoView({ block: 'nearest' });
        if (this.drawerOpen) this.open(this.selected);
      },

      onKey(event) {
        // A hidden tab keeps its window listener: only the visible pane takes keys.
        if (!this.$el.offsetParent) return;
        if (event.key === 'Escape' && this.drawerOpen) {
          this.closeDrawer();
          return;
        }
        if (window.ltKeyStandsDown(event, document)) return;
        if (event.key === '/') {
          event.preventDefault();
          const box = document.getElementById('explore-q');
          if (box) box.focus();
        } else if (event.key === 'j' || event.key === 'k') {
          event.preventDefault();
          this.move(event.key === 'j' ? 1 : -1);
        } else if (event.key === 'Enter' && this.selected !== null && !this.drawerOpen) {
          event.preventDefault();
          this.open(this.selected);
        }
      },
    };
  };

  // ── the histogram ───────────────────────────────────────────────────────

  window.exploreHistogram = function (cfg) {
    return {
      colors: cfg.colors,
      label: 'Loading…',
      zoomed: false,
      data: null,
      drag: null,

      init() {
        const form = exploreForm();
        this.zoomed = !!(form && (form.elements.from.value || form.elements.to.value));
        this.load(cfg.qs);
        this._onResults = (event) => {
          const f = exploreForm();
          this.zoomed = !!(f && (f.elements.from.value || f.elements.to.value));
          this.load((event.detail || {}).qs || '');
        };
        document.body.addEventListener('exploreResults', this._onResults);
        const canvas = this.$refs.canvas;
        this._resize = new ResizeObserver(() => this.draw());
        this._resize.observe(canvas);
        canvas.addEventListener('pointerdown', (e) => this.down(e));
        canvas.addEventListener('pointermove', (e) => this.moveTo(e));
        canvas.addEventListener('pointerup', (e) => this.up(e));
      },

      destroy() {
        document.body.removeEventListener('exploreResults', this._onResults);
        if (this._resize) this._resize.disconnect();
      },

      async load(qs) {
        const width = Math.max(100, Math.round(this.$refs.canvas.clientWidth || 800));
        const sep = qs ? '&' : '';
        try {
          const res = await fetch(`${cfg.url}?${qs}${sep}width=${width}`, { credentials: 'same-origin' });
          this.data = await res.json();
        } catch (_err) {
          this.data = { error: 'The chart could not be loaded.' };
        }
        if (this.data.busy) {
          setTimeout(() => this.load(qs), 2000);
          return;
        }
        this.label = this.data.error
          ? this.data.error
          : this.data.origin
            ? `${this.data.origin.replace('T', ' ')} to ${this.data.end.replace('T', ' ')} UTC · ${bucketLabel(this.data.bucket_seconds)} per bar`
            : 'No dated events';
        this.draw();
      },

      x(event) {
        const rect = this.$refs.canvas.getBoundingClientRect();
        return Math.max(0, Math.min(rect.width, event.clientX - rect.left));
      },

      down(event) {
        if (!this.data || !this.data.counts || !this.data.counts.length) return;
        this.drag = { x0: this.x(event), x1: this.x(event) };
        this.$refs.canvas.setPointerCapture(event.pointerId);
      },

      moveTo(event) {
        if (!this.drag) return;
        this.drag.x1 = this.x(event);
        this.draw();
      },

      up(event) {
        if (!this.drag) return;
        const { x0 } = this.drag;
        const x1 = this.x(event);
        this.drag = null;
        if (Math.abs(x1 - x0) < 4) {
          this.draw();
          return;
        }
        const width = this.$refs.canvas.getBoundingClientRect().width;
        const range = brushRange(x0, x1, width, this.data.origin, this.data.bucket_seconds, this.data.counts.length);
        const form = exploreForm();
        if (!range || !form) return;
        form.elements.from.value = range.from;
        form.elements.to.value = range.to;
        submitExplore();
      },

      resetZoom() {
        const form = exploreForm();
        if (!form) return;
        form.elements.from.value = '';
        form.elements.to.value = '';
        submitExplore();
      },

      draw() {
        const canvas = this.$refs.canvas;
        const ratio = window.devicePixelRatio || 1;
        const width = canvas.clientWidth;
        const height = canvas.clientHeight;
        if (!width || !height) return;
        canvas.width = Math.round(width * ratio);
        canvas.height = Math.round(height * ratio);
        const ctx = canvas.getContext('2d');
        ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
        ctx.clearRect(0, 0, width, height);
        if (!this.data || !this.data.counts) return;
        const { axis, bars } = layout(this.data.counts, this.data.detected || [], width, height);
        ctx.fillStyle = this.colors.events;
        for (const b of bars) if (b.up) ctx.fillRect(b.x, axis - b.up, b.w, b.up);
        ctx.fillStyle = this.colors.detected;
        for (const b of bars) if (b.down) ctx.fillRect(b.x, axis + 1, b.w, b.down);
        if (this.drag) {
          ctx.fillStyle = this.colors.brush;
          ctx.fillRect(Math.min(this.drag.x0, this.drag.x1), 0, Math.abs(this.drag.x1 - this.drag.x0), height);
        }
      },
    };
  };
})();
