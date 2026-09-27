/* Events timeline — the Alpine component behind the zoomable alert markers.
 *
 * Owns fetching, debouncing, zoom→resolution and state; `timeline-canvas.js` owns drawing.
 * The split is deliberate — this file never touches a pixel and the canvas never touches
 * the network — but there is only one renderer, and the contract between them is small:
 *
 *   mount(hostEl, {onRangeChange, onItemClick, onHover})
 *   setColors(colors)  setGroupings(list)  setItems(items)
 *   setExtent(fromMs, toMs)  getRange()  setRange(fromMs, toMs)  zoom(dir)  destroy()
 *
 * Loaded in <head> BEFORE alpine.min.js — see the comment there. Alpine evaluates every
 * x-data in a microtask right after its own script runs, so a factory defined in a later
 * deferred script is undefined exactly when it is needed.
 */
(function () {
  'use strict';

  // Aim for ~200 markers across the viewport, then let the server clamp to the stored
  // base resolution. Requesting finer than that is free to ask for and impossible to serve.
  var TARGET_MARKERS = 200;
  // Pan/zoom fires continuously; one request per gesture, not per frame.
  var DEBOUNCE_MS = 150;

  window.eventTimeline = function (opts) {
    opts = opts || {};
    return {
      url: opts.url || '',
      // Namespaces this surface's zoom in the shared store: `job:12`, `case:3`.
      stateKey: opts.stateKey || '',

      renderer: null,
      loading: false,
      ready: false,
      error: '',
      indexMissing: false,
      stats: null,
      selected: null,
      hover: null,
      // Which per-finding partial is open in the pinned panel ('' | 'events' | 'rule').
      detailKind: '',
      detailLoading: false,
      // Severity/tactic hex, shipped by the API so the canvas, the readout and the
      // severity macros all resolve to one palette. Never re-declare it in a template:
      // tests/test_alpine_components_resolve.py fails the build if you do.
      colors: { severity: {}, tactic: {} },

      _abort: null,
      _debounce: null,
      _range: null,
      // Range callbacks are ignored until the first response has been framed. A renderer
      // that emits one before it has data — carrying whatever default window it invented —
      // otherwise debounces into a fetch for a range the job does not cover, gets nothing
      // back, and wipes the real payload.
      _framed: false,
      // Set while *we* drive the range programmatically, so the renderer's own echo through
      // onRangeChange does not make the initial framing refetch itself.
      _suppressRange: false,

      init() {
        if (!window.LogsTotalTimelineCanvas) {
          this.error = 'The timeline renderer failed to load.';
          return;
        }
        var el = this.$refs.canvas;
        var self = this;
        this.renderer = window.LogsTotalTimelineCanvas.create();
        this.renderer.mount(el, {
          onRangeChange: function (fromMs, toMs) { self._onRangeChange(fromMs, toMs); },
          // Clicking empty canvas passes null, which unpins. Either way the open detail
          // panel belongs to the *previous* marker, so it goes.
          onItemClick: function (item) {
            self.selected = item;
            self.hideDetail();
          },
          onHover: function (item) { self.hover = item; },
        });

        // Restore this surface's zoom from the store rather than the DOM. The case
        // timeline's filter form swaps #case-timeline-region wholesale on every change,
        // which remounts this canvas — without the store, narrowing to one job would throw
        // the analyst back to the full span they had just zoomed out of.
        var saved = this._savedRange();
        this._range = saved;
        this.load(saved ? saved[0] : null, saved ? saved[1] : null);
      },

      destroy() {
        if (this._debounce) clearTimeout(this._debounce);
        if (this._abort) this._abort.abort();
        if (this.renderer) this.renderer.destroy();
      },

      _store() {
        return (window.Alpine && Alpine.store && Alpine.store('timelineRange')) || null;
      },

      _savedRange() {
        var s = this._store();
        var v = s && this.stateKey ? s.get(this.stateKey) : null;
        return Array.isArray(v) && v.length === 2 ? v : null;
      },

      _saveRange(fromMs, toMs) {
        var s = this._store();
        if (s && this.stateKey) s.set(this.stateKey, [fromMs, toMs]);
      },

      _onRangeChange(fromMs, toMs) {
        if (!this._framed || this._suppressRange) return;
        if (!(toMs > fromMs)) return;
        this._range = [fromMs, toMs];
        this._saveRange(fromMs, toMs);
        if (this._debounce) clearTimeout(this._debounce);
        var self = this;
        this._debounce = setTimeout(function () { self.load(fromMs, toMs); }, DEBOUNCE_MS);
      },

      _resolutionFor(fromMs, toMs) {
        if (fromMs == null || toMs == null) return null;
        var span = Math.max(1, Math.round((toMs - fromMs) / 1000));
        return Math.max(1, Math.floor(span / TARGET_MARKERS));
      },

      load(fromMs, toMs) {
        if (!this.url) return;
        var params = new URLSearchParams();
        if (fromMs != null) params.set('frm', Math.floor(fromMs));
        if (toMs != null) params.set('to', Math.ceil(toMs));
        var res = this._resolutionFor(fromMs, toMs);
        if (res) params.set('resolution', res);

        // A newer range supersedes an in-flight one outright: without the abort, changing
        // zoom quickly leaves two requests racing and the slower reply repaints stale
        // markers over fresh ones.
        if (this._abort) this._abort.abort();
        var controller = new AbortController();
        this._abort = controller;
        this.loading = true;
        this.error = '';

        // The case surface bakes its job/severity filters into `url`, so it already
        // carries a query string; appending a second `?` would silently break every param.
        var sep = this.url.indexOf('?') === -1 ? '?' : '&';
        var self = this;
        fetch(this.url + sep + params.toString(), { credentials: 'same-origin', signal: controller.signal })
          .then(function (r) { return r.ok ? r.json() : Promise.reject(r); })
          .then(function (payload) {
            if (self._abort !== controller) return;
            self.indexMissing = !!payload.index_missing;
            // The canvas overplots, so it draws whatever the server sends — the count in the
            // header is always what is on screen. The server's own cap is reported
            // separately as `truncated`.
            var items = payload.items || [];
            self.stats = {
              shown: items.length,
              discarded: payload.discarded || 0,
              total: payload.total || 0,
              resolution: payload.resolution || 1,
              baseResolution: payload.base_resolution || 1,
              truncated: !!payload.truncated,
              jobsWithoutIndex: payload.jobs_without_index || 0,
            };
            if (payload.colors) {
              self.colors = payload.colors;
              self.renderer.setColors(payload.colors);
            }
            // Lane set comes from the index, not from the visible items — otherwise zooming
            // past a tactic's last marker removes its lane and the panel resizes mid-gesture.
            // Before setItems so the lanes are in place when the markers land on them.
            if (payload.groupings && self.renderer.setGroupings) {
              self.renderer.setGroupings(payload.groupings);
            }
            self.renderer.setItems(items);
            // Hand the renderer the full data span so it can bound zoom-out and panning.
            // Without a ceiling the wheel multiplies the span indefinitely and the axis
            // ends up drawing an unbounded number of gridlines.
            if (payload.extent && self.renderer.setExtent) {
              self.renderer.setExtent(payload.extent[0], payload.extent[1]);
            }
            // First load has no range of its own: frame the data, then adopt whatever
            // extent the renderer settled on so the next zoom is relative to it.
            // The full extent, deliberately. An opening window the *server* picks has to
            // be explained and escapable, and that "I want the whole span" state did not
            // survive a re-render — the case Timeline tab swaps this panel on every filter
            // change, so each one snapped the analyst back. Framing on everything is the
            // one behaviour that needs no state to stay correct.
            if (!self._range && payload.extent) {
              self._suppressRange = true;
              self.renderer.setRange(payload.extent[0], payload.extent[1]);
              self._range = self.renderer.getRange();
              // Release on the next task: the renderer's own onRangeChange echo may be
              // queued rather than synchronous.
              setTimeout(function () { self._suppressRange = false; }, 0);
            }
            self._framed = true;
            self.ready = true;
          })
          .catch(function (err) {
            if (err && err.name === 'AbortError') return;
            // Never leave a blank canvas on failure — it is indistinguishable from a job
            // with no alerts, which is the opposite conclusion.
            self.ready = false;
            self.stats = null;
            self.error = (err && err.status)
              ? 'Could not load the events timeline (HTTP ' + err.status + ').'
              : 'Could not load the events timeline.';
          })
          .finally(function () {
            if (self._abort !== controller) return;
            self.loading = false;
            self._abort = null;
          });
      },

      /** Zoom buttons — the discoverable path, since the wheel needs a modifier. */
      zoom(dir) {
        if (this.renderer && this.renderer.zoom) this.renderer.zoom(dir);
      },
      canZoom() {
        return !!(this.ready && this.renderer && this.renderer.zoom);
      },

      resetZoom() {
        var s = this._store();
        if (s && this.stateKey) s.clear(this.stateKey);
        this._range = null;
        this._framed = false; // let the next payload re-frame to the full extent
        this.selected = null;
        this.load(null, null);
      },

      // ── Display helpers, used by the template ──────────────────────────────
      resolutionLabel() {
        if (!this.stats) return '';
        var s = this.stats.resolution;
        if (s < 60) return s + 's';
        if (s < 3600) return Math.round(s / 60) + 'm';
        if (s < 86400) return Math.round(s / 3600) + 'h';
        return Math.round(s / 86400) + 'd';
      },
      atFullDetail() {
        return !!this.stats && this.stats.resolution <= this.stats.baseResolution;
      },
      /* A marker is a *window*, not an instant, whenever it collapsed more than one alert —
         showing only its start implied a precision the index does not have. */
      markerWhen(it) {
        var res = (this.stats && this.stats.resolution) || 1;
        var start = this.formatTime(it.start);
        if (!it || (it.meta.events || 1) <= 1 || res <= 1) return start;
        var end = new Date(it.start + res * 1000).toISOString().slice(11, 19);
        return start + ' → ' + end;
      },

      clearSelection() {
        this.selected = null;
        this.hideDetail();
      },

      hideDetail() {
        this.detailKind = '';
        if (this.$refs.detail) this.$refs.detail.innerHTML = '';
      },

      /* Load a per-finding partial into the pinned panel.
         htmx.ajax rather than fetch+innerHTML: the events partial carries its own htmx
         attributes, and only htmx's own swap runs its processing pass over them. */
      showDetail(it, kind) {
        var id = it && it.meta && it.meta.finding_id;
        if (!id || !window.htmx) return;
        if (this.detailKind === kind) return this.hideDetail();
        this.detailKind = kind;
        this.detailLoading = true;
        var self = this;
        var url = '/jobs/findings/' + id + (kind === 'rule' ? '/rule' : '/events');
        this.$nextTick(function () {
          window.htmx
            .ajax('GET', url, { target: self.$refs.detail, swap: 'innerHTML' })
            .catch(function () {
              if (self.$refs.detail) self.$refs.detail.textContent = 'Could not load that detail.';
            })
            .finally(function () { self.detailLoading = false; });
        });
      },

      severityColor(category) {
        return (this.colors.severity && this.colors.severity[category]) || '#4b5563';
      },
      tacticLabel(key) {
        if (!key || key === '_other') return 'Other';
        return key.replace(/_/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });
      },
      formatTime(ms) {
        if (ms == null) return '';
        try {
          return new Date(ms).toISOString().replace('T', ' ').replace('.000Z', 'Z');
        } catch (e) {
          return String(ms);
        }
      },
    };
  };
})();
