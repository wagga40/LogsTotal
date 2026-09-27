/* Events-timeline renderer — a purpose-built <canvas>. No dependencies.
 *
 * Hand-rolled rather than delegated to a timeline library, and the reason is *overplotting*:
 * an alert timeline is dense by nature, and general-purpose libraries stack overlapping
 * items into one row each. On a real job every marker overlaps every other in time, so
 * stacking turns a 300px panel into a 1,200-row ribbon and the overview is gone. Here
 * markers share a lane and pile up visually, which is what makes density legible.
 *
 * Implements the renderer contract documented in timeline.js.
 */
(function () {
  'use strict';

  var LANE_H = 22;
  var LANE_GAP = 2;
  var AXIS_H = 26;
  var PAD_L = 132;   // room for lane labels
  var PAD_R = 12;
  var PAD_T = 8;
  var MARKER_R = 3.5;
  var MIN_SPAN_MS = 1000;          // do not zoom past one second
  var HIT_RADIUS_PX = 6;
  var DEFAULT_COLOR = '#6b7280';

  // How far past the data you may zoom out. Without a ceiling the wheel multiplies the
  // span without bound, and the gridline loop below then walks millions of ticks — which
  // is what froze the page on repeated zoom-out.
  var MAX_SPAN_FACTOR = 4;
  var ABSOLUTE_MAX_SPAN_MS = 100 * 365 * 864e5;   // a century, as a last-resort ceiling
  var MAX_GRIDLINES = 40;                          // hard bound on the tick loop

  var DAY_MS = 864e5;
  var YEAR_MS = 365 * DAY_MS;

  // Tick ladder in ms — the axis picks the first step giving <= ~10 labels. Tops out at a
  // decade; beyond that the step is computed, so no span can outrun the ladder.
  var TICKS = [
    1e3, 5e3, 15e3, 30e3, 60e3, 3e5, 9e5, 18e5, 36e5, 108e5, 216e5,
    DAY_MS, 7 * DAY_MS, 31 * DAY_MS, 92 * DAY_MS, YEAR_MS, 10 * YEAR_MS
  ];

  function tickStep(span) {
    for (var i = 0; i < TICKS.length; i++) {
      if (span / TICKS[i] <= 10) return TICKS[i];
    }
    // Past the ladder: derive a step directly so the loop stays bounded whatever the span.
    return Math.max(TICKS[TICKS.length - 1], Math.ceil(span / 10));
  }

  function p2(n) { return n < 10 ? '0' + n : '' + n; }

  // Dates are DD-MM / DD-MM-YYYY and times are 24h, always UTC — the index normalises every
  // tool's timestamp to UTC, so rendering in the viewer's local zone would silently shift
  // the axis away from the data.
  function fmtTick(ms, span) {
    var d = new Date(ms);
    if (span < 6e4) return p2(d.getUTCMinutes()) + ':' + p2(d.getUTCSeconds());
    if (span < DAY_MS) return p2(d.getUTCHours()) + ':' + p2(d.getUTCMinutes());
    if (span < YEAR_MS) return p2(d.getUTCDate()) + '-' + p2(d.getUTCMonth() + 1);
    return p2(d.getUTCDate()) + '-' + p2(d.getUTCMonth() + 1) + '-' + d.getUTCFullYear();
  }

  function labelFor(key) {
    if (!key || key === '_other') return 'Other';
    return key.replace(/_/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });
  }

  function create() {
    return {
      el: null, canvas: null, ctx: null, cbs: null, ro: null,
      items: [], lanes: [], colors: { severity: {}, tactic: {} },
      from: 0, to: 0, w: 0, h: 0, dpr: 1, extent: null,
      _drag: null, _raf: null, _groupings: null,

      mount(el, cbs) {
        this.el = el;
        this.cbs = cbs || {};
        this.canvas = document.createElement('canvas');
        this.canvas.style.width = '100%';
        this.canvas.style.display = 'block';
        this.canvas.style.cursor = 'crosshair';
        el.appendChild(this.canvas);
        this.ctx = this.canvas.getContext('2d');

        var self = this;
        this._onWheel = function (e) { self._wheel(e); };
        this._onDown = function (e) { self._down(e); };
        this._onMove = function (e) { self._move(e); };
        this._onUp = function (e) { self._up(e); };
        this._onLeave = function () { if (self.cbs.onHover) self.cbs.onHover(null); };

        this.canvas.addEventListener('wheel', this._onWheel, { passive: false });
        this.canvas.addEventListener('mousedown', this._onDown);
        this.canvas.addEventListener('mousemove', this._onMove);
        window.addEventListener('mouseup', this._onUp);
        this.canvas.addEventListener('mouseleave', this._onLeave);

        // The panel is often lazy-loaded into a container that has no width yet, so
        // measuring once at mount would size the canvas to zero.
        if (window.ResizeObserver) {
          this.ro = new ResizeObserver(function () { self._resize(); });
          this.ro.observe(el);
        }
        this._resize();
      },

      destroy() {
        if (this.ro) this.ro.disconnect();
        if (this._raf) cancelAnimationFrame(this._raf);
        if (this.canvas) {
          this.canvas.removeEventListener('wheel', this._onWheel);
          this.canvas.removeEventListener('mousedown', this._onDown);
          this.canvas.removeEventListener('mousemove', this._onMove);
          this.canvas.removeEventListener('mouseleave', this._onLeave);
          if (this.canvas.parentNode) this.canvas.parentNode.removeChild(this.canvas);
        }
        window.removeEventListener('mouseup', this._onUp);
      },

      setColors(colors) {
        this.colors = colors || { severity: {}, tactic: {} };
      },

      /* Lane identity for the whole job, independent of the viewport.
       *
       * Derived from the visible items, a lane would drop as soon as a zoom excluded its
       * last marker: the canvas would get shorter, everything below it move up, and the page
       * jump under the cursor mid-gesture. Lanes belong to the *data*, so the server sends
       * every tactic in the index and empty lanes simply render as empty bands. */
      setGroupings(groupings) {
        this._groupings = (groupings && groupings.length) ? groupings.slice() : null;
        this._applyLanes();
      },

      setItems(items) {
        this.items = items || [];
        this._applyLanes();
      },

      _applyLanes() {
        var lanes;
        if (this._groupings) {
          lanes = this._groupings.slice();
        } else {
          // No server-supplied set (an older payload): fall back to the visible items.
          var seen = {};
          lanes = [];
          for (var i = 0; i < this.items.length; i++) {
            var g = this.items[i].grouping || '_other';
            if (!seen[g]) { seen[g] = true; lanes.push(g); }
          }
        }
        // Stable lane order: whatever the server's tactic palette declares (kill-chain
        // order), with anything unrecognised appended.
        var known = Object.keys(this.colors.tactic || {});
        lanes.sort(function (a, b) {
          var ia = known.indexOf(a), ib = known.indexOf(b);
          if (ia === -1) ia = 999;
          if (ib === -1) ib = 999;
          return ia - ib;
        });
        var changed = lanes.length !== this.lanes.length;
        this.lanes = lanes;
        // Only re-measure when the lane count actually moved — _resize reallocates the
        // backing store, and doing that on every fetch is what makes a zoom gesture stutter.
        if (changed) this._resize(); else this._draw();
      },

      getRange() { return [this.from, this.to]; },

      /** The full span of the data, used to bound zoom-out and panning. */
      setExtent(fromMs, toMs) {
        this.extent = (fromMs != null && toMs > fromMs) ? [fromMs, toMs] : null;
      },

      setRange(fromMs, toMs) {
        if (fromMs == null || toMs == null || !(toMs > fromMs)) return;
        this.from = fromMs;
        this.to = toMs;
        this._draw();
      },

      // ── Geometry ───────────────────────────────────────────────────────────
      _plotW() { return Math.max(1, this.w - PAD_L - PAD_R); },

      _x(ms) {
        var span = this.to - this.from || 1;
        return PAD_L + ((ms - this.from) / span) * this._plotW();
      },

      _ms(x) {
        var span = this.to - this.from || 1;
        return this.from + ((x - PAD_L) / this._plotW()) * span;
      },

      _laneY(grouping) {
        var i = this.lanes.indexOf(grouping || '_other');
        if (i === -1) i = this.lanes.length;
        return PAD_T + i * (LANE_H + LANE_GAP) + LANE_H / 2;
      },

      _resize() {
        if (!this.el || !this.canvas) return;
        var rect = this.el.getBoundingClientRect();
        var laneCount = Math.max(1, this.lanes.length);
        this.dpr = window.devicePixelRatio || 1;
        this.w = Math.max(240, Math.round(rect.width));
        this.h = PAD_T + laneCount * (LANE_H + LANE_GAP) + AXIS_H;
        this.canvas.width = Math.round(this.w * this.dpr);
        this.canvas.height = Math.round(this.h * this.dpr);
        this.canvas.style.height = this.h + 'px';
        this.ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
        this._draw();
      },

      // ── Interaction ────────────────────────────────────────────────────────
      _pos(e) {
        var r = this.canvas.getBoundingClientRect();
        return { x: e.clientX - r.left, y: e.clientY - r.top };
      },

      _wheel(e) {
        if (!(this.to > this.from)) return;
        // A bare wheel scrolls the page. Zoom needs ctrl/⌘ (or shift) — the same bargain
        // embedded maps make, and the only one that keeps a full-width panel from trapping
        // the scroll wheel halfway down a long page. The header says so, and the +/- buttons
        // mean the modifier is a shortcut rather than the only way in.
        if (!(e.ctrlKey || e.metaKey || e.shiftKey)) return;
        e.preventDefault();
        var p = this._pos(e);
        // Anchor the zoom at the cursor: the instant under the pointer stays put, which is
        // the only zoom that feels like inspecting rather than scrolling.
        this.zoomAt(this._ms(p.x), e.deltaY > 0 ? 1 : -1, Math.abs(e.deltaY));
      },

      /** Zoom by one step. `dir` is +1 out / -1 in; `magnitude` scales trackpad deltas. */
      zoomAt(anchorMs, dir, magnitude) {
        var current = this.to - this.from;
        if (!(current > 0)) return;
        // Proportional to the gesture: a trackpad emits many small deltas where a mouse
        // emits few large ones, and a flat factor makes the trackpad unusable.
        var step = Math.min(0.25, 0.05 + (magnitude || 40) / 600);
        var factor = dir > 0 ? 1 + step : 1 / (1 + step);
        var span = current * factor;

        if (span < MIN_SPAN_MS) span = MIN_SPAN_MS;
        var max = this._maxSpan();
        if (span > max) span = max;
        if (span === current) return;

        var frac = (anchorMs - this.from) / current;
        this.from = anchorMs - span * frac;
        this.to = this.from + span;
        this._clampToExtent();
        this._draw();
        this._emitRange();
      },

      /** Zoom in/out about the centre — what the +/- buttons call. */
      zoom(dir) {
        this.zoomAt((this.from + this.to) / 2, dir, 120);
      },

      _maxSpan() {
        if (this.extent && this.extent[1] > this.extent[0]) {
          return Math.min((this.extent[1] - this.extent[0]) * MAX_SPAN_FACTOR, ABSOLUTE_MAX_SPAN_MS);
        }
        return ABSOLUTE_MAX_SPAN_MS;
      },

      /** Keep the window from drifting far outside the data it is meant to show. */
      _clampToExtent() {
        if (!this.extent || !(this.extent[1] > this.extent[0])) return;
        var span = this.to - this.from;
        var pad = span / 2;
        var lo = this.extent[0] - pad;
        var hi = this.extent[1] + pad;
        if (this.from < lo) { this.from = lo; this.to = lo + span; }
        if (this.to > hi) { this.to = hi; this.from = hi - span; }
      },

      _down(e) {
        var p = this._pos(e);
        this._drag = { x: p.x, y: p.y, from: this.from, to: this.to, moved: false };
        this.canvas.style.cursor = 'grabbing';
      },

      _move(e) {
        var p = this._pos(e);
        if (this._drag) {
          var dx = p.x - this._drag.x;
          if (Math.abs(dx) > 2) this._drag.moved = true;
          var span = this._drag.to - this._drag.from;
          var shift = (dx / this._plotW()) * span;
          this.from = this._drag.from - shift;
          this.to = this._drag.to - shift;
          this._clampToExtent();
          this._draw();
          return;
        }
        if (this.cbs.onHover) this.cbs.onHover(this._hit(p.x, p.y));
      },

      _up() {
        if (!this._drag) return;
        var drag = this._drag;
        this._drag = null;
        this.canvas.style.cursor = 'crosshair';
        if (drag.moved) {
          this._emitRange();
          return;
        }
        // A press that never moved is a click, and this is the only place it can be
        // detected: the canvas has no per-marker elements to attach a 'click' listener to,
        // and a plain click handler would also fire at the end of every pan. Without it
        // `onItemClick` was declared in the contract, wired up in timeline.js, and never
        // called — so "click to pin it" did nothing.
        if (this.cbs.onItemClick) this.cbs.onItemClick(this._hit(drag.x, drag.y));
      },

      _emitRange() {
        if (this.cbs.onRangeChange) this.cbs.onRangeChange(this.from, this.to);
      },

      _hit(x, y) {
        var best = null, bestD = HIT_RADIUS_PX;
        for (var i = 0; i < this.items.length; i++) {
          var it = this.items[i];
          var dy = Math.abs(this._laneY(it.grouping) - y);
          if (dy > LANE_H / 2) continue;
          var dx = Math.abs(this._x(it.start) - x);
          if (dx <= bestD) { bestD = dx; best = it; }
        }
        return best;
      },

      // ── Drawing ────────────────────────────────────────────────────────────
      _draw() {
        if (this._raf) return;
        var self = this;
        this._raf = requestAnimationFrame(function () {
          self._raf = null;
          self._paint();
        });
      },

      _paint() {
        var ctx = this.ctx;
        if (!ctx) return;
        ctx.clearRect(0, 0, this.w, this.h);
        if (!(this.to > this.from)) return;

        var plotTop = PAD_T;
        var plotBottom = PAD_T + Math.max(1, this.lanes.length) * (LANE_H + LANE_GAP);

        // Lane bands + labels
        ctx.font = '11px ui-sans-serif, system-ui, sans-serif';
        ctx.textBaseline = 'middle';
        for (var i = 0; i < this.lanes.length; i++) {
          var key = this.lanes[i];
          var y = PAD_T + i * (LANE_H + LANE_GAP);
          ctx.fillStyle = i % 2 ? 'rgba(255,255,255,0.03)' : 'rgba(255,255,255,0.06)';
          ctx.fillRect(PAD_L, y, this._plotW(), LANE_H);
          ctx.fillStyle = (this.colors.tactic && this.colors.tactic[key]) || DEFAULT_COLOR;
          ctx.fillRect(PAD_L - 6, y, 3, LANE_H);
          ctx.fillStyle = 'rgba(203,213,225,0.85)';
          ctx.textAlign = 'right';
          ctx.fillText(this._trim(ctx, labelFor(key), PAD_L - 14), PAD_L - 12, y + LANE_H / 2);
        }

        // Axis gridlines + ticks
        var span = this.to - this.from;
        var step = tickStep(span);
        ctx.textAlign = 'center';
        ctx.strokeStyle = 'rgba(148,163,184,0.18)';
        ctx.lineWidth = 1;
        var first = Math.ceil(this.from / step) * step;
        // Bounded explicitly as well as by tickStep: `to` is a float the wheel drives, and
        // one NaN or Infinity here would otherwise mean an endless loop with the main thread
        // held.
        var drawn = 0;
        for (var ms = first; ms <= this.to && drawn < MAX_GRIDLINES; ms += step, drawn++) {
          var x = Math.round(this._x(ms)) + 0.5;
          ctx.beginPath();
          ctx.moveTo(x, plotTop);
          ctx.lineTo(x, plotBottom);
          ctx.stroke();
          ctx.fillStyle = 'rgba(148,163,184,0.9)';
          ctx.fillText(fmtTick(ms, span), x, plotBottom + 13);
        }

        // Markers. Overplotted on purpose — density is the signal.
        var sev = this.colors.severity || {};
        for (var m = 0; m < this.items.length; m++) {
          var it = this.items[m];
          var mx = this._x(it.start);
          if (mx < PAD_L - MARKER_R || mx > this.w - PAD_R + MARKER_R) continue;
          var my = this._laneY(it.grouping);
          var n = (it.meta && it.meta.discarded) || 0;
          // Collapsed markers grow a little, so a burst reads as heavier than a single hit.
          var r = MARKER_R + Math.min(3, Math.log10(n + 1) * 2);
          ctx.fillStyle = sev[it.category] || DEFAULT_COLOR;
          ctx.globalAlpha = 0.85;
          ctx.beginPath();
          ctx.arc(mx, my, r, 0, Math.PI * 2);
          ctx.fill();
        }
        ctx.globalAlpha = 1;
      },

      _trim(ctx, text, maxW) {
        if (ctx.measureText(text).width <= maxW) return text;
        var s = text;
        while (s.length > 1 && ctx.measureText(s + '…').width > maxW) s = s.slice(0, -1);
        return s + '…';
      },
    };
  }

  window.LogsTotalTimelineCanvas = { create: create, available: function () { return true; } };
})();
