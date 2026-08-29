/**
 * Activity timeline — one line per identity group, drawn as inline SVG.
 *
 * It used to be a stacked bar per day: the total was easy to read, the groups
 * were not. A segment in the middle of a stack sits on whatever is below it, so
 * "are bots picking up?" could not be answered from it. Overlaid lines answer
 * exactly that, and the total moves into the hover tooltip.
 *
 * No chart library — the release UI dropped Chart.js and draws its own, the way
 * sparkline.js does. Colours come from the --grp-* tokens via cssVar(), never
 * from a literal in here.
 *
 * Markup contract (the activity_chart macro):
 *   .timeline[data-endpoint][data-from][data-to]
 *     script[type="application/json"]  { series, rows }
 *     .timeline-plot      — the SVG goes here
 *     .timeline-zoombar   — the two magnifier buttons, [data-zoom=in|out]
 *
 * Zooming is visual only: it picks what the chart shows, never what the page
 * queries. The date filter stays with the range tabs. Two ways in — drag a
 * range for a precise window, or press + for the middle half — and one way
 * out, which unwinds them in the order they were made.
 */
/* The arithmetic behind the chart, at file scope so it can be tested without a
 * browser — the same reason groupOf/summariseSelection sit outside map.js's
 * initialiser. Everything below the IIFE line touches the DOM. */
const PAD = { top: 12, right: 12, bottom: 22, left: 44 };
// Below this many days a daily axis has too few points to say anything. The
// server owns the number — it uses the same one to choose the bucket the page
// ships with — and sends it in the chart's payload; this is the fallback for a
// payload written before it did.
const HOUR_SWITCH_DAYS_DEFAULT = 3;
// Fewer buckets than this and there is nothing left to zoom into: halving four
// points leaves two, which is a line segment, not a shape.
const MIN_ZOOM_BUCKETS = 4;

/** Rounded gridline values from 0 to a nice number at or above max. */
function niceTicks(max, count) {
  const steps = count || 3;
  if (!(max > 0)) return [0, 1];
  const raw = max / steps;
  const mag = Math.pow(10, Math.floor(Math.log10(raw)));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => s >= raw) || mag * 10;
  const top = Math.ceil(max / step) * step;
  const out = [];
  for (let v = 0; v <= top + step / 2; v += step) out.push(Math.round(v));
  return out;
}

/** Which bucket size a span of days deserves. */
function pickBucket(days, threshold) {
  return days <= (threshold || HOUR_SWITCH_DAYS_DEFAULT) ? 'hour' : 'day';
}

/** "2026-08-05" → "05.08.", "2026-08-05T14" → "14:00". */
function formatBucket(t, bucket) {
  if (!t) return '';
  if (bucket === 'hour') return t.slice(11, 13) + ':00';
  return t.slice(8, 10) + '.' + t.slice(5, 7) + '.';
}

/** Long form for the tooltip and the zoom chip. */
function formatBucketLong(t, bucket) {
  const d = t.slice(8, 10) + '.' + t.slice(5, 7) + '.' + t.slice(2, 4);
  return bucket === 'hour' ? d + ' ' + t.slice(11, 13) + ':00' : d;
}

/** Index of the bucket under an x position inside the plot area. */
function bucketAt(x, plotLeft, plotWidth, count) {
  // A chart in a closed panel has no width, and the caller's scaling then hands
  // us NaN. Falling back to the first bucket keeps the hover harmless.
  if (count < 2 || !isFinite(x) || !(plotWidth > 0)) return 0;
  const rel = (x - plotLeft) / plotWidth;
  return Math.max(0, Math.min(count - 1, Math.round(rel * (count - 1))));
}

/** Days between two bucket keys, as the zoom uses it to choose a resolution. */
function spanInDays(from, to) {
  const a = Date.parse(from.length > 10 ? from + ':00:00Z' : from + 'T00:00:00Z');
  const b = Date.parse(to.length > 10 ? to + ':00:00Z' : to + 'T00:00:00Z');
  return isNaN(a) || isNaN(b) ? 0 : Math.abs(b - a) / 86400000;
}

(function () {
  'use strict';

  function render(box) {
    const state = box._tl;
    const rows = state.view;
    const plot = box.querySelector('.timeline-plot');
    if (!plot) return;
    if (!rows.length) {
      plot.innerHTML = '<p class="text-muted">No activity in this range.</p>';
      return;
    }

    const W = plot.clientWidth || 900;
    const H = plot.clientHeight || 190;
    const iw = Math.max(10, W - PAD.left - PAD.right);
    const ih = Math.max(10, H - PAD.top - PAD.bottom);
    const max = rows.reduce(
      (m, r) => state.series.reduce((mm, s) => Math.max(mm, r[s.key] || 0), m),
      0
    );
    const ticks = niceTicks(max);
    const top = ticks[ticks.length - 1] || 1;
    const x = (i) => PAD.left + (rows.length === 1 ? iw / 2 : (i * iw) / (rows.length - 1));
    const y = (v) => PAD.top + ih - ((v || 0) / top) * ih;

    const grid = ticks
      .map(
        (t) =>
          `<line class="tl-grid" x1="${PAD.left}" x2="${PAD.left + iw}" ` +
          `y1="${y(t).toFixed(1)}" y2="${y(t).toFixed(1)}"/>` +
          `<text class="tl-axis" x="${PAD.left - 6}" y="${(y(t) + 3.5).toFixed(1)}" ` +
          `text-anchor="end">${fmtNum(t)}</text>`
      )
      .join('');

    // About six date marks, whatever the bucket count.
    const every = Math.max(1, Math.round(rows.length / 6));
    const xAxis = rows
      .map((r, i) => {
        if (i % every !== 0 && i !== rows.length - 1) return '';
        // The first and last marks sit on the plot edge; centred, they would be
        // clipped by the SVG box (the last date lost its trailing dot).
        const anchor = i === 0 ? 'start' : i === rows.length - 1 ? 'end' : 'middle';
        return (
          `<text class="tl-axis" x="${x(i).toFixed(1)}" y="${H - 6}" text-anchor="${anchor}">` +
          `${formatBucket(r.day, state.bucket)}</text>`
        );
      })
      .join('');

    const gap = iw / Math.max(1, rows.length - 1);
    const lines = state.series
      .map((s) => {
        const pts = rows.map((r, i) => `${x(i).toFixed(1)},${y(r[s.key]).toFixed(1)}`).join(' ');
        const dots =
          gap >= 7
            ? rows
                .map(
                  (r, i) =>
                    `<circle cx="${x(i).toFixed(1)}" cy="${y(r[s.key]).toFixed(1)}" r="2.2" ` +
                    `fill="${s.color}"/>`
                )
                .join('')
            : '';
        return (
          `<g data-series="${s.key}"><polyline class="tl-line" points="${pts}" ` +
          `fill="none" stroke="${s.color}"/>${dots}</g>`
        );
      })
      .join('');

    plot.innerHTML =
      `<svg class="tl-svg" viewBox="0 0 ${W} ${H}" role="img" ` +
      `aria-label="Visits per ${state.bucket}, one line per identity group">` +
      grid +
      xAxis +
      lines +
      `<line class="tl-cursor" x1="0" x2="0" y1="${PAD.top}" y2="${PAD.top + ih}" style="display:none"/>` +
      `<rect class="tl-band" y="${PAD.top}" height="${ih}" width="0" style="display:none"/>` +
      `</svg>`;

    state.geom = { x, y, iw, ih, W, H };
  }

  function showTip(box, i) {
    const state = box._tl;
    const row = state.view[i];
    if (!row) return;
    const tip = box.querySelector('.timeline-tip');
    const svg = box.querySelector('.tl-svg');
    const cursor = box.querySelector('.tl-cursor');
    if (!tip || !svg) return;
    const px = state.geom.x(i);
    cursor.setAttribute('x1', px);
    cursor.setAttribute('x2', px);
    cursor.style.display = '';

    tip.innerHTML =
      `<strong>${formatBucketLong(row.day, state.bucket)}</strong>` +
      `<span class="tl-tip-total">${fmtNum(row.total)} visits</span>` +
      state.series
        .filter((s) => row[s.key])
        .map(
          (s) =>
            `<span class="tl-tip-row"><span class="tl-tip-dot" style="background:${s.color}"></span>` +
            `${s.label}<strong>${fmtNum(row[s.key])}</strong></span>`
        )
        .join('');
    const rect = svg.getBoundingClientRect();
    const left = (px / state.geom.W) * rect.width;
    tip.style.left = Math.round(left) + 'px';
    tip.classList.toggle('tl-tip--flip', left > rect.width * 0.6);
    tip.style.display = '';
  }

  function hideTip(box) {
    const tip = box.querySelector('.timeline-tip');
    const cursor = box.querySelector('.tl-cursor');
    if (tip) tip.style.display = 'none';
    if (cursor) cursor.style.display = 'none';
  }

  /** Reflect how far in we are on the two buttons.
   *
   * Out is available exactly when there is a step to undo, in exactly when
   * there are enough buckets left to halve — below four, the next step would
   * be one or two points, which is the state this chart cannot say anything in.
   */
  function setZoomControls(box) {
    const state = box._tl;
    const out = box.querySelector('[data-zoom="out"]');
    const zin = box.querySelector('[data-zoom="in"]');
    if (out) out.disabled = state.stack.length === 0;
    if (zin) zin.disabled = state.view.length < MIN_ZOOM_BUCKETS;
  }

  /** Remember the current view so one step out can restore it exactly. */
  function pushZoom(box) {
    const state = box._tl;
    state.stack.push({ view: state.view, bucket: state.bucket, zoom: state.zoom });
  }

  /** Undo one step in. A stack rather than a "reset": stepping out of the
   *  hourly view has to land back on the days it was opened from, and only the
   *  view it replaced knows what those were. */
  function zoomOut(box) {
    const state = box._tl;
    const prev = state.stack.pop();
    if (!prev) return;
    state.view = prev.view;
    state.bucket = prev.bucket;
    state.zoom = prev.zoom;
    setZoomControls(box);
    render(box);
  }

  /** Step in on the middle half of what is shown. */
  function zoomIn(box) {
    const n = box._tl.view.length;
    if (n < MIN_ZOOM_BUCKETS) return;
    applyZoom(box, Math.floor(n * 0.25), Math.ceil(n * 0.75) - 1);
  }

  /** Apply a zoom window, fetching finer buckets when it is short enough. */
  function applyZoom(box, i0, i1) {
    const state = box._tl;
    const rows = state.view;
    const lo = Math.min(i0, i1);
    const hi = Math.max(i0, i1);
    const a = rows[lo];
    const b = rows[hi];
    if (!a || !b || a.day === b.day) return;

    // Recorded before anything changes, so one step out restores exactly this —
    // whether the step in came from a drag or from the + button.
    pushZoom(box);
    // Slice what is already on screen — zooming again inside the hourly view
    // must narrow the hours, not fall back to comparing them against days.
    state.view = rows.slice(lo, hi + 1);
    state.zoom = [a.day, b.day];
    setZoomControls(box);
    render(box);

    const days = spanInDays(a.day, b.day);
    if (pickBucket(days, state.hourSwitchDays) === 'hour' && state.bucket !== 'hour' && state.endpoint) {
      // Hours exist server-side only; below three days the daily points are too
      // few to say anything, which is the whole reason to zoom that far.
      const params = new URLSearchParams(state.params);
      params.set('bucket', 'hour');
      params.set('from', a.day.slice(0, 10));
      params.set('to', b.day.slice(0, 10));
      fetch(state.endpoint + '?' + params.toString(), { headers: { Accept: 'application/json' } })
        .then((r) => (r.ok ? r.json() : null))
        .then((data) => {
          if (!data || !data.rows || !data.rows.length) return;
          state.bucket = data.bucket;
          state.view = data.rows;
          state.zoom = [data.rows[0].day, data.rows[data.rows.length - 1].day];
          setZoomControls(box);
          render(box);
        })
        .catch(() => {
          /* keep the daily slice rather than blanking the chart */
        });
    }
  }

  function init(box) {
    const script = box.querySelector('script[type="application/json"]');
    if (!script) return;
    const data = JSON.parse(script.textContent);
    const series = data.series.map((s) => ({ ...s, color: cssVar(s.token) }));
    box._tl = {
      all: data.rows,
      view: data.rows,
      series,
      // The resolution the rows arrived in. Hard-coded to 'day' once, which
      // mislabelled every hourly axis the server shipped as a date.
      bucket: data.bucket || 'day',
      initialBucket: data.bucket || 'day',
      stack: [],
      hourSwitchDays: data.hourSwitchDays || HOUR_SWITCH_DAYS_DEFAULT,
      zoom: null,
      endpoint: box.dataset.endpoint || '',
      params: box.dataset.params || '',
      geom: null,
    };
    render(box);
    setZoomControls(box);

    box.querySelectorAll('[data-zoom]').forEach((btn) => {
      btn.addEventListener('click', () => {
        if (btn.dataset.zoom === 'in') zoomIn(box);
        else zoomOut(box);
      });
    });

    const plot = box.querySelector('.timeline-plot');
    let dragFrom = null;

    const indexAt = (clientX) => {
      const svg = box.querySelector('.tl-svg');
      if (!svg) return 0;
      const rect = svg.getBoundingClientRect();
      const scale = box._tl.geom.W / rect.width;
      return bucketAt(
        (clientX - rect.left) * scale,
        PAD.left,
        box._tl.geom.iw,
        box._tl.view.length
      );
    };

    plot.addEventListener('mousemove', (e) => {
      if (!box._tl.geom) return;
      const i = indexAt(e.clientX);
      showTip(box, i);
      if (dragFrom !== null) {
        const band = box.querySelector('.tl-band');
        const x0 = box._tl.geom.x(Math.min(dragFrom, i));
        const x1 = box._tl.geom.x(Math.max(dragFrom, i));
        band.setAttribute('x', x0);
        band.setAttribute('width', Math.max(0, x1 - x0));
        band.style.display = '';
      }
    });
    plot.addEventListener('mouseleave', () => hideTip(box));
    plot.addEventListener('mousedown', (e) => {
      if (e.button !== 0 || !box._tl.geom) return;
      e.preventDefault();
      dragFrom = indexAt(e.clientX);
    });
    document.addEventListener('mouseup', (e) => {
      if (dragFrom === null) return;
      const from = dragFrom;
      dragFrom = null;
      const band = box.querySelector('.tl-band');
      if (band) band.style.display = 'none';
      if (!box._tl.geom) return;
      const to = indexAt(e.clientX);
      if (Math.abs(to - from) >= 1) applyZoom(box, from, to);
    });

    window.addEventListener('resize', () => render(box));
    document.addEventListener('themechange', () => {
      box._tl.series = data.series.map((s) => ({ ...s, color: cssVar(s.token) }));
      render(box);
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.timeline').forEach(init);
  });
})();
