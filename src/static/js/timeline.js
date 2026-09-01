/**
 * Activity timeline — a total, and one small chart per identity group.
 *
 * It was a stacked bar per day first: the total was easy to read, the groups
 * were not, because a segment in the middle of a stack sits on whatever is
 * below it. Overlaid lines fixed that and created a worse problem — one linear
 * axis shared by five series whose magnitudes differ by three orders of
 * magnitude. Measured on a month of real traffic: threats peaked at 7 043 and
 * drew 144 px, humans peaked at 16 and drew 0.3 px. Three of the five series
 * were flat lines glued to the baseline, and humans — the series an operator
 * most wants to see — was a third of a pixel.
 *
 * So: a hero band for the total, answering "when did this traffic happen" at a
 * glance, and five small multiples under it, each scaled to its own maximum
 * with that maximum printed beside its name. Magnitude moves from a shared axis
 * to a number, which is where it survives. One shared x-domain and one shared
 * cursor keep the six reading as one chart.
 *
 * A log axis would have been the other escape and is the wrong one: humans has
 * true zero days — most of them — and zero has no place on a log scale.
 *
 * No chart library — the release UI dropped Chart.js and draws its own, the way
 * sparkline.js does. Colours come from the --grp-* tokens via cssVar(), never
 * from a literal in here.
 *
 * Markup contract (the activity_chart macro):
 *   .timeline[data-endpoint][data-from][data-to]
 *     script[type="application/json"]  { series, rows }
 *     .timeline-plot      — .tl-hero and .tl-mults are written into this
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
// The hero's own padding. `bottom` carries two rows of axis on an hourly view:
// the hour, and the date it belongs to.
const PAD = { top: 12, right: 12, bottom: 34, left: 44 };
const HERO_H = 150;
// One small multiple. Tall enough for a shape, short enough that five of them
// plus the hero stay inside one screen.
const MULT_H = 52;
const MULT_PAD = { top: 6, bottom: 4 };
// The narrowest a date label may be given before the axis drops it. Six labels
// in 134 px of plot — which is what a 420 px viewport leaves — overlapped every
// neighbour and rendered as a smear.
const LABEL_SLOT = 90;
// Below this many days a daily axis has too few points to say anything. The
// server owns the number — it uses the same one to choose the bucket the page
// ships with — and sends it in the chart's payload; this is the fallback for a
// payload written before it did.
const HOUR_SWITCH_DAYS_DEFAULT = 3;
// Fewer buckets than this and there is nothing left to zoom into: halving four
// points leaves two, which is a line segment, not a shape. Six, not four —
// zoomIn takes the middle half, so four in gives two out, the state this
// constant exists to forbid. It permitted it for as long as it said four.
const MIN_ZOOM_BUCKETS = 6;

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

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** "2026-08-05" → "05 Aug". Not 05.08. — the dashboard is English-only, and a
 *  day-first numeric date is ambiguous against M/D for twelve days a month. */
function formatDay(t) {
  return t.slice(8, 10) + ' ' + (MONTHS[Number(t.slice(5, 7)) - 1] || '');
}

/** "2026-08-05" → "05 Aug", "2026-08-05T14" → "14:00". */
function formatBucket(t, bucket) {
  if (!t) return '';
  if (bucket === 'hour') return t.slice(11, 13) + ':00';
  return formatDay(t);
}

/** Long form for the tooltip and the range readout. */
function formatBucketLong(t, bucket) {
  const d = formatDay(t) + ' ' + t.slice(0, 4);
  return bucket === 'hour' ? d + ' ' + t.slice(11, 13) + ':00' : d;
}

/** Which bucket indices get a label, given how much room there is for them.
 *
 * The old rule asked for six marks whatever the width. At 420 px the plot is
 * 134 px wide and six labels need about 253 px of text, so every adjacent pair
 * overlapped and the axis rendered as a smear. Room decides now, and the last
 * bucket always gets one — it is the edge of the window.
 */
function axisIndices(count, innerWidth) {
  if (count < 1) return [];
  if (count === 1) return [0];
  const slots = Math.max(1, Math.floor(innerWidth / LABEL_SLOT));
  const every = Math.max(1, Math.ceil((count - 1) / Math.min(6, slots)));
  const out = [];
  for (let i = 0; i < count; i += every) out.push(i);
  const last = count - 1;
  // `every` rarely divides the range evenly, so the mark before the last can
  // land right on top of it. One of the two has to go, and it is not the edge.
  if (out[out.length - 1] !== last) {
    if (last - out[out.length - 1] < every * 0.6) out.pop();
    out.push(last);
  }
  return out;
}

/** The first bucket of each day in an hourly view, for the axis' second row.
 *
 * An hourly axis reads 00:00 12:00 00:00 12:00 00:00 — six of seven labels
 * ambiguous, and nothing on the chart saying which day a point belongs to. The
 * date goes underneath, once per day, centred on that day's span.
 */
function dayBands(rows) {
  const bands = [];
  rows.forEach((r, i) => {
    const day = r.day.slice(0, 10);
    const last = bands[bands.length - 1];
    if (last && last.day === day) last.to = i;
    else bands.push({ day: day, from: i, to: i });
  });
  return bands;
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

  /** The line through a series, and the area under it. */
  function shape(rows, key, x, y, baseY, color, cls, areaCls) {
    const pts = rows.map((r, i) => `${x(i).toFixed(1)},${y(r[key]).toFixed(1)}`);
    const area =
      `M${x(0).toFixed(1)},${baseY.toFixed(1)} L` +
      pts.join(' L') +
      ` L${x(rows.length - 1).toFixed(1)},${baseY.toFixed(1)} Z`;
    return (
      `<path class="${areaCls}" d="${area}" fill="${color}"/>` +
      `<polyline class="${cls}" points="${pts.join(' ')}" fill="none" stroke="${color}"/>`
    );
  }

  /** One series, or two nested when the New comparison is on.
   *
   * New is always a subset of All — an address whose first request is inside
   * the window is an address inside the window — so the two nest and the gap
   * between them is the returning traffic. All is drawn as the outline and New
   * as the solid fill inside it: "of this much, this much had not been here
   * before". Drawn in that order so the fill sits over the outline's own.
   */
  function seriesShape(rows, key, x, y, baseY, color, cls) {
    const outer = shape(rows, key, x, y, baseY, color, cls, 'tl-area');
    if (!(key + '_new' in rows[0])) return outer;
    return outer + shape(rows, key + '_new', x, y, baseY, color, cls + ' tl-line--new', 'tl-area tl-area--new');
  }

  /** The hero: the total, on its own axis, with the shared x-axis under it. */
  function renderHero(box, rows) {
    const state = box._tl;
    const host = box.querySelector('.tl-hero');
    const W = host.clientWidth || 900;
    const iw = Math.max(10, W - PAD.left - PAD.right);
    const ih = Math.max(10, HERO_H - PAD.top - PAD.bottom);
    const ticks = niceTicks(rows.reduce((m, r) => Math.max(m, r.total || 0), 0));
    const top = ticks[ticks.length - 1] || 1;
    const x = (i) => PAD.left + (rows.length === 1 ? iw / 2 : (i * iw) / (rows.length - 1));
    const y = (v) => PAD.top + ih - ((v || 0) / top) * ih;
    const baseY = PAD.top + ih;

    const grid = ticks
      .map(
        (v) =>
          `<line class="tl-grid" x1="${PAD.left}" x2="${PAD.left + iw}" ` +
          `y1="${y(v).toFixed(1)}" y2="${y(v).toFixed(1)}"/>` +
          `<text class="tl-axis" x="${PAD.left - 6}" y="${(y(v) + 3.5).toFixed(1)}" ` +
          `text-anchor="end">${fmtNum(v)}</text>`
      )
      .join('');

    const rowY = baseY + 14;
    const xAxis = axisIndices(rows.length, iw)
      .map((i) => {
        // The edge marks are anchored inward; centred, the SVG box clips them.
        const anchor = i === 0 ? 'start' : i === rows.length - 1 ? 'end' : 'middle';
        return (
          `<text class="tl-axis" x="${x(i).toFixed(1)}" y="${rowY}" text-anchor="${anchor}">` +
          `${formatBucket(rows[i].day, state.bucket)}</text>`
        );
      })
      .join('');

    // Second row, hours only: which day each block of hours belongs to, plus a
    // tick at every midnight so the blocks are visibly separate.
    let dateRow = '';
    if (state.bucket === 'hour') {
      dateRow = dayBands(rows)
        .map((b) => {
          const mid = (x(b.from) + x(b.to)) / 2;
          const edge =
            b.from > 0
              ? `<line class="tl-daytick" x1="${x(b.from).toFixed(1)}" ` +
                `x2="${x(b.from).toFixed(1)}" y1="${PAD.top}" y2="${(baseY + 4).toFixed(1)}"/>`
              : '';
          return (
            edge +
            `<text class="tl-axis tl-axis--date" x="${mid.toFixed(1)}" y="${rowY + 12}" ` +
            `text-anchor="middle">${formatDay(b.day)}</text>`
          );
        })
        .join('');
    }

    host.innerHTML =
      `<svg class="tl-svg" viewBox="0 0 ${W} ${HERO_H}" role="img" ` +
      `aria-label="Total ${state.unit} per ${state.bucket}">` +
      grid +
      xAxis +
      dateRow +
      seriesShape(rows, 'total', x, y, baseY, 'var(--text)', 'tl-line tl-line--total') +
      `<line class="tl-cursor" x1="0" x2="0" y1="${PAD.top}" y2="${baseY}" style="display:none"/>` +
      `<rect class="tl-band" y="${PAD.top}" height="${ih}" width="0" style="display:none"/>` +
      `</svg>`;
    return { x, W, iw, ih };
  }

  /** One small multiple per group, each against its own maximum.
   *
   * The maximum is printed rather than read off an axis. That is the trade the
   * whole layout makes: five series cannot share one linear scale, so each gets
   * its own and says out loud what it is worth.
   */
  function renderMultiples(box, rows) {
    const state = box._tl;
    const host = box.querySelector('.tl-mults');
    host.innerHTML = state.series
      .map((s) => {
        const peak = rows.reduce((m, r) => Math.max(m, r[s.key] || 0), 0);
        return (
          `<div class="tl-mult" data-series="${s.key}">` +
          `<div class="tl-mult-head">` +
          `<span class="tl-mult-name" style="color:${s.color}">${s.label}</span>` +
          // Named, not bare. A bare number beside a group name is read as a
          // count of that group, and the filter chip one panel up carries
          // exactly that — distinct addresses. "Humans 3" sat beside
          // "Humans 8" with nothing saying one counts addresses and the other
          // counts visits in the busiest bucket. Both were right; the pair was
          // unreadable.
          `<span class="tl-mult-peak">peak ${fmtNum(peak)}/${state.bucket}</span>` +
          `</div><div class="tl-mult-plot"></div></div>`
        );
      })
      .join('');

    host.querySelectorAll('.tl-mult').forEach((cell, n) => {
      const s = state.series[n];
      const plot = cell.querySelector('.tl-mult-plot');
      const w = plot.clientWidth || 180;
      const ih = MULT_H - MULT_PAD.top - MULT_PAD.bottom;
      const peak = rows.reduce((m, r) => Math.max(m, r[s.key] || 0), 0) || 1;
      const x = (i) => (rows.length === 1 ? w / 2 : (i * w) / (rows.length - 1));
      const y = (v) => MULT_PAD.top + ih - ((v || 0) / peak) * ih;
      const baseY = MULT_PAD.top + ih;
      plot.innerHTML =
        `<svg class="tl-svg tl-svg--mult" viewBox="0 0 ${w} ${MULT_H}" role="img" ` +
        `aria-label="${s.label}, peak ${peak} ${state.unit} per ${state.bucket}">` +
        `<line class="tl-grid" x1="0" x2="${w}" y1="${baseY}" y2="${baseY}"/>` +
        seriesShape(rows, s.key, x, y, baseY, s.color, 'tl-line') +
        `<line class="tl-cursor" data-w="${w}" x1="0" x2="0" y1="${MULT_PAD.top}" ` +
        `y2="${baseY}" style="display:none"/></svg>`;
    });
  }

  function render(box) {
    const state = box._tl;
    const rows = state.view;
    const plot = box.querySelector('.timeline-plot');
    if (!plot) return;
    if (!rows.length) {
      plot.innerHTML = '<p class="text-muted">No activity in the selected range.</p>';
      state.geom = null;
      return;
    }
    if (!plot.querySelector('.tl-hero')) {
      plot.innerHTML = '<div class="tl-hero"></div><div class="tl-mults"></div>';
    }
    const hero = renderHero(box, rows);
    renderMultiples(box, rows);
    // What the reader is actually looking at, in words. Two disabled buttons
    // say a zoom is possible; they never said three days out of ninety.
    const readout = box.querySelector('.timeline-range');
    if (readout) {
      readout.textContent =
        formatBucketLong(rows[0].day, state.bucket) +
        ' – ' +
        formatBucketLong(rows[rows.length - 1].day, state.bucket);
    }
    state.geom = { x: hero.x, iw: hero.iw, W: hero.W, ih: hero.ih };
  }

  function showTip(box, i) {
    const state = box._tl;
    const row = state.view[i];
    if (!row || !state.geom) return;
    const tip = box.querySelector('.timeline-tip');
    const svg = box.querySelector('.tl-hero .tl-svg');
    if (!tip || !svg) return;

    // One cursor per chart, at the same bucket: what makes the hero and the
    // five bands read as one picture rather than six.
    const frac = state.view.length < 2 ? 0.5 : i / (state.view.length - 1);
    const heroX = state.geom.x(i);
    box.querySelectorAll('.tl-cursor').forEach((c) => {
      // data-w rather than the owning svg's viewBox: inline SVG written through
      // innerHTML is not an SVGElement everywhere, and reading .baseVal off it
      // throws in the jsdom the unit tests run in.
      const w = Number(c.dataset.w || 0);
      const px = w ? frac * w : heroX;
      c.setAttribute('x1', px);
      c.setAttribute('x2', px);
      c.style.display = '';
    });

    // Every series, every time — including the ones at zero. Filtering them out
    // made the humans row vanish on the 25 days it was empty, which reads as
    // "humans is not a category here" rather than as zero, and made the tooltip
    // change height as the cursor moved.
    // Under the comparison every figure carries its New half, because the gap
    // between the two is the thing being compared and reading it off the
    // picture is guesswork.
    const both = 'total_new' in row;
    const half = (k) => (both ? ` <em>${fmtNum(row[k + '_new'] || 0)} new</em>` : '');
    tip.innerHTML =
      `<strong>${formatBucketLong(row.day, state.bucket)}</strong>` +
      `<span class="tl-tip-total">${fmtNum(row.total)} ${state.unit}${half('total')}</span>` +
      state.series
        .map(
          (s) =>
            `<span class="tl-tip-row${row[s.key] ? '' : ' tl-tip-row--zero'}">` +
            `<span class="tl-tip-dot" style="background:${s.color}"></span>` +
            `${s.label}<strong>${fmtNum(row[s.key] || 0)}${half(s.key)}</strong></span>`
        )
        .join('');
    const rect = svg.getBoundingClientRect();
    const left = (heroX / state.geom.W) * rect.width;
    tip.style.left = Math.round(left) + 'px';
    tip.classList.toggle('tl-tip--flip', left > rect.width * 0.6);
    tip.style.display = '';
  }

  function hideTip(box) {
    const tip = box.querySelector('.timeline-tip');
    if (tip) tip.style.display = 'none';
    box.querySelectorAll('.tl-cursor').forEach((c) => {
      c.style.display = 'none';
    });
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
      // What this chart counts. The same renderer draws requests and distinct
      // addresses, and a tooltip saying "visits" over an address count is the
      // kind of wrong that looks right.
      unit: data.unit || 'visits',
      zoom: null,
      endpoint: box.dataset.endpoint || '',
      params: box.dataset.params || '',
      geom: null,
    };
    render(box);
    setZoomControls(box);

    try {
      if (localStorage.getItem('vidar.tl.dragged')) {
        const hint = box.querySelector('.timeline-hint');
        if (hint) hint.classList.add('timeline-hint--done');
      }
    } catch (err) {
      /* no storage: the hint stays, which is the harmless direction */
    }

    box.querySelectorAll('[data-zoom]').forEach((btn) => {
      btn.addEventListener('click', () => {
        if (btn.dataset.zoom === 'in') zoomIn(box);
        else zoomOut(box);
      });
    });

    const plot = box.querySelector('.timeline-plot');
    let dragFrom = null;
    // The chart the drag began on, so the release is measured against the same
    // one — a drag that starts on a small multiple and ends over the hero
    // otherwise reads its two ends off two different scales.
    let dragTarget = null;

    /** The bucket under the pointer, read off whichever chart it is over.
     *
     * A small multiple spans a fifth of the width and the whole x-domain, so
     * mapping its pointer through the hero's geometry would land five buckets
     * away from the one under the cursor. Each chart answers for itself.
     */
    const indexAt = (clientX, target) => {
      const state = box._tl;
      if (!state.geom) return 0;
      const mult = target && target.closest && target.closest('.tl-mult-plot');
      if (mult) {
        const r = mult.getBoundingClientRect();
        return bucketAt((clientX - r.left) / (r.width || 1) * 1000, 0, 1000, state.view.length);
      }
      const svg = box.querySelector('.tl-hero .tl-svg');
      if (!svg) return 0;
      const rect = svg.getBoundingClientRect();
      const scale = state.geom.W / rect.width;
      return bucketAt((clientX - rect.left) * scale, PAD.left, state.geom.iw, state.view.length);
    };

    plot.addEventListener('mousemove', (e) => {
      if (!box._tl.geom) return;
      const i = indexAt(e.clientX, e.target);
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
      dragFrom = indexAt(e.clientX, e.target);
      dragTarget = e.target;
    });
    document.addEventListener('mouseup', (e) => {
      if (dragFrom === null) return;
      const from = dragFrom;
      dragFrom = null;
      const band = box.querySelector('.tl-band');
      if (band) band.style.display = 'none';
      if (!box._tl.geom) return;
      const to = indexAt(e.clientX, dragTarget);
      dragTarget = null;
      if (Math.abs(to - from) < 1) return;
      applyZoom(box, from, to);
      // Taught once. A hint that stays after the reader has done the thing is
      // just a line of chrome on every later visit.
      const hint = box.querySelector('.timeline-hint');
      if (hint) hint.classList.add('timeline-hint--done');
      try {
        localStorage.setItem('vidar.tl.dragged', '1');
      } catch (err) {
        /* private mode, or storage refused — the hint simply shows again */
      }
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
