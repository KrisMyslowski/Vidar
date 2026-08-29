/**
 * Inline-SVG sparklines for stat cards (overview KPI row).
 *
 * Markup contract (rendered by the stat_card macro): a .card with a
 * data-spark="1,2,3" attribute and an empty .card-spark container. One thin
 * accent line, no grid/axes, the latest point marked. Re-rendered on
 * themechange so the stroke follows the accent token. Numbers only — no
 * user-controlled strings reach innerHTML.
 */
(function () {
  function render() {
    document.querySelectorAll('[data-spark]').forEach((card) => {
      const box = card.querySelector('.card-spark');
      if (!box) return;
      // Blanks are dropped before Number() sees them: Number('') is 0, not NaN,
      // so a stray comma used to survive the isNaN filter and draw a dip to the
      // baseline that no data point stands behind.
      const vals = card.dataset.spark
        .split(',')
        .filter((s) => s.trim() !== '')
        .map(Number)
        .filter((v) => !isNaN(v));
      if (vals.length < 2) { box.innerHTML = ''; return; }

      const W = 120, H = 28, P = 2;
      const max = Math.max(...vals), min = Math.min(...vals);
      const x = (i) => P + (i * (W - 2 * P)) / (vals.length - 1);
      const y = (v) => (max === min ? H / 2 : H - P - ((v - min) * (H - 2 * P)) / (max - min));
      const pts = vals.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ');
      const lastX = x(vals.length - 1).toFixed(1);
      const lastY = y(vals[vals.length - 1]).toFixed(1);
      const stroke = cssVar('accent-soft') || cssVar('accent');

      box.innerHTML =
        `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" aria-hidden="true">` +
        `<polyline points="${pts}" fill="none" stroke="${stroke}" stroke-width="1.5"/>` +
        `<circle cx="${lastX}" cy="${lastY}" r="2" fill="${cssVar('accent')}"/>` +
        `</svg>`;
    });
  }

  document.addEventListener('DOMContentLoaded', render);
  document.addEventListener('themechange', render);
})();
