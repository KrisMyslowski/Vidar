/* Runs inside /visitors?view=timeline. Drives the activity chart the way a
 * reader does — hover, drag, drag again, zoom back out — and reports what each
 * step produced.
 *
 * It used to run on the Overview, where the chart lived until it moved to the
 * timeline view to answer for the current selection. The suite needs a headless
 * browser and had never actually run anywhere, so nothing noticed. */
(async () => {
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const box = document.querySelector('.timeline');
  if (!box) return { missing: true };
  const plot = box.querySelector('.timeline-plot');

  const state = () => {
    const line = box.querySelector('.tl-svg polyline');
    const labels = [...box.querySelectorAll('.tl-axis')].map((t) => t.textContent);
    return {
      lines: box.querySelectorAll('.tl-svg polyline').length,
      buckets: line ? line.getAttribute('points').trim().split(/\s+/).length : 0,
      xLabels: labels.filter((t) => /[.:]/.test(t)),
      // Zoomed in is "the way out is available". The chip this used to read is
      // gone; the zoombar's out button carries the same fact as `disabled`,
      // which is also the honest state at either end.
      zoomedIn: !box.querySelector('.timeline-zoombar [data-zoom="out"]').disabled,
    };
  };

  const drag = async (fromFrac, toFrac, settle) => {
    const b = plot.getBoundingClientRect();
    const x0 = b.x + b.width * fromFrac;
    const x1 = b.x + b.width * toFrac;
    const y = b.y + b.height / 2;
    plot.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, button: 0, clientX: x0, clientY: y }));
    plot.dispatchEvent(new MouseEvent('mousemove', { bubbles: true, clientX: x1, clientY: y }));
    document.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, clientX: x1, clientY: y }));
    await wait(settle);
  };

  await wait(400);
  const out = { initial: state() };

  // Hover: the tooltip has to name every series that has a value, plus the total.
  const b = plot.getBoundingClientRect();
  plot.dispatchEvent(
    new MouseEvent('mousemove', { bubbles: true, clientX: b.x + b.width / 2, clientY: b.y + 40 })
  );
  await wait(80);
  const tip = box.querySelector('.timeline-tip');
  out.tooltip = {
    shown: tip.style.display !== 'none',
    text: tip.textContent.replace(/\s+/g, ' ').trim(),
    rows: tip.querySelectorAll('.tl-tip-row').length,
  };
  out.cursorShown = box.querySelector('.tl-cursor').style.display !== 'none';

  await drag(0.3, 0.5, 250);
  out.afterDrag = state();

  // A short window: days would be single points, so the chart asks for hours.
  await drag(0.45, 0.52, 1200);
  out.afterShortDrag = state();

  // Each step out undoes one step in, so two drags need two clicks.
  const out_btn = () => box.querySelector('.timeline-zoombar [data-zoom="out"]');
  for (let i = 0; i < 2 && !out_btn().disabled; i++) {
    out_btn().click();
    await wait(250);
  }
  out.afterReset = state();

  // Nothing may stick out of the panel it lives in.
  const panel = box.closest('.panel').getBoundingClientRect();
  const svg = box.querySelector('.tl-svg').getBoundingClientRect();
  out.fits = svg.left >= panel.left - 1 && svg.right <= panel.right + 1;
  return out;
})()
