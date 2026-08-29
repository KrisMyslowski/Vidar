/* The rich tooltip: one element, moved and refilled per hover.
 *
 * Two shapes. data-tip is a single line; data-tip-what plus data-tip-source is
 * the What/How pair the taxonomy chips and column headers use — a label that
 * says what a number means and where it comes from, which is most of what makes
 * this dashboard readable without the docs open.
 *
 * A single shared node rather than one per trigger: there are several hundred
 * tips on a full visitors page, and they only ever appear one at a time.
 */
document.addEventListener('DOMContentLoaded', () => {
  // esc is provided by utils.js loaded in base.html
  const tip = document.createElement('div');
  tip.className = 'rich-tooltip';
  document.body.appendChild(tip);

  /** Fill the tooltip for `el` and place it below, or above when it would go
   * off the bottom. Measured while hidden but displayed: the height is not
   * known until the content is in, and reading it before the paint avoids the
   * flash of a tooltip appearing in the wrong place first. */
  function show(el) {
    if (el.dataset.tipWhat) {
      tip.innerHTML =
        `<div class="rt-row"><span class="rt-label">What</span><span>${esc(el.dataset.tipWhat)}</span></div>` +
        `<div class="rt-row"><span class="rt-label">How</span><span>${esc(el.dataset.tipSource)}</span></div>`;
    } else {
      tip.innerHTML = `<div class="rt-row"><span>${esc(el.dataset.tip)}</span></div>`;
    }
    tip.style.visibility = 'hidden';
    tip.style.display = 'block';
    const rect = el.getBoundingClientRect();
    const tr   = tip.getBoundingClientRect();
    let top  = rect.bottom + window.scrollY + 8;
    if (rect.bottom + tr.height + 8 > window.innerHeight) {
      top = rect.top + window.scrollY - tr.height - 8;
    }
    let left = rect.left + window.scrollX;
    left = Math.min(left, window.innerWidth + window.scrollX - tr.width - 16);
    tip.style.top  = top + 'px';
    tip.style.left = Math.max(8, left) + 'px';
    tip.style.visibility = 'visible';
  }

  const SEL = '[data-tip-what], [data-tip]';

  document.addEventListener('mouseover', e => {
    const el = e.target.closest(SEL);
    if (el) show(el);
  });

  // Focus as well as hover. Every explanation in the dashboard was mouse-only:
  // the elements carry tabindex="0" precisely so they can be reached, and then
  // reaching them showed nothing. Touch gets the same benefit — a tap focuses.
  document.addEventListener('focusin', e => {
    const el = e.target.closest(SEL);
    if (el) show(el);
  });

  document.addEventListener('focusout', e => {
    if (e.target.closest(SEL)) tip.style.display = 'none';
  });

  document.addEventListener('mouseout', e => {
    const el = e.target.closest(SEL);
    if (!el) return;
    if (!e.relatedTarget || !el.contains(e.relatedTarget)) {
      tip.style.display = 'none';
    }
  });
});
