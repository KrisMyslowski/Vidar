/**
 * Dynamic "+N" overflow for multi-value table cells.
 *
 * Each `.cell-overflow` holds its items (chips/badges) on a single line. When
 * the cell is too narrow to show them all, trailing items are hidden and a teal
 * `[+N]` chip is appended whose tooltip lists the hidden items. Hiding is
 * preferred over truncating, but the last item standing may ellipsise so the
 * chip beside it stays whole. Recomputed on load and on resize; on the mobile
 * card layout (≤1100px) every item is shown.
 *
 * Markup contract (rendered by the overflow_cell macro):
 *   <span class="cell-overflow">
 *     <span class="badge …">item</span> …
 *   </span>
 */
(function () {
  var MOBILE = window.matchMedia('(max-width: 1100px)');

  function items(cell) {
    return Array.prototype.filter.call(cell.children, function (el) {
      return !el.classList.contains('ov-more');
    });
  }

  function tipFor(hidden) {
    return hidden
      .map(function (el) { return (el.textContent || '').trim(); })
      .filter(Boolean)
      .join(', ');
  }

  function fit(cell) {
    var els = items(cell);
    // Reset to the full, un-collapsed state first.
    els.forEach(function (el) {
      el.style.display = '';
      el.classList.remove('ov-shrink');
    });
    var more = cell.querySelector(':scope > .ov-more');
    if (more) more.remove();

    if (MOBILE.matches || els.length === 0) return;
    if (cell.scrollWidth <= cell.clientWidth) return; // everything fits

    // Phase 1 — hide trailing items (none shrink yet) and append a +N chip,
    // until the row fits or only one item is left.
    more = document.createElement('span');
    more.className = 'badge badge-teal label-help ov-more';
    cell.appendChild(more);

    var hidden = [];
    var visible = els.length;
    while (visible > 1 && cell.scrollWidth > cell.clientWidth) {
      var el = els[visible - 1];
      el.style.display = 'none';
      hidden.unshift(el);
      visible--;
      more.textContent = '+' + hidden.length;
      more.setAttribute('data-tip', tipFor(hidden));
    }
    if (hidden.length === 0) more.remove();

    // Phase 2 — nothing left to hide but it still does not fit. Let the last
    // visible item ellipsise: being cut mid-glyph reads as a rendering fault,
    // and it was the +N chip beside it that got clipped instead of the text.
    if (cell.scrollWidth > cell.clientWidth) {
      var last = els[visible - 1];
      if (last) last.classList.add('ov-shrink');
    }
  }

  function fitAll() {
    document.querySelectorAll('.cell-overflow').forEach(fit);
  }

  document.addEventListener('DOMContentLoaded', fitAll);

  var t;
  window.addEventListener('resize', function () {
    clearTimeout(t);
    t = setTimeout(fitAll, 120);
  });
  // Re-fit when crossing the mobile/desktop boundary.
  (MOBILE.addEventListener ? MOBILE.addEventListener('change', fitAll) : MOBILE.addListener(fitAll));
})();
