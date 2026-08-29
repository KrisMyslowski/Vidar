/* "Table ⇄" switch on a chart card: swaps the bar view for the same numbers as
 * a plain table. Both are already in the DOM, so the toggle is a visibility
 * flip — every distribution stays readable without relying on color alone.
 */
(function () {
  'use strict';

  document.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-viz-toggle]');
    if (!btn) return;
    var card = btn.closest('[data-viz]');
    if (!card) return;
    var bars = card.querySelector('[data-viz-bars]');
    var table = card.querySelector('[data-viz-table]');
    if (!bars || !table) return;
    var showTable = table.hidden;
    table.hidden = !showTable;
    bars.hidden = showTable;
    btn.classList.toggle('active', showTable);
    btn.setAttribute('aria-pressed', String(showTable));
  });
})();
