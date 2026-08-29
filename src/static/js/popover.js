/* One open menu at a time.
 *
 * Classes, Signals, Export, Columns and the custom range are <details>
 * elements that position their panel absolutely. Nothing coordinated them, so
 * they all stayed open at once and the panels covered each other — Signals sat
 * on top of the class list and clipped its labels. A <details> also stays open
 * until its own summary is clicked again, which is not how a menu behaves.
 *
 * Marked with data-popover so this never reaches the <details> that are real
 * page content: the visitor detail map, the range form's own fields.
 */
(function () {
  'use strict';

  var SEL = '[data-popover]';

  /** Close every open popover except `keep` (pass null to close all). */
  function closeOthers(keep) {
    document.querySelectorAll(SEL + '[open]').forEach(function (el) {
      if (el !== keep) el.removeAttribute('open');
    });
  }

  document.addEventListener('click', function (e) {
    var menu = e.target.closest(SEL);
    // A click inside a menu belongs to that menu (a chip, a checkbox, a date
    // field); only a click outside every menu closes them.
    if (!menu) return closeOthers(null);
    // Opening is handled here rather than on the 'toggle' event, which the
    // browser fires asynchronously: two quick clicks queue two toggles, the
    // first one runs last and closes the menu the second click just opened —
    // the first menu wins instead of the one the reader asked for.
    if (e.target.closest('summary')) closeOthers(menu);
  });

  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    var open = document.querySelector(SEL + '[open]');
    if (!open) return;
    open.removeAttribute('open');
    var summary = open.querySelector('summary');
    if (summary) summary.focus();
  });
})();
