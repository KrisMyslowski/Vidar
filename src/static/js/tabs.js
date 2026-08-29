/* Client-side tab panels for blocks whose data is already on the page.
 * A [data-tabs] container holds [data-tab] buttons and [data-tab-panel] panels;
 * clicking a button shows the panel with the matching name. Used by the Top
 * block on the Overview, where all six datasets ship with the page — switching
 * must not cost a reload.
 */
(function () {
  'use strict';

  /** Show the panel called `name` and mark its button, inside one container.
   * Both loops run over the container, not the document: two tab blocks on the
   * same page must not switch each other. */
  function activate(container, name) {
    container.querySelectorAll('[data-tab]').forEach(function (btn) {
      btn.classList.toggle('active', btn.dataset.tab === name);
    });
    container.querySelectorAll('[data-tab-panel]').forEach(function (panel) {
      panel.hidden = panel.dataset.tabPanel !== name;
    });
  }

  document.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-tab]');
    if (!btn) return;
    var container = btn.closest('[data-tabs]');
    if (!container) return;
    e.preventDefault();
    activate(container, btn.dataset.tab);
  });

  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('[data-tabs]').forEach(function (container) {
      var first = container.querySelector('[data-tab].active') || container.querySelector('[data-tab]');
      if (first) activate(container, first.dataset.tab);
    });
  });
})();
