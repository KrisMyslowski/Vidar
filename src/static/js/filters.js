/* Generic multi-select filter bar for server-side filtered pages.
 * Handles two param types: ?class= (taxonomy) and ?signal= (enrichment flags).
 * Active state is server-rendered; JS only handles click → URL navigation.
 * Text inputs (country, ip, min_visits, port, q, status) in the filter bar are
 * read on chip-click so their current values survive navigation. The date
 * fields are not among them: they belong to the range tabs, which own the
 * window independently of the chips.
 */
(function () {
  'use strict';

  /** The URL for a filter state: class/signal params rebuilt from scratch, page
   * reset to 1, and the bar's text inputs carried along so a chip click does not
   * silently drop the country or date somebody typed. clearAll wipes both. */
  function buildFilterUrl(container, activeClasses, activeSignals, clearAll) {
    var url = new URL(window.location.href);
    url.searchParams.delete('class');
    url.searchParams.delete('signal');
    url.searchParams.set('page', '1');
    if (!clearAll) {
      activeClasses.forEach(function (c) { url.searchParams.append('class', c); });
      activeSignals.forEach(function (s) { url.searchParams.append('signal', s); });
      // Sync text input values from the bar so they survive chip navigation.
      // date_from/date_to are deliberately absent: they live in the range tabs,
      // outside this container, so querySelector never found them anyway — and
      // the window is not this control's to carry.
      ['country', 'ip', 'min_visits', 'port', 'q', 'status'].forEach(
        function (name) {
          var input = container.querySelector('[name="' + name + '"]');
          if (input) {
            if (input.value) url.searchParams.set(name, input.value);
            else url.searchParams.delete(name);
          }
        }
      );
    } else {
      // Clear-all drops the drill-downs and the search term, and keeps the
      // window. The range tabs are their own control — clearing the chips used
      // to silently throw away a custom date range the reader had set in a
      // different part of the page.
      ['country', 'ip', 'min_visits', 'port', 'q', 'status'].forEach(
        function (name) {
          url.searchParams.delete(name);
        }
      );
    }
    return url.toString();
  }

  /** Wire one filter bar. Active state comes from the URL, not the DOM — the
   * server rendered it, and reading it back keeps one source. */
  function initFilterBar(container) {
    if (!container) return;
    var allBtn = container.querySelector('.filter-toggle--all');
    var classToggles = Array.from(
      container.querySelectorAll('.filter-toggle[data-filter-value]')
    );
    var signalToggles = Array.from(
      container.querySelectorAll('.filter-toggle[data-signal-value]')
    );
    var params = new URL(window.location.href).searchParams;
    var activeClasses = params.getAll('class');
    var activeSignals = params.getAll('signal');

    if (allBtn) {
      allBtn.addEventListener('click', function () {
        window.location.href = buildFilterUrl(container, [], [], true);
      });
    }

    classToggles.forEach(function (toggle) {
      toggle.addEventListener('click', function () {
        var value = toggle.dataset.filterValue;
        if (!value) return;
        if (activeClasses.indexOf(value) === -1) {
          activeClasses = activeClasses.concat([value]);
        } else {
          activeClasses = activeClasses.filter(function (c) { return c !== value; });
        }
        window.location.href = buildFilterUrl(container, activeClasses, activeSignals, false);
      });
    });

    signalToggles.forEach(function (toggle) {
      toggle.addEventListener('click', function () {
        var value = toggle.dataset.signalValue;
        if (!value) return;
        if (activeSignals.indexOf(value) === -1) {
          activeSignals = activeSignals.concat([value]);
        } else {
          activeSignals = activeSignals.filter(function (s) { return s !== value; });
        }
        window.location.href = buildFilterUrl(container, activeClasses, activeSignals, false);
      });
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('.visitor-filter-bar').forEach(initFilterBar);
  });
})();
