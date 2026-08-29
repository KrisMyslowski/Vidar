/**
 * Client-side table sorting. Add class="sortable" to any <table> to enable.
 * Click a <th> to toggle ascending/descending sort on that column.
 * Handles dd.mm.yy dates, numbers, and strings.
 */
(function () {
  /**
   * Parse cell text into a sortable value.
   * Dates (dd.mm.yy HH:MM) -> "20YYMMDD HH:MM" string
   * Numbers -> float
   * Blank/dash -> sorts last
   */
  function parseVal(text) {
    text = text.trim();
    if (text === '—' || text === '') return '\uffff';
    // Convert dd.mm.yy HH:MM to sortable ISO-like string
    var dm = text.match(/^(\d{2})\.(\d{2})\.(\d{2})\s+(\d{2}:\d{2})$/);
    if (dm) return '20' + dm[3] + dm[2] + dm[1] + dm[4];
    var n = parseFloat(text.replace(/,/g, ''));
    if (!isNaN(n)) return n;
    return text.toLowerCase();
  }

  /** Sort table rows by column index. Reorders <tbody> rows in-place. */
  function sortTable(table, colIdx, asc) {
    var tbody = table.querySelector('tbody');
    if (!tbody) return;
    var rows = Array.from(tbody.querySelectorAll('tr'));
    rows.sort(function (a, b) {
      var va = parseVal(a.cells[colIdx] ? a.cells[colIdx].textContent : '');
      var vb = parseVal(b.cells[colIdx] ? b.cells[colIdx].textContent : '');
      if (typeof va === 'number' && typeof vb === 'number') return asc ? va - vb : vb - va;
      var sa = String(va), sb = String(vb);
      return asc ? sa.localeCompare(sb) : sb.localeCompare(sa);
    });
    rows.forEach(function (r) { tbody.appendChild(r); });
  }

  // Delegate click handler: any <th> inside a table.sortable triggers sort
  document.addEventListener('click', function (e) {
    var th = e.target.closest('th');
    if (!th) return;
    var table = th.closest('table.sortable');
    if (!table) return;

    // If this table uses server-side sorting (paginated), don't perform client-side reordering.
    if (table.classList.contains('server-sort')) return;

    var thead = th.closest('thead');
    if (!thead) return;
    var ths = Array.from(thead.querySelectorAll('th'));
    var colIdx = ths.indexOf(th);
    if (colIdx < 0) return;

    // Toggle direction: if already ascending, switch to descending
    var wasAsc = th.classList.contains('sort-asc');
    ths.forEach(function (t) { t.classList.remove('sort-asc', 'sort-desc'); });
    var asc = !wasAsc;
    th.classList.add(asc ? 'sort-asc' : 'sort-desc');
    sortTable(table, colIdx, asc);
  });
})();
