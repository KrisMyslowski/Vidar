/* Per-table column visibility for the column_picker block.
 * Columns are addressed by the data-col attribute on their <th>/<td>; the
 * hidden set is persisted per user under vidar.cols.<table_key>.
 * Hiding is display:none and nothing else. Tables use table-layout:fixed and
 * take their widths from the header row, so a hidden <th> takes its width with
 * it — there is no <colgroup> left to keep in step.
 */
(function () {
  'use strict';

  var PREFIX = 'vidar.cols.';

  /** The hidden-column list stored for one table, or [] if unreadable. */
  function readHidden(key) {
    try {
      var raw = localStorage.getItem(PREFIX + key);
      return raw ? JSON.parse(raw) : [];
    } catch (e) {
      return []; // unreadable storage: show everything rather than guess
    }
  }

  /** Persist one table's hidden-column list; a failure is not worth reporting. */
  function writeHidden(key, hidden) {
    try {
      localStorage.setItem(PREFIX + key, JSON.stringify(hidden));
    } catch (e) {
      /* storage unavailable (private mode) — visibility stays session-only */
    }
  }

  /** Show or hide every cell of one column, header included. */
  function applyColumn(block, col, hide) {
    block.querySelectorAll('[data-col="' + col + '"]').forEach(function (el) {
      el.style.display = hide ? 'none' : '';
    });
  }

  /** Restore one table's column choice and keep its checkboxes in step. */
  function initBlock(block) {
    var key = block.dataset.tableKey;
    if (!key) return;
    var stored = window.localStorage && localStorage.getItem(PREFIX + key);
    // No stored choice yet: fall back to the columns the template marked as
    // off — a first visit should see the readable table, not every column
    // squeezed to nothing. Once the user decides, their choice wins.
    var hidden = stored
      ? readHidden(key)
      : Array.prototype.map.call(
          block.querySelectorAll('[data-col-toggle][data-col-default-off]'),
          function (box) { return box.dataset.colToggle; }
        );

    hidden.forEach(function (col) { applyColumn(block, col, true); });

    block.querySelectorAll('[data-col-toggle]').forEach(function (box) {
      var col = box.dataset.colToggle;
      box.checked = hidden.indexOf(col) === -1;
      box.addEventListener('change', function () {
        var hide = !box.checked;
        applyColumn(block, col, hide);
        var idx = hidden.indexOf(col);
        if (hide && idx === -1) hidden.push(col);
        if (!hide && idx !== -1) hidden.splice(idx, 1);
        writeHidden(key, hidden);
      });
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('.table-block[data-table-key]').forEach(initBlock);
  });
})();
