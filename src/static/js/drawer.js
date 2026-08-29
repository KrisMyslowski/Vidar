/* Slide-over for aggregation rows.
 * A row carrying data-drawer-src opens /visitors/rows as a fragment beside the
 * table instead of navigating — the drill-down stays a pill on the page below.
 * Links inside a row (the dimension itself, an IP) keep their normal behavior.
 */
(function () {
  'use strict';

  var panel, backdrop;

  /** Build the panel and its backdrop once, and re-build if they were detached. */
  function ensureShell() {
    // isConnected, not just truthiness: if the shell was ever detached from the
    // document, the cached reference would keep receiving content nobody sees.
    if (panel && panel.isConnected) return;
    backdrop = document.createElement('div');
    backdrop.className = 'drawer-backdrop';
    backdrop.addEventListener('click', close);
    panel = document.createElement('aside');
    panel.className = 'drawer';
    panel.setAttribute('role', 'dialog');
    panel.setAttribute('aria-modal', 'true');
    document.body.appendChild(backdrop);
    document.body.appendChild(panel);
  }

  /** Hide the drawer. Content stays, so reopening the same row is instant. */
  function close() {
    if (!panel) return;
    panel.classList.remove('open');
    backdrop.classList.remove('open');
  }

  /** Open the drawer and load `src` into it, with a placeholder while it flies.
   * A failed fetch says so in the panel: the drawer is already open by then, and
   * an empty one reads as "no IPs" rather than "this did not load". */
  function open(src) {
    ensureShell();
    panel.innerHTML = '<div class="drawer-loading">Loading…</div>';
    panel.classList.add('open');
    backdrop.classList.add('open');
    fetch(src, { headers: { 'X-Requested-With': 'fetch' } })
      .then(function (r) {
        if (!r.ok) throw new Error(r.status);
        return r.text();
      })
      .then(function (html) {
        panel.innerHTML = html;
      })
      .catch(function () {
        panel.innerHTML = '<div class="drawer-loading">Could not load these IPs.</div>';
      });
  }

  document.addEventListener('click', function (e) {
    if (e.target.closest('[data-drawer-close]')) {
      close();
      return;
    }
    var row = e.target.closest('tr[data-drawer-src]');
    // Anchors and form controls inside the row keep doing their own thing.
    if (!row || e.target.closest('a, button, input, label, summary')) return;
    open(row.dataset.drawerSrc);
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') close();
  });
})();
