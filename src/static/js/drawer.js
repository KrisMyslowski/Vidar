/* Slide-over for aggregation rows.
 * A row carrying data-drawer-src opens /visitors/rows as a fragment beside the
 * table instead of navigating — the drill-down stays a pill on the page below.
 * Links inside a row (the dimension itself, an IP) keep their normal behavior.
 *
 * A fragment may also sort and page itself. Its own links point back at its own
 * route, and are re-fetched into the panel rather than followed — see onNav.
 */
(function () {
  'use strict';

  var panel, backdrop, currentSrc, returnFocus;

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
    // A dialog needs a name, and focus has to be able to land on it: aria-modal
    // tells assistive technology that everything behind is inert, so leaving
    // focus back there put the reader somewhere they were told does not exist.
    panel.setAttribute('aria-label', 'Details');
    panel.tabIndex = -1;
    document.body.appendChild(backdrop);
    document.body.appendChild(panel);
  }

  /** Hide the drawer. Content stays, so reopening the same row is instant. */
  function close() {
    if (!panel || !panel.classList.contains('open')) return;
    panel.classList.remove('open');
    backdrop.classList.remove('open');
    // Back to whatever opened it, so a keyboard reader carries on down the table
    // from the row they were on rather than from the top of the page.
    if (returnFocus && returnFocus.isConnected) returnFocus.focus();
    returnFocus = null;
  }

  /** Fetch `src` into the panel, then run `done`.
   * A failed fetch says so in the panel: the drawer is already open by then, and
   * an empty one reads as "no IPs" rather than "this did not load". */
  function load(src, done) {
    currentSrc = src;
    fetch(src, { headers: { 'X-Requested-With': 'fetch' } })
      .then(function (r) {
        if (!r.ok) throw new Error(r.status);
        return r.text();
      })
      .then(function (html) {
        panel.innerHTML = html;
        if (done) done();
      })
      .catch(function () {
        // Not "these IPs": three fragments open in here and a fourth is coming,
        // and only one of them is a list of addresses.
        panel.innerHTML = '<div class="drawer-loading">Could not load this.</div>';
      });
  }

  /** Open the drawer on `src`, with a placeholder while it flies. */
  function open(src) {
    ensureShell();
    returnFocus = document.activeElement;
    panel.innerHTML = '<div class="drawer-loading">Loading…</div>';
    panel.classList.add('open');
    backdrop.classList.add('open');
    panel.focus({ preventScroll: true });
    load(src);
  }

  /** Re-fetch the open fragment with new parameters.
   * Not open(): the panel keeps what it is showing until the new markup
   * arrives, and the reader keeps their place. Blanking to "Loading…" would
   * throw the panel back to the top on every sort click, and a header clicked
   * halfway down a 266-row table is a header you want to stay next to.
   * Restored after innerHTML, not on a timer — the fetch resolves whenever it
   * resolves. */
  function reload(src) {
    var top = panel.scrollTop;
    load(src, function () {
      panel.scrollTop = top;
    });
  }

  /** The fragment's own sort and pager links, which must not navigate.
   * Recognised by where they point: a link back to the route the panel is
   * already showing is the panel asking itself for a different order or page.
   * Anything else in there — an address, a path — is a real link and is left
   * alone. Comparing the resolved path also means it does not matter whether
   * the fragment writes its route out or leaves the href relative. */
  function onNav(target) {
    if (!currentSrc) return null;
    var here = new URL(currentSrc, location.href);
    var url = new URL(target.getAttribute('href'), here);
    return url.pathname === here.pathname && url.origin === here.origin ? url : null;
  }

  document.addEventListener('click', function (e) {
    if (e.target.closest('[data-drawer-close]')) {
      close();
      return;
    }
    var link = e.target.closest('.drawer a[href]');
    if (link) {
      var url = onNav(link);
      if (url) {
        e.preventDefault();
        reload(url.toString());
      }
      return;
    }
    var row = e.target.closest('tr[data-drawer-src]');
    // Anchors and form controls inside the row keep doing their own thing.
    if (!row || e.target.closest('a, button, input, label, summary')) return;
    open(row.dataset.drawerSrc);
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      close();
      return;
    }
    // A row opens from the keyboard the way it opens from a click. The rows carry
    // tabindex="0" in their templates; before that the incident, finding and
    // session panels could not be reached without a mouse at all. Only the row
    // itself: Enter on a link inside it follows the link.
    if (e.key !== 'Enter' && e.key !== ' ') return;
    var row = e.target;
    if (!row.matches || !row.matches('tr[data-drawer-src]')) return;
    e.preventDefault();
    open(row.dataset.drawerSrc);
  });
})();
