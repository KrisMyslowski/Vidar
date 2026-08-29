/** The behaviors that used to live in inline `onclick`/`onsubmit` attributes.
 *
 * A Content-Security-Policy without 'unsafe-inline' blocks inline event handler
 * attributes, and a nonce does not help there: nonces apply to <script>
 * elements, never to on* attributes. So each of them became a data attribute
 * plus a delegated listener here, which is also the reason this file can be
 * tested at all — tests/js/actions.test.js exercises exactly these decisions.
 *
 * Delegated from `document`, so rows and forms rendered into a fragment after
 * load are covered without rebinding.
 */
(function () {
  /* `↻ Refresh` — was onclick="location.reload()". */
  document.addEventListener('click', function (e) {
    const btn = e.target.closest('[data-reload]');
    if (!btn) return;
    e.preventDefault();
    location.reload();
  });

  /* Destructive settings forms — was onsubmit="return confirm('…')". The prompt
   * text is rendered into data-confirm by the template, autoescaped like any
   * other attribute, instead of being spliced into a JS string literal. */
  document.addEventListener('submit', function (e) {
    const form = e.target.closest('form[data-confirm]');
    if (!form) return;
    if (!confirm(form.getAttribute('data-confirm'))) e.preventDefault();
  });

  /* No date input may offer a day in the future. Was the last inline <script>
   * in base.html; moved here so only the pre-paint theme bootstrap stays inline
   * and needs a nonce. */
  function capDateInputs() {
    const today = new Date().toISOString().slice(0, 10);
    document.querySelectorAll('input[type="date"]').forEach(function (el) {
      el.max = today;
    });
  }
  // Both, deliberately. In the page this script is parser-blocking in <body>,
  // so the document is still loading and the listener does the work. Loaded any
  // other way — deferred, injected, or in a test — that event has already gone
  // by, and only the immediate call would run. Setting the same max twice costs
  // nothing; missing an input costs a filter that can ask for tomorrow.
  document.addEventListener('DOMContentLoaded', capDateInputs);
  if (document.readyState !== 'loading') capDateInputs();
})();
