/* The accessibility basics a reader without a mouse or without sight depends on:
 * every control has a name, every field a label, every image an alt, nothing
 * clickable is a bare element outside the tab order, and no tabindex reorders
 * the page. Not an audit — what it checks, it checks on every page. */
(() => {
  const name = (el) => (el.getAttribute('aria-label') || el.getAttribute('title') || el.textContent || el.getAttribute('alt') || el.getAttribute('value') || '').trim();
  const labelled = (el) => {
    if (el.getAttribute('aria-label') || el.getAttribute('aria-labelledby') || el.getAttribute('title')) return true;
    if (el.id && document.querySelector(`label[for="${CSS.escape(el.id)}"]`)) return true;
    return !!el.closest('label');
  };
  const sel = (el) => el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + (typeof el.className === 'string' && el.className ? '.' + el.className.trim().split(/\s+/).slice(0, 2).join('.') : '');
  const visible = (el) => el.checkVisibility({ visibilityProperty: true });
  const out = { unnamed: [], unlabelled: [], noalt: [], clickNotControl: [], positiveTabindex: [] };
  for (const el of document.querySelectorAll('button, a[href], [role=button], summary')) {
    if (visible(el) && !name(el)) out.unnamed.push(sel(el));
  }
  for (const el of document.querySelectorAll('input:not([type=hidden]), select, textarea')) {
    if (visible(el) && !labelled(el) && !(el.placeholder && el.getAttribute('aria-label'))) out.unlabelled.push(sel(el) + (el.placeholder ? ` [placeholder="${el.placeholder}"]` : ''));
  }
  for (const el of document.querySelectorAll('img')) if (!el.hasAttribute('alt')) out.noalt.push(sel(el));
  for (const el of document.querySelectorAll('[data-action], [data-filter-value], [data-tab]')) {
    const t = el.tagName.toLowerCase();
    if (!['button', 'a', 'summary', 'input', 'select', 'tr'].includes(t) && el.tabIndex < 0 && visible(el)) out.clickNotControl.push(sel(el));
  }
  for (const el of document.querySelectorAll('[tabindex]')) if (el.tabIndex > 0) out.positiveTabindex.push(sel(el));
  for (const k of Object.keys(out)) out[k] = [...new Set(out[k])].slice(0, 6);
  // How much was read, so a page that rendered nothing cannot pass as clean.
  out.controls = document.querySelectorAll('button, a[href], [role=button], summary').length;
  return out;
})()
