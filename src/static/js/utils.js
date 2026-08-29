/** Shared JS utilities used by map.js, sparkline.js and tooltip.js. */

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue('--' + name).trim();
}

/** Convert a CSS color variable to an 8-digit hex with alpha (e.g. #ef4444b3 for 0.7). */
function cssColor(name, alpha) {
  const hex = cssVar(name);
  const a = Math.round(alpha * 255).toString(16).padStart(2, '0');
  return hex + a;
}

/**
 * Group a number the way the server does.
 *
 * fmtnum() in template_filters.py uses Python's `,` format spec, which is fixed
 * whatever the locale. Formatting without naming one follows the viewer's
 * browser instead, so the same page showed 1,234 in a table cell and 1.234 in
 * the map legend. The dashboard is English throughout; the server's convention
 * wins, and test_assets.py keeps this the only formatter.
 */
function fmtNum(n) {
  return Number(n || 0).toLocaleString('en-US');
}

/** Safely escape a string for insertion into HTML content. */
function esc(text) {
  const el = document.createElement('span');
  el.textContent = text || '';
  return el.innerHTML;
}
