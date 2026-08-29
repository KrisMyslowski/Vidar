/* The dashboard's scripts are plain <script> files, not modules: they wrap
 * themselves in an IIFE and bind to the document. To exercise one, evaluate its
 * source in the jsdom document the test just built, then fire the event it
 * waits for. */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const JS_DIR = join(dirname(fileURLToPath(import.meta.url)), '../../src/static/js');

/**
 * Evaluate a dashboard script against the current document.
 *
 * Call this once per test file (beforeAll), not per test: these modules bind
 * delegated listeners to `document`, so loading twice binds twice and every
 * click would be handled twice — a toggle would appear to do nothing.
 */
export function loadScript(name) {
  const src = readFileSync(join(JS_DIR, name), 'utf8');
  // Indirect eval keeps the script in global scope, the way a <script> tag runs.
  (0, eval)(src);
}

/** Fire the event the DOM-ready modules wait for. */
export function domReady() {
  document.dispatchEvent(new window.Event('DOMContentLoaded'));
}

/** Click that actually bubbles to the delegated document listeners. */
export function click(el) {
  el.dispatchEvent(new window.MouseEvent('click', { bubbles: true, cancelable: true }));
}
