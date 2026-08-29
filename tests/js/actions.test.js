import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { click, loadScript } from './helpers.js';

/* These three behaviours were inline onclick/onsubmit attributes until the CSP
 * went in, and inline handlers are exactly what a script-src without
 * 'unsafe-inline' blocks — a nonce does not cover attribute handlers. Moving
 * them into a delegated listener is what makes them testable at all, so the
 * conversion is verified here rather than only in a browser. */
describe('actions.js — the behaviours that used to be inline handlers', () => {
  beforeAll(() => {
    loadScript('actions.js');
  });

  beforeEach(() => {
    document.body.innerHTML = '';
  });

  describe('[data-reload]', () => {
    it('reloads when the refresh button is clicked', () => {
      document.body.innerHTML = '<button data-reload>Refresh</button>';
      const reload = vi.fn();
      Object.defineProperty(window, 'location', {
        value: { reload }, writable: true, configurable: true,
      });

      click(document.querySelector('[data-reload]'));

      expect(reload).toHaveBeenCalledTimes(1);
    });

    it('ignores clicks on buttons that do not carry the attribute', () => {
      document.body.innerHTML = '<button class="btn-refresh">Not me</button>';
      const reload = vi.fn();
      Object.defineProperty(window, 'location', {
        value: { reload }, writable: true, configurable: true,
      });

      click(document.querySelector('button'));

      expect(reload).not.toHaveBeenCalled();
    });
  });

  describe('form[data-confirm]', () => {
    /** Submit and report whether the default (the actual POST) survived. */
    function submit(form) {
      const ev = new window.Event('submit', { bubbles: true, cancelable: true });
      form.dispatchEvent(ev);
      return !ev.defaultPrevented;
    }

    it('lets the delete through once confirmed', () => {
      document.body.innerHTML = '<form data-confirm="Delete 2026-08?"></form>';
      window.confirm = vi.fn(() => true);

      expect(submit(document.querySelector('form'))).toBe(true);
      expect(window.confirm).toHaveBeenCalledWith('Delete 2026-08?');
    });

    it('cancels the delete when the prompt is declined', () => {
      document.body.innerHTML = '<form data-confirm="Delete 2026-08?"></form>';
      window.confirm = vi.fn(() => false);

      expect(submit(document.querySelector('form'))).toBe(false);
    });

    it('does not prompt for a form without the attribute', () => {
      document.body.innerHTML = '<form></form>';
      window.confirm = vi.fn(() => false);

      expect(submit(document.querySelector('form'))).toBe(true);
      expect(window.confirm).not.toHaveBeenCalled();
    });
  });

  it('caps every date input at today, so no filter can ask for the future', () => {
    document.body.innerHTML = '<input type="date" id="a"><input type="date" id="b">';
    document.dispatchEvent(new window.Event('DOMContentLoaded'));

    const today = new Date().toISOString().slice(0, 10);
    expect(document.querySelector('#a').max).toBe(today);
    expect(document.querySelector('#b').max).toBe(today);
  });
});
