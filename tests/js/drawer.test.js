import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { click, loadScript } from './helpers.js';

describe('drawer.js — the slide-over behind an aggregation row', () => {
  beforeAll(() => loadScript('drawer.js'));

  beforeEach(() => {
    document.body.innerHTML = `
      <table><tbody>
        <tr data-drawer-src="/visitors/rows?asn=AS1">
          <td><a href="/visitors?asn=AS1" id="dim">AS1</a></td>
          <td id="plain">555</td>
        </tr>
      </tbody></table>`;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    document.querySelectorAll('.drawer, .drawer-backdrop').forEach((el) => el.remove());
  });

  function stubFetch(body = '<p>rows</p>') {
    const fetchMock = vi.fn(() => Promise.resolve({ ok: true, text: () => Promise.resolve(body) }));
    vi.stubGlobal('fetch', fetchMock);
    return fetchMock;
  }

  const panel = () => document.querySelector('.drawer');

  it('fetches the row fragment and opens', async () => {
    const fetchMock = stubFetch('<p>the IPs</p>');
    click(document.getElementById('plain'));
    expect(fetchMock).toHaveBeenCalledWith('/visitors/rows?asn=AS1', expect.anything());
    await vi.waitFor(() => expect(panel().innerHTML).toContain('the IPs'));
    expect(panel().classList.contains('open')).toBe(true);
  });

  it('leaves links alone so a row stays navigable', () => {
    const fetchMock = stubFetch();
    click(document.getElementById('dim'));
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('closes on Escape', async () => {
    stubFetch();
    click(document.getElementById('plain'));
    await vi.waitFor(() => expect(panel().classList.contains('open')).toBe(true));
    document.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    expect(panel().classList.contains('open')).toBe(false);
  });

  describe('from the keyboard', () => {
    // The rows were reachable by mouse only: no tabindex, no key handler. The
    // incident, finding and session panels could not be opened without one.
    const row = () => document.querySelector('tr[data-drawer-src]');
    const press = (el, key) =>
      el.dispatchEvent(new window.KeyboardEvent('keydown', { key, bubbles: true }));

    it('opens on Enter and on Space from the focused row', async () => {
      for (const key of ['Enter', ' ']) {
        const fetchMock = stubFetch('<p>opened</p>');
        row().setAttribute('tabindex', '0');
        row().focus();
        press(row(), key);
        expect(fetchMock).toHaveBeenCalledWith('/visitors/rows?asn=AS1', expect.anything());
        await vi.waitFor(() => expect(panel().classList.contains('open')).toBe(true));
        press(document, 'Escape');
      }
    });

    it('ignores Enter on a link inside the row, which follows itself', () => {
      const fetchMock = stubFetch();
      press(document.getElementById('dim'), 'Enter');
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('moves focus into the panel, and back to the row on close', async () => {
      stubFetch('<p>opened</p>');
      row().setAttribute('tabindex', '0');
      row().focus();
      press(row(), 'Enter');
      await vi.waitFor(() => expect(document.activeElement).toBe(panel()));
      expect(panel().getAttribute('aria-label')).toBeTruthy();
      press(document, 'Escape');
      expect(document.activeElement).toBe(row());
    });
  });

  it('says so when the fragment cannot be loaded', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('offline'))));
    click(document.getElementById('plain'));
    await vi.waitFor(() => expect(panel().textContent).toContain('Could not load'));
  });

  it('reports a failing response instead of showing an error page', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({ ok: false, status: 500 })));
    click(document.getElementById('plain'));
    await vi.waitFor(() => expect(panel().textContent).toContain('Could not load'));
  });

  // A fragment that sorts and pages itself (/incidents/case) links back at its
  // own route. Those links must move the panel; every other link in there is a
  // real one and must still leave the page.
  describe('a fragment that sorts and pages itself', () => {
    const openOn = async (src, body) => {
      document.body.innerHTML = `<table><tbody><tr data-drawer-src="${src}"><td id="cell">x</td></tr></tbody></table>`;
      stubFetch(body);
      click(document.getElementById('cell'));
      await vi.waitFor(() => expect(panel().innerHTML).toContain('id="sort"'));
    };
    const fragment =
      '<a id="sort" href="/incidents/case?page=2&sort=path&sig=abc">Path</a>' +
      '<a id="address" href="/visitors/203.0.113.1">203.0.113.1</a>';

    it('re-fetches a link back to its own route instead of navigating', async () => {
      await openOn('/incidents/case?sig=abc', fragment);
      const fetchMock = stubFetch('<a id="sort" href="#">sorted</a>');
      click(document.getElementById('sort'));
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining('/incidents/case?page=2&sort=path'),
        expect.anything(),
      );
      await vi.waitFor(() => expect(panel().textContent).toContain('sorted'));
      expect(panel().classList.contains('open')).toBe(true);
    });

    it('leaves a link that points somewhere else alone', async () => {
      await openOn('/incidents/case?sig=abc', fragment);
      const fetchMock = stubFetch();
      click(document.getElementById('address'));
      expect(fetchMock).not.toHaveBeenCalled();
    });
  });
});
