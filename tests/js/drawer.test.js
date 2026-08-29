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
});
