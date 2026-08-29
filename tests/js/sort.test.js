import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { click, loadScript } from './helpers.js';

/* sort.js is the oldest file in the tree and had no test at all. Everything it
 * decides is a guess about cell text: that "12.05.26 09:30" is a date and not a
 * number, that "1,234" is a number and not a string, that an em dash sorts
 * last. Each of those is wrong for some column, so each is worth pinning. */
describe('sort.js — client-side table sorting', () => {
  beforeAll(() => loadScript('sort.js'));

  /** Build a one-column sortable table from cell texts. */
  function table(cells, { serverSort = false, head = 'Col' } = {}) {
    document.body.innerHTML = `
      <table class="sortable${serverSort ? ' server-sort' : ''}">
        <thead><tr><th>${head}</th></tr></thead>
        <tbody>${cells.map((c) => `<tr><td>${c}</td></tr>`).join('')}</tbody>
      </table>`;
    return document.querySelector('table');
  }

  const order = (t) => [...t.querySelectorAll('tbody td')].map((td) => td.textContent);
  const header = (t) => t.querySelector('th');

  beforeEach(() => { document.body.innerHTML = ''; });

  it('sorts strings case-insensitively on the first click', () => {
    const t = table(['banana', 'Apple', 'cherry']);
    click(header(t));
    expect(order(t)).toEqual(['Apple', 'banana', 'cherry']);
  });

  it('reverses on the second click', () => {
    const t = table(['banana', 'Apple', 'cherry']);
    click(header(t));
    click(header(t));
    expect(order(t)).toEqual(['cherry', 'banana', 'Apple']);
  });

  it('sorts numbers as numbers, not as text', () => {
    const t = table(['9', '10', '100']);
    click(header(t));
    expect(order(t)).toEqual(['9', '10', '100']);
  });

  it('reads a thousands separator as part of the number', () => {
    const t = table(['1,200', '999', '11,000']);
    click(header(t));
    expect(order(t)).toEqual(['999', '1,200', '11,000']);
  });

  it('sorts dd.mm.yy HH:MM chronologically across months and years', () => {
    const t = table(['05.01.26 09:00', '31.12.25 23:59', '05.01.26 08:00']);
    click(header(t));
    expect(order(t)).toEqual(['31.12.25 23:59', '05.01.26 08:00', '05.01.26 09:00']);
  });

  it('puts blanks and em dashes last, ascending', () => {
    const t = table(['zulu', '—', 'alpha']);
    click(header(t));
    expect(order(t)).toEqual(['alpha', 'zulu', '—']);
  });

  it('marks the direction on the header', () => {
    const t = table(['b', 'a']);
    click(header(t));
    expect(header(t).classList.contains('sort-asc')).toBe(true);
    click(header(t));
    expect(header(t).classList.contains('sort-desc')).toBe(true);
    expect(header(t).classList.contains('sort-asc')).toBe(false);
  });

  it('leaves a server-sorted table alone', () => {
    // Those tables are paginated: reordering the page in the browser would
    // shuffle one page of a larger ordering and claim it is sorted.
    const t = table(['b', 'a', 'c'], { serverSort: true });
    click(header(t));
    expect(order(t)).toEqual(['b', 'a', 'c']);
  });

  it('ignores a click outside a sortable table', () => {
    document.body.innerHTML = '<table><thead><tr><th>X</th></tr></thead>'
      + '<tbody><tr><td>b</td></tr><tr><td>a</td></tr></tbody></table>';
    const t = document.querySelector('table');
    click(t.querySelector('th'));
    expect(order(t)).toEqual(['b', 'a']);
  });

  it('survives a row that is missing the cell', () => {
    document.body.innerHTML = `
      <table class="sortable">
        <thead><tr><th>A</th><th>B</th></tr></thead>
        <tbody>
          <tr><td>x</td><td>2</td></tr>
          <tr><td>y</td></tr>
          <tr><td>z</td><td>1</td></tr>
        </tbody>
      </table>`;
    const t = document.querySelector('table');
    click(t.querySelectorAll('th')[1]);
    expect(t.querySelectorAll('tbody tr').length).toBe(3);
  });
});
