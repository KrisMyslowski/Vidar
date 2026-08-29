import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { domReady, loadScript } from './helpers.js';

/* jsdom has no layout, so the cell's widths are simulated: clientWidth is the
 * budget, scrollWidth the sum of what is currently visible. That keeps the real
 * decisions under test — which items get hidden, when the +N chip appears, and
 * which item is allowed to ellipsise. */
describe('overflow.js — [+N] for multi-value cells', () => {
  beforeAll(() => {
    window.matchMedia = (q) => ({
      matches: false, media: q, addEventListener() {}, removeEventListener() {}, addListener() {},
    });
    loadScript('overflow.js');
  });

  /** Build a cell whose items have the given widths, inside `budget` pixels. */
  function cell(widths, budget) {
    document.body.innerHTML = '<span class="cell-overflow"></span>';
    const el = document.querySelector('.cell-overflow');
    widths.forEach((w, i) => {
      const item = document.createElement('span');
      item.className = 'badge';
      item.textContent = `item${i}`;
      Object.defineProperty(item, '_w', { value: w, writable: true });
      el.appendChild(item);
    });
    Object.defineProperty(el, 'clientWidth', { get: () => budget });
    Object.defineProperty(el, 'scrollWidth', {
      get: () =>
        [...el.children].reduce((sum, c) => {
          if (c.style.display === 'none') return sum;
          // A shrunken item is allowed to give way; the chip never does.
          if (c.classList.contains('ov-shrink')) return sum + 20;
          return sum + (c._w ?? 24);
        }, 0),
    });
    return el;
  }

  const visible = (el) => [...el.children].filter((c) => c.style.display !== 'none');
  const more = (el) => el.querySelector('.ov-more');

  beforeEach(() => { document.body.innerHTML = ''; });

  it('leaves a cell alone when everything fits', () => {
    const el = cell([20, 20], 100);
    domReady();
    expect(more(el)).toBe(null);
    expect(visible(el)).toHaveLength(2);
  });

  it('hides trailing items and counts them', () => {
    // 3×40 = 120 over a 100 budget. Hiding one leaves 40+40+24(chip) = 104,
    // still over, so two go — the chip's own width counts against the budget.
    const el = cell([40, 40, 40], 100);
    domReady();
    expect(more(el).textContent).toBe('+2');
    expect(visible(el).filter((c) => !c.classList.contains('ov-more'))).toHaveLength(1);
  });

  it('lists the hidden items in the chip tooltip', () => {
    const el = cell([40, 40, 40], 100);
    domReady();
    expect(more(el).dataset.tip).toContain('item2');
  });

  it('never leaves the column empty', () => {
    const el = cell([500, 500, 500], 40);
    domReady();
    const shown = visible(el).filter((c) => !c.classList.contains('ov-more'));
    expect(shown.length).toBeGreaterThanOrEqual(1);
  });

  it('ellipsises the last item standing rather than clipping the +N chip', () => {
    // One very wide item plus more: the chip has to survive whole, so the item
    // beside it is the thing that gives way.
    const el = cell([500, 40, 40], 60);
    domReady();
    expect(more(el)).not.toBe(null);
    expect(more(el).textContent).toBe('+2');
    expect(el.children[0].classList.contains('ov-shrink')).toBe(true);
  });

  it('ellipsises a lone oversized item even without a chip', () => {
    const el = cell([500], 60);
    domReady();
    expect(more(el)).toBe(null); // nothing was hidden, so nothing to count
    expect(el.children[0].classList.contains('ov-shrink')).toBe(true);
  });

  it('starts from a clean slate on every fit', () => {
    const el = cell([40, 40, 40], 100);
    domReady();
    expect(more(el).textContent).toBe('+2');
    domReady(); // a second pass must not compound the previous one
    expect(el.querySelectorAll('.ov-more')).toHaveLength(1);
    expect(more(el).textContent).toBe('+2');
  });
});
