import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { click, loadScript } from './helpers.js';

describe('viz.js — "Table ⇄" switch', () => {
  beforeAll(() => loadScript('viz.js'));

  beforeEach(() => {
    document.body.innerHTML = `
      <div data-viz>
        <button data-viz-toggle>Table ⇄</button>
        <div data-viz-bars>bars</div>
        <div data-viz-table hidden>numbers</div>
      </div>`;
  });

  const btn = () => document.querySelector('[data-viz-toggle]');
  const bars = () => document.querySelector('[data-viz-bars]');
  const table = () => document.querySelector('[data-viz-table]');

  it('starts on the bars', () => {
    expect(bars().hidden).toBe(false);
    expect(table().hidden).toBe(true);
  });

  it('swaps to the table and back', () => {
    click(btn());
    expect(table().hidden).toBe(false);
    expect(bars().hidden).toBe(true);
    expect(btn().getAttribute('aria-pressed')).toBe('true');

    click(btn());
    expect(table().hidden).toBe(true);
    expect(bars().hidden).toBe(false);
    expect(btn().getAttribute('aria-pressed')).toBe('false');
  });
});
