import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { click, domReady, loadScript } from './helpers.js';

describe('tabs.js — Top panel switching', () => {
  beforeAll(() => loadScript('tabs.js'));

  beforeEach(() => {
    document.body.innerHTML = `
      <div data-tabs>
        <button class="tab active" data-tab="a">A</button>
        <button class="tab" data-tab="b">B</button>
        <div data-tab-panel="a">panel a</div>
        <div data-tab-panel="b" hidden>panel b</div>
      </div>`;
    domReady();
  });

  const panel = (n) => document.querySelector(`[data-tab-panel="${n}"]`);
  const tab = (n) => document.querySelector(`[data-tab="${n}"]`);

  it('shows only the active panel on load', () => {
    expect(panel('a').hidden).toBe(false);
    expect(panel('b').hidden).toBe(true);
  });

  it('swaps panel and active state on click', () => {
    click(tab('b'));
    expect(panel('a').hidden).toBe(true);
    expect(panel('b').hidden).toBe(false);
    expect(tab('b').classList.contains('active')).toBe(true);
    expect(tab('a').classList.contains('active')).toBe(false);
  });

  it('leaves other tab groups alone', () => {
    document.body.insertAdjacentHTML('beforeend', `
      <div data-tabs>
        <button class="tab active" data-tab="x">X</button>
        <div data-tab-panel="x">other</div>
      </div>`);
    click(tab('b'));
    expect(document.querySelector('[data-tab-panel="x"]').hidden).toBe(false);
  });
});
