import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { loadScript } from './helpers.js';

describe('popover.js — one open menu at a time', () => {
  beforeAll(() => loadScript('popover.js'));

  beforeEach(() => {
    document.body.innerHTML = `
      <div class="filter-rail">
        <details class="filter-disclosure" data-popover id="classes">
          <summary>Classes ▾</summary>
          <div class="filter-disclosure-menu"><button class="filter-toggle">humans</button></div>
        </details>
        <details class="filter-disclosure" data-popover id="signals">
          <summary>Signals ▾</summary>
          <div class="filter-disclosure-menu"><button class="filter-toggle">Tor</button></div>
        </details>
        <details class="col-picker" data-popover id="cols">
          <summary>Columns ▾</summary>
          <label><input type="checkbox" data-col-toggle="isp"> ISP</label>
        </details>
      </div>
      <table><tbody><tr><td id="outside">elsewhere</td></tr></tbody></table>`;
  });

  const el = (id) => document.getElementById(id);
  const click = (node) => node.dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  // Click the summary, as a reader does — the <details> opens itself.
  const open = (id) => click(el(id).querySelector('summary'));

  it('closes the other menu when one opens', () => {
    open('classes');
    expect(el('classes').open).toBe(true);
    open('signals');
    expect(el('signals').open).toBe(true);
    expect(el('classes').open).toBe(false);
  });

  it('closes every kind of menu, not just its own kind', () => {
    open('classes');
    open('cols');
    expect(el('classes').open).toBe(false);
    expect(el('cols').open).toBe(true);
  });

  it('lets the last click win when two arrive in the same tick', () => {
    // Closing on the 'toggle' event failed exactly here: the browser fires it
    // asynchronously, so the first click's handler ran last and closed the menu
    // the second click had just opened.
    click(el('classes').querySelector('summary'));
    click(el('signals').querySelector('summary'));
    expect(el('signals').open).toBe(true);
    expect(el('classes').open).toBe(false);
  });

  it('closes on a click outside', () => {
    open('signals');
    click(el('outside'));
    expect(el('signals').open).toBe(false);
  });

  it('stays open when clicking inside its own panel', () => {
    // Choosing a class or ticking a column must not dismiss the menu.
    open('cols');
    click(document.querySelector('[data-col-toggle]'));
    expect(el('cols').open).toBe(true);
  });

  it('closes on Escape and returns focus to its summary', () => {
    open('classes');
    document.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    expect(el('classes').open).toBe(false);
    expect(document.activeElement).toBe(el('classes').querySelector('summary'));
  });

  it('leaves a <details> that is page content alone', () => {
    // The visitor detail map lives in one; closing it on every stray click
    // would tear down the Leaflet instance it holds.
    document.body.insertAdjacentHTML('beforeend', '<details id="map" open><summary>Map</summary></details>');
    open('signals');
    click(el('outside'));
    expect(el('map').open).toBe(true);
  });
});
