import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { domReady, loadScript } from './helpers.js';

describe('columns.js — per-table column visibility', () => {
  beforeAll(() => loadScript('columns.js'));

  beforeEach(() => {
    window.localStorage.clear();
    document.body.innerHTML = `
      <div class="table-block" data-table-key="t1">
        <label><input type="checkbox" data-col-toggle="isp" checked></label>
        <table>
          <thead><tr><th data-col="ip" class="c-ip">IP</th><th data-col="isp" class="c-text">ISP</th></tr></thead>
          <tbody><tr><td data-col="ip">1.2.3.4</td><td data-col="isp">ACME</td></tr></tbody>
        </table>
      </div>`;
  });

  const box = () => document.querySelector('[data-col-toggle="isp"]');
  const cells = () => [...document.querySelectorAll('td[data-col="isp"]')];
  const header = () => document.querySelector('th[data-col="isp"]');

  function uncheck() {
    box().checked = false;
    box().dispatchEvent(new window.Event('change', { bubbles: true }));
  }

  it('hides the cells when a column is switched off', () => {
    domReady();
    uncheck();
    expect(cells()[0].style.display).toBe('none');
  });

  it('takes the header with the cells', () => {
    // Tables are table-layout:fixed and read their widths from the header row,
    // so the <th> IS the column width. Leaving it behind would keep the width
    // and shift every row one column against its heading.
    domReady();
    uncheck();
    expect(header().style.display).toBe('none');
  });

  it('gives the column back on re-check, header included', () => {
    domReady();
    uncheck();
    box().checked = true;
    box().dispatchEvent(new window.Event('change', { bubbles: true }));
    expect(header().style.display).toBe('');
    expect(cells()[0].style.display).toBe('');
  });

  it('remembers the choice for that table', () => {
    domReady();
    uncheck();
    expect(JSON.parse(window.localStorage.getItem('vidar.cols.t1'))).toEqual(['isp']);
  });

  it('restores the hidden set on the next page load', () => {
    window.localStorage.setItem('vidar.cols.t1', JSON.stringify(['isp']));
    domReady();
    expect(cells()[0].style.display).toBe('none');
    expect(box().checked).toBe(false);
  });

  it("starts with the template's default-off columns hidden", () => {
    document.body.innerHTML = `
      <div class="table-block" data-table-key="t2">
        <label><input type="checkbox" data-col-toggle="isp" checked></label>
        <label><input type="checkbox" data-col-toggle="os" data-col-default-off></label>
        <table>
          <thead><tr><th data-col="isp" class="c-text">ISP</th><th data-col="os" class="c-client">OS</th></tr></thead>
          <tbody><tr><td data-col="isp">ACME</td><td data-col="os">Windows</td></tr></tbody>
        </table>
      </div>`;
    domReady();
    expect(document.querySelector('td[data-col="os"]').style.display).toBe('none');
    expect(document.querySelector('td[data-col="isp"]').style.display).toBe('');
  });

  it('lets a stored choice override the default', () => {
    window.localStorage.setItem('vidar.cols.t3', JSON.stringify([]));
    document.body.innerHTML = `
      <div class="table-block" data-table-key="t3">
        <label><input type="checkbox" data-col-toggle="os" data-col-default-off></label>
        <table>
          <thead><tr><th data-col="os" class="c-client">OS</th></tr></thead>
          <tbody><tr><td data-col="os">Windows</td></tr></tbody>
        </table>
      </div>`;
    domReady();
    // The user switched it back on; the template default must not win again.
    expect(document.querySelector('td[data-col="os"]').style.display).toBe('');
  });

  it('survives unreadable storage instead of breaking the table', () => {
    window.localStorage.setItem('vidar.cols.t1', 'not json');
    expect(() => domReady()).not.toThrow();
    expect(cells()[0].style.display).toBe('');
  });
});
