import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { domReady, loadScript } from './helpers.js';

/* sparkline.js had no test. Three of its decisions only show up at the edges:
 * a series too short to draw a line from, a flat series that would divide by
 * zero on the y scale, and the themechange redraw that exists so the stroke
 * follows the accent token. */
describe('sparkline.js — inline SVG for stat cards', () => {
  beforeAll(() => {
    // The module reads the accent through utils.js's cssVar, which is not
    // loaded here: stub it the way a <script> earlier in the page would.
    globalThis.cssVar = (name) => (name === 'accent-soft' ? '#0aa' : '#0ff');
    loadScript('sparkline.js');
  });

  function card(spark) {
    document.body.innerHTML =
      `<div class="card" data-spark="${spark}"><div class="card-spark"></div></div>`;
    return document.querySelector('.card-spark');
  }

  const points = (box) =>
    box.querySelector('polyline').getAttribute('points').split(' ').map((p) => p.split(',').map(Number));

  beforeEach(() => { document.body.innerHTML = ''; });

  it('draws a point per value', () => {
    const box = card('1,2,3,4');
    domReady();
    expect(points(box)).toHaveLength(4);
  });

  it('spans the full width and marks the last point', () => {
    const box = card('0,10');
    domReady();
    const pts = points(box);
    expect(pts[0][0]).toBeCloseTo(2, 1);
    expect(pts[pts.length - 1][0]).toBeCloseTo(118, 1);
    const dot = box.querySelector('circle');
    expect(Number(dot.getAttribute('cx'))).toBeCloseTo(118, 1);
  });

  it('puts the larger value higher up the box', () => {
    const box = card('1,9');
    domReady();
    const [[, y0], [, y1]] = points(box);
    expect(y1).toBeLessThan(y0); // SVG y grows downwards
  });

  it('draws a flat series down the middle instead of dividing by zero', () => {
    const box = card('5,5,5');
    domReady();
    const ys = points(box).map(([, y]) => y);
    expect(new Set(ys).size).toBe(1);
    expect(ys[0]).toBeCloseTo(14, 1); // H / 2
  });

  it('draws nothing for a series too short to be a line', () => {
    const box = card('7');
    domReady();
    expect(box.innerHTML).toBe('');
  });

  it('drops values that are not numbers, blanks included', () => {
    // Number('') is 0, so a stray comma used to slip past the isNaN filter and
    // draw a dip to the baseline with no data point behind it.
    const box = card('1,,x,3');
    domReady();
    expect(points(box)).toHaveLength(2);
  });

  it('keeps a real zero', () => {
    const box = card('0,5,0');
    domReady();
    expect(points(box)).toHaveLength(3);
  });

  it('leaves a card without a container alone', () => {
    document.body.innerHTML = '<div class="card" data-spark="1,2,3"></div>';
    expect(() => domReady()).not.toThrow();
  });

  it('redraws on themechange so the stroke follows the accent', () => {
    const box = card('1,2,3');
    domReady();
    expect(box.querySelector('polyline').getAttribute('stroke')).toBe('#0aa');

    globalThis.cssVar = () => '#f00';
    document.dispatchEvent(new window.Event('themechange'));
    expect(box.querySelector('polyline').getAttribute('stroke')).toBe('#f00');

    globalThis.cssVar = (name) => (name === 'accent-soft' ? '#0aa' : '#0ff');
  });

  it('falls back to the plain accent when the soft one is unset', () => {
    globalThis.cssVar = (name) => (name === 'accent-soft' ? '' : '#123');
    const box = card('1,2,3');
    domReady();
    expect(box.querySelector('polyline').getAttribute('stroke')).toBe('#123');
    globalThis.cssVar = (name) => (name === 'accent-soft' ? '#0aa' : '#0ff');
  });
});
