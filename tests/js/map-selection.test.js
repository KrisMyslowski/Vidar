import { beforeAll, describe, expect, it } from 'vitest';
import { loadScript } from './helpers.js';

/* Panning the map *is* the selection: everything the sidebar shows is derived
 * from the markers inside the current viewport on every move. That derivation
 * is pure, and it is the one part of the map worth testing without Leaflet. */
describe('map.js — viewport selection', () => {
  beforeAll(() => loadScript('map.js'));

  const marker = (cc, cls) => ({ country_code: cc, visitor_class: cls });

  describe('groupOf', () => {
    it('takes the group before the slash', () => {
      expect(groupOf({ visitor_class: 'humans/browser-direct' })).toBe('humans');
      expect(groupOf({ visitor_class: 'threats/exploit-probers' })).toBe('threats');
    });

    it('files anything it does not recognise under unknown', () => {
      expect(groupOf({ visitor_class: '' })).toBe('unknown');
      expect(groupOf({})).toBe('unknown');
      expect(groupOf({ visitor_class: 'infrastructure/hosting' })).toBe('unknown');
    });
  });

  describe('summariseSelection', () => {
    it('counts nothing for an empty viewport', () => {
      expect(summariseSelection([])).toEqual({ total: 0, counts: {}, byCountry: {} });
    });

    it('tallies groups and splits them per country', () => {
      const { total, counts, byCountry } = summariseSelection([
        marker('DE', 'humans/browser-direct'),
        marker('DE', 'bots/generic-bots'),
        marker('US', 'bots/generic-bots'),
        marker('US', 'threats/exploit-probers'),
        marker('US', 'bots/ai-crawlers'),
      ]);
      expect(total).toBe(5);
      expect(counts).toEqual({ humans: 1, bots: 3, threats: 1 });
      expect(byCountry.DE).toEqual({ ips: 2, groups: { humans: 1, bots: 1 } });
      expect(byCountry.US.ips).toBe(3);
      expect(byCountry.US.groups).toEqual({ bots: 2, threats: 1 });
    });

    it('gives markers without a country their own bucket', () => {
      const { byCountry } = summariseSelection([marker('', 'bots/generic-bots')]);
      expect(byCountry['—'].ips).toBe(1);
    });
  });

  describe('mixGradient', () => {
    const resolve = (token) => `var(--${token})`;

    it('is empty when there is nothing to show', () => {
      expect(mixGradient({}, 0, resolve)).toBe('');
    });

    it('lays the groups end to end in taxonomy order', () => {
      const css = mixGradient({ humans: 1, bots: 3 }, 4, resolve);
      expect(css).toBe(
        'linear-gradient(90deg,var(--grp-humans) 0.0% 25.0%,var(--grp-bots) 25.0% 100.0%)'
      );
    });

    it('reaches exactly 100% so the bar has no gap at its end', () => {
      const css = mixGradient({ humans: 1, bots: 1, threats: 1 }, 3, resolve);
      expect(css.endsWith('100.0%)')).toBe(true);
    });

    it('takes its colors from the taxonomy tokens, never a literal', () => {
      const css = mixGradient({ threats: 1 }, 1, resolve);
      expect(css).toContain('var(--grp-threats)');
      expect(css).not.toMatch(/#[0-9a-f]{3,6}/i);
    });
  });

  describe('binSizeForZoom', () => {
    it('halves the cell with every zoom step', () => {
      expect(binSizeForZoom(2)).toBe(20);
      expect(binSizeForZoom(3)).toBe(10);
      expect(binSizeForZoom(4)).toBe(5);
    });

    it('stops shrinking, so a deep zoom cannot ask for millions of cells', () => {
      expect(binSizeForZoom(20)).toBe(0.05);
      expect(binSizeForZoom(0)).toBe(20); // below the map's own minZoom
    });
  });

  describe('binMarkers', () => {
    const at = (lat, lon, extra = {}) => ({ lat, lon, visit_count: 1, ...extra });

    it('puts markers of one cell together and keeps the others apart', () => {
      const bins = binMarkers([at(50.1, 8.6), at(50.9, 8.9), at(52.5, 13.4)], 10);
      expect(bins.length).toBe(2);
      expect(bins.map((b) => b.ips).sort()).toEqual([1, 2]);
    });

    it('anchors a cell on its south-west corner', () => {
      const [bin] = binMarkers([at(50.1, 8.6)], 10);
      expect(bin.lat).toBe(50);
      expect(bin.lon).toBe(0);
      expect(bin.size).toBe(10);
    });

    it('handles the southern and western hemispheres', () => {
      const [bin] = binMarkers([at(-33.9, -70.6)], 10);
      // floor(), not truncation: -33.9 belongs to the cell starting at -40.
      expect(bin.lat).toBe(-40);
      expect(bin.lon).toBe(-80);
    });

    it('counts IPs, sums visits and names the dominant class', () => {
      const [bin] = binMarkers(
        [
          at(50.1, 8.6, { visit_count: 10, visitor_class: 'bots/ai-crawlers' }),
          at(50.2, 8.7, { visit_count: 5, visitor_class: 'bots/seo-tools' }),
          at(50.3, 8.8, { visit_count: 100, visitor_class: 'threats/exploit-probers' }),
        ],
        10
      );
      expect(bin.ips).toBe(3);
      expect(bin.visits).toBe(115);
      expect(bin.groups).toEqual({ bots: 2, threats: 1 });
      // The busiest IP is a threat, but the cell is mostly bots — the shade is
      // about how many IPs there are, not how loud one of them is.
      expect(bin.top).toBe('bots');
    });

    it('returns nothing for no markers', () => {
      expect(binMarkers([], 10)).toEqual([]);
    });
  });

  describe('heatIntensity', () => {
    it('is 0 for an empty cell and 1 for the busiest', () => {
      expect(heatIntensity(0, 300)).toBe(0);
      expect(heatIntensity(300, 300)).toBe(1);
    });

    it('rises with the count', () => {
      const a = heatIntensity(5, 300);
      const b = heatIntensity(50, 300);
      expect(b).toBeGreaterThan(a);
    });

    it('keeps a small cell visible beside a huge one', () => {
      // Linear, 5 of 300 would be 1.7% — invisible. Logarithmic it is a fifth
      // of the way up, which is the whole point of the ramp.
      expect(heatIntensity(5, 300)).toBeGreaterThan(0.3);
    });

    it('survives a single-cell map without dividing by zero', () => {
      expect(heatIntensity(1, 0)).toBe(0);
    });
  });
});
