import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { loadScript } from './helpers.js';

/* The string-building half of the geo page. All of it used to live inside one
 * 330-line DOMContentLoaded callback, closed over Leaflet objects, so none of
 * it could be reached without a browser. Pulled out, it is ordinary text work —
 * and text work on user data, which is where escaping either happens or does
 * not. */
describe('map.js — what the geo page renders', () => {
  beforeAll(() => {
    loadScript('utils.js'); // cssVar/esc/fmtNum, loaded before every module in base.html
    loadScript('map.js');
  });

  beforeEach(() => { document.body.innerHTML = ''; });

  describe('basemap tiles', () => {
    const setKey = (key) => {
      document.body.innerHTML = key === null ? '' :
        `<script type="application/json" id="map-tile-data">${JSON.stringify({ key })}</script>`;
    };

    it('asks for tiles unadorned when no key is configured', () => {
      setKey(null);
      expect(getTileUrl()).not.toContain('?');
    });

    it('does not send an empty key, which would look like a configured one', () => {
      setKey('');
      expect(getTileUrl()).not.toContain('key=');
    });

    it('appends the key exactly once, escaped', () => {
      setKey('ab/cd 12');
      const url = getTileUrl();
      expect(url.match(/\?key=/g)).toHaveLength(1);
      expect(url).toContain('key=ab%2Fcd%2012');
    });

    it('credits CARTO and OpenStreetMap, which the free tier requires', () => {
      const a = tileOptions().attribution;
      expect(a).toContain('CARTO');
      expect(a).toContain('OpenStreetMap');
    });
  });

  describe('markerPopup', () => {
    const base = {
      ip: '93.184.216.34', city: 'Berlin', country: 'Germany', country_code: 'DE',
      isp: 'Example ISP', asn: 'AS1', visit_count: 12, visitor_class: 'humans/browser-direct',
    };

    it('names the class, not the group', () => {
      expect(markerPopup(base)).toContain('<strong>browser-direct</strong>');
    });

    it('links to the visitor page', () => {
      expect(markerPopup(base)).toContain('href="/visitors/93.184.216.34"');
    });

    it('escapes what comes from the log', () => {
      const html = markerPopup({ ...base, city: '<script>x</script>', isp: 'A & B' });
      expect(html).not.toContain('<script>');
      expect(html).toContain('A &amp; B');
    });

    it('encodes the IP in the URL as well as escaping it in the text', () => {
      const html = markerPopup({ ...base, ip: 'a b/c' });
      expect(html).toContain('href="/visitors/a%20b%2Fc"');
    });

    it('lists only the signals that are set', () => {
      expect(markerPopup(base)).not.toContain('Tor');
      const flagged = markerPopup({ ...base, is_tor: 1, is_hosting: 1 });
      expect(flagged).toContain('Tor');
      expect(flagged).toContain('Hosting');
      expect(flagged).not.toContain('DNSBL');
    });

    it('falls back to a dash for missing geo', () => {
      const html = markerPopup({ ip: '1.2.3.4', visit_count: 1 });
      expect(html).toContain('—, —');
      expect(html).toContain('unknown');
    });

    it('omits the ASN line when there is none', () => {
      expect(markerPopup({ ...base, asn: '' })).not.toContain('ASN:');
    });
  });

  describe('markerRadius', () => {
    it('grows with visits but flattens out', () => {
      expect(markerRadius(0)).toBeLessThan(markerRadius(10));
      expect(markerRadius(10)).toBeLessThan(markerRadius(1000));
    });

    it('never exceeds the cap, however loud the IP', () => {
      expect(markerRadius(1e9)).toBe(16);
    });
  });

  describe('legends', () => {
    it('names every group in the taxonomy', () => {
      // `const GROUPS` at the top of map.js is block-scoped to the eval, so the
      // test reads the same fallback list the module falls back to.
      const html = classLegendHtml({});
      ['humans', 'bots', 'automated', 'threats', 'unknown'].forEach((g) =>
        expect(html).toContain(`data-grp="${g}"`));
    });

    it('uses the singular label for a dot', () => {
      expect(classLegendHtml({})).toContain('Human');
      expect(classLegendHtml({})).not.toContain('Humans');
    });

    it('carries the taxonomy tooltip pair when there is one', () => {
      const html = classLegendHtml({ bots: { what: 'A crawler.', how: 'By user agent.' } });
      expect(html).toContain('data-tip-what="A crawler."');
      expect(html).toContain('data-tip-source="By user agent."');
    });

    it('writes both halves even when the taxonomy has none', () => {
      // A lone data-tip-what renders a How row reading "undefined".
      const html = classLegendHtml({});
      const whats = html.match(/data-tip-what=/g) || [];
      const hows = html.match(/data-tip-source=/g) || [];
      expect(whats.length).toBe(hows.length);
    });

    it('shows the busiest cell as the heat scale upper end', () => {
      expect(heatLegendHtml(1234)).toContain('1,234');
      expect(heatLegendHtml(0)).toContain('IPs per cell');
    });
  });

  describe('plural vs singular', () => {
    it('counts read as plurals', () => {
      // GROUP_LABEL is singular because the legend names one dot; anywhere a
      // count follows, the group's own name is already the plural.
      expect(mixSummary({ humans: 3, automated: 2 })).toBe('Humans 3 · Automated 2');
    });

    it('leaves out groups with nothing in them', () => {
      expect(mixSummary({ humans: 0, bots: 4 })).toBe('Bots 4');
      expect(mixSummary({})).toBe('');
    });

    it('the inline legend agrees with the summary', () => {
      const html = mixLegendHtml({ humans: 3 });
      expect(html).toContain('Humans');
      expect(html).toContain('<strong>3</strong>');
    });
  });

  describe('countryRowsHtml', () => {
    const grad = () => 'linear-gradient(90deg,red 0% 100%)';

    it('says so when the viewport holds nothing', () => {
      expect(countryRowsHtml({}, grad)).toContain('No IPs in this viewport');
    });

    it('sorts by IP count and scales the bars against the top row', () => {
      const html = countryRowsHtml(
        { DE: { ips: 10, groups: {} }, FR: { ips: 5, groups: {} } }, grad);
      expect(html.indexOf('DE')).toBeLessThan(html.indexOf('FR'));
      expect(html).toContain('width:100.0%');
      expect(html).toContain('width:50.0%');
    });

    it('stops at twelve rows', () => {
      const many = {};
      for (let i = 0; i < 20; i += 1) many[`C${i}`] = { ips: 20 - i, groups: {} };
      expect((countryRowsHtml(many, grad).match(/facet-row/g) || []).length).toBe(12);
    });

    it('escapes the country code', () => {
      const html = countryRowsHtml({ '"><b>': { ips: 1, groups: {} } }, grad);
      expect(html).not.toContain('<b>');
    });
  });

  describe('viewportLabel', () => {
    it('names the hemispheres', () => {
      expect(viewportLabel({ lat: 52.5, lng: 13.4 })).toBe('52.5N 13.4E');
      expect(viewportLabel({ lat: -33.9, lng: -70.7 })).toBe('33.9S 70.7W');
    });

    it('treats the equator and the meridian as north and east', () => {
      expect(viewportLabel({ lat: 0, lng: 0 })).toBe('0.0N 0.0E');
    });
  });

  describe('railFilter', () => {
    const rows = [
      { marker: {}, data: { country_code: 'DE', visit_count: 10 } },
      { marker: {}, data: { country_code: 'FR', visit_count: 2 } },
      { marker: {}, data: { country_code: '', visit_count: 50 } },
    ];

    function rail(country = '', minVisits = '') {
      document.body.innerHTML =
        `<div class="visitor-filter-bar">
           <input name="country" value="${country}">
           <input name="min_visits" value="${minVisits}">
         </div>`;
    }

    it('passes everything when the rail is empty', () => {
      rail();
      expect(railFilter(rows)).toHaveLength(3);
    });

    it('matches a country prefix, case-insensitively', () => {
      rail('de');
      expect(railFilter(rows).map(({ data }) => data.country_code)).toEqual(['DE']);
    });

    it('applies the visit floor', () => {
      rail('', '10');
      expect(railFilter(rows).map(({ data }) => data.visit_count)).toEqual([10, 50]);
    });

    it('ignores a non-numeric floor rather than dropping everything', () => {
      rail('', 'abc');
      expect(railFilter(rows)).toHaveLength(3);
    });

    it('works on a page with no rail at all', () => {
      document.body.innerHTML = '';
      expect(railFilter(rows)).toHaveLength(3);
    });
  });
});
