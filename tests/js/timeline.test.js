import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { loadScript } from './helpers.js';

/* The activity chart draws itself: axis steps, bucket size and the index under
 * the cursor are arithmetic, and arithmetic is testable without a browser.
 * What only a browser can answer — that a drag narrows the picture — is
 * measured in tests/test_layout_browser.py. */
describe('timeline.js', () => {
  beforeAll(() => {
    loadScript('utils.js'); // cssVar/esc, loaded before every module in base.html
    loadScript('timeline.js');
  });

  describe('niceTicks', () => {
    it('starts at zero and ends at or above the peak', () => {
      const t = niceTicks(1340);
      expect(t[0]).toBe(0);
      expect(t[t.length - 1]).toBeGreaterThanOrEqual(1340);
    });

    it('uses round numbers a reader can add up', () => {
      expect(niceTicks(1340)).toEqual([0, 500, 1000, 1500]);
      expect(niceTicks(9)).toEqual([0, 5, 10]);
    });

    it('survives an empty chart', () => {
      expect(niceTicks(0)).toEqual([0, 1]);
    });
  });

  describe('pickBucket', () => {
    it('asks for hours once days would be single points', () => {
      expect(pickBucket(2)).toBe('hour');
      expect(pickBucket(3)).toBe('hour');
    });

    it('stays on days for anything longer', () => {
      expect(pickBucket(4)).toBe('day');
      expect(pickBucket(90)).toBe('day');
    });
  });

  describe('formatBucket', () => {
    it('shows the day for daily buckets and the hour for hourly ones', () => {
      expect(formatBucket('2026-08-05', 'day')).toBe('05.08.');
      expect(formatBucket('2026-08-05T14', 'hour')).toBe('14:00');
    });

    it('spells the date out in the tooltip, hour included', () => {
      expect(formatBucketLong('2026-08-05', 'day')).toBe('05.08.26');
      expect(formatBucketLong('2026-08-05T14', 'hour')).toBe('05.08.26 14:00');
    });
  });

  describe('bucketAt', () => {
    // plot from x=40, 300 wide, 11 buckets → one every 30px
    const at = (x) => bucketAt(x, 40, 300, 11);

    it('maps the plot edges to the first and last bucket', () => {
      expect(at(40)).toBe(0);
      expect(at(340)).toBe(10);
    });

    it('snaps to the nearest bucket, not the one to the left', () => {
      expect(at(40 + 74)).toBe(2); // 74px is closer to 60 than to 90
      expect(at(40 + 76)).toBe(3);
    });

    it('clamps outside the plot instead of returning nonsense', () => {
      expect(at(-500)).toBe(0);
      expect(at(9999)).toBe(10);
    });

    it('survives a chart with no width, as in a closed panel', () => {
      // The caller scales by the rendered width; at zero that arithmetic hands
      // this NaN, and the hover then silently did nothing.
      expect(bucketAt(NaN, 40, 300, 11)).toBe(0);
      expect(bucketAt(50, 40, 0, 11)).toBe(0);
    });
  });

  describe('spanInDays', () => {
    it('measures whole days and hourly keys alike', () => {
      expect(spanInDays('2026-08-01', '2026-08-08')).toBe(7);
      expect(spanInDays('2026-08-05T00', '2026-08-05T12')).toBe(0.5);
    });

    it('is 0 for something it cannot parse rather than NaN', () => {
      expect(spanInDays('nonsense', '2026-08-08')).toBe(0);
    });
  });

  describe('rendering', () => {
    const rows = [
      { day: '2026-08-01', total: 3, humans: 1, bots: 2, automated: 0, threats: 0, unknown: 0 },
      { day: '2026-08-02', total: 5, humans: 2, bots: 3, automated: 0, threats: 0, unknown: 0 },
      { day: '2026-08-03', total: 9, humans: 4, bots: 5, automated: 0, threats: 0, unknown: 0 },
    ];
    const series = [
      { key: 'humans', label: 'Humans', token: 'grp-humans' },
      { key: 'bots', label: 'Bots', token: 'grp-bots' },
    ];

    beforeEach(() => {
      document.body.innerHTML = `
        <div class="timeline" data-endpoint="/api/activity" data-params="">
          <script type="application/json">${JSON.stringify({ series, rows })}</script>
          <div class="timeline-plot"></div>
          <div class="timeline-tip" style="display:none"></div>
          <div class="timeline-zoombar">
            <button data-zoom="out" disabled></button>
            <button data-zoom="in"></button>
          </div>
        </div>`;
      // jsdom reports zero-size boxes; the renderer falls back to its defaults.
      document.dispatchEvent(new window.Event('DOMContentLoaded'));
    });

    it('draws one line per series', () => {
      const lines = document.querySelectorAll('.tl-svg polyline');
      expect(lines.length).toBe(2);
      expect([...lines].map((l) => l.parentElement.dataset.series)).toEqual(['humans', 'bots']);
    });

    it('gives every bucket a point on every line', () => {
      const pts = document.querySelector('.tl-svg polyline').getAttribute('points').split(' ');
      expect(pts.length).toBe(rows.length);
    });

    it('names every series and the total on hover', () => {
      const plot = document.querySelector('.timeline-plot');
      plot.dispatchEvent(new window.MouseEvent('mousemove', { bubbles: true, clientX: 0 }));
      const tip = document.querySelector('.timeline-tip');
      expect(tip.style.display).toBe('');
      expect(tip.textContent).toContain('Humans');
      expect(tip.textContent).toContain('Bots');
      expect(tip.textContent).toContain('visits');
    });

    describe('the zoom buttons', () => {
      // Its own mount: the shared fixture is three buckets, which is already
      // below the point where zooming in means anything — and those three are
      // what the hourly-fetch test above needs, so they stay as they are.
      const many = Array.from({ length: 12 }, (_, i) => ({
        day: `2026-08-${String(i + 1).padStart(2, '0')}`,
        total: 10 + i,
        humans: 5,
        bots: 5 + i,
        automated: 0,
        threats: 0,
        unknown: 0,
      }));

      beforeEach(() => {
        document.body.innerHTML = `
          <div class="timeline" data-endpoint="/api/activity" data-params="">
            <script type="application/json">${JSON.stringify({ series, rows: many })}</script>
            <div class="timeline-plot"></div>
            <div class="timeline-tip" style="display:none"></div>
            <div class="timeline-zoombar">
              <button data-zoom="out" disabled></button>
              <button data-zoom="in"></button>
            </div>
          </div>`;
        document.dispatchEvent(new window.Event('DOMContentLoaded'));
      });

      const btn = (dir) => document.querySelector(`[data-zoom="${dir}"]`);
      const shown = () =>
        document.querySelector('.tl-svg polyline').getAttribute('points').split(' ').length;

      it('starts fully zoomed out, with nothing to step back to', () => {
        expect(btn('out').disabled).toBe(true);
        expect(btn('in').disabled).toBe(false);
      });

      it('+ narrows to the middle of what is shown', () => {
        const before = shown();
        btn('in').click();
        expect(shown()).toBeLessThan(before);
        expect(btn('out').disabled).toBe(false);
      });

      it('- puts back exactly what + took away', () => {
        const before = shown();
        btn('in').click();
        btn('out').click();
        expect(shown()).toBe(before);
        expect(btn('out').disabled).toBe(true);
      });

      it('stops offering + once there is nothing finer to show', () => {
        // Four buckets halve to two, which is a segment rather than a shape.
        for (let i = 0; i < 6 && !btn('in').disabled; i++) btn('in').click();
        expect(btn('in').disabled).toBe(true);
      });

      // A drag cannot be exercised here: jsdom reports a zero-width box, so both
      // ends of the gesture resolve to the same bucket and applyZoom declines.
      // That the drag pushes onto this same stack is one line of code away from
      // what the tests above cover, and a real drag is measured in
      // tests/test_layout_browser.py.
    });

    it('keeps the chart when the hourly fetch fails', async () => {
      // A failed request must not blank the picture — the daily slice stays.
      window.fetch = vi.fn(() => Promise.reject(new Error('offline')));
      const plot = document.querySelector('.timeline-plot');
      plot.dispatchEvent(new window.MouseEvent('mousedown', { bubbles: true, button: 0, clientX: 0 }));
      document.dispatchEvent(new window.MouseEvent('mouseup', { bubbles: true, clientX: 1e6 }));
      await new Promise((r) => setTimeout(r, 10));
      expect(document.querySelectorAll('.tl-svg polyline').length).toBe(2);
    });
  });
});
