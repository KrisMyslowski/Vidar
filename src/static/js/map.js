/**
 * Leaflet.js maps: clustered geo map (geo page) + single-IP detail map.
 * Colors read from dashboard CSS custom properties via cssVar() (utils.js);
 * taxonomy group colors use the --grp-* tokens (single source in tokens.css).
 */

const TILE_DARK  = 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';
const TILE_LIGHT = 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png';

/* CARTO's free tier requires this to stay visible. It is the condition that
 * makes the key free, so the attribution control is on and this string is
 * passed to every tile layer. */
const TILE_ATTRIBUTION =
  '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> ' +
  'contributors &copy; <a href="https://carto.com/attributions">CARTO</a>';

/* The key, or '' when none is configured. Server-rendered into #map-tile-data,
 * which base.html omits entirely when the setting is empty. */
function tileKey() {
  const el = document.getElementById('map-tile-data');
  if (!el) return '';
  try { return JSON.parse(el.textContent).key || ''; } catch { return ''; }
}

/* Without a key CARTO stamps "API KEY REQUIRED" into every tile — a valid PNG
 * with a 200, so nothing here can detect it. The URL is unchanged in that case
 * rather than carrying an empty parameter: a wrong key and no key produce
 * byte-identical tiles, and `?key=` would look like one had been set. */
function getTileUrl() {
  const base = document.documentElement.getAttribute('data-theme') === 'light'
    ? TILE_LIGHT : TILE_DARK;
  const key = tileKey();
  return key ? `${base}?key=${encodeURIComponent(key)}` : base;
}

function tileOptions() {
  return { maxZoom: 19, attribution: TILE_ATTRIBUTION };
}

/**
 * Identity groups in display order, read from the taxonomy the server ships as
 * #taxonomy-data (base.html). The literal is the fallback for a document that
 * carries no taxonomy — which in practice means the unit tests, since every page
 * extends base.html. Keeping a second copy here is what this reads it to avoid.
 */
function taxonomyGroups() {
  try {
    const groups = JSON.parse(document.getElementById('taxonomy-data').textContent).groups;
    if (Array.isArray(groups) && groups.length) return groups;
  } catch (e) {
    /* no taxonomy in this document — fall through */
  }
  return ['humans', 'bots', 'automated', 'threats', 'unknown'];
}

const GROUPS = taxonomyGroups();
// --grp-* tokens from tokens.css (single source of truth for identity colors).
// Derived from the group name, so a new group needs no entry here.
const CLASS_COLORS = Object.fromEntries(GROUPS.map((g) => [g, `grp-${g}`]));

/** Identity group of a marker; anything unrecognized counts as unknown. */
function groupOf(d) {
  const g = (d.visitor_class || '').split('/')[0];
  return GROUPS.indexOf(g) === -1 ? 'unknown' : g;
}

/**
 * Aggregate the markers inside the viewport into the numbers the selection
 * panel shows. Pure on purpose: panning is the selection, so this runs on every
 * map move and is the one piece of the map worth testing on its own.
 * Returns { total, counts, byCountry: { CC: { ips, groups } } }.
 */
function summariseSelection(rows) {
  const counts = {};
  const byCountry = {};
  rows.forEach((d) => {
    const g = groupOf(d);
    counts[g] = (counts[g] || 0) + 1;
    const cc = d.country_code || '—';
    byCountry[cc] = byCountry[cc] || { ips: 0, groups: {} };
    byCountry[cc].ips += 1;
    byCountry[cc].groups[g] = (byCountry[cc].groups[g] || 0) + 1;
  });
  return { total: rows.length, counts, byCountry };
}

/**
 * Heat view: density, not identity.
 *
 * The old heat layer drew one translucent disc per IP in its class colour.
 * Overlaid, red on blue turned pink and a pale patch could mean "few IPs" or
 * "two colours cancelling out" — there was nothing to read off it. Density is
 * one number, so it gets one ramp; which visitors they are is what the cluster
 * view is for.
 *
 * These three are pure and live beside summariseSelection for the same reason:
 * they are the part of the map worth testing without a browser.
 */

/** Cell size in degrees for a zoom level — about 18 cells across at zoom 2. */
function binSizeForZoom(zoom) {
  return Math.max(0.05, 20 / Math.pow(2, Math.max(0, zoom - 2)));
}

/**
 * Group markers into square cells of `size` degrees.
 * Returns [{ lat, lon, size, ips, visits, groups, top }], lat/lon = SW corner.
 */
function binMarkers(rows, size) {
  const bins = new Map();
  rows.forEach((d) => {
    const lat = Math.floor(d.lat / size) * size;
    const lon = Math.floor(d.lon / size) * size;
    const key = lat + ':' + lon;
    let bin = bins.get(key);
    if (!bin) {
      bin = { lat, lon, size, ips: 0, visits: 0, groups: {}, top: 'unknown' };
      bins.set(key, bin);
    }
    const g = groupOf(d);
    bin.ips += 1;
    bin.visits += d.visit_count || 0;
    bin.groups[g] = (bin.groups[g] || 0) + 1;
    if (bin.groups[g] > (bin.groups[bin.top] || 0)) bin.top = g;
  });
  return [...bins.values()];
}

/**
 * 0..1 for a cell's count against the busiest cell, logarithmic: on a linear
 * ramp one Frankfurt cell with 300 IPs makes every cell with 5 invisible.
 */
function heatIntensity(count, max) {
  if (!count || max <= 0) return 0;
  return Math.min(1, Math.log(count + 1) / Math.log(max + 1));
}

/** Stacked-bar gradient for a group tally. resolve() maps a token to a color. */
function mixGradient(counts, total, resolve) {
  let at = 0;
  const stops = [];
  GROUPS.forEach((g) => {
    const share = total ? ((counts[g] || 0) / total) * 100 : 0;
    if (!share) return;
    stops.push(`${resolve(CLASS_COLORS[g])} ${at.toFixed(1)}% ${(at + share).toFixed(1)}%`);
    at += share;
  });
  return stops.length ? `linear-gradient(90deg,${stops.join(',')})` : '';
}

let _geoMap = null, _geoTileLayer = null;
let _detailMap = null, _detailTileLayer = null, _detailMarker = null;

// Theme recolor hook — set by the geo-page init below; recolors markers,
// clusters, and the legend from the re-resolved CSS tokens.
let _recolorGeo = null;

document.addEventListener('themechange', function () {
  if (_geoMap && _geoTileLayer) {
    _geoMap.removeLayer(_geoTileLayer);
    _geoTileLayer = L.tileLayer(getTileUrl(), tileOptions()).addTo(_geoMap);
  }
  if (_detailMap && _detailTileLayer) {
    _detailMap.removeLayer(_detailTileLayer);
    _detailTileLayer = L.tileLayer(getTileUrl(), tileOptions()).addTo(_detailMap);
  }
  if (_detailMarker) {
    const accent = cssVar('accent');
    _detailMarker.setStyle({ fillColor: accent, color: accent });
  }
  if (_recolorGeo) _recolorGeo();
});

/** Render a single-marker Leaflet map inside #detail-map (visitor detail page). */
function renderDetailMap(lat, lon, city, country, ip) {
  const el = document.getElementById('detail-map');
  if (!el || _detailMap) return;
  _detailMap = L.map('detail-map', { scrollWheelZoom: false })
    .setView([lat, lon], 11);
  _detailTileLayer = L.tileLayer(getTileUrl(), tileOptions()).addTo(_detailMap);
  const accent = cssVar('accent');
  _detailMarker = L.circleMarker([lat, lon], {
    radius: 8, fillColor: accent, color: accent,
    weight: 2, opacity: 0.9, fillOpacity: 0.5,
  }).bindPopup(`<strong>${esc(city || '—')}, ${esc(country || '—')}</strong><br>${esc(ip)}`)
    .addTo(_detailMap);
}

// The detail map sits in a collapsed <details>, so it has no size until the
// section is opened — build it on first open, not on DOMContentLoaded.
document.addEventListener('DOMContentLoaded', () => {
  const el = document.getElementById('detail-map');
  if (!el || !el.dataset.lat) return;
  const build = () => {
    renderDetailMap(
      parseFloat(el.dataset.lat), parseFloat(el.dataset.lon),
      el.dataset.city, el.dataset.country, el.dataset.ip
    );
    if (_detailMap) _detailMap.invalidateSize();
  };
  const box = el.closest('details');
  if (box) box.addEventListener('toggle', () => { if (box.open) build(); });
  else build();
});

// ── Geo page ─────────────────────────────────────────────────────────────────
// What follows used to be one 330-line DOMContentLoaded callback. Everything in
// it closed over everything else, so no part could be read — or tested —
// without the whole. The derivations are top-level and pure now; the views own
// their own state behind a small interface; the callback is wiring.

/** Singular display copy for the legend only. The *list* comes from GROUPS, so
 * a group added to the taxonomy cannot go missing here; this just names it. */
const GROUP_LABEL = {
  humans: 'Human', bots: 'Bot', automated: 'Automated',
  threats: 'Threat', unknown: 'Unknown',
};

/** Title case for a group name the label map does not cover. */
function groupLabel(grp) {
  return GROUP_LABEL[grp] || grp.charAt(0).toUpperCase() + grp.slice(1);
}

/**
 * The group name itself, capitalised — "Humans", not "Human". GROUP_LABEL is
 * singular because the map legend names one dot; everywhere a count follows it
 * reads as a plural, and mixing the two up says "Automateds".
 */
function groupPlural(grp) {
  return grp.charAt(0).toUpperCase() + grp.slice(1);
}

/** The popup body for one marker. Pure string work — the reason it is up here. */
function markerPopup(m) {
  const cls = m.visitor_class ? m.visitor_class.split('/').pop() : 'unknown';
  const signals = [];
  if (m.is_tor)       signals.push('<span class="text-purple">Tor</span>');
  if (m.is_proxy)     signals.push('<span class="text-red">Proxy / VPN</span>');
  if (m.dnsbl_listed) signals.push('<span class="text-orange">DNSBL</span>');
  if (m.is_hosting)   signals.push('<span class="text-yellow">Hosting</span>');
  return (
    `<strong><a href="/visitors/${encodeURIComponent(m.ip)}">${esc(m.ip)}</a></strong><br>` +
    `${esc(m.city || '—')}, ${esc(m.country || '—')}` +
    (m.country_code ? ` (${esc(m.country_code)})` : '') + '<br>' +
    `ISP: ${esc(m.isp || '—')}<br>` +
    (m.asn ? `ASN: ${esc(m.asn)}<br>` : '') +
    `Visits: ${m.visit_count}<br>` +
    `Class: <strong>${esc(cls)}</strong>` +
    (signals.length ? `<br>${signals.join(' ')}` : '')
  );
}

/** Marker radius from visit count — log so one loud IP does not swamp the rest. */
function markerRadius(visits) {
  return Math.min(6 + Math.log2(visits + 1) * 2, 16);
}

/** The legend for cluster mode: which colour is which identity group. */
function classLegendHtml(groupTips) {
  return '<b>Class</b>' + GROUPS.map((grp) => {
    const t = groupTips[grp] || { what: '', how: '' };
    return `<div data-tip-what="${t.what}" data-tip-source="${t.how}">` +
           `<span class="ldot" data-grp="${grp}" style="background:${cssVar(CLASS_COLORS[grp] || 'grp-unknown')}"></span> ` +
           `${groupLabel(grp)}</div>`;
  }).join('');
}

/**
 * The legend for heat mode. Heat says nothing about identity, so its legend
 * says what it does say: how the shade maps to a count, and what the busiest
 * cell holds.
 */
function heatLegendHtml(peak) {
  const heat = cssVar('heat');
  const steps = [0.08, 0.3, 0.52, 0.74, 1];
  return '<b>IPs per cell</b><div class="heat-scale">' +
    steps.map((s) =>
      `<span class="heat-step" style="background:${heat};opacity:${(0.12 + 0.68 * s).toFixed(2)}"></span>`
    ).join('') +
    `</div><div class="heat-scale-ends"><span>few</span><span>${fmtNum(peak)}</span></div>`;
}

/** The coordinate label on the viewport pill. */
function viewportLabel(center) {
  return `${Math.abs(center.lat).toFixed(1)}${center.lat >= 0 ? 'N' : 'S'} ` +
         `${Math.abs(center.lng).toFixed(1)}${center.lng >= 0 ? 'E' : 'W'}`;
}

/** The country rows under the selection panel, tallest bar first. */
function countryRowsHtml(byCountry, gradient) {
  const top = Object.entries(byCountry).sort((a, b) => b[1].ips - a[1].ips).slice(0, 12);
  const peak = top.length ? top[0][1].ips : 0;
  return top.map(([cc, c]) =>
    `<a class="facet-row" href="#" data-country="${esc(cc)}" title="Zoom to ${esc(cc)} and filter by it">` +
    `<span class="facet-label">${esc(cc)}</span>` +
    `<span class="facet-bar"><span class="facet-bar-fill" style="width:${peak ? (c.ips / peak * 100).toFixed(1) : 0}%;` +
    `background:${gradient(c.groups, c.ips)}"></span></span>` +
    `<span class="facet-count">${fmtNum(c.ips)}</span></a>`
  ).join('') || '<p class="text-muted">No IPs in this viewport.</p>';
}

/** The group tally as "Bots 12 · Humans 4", for the mix bar's tooltip. */
function mixSummary(counts) {
  return GROUPS.filter((g) => counts[g])
    .map((g) => `${groupPlural(g)} ${fmtNum(counts[g])}`)
    .join(' · ');
}

/** The inline legend beside the mix bar. */
function mixLegendHtml(counts) {
  return GROUPS.filter((g) => counts[g]).map((g) =>
    `<span class="mix-legend-item"><span class="mix-legend-dot" style="background:${cssVar(CLASS_COLORS[g])}"></span>` +
    `${groupPlural(g)}<strong>${fmtNum(counts[g])}</strong></span>`
  ).join('');
}

/** The markers passing the rail's country and min-visits filters. */
function railFilter(allMarkers) {
  const countryInput   = document.querySelector('.visitor-filter-bar [name="country"]');
  const minVisitsInput = document.querySelector('.visitor-filter-bar [name="min_visits"]');
  const countryQ  = (countryInput  ? countryInput.value  : '').trim().toUpperCase();
  const minVisits = parseInt(minVisitsInput ? minVisitsInput.value : '') || 0;
  return allMarkers.filter(({ data }) =>
    (!countryQ || (data.country_code || '').startsWith(countryQ))
    && data.visit_count >= minVisits);
}

/** Build the circle markers, each tagged with its group for recolouring. */
function buildMarkers(rows) {
  return rows.map((m) => {
    const grp   = (m.visitor_class || '').split('/')[0] || 'unknown';
    const color = cssVar(CLASS_COLORS[grp] || 'grp-unknown');
    const circle = L.circleMarker([m.lat, m.lon], {
      radius: markerRadius(m.visit_count), fillColor: color, color,
      weight: 1, opacity: 0.8, fillOpacity: 0.5,
    });
    circle._grp = grp;
    circle.bindPopup(markerPopup(m));
    return { marker: circle, data: m };
  });
}

/** The cluster layer, whose bubbles take the colour of their dominant group. */
function buildCluster() {
  return L.markerClusterGroup({
    iconCreateFunction(c) {
      const counts = {};
      c.getAllChildMarkers().forEach((m) => { counts[m._grp] = (counts[m._grp] || 0) + 1; });
      const dominant = Object.entries(counts).sort((a, b) => b[1] - a[1])[0][0];
      const color = cssVar(CLASS_COLORS[dominant] || 'grp-unknown');
      const n = c.getChildCount();
      const size = n < 10 ? 28 : n < 100 ? 36 : 44;
      return L.divIcon({
        html: `<div class="mcluster" style="width:${size}px;height:${size}px;border-color:${color}">${n}</div>`,
        className: '',
        iconSize: [size, size],
        iconAnchor: [size / 2, size / 2],
      });
    },
  });
}

/** Fixed server marker — from SERVER_LAT/LON/CITY/COUNTRY/ASN/IP. */
function addServerMarker(map) {
  const srvEl = document.getElementById('server-location-data');
  if (!srvEl) return;
  const srv = JSON.parse(srvEl.textContent);
  const icon = L.divIcon({
    html: '<div class="server-marker">⬡</div>',
    className: '', iconSize: [24, 24], iconAnchor: [12, 12], popupAnchor: [0, -14],
  });
  L.marker([srv.lat, srv.lon], { icon, interactive: true, zIndexOffset: 1000 })
    .bindPopup(
      `<strong>Server</strong><br>${esc(srv.city)}, ${esc(srv.country)}` +
      (srv.asn ? `<br>${esc(srv.asn)}` : '') +
      (srv.ip  ? `<br>${esc(srv.ip)}`  : '')
    )
    .addTo(map);
}

/** The legend overlay. Which of the two it draws is asked, not stored twice. */
function createLegend(map, isHeatOn, heatPeak) {
  const groupTips = (() => {
    try {
      return JSON.parse(document.getElementById('taxonomy-data').textContent).group_tips || {};
    } catch (e) {
      return {};
    }
  })();
  let el = null;
  const control = L.control({ position: 'bottomright' });
  control.onAdd = function () {
    el = L.DomUtil.create('div', 'map-legend');
    el.innerHTML = classLegendHtml(groupTips);
    return el;
  };
  control.addTo(map);
  return {
    render() {
      if (el) el.innerHTML = isHeatOn() ? heatLegendHtml(heatPeak()) : classLegendHtml(groupTips);
    },
  };
}

/**
 * Heat view: density, not identity. Cells are rebuilt on every move because
 * their size follows the zoom.
 */
function createHeatView(map, activeMarkers, onDrawn) {
  const layer = L.layerGroup();
  let on = false;
  let peak = 0;   // IPs in the busiest cell — the legend's upper end

  function draw() {
    if (!on) return;
    layer.clearLayers();
    const size = binSizeForZoom(map.getZoom());
    const bins = binMarkers(activeMarkers().map(({ data }) => data), size);
    peak = bins.reduce((m, b) => Math.max(m, b.ips), 0);
    const heat = cssVar('heat');
    bins.forEach((b) => {
      const bounds = [[b.lat, b.lon], [b.lat + b.size, b.lon + b.size]];
      const shade = heatIntensity(b.ips, peak);
      L.rectangle(bounds, {
        color: heat, weight: 1,
        opacity: 0.15 + 0.35 * shade,
        fillColor: heat, fillOpacity: 0.12 + 0.68 * shade,
      })
        .bindTooltip(
          `<strong>${fmtNum(b.ips)} IPs</strong> · ` +
          `${fmtNum(b.visits)} visits<br>` +
          `mostly ${groupPlural(b.top)}`,
          { direction: 'top', sticky: true }
        )
        // Zooming into the cell IS the selection: the sidebar reads the
        // viewport, so it follows without a second mechanism.
        .on('click', () => map.fitBounds(bounds, { padding: [20, 20] }))
        .addTo(layer);
    });
    onDrawn();
  }

  return {
    draw,
    isOn: () => on,
    peak: () => peak,
    setOn(next, cluster) {
      on = next;
      if (on) { map.removeLayer(cluster); map.addLayer(layer); draw(); }
      else    { map.removeLayer(layer);   map.addLayer(cluster); }
    },
  };
}

/**
 * The selection panel. Everything in it is derived from what is inside the
 * viewport, so panning and zooming *is* the selection.
 */
function createSelectionPanel(map, activeMarkers) {
  const selIps       = document.getElementById('sel-ips');
  const selCountries = document.getElementById('sel-countries');
  const selThreats   = document.getElementById('sel-threats');
  const selMix       = document.getElementById('sel-mix');
  const selLegend    = document.getElementById('sel-legend');
  const selList      = document.getElementById('sel-countries-list');
  const headCount    = document.getElementById('map-count');
  const gradient = (counts, total) => mixGradient(counts, total, cssVar);

  /**
   * Asking a *layer* whether it holds a marker was the bug behind the empty
   * selection panel: in heat mode the cluster is gone and the markers were
   * never on the map by themselves, so every count came out zero while the map
   * was full of points. It reads the filtered set instead.
   */
  function inViewport() {
    const bounds = map.getBounds();
    return activeMarkers()
      .filter(({ marker }) => bounds.contains(marker.getLatLng()))
      .map(({ data }) => data);
  }

  return {
    list: selList,
    update() {
      if (!selIps) return;
      const data = inViewport();
      const { counts, byCountry } = summariseSelection(data);

      selIps.textContent = fmtNum(data.length);
      selCountries.textContent = fmtNum(Object.keys(byCountry).length);
      selThreats.textContent = fmtNum(counts.threats);
      if (headCount) headCount.textContent = fmtNum(data.length) + ' IPs in viewport';

      selMix.style.background = gradient(counts, data.length);
      selMix.dataset.tip = mixSummary(counts);
      selLegend.innerHTML = mixLegendHtml(counts);
      selList.innerHTML = countryRowsHtml(byCountry, gradient);
    },
  };
}

/**
 * Shift-dragging a box is Leaflet's own box-zoom; the resulting window is
 * surfaced as a removable pill so the narrowing is visible and undoable.
 */
function createViewportPill(map) {
  return function setViewportPill(center) {
    const rail = document.querySelector('.filter-rail-row');
    if (!rail) return;
    const existing = rail.querySelector('.viewport-pill');
    if (existing) existing.remove();
    if (!center) return;
    const pill = document.createElement('span');
    pill.className = 'drill-pill viewport-pill';
    // The coordinate is the centre of the box, but what the pill *selects* is
    // everything the map currently shows — which the number alone never said.
    pill.dataset.tipWhat = 'The selection follows the map view.';
    pill.dataset.tipSource = 'Counts and lists are recomputed from the markers inside the current bounds.';
    pill.innerHTML = `<strong>Viewport</strong><code>${esc(viewportLabel(center))}</code>` +
                     '<a href="#" aria-label="Reset viewport">✕</a>';
    pill.querySelector('a').addEventListener('click', (e) => {
      e.preventDefault();
      map.setView([30, 0], 2);
      setViewportPill(null);
    });
    rail.appendChild(pill);
  };
}

document.addEventListener('DOMContentLoaded', () => {
  if (!document.getElementById('markers-data')) return; // not on geo page
  // cssVar and esc are provided by utils.js loaded in base.html

  const rows = JSON.parse(document.getElementById('markers-data').textContent);
  _geoMap = L.map('map', {
    minZoom: 2, maxBounds: [[-85, -180], [85, 180]],
    maxBoundsViscosity: 1.0,
  }).setView([30, 0], 2);
  _geoTileLayer = L.tileLayer(getTileUrl(), tileOptions()).addTo(_geoMap);

  const map = _geoMap;
  const allMarkers = buildMarkers(rows);
  const cluster = buildCluster();
  allMarkers.forEach(({ marker }) => cluster.addLayer(marker));
  map.addLayer(cluster);
  addServerMarker(map);

  const activeMarkers = () => railFilter(allMarkers);

  // The legend asks the heat view for its state and the heat view tells the
  // legend to redraw, so one of the two has to be named before it exists.
  let heat = null;
  const legend = createLegend(map, () => !!heat && heat.isOn(), () => (heat ? heat.peak() : 0));
  heat = createHeatView(map, activeMarkers, legend.render);
  const selection = createSelectionPanel(map, activeMarkers);
  const setViewportPill = createViewportPill(map);

  // Re-resolve marker/cluster/legend colors from the CSS tokens (theme change).
  _recolorGeo = function () {
    allMarkers.forEach(({ marker }) => {
      const color = cssVar(CLASS_COLORS[marker._grp] || 'grp-unknown');
      marker.setStyle({ fillColor: color, color });
    });
    cluster.refreshClusters();
    document.querySelectorAll('.map-legend .ldot[data-grp]').forEach((dot) => {
      dot.style.background = cssVar(CLASS_COLORS[dot.dataset.grp] || 'grp-unknown');
    });
  };

  function refresh() {
    cluster.clearLayers();
    activeMarkers().forEach(({ marker }) => cluster.addLayer(marker));
    heat.draw();
    selection.update();
  }

  [
    document.querySelector('.visitor-filter-bar [name="country"]'),
    document.querySelector('.visitor-filter-bar [name="min_visits"]'),
  ].forEach((el) => { if (el) el.addEventListener('input', refresh); });

  // Clicking a country zooms to its markers and applies the country filter.
  if (selection.list) {
    selection.list.addEventListener('click', (e) => {
      const row = e.target.closest('[data-country]');
      if (!row) return;
      e.preventDefault();
      const cc = row.dataset.country;
      const pts = allMarkers
        .filter(({ data }) => (data.country_code || '—') === cc)
        .map(({ marker }) => marker.getLatLng());
      if (pts.length) map.fitBounds(L.latLngBounds(pts), { padding: [40, 40], maxZoom: 6 });
      const url = new URL(window.location.href);
      url.searchParams.set('country', cc);
      setViewportPill(null);
      window.location.href = url.toString();
    });
  }

  document.querySelectorAll('[data-map-mode]').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('[data-map-mode]').forEach((b) =>
        b.classList.toggle('active', b === btn));
      heat.setOn(btn.dataset.mapMode === 'heat', cluster);
      legend.render();
      selection.update();
    });
  });

  map.on('boxzoomend', (e) => setViewportPill(e.boxZoomBounds.getCenter()));
  map.on('moveend zoomend', () => { heat.draw(); selection.update(); });
  selection.update();
});
