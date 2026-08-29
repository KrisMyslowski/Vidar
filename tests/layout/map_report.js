/* Runs inside the map page. Drives the two view modes and reports what the
 * reader would see: the selection numbers, whether the controls collide, and
 * what a click on a heat cell does. */
(async () => {
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const num = (id) => {
    const el = document.getElementById(id);
    return el ? parseInt(el.textContent.replace(/[^0-9]/g, ''), 10) || 0 : null;
  };
  const selection = () => ({
    ips: num('sel-ips'),
    countries: num('sel-countries'),
    threats: num('sel-threats'),
    countryRows: document.querySelectorAll('#sel-countries-list [data-country]').length,
  });
  const mode = (name) => {
    const btn = [...document.querySelectorAll('[data-map-mode]')].find(
      (b) => b.dataset.mapMode === name
    );
    btn.click();
    return wait(500);
  };
  const box = (sel) => {
    const el = document.querySelector(sel);
    if (!el) return null;
    const r = el.getBoundingClientRect();
    return { x: Math.round(r.left), y: Math.round(r.top), w: Math.round(r.width), h: Math.round(r.height) };
  };
  const overlap = (a, b) =>
    !!a && !!b && a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

  await wait(600); // Leaflet lays the map out after its own tick

  const cluster = selection();
  await mode('heat');
  const heat = selection();
  const cells = document.querySelectorAll('#map .leaflet-interactive').length;
  const legend = (document.querySelector('.map-legend') || {}).textContent || '';

  // Click the busiest-looking cell: whichever rectangle is most opaque.
  const rects = [...document.querySelectorAll('#map path.leaflet-interactive')];
  let clicked = null;
  if (rects.length) {
    const target = rects.reduce((best, r) =>
      parseFloat(r.getAttribute('fill-opacity') || 0) > parseFloat(best.getAttribute('fill-opacity') || 0)
        ? r
        : best
    );
    target.dispatchEvent(new MouseEvent('click', { bubbles: true, view: window }));
    await wait(900);
    clicked = selection();
  }

  await mode('cluster');
  const backToCluster = selection();

  return {
    cluster,
    heat,
    afterCellClick: clicked,
    backToCluster,
    heatCells: cells,
    heatLegend: legend.trim().slice(0, 60),
    controls: {
      toggle: box('.map-overlay--tr'),
      zoom: box('.leaflet-control-zoom'),
      legend: box('.map-legend'),
      hint: box('.map-hint'),
    },
    collisions: {
      toggleZoom: overlap(box('.map-overlay--tr'), box('.leaflet-control-zoom')),
      toggleLegend: overlap(box('.map-overlay--tr'), box('.map-legend')),
      hintLegend: overlap(box('.map-hint'), box('.map-legend')),
    },
  };
})()
