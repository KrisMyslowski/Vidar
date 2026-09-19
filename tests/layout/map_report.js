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
  // A fixed wait is a guess at how long Leaflet takes, and on a slow CI runner
  // it guessed short: a heat cell's fitBounds was still under way when the
  // numbers were read, so "after the click" and "back to cluster" saw two
  // different viewports (3 countries / 8 IPs, then 1 / 6).
  //
  // The panel's numbers alone cannot say the map has stopped: selection.update()
  // runs on moveend, so they sit still for the whole animation. Settled is
  // therefore the map pane's transform, the zoom-animation class and the
  // numbers all unchanged over a window longer than Leaflet's 250ms animation.
  const settled = async (timeout = 8000) => {
    const container = document.getElementById('map');
    const pane = container && container.querySelector('.leaflet-map-pane');
    const signature = () =>
      JSON.stringify([
        container && container.classList.contains('leaflet-zoom-anim'),
        pane && pane.style.transform,
        selection(),
      ]);
    const deadline = Date.now() + timeout;
    let last = null;
    let stable = 0;
    while (Date.now() < deadline) {
      await wait(100);
      const now = signature();
      stable = now === last ? stable + 1 : 0;
      last = now;
      if (stable >= 5) return;
    }
  };
  const mode = async (name) => {
    const btn = [...document.querySelectorAll('[data-map-mode]')].find(
      (b) => b.dataset.mapMode === name
    );
    btn.click();
    await settled();
  };
  const box = (sel) => {
    const el = document.querySelector(sel);
    if (!el) return null;
    const r = el.getBoundingClientRect();
    return { x: Math.round(r.left), y: Math.round(r.top), w: Math.round(r.width), h: Math.round(r.height) };
  };
  const overlap = (a, b) =>
    !!a && !!b && a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

  await settled(); // Leaflet lays the map out after its own tick

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
    // heat.draw() rebuilds every cell on moveend, so the clicked one leaving the
    // DOM is the proof the move finished — only then is settling meaningful.
    const deadline = Date.now() + 8000;
    while (target.isConnected && Date.now() < deadline) await wait(50);
    await settled();
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
