/* Whether the page is wider than the window, and what makes it so.
 *
 * `html, body { overflow-x: hidden }` hid any such overflow instead of showing it,
 * so nothing was ever measured here. An element counts when its right edge passes
 * the viewport and no ancestor between it and <body> scrolls or clips it on the
 * x axis — content inside a table scroller is reachable, content out here is not. */
(() => {
  const width = document.documentElement.clientWidth;
  const offenders = [];
  for (const el of document.body.querySelectorAll('*')) {
    const r = el.getBoundingClientRect();
    if (r.width === 0 || r.right <= width + 1) continue;
    // A closed <details> still lays its content out, just unrendered — an
    // absolutely positioned filter menu reached past the edge without anybody
    // being able to see it. Not an overflow a reader meets.
    if (!el.checkVisibility({ visibilityProperty: true, contentVisibilityAuto: true })) continue;
    let contained = false;
    for (let n = el.parentElement; n && n !== document.body; n = n.parentElement) {
      if (getComputedStyle(n).overflowX !== 'visible') { contained = true; break; }
    }
    if (contained) continue;
    // Report the outermost offender only: its children overflow because it does.
    if (offenders.some((o) => o.node.contains(el))) continue;
    offenders.push({ node: el });
  }
  return {
    viewport: width,
    scrollWidth: document.documentElement.scrollWidth,
    offenders: offenders.slice(0, 8).map(({ node }) => ({
      sel: node.tagName.toLowerCase() + (node.id ? '#' + node.id : '') +
        (node.className && typeof node.className === 'string' ? '.' + node.className.trim().split(/\s+/).join('.') : ''),
      right: Math.round(node.getBoundingClientRect().right),
    })),
  };
})()
