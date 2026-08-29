/* Opens the Custom range control and reports whether it is actually usable:
 * visible, hit-testable, inside the window — and whether submitting it lands on
 * a URL that carries the dates and the view. */
(async () => {
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const box = document.querySelector('.range-custom');
  if (!box) return { missing: true };

  box.querySelector('summary').click();
  await wait(200);

  const form = box.querySelector('.range-custom-form');
  const r = form.getBoundingClientRect();
  const cx = r.x + r.width / 2;
  const cy = r.y + r.height / 2;
  const hit = document.elementFromPoint(cx, cy);

  // Anything between the form and the viewport that clips it away.
  const clippers = [];
  for (let n = form.parentElement; n && n !== document.body; n = n.parentElement) {
    const cs = getComputedStyle(n);
    if (cs.overflow !== 'visible' || cs.overflowX !== 'visible' || cs.overflowY !== 'visible') {
      const b = n.getBoundingClientRect();
      const cuts = r.bottom > b.bottom + 1 || r.top < b.top - 1 || r.right > b.right + 1;
      clippers.push({
        sel: n.tagName.toLowerCase() + '.' + String(n.className).split(' ')[0],
        overflow: cs.overflow + '/' + cs.overflowX,
        cuts,
      });
    }
  }

  const from = form.querySelector('[name="date_from"]');
  const to = form.querySelector('[name="date_to"]');
  from.value = '2026-07-01';
  to.value = '2026-07-15';
  const action = form.getAttribute('action');
  const hidden = [...form.querySelectorAll('input[type=hidden]')].map(
    (i) => i.name + '=' + i.value
  );

  return {
    open: box.open,
    rect: { x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height) },
    // The form is usable only if a click at its middle reaches it.
    reachable: !!(hit && form.contains(hit)),
    hitSelector: hit ? hit.tagName.toLowerCase() + '.' + String(hit.className).split(' ')[0] : null,
    insideWindow: r.right <= window.innerWidth + 1 && r.bottom <= window.innerHeight + 1,
    clippers,
    action,
    hidden,
  };
})()
