/* Runs inside the page. Reports the geometry of every laid-out table, once as
 * delivered and once for each column the picker can hide — because both column
 * bugs only appeared after something was hidden. */
(() => {
  const visible = (el) => getComputedStyle(el).display !== 'none';
  const round = (n) => Math.round(n);

  // The space a table may fill: the parent's box minus its padding. A panel
  // pads its content, and a table is not expected to sit in that padding.
  function contentWidth(el) {
    const cs = getComputedStyle(el);
    return el.getBoundingClientRect().width - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight);
  }

  // The nearest ancestor that scrolls. A table wider than its container is
  // only acceptable if the reader can reach the rest of it.
  function scroller(el) {
    for (let n = el.parentElement; n && n !== document.body; n = n.parentElement) {
      const ox = getComputedStyle(n).overflowX;
      if (ox === 'auto' || ox === 'scroll') {
        return { clientW: n.clientWidth, scrollW: n.scrollWidth };
      }
    }
    return null;
  }

  function snapshot(state) {
    return [...document.querySelectorAll('table')]
      .filter((t) => t.tHead && t.getBoundingClientRect().width > 0)
      .map((t, i) => {
        const ths = [...t.tHead.rows[0].cells].filter(visible);
        const bodyRows = [...(t.tBodies[0] ? t.tBodies[0].rows : [])];
        const dataRow = bodyRows.find(
          (r) => r.cells.length > 1 && !r.cells[0].hasAttribute('colspan')
        );
        const cells = dataRow ? [...dataRow.cells].filter(visible) : [];
        return {
          state,
          table: i,
          container: round(contentWidth(t.parentElement)),
          width: round(t.getBoundingClientRect().width),
          display: getComputedStyle(t).display,
          scroller: scroller(t),
          cols: ths.map((th) => {
            const r = th.getBoundingClientRect();
            return {
              label: th.textContent.trim().replace(/[↑↓⇅]/g, '').trim(),
              key: th.dataset.col || null,
              cls: [...th.classList].find((c) => c.startsWith('c-')) || null,
              w: round(r.width),
              x: round(r.left),
            };
          }),
          bodyX: cells.map((td) => round(td.getBoundingClientRect().left)),
        };
      });
  }

  const states = snapshot('default');

  // Tables inside a closed tab panel have no layout yet. The Overview's Top
  // block keeps five of its six tables there, so open each one and measure.
  for (const tab of document.querySelectorAll('[data-tab]')) {
    tab.click();
    states.push(...snapshot('tab ' + tab.dataset.tab));
  }

  // The extremes, which one-at-a-time toggling never reaches: everything the
  // picker offers switched on (the widest the table can get — it must still fit
  // its container) and everything switched off (the narrowest — it must still
  // fill it).
  const boxes = [...document.querySelectorAll('[data-col-toggle]')];
  const setAll = (checked) =>
    boxes.forEach((b) => {
      if (b.checked !== checked) {
        b.checked = checked;
        b.dispatchEvent(new Event('change', { bubbles: true }));
      }
    });
  if (boxes.length) {
    const initial = boxes.map((b) => b.checked);
    setAll(true);
    states.push(...snapshot('every column'));
    setAll(false);
    states.push(...snapshot('no optional column'));
    boxes.forEach((b, i) => {
      if (b.checked !== initial[i]) {
        b.checked = initial[i];
        b.dispatchEvent(new Event('change', { bubbles: true }));
      }
    });
  }

  for (const box of boxes) {
    const was = box.checked;
    const flip = () => box.dispatchEvent(new Event('change', { bubbles: true }));
    box.checked = !was;
    flip();
    states.push(...snapshot((was ? 'without ' : 'with ') + box.dataset.colToggle));
    box.checked = was;
    flip();
  }
  return states;
})()
