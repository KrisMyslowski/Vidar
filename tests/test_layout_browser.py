"""What the browser actually lays out — measured, not inferred.

Every other test in this suite reads markup. Markup was never the problem: both
column defects rendered perfectly valid HTML and still put the ISP heading over
the Signals bar, or left the table at half the container's width. jsdom cannot
see that (it computes no layout), so this module starts the app, drives a real
headless browser, and measures.

It skips itself when no browser is installed, the same way the JS suite skips
without node. Set VIDAR_CHROME to point at one explicitly.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

LAYOUT_DIR = Path(__file__).parent / "layout"
MEASURE = LAYOUT_DIR / "measure.mjs"
REPORT = LAYOUT_DIR / "report.js"
MAP_REPORT = LAYOUT_DIR / "map_report.js"
TIMELINE_REPORT = LAYOUT_DIR / "timeline_report.js"
RANGE_REPORT = LAYOUT_DIR / "range_report.js"
ROOT = Path(__file__).resolve().parent.parent

# The widths the stylesheet assigns per column type, in rem (c-group is 132px).
# They live in tables.css since dashboard.css was split.
# Percentage types resolve against the table and are checked separately.
CLASS_REM = {
    "c-num": 4.5,
    "c-cc": 4.0,
    "c-port": 5.5,
    "c-badge": 6.5,
    "c-date": 8.0,
    "c-ip": 10.0,
    "c-mix": 9.0,
    "c-city": 8.0,
    "c-text": 12.0,
    "c-textsm": 8.0,
    "c-client": 11.0,
    "c-group": 8.25,
    "c-total": 5.0,
    "c-wide": 20.0,
}
# c-wide marks the column a table is about; it must lead its table.
DOMINANT_CLASS = "c-wide"

PAGES = [
    "/",
    "/visitors",
    "/visitors?group=asn",
    "/visitors?group=country",
    "/visitors?group=client",
    "/visitors?group=path",
    "/analysis",
    "/exposure",
    "/visitors/203.0.113.10",
]
# Below 1100px the tables become a card layout — a different system with no
# column widths at all, covered by its own case.
VIEWPORTS = [1280, 1600, 1920]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def _node():
    if not shutil.which("node"):
        pytest.skip("node not installed — layout is not measured")
    return shutil.which("node")


@pytest.fixture(scope="module")
def server(_node, tmp_path_factory):
    """The real app on a real port, seeded like the dashboard_db fixture."""
    from src.db import get_conn, init_db
    from src.queries import insert_visit, set_visitor_class, upsert_ip_intel
    from tests.test_dashboard_routes import _intel

    db = tmp_path_factory.mktemp("layout") / "layout.db"
    log = tmp_path_factory.mktemp("layout-log") / "access.log"
    log.write_text("")
    init_db(db)
    with get_conn(db) as conn:
        for ip, path, status in [
            ("203.0.113.10", "/", 200),
            ("203.0.113.20", "/wp-admin/setup-config.php", 404),
            ("2001:db8:1234:5678::1", "/api/v1/status", 200),
        ]:
            # Spread over a fortnight and across the clock: the activity chart
            # needs something to zoom into, and hourly buckets need hours that
            # differ.
            for n in range(14):
                insert_visit(
                    conn,
                    ip=ip,
                    timestamp=f"2026-07-{20 + n // 2:02d}T{(n * 5) % 24:02d}:00:00+00:00",
                    method="GET",
                    path=path,
                    status=status,
                    bytes_sent=1234,
                    browser="Mobile Safari 13.2.3",
                    os="iOS 13.2",
                )
        # Three continents, so the heat grid has more than one cell to shade.
        upsert_ip_intel(
            conn,
            _intel("203.0.113.10", isp="Deutsche Telekom AG", city="Frankfurt", lat=50.1, lon=8.7),
        )
        upsert_ip_intel(
            conn,
            _intel(
                "203.0.113.20",
                isp="Amazon Data Services",
                city="Ashburn",
                country="United States",
                country_code="US",
                lat=39.0,
                lon=-77.5,
            ),
        )
        upsert_ip_intel(
            conn,
            _intel(
                "2001:db8:1234:5678::1",
                isp="Censys",
                city="Singapore",
                country="Singapore",
                country_code="SG",
                lat=1.35,
                lon=103.8,
            ),
        )
        set_visitor_class(conn, "203.0.113.10", "humans/browser-direct")
        set_visitor_class(conn, "203.0.113.20", "threats/exploit-probers")
        set_visitor_class(conn, "2001:db8:1234:5678::1", "bots/security-researchers")

    port = _free_port()
    env = {**os.environ, "DB_PATH": str(db), "LOG_PATH": str(log)}
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "src.main:app",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                import urllib.request

                urllib.request.urlopen(base + "/health", timeout=1)
                break
            except Exception:
                if proc.poll() is not None:
                    pytest.skip("app did not start")
                time.sleep(0.1)
        else:
            pytest.skip("app did not answer /health")
        yield base
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def measure(node, jobs, expression=None):
    """Geometry of every table for each job, keyed by the job's key.

    One browser handles every job: starting one per page/viewport turned a
    5-second check into a 40-second one.
    """
    out = subprocess.run(
        [node, str(MEASURE), str(expression or REPORT)],
        input=json.dumps(jobs),
        capture_output=True,
        text=True,
        timeout=300,
    )
    if out.returncode == 3:
        pytest.skip(f"no browser available: {out.stderr.strip()}")
    assert out.returncode == 0, f"measuring failed: {out.stderr}"
    return json.loads(out.stdout)


@pytest.fixture(scope="module")
def geometry(_node, server):
    """Every page at every viewport, measured once for all assertions below."""
    jobs = [
        {"key": f"{path} @{width}", "url": server + path, "width": width}
        for path in PAGES
        for width in VIEWPORTS
    ]
    return measure(_node, jobs)


def _cases(geometry):
    for where, states in geometry.items():
        for t in states:
            yield f"{where} [{t['state']}] table#{t['table']}", t


def test_tables_never_leave_their_container_half_empty(geometry):
    """A table must use the space it is given.

    Too narrow is the half-empty page from the report: the one unsized column
    was the one being hidden, so the table shrank to the sum of the remaining
    fixed widths and stopped there.
    """
    bad = [
        f"{where}: {t['width']}px in a {t['container']}px container"
        for where, t in _cases(geometry)
        if t["display"] == "table" and t["container"] - t["width"] > 4
    ]
    assert not bad, "tables that do not fill their container:\n" + "\n".join(bad)


def test_nothing_is_clipped_out_of_reach(geometry):
    """More columns than fit is a choice the reader may make. Losing one is not.

    A fixed-layout table is at least as wide as its columns add up to, so
    switching on all twelve overflows — and with `overflow: hidden` on the
    wrapper, Last Seen was simply gone from the page. The surplus has to stay
    reachable by scrolling.
    """
    bad = []
    for where, t in _cases(geometry):
        if t["display"] != "table" or t["width"] - t["container"] <= 4:
            continue
        sc = t["scroller"]
        if not sc:
            bad.append(f"{where}: {t['width']}px table in {t['container']}px, nothing scrolls")
        elif sc["scrollW"] - sc["clientW"] < t["width"] - t["container"] - 4:
            bad.append(
                f"{where}: {t['width'] - t['container']}px overflow but only "
                f"{sc['scrollW'] - sc['clientW']}px of it can be scrolled to"
            )
    assert not bad, "table content that cannot be reached:\n" + "\n".join(bad)


def test_no_visible_column_collapses(geometry):
    """A visible heading with zero width — ISP vanished exactly this way."""
    bad = [
        f"{where}: {c['label'] or c['key']} is {c['w']}px"
        for where, t in _cases(geometry)
        for c in t["cols"]
        if c["w"] < 8
    ]
    assert not bad, "columns rendered at (almost) zero width:\n" + "\n".join(bad)


def test_body_cells_line_up_with_their_heading(geometry):
    """The first defect: every row one column left of its heading."""
    bad = []
    for where, t in _cases(geometry):
        if not t["bodyX"]:
            continue
        heads = [c["x"] for c in t["cols"]]
        if len(heads) != len(t["bodyX"]):
            bad.append(f"{where}: {len(t['bodyX'])} body cells vs {len(heads)} headings")
            continue
        for i, (hx, bx) in enumerate(zip(heads, t["bodyX"], strict=True)):
            if abs(hx - bx) > 1:
                bad.append(f"{where}: column {i} heading at {hx}px, cell at {bx}px")
    assert not bad, "rows that do not line up with their headings:\n" + "\n".join(bad)


def test_equal_column_types_render_equally_wide(geometry):
    """Two c-mix columns must be the same width.

    The second defect made them 602px and 144px, because the widths were
    assigned one position off. Comparing types instead of absolute pixels keeps
    this independent of how a browser distributes leftover space.
    """
    bad = []
    for where, t in _cases(geometry):
        by_class = {}
        for c in t["cols"]:
            if c["cls"] in CLASS_REM:
                by_class.setdefault(c["cls"], []).append(c)
        for cls, cols in by_class.items():
            widths = {c["w"] for c in cols}
            if max(widths) - min(widths) > 2:
                shown = ", ".join(f"{c['label'] or c['key']}={c['w']}" for c in cols)
                bad.append(f"{where}: {cls} columns differ ({shown})")
    assert not bad, "same column type, different width:\n" + "\n".join(bad)


def test_wider_types_render_wider(geometry):
    """A 10rem column must not end up narrower than a 4.5rem one.

    Absolute pixels are the browser's business — it spreads leftover space over
    the columns and scales them down together when they don't fit. The order is
    ours: it encodes which column deserves the room.
    """
    bad = []
    for where, t in _cases(geometry):
        typed = [c for c in t["cols"] if c["cls"] in CLASS_REM]
        for a in typed:
            for b in typed:
                if CLASS_REM[a["cls"]] - CLASS_REM[b["cls"]] > 0.4 and a["w"] < b["w"] - 2:
                    bad.append(
                        f"{where}: {a['label']} ({a['cls']}, {a['w']}px) "
                        f"narrower than {b['label']} ({b['cls']}, {b['w']}px)"
                    )
    assert not bad, "column widths out of order:\n" + "\n".join(sorted(set(bad)))


def test_dominant_column_stays_dominant(geometry):
    """c-wide marks the column a table is about (Path). It must lead."""
    bad = [
        f"{where}: {c['label']} is {c['w']}px, widest is {max(x['w'] for x in t['cols'])}px"
        for where, t in _cases(geometry)
        for c in t["cols"]
        if c["cls"] == DOMINANT_CLASS and c["w"] < max(x["w"] for x in t["cols"])
    ]
    assert not bad, "dominant columns that are not the widest:\n" + "\n".join(bad)


def test_card_layout_stacks_instead_of_sizing_columns(_node, server):
    """Below 1100px the table becomes cards — a different system with no column
    widths at all. Checked so a width change cannot silently reach into it."""
    states = measure(_node, [{"key": "cards", "url": server + "/visitors", "width": 900}])["cards"]
    tables = [t for t in states if t["state"] == "default"]
    assert tables, "no table measured at 900px"
    for t in tables:
        assert t["display"] == "block", f"table still laid out as a table at 900px: {t['display']}"


@pytest.fixture(scope="module")
def map_view(_node, server):
    """The map page driven through both view modes, measured once."""
    return measure(
        _node,
        [{"key": "map", "url": server + "/visitors?view=map", "width": 1600}],
        expression=MAP_REPORT,
    )["map"]


def test_heat_view_keeps_the_selection_panel_alive(map_view):
    """The panel used to read 0 IPs / 0 countries / 0 threats in Heat.

    It asked which *layer* held a marker, and in Heat the cluster is gone while
    the markers were never on the map by themselves — so every count came out
    zero over a map full of points.
    """
    assert map_view["cluster"]["ips"] > 0, "nothing on the map to begin with"
    assert map_view["heat"] == map_view["cluster"], (
        f"selection differs by view mode: heat={map_view['heat']} "
        f"cluster={map_view['cluster']}"
    )
    # Switching back does not move the map, so the numbers must be the ones
    # from after the cell click — the mode never changes what is selected.
    assert map_view["backToCluster"] == map_view["afterCellClick"]


def test_heat_draws_clickable_cells(map_view):
    """Heat used to be non-interactive discs — nothing to hover, nothing to
    click. The grid cells carry a tooltip and zoom the map."""
    assert map_view["heatCells"] > 1, "heat drew no separate cells"
    assert map_view["afterCellClick"] is not None
    assert map_view["afterCellClick"]["ips"] <= map_view["heat"]["ips"]
    assert map_view["afterCellClick"]["countries"] <= map_view["heat"]["countries"]


def test_heat_legend_explains_the_shade(map_view):
    """A density ramp says nothing about identity, so the legend must stop
    listing classes and name what the shade means instead."""
    assert "IPs per cell" in map_view["heatLegend"]


def test_map_controls_do_not_cover_each_other(map_view):
    """The mode switch sat on top of Leaflet's zoom buttons."""
    assert map_view["controls"]["toggle"], "no mode switch found"
    assert map_view["controls"]["zoom"], "no zoom control found"
    assert not any(
        map_view["collisions"].values()
    ), f"overlapping map controls: {map_view['collisions']} at {map_view['controls']}"


@pytest.fixture(scope="module")
def timeline_view(_node, server):
    """The activity chart driven through hover, two zooms and back out.

    On the timeline view, not the Overview: the chart moved there to answer for
    the current selection. This pointed at "/" until the suite first ran on a
    machine that had a browser, which was CI.
    """
    return measure(
        _node,
        [{"key": "tl", "url": server + "/visitors?view=timeline", "width": 1600}],
        expression=TIMELINE_REPORT,
    )["tl"]


def test_activity_draws_one_line_per_group(timeline_view):
    """Stacked bars showed the total and hid the groups; a segment in the middle
    of a stack sits on whatever is below it."""
    assert not timeline_view.get("missing"), "no activity chart on the timeline view"
    assert timeline_view["initial"]["lines"] == 5
    assert timeline_view["initial"]["buckets"] > 5
    assert timeline_view["initial"]["xLabels"], "no date marks on the axis"
    assert timeline_view["fits"], "the chart runs outside its panel"


def test_hover_names_every_series(timeline_view):
    """The total moved from the bar's height into the tooltip, so the tooltip
    has to carry it — and each group's number beside it."""
    assert timeline_view["tooltip"]["shown"]
    assert timeline_view["cursorShown"]
    assert timeline_view["tooltip"]["rows"] >= 1
    assert "visits" in timeline_view["tooltip"]["text"]


def test_dragging_zooms_and_the_zoombar_undoes_it(timeline_view):
    """Drag is the precise way in, the zoombar the coarse way and the only way
    back out. Each step out undoes one step in, so two drags take two clicks."""
    before = timeline_view["initial"]["buckets"]
    zoomed = timeline_view["afterDrag"]
    assert zoomed["buckets"] < before, "the drag did not narrow the chart"
    assert zoomed["zoomedIn"], "zoomed in, but the way out is still disabled"
    assert not timeline_view["initial"]["zoomedIn"], "unzoomed, but out is offered"
    assert timeline_view["afterReset"]["buckets"] == before
    assert not timeline_view["afterReset"]["zoomedIn"]


def test_a_short_window_switches_to_hours(timeline_view):
    """Zoomed to a couple of days, daily points say nothing — which is the whole
    reason to zoom that far."""
    labels = timeline_view["afterShortDrag"]["xLabels"]
    assert any(":" in t for t in labels), f"no hourly marks: {labels}"


@pytest.fixture(scope="module")
def range_control(_node, server):
    """The Custom range control, opened on the table view and on the map."""
    return measure(
        _node,
        [
            {"key": "table", "url": server + "/visitors", "width": 1600},
            {"key": "map", "url": server + "/visitors?view=map", "width": 1600},
            {"key": "overview", "url": server + "/", "width": 1600},
        ],
        expression=RANGE_REPORT,
    )


@pytest.mark.parametrize("page", ["table", "map", "overview"])
def test_custom_range_panel_is_reachable(range_control, page):
    """Custom opens a panel that a reader can actually click into.

    It could not, since the release UI moved the control inside the segmented
    tab strip: .tab-group carried overflow:hidden for its rounded corners and
    clipped the panel away. Nothing in the markup shows that — the panel was
    there, open, and invisible.
    """
    view = range_control[page]
    assert not view.get("missing"), f"{page}: no Custom control"
    assert view["open"], f"{page}: the panel did not open"
    assert view["rect"]["h"] > 20, f"{page}: the panel has no height: {view['rect']}"
    assert view["reachable"], (
        f"{page}: a click in the middle of the panel lands on "
        f"{view['hitSelector']} instead of the form"
    )
    assert view["insideWindow"], f"{page}: the panel hangs outside the window: {view['rect']}"
    cutting = [c for c in view["clippers"] if c["cuts"]]
    assert not cutting, f"{page}: the panel is clipped by {cutting}"


def test_custom_range_keeps_the_view_it_was_opened_from(range_control):
    """Applying a custom window on the map must come back to the map."""
    assert "view=map" in range_control["map"]["hidden"]
    assert range_control["map"]["action"] == "/visitors"
