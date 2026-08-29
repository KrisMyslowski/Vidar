"""Tests for dashboard HTML routes (all views + legacy 301 redirects)."""

import json
import re
from datetime import date, datetime, timedelta, timezone
from html import unescape
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from src import archive
from src.db import get_conn
from src.main import app
from src.queries import (
    count_networks,
    count_visits,
    get_activity_timeline,
    get_clients,
    get_countries,
    get_geo_data,
    get_identity_signal_matrix,
    get_networks,
    get_paths,
    get_top_ports,
    get_top_tags,
    get_visitor_ip_counts,
    get_visitors_grouped,
    insert_visit,
    set_visitor_class,
    upsert_ip_intel,
)
from src.taxonomy import VISITOR_CATEGORIES
from tests.conftest import dashboard_css

STATIC = Path(__file__).resolve().parent.parent / "src" / "static"


@pytest.fixture
def client(tmp_db):
    """FastAPI test client with patched DB path."""
    from src.config import settings

    with patch.object(settings, "db_path", tmp_db):
        yield TestClient(app)


def _intel(ip: str, **overrides) -> dict:
    """Complete ip_intel row with sensible defaults."""
    base = {
        "ip": ip,
        "country": "Germany",
        "country_code": "DE",
        "city": "Berlin",
        "lat": 52.5,
        "lon": 13.4,
        "isp": "Test ISP",
        "org": "Test Org",
        "asn": "AS1",
        "is_proxy": False,
        "is_hosting": False,
        "is_mobile": False,
        "reverse_dns": "",
        "open_ports": "",
        "tags": "",
        "hostnames": "",
        "cpes": "",
        "vulns": "",
        "is_tor": False,
        "dnsbl_listed": False,
        "dnsbl_sources": "",
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    base.update(overrides)
    return base


@pytest.fixture
def dashboard_db(tmp_db):
    """DB with one classified human and one classified bot visitor."""
    now = datetime.now(timezone.utc).isoformat()
    with get_conn(tmp_db) as conn:
        insert_visit(
            conn,
            ip="203.0.113.10",
            timestamp=now,
            method="GET",
            path="/",
            status=200,
            bytes_sent=5000,
            browser="Chrome",
            os="Windows",
        )
        insert_visit(
            conn,
            ip="203.0.113.20",
            timestamp=now,
            method="GET",
            path="/wp-admin",
            status=404,
            bytes_sent=0,
            browser="Bot",
            os="Unknown",
        )
        upsert_ip_intel(conn, _intel("203.0.113.10"))
        upsert_ip_intel(conn, _intel("203.0.113.20", country="United States", country_code="US"))
        set_visitor_class(conn, "203.0.113.10", "humans/browser-direct")
        set_visitor_class(conn, "203.0.113.20", "bots/generic-bots")
    yield tmp_db


class TestDashboardViews:
    """Every HTML view renders with status 200 and its page header."""

    @pytest.mark.parametrize(
        "path,marker",
        [
            ("/", "Overview"),
            ("/visitors", "Visitors"),
            ("/visitors?group=asn", "Networks"),
            ("/visitors?group=country", "Countries"),
            ("/visitors?group=client", "Clients"),
            ("/visitors?group=path", "Paths"),
            ("/visitors?view=map", 'id="map"'),
            ("/analysis", "Analysis"),
            ("/exposure", "Shodan"),
        ],
    )
    def test_view_renders(self, client, dashboard_db, path, marker):
        with patch("src.config.settings.db_path", dashboard_db):
            response = client.get(path)
        assert response.status_code == 200
        assert marker in response.text

    @pytest.mark.parametrize("group", ["ip", "asn", "country", "client", "path"])
    def test_group_renders_its_table(self, client, dashboard_db, group):
        """Every grouping renders its own table block through the shared frame."""
        with patch("src.config.settings.db_path", dashboard_db):
            response = client.get(f"/visitors?group={group}")
        assert response.status_code == 200
        assert f'data-table-key="visitors-{group}"' in response.text

    def test_unknown_group_and_view_fall_back(self, client, dashboard_db):
        """A bogus ?group=/?view= renders the default instead of erroring."""
        with patch("src.config.settings.db_path", dashboard_db):
            response = client.get("/visitors?group=bogus&view=bogus")
        assert response.status_code == 200
        assert 'data-table-key="visitors-ip"' in response.text

    def test_group_sort_whitelist_is_per_group(self, client, dashboard_db):
        """A sort key valid for another grouping falls back to that group's default."""
        with patch("src.config.settings.db_path", dashboard_db):
            response = client.get("/visitors?group=asn&sort=unique_pages")
        assert response.status_code == 200
        # unique_pages belongs to the IP grouping — asn falls back to visits.
        assert "sort=visits" in response.text

    def test_timeline_view_shows_heatmap(self, client, dashboard_db):
        """The traffic-rhythm heatmap renders on the timeline view.

        It used to sit on the Overview, where it could only ever be all-time; it
        belongs beside the activity chart, on the page that has a selection. It
        carries no controls of its own — the page's group chips are the control,
        and they narrow the chart and the tables with it.
        """
        with patch("src.config.settings.db_path", dashboard_db):
            response = client.get("/visitors?view=timeline")
        assert response.status_code == 200
        assert "Traffic Rhythm" in response.text
        assert 'class="heatmap"' in response.text
        assert "data-hm-group" not in response.text, "the grid grew its own group toggle again"

    def test_the_heatmap_answers_for_the_current_filter(self, client, dashboard_db):
        """Filtering the page filters the heatmap.

        The fixture holds one human and one bot. Unfiltered the grid counts both;
        filtered to humans it counts one — otherwise the heatmap is answering a
        different question from the chart directly above it, and now that the
        grid has no toggle of its own, the page filter is the only way to slice
        it at all.

        Counted off the cell tooltips, which are what a reader actually reads.
        """
        with patch("src.config.settings.db_path", dashboard_db):
            everything = client.get("/visitors?view=timeline&range=all").text
            humans = client.get("/visitors?view=timeline&range=all&class=humans").text

        def total(html):
            return sum(int(n.replace(",", "")) for n in re.findall(r"— ([\d,]+) visits", html))

        assert total(everything) == 2
        assert total(humans) == 1
        assert total(humans) < total(everything)

    def test_overview_shows_attention_and_nav_badge(self, client, tmp_db):
        """A finding shows up in Needs attention and drives the nav badge."""
        now = datetime.now(timezone.utc)
        with get_conn(tmp_db) as conn:
            for i in range(3):
                insert_visit(
                    conn,
                    ip=f"203.0.113.7{i}",
                    timestamp=now.isoformat(),
                    path="/.env",
                    status=404,
                )
        resp = client.get("/")
        assert resp.status_code == 200
        assert "Needs attention" in resp.text
        assert "/.env" in resp.text
        assert 'class="nav-badge"' in resp.text

    def test_overview_without_findings_says_so(self, client, tmp_db):
        """An empty findings list renders the reassurance, not an empty block."""
        resp = client.get("/")
        assert resp.status_code == 200
        assert "Nothing needs attention right now." in resp.text
        assert 'class="nav-badge"' not in resp.text

    def test_distributions_are_css_bars_not_canvas(self, client, dashboard_db):
        """The release UI draws every distribution as CSS bars — no chart canvas
        and no Chart.js anywhere, so the pages carry no chart dependency."""
        with patch("src.config.settings.db_path", dashboard_db):
            for path in ("/", "/analysis", "/exposure", "/visitors?view=timeline"):
                text = client.get(path).text
                # The only canvas left is the theme-toggle icon in the sidebar.
                body = text.split('<main class="content">')[1]
                assert "<canvas" not in body, path
                assert "chart.umd" not in text, path
                assert "charts.js" not in text, path

    def test_activity_ships_its_rows_inline(self, client, dashboard_db):
        """The activity chart is drawn by timeline.js from data in the page.

        Inline rather than fetched, so the chart is there on first paint; only a
        zoom deep enough to want hourly buckets costs a request.
        """
        with patch("src.config.settings.db_path", dashboard_db):
            text = client.get("/visitors?view=timeline&range=all").text
        assert 'class="timeline"' in text
        # No series legend beside it: the page's group chips carry the same five
        # colours and also filter, so a legend under them was a key nobody could
        # act on. The series still travel in the payload — the chart needs them.
        assert 'class="series-legend"' not in text
        payload = json.loads(
            text.split('<script type="application/json">')[1].split("</script>")[0]
        )
        assert payload["rows"], "no activity rows embedded"
        assert {"day", "total", "humans", "bots", "threats"} <= set(payload["rows"][0])
        # Every series carries a token, because an SVG presentation attribute
        # cannot take a var() — timeline.js resolves it through cssVar().
        assert [s["token"] for s in payload["series"]] == [
            "grp-humans",
            "grp-bots",
            "grp-automated",
            "grp-threats",
            "grp-unknown",
        ]

    def test_map_view_has_selection_sidebar(self, client, dashboard_db):
        """The map view ships the viewport-driven selection panel, the country
        list, and the Cluster/Heat switch — map.js fills them from the markers."""
        with patch("src.config.settings.db_path", dashboard_db):
            text = client.get("/visitors?view=map").text
        assert 'class="map-layout"' in text
        assert 'id="sel-ips"' in text and 'id="sel-countries"' in text
        assert 'id="sel-threats"' in text and 'id="sel-mix"' in text
        assert 'id="sel-countries-list"' in text
        assert 'data-map-mode="cluster"' in text and 'data-map-mode="heat"' in text

    def test_analysis_cards_offer_a_table_view(self, client, dashboard_db):
        """Every distribution card can be read as plain numbers ("Table ⇄")."""
        with patch("src.config.settings.db_path", dashboard_db):
            text = client.get("/analysis").text
        assert text.count("data-viz-toggle") == 3
        assert text.count("data-viz-bars") == text.count("data-viz-table") == 3

    def test_path_rows_carry_a_status_mix(self, client, dashboard_db):
        """The Path grouping shows the status split as a mix bar, not badges."""
        with patch("src.config.settings.db_path", dashboard_db):
            text = client.get("/visitors?group=path").text
        assert 'data-col="status_mix"' in text
        assert "4xx client error" in text  # the mix bar names its segments

    def test_tab_strips_are_one_segmented_control(self, client, dashboard_db):
        """Tabs share one frame (.tab-group) instead of each drawing its own box.

        A tab must not carry a border of its own — that is also what clears the
        UA border on the <button> tabs (Top panel, Cluster/Heat).
        """
        css = dashboard_css()
        # Anchored at the line start: `.tab-group > :first-child > .tab {` ends
        # in the same three characters and would otherwise be read as this rule.
        tab_rule = re.search(r"^\.tab \{(.*?)\}", css, re.S | re.M).group(1)
        assert "border: 0;" in tab_rule
        assert "border-radius: 0;" in tab_rule
        with patch("src.config.settings.db_path", dashboard_db):
            assert 'class="tab-group"' in client.get("/").text
            assert 'class="tab-group"' in client.get("/visitors").text

    def test_header_links_are_not_body_links(self, client, dashboard_db):
        """A sortable column head must inherit the <th> color, never render as a
        default blue link."""
        css = dashboard_css()
        assert "th a { color: inherit;" in css
        with patch("src.config.settings.db_path", dashboard_db):
            assert "<th" in client.get("/visitors").text

    def test_map_block_has_no_header_only_overlays(self, client, dashboard_db):
        """The map is the block: its controls float on it, nothing sits above."""
        with patch("src.config.settings.db_path", dashboard_db):
            text = client.get("/visitors?view=map").text
        assert 'class="map-frame"' in text
        # Which corner an overlay sits in is a layout question, and one the
        # markup cannot answer: the mode switch used to cover Leaflet's zoom
        # buttons while this assertion was green. test_layout_browser.py
        # measures that they do not overlap.
        assert 'class="map-overlay' in text
        assert 'data-map-mode="heat"' in text
        assert 'class="map-overlay map-overlay--bl' in text
        assert "markers in the same group colors" not in text  # was mock placeholder

    def test_exposure_table_matches_the_spec_columns(self, client, dashboard_db):
        """IP · CC · Ports · Class mix · CVEs · Visits, ports/CVEs as mono text."""
        now = datetime.now(timezone.utc).isoformat()
        with get_conn(dashboard_db) as conn:
            upsert_ip_intel(
                conn, _intel("203.0.113.10", open_ports="22,443", vulns="CVE-2024-6387")
            )
            insert_visit(conn, ip="203.0.113.10", timestamp=now, path="/", status=200)
        with patch("src.config.settings.db_path", dashboard_db):
            text = client.get("/exposure").text
        assert ">Class mix</span>" in text and ">Visits</span>" in text
        assert 'class="cell-mono' in text  # ports/CVEs are text, not badge walls
        assert "CVE-2024-6387" in text

    def test_class_and_signal_are_bars_on_every_surface(self, client, dashboard_db):
        """Class mix and Signals render as the same mix bar everywhere — including
        the IP grouping, the slide-over, Exposure and the Overview's Top→IPs.

        A single visitor has one identity, so its bar is one full-width band; the
        exact class lives in the tooltip. No table falls back to a class badge.
        """
        # Exposure only lists IPs that carry Shodan data.
        with get_conn(dashboard_db) as conn:
            upsert_ip_intel(conn, _intel("203.0.113.10", open_ports="22,443"))
            set_visitor_class(conn, "203.0.113.10", "humans/browser-direct")
        surfaces = [
            "/visitors",  # group=ip
            "/visitors?group=asn",
            "/visitors/rows?asn=AS1",
            "/exposure",
            "/",
        ]
        with patch("src.config.settings.db_path", dashboard_db):
            for path in surfaces:
                text = client.get(path).text
                assert 'class="mix-bar"' in text, path
                assert "class_badge" not in text, path
        with patch("src.config.settings.db_path", dashboard_db):
            ip_table = client.get("/visitors").text
        # The IP row's own class bar carries the full class string as its tooltip.
        assert 'data-tip="humans/browser-direct"' in ip_table
        assert 'data-col="class_mix"' in ip_table and 'data-col="signal_mix"' in ip_table

    def test_matrix_headers_fit_their_columns(self, client, dashboard_db):
        """The signal columns are equal-width, so their headers use the short
        forms — the full labels collided with the neighbouring column."""
        with patch("src.config.settings.db_path", dashboard_db):
            text = client.get("/analysis").text
        assert ">Hosting</span>" in text and ">DNSBL</span>" in text
        assert "Hosting / Cloud" not in text.split("</table>")[0]
        assert 'class="c-group"' in text and 'class="c-total"' in text
        # A header must ellipsise inside its own column, never overrun it.
        css = dashboard_css()
        th_rule = css.split("\nth {", 1)[1].split("}", 1)[0]
        assert "overflow: hidden" in th_rule and "text-overflow: ellipsis" in th_rule

    def test_range_presets_keep_the_filter_state(self, client, dashboard_db):
        """Picking a range is not a request to drop the selection.

        All three tab strips (Group by, View, range) must carry the same state;
        the range presets used to link to a bare ?range= and reset everything.
        """
        with patch("src.config.settings.db_path", dashboard_db):
            text = client.get("/visitors?group=asn&class=bots&signal=is_hosting&asn=AS1").text
        presets = re.findall(r'href="(/visitors\?range=[^"]*)"', text)
        assert len(presets) == 5, presets  # all, 24h, 7d, 30d, 90d
        for href in presets:
            assert "group=asn" in href, href
            assert "class=bots" in href, href
            assert "signal=is_hosting" in href, href
            assert "asn=AS1" in href, href

    def test_status_filter_only_exists_where_it_applies(self, client, dashboard_db):
        """A pill must never claim a narrowing the query does not perform.

        Only the Path grouping filters by status band; carrying ?status= into
        another grouping used to render an "Active: Status 4xx" pill over an
        unchanged row set.
        """
        with patch("src.config.settings.db_path", dashboard_db):
            path_view = client.get("/visitors?group=path&status=4xx").text
            asn_view = client.get("/visitors?group=asn&status=4xx").text
            asn_plain = client.get("/visitors?group=asn").text
        assert "Status" in path_view and 'class="drill-pill"' in path_view
        assert 'class="drill-pill"' not in asn_view
        # ...and the grouping links must not carry it onwards either.
        assert "status=4xx" not in asn_view
        assert asn_view.count("<tr") == asn_plain.count("<tr")

    def test_overview_aggregates_are_cached(self, client, dashboard_db):
        """The expensive aggregates are computed once per TTL, not per request.

        Synchronous SQLite runs on the event loop, so a slow Overview stalls the
        log tailer and the enrichment worker with it.
        """
        import src.routes._cache as cache
        import src.routes.overview as overview

        with patch("src.config.settings.db_path", dashboard_db):
            client.get("/")  # fills the cache
            with patch.object(overview, "get_stats", side_effect=AssertionError) as spy:
                resp = client.get("/")  # must not touch the DB again
            assert resp.status_code == 200
            spy.assert_not_called()
        # Keyed by window now — every aggregate answers for a range, so a shared
        # key would serve one reader's window to the next for a whole TTL.
        assert any(k.startswith("stats:") for k in cache._agg_cache)
        assert "attention" in cache._agg_cache

    def test_nav_badge_shares_the_overview_cache(self, client, dashboard_db):
        """The badge sits on every page — it must reuse the findings, not redo them."""
        import src.routes._cache as cache

        with patch("src.config.settings.db_path", dashboard_db):
            client.get("/")
            with patch.object(cache, "get_attention_items", side_effect=AssertionError) as spy:
                assert client.get("/exposure").status_code == 200
            spy.assert_not_called()

    def test_findings_report_what_triggered_them(self, client, tmp_db):
        """A finding must not name a number that can be zero.

        The rate-limit finding fires on DELAYED *or* REJECTED events but used to
        print only the rejected count — "IP — 0 rejected in the last 6 h"
        whenever nginx had merely throttled.
        """
        from src.queries import get_attention_items

        now = datetime.now(timezone.utc).isoformat()
        with get_conn(tmp_db) as conn:
            for _ in range(3):
                insert_visit(
                    conn,
                    ip="203.0.113.80",
                    timestamp=now,
                    path="/",
                    status=200,
                    limit_req_status="DELAYED",  # throttled, never rejected
                )
        with get_conn(tmp_db) as conn:
            items = get_attention_items(conn)
        rate = next(i for i in items if i["tag"] == "Rate limit")
        assert "0 rejected" not in rate["text"]
        assert "3 rate-limited" in rate["text"]

    def test_empty_state_only_blames_a_filter_when_there_is_one(self, client, tmp_db):
        """With nothing filtered, nothing was excluded — say so plainly."""
        plain = client.get("/visitors?group=asn").text
        assert "No networks recorded yet." in plain
        assert "in the selected range" not in plain

        filtered = client.get("/visitors?group=asn&class=threats").text
        assert "No network matches" in filtered
        assert "in the selected range" in filtered

    @pytest.mark.parametrize("view", ["map", "timeline"])
    def test_only_the_table_view_has_a_grouping(self, client, dashboard_db, view):
        """The map plots individual IPs and the timeline aggregates by day —
        neither honours ?group=, so neither shows the strip nor carries the
        parameter onwards."""
        with patch("src.config.settings.db_path", dashboard_db):
            table = client.get("/visitors?group=path").text
            other = client.get(f"/visitors?group=path&view={view}").text
        assert "Group by" in table
        assert "Group by" not in other
        # Switching drops group=path. It does carry the window, like every other
        # link on the page.
        href = re.search(rf'href="(/visitors\?view={view}[^"]*)"', table).group(1)
        assert "group=" not in href, href

    def test_view_strip_comes_before_the_grouping(self, client, dashboard_db):
        """View decides whether a grouping applies at all, so it reads first."""
        with patch("src.config.settings.db_path", dashboard_db):
            text = client.get("/visitors?group=asn").text
        assert text.index(">View<") < text.index(">Group by<")

    def test_map_only_keeps_the_filters_it_honours(self, client, dashboard_db):
        """Same rule as ?status=: no pill for a filter the query never sees.

        get_geo_data narrows by class, signal, country, min_visits and the date
        window — a network or path drill-down reaches nothing on the map.
        """
        with patch("src.config.settings.db_path", dashboard_db):
            ignored = client.get("/visitors?view=map&asn=AS1&path=/x&browser=Chrome").text
            honoured = client.get("/visitors?view=map&country=DE").text
        # The marker payload legitimately contains ASNs, so assert on the rail.
        assert 'class="drill-pills"' not in ignored
        assert 'class="drill-pills"' in honoured
        assert "<strong>Country</strong>" in honoured

    def test_no_route_queries_on_the_event_loop(self):
        """SQLite here is synchronous: a query on the loop stalls the log tailer
        and the enrichment worker for its whole duration, not just the response.

        Every async handler that touches the database must go through fetch().
        The export is the one exception — it hands a *sync* generator to
        StreamingResponse, which Starlette iterates in a threadpool.
        """
        import re
        from pathlib import Path

        routes = Path(__file__).resolve().parent.parent / "src" / "routes"
        offenders = []
        for mod in ("dashboard.py", "api.py"):
            src = (routes / mod).read_text()
            for m in re.finditer(r'@router\.get\("([^"]+)"\)\s*\nasync def \w+\(', src):
                body = src[m.end() :]
                nxt = body.find("@router.get(")
                body = body[: nxt if nxt > 0 else len(body)]
                if (
                    "get_conn()" in body
                    and "fetch(" not in body
                    and "StreamingResponse" not in body
                ):
                    offenders.append(f"{mod}:{m.group(1)}")
        assert not offenders, f"routes querying on the event loop: {offenders}"

    def test_optional_cells_carry_their_column_key(self, client, dashboard_db):
        """Hiding a column must take the body cells with it.

        The <col> and <th> alone would collapse the width while the <td> stayed,
        skewing every row against its header.
        """
        with patch("src.config.settings.db_path", dashboard_db):
            text = client.get("/visitors").text
        body = text.split("<tbody>")[1]
        for key in ("city", "isp", "pages", "port", "browser", "os"):
            assert f'data-col="{key}"' in body, key

    def test_detail_columns_start_hidden(self, client, dashboard_db):
        """Twelve columns left every flexible one at ~4 rem. The detail a reader
        rarely needs waits behind Columns ▾ instead of crowding what they do."""
        with patch("src.config.settings.db_path", dashboard_db):
            text = client.get("/visitors").text
        picker = text.split('data-col-picker="visitors-ip"')[1].split("</details>")[0]
        for key in ("city", "pages", "port", "browser", "os"):
            assert f'data-col-toggle="{key}" data-col-default-off' in picker, key
        assert 'data-col-toggle="isp" checked' in picker  # ISP stays on

    def test_views_render_on_empty_db(self, client, tmp_db):
        """All list views survive an empty database."""
        for path in (
            "/",
            "/visitors",
            "/visitors?group=asn",
            "/visitors?group=country",
            "/visitors?group=client",
            "/visitors?group=path",
            "/visitors?view=map",
            "/analysis",
            "/exposure",
        ):
            response = client.get(path)
            assert response.status_code == 200, path

    def test_visitor_detail_renders(self, client, dashboard_db):
        with patch("src.config.settings.db_path", dashboard_db):
            response = client.get("/visitors/203.0.113.10")
        assert response.status_code == 200
        assert "203.0.113.10" in response.text

    def test_visitor_detail_unknown_ip_404(self, client, dashboard_db):
        with patch("src.config.settings.db_path", dashboard_db):
            response = client.get("/visitors/198.51.100.99")
        assert response.status_code == 404

    def test_visitor_detail_invalid_ip_400(self, client, dashboard_db):
        with patch("src.config.settings.db_path", dashboard_db):
            response = client.get("/visitors/not-an-ip")
        assert response.status_code == 400


class TestFilterParams:
    """?class=, ?signal=, and ?country= filters narrow the /visitors table.

    The Humans / Not-Humans pages were removed; the unified class/signal legend on
    /visitors now filters the same data inline.
    """

    def test_class_humans_lists_only_humans(self, client, dashboard_db):
        with patch("src.config.settings.db_path", dashboard_db):
            response = client.get("/visitors?class=humans")
        assert response.status_code == 200
        assert "203.0.113.10" in response.text
        assert "203.0.113.20" not in response.text

    def test_class_bots_lists_only_bots(self, client, dashboard_db):
        with patch("src.config.settings.db_path", dashboard_db):
            response = client.get("/visitors?class=bots")
        assert response.status_code == 200
        assert "203.0.113.20" in response.text
        assert "203.0.113.10" not in response.text

    def test_group_prefix_class_filter(self, dashboard_db):
        """class=<group> matches every class in that group (Ticket 0)."""
        with get_conn(dashboard_db) as conn:
            bots = {r["ip"] for r in get_visitors_grouped(conn, class_filter=["bots"])}
            humans = {r["ip"] for r in get_visitors_grouped(conn, class_filter=["humans"])}
        assert bots == {"203.0.113.20"}  # bots/generic-bots matched by prefix
        assert humans == {"203.0.113.10"}  # humans/browser-direct matched by prefix

    def test_full_class_and_group_filter_coexist(self, dashboard_db):
        """A full class string and a group prefix can be combined (OR)."""
        with get_conn(dashboard_db) as conn:
            ips = {
                r["ip"]
                for r in get_visitors_grouped(conn, class_filter=["humans/browser-direct", "bots"])
            }
        assert ips == {"203.0.113.10", "203.0.113.20"}

    def test_class_filter_narrows(self, client, dashboard_db):
        with patch("src.config.settings.db_path", dashboard_db):
            matching = client.get("/visitors?class=bots/generic-bots")
            non_matching = client.get("/visitors?class=threats/exploit-probers")
        assert "203.0.113.20" in matching.text
        assert "203.0.113.20" not in non_matching.text

    def test_unknown_class_value_is_dropped(self, client, dashboard_db):
        """Invalid taxonomy values are silently ignored, not errors."""
        with patch("src.config.settings.db_path", dashboard_db):
            response = client.get("/visitors?class=no-such-class")
        assert response.status_code == 200
        assert "203.0.113.10" in response.text

    def test_signal_filter_applies(self, client, dashboard_db):
        with patch("src.config.settings.db_path", dashboard_db):
            response = client.get("/visitors?class=bots&signal=is_tor")
        assert response.status_code == 200
        assert "203.0.113.20" not in response.text

    def test_country_filter_applies(self, client, dashboard_db):
        with patch("src.config.settings.db_path", dashboard_db):
            matching = client.get("/visitors?class=humans&country=DE")
            non_matching = client.get("/visitors?class=humans&country=US")
        assert "203.0.113.10" in matching.text
        assert "203.0.113.10" not in non_matching.text


class TestLegacyRedirects:
    """Old paths 301-redirect to their successor — always in one hop.

    The four aggregation tables became ?group=, the map became ?view=map, and
    Analysis/Exposure became top-level routes.
    """

    @pytest.mark.parametrize(
        "old,new",
        [
            # The six routes that turned into parameters.
            ("/visitors/networks", "/visitors?group=asn"),
            ("/visitors/countries", "/visitors?group=country"),
            ("/visitors/clients", "/visitors?group=client"),
            ("/visitors/paths", "/visitors?group=path"),
            ("/visitors/geo", "/visitors?view=map"),
            ("/visitors/analysis", "/analysis"),
            ("/tools/shodan", "/exposure"),
            # Older redirects, re-pointed at the new targets (no 301 chains).
            ("/humans", "/visitors?class=humans"),
            ("/not-humans", "/visitors"),
            ("/visitors/humans", "/visitors?class=humans"),
            ("/visitors/not-humans", "/visitors"),
            ("/geo", "/visitors?view=map"),
            ("/analyse", "/analysis"),
            ("/threats", "/analysis"),
            ("/visitors/analyse", "/analysis"),
            ("/timeline", "/"),
            ("/visitors/timeline", "/"),
        ],
    )
    def test_redirect(self, client, tmp_db, old, new):
        response = client.get(old, follow_redirects=False)
        assert response.status_code == 301
        assert response.headers["location"] == new

    @pytest.mark.parametrize(
        "old,expected",
        [
            ("/visitors/networks?class=threats", ["group=asn", "class=threats"]),
            (
                "/visitors/countries?date_from=2026-07-01",
                ["group=country", "date_from=2026-07-01"],
            ),
            ("/visitors/clients?q=chrome", ["group=client", "q=chrome"]),
            ("/visitors/paths?status=4xx&q=env", ["group=path", "status=4xx", "q=env"]),
            (
                "/visitors/geo?class=humans&min_visits=5",
                ["view=map", "class=humans", "min_visits=5"],
            ),
            ("/visitors/analysis?date_from=2026-07-01", ["date_from=2026-07-01"]),
            ("/tools/shodan?port=22&tag=scanner", ["port=22", "tag=scanner"]),
        ],
    )
    def test_redirects_carry_their_parameters(self, client, tmp_db, old, expected):
        """A legacy bookmark must not silently widen what it shows.

        Dropping the filter on redirect lands the visitor on unfiltered data
        while they believe they are looking at the narrowed view.
        """
        resp = client.get(old, follow_redirects=False)
        assert resp.status_code == 301
        for part in expected:
            assert part in resp.headers["location"], (old, resp.headers["location"])

    def test_no_redirect_chains(self, client, tmp_db):
        """Every legacy path reaches its target in exactly one hop."""
        for old in ("/geo", "/analyse", "/visitors/networks", "/tools/shodan"):
            resp = client.get(old, follow_redirects=False)
            target = resp.headers["location"]
            assert client.get(target, follow_redirects=False).status_code == 200, old


class TestSettings:
    """Settings is three pages behind the gear: status, storage and the JSON API.

    Storage and API were sidebar-footer links before — the export pulled the whole
    database from a page header that showed a filtered view, and `API` named one of
    four endpoints. Status came later, for the things that otherwise needed
    `docker logs`.
    """

    def test_settings_lands_on_status_in_one_hop(self, client, tmp_db):
        """The section has no landing page; the first sub-nav entry is it."""
        resp = client.get("/settings", follow_redirects=False)
        assert resp.status_code == 301
        assert resp.headers["location"] == "/settings/status"
        assert client.get("/settings/status", follow_redirects=False).status_code == 200

    def test_exports_still_lands_on_storage(self, client, tmp_db):
        """Exports folded into Storage, and that redirect did not move."""
        resp = client.get("/settings/exports", follow_redirects=False)
        assert resp.status_code == 301
        assert resp.headers["location"] == "/settings/storage"
        assert client.get("/settings/storage", follow_redirects=False).status_code == 200

    @pytest.mark.parametrize(
        "path,active_label",
        [
            ("/settings/status", "Status"),
            ("/settings/storage", "Storage &amp; Retention"),
            ("/settings/api", "API"),
        ],
    )
    def test_sub_nav_marks_the_page_it_is_on(self, client, tmp_db, path, active_label):
        """Every entry is always listed; exactly the current one is active."""
        text = client.get(path).text
        for label in (">Status<", ">Storage &amp; Retention<", ">API<"):
            assert label in text, label
        assert f'class="active">{active_label}<' in text

    def test_api_page_lists_every_endpoint(self, client, tmp_db):
        """All four, not just the one the old footer link pointed at.

        This is also where whole-database CSV/JSON lives now that the Exports
        page is gone — the archives hand out zips, not CSV.
        """
        text = client.get("/settings/api").text
        for endpoint in ("/api/stats", "/api/activity", "/api/visits", "/api/export"):
            assert endpoint in text, endpoint

    def test_gear_reaches_settings_from_a_dashboard_page(self, client, tmp_db):
        assert 'href="/settings/storage"' in client.get("/").text


class TestStorageSettings:
    """Retention mode and the archive actions.

    Every action is a POST that answers 303, so a reload of the settings page
    re-runs nothing — a refresh must not restore a month a second time.
    """

    def test_page_shows_the_mode_and_the_active_window(self, client, tmp_db):
        text = client.get("/settings/storage").text
        assert 'value="rolling"' in text and 'value="lifetime"' in text
        # Rolling is the default, so the window and its size are both on the
        # page from the start.
        assert "Window:" in text
        assert 'name="months"' in text and 'value="2"' in text

    def test_window_size_is_settable_and_moves_the_boundary(self, client, tmp_db):
        with get_conn(tmp_db) as conn:
            assert archive.get_rolling_months(conn) == 2

        assert client.post("/settings/storage/window", data={"months": "5"}).status_code == 200
        with get_conn(tmp_db) as conn:
            assert archive.get_rolling_months(conn) == 5
            now = datetime(2026, 8, 7, tzinfo=timezone.utc)
            assert archive.window_start_month(now, 5) == "2026-03"

    @pytest.mark.parametrize("sent,stored", [("-3", 0), ("999", 24), ("0", 0)])
    def test_window_size_is_clamped(self, client, tmp_db, sent, stored):
        """A typo must not quietly turn rolling into lifetime."""
        client.post("/settings/storage/window", data={"months": sent})
        with get_conn(tmp_db) as conn:
            assert archive.get_rolling_months(conn) == stored

    def test_switching_mode_persists_and_redirects(self, client, tmp_db):
        resp = client.post(
            "/settings/storage/mode", data={"mode": "lifetime"}, follow_redirects=False
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/settings/storage"

        with get_conn(tmp_db) as conn:
            assert archive.get_mode(conn) == "lifetime"
        assert "settings-warning" in client.get("/settings/storage").text

    def test_archived_month_is_listed_with_its_actions(self, client, tmp_db):
        with get_conn(tmp_db) as conn:
            insert_visit(conn, ip="1.1.1.1", timestamp="2026-04-05T10:00:00+00:00")
            upsert_ip_intel(conn, {"ip": "1.1.1.1"})
            archive.archive_month(conn, "2026-04")

        text = client.get("/settings/storage").text
        assert "2026-04" in text
        assert "/settings/storage/download/2026-04" in text
        assert "/settings/storage/restore/2026-04" in text

    def test_restore_then_release_round_trip(self, client, tmp_db):
        with get_conn(tmp_db) as conn:
            insert_visit(conn, ip="1.1.1.1", timestamp="2026-04-05T10:00:00+00:00")
            upsert_ip_intel(conn, {"ip": "1.1.1.1"})
            archive.archive_month(conn, "2026-04")

        assert client.post("/settings/storage/restore/2026-04").status_code == 200
        with get_conn(tmp_db) as conn:
            assert count_visits(conn) == 1

        assert client.post("/settings/storage/release/2026-04").status_code == 200
        with get_conn(tmp_db) as conn:
            assert count_visits(conn) == 0

    def test_download_serves_the_zip(self, client, tmp_db):
        with get_conn(tmp_db) as conn:
            insert_visit(conn, ip="1.1.1.1", timestamp="2026-04-05T10:00:00+00:00")
            upsert_ip_intel(conn, {"ip": "1.1.1.1"})
            archive.archive_month(conn, "2026-04")

        resp = client.get("/settings/storage/download/2026-04")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/zip"
        assert resp.content[:2] == b"PK"

    @pytest.mark.parametrize("month", ["2026-13", "2026-6", "2026", "2019-01"])
    def test_download_answers_404_for_anything_it_will_not_serve(self, client, tmp_db, month):
        """The month segment becomes a filename — it never reaches open() unchecked.

        Malformed and simply-absent look identical from outside on purpose: the
        response should not tell a prober which shapes the validator likes.
        """
        assert client.get(f"/settings/storage/download/{month}").status_code == 404

    def test_a_live_month_downloads_as_a_zip_without_leaving_the_db(self, client, tmp_db):
        """Nothing leaves this service uncompressed, archived or not."""
        with get_conn(tmp_db) as conn:
            insert_visit(conn, ip="1.1.1.1", timestamp="2026-08-05T10:00:00+00:00")
            upsert_ip_intel(conn, {"ip": "1.1.1.1"})

        resp = client.get("/settings/storage/download/2026-08")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/zip"
        assert resp.content[:2] == b"PK"
        with get_conn(tmp_db) as conn:
            assert count_visits(conn) == 1, "download must not remove anything"

    def test_deleting_a_month_removes_it_without_an_archive(self, client, tmp_db):
        with get_conn(tmp_db) as conn:
            insert_visit(conn, ip="1.1.1.1", timestamp="2026-08-05T10:00:00+00:00")
            upsert_ip_intel(conn, {"ip": "1.1.1.1"})

        assert client.post("/settings/storage/delete-month/2026-08").status_code == 200
        with get_conn(tmp_db) as conn:
            assert count_visits(conn) == 0

    def test_deleting_an_archive_removes_the_file_only(self, client, tmp_db, tmp_archive_dir):
        with get_conn(tmp_db) as conn:
            insert_visit(conn, ip="1.1.1.1", timestamp="2026-04-05T10:00:00+00:00")
            upsert_ip_intel(conn, {"ip": "1.1.1.1"})
            archive.archive_month(conn, "2026-04")
        client.post("/settings/storage/restore/2026-04")

        assert client.post("/settings/storage/delete-archive/2026-04").status_code == 200
        assert not (tmp_archive_dir / "2026-04.zip").exists()
        with get_conn(tmp_db) as conn:
            assert count_visits(conn) == 1, "restored rows stay; only the file went"

    def test_download_cannot_escape_the_archive_directory(self, client, tmp_db, tmp_path):
        secret = tmp_path / "secret.zip"
        secret.write_bytes(b"PK-not-yours")
        for attempt in ("../secret", "..%2Fsecret", "....//secret"):
            resp = client.get(f"/settings/storage/download/{attempt}")
            assert resp.status_code in (400, 404), attempt
            assert b"not-yours" not in resp.content


def test_visitors_port_filter(client, tmp_db):
    """?port= narrows the visitor list to IPs that connected on that server port."""
    now = datetime.now(timezone.utc).isoformat()
    with get_conn(tmp_db) as conn:
        insert_visit(
            conn,
            ip="203.0.113.81",
            timestamp=now,
            method="GET",
            path="/",
            status=200,
            server_port=443,
        )
        insert_visit(
            conn,
            ip="203.0.113.82",
            timestamp=now,
            method="GET",
            path="/",
            status=200,
            server_port=80,
        )
    resp = client.get("/visitors", params={"port": 443})
    assert resp.status_code == 200
    assert "203.0.113.81" in resp.text
    assert "203.0.113.82" not in resp.text

    # An out-of-range port is ignored (no filter), so both IPs show.
    resp_all = client.get("/visitors", params={"port": 99999})
    assert "203.0.113.81" in resp_all.text
    assert "203.0.113.82" in resp_all.text


def test_identity_signal_matrix_counts(tmp_db):
    """A human carrying a proxy signal lands in the humans row, proxy column."""
    with get_conn(tmp_db) as conn:
        insert_visit(conn, ip="1.1.1.1", timestamp="2026-06-10T10:00:00", path="/")
        upsert_ip_intel(conn, _intel("1.1.1.1", is_proxy=True))
        set_visitor_class(conn, "1.1.1.1", "humans/browser-direct")
    with get_conn(tmp_db) as conn:
        matrix = {r["grp"]: r for r in get_identity_signal_matrix(conn)}
    assert matrix["humans"]["proxy"] == 1
    assert matrix["humans"]["total"] == 1
    assert matrix["humans"]["tor"] == 0
    assert matrix["humans"]["mobile"] == 0
    assert matrix["humans"]["clean"] == 0  # carries a proxy signal, so not clean


class TestActiveFilterPills:
    """Every active filter is visible and removable on its own.

    A class was only ever shown as a highlighted chip, and a signal not even
    that — its chips live inside a closed menu. A filtered page was then hard to
    tell from an empty one, and there was no way to drop one filter without
    editing the URL.
    """

    URL = (
        "/visitors?class=humans&class=bots%2Fai-crawlers"
        "&signal=is_hosting&signal=clean&q=telekom&asn=AS3320"
    )

    def _pills(self, client, db, url=None):
        with patch("src.config.settings.db_path", db):
            text = client.get(url or self.URL).text
        row = text.split('<div class="drill-pills">')[1].split("</div>")[0]
        return [
            {"kind": m.group(1), "value": m.group(2), "href": unescape(m.group(3))}
            for m in re.finditer(
                r"<strong>(.*?)</strong><code>(.*?)</code><a href=\"([^\"]+)\"", row
            )
        ]

    def test_classes_signals_and_search_all_get_a_pill(self, client, dashboard_db):
        pills = self._pills(client, dashboard_db)
        assert [p["kind"] for p in pills] == [
            "Network",
            "Class",
            "Class",
            "Signal",
            "Signal",
            "Search",
        ]
        assert [p["value"] for p in pills[1:]] == [
            "Humans",
            "Ai Crawlers",
            "Hosting / Cloud",
            "Clean",
            "telekom",
        ]

    def test_a_pill_removes_only_its_own_value(self, client, dashboard_db):
        """?class= and ?signal= carry several values; removing one must not take
        its neighbours with it."""
        pills = self._pills(client, dashboard_db)
        humans = next(p for p in pills if p["value"] == "Humans")
        assert "class=bots/ai-crawlers" in humans["href"]
        assert "class=humans" not in humans["href"]
        assert "signal=is_hosting" in humans["href"] and "signal=clean" in humans["href"]
        assert "asn=AS3320" in humans["href"] and "q=telekom" in humans["href"]

    def test_signal_pill_keeps_the_classes(self, client, dashboard_db):
        pills = self._pills(client, dashboard_db)
        clean = next(p for p in pills if p["value"] == "Clean")
        assert "signal=clean" not in clean["href"]
        assert "signal=is_hosting" in clean["href"]
        assert clean["href"].count("class=") == 2

    def test_pills_carry_their_taxonomy_colour(self, client, dashboard_db):
        with patch("src.config.settings.db_path", dashboard_db):
            text = client.get(self.URL).text
        row = text.split('<div class="drill-pills">')[1].split("</div>")[0]
        assert "--grp-humans" in row and "--sig-clean" in row

    def test_clear_all_keeps_grouping_view_and_range(self, client, dashboard_db):
        """The range tabs are their own control — clearing filters is not a
        request to look at a different time window."""
        with patch("src.config.settings.db_path", dashboard_db):
            text = client.get(self.URL + "&range=30d&group=asn").text
        row = text.split('<div class="drill-pills">')[1].split("</div>")[0]
        href = unescape(re.search(r'drill-pills-clear" href="([^"]+)"', row).group(1))
        assert "range=30d" in href and "group=asn" in href
        assert "class=" not in href and "signal=" not in href and "q=" not in href

    def test_no_pill_row_without_filters(self, client, dashboard_db):
        with patch("src.config.settings.db_path", dashboard_db):
            assert '<div class="drill-pills">' not in client.get("/visitors").text


class TestCleanSignal:
    """ "Clean" — an IP with none of the tracked signals — is one definition.

    It used to be three that disagreed: the matrix column also demanded
    is_mobile = 0, the map's selection counts ignored Shodan tags, and the
    tooltip on both promised "no Tor, Proxy/VPN, Hosting, DNSBL, or Shodan tags"
    which neither checked. Now it is a filter chip, so the number behind the
    chip, the number in the matrix and the number on the map have to agree.
    """

    @pytest.fixture
    def signals_db(self, tmp_db):
        """Five IPs: one per signal, one clean, one mobile-but-clean, one raw."""
        with get_conn(tmp_db) as conn:
            for ip in (
                "10.0.0.1",  # clean
                "10.0.0.2",  # tor
                "10.0.0.3",  # shodan tag only
                "10.0.0.4",  # mobile, no signals
                "10.0.0.5",  # never enriched
            ):
                insert_visit(conn, ip=ip, timestamp="2026-06-10T10:00:00", path="/")
            upsert_ip_intel(conn, _intel("10.0.0.1"))
            upsert_ip_intel(conn, _intel("10.0.0.2", is_tor=True))
            upsert_ip_intel(conn, _intel("10.0.0.3", tags="scanner"))
            upsert_ip_intel(conn, _intel("10.0.0.4", is_mobile=True))
            for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"):
                set_visitor_class(conn, ip, "humans/browser-direct")
        return tmp_db

    def _clean_ips(self, db):
        with get_conn(db) as conn:
            return {
                r["ip"] for r in get_visitors_grouped(conn, signal_filter=["clean"], limit=100)
            }

    def test_filter_returns_exactly_the_unmarked_ips(self, signals_db):
        assert self._clean_ips(signals_db) == {"10.0.0.1", "10.0.0.4"}

    def test_a_shodan_tag_is_enough_to_be_unclean(self, signals_db):
        """The tooltip always claimed this; the SQL behind it did not."""
        assert "10.0.0.3" not in self._clean_ips(signals_db)

    def test_mobile_does_not_make_an_ip_unclean(self, signals_db):
        """Mobile says which network an IP sits on, not what is known against
        it — and it is not offered as a signal."""
        assert "10.0.0.4" in self._clean_ips(signals_db)

    def test_an_unenriched_ip_is_unknown_not_clean(self, signals_db):
        assert "10.0.0.5" not in self._clean_ips(signals_db)

    def test_matrix_column_and_filter_agree(self, signals_db):
        with get_conn(signals_db) as conn:
            matrix = {r["grp"]: r for r in get_identity_signal_matrix(conn)}
        assert matrix["humans"]["clean"] == len(self._clean_ips(signals_db))

    def test_map_count_and_filter_agree(self, signals_db):
        with get_conn(signals_db) as conn:
            _markers, stats = get_geo_data(conn)
        assert stats["clean_count"] == len(self._clean_ips(signals_db))

    def test_aggregate_bars_carry_the_clean_share(self, signals_db):
        """Without it a row with one Tor IP among 500 draws a fully purple bar."""
        with get_conn(signals_db) as conn:
            rows = get_countries(conn, limit=10)
        assert sum(r["clean_ips"] for r in rows) == len(self._clean_ips(signals_db))

    def test_chip_offers_clean(self, client, signals_db):
        with patch("src.config.settings.db_path", signals_db):
            text = client.get("/visitors").text
        assert 'data-signal-value="clean"' in text

    def test_matrix_links_its_clean_column(self, client, signals_db):
        with patch("src.config.settings.db_path", signals_db):
            text = client.get("/analysis").text
        assert "signal=clean" in text


def test_analysis_shows_identity_signal_matrix(client, dashboard_db):
    """Analysis renders the Identity x Signals matrix with the seeded groups."""
    with patch("src.config.settings.db_path", dashboard_db):
        resp = client.get("/analysis")
    assert resp.status_code == 200
    assert "Identity" in resp.text and "Signals" in resp.text
    assert "Humans" in resp.text and "Bots" in resp.text


def test_analysis_date_range_scopes_visit_widgets(client, tmp_db):
    """date_from/date_to narrow the visit-based Analysis widgets (status dist,
    unusual methods); without params everything is included."""
    with get_conn(tmp_db) as conn:
        insert_visit(
            conn,
            ip="203.0.113.30",
            timestamp="2026-05-01T10:00:00",
            path="/",
            status=404,
            method="TRACE",
        )
        insert_visit(
            conn,
            ip="203.0.113.31",
            timestamp="2026-06-15T10:00:00",
            path="/",
            status=200,
            method="PUT",
        )

    def band(text, code):
        # The status card lists only the bands that actually occurred.
        return f'<span class="facet-label">{code}</span>' in text

    resp = client.get("/analysis", params={"date_from": "2026-06-01", "date_to": "2026-06-30"})
    assert resp.status_code == 200
    assert "PUT" in resp.text
    assert "TRACE" not in resp.text  # May visit is outside the range
    assert band(resp.text, "2xx")
    assert not band(resp.text, "4xx")  # the 404 is outside the range

    # ?range=all, not a bare URL: the window above is now remembered in a cookie,
    # so "no parameters" means "whatever was last chosen". Asking for everything
    # is a choice like any other and has to be said out loud.
    resp_all = client.get("/analysis", params={"range": "all"})
    assert "TRACE" in resp_all.text
    assert band(resp_all.text, "4xx")


def test_analysis_range_preset(client, tmp_db):
    """?range=7d resolves to a date window and marks the preset active."""
    resp = client.get("/analysis", params={"range": "7d"})
    assert resp.status_code == 200
    assert 'class="tab active"' in resp.text


def _default_range_label() -> str:
    """The label the default preset renders with, read from the presets.

    The tests below care that the *default* tab is the active one, not what it
    is called this month — it has been "Default" and is now "90 days". Looking
    it up keeps a rename from reading as a behaviour failure.
    """
    from src.routes._range import _RANGE_PRESETS, DEFAULT_RANGE

    return next(label for key, _, label in _RANGE_PRESETS if key == DEFAULT_RANGE)


def _active_range_tab(text: str) -> str:
    """The label of the highlighted tab in the range strip.

    Scoped to .range-tabs on purpose: Visitors carries two more tab strips (View,
    Group by) that use the same active class, and a bare search would pick up
    whichever came first.
    """
    strip = text.split('<div class="range-tabs">')[1].split("</div>")[0]
    match = re.search(r'class="tab active"[^>]*>\s*([^<]+?)\s*<', strip)
    return match.group(1) if match else ""


class TestRangeMemory:
    """The chosen window follows the reader from page to page."""

    def test_the_window_survives_a_page_change(self, client, tmp_db):
        assert _active_range_tab(client.get("/", params={"range": "7d"}).text) == "7 days"
        # No parameters at all — the sidebar links are bare, and this is the
        # whole point of the feature.
        assert _active_range_tab(client.get("/visitors").text) == "7 days"
        assert _active_range_tab(client.get("/analysis").text) == "7 days"
        assert _active_range_tab(client.get("/exposure").text) == "7 days"

    def test_a_custom_window_travels_too(self, client, tmp_db):
        client.get("/", params={"date_from": "2026-01-01", "date_to": "2026-01-31"})
        text = client.get("/analysis").text
        assert _active_range_tab(text) == "Custom"
        assert 'value="2026-01-01"' in text and 'value="2026-01-31"' in text

    def test_all_clears_the_memory_for_every_page(self, client, tmp_db):
        client.get("/", params={"range": "24h"})
        assert _active_range_tab(client.get("/analysis", params={"range": "all"}).text) == "All"
        assert _active_range_tab(client.get("/visitors").text) == "All"

    def test_the_url_still_wins_over_what_was_remembered(self, client, tmp_db):
        client.get("/", params={"range": "30d"})
        assert _active_range_tab(client.get("/visitors?range=7d").text) == "7 days"

    def test_the_memory_ends_with_the_browser_session(self, client, tmp_db):
        """No Max-Age and no Expires: closing the browser is the reset."""
        header = client.get("/", params={"range": "7d"}).headers["set-cookie"]
        assert "vidar_range=7d" in header
        assert "max-age" not in header.lower() and "expires" not in header.lower()

    @pytest.mark.parametrize(
        "forged", ["1y", "custom:not-a-date:2026-01-31", "custom::", "../../etc", ""]
    )
    def test_a_forged_cookie_is_dropped_not_repaired(self, client, tmp_db, forged):
        """The cookie reaches SQL as a date filter, so it passes the same gates
        the query string does. Anything else falls back to the default window,
        never to a half-parsed one."""
        client.cookies.set("vidar_range", forged)
        assert _active_range_tab(client.get("/analysis").text) == _default_range_label()

    def test_an_untouched_dashboard_opens_on_the_default_window(self, client, tmp_db):
        """No cookie, no parameters: 90 days, and the tab says so.

        There is no unfiltered-by-accident state any more — every number on the
        page answers for whatever this resolves to, so it has to be visible.
        """
        text = client.get("/").text
        assert _active_range_tab(text) == _default_range_label()
        assert "90" in _default_range_label(), "the default tab must name its span"


def test_exposure_page_renders(client, tmp_db):
    """Exposure lists the IPs carrying Shodan data, with the three facets."""
    now = datetime.now(timezone.utc).isoformat()
    with get_conn(tmp_db) as conn:
        insert_visit(conn, ip="203.0.113.50", timestamp=now, method="GET", path="/", status=200)
        upsert_ip_intel(
            conn,
            _intel("203.0.113.50", tags="scanner", vulns="CVE-2021-1234", open_ports="80,443"),
        )
    resp = client.get("/exposure")
    assert resp.status_code == 200
    assert "Shodan" in resp.text
    assert "203.0.113.50" in resp.text
    # The three facets over the same host set
    assert "Open ports" in resp.text
    assert "CVEs" in resp.text
    assert "Tags" in resp.text


def test_exposure_port_filter(client, tmp_db):
    """?port= narrows the host list to IPs exposing that port."""
    now = datetime.now(timezone.utc).isoformat()
    with get_conn(tmp_db) as conn:
        insert_visit(conn, ip="203.0.113.50", timestamp=now, path="/", status=200)
        insert_visit(conn, ip="203.0.113.51", timestamp=now, path="/", status=200)
        upsert_ip_intel(conn, _intel("203.0.113.50", open_ports="22,80"))
        upsert_ip_intel(conn, _intel("203.0.113.51", open_ports="443"))

    resp = client.get("/exposure", params={"port": 22})
    assert resp.status_code == 200
    assert "203.0.113.50" in resp.text
    assert "203.0.113.51" not in resp.text
    assert 'class="drill-pill"' in resp.text  # clearable filter pill


def test_exposure_facets_share_the_table_filter(client, tmp_db):
    """Facets describe the filtered host set, not the whole database.

    Host A exposes 22+80, host B exposes 443. Filtering by port 22 must drop 443
    from the ports facet — otherwise a facet count contradicts the table below it.
    """
    now = datetime.now(timezone.utc).isoformat()
    with get_conn(tmp_db) as conn:
        insert_visit(conn, ip="203.0.113.60", timestamp=now, path="/", status=200)
        insert_visit(conn, ip="203.0.113.61", timestamp=now, path="/", status=200)
        upsert_ip_intel(conn, _intel("203.0.113.60", open_ports="22,80", tags="scanner"))
        upsert_ip_intel(conn, _intel("203.0.113.61", open_ports="443", tags="cloud"))

    with get_conn(tmp_db) as conn:
        unfiltered = {r["value"] for r in get_top_ports(conn)}
        filtered = {r["value"] for r in get_top_ports(conn, port=22)}
        tags_filtered = {r["value"] for r in get_top_tags(conn, port=22)}
    assert unfiltered == {22, 80, 443}
    assert filtered == {22, 80}  # only the ports of hosts that also expose 22
    assert tags_filtered == {"scanner"}  # cloud belongs to the excluded host


def test_agg_tables_search_filters(client, tmp_db):
    """?q= narrows Networks (org/ISP/ASN), Countries (name/code), and Clients
    (browser/OS/device) via the shared _agg_q_filter."""
    now = datetime.now(timezone.utc).isoformat()
    with get_conn(tmp_db) as conn:
        insert_visit(
            conn, ip="203.0.113.90", timestamp=now, path="/", status=200, browser="Firefox"
        )
        insert_visit(
            conn, ip="203.0.113.91", timestamp=now, path="/", status=200, browser="Safari"
        )
        upsert_ip_intel(
            conn,
            _intel(
                "203.0.113.90",
                asn="AS100",
                org="Hetzner Online",
                isp="Hetzner",
                country="France",
                country_code="FR",
            ),
        )
        upsert_ip_intel(
            conn,
            _intel(
                "203.0.113.91",
                asn="AS200",
                org="Google LLC",
                isp="Google",
                country="Japan",
                country_code="JP",
            ),
        )

    resp = client.get("/visitors", params={"group": "asn", "q": "hetzner"})
    assert resp.status_code == 200
    assert "AS100" in resp.text
    assert "AS200" not in resp.text

    resp = client.get("/visitors", params={"group": "country", "q": "fran"})
    assert resp.status_code == 200
    assert "France" in resp.text
    assert "Japan" not in resp.text

    resp = client.get("/visitors", params={"group": "client", "q": "firefox"})
    assert resp.status_code == 200
    assert "Firefox" in resp.text
    assert "Safari" not in resp.text


def test_agg_tables_render_search_form(client, tmp_db):
    """Every grouping renders the one filter rail: search + range."""
    for group in ("asn", "country", "client", "path"):
        resp = client.get(f"/visitors?group={group}")
        assert resp.status_code == 200, group
        assert 'name="q"' in resp.text, group
        assert 'name="date_from"' in resp.text, group


def test_status_filter_is_a_removable_pill(client, tmp_db):
    """?status= has no control of its own — it shows as a pill that clears it."""
    resp = client.get("/visitors?group=path&status=4xx")
    assert resp.status_code == 200
    assert 'class="drill-pill"' in resp.text
    assert "Status" in resp.text and "4xx" in resp.text


def test_paths_search_filters(client, tmp_db):
    """?q= server-side filters the Paths table by path substring."""
    now = datetime.now(timezone.utc).isoformat()
    with get_conn(tmp_db) as conn:
        insert_visit(
            conn, ip="203.0.113.60", timestamp=now, method="GET", path="/wp-admin", status=404
        )
        insert_visit(
            conn, ip="203.0.113.61", timestamp=now, method="GET", path="/phpmyadmin", status=404
        )

    resp = client.get("/visitors", params={"group": "path", "q": "wp-admin"})
    assert resp.status_code == 200
    assert "/wp-admin" in resp.text
    assert "/phpmyadmin" not in resp.text

    # No filter shows both paths.
    resp_all = client.get("/visitors?group=path")
    assert "/wp-admin" in resp_all.text
    assert "/phpmyadmin" in resp_all.text


def test_paths_search_matches_user_agent(client, tmp_db):
    """The search spans the User-Agent too, so 'wget' surfaces CLI-tool paths."""
    now = datetime.now(timezone.utc).isoformat()
    with get_conn(tmp_db) as conn:
        insert_visit(
            conn,
            ip="203.0.113.70",
            timestamp=now,
            method="GET",
            path="/secret-probe",
            status=404,
            user_agent="Wget/1.21.1",
        )
        insert_visit(
            conn,
            ip="203.0.113.71",
            timestamp=now,
            method="GET",
            path="/other-probe",
            status=404,
            user_agent="Mozilla/5.0",
        )
    resp = client.get("/visitors", params={"group": "path", "q": "wget"})
    assert resp.status_code == 200
    assert "/secret-probe" in resp.text
    assert "/other-probe" not in resp.text


def test_paths_status_filter(client, tmp_db):
    """?status=4xx narrows the Paths table to paths with client-error responses."""
    now = datetime.now(timezone.utc).isoformat()
    with get_conn(tmp_db) as conn:
        insert_visit(conn, ip="203.0.113.80", timestamp=now, method="GET", path="/ok", status=200)
        insert_visit(
            conn, ip="203.0.113.81", timestamp=now, method="GET", path="/probe", status=404
        )

    resp = client.get("/visitors", params={"group": "path", "status": "4xx"})
    assert resp.status_code == 200
    assert "/probe" in resp.text
    assert "/ok" not in resp.text

    # An unknown status value is ignored → full view.
    resp_bad = client.get("/visitors", params={"group": "path", "status": "bogus"})
    assert "/ok" in resp_bad.text


def test_paths_pager_preserves_search(client, tmp_db):
    """Sort headers and the pager keep q and status when paginating."""
    now = datetime.now(timezone.utc).isoformat()
    with get_conn(tmp_db) as conn:
        # 20 distinct admin paths → more than one page at limit=10 under the q filter.
        for i in range(20):
            insert_visit(
                conn,
                ip=f"198.51.100.{i}",
                timestamp=now,
                method="GET",
                path=f"/admin/{i}",
                status=404,
            )
    resp = client.get(
        "/visitors", params={"group": "path", "q": "admin", "status": "4xx", "limit": 10}
    )
    assert resp.status_code == 200
    # The Next link must carry the pager param and the preserved search + status.
    assert "page=2" in resp.text
    assert "q=admin" in resp.text
    assert "status=4xx" in resp.text


def test_requests_redirects_to_paths(client, tmp_db):
    """The removed Requests page 301s to the Paths 4xx view, mapping path_q → q."""
    resp = client.get("/visitors/requests", follow_redirects=False)
    assert resp.status_code == 301
    assert resp.headers["location"] == "/visitors?group=path&status=4xx"

    resp_q = client.get(
        "/visitors/requests", params={"path_q": "wp-admin"}, follow_redirects=False
    )
    assert resp_q.status_code == 301
    assert resp_q.headers["location"] == "/visitors?group=path&status=4xx&q=wp-admin"


class TestAggregationTables:
    """The Visitor aggregation tables group the same visit⋈intel data by a new
    dimension, with the unified class/signal breakdown per row."""

    def test_networks_group_by_asn(self, dashboard_db):
        """Both seed IPs share AS1 → one network row aggregating their classes."""
        with get_conn(dashboard_db) as conn:
            rows = get_networks(conn)
            assert count_networks(conn) == 1
        row = rows[0]
        assert row["asn"] == "AS1"
        assert row["unique_ips"] == 2
        assert row["visits"] == 2
        assert row["humans_ips"] == 1
        assert row["bots_ips"] == 1
        assert row["country_count"] == 2  # DE + US

    def test_countries_group_by_country(self, dashboard_db):
        with get_conn(dashboard_db) as conn:
            rows = get_countries(conn)
        by_code = {r["country_code"]: r for r in rows}
        assert set(by_code) == {"DE", "US"}
        assert by_code["DE"]["humans_ips"] == 1
        assert by_code["US"]["bots_ips"] == 1

    def test_clients_group_by_browser(self, dashboard_db):
        with get_conn(dashboard_db) as conn:
            rows = get_clients(conn)
        browsers = {r["browser"] for r in rows}
        assert "Chrome" in browsers
        assert "Bot" in browsers

    def test_paths_group_by_path_with_status_mix(self, dashboard_db):
        with get_conn(dashboard_db) as conn:
            rows = get_paths(conn)
        by_path = {r["path"]: r for r in rows}
        assert by_path["/"]["s2xx"] == 1  # human hit "/" with 200
        assert by_path["/wp-admin"]["s4xx"] == 1  # bot hit "/wp-admin" with 404

    def test_class_filter_applies_to_aggregation(self, dashboard_db):
        """The legend's class filter narrows the aggregate to one identity group."""
        with get_conn(dashboard_db) as conn:
            rows = get_countries(conn, class_filter=["humans"])
        by_code = {r["country_code"]: r for r in rows}
        assert set(by_code) == {"DE"}  # only the human's country remains
        assert by_code["DE"]["humans_ips"] == 1

    def test_empty_db_aggregations(self, client, tmp_db):
        for path in ("networks", "countries", "clients", "paths"):
            resp = client.get(f"/visitors/{path}")
            assert resp.status_code == 200, path


class TestDrilldownFilters:
    """Aggregation rows link into /visitors pre-filtered by their dimension."""

    def test_asn_filter(self, client, dashboard_db):
        with patch("src.config.settings.db_path", dashboard_db):
            resp = client.get("/visitors?asn=AS1")
        assert resp.status_code == 200
        assert "203.0.113.10" in resp.text and "203.0.113.20" in resp.text
        assert 'class="drill-pill"' in resp.text  # drill-down pill is shown
        assert "AS1" in resp.text

    def test_path_filter(self, client, dashboard_db):
        with patch("src.config.settings.db_path", dashboard_db):
            resp = client.get("/visitors?path=/wp-admin")
        assert resp.status_code == 200
        assert "203.0.113.20" in resp.text
        assert "203.0.113.10" not in resp.text

    def test_browser_filter(self, client, dashboard_db):
        with patch("src.config.settings.db_path", dashboard_db):
            resp = client.get("/visitors?browser=Chrome")
        assert resp.status_code == 200
        assert "203.0.113.10" in resp.text
        assert "203.0.113.20" not in resp.text


# ── Field-aware search on the default grouping ────────────────────────────────
# Before the registry every term was a substring against eleven columns at once,
# so `de` matched 3,617 of 11,564 production IPs — 1,627 via `path`, because
# "index" contains the letters — while the 961 IPs actually in Germany drowned.


def _searchable_fixture(conn):
    now = datetime.now(timezone.utc).isoformat()
    insert_visit(
        conn,
        ip="192.0.2.96",
        timestamp=now,
        path="/index.html",
        status=200,
        browser="Chrome",
        os="Windows",
        device="Desktop",
        method="GET",
        server_port=443,
        http_version="HTTP/2.0",
        user_agent="Mozilla/5.0 Chrome/126",
        referer="https://news.example/a",
    )
    insert_visit(
        conn,
        ip="192.0.2.96",
        timestamp=now,
        path="/.env",
        status=404,
        browser="Chrome",
        os="Windows",
        device="Desktop",
        method="GET",
    )
    insert_visit(
        conn,
        ip="198.51.100.7",
        timestamp=now,
        path="/",
        status=200,
        browser="Firefox",
        os="Linux",
        device="Bot",
        method="POST",
        server_port=80,
        http_version="HTTP/1.1",
        user_agent="curl/8.1.0",
    )
    upsert_ip_intel(
        conn,
        _intel(
            "192.0.2.96",
            asn="AS9009",
            org="M247 Europe",
            isp="Datacamp Limited",
            country="Poland",
            country_code="PL",
            city="Warsaw",
            reverse_dns="host.datacamp.example",
            is_tor=1,
            tags="scanner",
            open_ports="22,443",
            vulns="CVE-2021-44228",
        ),
    )
    upsert_ip_intel(
        conn,
        _intel(
            "198.51.100.7",
            asn="AS64500",
            org="Example Telecom",
            isp="Example Telecom",
            country="Germany",
            country_code="DE",
            city="Berlin",
        ),
    )
    set_visitor_class(conn, "192.0.2.96", "threats/exploit-probers")
    set_visitor_class(conn, "198.51.100.7", "humans/browser-direct")


DE_IP, PL_IP = "198.51.100.7", "192.0.2.96"


@pytest.mark.parametrize(
    "term,present,absent",
    [
        # The reported bug: DE is the country, not a substring of "index".
        ("de", DE_IP, PL_IP),
        ("DE", DE_IP, PL_IP),
        ("country:DE", DE_IP, PL_IP),
        ("cc:pl", PL_IP, DE_IP),
        ("country:germ", DE_IP, PL_IP),
        ("city:Berlin", DE_IP, PL_IP),
        ("city:Warsaw", PL_IP, DE_IP),
        ("192.0.2.", PL_IP, DE_IP),
        ("ip:198.51.", DE_IP, PL_IP),
        ("AS9009", PL_IP, DE_IP),
        ("asn:AS64500", DE_IP, PL_IP),
        ("org:M247", PL_IP, DE_IP),
        ("isp:datacamp", PL_IP, DE_IP),
        ("rdns:datacamp.example", PL_IP, DE_IP),
        ("/.env", PL_IP, DE_IP),
        ("path:/.env", PL_IP, DE_IP),
        ("ua:curl", DE_IP, PL_IP),
        ("browser:Firefox", DE_IP, PL_IP),
        ("os:Windows", PL_IP, DE_IP),
        ("device:Bot", DE_IP, PL_IP),
        ("referer:news.example", PL_IP, DE_IP),
        ("class:threats", PL_IP, DE_IP),
        ("class:humans/browser-direct", DE_IP, PL_IP),
        ("signal:tor", PL_IP, DE_IP),
        ("tag:scanner", PL_IP, DE_IP),
        ("port:22", PL_IP, DE_IP),
        ("cve:CVE-2021", PL_IP, DE_IP),
        ("serverport:80", DE_IP, PL_IP),
        ("404", PL_IP, DE_IP),
        ("status:404", PL_IP, DE_IP),
        ("status:4xx", PL_IP, DE_IP),
        ("method:POST", DE_IP, PL_IP),
        ("http:2", PL_IP, DE_IP),
        ("datacamp", PL_IP, DE_IP),  # broad, no field, no recognised shape
    ],
)
def test_search_field_matrix(client, tmp_db, term, present, absent):
    with get_conn(tmp_db) as conn:
        _searchable_fixture(conn)
    body = client.get("/visitors", params={"q": term}).text
    assert present in body, term
    assert absent not in body, term


def test_short_term_no_longer_matches_a_path_substring(client, tmp_db):
    """The exact reported symptom: /index.html must not answer a search for DE."""
    with get_conn(tmp_db) as conn:
        _searchable_fixture(conn)
    with get_conn(tmp_db) as conn:
        assert [r["ip"] for r in get_visitors_grouped(conn, q="de")] == [DE_IP]
        # …and naming the field brings the substring behaviour back.
        assert [r["ip"] for r in get_visitors_grouped(conn, q="path:de")] == [PL_IP]


def test_search_keeps_the_rows_own_totals(client, tmp_db):
    """Searching by path selects the visitor; it must not shrink its numbers."""
    with get_conn(tmp_db) as conn:
        _searchable_fixture(conn)
    with get_conn(tmp_db) as conn:
        rows = get_visitors_grouped(conn, q="/.env")
    assert [r["ip"] for r in rows] == [PL_IP]
    assert rows[0]["visit_count"] == 2


def test_search_terms_are_anded(client, tmp_db):
    with get_conn(tmp_db) as conn:
        _searchable_fixture(conn)
    with get_conn(tmp_db) as conn:
        assert len(get_visitors_grouped(conn, q="isp:datacamp /.env")) == 1
        assert get_visitors_grouped(conn, q="isp:datacamp country:DE") == []


def test_search_quoted_phrase_stays_literal(client, tmp_db):
    with get_conn(tmp_db) as conn:
        _searchable_fixture(conn)
    with get_conn(tmp_db) as conn:
        assert len(get_visitors_grouped(conn, q='"M247 Europe"')) == 1
        assert get_visitors_grouped(conn, q='"Europe M247"') == []


@pytest.mark.parametrize("term", ["%", "_", "%%", "\\"])
def test_search_wildcards_are_literal(client, tmp_db, term):
    with get_conn(tmp_db) as conn:
        _searchable_fixture(conn)
    with get_conn(tmp_db) as conn:
        assert get_visitors_grouped(conn, q=term) == []


def test_search_narrows_map_and_timeline(client, tmp_db):
    with get_conn(tmp_db) as conn:
        _searchable_fixture(conn)
    with get_conn(tmp_db) as conn:
        markers, _ = get_geo_data(conn, q="isp:datacamp")
        assert [m["ip"] for m in markers] == [PL_IP]
        assert sum(d["total"] for d in get_activity_timeline(conn, q="isp:datacamp")) == 2
        assert sum(d["total"] for d in get_activity_timeline(conn)) == 3


@pytest.mark.parametrize(
    "q,shown",
    [
        ("wat:xyz", "wat"),
        # A known field given a value outside its enumeration. This used to build
        # a term that produced no SQL: the page listed everything under a pill
        # claiming a filter, and said nothing.
        ("signal:nonsense", "signal:nonsense"),
        ("class:bogus", "class:bogus"),
    ],
)
def test_a_term_that_cannot_filter_is_reported_not_dropped(client, tmp_db, q, shown):
    with get_conn(tmp_db) as conn:
        _searchable_fixture(conn)
    body = client.get("/visitors", params={"q": q}).text
    assert "no such field or value" in body
    assert shown in body
    # And no pill: a pill is a claim that the list is narrowed.
    pills = re.findall(r"<strong>([^<]*)</strong><code>([^<]*)</code>", body)
    assert not [p for p in pills if p[1] in q], f"a dropped term still drew a pill: {pills}"


def test_one_pill_per_term_each_removing_only_itself(client, tmp_db):
    with get_conn(tmp_db) as conn:
        _searchable_fixture(conn)
    body = client.get("/visitors", params={"q": "country:DE ua:curl"}).text
    pills = body.split('class="drill-pills"')[1].split("</div>")[0]
    assert "Country" in pills and "User-Agent" in pills
    # Removing the country pill must leave the user-agent term standing.
    assert "q=ua%3Acurl" in pills


def test_search_syntax_help_is_rendered_from_the_registry(client, tmp_db):
    with get_conn(tmp_db) as conn:
        _searchable_fixture(conn)
    body = client.get("/visitors").text
    for example in ("country:DE", "tag:scanner", "status:404", "ua:wget"):
        assert example in body, example


# ── The search form must not discard the rest of the selection ────────────────


def test_search_form_carries_the_other_filters(client, tmp_db):
    """Enter in the search box rebuilt the URL from a short hidden-field list, so
    it silently dropped the status band and every drill-down — searching inside a
    drill-down widened the result instead of narrowing it."""
    with get_conn(tmp_db) as conn:
        _searchable_fixture(conn)
    body = client.get(
        "/visitors",
        params={"group": "path", "status": "4xx", "class": "bots", "range": "7d"},
    ).text
    form = body.split('class="filter-rail-search"')[1].split("</form>")[0]
    for field in (
        'name="status" value="4xx"',
        'name="class" value="bots"',
        'name="group" value="path"',
        'name="range" value="7d"',
    ):
        assert field in form, field
    # A preset range must travel as ?range=, not as resolved dates — otherwise
    # submitting flips the page to "custom" and the tab loses its highlight.
    assert 'name="date_from"' not in form


def test_custom_range_form_carries_search_and_classes(client, tmp_db):
    with get_conn(tmp_db) as conn:
        _searchable_fixture(conn)
    body = client.get("/visitors", params={"q": "datacamp", "class": "bots"}).text
    form = body.split('class="range-custom-form"')[1].split("</form>")[0]
    assert 'name="q" value="datacamp"' in form
    assert 'name="class" value="bots"' in form


def test_forms_omit_fields_left_at_their_default(client, tmp_db):
    """group=ip and view=table are the defaults and were emitted as empty hidden
    inputs, so every submitted URL grew a stray ?group=&view=."""
    with get_conn(tmp_db) as conn:
        _searchable_fixture(conn)
    body = client.get("/visitors", params={"class": "bots"}).text
    hidden = [ln for ln in body.split("<input") if 'type="hidden"' in ln]
    assert any('name="class"' in ln for ln in hidden), "an active filter must be carried"
    assert not [ln for ln in hidden if 'value=""' in ln], "no empty hidden inputs"
    assert not [ln for ln in hidden if 'name="group"' in ln or 'name="view"' in ln]


def test_search_sits_on_its_own_rail_row(client, tmp_db):
    """The placeholder names five dimensions and was truncated beside the chips;
    the Syntax panel also read as belonging to the chip row rather than to the
    box it explains."""
    with get_conn(tmp_db) as conn:
        _searchable_fixture(conn)
    rail = client.get("/visitors").text.split('class="panel visitor-filter-bar')[1]
    rows = re.findall(r'class="filter-rail-row([^"]*)"', rail)
    assert rows == ["", " filter-rail-searchrow"]
    # The search form and the Syntax disclosure belong to the second row.
    assert rail.index("filter-rail-searchrow") < rail.index('class="filter-rail-search"')
    assert rail.index("filter-rail-searchrow") < rail.index("search-help")


def test_each_group_chip_carries_its_own_subclasses(client, tmp_db):
    """The flat "Classes" menu mixed all five groups into one list. Each group is
    now its own dropdown: "All <group>" plus that group's subclasses."""
    with get_conn(tmp_db) as conn:
        _searchable_fixture(conn)
    rail = client.get("/visitors").text.split('class="filter-rail-row"')[1]
    rail = rail.split("filter-rail-searchrow")[0]
    assert "Classes ▾" not in rail
    assert "Signals ▾" in rail, "the signal menu is unrelated and stays"

    groups = dict(VISITOR_CATEGORIES)
    menus = re.findall(r'<details class="group-filter"[^>]*>(.*?)</details>', rail, re.S)
    assert len(menus) == len([g for g, cats in VISITOR_CATEGORIES if any("/" in c for c in cats)])
    for menu in menus:
        values = re.findall(r'data-filter-value="([^"]+)"', menu)
        group = values[0]  # the "All <group>" entry comes first
        assert values[1:] == [c for c in groups[group] if "/" in c], group

    # The summary only opens the menu; filters.js binds to data-filter-value, so
    # carrying one there would filter on every open.
    assert not re.search(r"<summary[^>]*data-filter-value", rail)


def test_group_menu_entries_carry_their_ip_counts(client, tmp_db):
    """Every entry in a group menu shows how many IPs it holds.

    The chips outside carried counts and the entries inside did not, so the menu
    listed which classes exist without saying which ones the data has — a reader
    picked a filter to discover it returns nothing. `humans/browser-direct` has
    the one IP the fixture classified; its two siblings are a real zero.
    """
    with get_conn(tmp_db) as conn:
        _searchable_fixture(conn)
        expected = get_visitor_ip_counts(conn)
    rail = client.get("/visitors").text.split('class="filter-rail-row"')[1]
    rail = rail.split("filter-rail-searchrow")[0]

    entry = re.compile(
        r'data-filter-value="([^"]+)"[\s\S]*?<span class="filter-dot"></span>'
        # The <strong> carries a tooltip of its own now — the count is distinct
        # IPs inside the selected range, which is not obvious from a number.
        r"[^<]*(?:<strong[^>]*>([^<]*)</strong>)?\s*</button>"
    )
    seen = {}
    for menu in re.findall(r'<details class="group-filter"[^>]*>(.*?)</details>', rail, re.S):
        for value, count in entry.findall(menu):
            assert count, f"{value} has no count"
            seen[value] = int(count.replace(",", ""))

    assert seen["humans"] == expected["humans"] == 1
    assert seen["humans/browser-direct"] == 1
    assert seen["humans/browser-referred"] == 0
    assert seen["threats/exploit-probers"] == 1


def test_group_without_subclasses_stays_a_plain_chip(client, tmp_db):
    """`unknown` has no subclasses, so a dropdown would open onto nothing."""
    with get_conn(tmp_db) as conn:
        _searchable_fixture(conn)
    rail = client.get("/visitors").text.split('class="filter-rail-row"')[1]
    rail = rail.split("filter-rail-searchrow")[0]
    unknown = re.search(r'<button[^>]*data-filter-value="unknown"[^>]*>', rail)
    assert unknown, "unknown must still be a directly clickable chip"


def test_help_button_stays_beside_the_search_box(client, tmp_db):
    """The panel is a sibling of the <details>, not its content. As content it
    dragged the button onto the panel's own line; as an overlay it covered the
    tables. Sibling plus the ~ combinator keeps the button inline and the tables
    full width below it."""
    with get_conn(tmp_db) as conn:
        _searchable_fixture(conn)
    row = client.get("/visitors").text.split('filter-rail-searchrow"')[1].split("\n  </div>")[0]
    assert row.count("Help ▾") == 1
    # form, then the toggle, then the panel — and the panel outside the details.
    assert row.index("filter-rail-search") < row.index("<details") < row.index("search-help-panel")
    assert "</details>" in row.split("search-help-panel")[0]
    css = dashboard_css()
    assert ".search-help[open] ~ .search-help-panel" in css


def test_the_help_panel_documents_every_class_and_signal(client, tmp_db):
    """The chips are the filter; this is the only place that says what they mean.

    Generated from the taxonomy registry rather than written out, so the answer
    cannot drift from the thing it describes — which is the failure mode a
    hand-kept list has, and the reason the class chips went undocumented for as
    long as they did.
    """
    from src.taxonomy import SIGNALS, VALID_CLASSES

    with get_conn(tmp_db) as conn:
        _searchable_fixture(conn)
    panel = client.get("/visitors").text.split('id="search-syntax"')[1].split("\n    </div>")[0]

    missing = [c for c in VALID_CLASSES if f"<code>{c}</code>" not in panel]
    assert not missing, f"classes with no entry in Help: {sorted(missing)}"
    for s in SIGNALS:
        assert s.key in panel, f"signal {s.key} has no entry in Help"
        assert s.tip[0] in panel, f"signal {s.key} is listed without saying what it means"
    # Three tabs, and the machinery that switches them.
    assert panel.count("data-tab-panel=") == 3
    assert "tabs.js" in client.get("/visitors").text

    # One table for all five groups. A table sizes its columns from its own
    # contents, so a table per group put the description column at a different
    # x in each — set by whichever class name in that group was longest.
    classes_tab = panel.split('data-tab-panel="classes"')[1].split('data-tab-panel="signals"')[0]
    assert classes_tab.count("<table") == 1, "one table per group misaligns the columns"


class TestTheActivityChartsResolution:
    """The window picks the bucket, because zooming cannot rescue a short one.

    On a 24-hour range a daily axis is one or two points, and the zoom is no way
    out: it works by dragging between two buckets, so inside a single bucket
    there is nothing to open. The chart used to ship days regardless and could
    not be zoomed to hours on exactly the range where hours are all there is.
    """

    def _payload(self, html):
        raw = re.search(
            r'<script type="application/json">\s*(\{.*?\})\s*</script>', html, re.S
        ).group(1)
        return json.loads(raw)

    @pytest.fixture
    def three_days(self, tmp_db):
        """Three days of traffic, every third hour, ending yesterday at 23:00.

        Anchored to whole past days rather than to `now`: the 24h preset resolves
        to *today*, so a fixture counted backwards from the current moment holds
        one bucket at 00:30 and eight at 23:30. The test below asks for the day
        before instead, which is the same length of window and always full.
        """
        midnight = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        with get_conn(tmp_db) as conn:
            for h in range(1, 73, 3):
                insert_visit(
                    conn,
                    ip="203.0.113.10",
                    timestamp=(midnight - timedelta(hours=h)).isoformat(),
                    method="GET",
                    path="/",
                )
        yield tmp_db

    def test_a_one_day_window_ships_hourly_buckets(self, client, three_days):
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).date().isoformat()
        with patch("src.config.settings.db_path", three_days):
            data = self._payload(
                client.get(
                    f"/visitors?view=timeline&date_from={yesterday}&date_to={yesterday}"
                ).text
            )
        assert data["bucket"] == "hour"
        # "2026-08-12T01" — the hour is in the key, which is what makes it a point.
        assert all(len(r["day"]) == 13 for r in data["rows"])
        assert len(data["rows"]) > 2, "a chart needs more than the two points a day axis gave"

    @pytest.mark.parametrize(
        "span_days,expected",
        [(0, "hour"), (1, "hour"), (3, "hour"), (4, "day"), (6, "day"), (89, "day")],
    )
    def test_the_threshold_itself(self, span_days, expected):
        """The decision, without a page around it — the 24h preset resolves to a
        single day, which is the first row. Asserted here rather than through a
        rendered chart because the presets resolve against the current clock: a
        24h window at 00:30 holds one hour of traffic and at 23:30 holds
        twenty-four, and neither says anything about the rule."""
        from src.routes._charts import pick_bucket

        end = date(2026, 8, 12)
        start = end - timedelta(days=span_days)
        assert pick_bucket(start.isoformat(), end.isoformat()) == expected

    def test_an_open_window_stays_daily(self):
        """`all` has no bounds, and is the longest span there is."""
        from src.routes._charts import pick_bucket

        assert pick_bucket(None, None) == "day"
        assert pick_bucket("2026-08-01", None) == "day"

    @pytest.mark.parametrize("rng", ["7d", "30d", "90d", "all"])
    def test_the_long_ranges_stay_daily(self, client, three_days, rng):
        """Anything a day axis can carry keeps it — hours over 90 days is noise."""
        with patch("src.config.settings.db_path", three_days):
            data = self._payload(client.get(f"/visitors?view=timeline&range={rng}").text)
        assert data["bucket"] == "day"
        assert all(len(r["day"]) == 10 for r in data["rows"])

    def test_the_switch_threshold_reaches_the_browser(self, client, three_days):
        """One number decides which bucket ships and which one a zoom drops to.
        It travels in the payload so timeline.js cannot hold a second opinion."""
        from src.routes._charts import HOUR_SWITCH_DAYS

        with patch("src.config.settings.db_path", three_days):
            data = self._payload(client.get("/visitors?view=timeline&range=7d").text)
        assert data["hourSwitchDays"] == HOUR_SWITCH_DAYS


class TestTheRangeGovernsEveryPage:
    """The rule this whole feature exists for: the window scopes every number.

    Half a page reacting to the range is worse than none of it — the header
    claims a filter that only some of the tiles below apply. These tests hold
    the rule itself, not any one figure: the same fixture is rendered inside and
    outside the window, and what the page shows has to differ.
    """

    @pytest.fixture
    def two_eras_db(self, tmp_db):
        """One IP long ago, one today — nothing overlaps the two windows."""
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        now = datetime.now(timezone.utc).isoformat()
        with get_conn(tmp_db) as conn:
            for ip, ts, path in (
                ("203.0.113.10", old, "/old.html"),
                ("203.0.113.10", old, "/old.html"),
                ("203.0.113.11", now, "/new.html"),
            ):
                insert_visit(conn, ip=ip, timestamp=ts, path=path, status=200, bytes_sent=10)
            upsert_ip_intel(conn, _intel("203.0.113.10", tags="scanner", open_ports="22"))
            upsert_ip_intel(conn, _intel("203.0.113.11", tags="vpn", open_ports="443"))
            set_visitor_class(conn, "203.0.113.10", "threats/exploit-probers")
            set_visitor_class(conn, "203.0.113.11", "bots/crawler")
        return tmp_db

    def _page(self, client, db, path, rng):
        with patch("src.config.settings.db_path", db):
            sep = "&" if "?" in path else "?"
            return client.get(f"{path}{sep}range={rng}").text

    @pytest.mark.parametrize("path", ["/", "/visitors", "/analysis", "/exposure"])
    def test_the_old_era_is_absent_from_the_recent_window(self, client, two_eras_db, path):
        recent = self._page(client, two_eras_db, path, "24h")
        everything = self._page(client, two_eras_db, path, "all")
        assert "203.0.113.10" in everything or "/old.html" in everything or "22" in everything
        assert "203.0.113.10" not in recent
        assert "/old.html" not in recent

    def test_overview_tiles_all_move_with_the_window(self, client, two_eras_db):
        recent = self._page(client, two_eras_db, "/", "24h")
        everything = self._page(client, two_eras_db, "/", "all")

        def cards(text):
            return dict(
                re.findall(
                    r'<div class="card-label">.*?>([^<]+)</span></div>\s*'
                    r'<div class="card-value[^"]*">([^<]*)<',
                    text,
                    re.S,
                )
            )

        a, b = cards(everything), cards(recent)
        assert a and a.keys() == b.keys()
        assert a["Visits"] == "3" and b["Visits"] == "1"
        assert a["Unique IPs"] == "2" and b["Unique IPs"] == "1"
        assert a["Bandwidth"] != b["Bandwidth"]

    def test_the_fixed_window_tiles_are_gone(self, client, two_eras_db):
        """Today / Last 7 Days / Last 30 Days carried their own windows next to
        a chosen one — three contradictions on a page with a range in its head."""
        text = self._page(client, two_eras_db, "/", "all")
        for label in ("Last 7 Days", "Last 30 Days"):
            assert f">{label}<" not in text

    def test_the_matrix_counts_only_ips_from_the_window(self, client, two_eras_db):
        def cells(text):
            body = text.split('class="responsive-table matrix"')[1]
            tbody = body.split("<tbody>")[1].split("</tbody>")[0]
            return [int(v) for v in re.findall(r">\s*([0-9]+)\s*<", tbody)]

        assert sum(cells(self._page(client, two_eras_db, "/analysis", "all"))) > sum(
            cells(self._page(client, two_eras_db, "/analysis", "24h"))
        )

    def test_exposure_hosts_follow_the_window(self, client, two_eras_db):
        recent = self._page(client, two_eras_db, "/exposure", "24h")
        everything = self._page(client, two_eras_db, "/exposure", "all")
        assert "203.0.113.10" in everything and "203.0.113.11" in everything
        assert "203.0.113.10" not in recent and "203.0.113.11" in recent

    def test_exposure_links_carry_the_window(self, client, two_eras_db):
        """A facet click must not widen the time window on the way."""
        text = self._page(client, two_eras_db, "/exposure", "24h")
        links = re.findall(r'href="(/exposure\?[^"]*)"', text)
        assert links
        value_links = [unescape(h) for h in links if "port=" in h or "tag=" in h or "vuln=" in h]
        assert value_links
        for href in value_links:
            assert "range=24h" in href, href

    def test_the_delta_compares_against_the_span_before(self, client, tmp_db):
        """And names it, rather than claiming "vs prior week" at every range.

        The comparison window is built from dates and has to be expanded to
        timestamps like the main one; comparing a bare "2026-08-07" against
        "2026-08-07T10:00:00" as an upper bound excludes that whole day, which
        showed up as a missing delta rather than a wrong one.
        """
        now = datetime.now(timezone.utc)
        with get_conn(tmp_db) as conn:
            for _ in range(4):
                insert_visit(conn, ip="203.0.113.5", timestamp=now.isoformat(), path="/")
            insert_visit(
                conn,
                ip="203.0.113.6",
                timestamp=(now - timedelta(days=1)).isoformat(),
                path="/",
            )
        text = client.get("/?range=24h").text
        delta = re.search(r"card-delta[^>]*>([^<]+)<", text)
        assert delta, "no delta rendered although the previous day has visits"
        assert "vs previous 24 h" in delta.group(1)
        assert "+300%" in delta.group(1)  # 4 today against 1 the day before
