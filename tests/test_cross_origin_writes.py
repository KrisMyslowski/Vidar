"""No foreign page may change this dashboard's state.

There is no login: the SSH tunnel covers the network, not the browser at its
end. A form post is a simple request, so any page the operator has open can
send one to localhost:8080 — and two of the endpoints it reaches delete data.

The parametrised tests walk app.routes, so a new POST route is covered by
existing.
"""

import pytest
from fastapi.testclient import TestClient

from src.main import _UNSAFE_METHODS, app

# Every state-changing route the app declares, path params filled in. Derived
# from the router, so nothing is kept in step by hand.
_UNSAFE_ROUTES = sorted(
    {
        (method, route.path.replace("{month}", "2026-08"))
        for route in app.routes
        for method in getattr(route, "methods", set()) & _UNSAFE_METHODS
    }
)


@pytest.fixture
def client(tmp_db):
    return TestClient(app)


def _ids(case):
    return f"{case[0]} {case[1]}"


class TestTheGate:
    """Sec-Fetch-Site is set by the browser and cannot be forged by the page."""

    @pytest.mark.parametrize("case", _UNSAFE_ROUTES, ids=_ids)
    def test_a_cross_site_post_is_refused(self, client, case):
        method, path = case
        resp = client.request(method, path, headers={"Sec-Fetch-Site": "cross-site"})
        assert resp.status_code == 403, f"{method} {path} accepted a cross-site request"

    @pytest.mark.parametrize("case", _UNSAFE_ROUTES, ids=_ids)
    def test_same_site_is_not_enough(self, client, case):
        """A port is not part of a site — anything else on localhost sends this."""
        method, path = case
        resp = client.request(method, path, headers={"Sec-Fetch-Site": "same-site"})
        assert resp.status_code == 403, f"{method} {path} accepted a same-site request"

    @pytest.mark.parametrize("case", _UNSAFE_ROUTES, ids=_ids)
    def test_the_dashboards_own_forms_get_through(self, client, case):
        """Whatever the handler answers, it must not be the gate's 403."""
        method, path = case
        resp = client.request(method, path, headers={"Sec-Fetch-Site": "same-origin"})
        assert resp.status_code != 403, f"{method} {path} refused its own form"


class TestTheOriginFallback:
    """For clients too old to send Sec-Fetch."""

    def test_a_foreign_origin_is_refused(self, client):
        resp = client.post(
            "/settings/storage/mode",
            data={"mode": "lifetime"},
            headers={"Origin": "https://evil.example"},
        )
        assert resp.status_code == 403

    def test_our_own_origin_is_accepted(self, client):
        resp = client.post(
            "/settings/storage/mode",
            data={"mode": "lifetime"},
            headers={"Origin": "http://testserver", "Host": "testserver"},
        )
        assert resp.status_code != 403


class TestWhatMustKeepWorking:
    def test_a_request_with_neither_header_is_left_alone(self, client):
        """curl, the smoke test and the rest of this suite send neither."""
        resp = client.post("/settings/storage/mode", data={"mode": "rolling"})
        assert resp.status_code != 403

    @pytest.mark.parametrize("path", ["/health", "/", "/visitors", "/settings/storage"])
    def test_reading_is_never_blocked(self, client, path):
        """A cross-site GET is how every link into the dashboard arrives."""
        resp = client.get(path, headers={"Sec-Fetch-Site": "cross-site"})
        assert resp.status_code != 403
