"""A page on another domain must not be able to read this dashboard through DNS.

The SSH tunnel covers the network, not the browser at its end, and the
cross-origin write guard covers writes, not reads. DNS rebinding gets past
both: a page on attacker.example re-points its own name at 127.0.0.1, and the
operator's browser then treats http://attacker.example:8080 as the page's own
origin. Sec-Fetch-Site says same-origin, the write guard lets a delete through,
and every response — /api/export, a whole-database snapshot — is readable by
the page that asked.

The one thing that page cannot change is the Host header its requests carry:
the browser sends the attacker's name. So the name is the check.
"""

import pytest
from fastapi.testclient import TestClient

from src.config import Settings, settings
from src.main import app

LOOPBACK = ["localhost", "127.0.0.1", "[::1]"]


@pytest.fixture
def client(tmp_db, monkeypatch):
    monkeypatch.setattr(settings, "allowed_hosts", list(LOOPBACK))
    return TestClient(app)


def _get(client, host, path="/health"):
    return client.get(path, headers={"Host": host})


def test_the_default_admits_loopback_and_nothing_else():
    assert Settings.model_fields["allowed_hosts"].default == LOOPBACK


@pytest.mark.parametrize("host", ["localhost:8080", "127.0.0.1:8080", "[::1]:8080", "LOCALHOST"])
def test_the_tunnel_names_are_served(client, host):
    assert _get(client, host).status_code == 200


@pytest.mark.parametrize(
    "path", ["/health", "/api/stats", "/api/export", "/settings/status", "/visitors"]
)
def test_a_rebound_name_is_refused_everywhere(client, path):
    resp = _get(client, "attacker.example:8080", path)
    assert resp.status_code == 400
    assert "attacker.example" not in resp.text, "the refusal echoes nothing back"


def test_a_rebound_write_is_refused_before_the_write_guard_is_asked(client):
    """Sec-Fetch-Site: same-origin is exactly what a rebound page's request says."""
    resp = client.post(
        "/settings/storage/delete-month/2026-08",
        headers={"Host": "attacker.example:8080", "Sec-Fetch-Site": "same-origin"},
    )
    assert resp.status_code == 400


def test_a_name_that_only_starts_like_loopback_is_not_loopback(client):
    assert _get(client, "localhost.attacker.example").status_code == 400
    assert _get(client, "127.0.0.1.attacker.example:8080").status_code == 400


def test_a_proxy_name_is_served_once_configured(client, monkeypatch):
    monkeypatch.setattr(settings, "allowed_hosts", [*LOOPBACK, "vidar.example.org"])
    assert _get(client, "vidar.example.org").status_code == 200
    assert _get(client, "vidar.example.org:443").status_code == 200
    assert _get(client, "other.example.org").status_code == 400


def test_a_star_turns_the_check_off(client, monkeypatch):
    monkeypatch.setattr(settings, "allowed_hosts", ["*"])
    assert _get(client, "anything.example").status_code == 200


def test_the_list_is_read_as_csv_from_the_environment(monkeypatch):
    monkeypatch.setenv("ALLOWED_HOSTS", "localhost, vidar.example.org")
    assert Settings().allowed_hosts == ["localhost", "vidar.example.org"]
