import asyncio

from aiohttp.test_utils import TestClient, TestServer

from honeypots.common import config
from honeypots.http_hp import server


def _call(monkeypatch, method, path, **kwargs):
    events = []
    monkeypatch.setattr(server, "emit", events.append)

    async def go():
        async with TestClient(TestServer(server.create_app())) as client:
            resp = await client.request(method, path, **kwargs)
            return resp.status

    return asyncio.run(go()), events


def test_unknown_path_is_404(monkeypatch):
    status, events = _call(monkeypatch, "GET", "/nothing")
    assert status == 404
    assert events[0].details["trap_hit"] is False


def test_trap_path_and_scanner_ua(monkeypatch):
    status, events = _call(monkeypatch, "GET", "/.env", headers={"User-Agent": "sqlmap/1.7"})
    assert status == 403
    assert events[0].details["trap_hit"] is True
    assert events[0].details["scanner_ua"] is True


def test_source_port_is_captured(monkeypatch):
    _, events = _call(monkeypatch, "GET", "/robots.txt")
    assert isinstance(events[0].source_port, int)


def test_login_password_is_hashed(monkeypatch):
    monkeypatch.setattr(config, "CAPTURE_PASSWORDS", False)
    _, events = _call(monkeypatch, "POST", "/wp-login.php", data={"log": "admin", "pwd": "hunter2"})
    d = events[0].details
    assert d["username"] == "admin"
    assert d["password"].startswith("sha256:")
