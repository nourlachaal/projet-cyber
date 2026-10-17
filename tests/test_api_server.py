import asyncio
import json

import pytest
from aiohttp.test_utils import TestClient, TestServer

from honeypots.api_hp.server import create_app
from honeypots.common import emitter


@pytest.fixture
def events_file(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    monkeypatch.setattr(emitter, "LOG_PATH", path)
    return path


def read_events(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def run(scenario, **app_kwargs):
    """Start the honeypot in-process, run an async scenario against it, return its result."""

    async def runner():
        async with TestClient(TestServer(create_app(**app_kwargs))) as client:
            return await scenario(client)

    return asyncio.run(runner())


def test_banner_and_unknown_route_are_logged(events_file):
    async def scenario(client):
        banner = await client.get("/")
        missing = await client.get("/nope")
        return banner.status, await banner.json(), missing.status

    banner_status, banner_json, missing_status = run(scenario)
    assert banner_status == 200 and banner_json["service"] == "acme-internal-api"
    assert missing_status == 404

    events = read_events(events_file)
    assert [e["event_type"] for e in events] == ["api_request", "api_request"]
    assert all(e["service"] == "api" for e in events)
    assert isinstance(events[0]["source_port"], int)
    assert events[0]["details"]["response_status"] == 200
    assert events[1]["details"]["response_status"] == 404


def test_login_refused_then_accepted(events_file):
    async def scenario(client):
        results = []
        for _ in range(3):
            resp = await client.post("/api/v1/auth/login",
                                     json={"username": "admin", "password": "admin123"})
            results.append((resp.status, await resp.json()))
        return results

    results = run(scenario, accept_after=3)
    assert [status for status, _ in results] == [401, 401, 200]
    assert "access_token" in results[2][1]

    events = read_events(events_file)
    auth = [e for e in events if e["event_type"] == "api_auth_attempt"]
    assert [e["details"]["attempt_no"] for e in auth] == [1, 2, 3]
    assert [e["details"]["success"] for e in auth] == [False, False, True]
    assert auth[0]["details"]["username"] == "admin"
    assert auth[0]["details"]["password"] == "admin123"  # clear text: isolated lab only


def test_users_endpoint_needs_a_token(events_file):
    async def scenario(client):
        none = await client.get("/api/v1/users")
        junk = await client.get("/api/v1/users", headers={"Authorization": "Bearer abc.def.ghi"})
        return none.status, junk.status

    assert run(scenario) == (401, 403)
    states = [e["details"]["token_state"] for e in read_events(events_file)]
    assert states == ["none", "unknown"]


def test_honeytoken_is_tracked_when_reused(events_file):
    async def scenario(client):
        login = await client.post("/api/v1/auth/login",
                                  json={"username": "root", "password": "toor"})
        token = (await login.json())["access_token"]
        auth = {"Authorization": f"Bearer {token}"}
        users = await client.get("/api/v1/users", headers=auth)
        one = await client.get("/api/v1/users/2", headers=auth)
        missing = await client.get("/api/v1/users/99", headers=auth)
        return users.status, await users.json(), one.status, missing.status

    users_status, users_json, one_status, missing_status = run(scenario, accept_after=1)
    assert users_status == 200 and len(users_json["users"]) == 5
    assert one_status == 200 and missing_status == 404

    events = read_events(events_file)
    used = [e for e in events if e["event_type"] == "honeytoken_used"]
    assert len(used) == 3
    assert used[0]["details"]["token_username"] == "root"
    requests = [e for e in events if e["event_type"] == "api_request"]
    assert all(e["details"]["token_state"] == "honeytoken" for e in requests)


def test_trap_path_and_scanner_user_agent_are_flagged(events_file):
    async def scenario(client):
        resp = await client.get("/api/v1/internal/config",
                                headers={"User-Agent": "sqlmap/1.7 (lab-scenario)"})
        return resp.status

    assert run(scenario) == 401
    details = read_events(events_file)[0]["details"]
    assert details["trap_hit"] is True
    assert details["scanner_ua"] is True


def test_attack_patterns_are_labelled_not_executed(events_file, tmp_path):
    marker = tmp_path / "pwned.txt"

    async def scenario(client):
        await client.get("/api/v1/users", params={"id": "1' OR '1'='1"})
        await client.get("/api/v1/users", params={"file": "../../etc/passwd"})
        await client.post("/api/v1/auth/login",
                          json={"username": f"a; touch {marker}", "password": "x"})

    run(scenario)
    events = read_events(events_file)
    assert "sqli" in events[0]["details"]["indicators"]
    assert "path_traversal" in events[1]["details"]["indicators"]
    assert "cmd_injection" in events[2]["details"]["indicators"]
    assert not marker.exists()  # received text is never executed


def test_passwords_and_tokens_are_hashed_when_capture_is_off(events_file):
    async def scenario(client):
        await client.post("/api/v1/auth/login", json={"username": "u", "password": "secret123"})
        await client.get("/api/v1/users", headers={"Authorization": "Bearer my.private.token"})

    run(scenario, accept_after=5, capture_passwords=False)
    text = events_file.read_text(encoding="utf-8")
    assert "secret123" not in text
    assert "my.private.token" not in text
    events = read_events(events_file)
    assert events[0]["details"]["password"].startswith("sha256:")


def test_oversized_request_is_refused_and_logged(events_file):
    async def scenario(client):
        resp = await client.post("/api/v1/auth/login", data=b"x" * 200_000)
        return resp.status

    assert run(scenario) == 413
    details = read_events(events_file)[0]["details"]
    assert details["body"] == "[too large]"
    assert details["response_status"] == 413
