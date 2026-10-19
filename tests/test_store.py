"""Tests for the threat-intel store (require the local Postgres lab container)."""

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

from honeypots.common.events import Event
from threat_intel.store import IOC, Store, ingest_jsonl

REPO_ROOT = Path(__file__).resolve().parents[1]
DSN = "postgresql://hive:hive@127.0.0.1:5433/hive"
REAL_JSONL = REPO_ROOT / "data" / "events.jsonl"


def _db_available() -> bool:
    try:
        with psycopg.connect(DSN, connect_timeout=2) as conn:
            conn.execute("SELECT 1")
        return True
    except psycopg.Error:
        return False


pytestmark = pytest.mark.skipif(
    not _db_available(), reason="PostgreSQL not reachable on 127.0.0.1:5433"
)


@pytest.fixture
def store():
    s = Store(DSN)
    s.migrate()
    with s._conn.transaction():
        s._conn.execute("TRUNCATE events, sessions, attackers, credentials, iocs, mitre_detections")
    yield s
    s.close()


def make_event(**overrides) -> Event:
    base = {
        "service": "ssh",
        "event_type": "connect",
        "source_ip": "203.0.113.10",
        "source_port": 40000,
        "session_id": uuid4().hex[:12],
        "details": {},
    }
    base.update(overrides)
    return Event(**base)


def test_migrate_creates_tables(store):
    rows = store._conn.execute(
        """
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name IN
          ('events', 'sessions', 'attackers', 'credentials', 'iocs', 'mitre_detections')
        """
    ).fetchall()
    assert len(rows) == 6


def test_insert_and_count_event(store):
    assert store.insert_event(make_event()) is True
    assert store.count_events() == 1


def test_duplicate_event_is_rejected(store):
    ev = make_event()
    assert store.insert_event(ev) is True
    assert store.insert_event(ev) is False
    assert store.count_events() == 1


def test_source_port_null_is_accepted(store):
    ev = make_event(service="http", event_type="http_request", source_port=None)
    assert store.insert_event(ev) is True


def test_ingest_jsonl_counts(store, tmp_path):
    path = tmp_path / "events.jsonl"
    good = make_event().model_dump_json()
    bad = '{"event_id": "broken", "service": "nope"}'
    path.write_text(good + "\n" + bad + "\n", encoding="utf-8")

    stats = ingest_jsonl(store, path)
    assert stats.read == 2
    assert stats.inserted == 1
    assert stats.invalid == 1
    assert stats.duplicates == 0
    assert store.count_events() == 1


def test_reingest_marks_all_duplicates(store, tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(make_event().model_dump_json() + "\n", encoding="utf-8")

    first = ingest_jsonl(store, path)
    second = ingest_jsonl(store, path)
    assert first.inserted == 1
    assert second.duplicates == 1
    assert second.inserted == 0
    assert store.count_events() == 1


def test_ingest_real_jsonl(store):
    if not REAL_JSONL.exists():
        pytest.skip("data/events.jsonl not generated yet (run scenarios/ first)")
    stats = ingest_jsonl(store, REAL_JSONL)
    assert stats.invalid == 0
    assert stats.read == stats.inserted + stats.duplicates
    assert stats.inserted > 0
    by_service = store.count_by_service()
    assert sum(by_service.values()) == stats.inserted
    assert {"ssh", "http", "api"} <= set(by_service)


def test_upsert_attacker_is_additive(store):
    ip = "198.51.100.7"
    store.insert_events([make_event(source_ip=ip, service="ssh")])
    store.upsert_attacker(make_event(source_ip=ip, service="ssh"))
    store.upsert_attacker(make_event(source_ip=ip, service="http"))

    row = store._conn.execute(
        "SELECT total_events, services FROM attackers WHERE ip = %s", [ip]
    ).fetchone()
    assert row[0] == 3
    assert "ssh" in row[1] and "http" in row[1]


def test_session_rollup(store):
    sid = "sess42"
    store.insert_events(
        [
            make_event(session_id=sid, event_type="command", details={"command": "whoami"}),
            make_event(
                session_id=sid,
                event_type="auth_attempt",
                details={"username": "root", "password": "x", "success": True},
            ),
        ]
    )

    row = store._conn.execute(
        "SELECT event_count, command_count, login_success FROM sessions WHERE session_id = %s",
        [sid],
    ).fetchone()
    assert row == (2, 1, True)


def test_credential_captured_from_auth_attempt(store):
    ev = make_event(
        event_type="auth_attempt",
        details={"username": "root", "password": "toor", "success": False, "attempt_no": 1},
    )
    store.insert_event(ev)
    store.insert_credential(ev)

    row = store._conn.execute("SELECT username, password, success FROM credentials").fetchone()
    assert row == ("root", "toor", False)


def test_upsert_ioc_dedup_and_confidence(store):
    now = datetime.now(UTC)
    ioc = IOC(
        type="url",
        value="http://evil.example/payload.sh",
        first_seen=now,
        last_seen=now,
        confidence=60,
        tags=["t1"],
    )

    store.upsert_ioc(ioc)
    store.upsert_ioc(ioc)

    row = store._conn.execute(
        "SELECT sight_count, confidence FROM iocs WHERE type = 'url'"
    ).fetchone()
    assert row[0] == 2
    assert row[1] == 60
