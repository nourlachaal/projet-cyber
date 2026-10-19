"""PostgreSQL persistence for the threat-intel pole (Student 3)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Self

import psycopg
from psycopg.types.json import Jsonb
from pydantic import ValidationError

from honeypots.common.events import Event

AUTH_EVENTS = ("auth_attempt", "api_auth_attempt")


@dataclass
class IngestStats:
    read: int = 0
    inserted: int = 0
    duplicates: int = 0
    invalid: int = 0


@dataclass
class IOC:
    """Observed indicator with provenance (not proof of an attack)."""

    type: str  # ipv4 | ipv6 | domain | url | user-agent | credential
    value: str
    first_seen: datetime
    last_seen: datetime
    sight_count: int = 1
    confidence: int = 50
    source: str = "honeypot"
    tags: list[str] = field(default_factory=list)


class Store:
    def __init__(self, dsn: str):
        self._dsn = dsn
        self._conn = psycopg.connect(dsn, autocommit=False)

    @classmethod
    def from_env(cls) -> Self:
        dsn = os.getenv("TI_DB_DSN")
        if not dsn:
            from threat_intel.db.migrate import load_dsn

            dsn = load_dsn()
        return cls(dsn)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --- migrations -------------------------------------------------------

    def migrate(self) -> list[str]:
        from threat_intel.db.migrate import migrate

        return migrate(self._conn)

    # --- write ------------------------------------------------------------

    def insert_event(self, ev: Event) -> bool:
        """Insert one event. True if inserted, False if duplicate (event_id)."""
        with self._conn.transaction():
            cur = self._conn.execute(
                """
                INSERT INTO events (
                    event_id, timestamp, received_at, service, event_type,
                    source_ip, source_port, session_id, details
                ) VALUES (%s, %s, now(), %s, %s, %s, %s, %s, %s)
                ON CONFLICT (event_id) DO NOTHING
                """,
                [
                    ev.event_id,
                    ev.timestamp,
                    ev.service,
                    ev.event_type,
                    ev.source_ip,
                    ev.source_port,
                    ev.session_id,
                    Jsonb(ev.details),
                ],
            )
            return cur.rowcount == 1

    def insert_events(self, events: list[Event]) -> IngestStats:
        """Insert a batch; side tables only updated for newly inserted events."""
        stats = IngestStats(read=len(events))
        for ev in events:
            if self.insert_event(ev):
                stats.inserted += 1
                self.upsert_attacker(ev)
                self.upsert_session_from_event(ev)
                self.insert_credential(ev)
            else:
                stats.duplicates += 1
        return stats

    def upsert_session_from_event(self, ev: Event) -> None:
        """Roll the event up into its session row (idempotent per event)."""
        is_command = ev.event_type == "command"
        login_ok = ev.event_type in AUTH_EVENTS and bool(ev.details.get("success"))
        ended_at = ev.timestamp if ev.event_type == "disconnect" else None
        with self._conn.transaction():
            self._conn.execute(
                """
                INSERT INTO sessions (
                    session_id, service, source_ip, started_at, ended_at,
                    event_count, command_count, login_success
                ) VALUES (%s, %s, %s, %s, %s, 1, %s, %s)
                ON CONFLICT (session_id) DO UPDATE SET
                    event_count    = sessions.event_count + 1,
                    command_count  = sessions.command_count + EXCLUDED.command_count,
                    login_success  = sessions.login_success OR EXCLUDED.login_success,
                    started_at     = LEAST(sessions.started_at, EXCLUDED.started_at),
                    ended_at       = COALESCE(sessions.ended_at, EXCLUDED.ended_at)
                """,
                [
                    ev.session_id,
                    ev.service,
                    ev.source_ip,
                    ev.timestamp,
                    ended_at,
                    1 if is_command else 0,
                    login_ok,
                ],
            )

    def upsert_attacker(self, ev: Event) -> None:
        """Additive per-IP rollup: total_events += 1, services merged."""
        with self._conn.transaction():
            self._conn.execute(
                """
                INSERT INTO attackers (ip, first_seen, last_seen, total_events, services)
                VALUES (%s, %s, %s, 1, ARRAY[%s]::text[])
                ON CONFLICT (ip) DO UPDATE SET
                    first_seen   = LEAST(attackers.first_seen, EXCLUDED.first_seen),
                    last_seen    = GREATEST(attackers.last_seen, EXCLUDED.last_seen),
                    total_events = attackers.total_events + 1,
                    services     = CASE
                        WHEN EXCLUDED.services[1] = ANY(attackers.services)
                            THEN attackers.services
                        ELSE attackers.services || EXCLUDED.services
                    END
                """,
                [ev.source_ip, ev.timestamp, ev.timestamp, ev.service],
            )

    def insert_credential(self, ev: Event) -> None:
        """Store captured auth attempts (auth_attempt / api_auth_attempt)."""
        if ev.event_type not in AUTH_EVENTS:
            return
        with self._conn.transaction():
            self._conn.execute(
                """
                INSERT INTO credentials (
                    timestamp, session_id, service, source_ip,
                    username, password, success, auth_method
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'password')
                """,
                [
                    ev.timestamp,
                    ev.session_id,
                    ev.service,
                    ev.source_ip,
                    ev.details.get("username", ""),
                    ev.details.get("password", ""),
                    bool(ev.details.get("success", False)),
                ],
            )

    def upsert_ioc(self, ioc: IOC) -> None:
        """Dedup on (type, value): sight_count+1, confidence = max seen."""
        with self._conn.transaction():
            self._conn.execute(
                """
                INSERT INTO iocs (
                    type, value, first_seen, last_seen,
                    sight_count, confidence, source, tags
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (type, value) DO UPDATE SET
                    first_seen  = LEAST(iocs.first_seen, EXCLUDED.first_seen),
                    last_seen   = GREATEST(iocs.last_seen, EXCLUDED.last_seen),
                    sight_count = iocs.sight_count + 1,
                    confidence  = GREATEST(iocs.confidence, EXCLUDED.confidence),
                    tags        = (
                        SELECT array_agg(DISTINCT t)
                        FROM unnest(iocs.tags || EXCLUDED.tags) AS t
                    )
                """,
                [
                    ioc.type,
                    ioc.value,
                    ioc.first_seen,
                    ioc.last_seen,
                    ioc.sight_count,
                    ioc.confidence,
                    ioc.source,
                    ioc.tags,
                ],
            )

    # --- read -------------------------------------------------------------

    def count_events(self) -> int:
        return self._conn.execute("SELECT count(*) FROM events").fetchone()[0]

    def count_by_service(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT service, count(*) FROM events GROUP BY service ORDER BY service"
        )
        return {row[0]: row[1] for row in rows}

    def recent_events(self, limit: int = 20) -> list[dict]:
        rows = self._conn.execute(
            """
            SELECT event_id, timestamp, service, event_type, source_ip, session_id
            FROM events ORDER BY timestamp DESC LIMIT %s
            """,
            [limit],
        ).fetchall()
        keys = ("event_id", "timestamp", "service", "event_type", "source_ip", "session_id")
        return [dict(zip(keys, row)) for row in rows]


def ingest_jsonl(store: Store, path: Path) -> IngestStats:
    """Parse a JSONL file (event contract) and persist it.

    Each line is validated with the shared Event model; invalid lines are
    counted and skipped, never crashing the batch.
    """
    stats = IngestStats()
    if not path.exists():
        return stats
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        stats.read += 1
        try:
            ev = Event.model_validate_json(line)
        except ValidationError:
            stats.invalid += 1
            continue
        if store.insert_event(ev):
            stats.inserted += 1
            store.upsert_attacker(ev)
            store.upsert_session_from_event(ev)
            store.insert_credential(ev)
        else:
            stats.duplicates += 1
    return stats
