# Progress report — Threat Intel (Student 3 — Data)

Status: 2026-10-19 · branch `main`

## Done

### Scope document

- `docs/threat-intel.md` — pole scope: schema, detection rules (thresholds +
  windows + MITRE ids), IOC extraction, STIX/blocklist exports, planned
  endpoints, testing strategy. Read it before touching `threat_intel/`.

### PostgreSQL lab service

- `docker-compose.yml`: `postgres:17-alpine` on the internal `lab` network,
  volume `pgdata`, no published ports in the base file (security model).
- `docker-compose.dev.yml`: published on `127.0.0.1:5433` (5432 was already
  taken by a local Windows PostgreSQL service).
- Credentials (lab only): user `hive`, password `hive`, database `hive`.
  Connection string: `postgresql://hive:hive@127.0.0.1:5433/hive`
  (also in `.env` as `TI_DB_DSN`; `.env` is gitignored, never commit it).

### Schema + migrations (`threat_intel/db/`)

5 goose-style migrations, applied by `py -3 -m threat_intel.db.migrate`
(state tracked in table `_migrations`, each file applied once, safe to re-run):

| Migration | Tables |
|---|---|
| `001_extensions.sql` | pgcrypto (uuid support) |
| `002_events.sql` | `events` — PK `event_id` UUID, `details` JSONB, indexes on timestamp / source_ip / session_id / (service, event_type) + GIN |
| `003_sessions_attackers.sql` | `sessions` (rollup per session), `attackers` (rollup per source IP) |
| `004_credentials.sql` | `credentials` (captured auth attempts) |
| `005_iocs_detections.sql` | `iocs` (`UNIQUE (type, value)`), `mitre_detections` (ready, filled in the detection-rules step) |

### Store layer (`threat_intel/store.py`)

- `Store` (psycopg 3): `insert_event` (dedup on `event_id` via
  `ON CONFLICT DO NOTHING`), `insert_events` (batch; side tables only updated
  for newly inserted events), `upsert_session_from_event`,
  `upsert_attacker` (additive `total_events`, services merged),
  `insert_credential`, `upsert_ioc` (`sight_count+1`, max confidence),
  plus read helpers (`count_events`, `count_by_service`, `recent_events`).
- `ingest_jsonl(store, path) -> IngestStats(read, inserted, duplicates, invalid)`:
  each JSONL line is validated with the shared pydantic `Event` model;
  invalid lines are counted and skipped, never crashing the batch.

### Tests (`tests/test_store.py`, 11 tests)

Migration state, insert/dedup, `source_port NULL` (HTTP), corrupted JSONL line,
re-ingest (all duplicates, count unchanged), real `data/events.jsonl`,
additive attacker upsert, session rollup, credential capture, IOC dedup.
Tests skip cleanly when Postgres is not reachable.

`python -m pytest` → **28 passed** (17 honeypot tests + 11 store tests).

### Verified end-to-end on real events

Ran the 3 scenarios (`ssh_scenario.py bruteforce|session`, `http_scan.py`,
`api_scan.py all`) against the honeypots, then ingested the resulting
`data/events.jsonl`:

    IngestStats(read=88, inserted=88, duplicates=0, invalid=0)
    by service: {'api': 40, 'http': 11, 'ssh': 37}
    attackers: 127.0.0.1 -> 88 events, services ['ssh', 'api', 'http']
    sessions: 11   credentials: 13

## Next steps

1. Detection rules engine (brute force T1110, web scan T1595.002,
   multi-service T1046, recon commands, download attempts T1105,
   honeytoken / exploit indicators) → fill `mitre_detections`.
2. MITRE ATT&CK catalog + session threat scoring.
3. IOC extraction from events + STIX 2.1 export (deterministic UUIDv5) +
   blocklists.
4. Intel API endpoints (heatmap, IOC list, exports) with the backend student.

## How to reproduce

    py -3 -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt
    docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d postgres
    py -3 -m threat_intel.db.migrate
    python -m pytest tests/test_store.py -v

Then start the honeypots, run the scenarios, and ingest:

    python -c "from pathlib import Path; from threat_intel.store import Store, ingest_jsonl; s = Store.from_env(); s.migrate(); print(ingest_jsonl(s, Path('data/events.jsonl')))"

## Notes for the team

- Event contract unchanged (`docs/event-schema.md`); any schema change must be
  agreed by all three members.
- `mitre_detections` and `iocs` tables exist but are still empty — they are
  filled by the upcoming detection/IOC steps.
- An observed IOC is an indicator with context, not proof of an attack.
