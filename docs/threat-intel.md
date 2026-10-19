# Threat Intelligence (Student 3 — Data)

Scope of the database and threat-intelligence pole: persistence, deterministic
detection rules, MITRE ATT&CK mapping, IOC extraction and intel exports.
No machine learning: every signal is a deterministic rule with a documented threshold.

## Responsibilities

- PostgreSQL schema, migrations and the `Store` layer (`threat_intel/`)
- Detection rules (single-event + sliding-window per source IP)
- MITRE ATT&CK catalog and detection mapping
- IOC extraction, deduplication and confidence scoring
- STIX 2.1 bundle export and firewall blocklists
- Intel API endpoints (heatmap, IOC list, exports, alerts)

Not in scope here: honeypot services (Student 1) and the event bus/API of the
backend (Student 2). This pole consumes the shared event contract
(`docs/event-schema.md`) and produces tables, alerts and exports.

## Interface with the backend

Events arrive as validated `honeypots.common.events.Event` objects (pydantic).
The ingestion entry point is:

- `threat_intel.store.ingest_jsonl(store, path) -> IngestStats`
  - reads one JSON object per line (same contract as `data/events.jsonl`)
  - validates each line with the shared `Event` model; invalid lines are counted, never crash the batch
  - `insert_event` (dedup on `event_id`), `upsert_session_from_event`, `upsert_attacker`
  - returns `IngestStats(read, inserted, duplicates, invalid)`

Until the backend exposes a collector (HTTP or Redis — see
`feature/backend-redis-api`), the JSONL file is the transport. The same
`insert_event` / `upsert_*` methods will be called by the backend pipeline
later; nothing else in this pole depends on how events arrive.

Configuration: `TI_DB_DSN` (e.g. `postgresql://hive:hive@127.0.0.1:5432/hive`).
Postgres runs in `docker-compose.yml` (service `postgres`, network `lab`,
no published ports in the base file; `127.0.0.1:5432` in the dev override only).

## Database schema

Migrations live in `threat_intel/db/migrations/` (goose-style `-- +goose Up/Down`),
applied by `py -3 -m threat_intel.db.migrate`.

| Table | Purpose | Dedup / key |
|---|---|---|
| `events` | every captured interaction (`details` as JSONB) | PK `event_id` (UUID), `ON CONFLICT DO NOTHING` |
| `sessions` | rollup per `session_id` (first/last seen, counts, login) | PK `session_id` |
| `attackers` | rollup per source IP (first/last seen, event count, services) | PK `ip`, additive upsert |
| `credentials` | captured auth attempts (SSH / API honeypots) | serial id, index on `(source_ip, timestamp)` |
| `iocs` | extracted indicators with confidence and provenance | `UNIQUE (type, value)`, `sight_count+1`, max confidence |
| `mitre_detections` | one row per technique triggered (evidence kept) | serial id, index on `(technique_id, detected_at)` |

Indexes: `events(timestamp DESC)`, `events(source_ip)`, `events(session_id)`,
`events(service, event_type)`, GIN on `events(details)`.

Notes on the real event stream:

- `timestamp` is UTC; JSONL uses the `Z` suffix — `TIMESTAMPTZ` accepts both `Z` and `+00:00`
- `source_port` is `null` for HTTP events (column is nullable)
- `event_type` stays `TEXT` (the contract does not close the set; a new event type must not require a migration)

## Detection rules (deterministic)

State is kept per source IP in memory (sliding windows) plus persisted alerts in
`mitre_detections`. Thresholds are justified in `docs/progress-honeypot.md`
(behaviours available for detection).

| Rule | Trigger | Window | Technique |
|---|---|---|---|
| Brute force | ≥ 5 `auth_attempt` with `success=false` | 5 min / IP | T1110 (Credential Access) |
| Web scanning | ≥ 10 distinct paths, or `scanner_ua=true`, or `trap_hit=true` | 60 s / IP | T1595.002 (Reconnaissance) |
| Multi-service probing | ≥ 3 distinct `service` values connecting | 60 s / IP | T1046 (Discovery) |
| Recon commands | `command` matching `whoami`, `id`, `uname`, `cat /etc/passwd`, `ps`, `ls`… | single event | T1082 / T1083 (Discovery) |
| Tool download | `file_download_attempt` (wget/curl, URL captured) | single event | T1105 (Command and Control) |
| Exploit indicators | `details.indicators` contains `sqli`, `path_traversal` or `cmd_injection` | single event | T1190 (Initial Access) |
| Honeytoken use | `event_type=honeytoken_used` (high-confidence signal per `docs/api-honeypot.md`) | single event | T1078 (Initial Access) |
| Valid account abuse | login accepted, or honeytoken reused from another IP (`reused_from_other_ip`) | single event | T1078 |

Each rule must be documented with: technique id, threshold, window, and which
event fields it reads. Alerts store the triggering evidence (event id / command /
path), not just the technique id.

## MITRE ATT&CK

- Catalog in `threat_intel/mitre.py`: technique id, name, tactic
- Every detection is written to `mitre_detections` with `evidence`, `confidence`, `source_ip`, `session_id`
- `sessions.mitre_techniques` + `sessions.threat_score` updated per session (+15 per unique technique)
- Heatmap query: `GROUP BY technique_id, tactic ORDER BY count DESC`

## IOC extraction

Extracted from events, never invented:

- `ipv4` / `ipv6` — source IPs of connections (public addresses only in the final view; lab loopbacks kept but tagged)
- `url` / `domain` — from `details.url` (wget/curl) and URLs found in commands or HTTP paths
- `user-agent` — only when the UA matches a known scanner/attack tool
- `credential` — observed username/password pairs (lab-only, see `docs/security-model.md`)

Confidence per triggering event type (starting point, tunable): exploit 95,
command 85, auth 80, scan 70, connect 50. Deduplication: `UNIQUE (type, value)`,
`sight_count += 1`, `first_seen`/`last_seen` widened, confidence = max seen,
tags merged.

**Principle of vigilance:** an observed IOC is an indicator with context
(first seen, service, confidence, provenance), not proof of an attack. Exports
must keep that context; a low-confidence user-agent is not a malicious IP.

## Exports

- `threat_intel/stix.py` — STIX 2.1 bundle: one identity (`projet-cyber`) + one indicator per IOC, deterministic UUIDv5 ids (idempotent re-import in OpenCTI/MISP)
- `threat_intel/blocklist.py` — IP-only blocklists, min-confidence filter, formats: `plain`, `iptables`, `nginx`, `csv`

## API endpoints (planned)

| Endpoint | Purpose |
|---|---|
| `GET /api/mitre/heatmap` | technique counts per tactic |
| `GET /api/iocs` | paginated IOC list (filters: type, min confidence) |
| `GET /api/iocs/export/stix` | STIX 2.1 bundle download |
| `GET /api/iocs/export/blocklist?format=` | blocklist download |
| `GET /api/alerts` | recent MITRE detections |

To be mounted with the backend (Student 2) or as a small standalone module first.

## Testing

- Unit tests for rules: synthetic events per rule, including window expiry
- Ingestion tests against the real JSONL produced by `scenarios/` (expected counts per service)
- IOC dedup, blocklist formats, STIX bundle structure
- Tests requiring Postgres use `TI_DB_DSN` and skip cleanly when the DB is not reachable
- Golden path: run the 3 scenarios → ingest → assert T1110 / T1595.002 / T1105 detections and IOC exports

## Status

- [x] Event contract understood (88 real events captured from the 3 scenarios)
- [ ] Postgres service + migrations + `store.py` (branch `feature/data-store`)
- [ ] Detection rules engine
- [ ] MITRE catalog + detections
- [ ] IOC extraction + STIX + blocklists
- [ ] Intel endpoints + integration tests
