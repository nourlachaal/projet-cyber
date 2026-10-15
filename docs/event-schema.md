# Event schema (contract between honeypots, backend and threat intel)

One JSON object per line in data/events.jsonl.

| field | type | description |
|---|---|---|
| event_id | string (uuid) | unique id |
| timestamp | string (ISO-8601, UTC) | when the event happened |
| service | ssh / http / api / ftp / redis / mysql / smb | which decoy produced it |
| event_type | string | connect, auth_attempt, command, http_request, disconnect ... |
| source_ip | string | client address |
| source_port | int or null | client port |
| session_id | string | groups events of one session |
| details | object | service-specific data |

Example:

    {"event_id": "...", "timestamp": "2026-10-15T18:30:00Z", "service": "http",
     "event_type": "http_request", "source_ip": "192.0.2.10", "source_port": null,
     "session_id": "a1b2c3", "details": {"method": "GET", "path": "/wp-login.php"}}

Any change to this schema must be agreed by all three team members.