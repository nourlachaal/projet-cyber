# API honeypot

A fake internal REST API ("Acme Internal API") that looks like a real backend. It records how an attacker explores it: documentation discovery, login attempts, user enumeration, probing of sensitive routes and injection attempts.

Code: `honeypots/api_hp/server.py` | Tests: `tests/test_api_server.py` | Scenario: `scenarios/api_scan.py`

## Run it

```powershell
python -m honeypots.api_hp.server          # listens on 127.0.0.1:8081
python scenarios\api_scan.py all           # in a second terminal (venv active)
Get-Content data\events.jsonl -Tail 12
```

## Routes

| Route | Behaviour |
|---|---|
| `GET /`, `GET /api/v1/health` | banner and health answers |
| `GET /openapi.json`, `/swagger.json`, `/api/docs`, `/api/v1/docs` | fake API documentation, which also advertises a lure route (`/api/v1/internal/config`) |
| `POST /api/v1/auth/login`, `/api/v1/login`, `/api/v1/token` | login. Refused until attempt number `HP_API_ACCEPT_AFTER` (default 3, counted per source IP), then a fake token is returned |
| `GET /api/v1/users`, `GET /api/v1/users/{id}` | 401 without token, 403 with an unknown token, fake users (ids 1 to 5) with a token issued by the honeypot |
| trap routes: `/api/v1/admin`, `/api/v1/internal/*`, `/api/v1/debug`, `/api/v1/config`, `/api/v1/backup`, `/.env`, `/actuator`, `/graphql` | 401 or 403, flagged with `trap_hit` |
| anything else | 404 JSON |

The fake users use the reserved `.test` domain. All data is fictional.

## Events

Common fields are described in `docs/event-schema.md`. Here `service` is always `api`.

| event_type | When | Main fields in `details` |
|---|---|---|
| `api_request` | every request except logins | `method`, `path`, `user_agent`, `headers`, `body`, `content_type`, `auth_present`, `token_state`, `trap_hit`, `scanner_ua`, `indicators`, `response_status` |
| `api_auth_attempt` | every login request | same fields plus `username`, `password`, `attempt_no`, `success`, and `token_id` when a token was issued |
| `honeytoken_used` | a request carries a token issued by the honeypot | `path`, `method`, `token_issued_to_ip`, `token_username`, `reused_from_other_ip` |

- `token_state` is `none`, `unknown` (a token the honeypot never issued) or `honeytoken`.
- `indicators` lists labels raised by simple pattern matching on what was received: `sqli`, `path_traversal`, `cmd_injection`. These are hints for analysis, not proof of an attack.
- A request using a honeytoken produces both an `api_request` event and a `honeytoken_used` event. The second one is the high-confidence signal for threat intelligence rules.

## Settings (environment variables)

| Variable | Default | Role |
|---|---|---|
| `HP_API_HOST` | `127.0.0.1` | listen address. Use `0.0.0.0` only inside the Docker network |
| `HP_API_PORT` | `8081` | listen port |
| `HP_API_ACCEPT_AFTER` | `3` | login accepted at this attempt number (1 = always accept). The counter is per IP and is never reset, so once accepted an IP stays accepted until the server restarts |
| `HP_CAPTURE_PASSWORDS` | `true` | `true` in the isolated lab. `false` stores a short hash for passwords and for the `Authorization` header |
| `HP_LOG_PATH` | `data/events.jsonl` | event file |

## What it never does

- It never executes or interprets anything it receives. Payloads are only logged and matched against patterns.
- The fake token is random and signed with nothing: it cannot be valid anywhere else.
- Requests above 64 KB are refused with 413 and logged as `[too large]`. Only the first 4096 bytes of a body are stored.
- In-memory state (login counters, issued tokens) is capped at 10,000 entries.
- It sends nothing to other machines.

## Limits

- State is in memory: tokens and counters are lost when the server restarts.
- Responses are static, so a careful attacker can recognise a honeypot.
- Only JSON and form-encoded bodies are understood.
