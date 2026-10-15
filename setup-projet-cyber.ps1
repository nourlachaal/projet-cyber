# setup-projet-cyber.ps1
# Run this script INSIDE an empty folder named projet-cyber.
# It creates the repository structure, the shared event model,
# an HTTP honeypot v1, a scenario script, tests, Docker files and VS Code settings.
# It never overwrites an existing file.

$root = (Get-Location).Path
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Write-File([string]$Path, [string]$Content) {
    $full = Join-Path $root $Path
    if (Test-Path $full) { Write-Host "  skip    $Path (already exists)"; return }
    $dir = Split-Path $full -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    [System.IO.File]::WriteAllText($full, $Content, $utf8)
    Write-Host "  created $Path"
}

Write-Host "Creating project structure in $root"

# ---------------------------------------------------------------- repo basics
Write-File ".gitignore" @'
# Python
__pycache__/
*.pyc
.venv/
.pytest_cache/
.ruff_cache/

# Secrets and local config
.env
*.key
ssh_host_key
ssh_host_key.pub

# Runtime data (logs, captured events)
data/*
!data/.gitkeep

# Editors / OS
.idea/
Thumbs.db
'@

Write-File ".gitattributes" @'
* text=auto
*.ps1 text eol=crlf
'@

Write-File ".env.example" @'
# Copy to .env (never commit .env)
HP_LOG_PATH=data/events.jsonl
HP_HTTP_PORT=8080
HP_SSH_PORT=2222
# true in the isolated lab; set to false if a honeypot is ever exposed (stores a hash instead)
HP_CAPTURE_PASSWORDS=true
'@

Write-File "requirements.txt" @'
asyncssh
aiohttp
pydantic>=2
pytest
ruff
'@

Write-File "pyproject.toml" @'
[tool.pytest.ini_options]
pythonpath = ["."]
testpaths = ["tests"]

[tool.ruff]
line-length = 100
'@

Write-File "README.md" @'
# projet-cyber

Adaptive honeypot and threat intelligence platform (university project, team of 3).

## Structure

- honeypots/   decoy services (SSH, HTTP, API ...) and the shared event model
- scenarios/   reproducible attack-simulation scripts (lab use only)
- backend/     event processing and API
- threat_intel/ detection rules, MITRE ATT&CK mapping, IOCs
- docs/        event schema, security model, honeypot notes

## Quick start (Windows, PowerShell)

    py -3 -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt
    python -m pytest
    python -m honeypots.http_hp.server

## Safety

Honeypots run only in a local or isolated lab network. Never expose them to the Internet.
Commands received by the fake services are never executed.

## References

Inspiration only (no code reused): public honeypot projects such as Cowrie and open-source honeypot platforms.
'@

Write-File ".github/pull_request_template.md" @'
## What does this PR do?

## How was it tested?
- [ ] pytest passes
- [ ] ran the service locally and checked the generated events

## Security checklist
- [ ] no secrets, keys or real credentials committed
- [ ] no received command or file is executed
- [ ] event format still matches docs/event-schema.md
'@

# ---------------------------------------------------------------- docs
Write-File "docs/event-schema.md" @'
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
'@

Write-File "docs/security-model.md" @'
# Security model of the honeypots

- Decoys never execute received commands and never serve real files.
- Honeypot containers run on an internal Docker network with no Internet access.
- Ports are published only on 127.0.0.1, and only with docker-compose.dev.yml.
- No real credentials, keys or personal data in the repository.
- Captured passwords: stored in clear only in the isolated lab (HP_CAPTURE_PASSWORDS=true),
  otherwise only a short hash.
- Isolation checks done so far: (to fill in)
'@

Write-File "docs/honeypots.md" @'
# Honeypot notes

For each service: what it simulates, which events it emits, what it never does.

## HTTP
- catch-all handler, trap paths (/wp-login.php, /phpmyadmin, /.env ...)
- event_type: http_request (details.trap_hit tells if a trap path was requested)

## SSH
- to do

## API
- to do
'@

# ---------------------------------------------------------------- honeypot code
Write-File "honeypots/__init__.py" ""
Write-File "honeypots/common/__init__.py" ""
Write-File "honeypots/ssh_hp/__init__.py" ""
Write-File "honeypots/api_hp/__init__.py" ""
Write-File "honeypots/http_hp/__init__.py" ""

Write-File "honeypots/common/config.py" @'
import os
from pathlib import Path

LOG_PATH = Path(os.getenv("HP_LOG_PATH", "data/events.jsonl"))
HTTP_PORT = int(os.getenv("HP_HTTP_PORT", "8080"))
SSH_PORT = int(os.getenv("HP_SSH_PORT", "2222"))

# True only in the isolated lab. If a honeypot is ever exposed, set to false:
# secrets are then stored as a short hash instead of in clear text.
CAPTURE_PASSWORDS = os.getenv("HP_CAPTURE_PASSWORDS", "true").lower() == "true"
'@

Write-File "honeypots/common/events.py" @'
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class Event(BaseModel):
    """Canonical event shared by all honeypots. See docs/event-schema.md."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    service: Literal["ssh", "http", "api", "ftp", "redis", "mysql", "smb"]
    event_type: str
    source_ip: str
    source_port: int | None = None
    session_id: str
    details: dict[str, Any] = Field(default_factory=dict)
'@

Write-File "honeypots/common/emitter.py" @'
from .config import LOG_PATH
from .events import Event


def emit(event: Event) -> None:
    """Append one event as a JSON line. Simple and enough for a lab-sized volume."""
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(event.model_dump_json() + "\n")
'@

Write-File "honeypots/http_hp/server.py" @'
import hashlib
from urllib.parse import parse_qs

from aiohttp import web

from honeypots.common import config
from honeypots.common.emitter import emit
from honeypots.common.events import Event

SCANNER_UA = ("sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirb", "wpscan", "zgrab")
TRAP_PATHS = ("/wp-login.php", "/wp-admin", "/phpmyadmin", "/admin", "/.env",
              "/.git/config", "/xmlrpc.php")
FAKE_HEADERS = {"Server": "Apache/2.4.52 (Ubuntu)"}

LOGIN_PAGE = """<html><head><title>Log In</title></head><body>
<form method="post" action="/wp-login.php">
<input name="log" placeholder="Username"><input name="pwd" type="password">
<button>Log In</button></form></body></html>"""

LOGIN_ERROR = "<html><body><p>ERROR: The password you entered is incorrect.</p></body></html>"


def protect_secret(value: str) -> str:
    """Clear text in the isolated lab, short hash otherwise."""
    if config.CAPTURE_PASSWORDS:
        return value
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:16]


def make_session_id(ip: str, user_agent: str) -> str:
    return hashlib.sha256(f"{ip}|{user_agent}".encode()).hexdigest()[:12]


async def handler(request: web.Request) -> web.Response:
    ip = request.remote or "unknown"
    ua = request.headers.get("User-Agent", "")
    raw_body = (await request.read())[:4096].decode("utf-8", errors="replace")
    path = request.path
    trap_hit = path.startswith(TRAP_PATHS)

    details = {
        "method": request.method,
        "path": request.path_qs,
        "user_agent": ua,
        "headers": dict(request.headers),
        "body": raw_body,
        "trap_hit": trap_hit,
        "scanner_ua": any(s in ua.lower() for s in SCANNER_UA),
    }

    is_login_post = request.method == "POST" and path.startswith("/wp-login.php")
    if is_login_post:
        form = parse_qs(raw_body)
        details["username"] = form.get("log", [""])[0]
        details["password"] = protect_secret(form.get("pwd", [""])[0])
        details["body"] = "[login form, see username/password fields]"

    emit(Event(service="http", event_type="http_request", source_ip=ip,
               session_id=make_session_id(ip, ua), details=details))

    if is_login_post:
        return web.Response(text=LOGIN_ERROR, content_type="text/html", headers=FAKE_HEADERS)
    if path.startswith("/wp-login.php"):
        return web.Response(text=LOGIN_PAGE, content_type="text/html", headers=FAKE_HEADERS)
    if path == "/robots.txt":
        return web.Response(text="User-agent: *\nDisallow: /wp-admin/\nDisallow: /phpmyadmin/\n",
                            headers=FAKE_HEADERS)
    if path.startswith(("/admin", "/phpmyadmin", "/wp-admin")):
        return web.Response(status=401, text="Unauthorized", headers=FAKE_HEADERS)
    if path.startswith(("/.env", "/.git")):
        return web.Response(status=403, text="Forbidden", headers=FAKE_HEADERS)
    return web.Response(status=404, text="Not Found", headers=FAKE_HEADERS)


def create_app() -> web.Application:
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=config.HTTP_PORT)
'@

Write-File "scripts/gen_host_key.py" @'
"""Generate the SSH host key used by the SSH honeypot (data/ssh_host_key, ignored by Git)."""
from pathlib import Path

import asyncssh

Path("data").mkdir(exist_ok=True)
key = asyncssh.generate_private_key("ssh-ed25519")
key.write_private_key("data/ssh_host_key")
print("Host key written to data/ssh_host_key")
'@

# ---------------------------------------------------------------- scenarios and tests
Write-File "scenarios/README.md" @'
# Scenarios (lab use only)

Replayable scripts that generate known behaviour against YOUR OWN lab honeypots.
Never run them against systems you do not own.

- http_scan.py : requests many paths with a scanner-like user-agent
'@

Write-File "scenarios/http_scan.py" @'
"""Simulate a web scan against the local HTTP honeypot (lab use only)."""
import sys
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
PATHS = ["/", "/robots.txt", "/wp-login.php", "/wp-admin/", "/phpmyadmin/", "/admin",
         "/.env", "/.git/config", "/xmlrpc.php", "/backup.zip", "/api/v1/users"]

for p in PATHS:
    req = urllib.request.Request(BASE + p, headers={"User-Agent": "sqlmap/1.7 (lab-scenario)"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            print(p, r.status)
    except urllib.error.HTTPError as e:
        print(p, e.code)
    except Exception as e:
        print(p, "error:", e)
'@

Write-File "tests/test_events.py" @'
from honeypots.common.events import Event


def test_event_defaults():
    e = Event(service="http", event_type="http_request", source_ip="192.0.2.10", session_id="s1")
    assert e.event_id
    assert e.timestamp.tzinfo is not None
    assert e.model_dump()["service"] == "http"
'@

# ---------------------------------------------------------------- docker
Write-File "Dockerfile" @'
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY honeypots ./honeypots
ENV PYTHONUNBUFFERED=1
CMD ["python", "-m", "honeypots.http_hp.server"]
'@

Write-File "docker-compose.yml" @'
# Base file: honeypots on an INTERNAL network (no Internet access, no published ports).
services:
  http-hp:
    build: .
    command: python -m honeypots.http_hp.server
    environment:
      HP_LOG_PATH: /app/data/events.jsonl
    volumes:
      - ./data:/app/data
    networks: [lab]

networks:
  lab:
    internal: true
'@

Write-File "docker-compose.dev.yml" @'
# Dev override: lets you test from Windows. Ports bound to 127.0.0.1 only.
# Usage: docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
services:
  http-hp:
    ports:
      - "127.0.0.1:8080:8080"

networks:
  lab:
    internal: false
'@

# ---------------------------------------------------------------- VS Code
Write-File ".vscode/settings.json" @'
{
  "python.defaultInterpreterPath": "${workspaceFolder}/.venv/Scripts/python.exe",
  "python.testing.pytestEnabled": true,
  "python.testing.pytestArgs": ["tests"],
  "[python]": {
    "editor.defaultFormatter": "charliermarsh.ruff",
    "editor.formatOnSave": true
  },
  "files.eol": "\n"
}
'@

Write-File ".vscode/extensions.json" @'
{
  "recommendations": [
    "ms-python.python",
    "ms-python.vscode-pylance",
    "charliermarsh.ruff",
    "ms-azuretools.vscode-docker",
    "eamodio.gitlens"
  ]
}
'@

# ---------------------------------------------------------------- placeholders for teammates
Write-File "data/.gitkeep" ""
Write-File "backend/.gitkeep" ""
Write-File "threat_intel/.gitkeep" ""

Write-Host ""
Write-Host "Done. Next steps:"
Write-Host "  1. py -3 -m venv .venv"
Write-Host "  2. .\.venv\Scripts\Activate.ps1"
Write-Host "  3. pip install -r requirements.txt"
Write-Host "  4. python -m pytest"
Write-Host "  5. python -m honeypots.http_hp.server"