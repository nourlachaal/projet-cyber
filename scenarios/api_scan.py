"""Simulate attackers against YOUR OWN local API honeypot (lab use only).

Usage:
    python scenarios/api_scan.py [scan|bruteforce|session|all] [base_url]

    scan        recon: root, docs, trap paths, with a scanner-like user-agent
    bruteforce  repeated logins with common passwords
    session     login until accepted, then use the token to enumerate users and probe
    all         the three above, one after the other

Default base URL: http://127.0.0.1:8081
Never run this against a system you do not own.
"""

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

MODES = ("scan", "bruteforce", "session", "all")
mode = sys.argv[1] if len(sys.argv) > 1 else "all"
BASE = (sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:8081").rstrip("/")

if mode not in MODES:
    sys.exit(f"unknown mode '{mode}', choose one of: {', '.join(MODES)}")

DELAY = 0.3  # seconds between requests, to keep sessions readable


def call(method, path, body=None, token=None, user_agent="python-requests/2.31 (lab-scenario)"):
    headers = {"User-Agent": user_agent}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            status, text = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        status, text = err.code, err.read().decode("utf-8", "replace")
    except OSError as err:
        sys.exit(f"cannot reach {BASE}: {err}. Is the API honeypot running?")
    print(f"{method:5} {path:45} -> {status}")
    time.sleep(DELAY)
    try:
        return status, json.loads(text)
    except ValueError:
        return status, {}


def scan():
    print("\n== scan: reconnaissance with a scanner user-agent ==")
    for path in ["/", "/api/v1/health", "/openapi.json", "/api/v1/docs", "/api/v1/users",
                 "/api/v1/admin", "/api/v1/internal/config", "/api/v1/debug", "/.env",
                 "/actuator", "/graphql", "/api/v2/users"]:
        call("GET", path, user_agent="sqlmap/1.7 (lab-scenario)")


def bruteforce():
    print("\n== bruteforce: repeated logins ==")
    for password in ["admin", "123456", "password", "admin123", "letmein"]:
        status, body = call("POST", "/api/v1/auth/login",
                            {"username": "admin", "password": password})
        if status == 200:
            print("   login accepted, token received:", body.get("access_token", "")[:25], "...")
            break


def session():
    print("\n== session: login, then use the token ==")
    token = None
    for attempt in range(1, 8):
        status, body = call("POST", "/api/v1/auth/login",
                            {"username": "svc-backup", "password": f"Winter2026!{attempt}"})
        if status == 200:
            token = body["access_token"]
            break
    if not token:
        print("   no token received")
        return
    call("GET", "/api/v1/users", token=token)
    for user_id in range(1, 9):  # enumeration of user ids
        call("GET", f"/api/v1/users/{user_id}", token=token)
    call("GET", "/api/v1/internal/config", token=token)
    injection = urllib.parse.quote("1' OR '1'='1")
    call("GET", f"/api/v1/users?id={injection}", token=token)
    call("GET", "/api/v1/users?file=" + urllib.parse.quote("../../etc/passwd"), token=token)


if mode in ("scan", "all"):
    scan()
if mode in ("bruteforce", "all"):
    bruteforce()
if mode in ("session", "all"):
    session()
print("\ndone. Look at data/events.jsonl")
