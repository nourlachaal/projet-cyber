"""API honeypot: a fake internal REST API built with aiohttp.

Nothing received is ever executed or interpreted. Requests are only logged as events
and matched against simple patterns to raise indicators (SQL injection, path traversal,
command injection). The API also hands out a fake access token (a honeytoken): if that
token is replayed later, a dedicated `honeytoken_used` event is emitted.

Run:  python -m honeypots.api_hp.server
"""

import base64
import hashlib
import json
import os
import re
import time
from urllib.parse import parse_qs, unquote_plus
from uuid import uuid4

from aiohttp import web

from honeypots.common.emitter import emit
from honeypots.common.events import Event

# --------------------------------------------------------------------------- settings
API_HOST = os.getenv("HP_API_HOST", "127.0.0.1")  # use 0.0.0.0 only inside the Docker network
API_PORT = int(os.getenv("HP_API_PORT", "8081"))
ACCEPT_AFTER = int(os.getenv("HP_API_ACCEPT_AFTER", "3"))  # login accepted at this attempt
CAPTURE_PASSWORDS = os.getenv("HP_CAPTURE_PASSWORDS", "true").lower() == "true"

MAX_BODY = 4096  # bytes kept in an event
MAX_REQUEST = 64 * 1024  # larger requests are refused with 413
MAX_TRACKED = 10_000  # cap on in-memory state (attempts per IP, issued tokens)

SCANNER_UA = ("sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirb", "wpscan", "zgrab",
              "nuclei", "ffuf", "burp")
TRAP_PATHS = ("/api/v1/admin", "/api/v1/internal", "/api/v1/debug", "/api/v1/config",
              "/api/v1/backup", "/.env", "/actuator", "/graphql")
LOGIN_PATHS = ("/api/v1/auth/login", "/api/v1/login", "/api/v1/token")
DOC_PATHS = ("/openapi.json", "/swagger.json", "/api/docs", "/api/v1/docs")

FAKE_HEADERS = {"Server": "nginx/1.18.0 (Ubuntu)", "X-Powered-By": "Express"}

FAKE_USERS = [
    {"id": 1, "username": "admin", "email": "admin@corp.example.test", "role": "admin"},
    {"id": 2, "username": "jdoe", "email": "j.doe@corp.example.test", "role": "user"},
    {"id": 3, "username": "asmith", "email": "a.smith@corp.example.test", "role": "user"},
    {"id": 4, "username": "backup-svc", "email": "backup@corp.example.test", "role": "service"},
    {"id": 5, "username": "mwilson", "email": "m.wilson@corp.example.test", "role": "user"},
]

FAKE_OPENAPI = {
    "openapi": "3.0.1",
    "info": {"title": "Acme Internal API", "version": "1.4.2"},
    "paths": {
        "/api/v1/auth/login": {"post": {"summary": "Obtain an access token"}},
        "/api/v1/users": {"get": {"summary": "List users"}},
        "/api/v1/users/{id}": {"get": {"summary": "Get one user"}},
        "/api/v1/internal/config": {"get": {"summary": "Internal configuration"}},
    },
}

SETTINGS_KEY = web.AppKey("settings", dict)
TOKENS_KEY = web.AppKey("tokens", dict)
ATTEMPTS_KEY = web.AppKey("attempts", dict)

# --------------------------------------------------------------------------- patterns
# Detection only: these patterns label what an attacker SENT. Nothing is executed.
PATTERNS = {
    "sqli": re.compile(
        r"('|%27)\s*(or|and)\s|union\s+select|sleep\s*\(|--\s|;\s*drop\s", re.IGNORECASE
    ),
    "path_traversal": re.compile(r"\.\./|\.\.\\|%2e%2e", re.IGNORECASE),
    "cmd_injection": re.compile(
        r"(;|\|\||&&|\$\()\s*(cat|ls|id|whoami|wget|curl|touch|rm|nc|bash|sh|powershell|cmd)\b",
        re.IGNORECASE,
    ),
}


def find_indicators(text: str) -> list[str]:
    """Label suspicious patterns, looking at the raw text and its URL-decoded form."""
    candidates = (text, unquote_plus(text))
    return [name for name, pattern in PATTERNS.items()
            if any(pattern.search(c) for c in candidates)]


# --------------------------------------------------------------------------- helpers
def protect_secret(value: str, capture: bool) -> str:
    """Clear text in the isolated lab, short hash otherwise."""
    if capture:
        return value
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:16]


def make_session_id(ip: str, user_agent: str) -> str:
    return hashlib.sha256(f"{ip}|{user_agent}".encode()).hexdigest()[:12]


def _b64(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_honeytoken(username: str) -> str:
    """A fake JWT-looking token. The signature is random: it can never be valid anywhere."""
    header = _b64({"alg": "HS256", "typ": "JWT"})
    payload = _b64({"sub": username or "admin", "role": "admin", "iat": int(time.time()),
                    "jti": uuid4().hex[:12]})
    signature = base64.urlsafe_b64encode(os.urandom(24)).rstrip(b"=").decode()
    return f"{header}.{payload}.{signature}"


def bearer_token(request: web.Request) -> str | None:
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip() or None
    return None


def parse_body(text: str) -> dict:
    """Accept JSON or form-encoded bodies. Never raises."""
    if not text:
        return {}
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except ValueError:
        pass
    return {k: v[0] for k, v in parse_qs(text).items() if v}


def safe_headers(request: web.Request, capture: bool) -> dict:
    headers = dict(request.headers)
    if not capture and "Authorization" in headers:
        headers["Authorization"] = protect_secret(headers["Authorization"], False)
    return headers


def json_response(status: int, payload: dict) -> web.Response:
    return web.json_response(payload, status=status, headers=FAKE_HEADERS)


# --------------------------------------------------------------------------- handler
async def handle(request: web.Request) -> web.Response:
    settings = request.app[SETTINGS_KEY]
    capture = settings["capture_passwords"]
    tokens: dict = request.app[TOKENS_KEY]
    attempts: dict = request.app[ATTEMPTS_KEY]

    ip = request.remote or "unknown"
    peer = request.transport.get_extra_info("peername") if request.transport else None
    port = peer[1] if peer and len(peer) > 1 else None
    ua = request.headers.get("User-Agent", "")
    session_id = make_session_id(ip, ua)
    method = request.method
    path = request.path.rstrip("/") or "/"

    too_large = False
    try:
        raw = await request.read()
    except web.HTTPRequestEntityTooLarge:
        raw, too_large = b"", True
    body = "[too large]" if too_large else raw[:MAX_BODY].decode("utf-8", errors="replace")

    token = bearer_token(request)
    if token is None:
        token_state = "none"
    elif token in tokens:
        token_state = "honeytoken"
    else:
        token_state = "unknown"

    trap_hit = path.startswith(TRAP_PATHS)
    indicators = find_indicators(f"{request.path_qs} {request.raw_path} {body}")
    data = parse_body(body)
    is_login = method == "POST" and path in LOGIN_PATHS

    # ---- decide the (fake) answer
    extra: dict = {}
    event_type = "api_request"
    if too_large:
        status, payload = 413, {"error": "payload too large"}
    elif is_login:
        event_type = "api_auth_attempt"
        username = str(data.get("username") or data.get("user") or data.get("email") or "")[:128]
        password = str(data.get("password") or data.get("pass") or "")[:256]
        if len(attempts) > MAX_TRACKED:
            attempts.clear()
        attempts[ip] = attempts.get(ip, 0) + 1
        success = attempts[ip] >= settings["accept_after"]
        extra = {"username": username, "password": protect_secret(password, capture),
                 "attempt_no": attempts[ip], "success": success}
        if success:
            if len(tokens) > MAX_TRACKED:
                tokens.clear()
            new_token = make_honeytoken(username)
            tokens[new_token] = {"ip": ip, "username": username, "issued": time.time()}
            extra["token_id"] = hashlib.sha256(new_token.encode()).hexdigest()[:12]
            status = 200
            payload = {"access_token": new_token, "token_type": "bearer", "expires_in": 3600}
        else:
            status, payload = 401, {"error": "invalid credentials"}
        body = "[login payload, see username/password fields]"
    elif path in LOGIN_PATHS:
        status, payload = 405, {"error": "method not allowed"}
    elif path == "/" and method == "GET":
        status, payload = 200, {"service": "acme-internal-api", "version": "1.4.2",
                                "docs": "/api/v1/docs"}
    elif path == "/api/v1/health" and method == "GET":
        status, payload = 200, {"status": "ok"}
    elif path in DOC_PATHS and method == "GET":
        status, payload = 200, FAKE_OPENAPI
    elif path == "/api/v1/users" and method == "GET":
        if token_state == "none":
            status, payload = 401, {"error": "missing token"}
        elif token_state == "unknown":
            status, payload = 403, {"error": "invalid token"}
        else:
            status, payload = 200, {"users": FAKE_USERS}
    elif re.fullmatch(r"/api/v1/users/\d+", path) and method == "GET":
        user_id = int(path.rsplit("/", 1)[1])
        if token_state == "none":
            status, payload = 401, {"error": "missing token"}
        elif token_state == "unknown":
            status, payload = 403, {"error": "invalid token"}
        else:
            user = next((u for u in FAKE_USERS if u["id"] == user_id), None)
            status, payload = (200, user) if user else (404, {"error": "user not found"})
    elif trap_hit:
        if token_state == "none":
            status, payload = 401, {"error": "authentication required"}
        elif token_state == "unknown":
            status, payload = 403, {"error": "invalid token"}
        else:
            status, payload = 403, {"error": "insufficient privileges"}
    else:
        status, payload = 404, {"error": "not found"}

    # ---- log what happened
    details = {
        "method": method,
        "path": request.path_qs,
        "user_agent": ua,
        "headers": safe_headers(request, capture),
        "body": body,
        "content_type": request.headers.get("Content-Type", ""),
        "auth_present": token is not None,
        "token_state": token_state,
        "trap_hit": trap_hit,
        "scanner_ua": any(s in ua.lower() for s in SCANNER_UA),
        "indicators": indicators,
        "response_status": status,
        **extra,
    }
    if token_state == "honeytoken":
        details["token_reused_from_other_ip"] = tokens[token]["ip"] != ip

    emit(Event(service="api", event_type=event_type, source_ip=ip, source_port=port,
               session_id=session_id, details=details))

    if token_state == "honeytoken":
        emit(Event(service="api", event_type="honeytoken_used", source_ip=ip, source_port=port,
                   session_id=session_id,
                   details={"path": request.path_qs, "method": method,
                            "token_issued_to_ip": tokens[token]["ip"],
                            "token_username": tokens[token]["username"],
                            "reused_from_other_ip": tokens[token]["ip"] != ip}))

    return json_response(status, payload)


def create_app(accept_after: int | None = None,
               capture_passwords: bool | None = None) -> web.Application:
    app = web.Application(client_max_size=MAX_REQUEST)
    app[SETTINGS_KEY] = {
        "accept_after": ACCEPT_AFTER if accept_after is None else accept_after,
        "capture_passwords": CAPTURE_PASSWORDS if capture_passwords is None else capture_passwords,
    }
    app[TOKENS_KEY] = {}
    app[ATTEMPTS_KEY] = {}
    app.router.add_route("*", "/{tail:.*}", handle)
    return app


def main() -> None:
    web.run_app(create_app(), host=API_HOST, port=API_PORT)


if __name__ == "__main__":
    main()
