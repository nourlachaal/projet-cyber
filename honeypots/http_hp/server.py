import hashlib
import os
from urllib.parse import parse_qs

from aiohttp import web

from honeypots.common import config
from honeypots.common.emitter import emit
from honeypots.common.events import Event
from honeypots.common.secrets import protect_secret

SCANNER_UA = ("sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirb", "wpscan", "zgrab")
TRAP_PATHS = (
    "/wp-login.php",
    "/wp-admin",
    "/phpmyadmin",
    "/admin",
    "/.env",
    "/.git/config",
    "/xmlrpc.php",
)
FAKE_HEADERS = {"Server": "Apache/2.4.52 (Ubuntu)"}

LOGIN_PAGE = """<html><head><title>Log In</title></head><body>
<form method="post" action="/wp-login.php">
<input name="log" placeholder="Username"><input name="pwd" type="password">
<button>Log In</button></form></body></html>"""

LOGIN_ERROR = "<html><body><p>ERROR: The password you entered is incorrect.</p></body></html>"


def make_session_id(ip: str, user_agent: str) -> str:
    return hashlib.sha256(f"{ip}|{user_agent}".encode()).hexdigest()[:12]


async def handler(request: web.Request) -> web.Response:
    ip = request.remote or "unknown"
    peer = request.transport.get_extra_info("peername") if request.transport else None
    source_port = peer[1] if peer else None
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

    emit(
        Event(
            service="http",
            event_type="http_request",
            source_ip=ip,
            source_port=source_port,
            session_id=make_session_id(ip, ua),
            details=details,
        )
    )

    if is_login_post:
        return web.Response(text=LOGIN_ERROR, content_type="text/html", headers=FAKE_HEADERS)
    if path.startswith("/wp-login.php"):
        return web.Response(text=LOGIN_PAGE, content_type="text/html", headers=FAKE_HEADERS)
    if path == "/robots.txt":
        return web.Response(
            text="User-agent: *\nDisallow: /wp-admin/\nDisallow: /phpmyadmin/\n",
            headers=FAKE_HEADERS,
        )
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
    web.run_app(
        create_app(), host=os.environ.get("HP_BIND_HOST", "127.0.0.1"), port=config.HTTP_PORT
    )
