"""SSH honeypot: accepts logins (after N attempts), exposes a FAKE shell, logs everything.

Safety: received commands are never executed (see shell.py). Port forwarding, SFTP, SCP,
agent/X11 forwarding are not implemented, so asyncssh refuses them. The server makes no
outbound connection.
"""
import asyncio
import time
from pathlib import Path
from uuid import uuid4

import asyncssh

from honeypots.common import config
from honeypots.common.emitter import emit
from honeypots.common.events import Event
from honeypots.common.secrets import protect_secret

from .shell import FakeShell

BANNER = ("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n\n"
          "Last login: Mon Nov 13 09:12:44 2023 from 10.0.2.2\n")
SERVER_VERSION = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
# Password attempts per source IP (across connections, so one-attempt-per-connection tools
# such as hydra are counted too). Reset to 0 when a login is accepted.
AUTH_COUNTS: dict[str, int] = {}
# Input errors that must not kill the fake session
IGNORED = (asyncssh.TerminalSizeChanged, asyncssh.BreakReceived, asyncssh.SignalReceived)


class HoneypotSSHServer(asyncssh.SSHServer):
    """One instance per TCP connection."""

    def __init__(self) -> None:
        self.session_id = uuid4().hex[:12]
        self.ip = "unknown"
        self.port: int | None = None
        self.username = ""
        self.started = time.monotonic()
        self._conn: asyncssh.SSHServerConnection | None = None

    # ------------------------------------------------------------- helpers
    def _emit(self, event_type: str, **details) -> None:
        emit(Event(service="ssh", event_type=event_type, source_ip=self.ip,
                   source_port=self.port, session_id=self.session_id, details=details))

    # ------------------------------------------------------------- connection
    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn
        peer = conn.get_extra_info("peername") or ("unknown", None)
        self.ip, self.port = str(peer[0]), peer[1]
        self._emit("connect")

    def connection_lost(self, exc: Exception | None) -> None:
        self._emit("disconnect", duration_s=round(time.monotonic() - self.started, 2),
                   error=str(exc) if exc else None)

    # ------------------------------------------------------------- authentication
    def begin_auth(self, username: str) -> bool:
        self.username = username
        return True  # authentication required

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        if len(AUTH_COUNTS) > 10_000:  # bound memory
            AUTH_COUNTS.clear()
        attempt_no = AUTH_COUNTS.get(self.ip, 0) + 1
        ok = attempt_no >= config.SSH_ACCEPT_AFTER
        AUTH_COUNTS[self.ip] = 0 if ok else attempt_no
        client = self._conn.get_extra_info("client_version") if self._conn else None
        self._emit("auth_attempt", username=username[:64], password=protect_secret(password[:128]),
                   success=ok, attempt_no=attempt_no, client_version=client)
        return ok

    # ------------------------------------------------------------- session
    def session_requested(self):
        return self._session

    async def _session(self, stdin: asyncssh.SSHReader, stdout: asyncssh.SSHWriter,
                       stderr: asyncssh.SSHWriter) -> None:
        """asyncssh calls this with the three channel streams of the session."""
        try:
            await asyncio.wait_for(self._interact(stdin, stdout), config.SSH_MAX_SESSION)
        except TimeoutError:
            stdout.write("\nConnection timed out.\n")
        except (asyncssh.Error, ConnectionError, OSError):
            pass
        finally:
            stdout.channel.exit(0)

    def _handle_line(self, stdout: asyncssh.SSHWriter, shell: FakeShell, line: str,
                     mode: str) -> bool:
        """Log + answer one line. Returns True when the session should end."""
        line = line.strip()[: config.SSH_MAX_CMD_LEN]
        if not line:
            return False
        self._emit("command", command=line, cwd=shell.cwd, mode=mode)
        result = shell.run(line)
        for d in result.downloads:
            self._emit("file_download_attempt", tool=d["tool"], url=d["url"], command=line)
        if result.output:
            stdout.write(result.output)
        return result.exit

    async def _interact(self, stdin: asyncssh.SSHReader, stdout: asyncssh.SSHWriter) -> None:
        shell = FakeShell(self.username)
        command = stdout.channel.get_command()
        if command is not None:  # ssh host "command"
            self._handle_line(stdout, shell, command, "exec")
            return
        stdout.write(BANNER)
        for _ in range(config.SSH_MAX_COMMANDS):
            stdout.write(shell.prompt())
            try:
                line = await asyncio.wait_for(stdin.readline(), config.SSH_IDLE_TIMEOUT)
            except TimeoutError:
                return
            except IGNORED:
                continue
            if not line:  # client closed its input
                return
            if self._handle_line(stdout, shell, line, "shell"):
                return


def ensure_host_key(path: Path) -> Path:
    """Create an ed25519 host key if it does not exist (data/ is ignored by Git)."""
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        asyncssh.generate_private_key("ssh-ed25519").write_private_key(str(path))
    return path


async def start_server(host: str | None = None, port: int | None = None,
                       hostkey: Path | None = None) -> asyncssh.SSHAcceptor:
    key = ensure_host_key(hostkey or config.SSH_HOSTKEY_PATH)
    return await asyncssh.create_server(
        HoneypotSSHServer,
        host if host is not None else config.SSH_HOST,
        config.SSH_PORT if port is None else port,
        server_host_keys=[str(key)],
        server_version=SERVER_VERSION,
        login_timeout=30,
        keepalive_interval=30,
    )


async def main() -> None:
    server = await start_server()
    print(f"SSH honeypot listening on {config.SSH_HOST}:{server.get_port()}")
    await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
