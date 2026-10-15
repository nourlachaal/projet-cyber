"""Fake shell: maps typed text to predefined answers. NOTHING IS EVER EXECUTED.

No subprocess, no os.system, no eval, no real file access. Every answer comes from
fakefs.py or from the canned strings below.
"""
import re
from dataclasses import dataclass, field

from . import fakefs

URL_RE = re.compile(r"^(?:https?|ftp)://\S+$", re.IGNORECASE)
SPLIT_RE = re.compile(r"\s*(?:;|&&|\|\|)\s*")
SILENT_OK = {"touch", "mkdir", "rm", "rmdir", "chmod", "chown", "mv", "cp", "kill", "export",
             "unset", "alias", "clear", "sleep", "nohup", "sync", "crontab", "service",
             "systemctl", "ln", "source", "set", "unalias"}


@dataclass
class ShellResult:
    output: str = ""
    exit: bool = False
    downloads: list[dict] = field(default_factory=list)  # [{"tool":..., "url":...}]


class FakeShell:
    def __init__(self, user: str = "root") -> None:
        self.user = user or "root"
        self.cwd = "/root"
        self.history: list[str] = []

    def prompt(self) -> str:
        shown = "~" if self.cwd == "/root" else self.cwd
        sign = "#" if self.user == "root" else "$"
        return f"{self.user}@{fakefs.HOSTNAME}:{shown}{sign} "

    def run(self, line: str) -> ShellResult:
        line = line.strip()
        result = ShellResult()
        if not line:
            return result
        self.history.append(line)
        for part in SPLIT_RE.split(line):
            part = part.split("|")[0].strip()  # pipes: only the first command is answered
            if not part:
                continue
            out, quit_, downloads = self._one(part)
            result.output += out
            result.downloads += downloads
            if quit_:
                result.exit = True
                break
        return result

    # ------------------------------------------------------------------ commands
    def _one(self, part: str) -> tuple[str, bool, list[dict]]:
        tokens = part.split()
        if tokens and tokens[0] == "sudo":
            tokens = tokens[1:] or ["sudo"]
        if not tokens:
            return "", False, []
        cmd, args = tokens[0], tokens[1:]
        flags = [a for a in args if a.startswith("-")]
        operands = [a for a in args if not a.startswith("-")]

        if cmd in ("exit", "logout"):
            return "", True, []
        if cmd == "pwd":
            return self.cwd + "\n", False, []
        if cmd == "cd":
            return self._cd(operands[0] if operands else "~"), False, []
        if cmd == "ls":
            return self._ls(operands, flags), False, []
        if cmd == "cat":
            return self._cat(operands), False, []
        if cmd == "whoami":
            return self.user + "\n", False, []
        if cmd == "id":
            return self._id(), False, []
        if cmd == "uname":
            if "-a" in flags:
                return (f"Linux {fakefs.HOSTNAME} 5.15.0-91-generic #101-Ubuntu SMP "
                        "Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n"), False, []
            return "Linux\n", False, []
        if cmd == "hostname":
            return fakefs.HOSTNAME + "\n", False, []
        if cmd == "uptime":
            return " 10:42:17 up 41 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\n", False, []
        if cmd == "ps":
            return ("  PID TTY          TIME CMD\n    1 ?        00:00:03 systemd\n"
                    "  412 ?        00:00:00 sshd\n  998 pts/0    00:00:00 bash\n"), False, []
        if cmd in ("ifconfig", "ip"):
            return ("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                    "        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n"), False, []
        if cmd == "echo":
            return " ".join(args).replace('"', "").replace("'", "") + "\n", False, []
        if cmd == "history":
            lines = [f"{i:5d}  {h}\n" for i, h in enumerate(self.history, 1)]
            return "".join(lines), False, []
        if cmd in ("wget", "curl"):
            return self._download(cmd, operands)
        if cmd in SILENT_OK:
            return "", False, []
        return f"bash: {cmd}: command not found\n", False, []

    def _cd(self, target: str) -> str:
        path = fakefs.resolve(self.cwd, target)
        if not fakefs.exists(path):
            return f"bash: cd: {target}: No such file or directory\n"
        if not fakefs.is_dir(path):
            return f"bash: cd: {target}: Not a directory\n"
        self.cwd = path
        return ""

    def _ls(self, operands: list[str], flags: list[str]) -> str:
        path = fakefs.resolve(self.cwd, operands[0]) if operands else self.cwd
        if not fakefs.exists(path):
            return f"ls: cannot access '{operands[0]}': No such file or directory\n"
        names = fakefs.list_dir(path) if fakefs.is_dir(path) else [path.rsplit("/", 1)[-1]]
        if "-l" in flags or "-la" in flags or "-al" in flags:
            rows = []
            for n in names:
                full = fakefs.resolve(path, n)
                kind = "d" if fakefs.is_dir(full) else "-"
                rows.append(f"{kind}rwxr-xr-x 1 root root 4096 Nov 14 10:00 {n}")
            return f"total {len(rows) * 4}\n" + "\n".join(rows) + "\n" if rows else ""
        return ("  ".join(names) + "\n") if names else ""

    def _cat(self, operands: list[str]) -> str:
        if not operands:
            return ""
        out = ""
        for op in operands:
            path = fakefs.resolve(self.cwd, op)
            content = fakefs.read_file(path)
            if content is not None:
                out += content
            elif fakefs.is_dir(path):
                out += f"cat: {op}: Is a directory\n"
            else:
                out += f"cat: {op}: No such file or directory\n"
        return out

    def _id(self) -> str:
        if self.user == "root":
            return "uid=0(root) gid=0(root) groups=0(root)\n"
        return f"uid=1000({self.user}) gid=1000({self.user}) groups=1000({self.user})\n"

    def _download(self, tool: str, operands: list[str]) -> tuple[str, bool, list[dict]]:
        """Only the URL is recorded. Nothing is fetched: the decoy has no outbound access."""
        urls = [o for o in operands if URL_RE.match(o)]
        downloads = [{"tool": tool, "url": u[:2048]} for u in urls]
        if tool == "wget":
            out = "wget: unable to resolve host address\n"
        else:
            out = "curl: (6) Could not resolve host\n"
        return (out if downloads else f"{tool}: missing URL\n"), False, downloads
