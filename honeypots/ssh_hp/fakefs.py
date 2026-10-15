"""A tiny fake filesystem. Pure data: nothing here ever touches the real disk."""
import posixpath

HOSTNAME = "srv01"

PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
admin:x:1000:1000:Admin User:/home/admin:/bin/bash
"""

OS_RELEASE = """PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
"""

# path -> None for a directory, str for a file (all content is fictional)
NODES: dict[str, str | None] = {
    "/": None,
    "/bin": None,
    "/etc": None,
    "/etc/passwd": PASSWD,
    "/etc/shadow": "cat: /etc/shadow: Permission denied\n",
    "/etc/hostname": HOSTNAME + "\n",
    "/etc/os-release": OS_RELEASE,
    "/etc/issue": "Ubuntu 22.04.3 LTS \\n \\l\n",
    "/home": None,
    "/home/admin": None,
    "/home/admin/notes.txt": "TODO: rotate backup credentials\n",
    "/root": None,
    "/root/.bash_history": "ls\ncd /var/www\nexit\n",
    "/root/backup.sh": "#!/bin/bash\ntar czf /tmp/backup.tgz /var/www\n",
    "/tmp": None,
    "/var": None,
    "/var/log": None,
    "/var/log/auth.log": "",
    "/var/www": None,
    "/var/www/index.html": "<html><body>It works!</body></html>\n",
}


def resolve(cwd: str, path: str) -> str:
    """Turn a user-supplied path into an absolute normalized path."""
    if path.startswith("~"):
        path = "/root" + path[1:]
    if not path.startswith("/"):
        path = posixpath.join(cwd, path)
    return posixpath.normpath(path)


def exists(path: str) -> bool:
    return path in NODES


def is_dir(path: str) -> bool:
    return path in NODES and NODES[path] is None


def read_file(path: str) -> str | None:
    node = NODES.get(path)
    return node if isinstance(node, str) else None


def list_dir(path: str) -> list[str]:
    prefix = "/" if path == "/" else path + "/"
    names = []
    for p in NODES:
        if p != path and p.startswith(prefix) and "/" not in p[len(prefix):]:
            names.append(p[len(prefix):])
    return sorted(names)
