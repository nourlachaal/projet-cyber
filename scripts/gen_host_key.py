"""Generate the SSH host key used by the SSH honeypot (data/ssh_host_key, ignored by Git)."""
from pathlib import Path

import asyncssh

Path("data").mkdir(exist_ok=True)
key = asyncssh.generate_private_key("ssh-ed25519")
key.write_private_key("data/ssh_host_key")
print("Host key written to data/ssh_host_key")