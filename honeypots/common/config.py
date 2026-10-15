import os
from pathlib import Path

LOG_PATH = Path(os.getenv("HP_LOG_PATH", "data/events.jsonl"))
HTTP_PORT = int(os.getenv("HP_HTTP_PORT", "8080"))
SSH_PORT = int(os.getenv("HP_SSH_PORT", "2222"))

# True only in the isolated lab. If a honeypot is ever exposed, set to false:
# secrets are then stored as a short hash instead of in clear text.
CAPTURE_PASSWORDS = os.getenv("HP_CAPTURE_PASSWORDS", "true").lower() == "true"

# --- SSH honeypot ---
SSH_HOST = os.getenv("HP_SSH_HOST", "0.0.0.0")
SSH_HOSTKEY_PATH = Path(os.getenv("HP_SSH_HOSTKEY_PATH", "data/ssh_host_key"))
# The login is accepted on the Nth password attempt from the same IP (1 = always accept).
SSH_ACCEPT_AFTER = int(os.getenv("HP_SSH_ACCEPT_AFTER", "3"))
SSH_IDLE_TIMEOUT = int(os.getenv("HP_SSH_IDLE_TIMEOUT", "120"))  # seconds without input
SSH_MAX_SESSION = int(os.getenv("HP_SSH_MAX_SESSION", "600"))  # seconds per session
SSH_MAX_COMMANDS = int(os.getenv("HP_SSH_MAX_COMMANDS", "200"))  # commands per session
SSH_MAX_CMD_LEN = 1024  # characters kept per command
