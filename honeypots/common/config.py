import os
from pathlib import Path

LOG_PATH = Path(os.getenv("HP_LOG_PATH", "data/events.jsonl"))
HTTP_PORT = int(os.getenv("HP_HTTP_PORT", "8080"))
SSH_PORT = int(os.getenv("HP_SSH_PORT", "2222"))

# True only in the isolated lab. If a honeypot is ever exposed, set to false:
# secrets are then stored as a short hash instead of in clear text.
CAPTURE_PASSWORDS = os.getenv("HP_CAPTURE_PASSWORDS", "true").lower() == "true"