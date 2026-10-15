import hashlib

from . import config


def protect_secret(value: str) -> str:
    """Clear text in the isolated lab, short hash otherwise (see HP_CAPTURE_PASSWORDS)."""
    if config.CAPTURE_PASSWORDS:
        return value
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:16]
