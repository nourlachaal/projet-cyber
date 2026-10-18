from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class Event(BaseModel):
    """Canonical event shared by all honeypots. See docs/event-schema.md."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    service: Literal["ssh", "http", "api", "ftp", "redis", "mysql", "smb"]
    event_type: str
    source_ip: str
    source_port: int | None = None
    session_id: str
    details: dict[str, Any] = Field(default_factory=dict)