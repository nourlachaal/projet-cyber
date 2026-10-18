
import os

import redis
from fastapi import FastAPI, HTTPException

from honeypots.common.events import Event

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
EVENT_STREAM = "honeypot:events"

app = FastAPI(
    title="Cyber Honeypot Backend",
    description="API de réception des événements des honeypots",
    version="0.2.0",
)

redis_client = redis.Redis.from_url(
    REDIS_URL,
    decode_responses=True,
    socket_connect_timeout=2,
    socket_timeout=2,
)


@app.get("/health")
def health_check():
    """Vérifie que l'API et Redis sont disponibles."""
    try:
        redis_client.ping()
    except redis.RedisError as exc:
        raise HTTPException(
            status_code=503,
            detail="Redis est indisponible",
        ) from exc

    return {"status": "ok", "redis": "connected"}


@app.post("/events", status_code=202)
def receive_event(event: Event):
    """Valide un événement et l'ajoute au flux Redis."""
    try:
        stream_id = redis_client.xadd(
            EVENT_STREAM,
            {"event": event.model_dump_json()},
        )
    except redis.RedisError as exc:
        raise HTTPException(
            status_code=503,
            detail="Impossible de transmettre l'événement à Redis",
        ) from exc

    return {
        "status": "accepted",
        "event_id": event.event_id,
        "stream_id": stream_id,
    }
