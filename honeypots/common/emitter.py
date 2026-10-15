from .config import LOG_PATH
from .events import Event


def emit(event: Event) -> None:
    """Append one event as a JSON line. Simple and enough for a lab-sized volume."""
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(event.model_dump_json() + "\n")