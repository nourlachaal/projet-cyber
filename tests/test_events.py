from honeypots.common.events import Event


def test_event_defaults():
    e = Event(service="http", event_type="http_request", source_ip="192.0.2.10", session_id="s1")
    assert e.event_id
    assert e.timestamp.tzinfo is not None
    assert e.model_dump()["service"] == "http"