CREATE TABLE events (
    event_id     UUID PRIMARY KEY,                          -- event_id du contrat
    timestamp    TIMESTAMPTZ NOT NULL,                      -- accepte Z et +00:00
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    service      TEXT NOT NULL CHECK (service IN
                   ('ssh','http','api','ftp','redis','mysql','smb')),
    event_type   TEXT NOT NULL,                             -- libre (contrat non fermé)
    source_ip    TEXT NOT NULL,
    source_port  INTEGER,                                   -- NULL côté HTTP
    session_id   TEXT NOT NULL,
    details      JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_events_ts     ON events (timestamp DESC);
CREATE INDEX idx_events_ip     ON events (source_ip);
CREATE INDEX idx_events_sess   ON events (session_id);
CREATE INDEX idx_events_svc    ON events (service, event_type);
CREATE INDEX idx_events_details ON events USING GIN (details);