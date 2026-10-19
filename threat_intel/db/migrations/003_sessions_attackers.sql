CREATE TABLE sessions (
    session_id   TEXT PRIMARY KEY,
    service      TEXT NOT NULL,
    source_ip    TEXT NOT NULL,
    started_at   TIMESTAMPTZ NOT NULL,
    ended_at     TIMESTAMPTZ,
    event_count  INTEGER NOT NULL DEFAULT 0,
    command_count INTEGER NOT NULL DEFAULT 0,
    login_success BOOLEAN NOT NULL DEFAULT FALSE
    -- mitre_techniques + threat_score : ajoutés en Étape 4 (MITRE)
);

CREATE TABLE attackers (
    ip           TEXT PRIMARY KEY,
    first_seen   TIMESTAMPTZ NOT NULL,
    last_seen    TIMESTAMPTZ NOT NULL,
    total_events BIGINT NOT NULL DEFAULT 0,
    services     TEXT[] NOT NULL DEFAULT '{}'
);