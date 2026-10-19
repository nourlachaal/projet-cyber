CREATE TABLE iocs (
    id          BIGSERIAL PRIMARY KEY,
    type        TEXT NOT NULL CHECK (type IN
                  ('ipv4','ipv6','domain','url','user-agent','credential')),
    value       TEXT NOT NULL,
    first_seen  TIMESTAMPTZ NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL,
    sight_count INTEGER NOT NULL DEFAULT 1,
    confidence  INTEGER NOT NULL DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
    source      TEXT NOT NULL DEFAULT 'honeypot',
    tags        TEXT[] NOT NULL DEFAULT '{}',
    UNIQUE (type, value)                                  -- dédup → upsert
);

CREATE TABLE mitre_detections (
    id           BIGSERIAL PRIMARY KEY,
    session_id   TEXT,
    technique_id TEXT NOT NULL,                           -- ex. 'T1110'
    tactic       TEXT NOT NULL,                           -- ex. 'credential-access'
    confidence   INTEGER NOT NULL DEFAULT 50,
    source_ip    TEXT NOT NULL,
    service      TEXT,
    evidence     TEXT,
    detected_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_mitre_tech ON mitre_detections (technique_id, detected_at DESC);