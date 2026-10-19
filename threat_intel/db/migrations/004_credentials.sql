CREATE TABLE credentials (
    id         BIGSERIAL PRIMARY KEY,
    timestamp  TIMESTAMPTZ NOT NULL,
    session_id TEXT,
    service    TEXT NOT NULL,
    source_ip  TEXT NOT NULL,
    username   TEXT NOT NULL,
    password   TEXT NOT NULL DEFAULT '',   -- clair uniquement en lab (HP_CAPTURE_PASSWORDS)
    success    BOOLEAN NOT NULL DEFAULT FALSE,
    auth_method TEXT NOT NULL DEFAULT 'password'
);
CREATE INDEX idx_cred_ip ON credentials (source_ip, timestamp DESC);
CREATE INDEX idx_cred_user ON credentials (username);