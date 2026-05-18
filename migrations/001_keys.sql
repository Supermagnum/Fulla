CREATE TABLE IF NOT EXISTS keys (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint       TEXT    NOT NULL UNIQUE,
    armored_key       TEXT    NOT NULL,
    first_name        TEXT,
    last_name         TEXT,
    email             TEXT    NOT NULL,
    callsign          TEXT,
    dmr_id            INTEGER,
    submitted_at      TEXT    NOT NULL,
    revoked_at        TEXT,
    revocation_reason TEXT,
    status            TEXT    NOT NULL DEFAULT 'active'
);

CREATE INDEX IF NOT EXISTS idx_keys_email ON keys(email);
CREATE INDEX IF NOT EXISTS idx_keys_fingerprint ON keys(fingerprint);
CREATE INDEX IF NOT EXISTS idx_keys_callsign ON keys(callsign);
CREATE INDEX IF NOT EXISTS idx_keys_dmr_id ON keys(dmr_id);
