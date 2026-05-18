CREATE TABLE IF NOT EXISTS pending_submissions (
    token           TEXT PRIMARY KEY,
    new_fingerprint TEXT NOT NULL,
    email           TEXT NOT NULL,
    first_name      TEXT,
    last_name       TEXT,
    callsign        TEXT,
    dmr_id          INTEGER,
    armored_key     TEXT NOT NULL,
    expires_at      TEXT NOT NULL
);
