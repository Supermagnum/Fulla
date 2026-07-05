-- Per-node key provenance for mesh conflict resolution.
-- NOT registered with crsql_as_crr — never replicated, never writable via apply_crsql_wire_rows.

CREATE TABLE IF NOT EXISTS key_local_confirmations (
    fingerprint   TEXT PRIMARY KEY,
    confirmed_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS key_local_first_seen (
    fingerprint    TEXT PRIMARY KEY,
    first_seen_at  TEXT NOT NULL
);

-- Bootstrap first_seen for keys already active before this migration (observation proxy only).
INSERT OR IGNORE INTO key_local_first_seen (fingerprint, first_seen_at)
SELECT fingerprint, submitted_at FROM keys WHERE status = 'active';
