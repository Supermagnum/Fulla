-- Peer registry for CR-SQLite mesh sync.
-- Runs without the CR-SQLite extension loaded. Do not call crsql_as_crr here.

CREATE TABLE IF NOT EXISTS mesh_peers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id         TEXT NOT NULL UNIQUE,
    region          TEXT NOT NULL,
    address         TEXT NOT NULL,
    dynamic_dns_host TEXT,
    ssh_fallback_user TEXT,
    ssh_fallback_key TEXT,
    last_sync_at    TEXT,
    last_sync_db_version INTEGER
);
