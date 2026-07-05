# Replication setup guide

Fulla supports three **optional**, independent replication mechanisms. All are **disabled by default**.

| Mode | Purpose | Typical use |
|------|---------|-------------|
| **CR-SQLite mesh** | Live bidirectional sync between up to **14** geographic nodes | Multi-region registry; survive partition and merge when links return |
| **Litestream** | Continuous WAL streaming to object storage | Disaster recovery; bare-metal rebuild |
| **SSH / rsync** | Periodic SQLite file copy to a backup host | Simple off-site snapshot without S3 |

Mesh sync is **not** a substitute for Litestream or SSH backups, and vice versa. Many operators enable **mesh + Litestream** on each node.

Configuration lives in a TOML file referenced by **`FULLA_CONFIG`**. All other Fulla settings (bind address, SMTP, rate limits) stay in `.env` / environment variables.

See also: [README replication overview](../README.md#replication), [FULLA_INTEGRATION.md](FULLA_INTEGRATION.md) (protocol v2, conflict resolution), [codemap.md](codemap.md) (implementation).

---

## Quick start checklist

1. Build or install Fulla on each node (`cargo build --release`).
2. Install the **CR-SQLite** loadable extension (mesh only) — same binary on every node.
3. Create **`/etc/fulla/.env`** per node (unique `DATABASE_URL`, shared or per-node SMTP as needed).
4. Create **`/etc/fulla/config.toml`** per node with `[replication.mesh]` (and optional Litestream/SSH).
5. Set **`FULLA_CONFIG=/etc/fulla/config.toml`** in the service environment.
6. On each node, start Fulla once and record the UUID in **`node_id_path`** (auto-created).
7. Exchange peer `node_id` values and list every **remote** peer in each node's `[[replication.mesh.peers]]` blocks.
8. Use the **same** `sync_authorization_secret` on all mesh nodes (minimum 16 characters).
9. Firewall: public HTTP(S) for users; **mesh `sync_api_port` only between peer IPs** (or VPN).
10. Upgrade **all mesh nodes together** when changing conflict-resolution or protocol behaviour.

---

## Environment wiring

`.env` (or systemd `EnvironmentFile`):

```bash
DATABASE_URL=sqlite:/var/lib/fulla/keyserver.db?mode=rwc
KEYSERVER_BASE_URL=https://keys-oslo.example.com
KEYSERVER_BIND=127.0.0.1:8080
# ... SMTP and other KEYSERVER_* variables — see SMTP_AND_MAIL.md
FULLA_CONFIG=/etc/fulla/config.toml
```

Example systemd fragment:

```ini
[Service]
EnvironmentFile=/etc/fulla/.env
ExecStart=/usr/local/bin/fulla
WorkingDirectory=/var/lib/fulla
```

The main registry listener (`KEYSERVER_BIND`) and the mesh listener (`sync_api_port`) are **separate sockets**. A reverse proxy usually terminates TLS on **443** for users; mesh TLS is configured separately on **`sync_tls_cert` / `sync_tls_key`** (or plain HTTP on a private network only).

---

## CR-SQLite mesh — two-node lab example

This example uses **documentation IPs** from [RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) (`203.0.113.0/24`). Replace with your real addresses.

| Node | Role | Public registry URL | Mesh sync URL | VPN / internal IP |
|------|------|---------------------|---------------|-------------------|
| **Oslo** | Node A | `https://keys-oslo.example.com` (→ `127.0.0.1:8080`) | `https://203.0.113.10:9443` | optional |
| **Frankfurt** | Node B | `https://keys-de.example.com` | `https://203.0.113.20:9443` | optional |

Both nodes share one cluster secret (generate once, store in a secrets manager):

```text
sync_authorization_secret = "k8mP2xQ9vL4nR7wT1yZ6aB3cD0eF5gH"
```

### Step 1 — Install CR-SQLite

Download a release matching your platform from [vlcn-io/cr-sqlite releases](https://github.com/vlcn-io/cr-sqlite/releases), install on both nodes, for example:

```bash
sudo install -m 755 crsqlite.so /usr/local/lib/crsqlite.so
```

SQLite must support `load_extension`. Fulla loads the extension on every pool connection when mesh is enabled.

Optional integrity pin (recommended in production):

```bash
sha256sum /usr/local/lib/crsqlite.so
# paste 64-char hex into crsqlite_extension_sha256 in config.toml
```

### Step 2 — TLS certificates for mesh (production)

Generate or issue a cert whose SAN/CN matches how peers reach the sync API (IP or hostname). Example self-signed per node (lab only):

```bash
# On Oslo (203.0.113.10)
openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
  -keyout /etc/fulla/sync.key -out /etc/fulla/sync.crt \
  -subj "/CN=203.0.113.10" -addext "subjectAltName=IP:203.0.113.10"

# On Frankfurt (203.0.113.20) — repeat with that IP/CN
```

For plain HTTP mesh (lab VPN only), omit **`sync_tls_cert`** and **`sync_tls_key`** on both nodes. Fulla logs a warning: keep port 9443 off the public Internet.

### Step 3 — Start each node once to obtain `node_id`

**Oslo** `/etc/fulla/config.toml` (initial — peers empty):

```toml
[replication.mesh]
enabled = true
node_id_path = "/var/lib/fulla/node_id"
crsqlite_extension_path = "/usr/local/lib/crsqlite.so"
sync_authorization_secret = "k8mP2xQ9vL4nR7wT1yZ6aB3cD0eF5gH"
sync_interval_minutes = 15
sync_api_port = 9443
sync_tls_cert = "/etc/fulla/sync.crt"
sync_tls_key  = "/etc/fulla/sync.key"
# peers added after both node_id files exist
```

Start Fulla, then read:

```bash
cat /var/lib/fulla/node_id
# Example: a1111111-1111-4111-8111-111111111111
```

Repeat on **Frankfurt**; you might get `b2222222-2222-4222-8222-222222222222`.

### Step 4 — Configure reciprocal peers

**Oslo** — list Frankfurt only (never list yourself):

```toml
[[replication.mesh.peers]]
node_id = "b2222222-2222-4222-8222-222222222222"
region  = "Western Europe"
address = "https://203.0.113.20:9443"
```

**Frankfurt** — list Oslo:

```toml
[[replication.mesh.peers]]
node_id = "a1111111-1111-4111-8111-111111111111"
region  = "Northern Europe"
address = "https://203.0.113.10:9443"
```

Restart both nodes (or redeploy config and restart). On startup Fulla upserts peers into the local `mesh_peers` table and begins cron sync every `sync_interval_minutes`.

### Step 5 — Firewall

**Oslo** (illustrative `ufw`):

```bash
# Public registry (or only from reverse proxy)
sudo ufw allow 443/tcp

# Mesh sync — Frankfurt's egress IP or shared VPN only
sudo ufw allow from 203.0.113.20 to any port 9443 proto tcp
```

**Frankfurt**:

```bash
sudo ufw allow 443/tcp
sudo ufw allow from 203.0.113.10 to any port 9443 proto tcp
```

Mesh binds **`0.0.0.0:sync_api_port`** inside Fulla. Restrict at the host firewall or cloud security group so only peer addresses reach 9443.

### Step 6 — Verify sync

1. Submit and confirm a key on Oslo (mailbox flow).
2. Within one sync interval, `GET /keys` on Frankfurt should show the same active key.
3. Check JSON logs for `mesh sync` success or `mesh peer sync failed` warnings.

Manual probe (replace secret and URL):

```bash
curl -sS -H "Authorization: Bearer k8mP2xQ9vL4nR7wT1yZ6aB3cD0eF5gH" \
  "https://203.0.113.20:9443/sync/changes?since_db_version=0&node_id=a1111111-1111-4111-8111-111111111111&limit=10&protocol_version=2"
```

---

## Three-node mesh over a VPN

When nodes have stable **private** addresses, point `address` at the VPN IP. Public users still use `KEYSERVER_BASE_URL` on each node's reverse proxy.

| Node | Region label | `KEYSERVER_BASE_URL` | Mesh `address` |
|------|--------------|----------------------|----------------|
| Oslo | Northern Europe | `https://keys-oslo.example.com` | `https://10.50.0.11:9443` |
| Frankfurt | Western Europe | `https://keys-de.example.com` | `https://10.50.0.12:9443` |
| London | UK / Ireland | `https://keys-uk.example.com` | `https://10.50.0.13:9443` |

Each node's `config.toml` contains **two** `[[replication.mesh.peers]]` entries (the other nodes). Example on **Oslo**:

```toml
[[replication.mesh.peers]]
node_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
region  = "Western Europe"
address = "https://10.50.0.12:9443"

[[replication.mesh.peers]]
node_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
region  = "UK / Ireland"
address = "https://10.50.0.13:9443"
```

Firewall rule pattern:

```bash
sudo ufw allow from 10.50.0.0/24 to any port 9443 proto tcp
```

Maximum mesh size: **13 remote peers + self = 14 nodes** total.

---

## Dynamic DNS (home / changing IP)

If a peer's public IP changes, set `dynamic_dns_host` to the hostname you update (for example via [deSEC](https://desec.io/)). Before each sync cycle Fulla resolves the hostname and substitutes it into `address` when the hostname appears in the URL.

```toml
[[replication.mesh.peers]]
node_id = "d3333333-3333-4333-8333-333333333333"
region  = "Oceania"
address = "https://fulla-sydney.dyndns.example.net:9443"
dynamic_dns_host = "fulla-sydney.dyndns.example.net"
```

The token in `address` must match `dynamic_dns_host` (or the URL host part) so substitution works. If DNS fails for a cycle, that peer is skipped until resolution succeeds.

The same `dynamic_dns_host` field exists on `[replication.litestream]` and `[replication.ssh]` for backup targets.

---

## Mesh configuration reference

| Key | Required | Default | Notes |
|-----|----------|---------|-------|
| `enabled` | yes | `false` | Master switch |
| `node_id_path` | yes | — | UUID file; created `0600` on first start |
| `crsqlite_extension_path` | yes | — | Path to `.so` / `.dylib` / `.dll` |
| `crsqlite_extension_sha256` | no | — | 64-char hex pin before `load_extension` |
| `sync_authorization_secret` | yes | — | **Shared** Bearer token, min 16 chars |
| `sync_interval_minutes` | no | `60` | Cron period for pull/push to all peers |
| `sync_api_port` | yes | — | Mesh listener (`0.0.0.0:port`) |
| `sync_tls_cert` / `sync_tls_key` | paired | — | Both set = HTTPS mesh; both omitted = plain HTTP |
| `sync_max_body_bytes` | no | `1048576` | POST `/sync/apply` body limit |
| `sync_max_changes_per_request` | no | `10000` | Pagination page size (protocol v2) |
| `sync_rate_limit_requests` | no | `600` | Global hourly cap on mesh HTTP (`0` = unlimited) |

Peer table (`[[replication.mesh.peers]]`):

| Key | Required | Notes |
|-----|----------|-------|
| `node_id` | yes | Remote node's UUID from its `node_id_path` |
| `region` | yes | Label for logs (design list in README) |
| `address` | yes | `http(s)://host:port` only — no path, credentials, or query |
| `dynamic_dns_host` | no | Hostname to resolve before each sync |

**Endpoints** (authenticated mesh only):

- `GET /sync/changes` — paginated outbound changes
- `POST /sync/apply` — apply inbound batch

User-facing routes on `KEYSERVER_BIND` are unrelated.

---

## Email conflicts after mesh merge

If two active keys with the same normalized email arrive from different peers, Fulla revokes the loser with `revocation_reason = 'mesh_conflict'`. Precedence on **this node**:

1. Row **locally confirmed** here (`GET /confirm/{token}` handled on this node) wins.
2. Else earliest **`first_seen_at`** (local observation time, not replicated).

Replicated `submitted_at` and fingerprint are **not** trust boundaries. Upgrade all nodes together when changing this logic (migration `010_key_local_provenance.sql`). Details: [FULLA_INTEGRATION.md — mesh_conflict](FULLA_INTEGRATION.md#email-conflict-resolution-mesh_conflict).

---

## Litestream (disaster recovery)

Independent of mesh. Streams SQLite WAL to durable storage; Fulla runs `litestream replicate -once` on an interval.

**Prerequisites:** `litestream` on `PATH`, on-disk `DATABASE_URL`.

```toml
[replication.litestream]
enabled = true
replica_url = "s3://fulla-backups-oslo/node-1?region=eu-north-1"
interval_minutes = 60
# dynamic_dns_host = "backup-gateway.dyndns.example.net"
```

Example layout: one bucket prefix per node (`s3://mybucket/oslo/`, `s3://mybucket/frankfurt/`). After catastrophic loss, restore the DB from Litestream, then let CR-SQLite mesh catch up remaining peers.

If Litestream is enabled but the binary is missing, Fulla logs a warning and skips the cron.

---

## SSH / rsync fallback

Copies the SQLite file to a remote host. Simpler than Litestream; not a live CRDT merge.

```toml
[replication.ssh]
enabled = true
remote_user = "fulla"
remote_host = "203.0.113.50"
remote_path = "/backups/fulla/oslo-keyserver.db"
ssh_key_path = "/etc/fulla/replication_id_ed25519"
interval_minutes = 60
offset_minutes = 5
# dynamic_dns_host = "backup.dyndns.example.net"
```

Requires `ssh` and `rsync` on `PATH`. When **both** Litestream and SSH are enabled, the first SSH run waits `litestream.interval_minutes + ssh.offset_minutes`, then SSH repeats every `ssh.interval_minutes`.

---

## Combined example (`config.toml`)

Oslo production node with mesh + Litestream (SSH optional):

```toml
[replication.mesh]
enabled = true
node_id_path = "/var/lib/fulla/node_id"
crsqlite_extension_path = "/usr/local/lib/crsqlite.so"
crsqlite_extension_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
sync_authorization_secret = "k8mP2xQ9vL4nR7wT1yZ6aB3cD0eF5gH"
sync_interval_minutes = 60
sync_api_port = 9443
sync_tls_cert = "/etc/fulla/sync.crt"
sync_tls_key  = "/etc/fulla/sync.key"

[[replication.mesh.peers]]
node_id = "b2222222-2222-4222-8222-222222222222"
region  = "Western Europe"
address = "https://10.50.0.12:9443"

[[replication.mesh.peers]]
node_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
region  = "UK / Ireland"
address = "https://10.50.0.13:9443"

[replication.litestream]
enabled = true
replica_url = "s3://fulla-dr/oslo?region=eu-north-1"
interval_minutes = 60

# [replication.ssh]
# enabled = false
```

Copy to `/etc/fulla/config.toml`, set `FULLA_CONFIG`, restart Fulla.

---

## Designed 14-region layout

For maximum geographic resilience, operators often deploy one node per region listed in the [README](../README.md#designed-regions) (Northern Europe through Oceania). Each node:

- Lists up to **13** peers (every other node).
- Uses ~**300 GB** disk for DB, WAL, CR-SQLite state, and snapshots.
- Keeps mesh port **off the public Internet** (VPN or peer IP allowlists).

Staged rollout: protocol v2 allows small sync batches between mixed versions; **full pages** from pre-v2 peers fail closed until upgraded. See [FULLA_INTEGRATION.md — truncation fail-closed](FULLA_INTEGRATION.md#staged-rollout-and-truncation-fail-closed-protocol-v2).

---

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| Startup error: CR-SQLite extension missing | Wrong `crsqlite_extension_path` or mesh enabled without installing the `.so` |
| `mesh: no peers in mesh_peers` | No `[[replication.mesh.peers]]` in config, or mesh not enabled |
| `401` on `/sync/changes` | Mismatched `sync_authorization_secret` between nodes |
| Peer skipped each cycle | DNS failure when using `dynamic_dns_host`; invalid `address` URL |
| `TruncationBlockedError` in logs | Old peer sent a full page without protocol v2 — upgrade lagging node |
| Keys on A not visible on B | Firewall blocking 9443; TLS trust mismatch; sync interval not elapsed |
| `mesh_conflict` revocation | Two active keys for same email merged — mailbox re-registration recovers legitimate owner |

Confirm mesh listener is up: `ss -tlnp | grep 9443` on the node.

---

## Security notes

- Treat `sync_authorization_secret` like a cluster root password; rotate only with coordinated config deploy on **all** nodes.
- Pin `crsqlite_extension_sha256` when possible (`src/extension_integrity.rs`).
- Never expose `sync_api_port` to the world without TLS and strict source IP filtering.
- Mesh replication does **not** replicate local-only provenance tables; conflict resolution depends on per-node confirm handling.
