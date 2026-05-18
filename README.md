# Fulla

Repository: [github.com/Supermagnum/Fulla](https://github.com/Supermagnum/Fulla).

Fulla is a closed Galdralag hardware key registry backed by SQLite. It exposes a web UI and API for key submission, confirmation, and revocation. Optional replication (CR-SQLite mesh, Litestream, SSH/rsync) is described under [Replication](#replication).

## Table of contents

- [About the name](#about-the-name)
- [Build and install on Ubuntu](#build-and-install-on-ubuntu)
- [Dependencies and packages](#dependencies-and-packages)
- [Configuration overview](#configuration-overview)
  - [Key listing and search](#key-listing-and-search)
- [Network ports and firewall](#network-ports-and-firewall)
- [Debugging and troubleshooting](#debugging-and-troubleshooting)
- [Galdra compatibility](#galdra--galdralag-firmware-compatibility)
- [Replication](#replication)
- [Maintainer scope and support](#maintainer-scope-and-support)

## About the name

Fulla is one of the lesser-known goddesses in Norse mythology, but her role is no less important. She is primarily known as the handmaiden and confidante of Frigg, the queen of Asgard and wife of Odin. Fulla’s name is thought to mean “bountiful” or “plentiful,” hinting at her association with abundance and care.

While Fulla doesn’t have as many myths dedicated to her as some of the other gods and goddesses, her presence is deeply felt in the stories where she appears. She is a symbol of loyalty, discretion, and the quiet power of those who work behind the scenes.

## Build and install on Ubuntu

These steps target **Ubuntu 22.04 LTS or 24.04 LTS** (or similar Debian-based systems). Adjust paths and service layout to match your environment.

### 1. Install system packages and Rust

Install build tools and Rust using the official **rustup** toolchain (recommended; the `rustc` package in Ubuntu’s archive is often too old for this project):

```bash
sudo apt update
sudo apt install -y build-essential pkg-config curl

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustc --version
```

### 2. Clone and build

```bash
git clone https://github.com/Supermagnum/Fulla fulla
cd fulla
cargo build --release
```

The binary is `target/release/fulla`.

### 3. Install the binary (optional)

```bash
sudo install -m 755 target/release/fulla /usr/local/bin/fulla
```

Create a dedicated system user, data directory, and environment file as required by your deployment policy. Run the process under **systemd** or another supervisor; the project does not ship a unit file, so write one that sets `EnvironmentFile`, `WorkingDirectory`, and `ExecStart=/usr/local/bin/fulla`.

### 4. Environment and config

- Copy `.env.example` to a secure location (for example `/etc/fulla/.env`) and set variables such as `DATABASE_URL`, `KEYSERVER_BIND`, and mail settings.
- If you use replication TOML, set `FULLA_CONFIG=/path/to/config.toml` in the same environment as the process.

There is no separate “install” target beyond building the binary; database migrations run automatically on startup.

## Dependencies and packages

### Required to compile Fulla (Ubuntu)

| Package / tool | Purpose |
|----------------|---------|
| `build-essential` | C/C++ toolchain (`gcc`, `make`) used by some native Rust crates |
| `pkg-config` | Discovering libraries during the build |
| `curl` | Downloading `rustup` |
| **Rust toolchain** (`rustup`, stable channel) | Compiling the project (`cargo build --release`) |

Most cryptographic and TLS usage in this tree goes through **Rustls** and **pure-Rust OpenPGP** features; you do not need a full OpenSSL development stack for a normal `cargo build` on Ubuntu.

### Runtime (operator responsibility)

| Component | When needed |
|-----------|-------------|
| **SQLite database file or path** | `DATABASE_URL` must point at a persistent SQLite URL (see `.env.example`) |
| **SMTP** | Outbound mail for confirmations (`KEYSERVER_*_SMTP_*` variables) |
| **TLS certificate and key** (optional for the main site) | If `KEYSERVER_TLS_CERT` / `KEYSERVER_TLS_KEY` are set, the main listener uses HTTPS |
| **CR-SQLite shared library** | Only when `[replication.mesh] enabled = true`; path set by `crsqlite_extension_path`. SQLite must support `load_extension` (bundled/driver build must expose it) |
| **`litestream` binary** | Only when `[replication.litestream] enabled = true` |
| **`ssh` + `rsync`** | Only when `[replication.ssh] enabled = true` |

Optional mesh peers need outbound HTTPS access to each other’s `sync_api_port` (or plain HTTP if you deliberately omit TLS on the mesh listener in non-production setups).

## Configuration overview

Two layers matter for operators:

1. **Environment variables** (typically from `.env` or systemd `Environment`): main bind address, base URL, database URL, SMTP, rate limits. See `.env.example`.
2. **`FULLA_CONFIG`**: path to a TOML fragment containing **`[replication]`** sections. If unset, replication defaults stay off.

**Ports** come from configuration, not from hard-coded defaults only:

| Setting | Typical role |
|---------|----------------|
| `KEYSERVER_BIND` | Main HTTP(S) listener (example `0.0.0.0:8443`). Host and port are chosen by you. |
| `[replication.mesh] sync_api_port` | Separate peer-sync listener (often **9443** in examples). Binds **`0.0.0.0`** in the binary; restrict with firewall rules. |

Place TLS files where the service user can read them; lock down ownership (for example root / dedicated group).

### Key listing and search

The **`GET /keys`** endpoint and matching HTML listings support **combined filters** via query parameters. Multiple parameters are **`AND`**-ed together.

| Parameter | Semantics |
|-----------|-----------|
| `email` | Case-insensitive **exact** match on stored email |
| `fingerprint` | **Prefix** match on fingerprint (hex, whitespace stripped, uppercased prefix) |
| `callsign` | Case-insensitive **exact** match |
| `dmr_id` | **Exact** numeric match (`INTEGER`) |
| `discord_id`, `irc_id`, `fluxer_id` | **Exact** match (after trim); suitable for identifiers stored as in the submission |
| `first_name`, `last_name` | Case-insensitive **substring** (`instr(lower(column), lower(value))`; empty needle is ignored) |

Pagination uses `page`, `per_page` (defaults: `1`, `25`, max `200` rows per page).

**JSON note:** requesting keys by **`email` alone** (no other filters) preserves the legacy behaviour (`GET /keys?email=` with **`Accept: application/json`**) of returning bundled key JSON for tooling; add any other query field to route through the general filtered listing instead.

### Galdra / Galdralag-firmware compatibility

The [`galdra keyserver`](https://github.com/Supermagnum/Galdralag-firmware) subcommands **`push`** / **`fetch`** target this API: **`POST {base}/api/v1/keys`** with **`email`**, **`armored_public_key`**, and optional sidecar JSON fields (display name **`first_name`/`last_name`**, **`callsign`**, **`dmr_id`**, **`radio_affiliation`**, **`fluxer_id`/`discord_id`/`irc_id`**, postal **`street`/`country`/`postal_code`/`region`**, and **`organisation`**, **`role`**, **`note`**, **`badge_number`**). Fulla accepts minimal bodies (those two keys only). Response JSON uses **`accepted`**, **`pending_confirmation`**, or **`error`** as **`galdra`** parses them, including **`422`** with a machine-readable **`reason`**. **`GET /keys/{fingerprint}`** and **`GET /keys?email=...`** with **`Accept: application/json`** align with **`galdra keyserver fetch`** (singleton or array).

## Network ports and firewall

### Inbound you may want to expose

1. **Main registry** (`KEYSERVER_BIND`): the only listener end users normally need (often **443** or **8443** behind a reverse proxy).
2. **Mesh sync API** (`sync_api_port`): **only peer nodes** should reach this. Do **not** publish it like a public HTTP API.

### Recommended posture

- Use **UFW** or **nftables**/cloud security groups so that:
  - The main port is reachable from the Internet **or** from your reverse proxy only.
  - `sync_api_port` is reachable **only from known peer IP addresses or VPN subnets**.

Example (illustrative; replace ports and subnets):

```bash
# Main site (HTTPS on host)
sudo ufw allow from any to any port 8443 proto tcp

# Mesh sync locked to VPN or peer subnets only
sudo ufw allow from 10.0.0.0/8 to any port 9443 proto tcp

sudo ufw enable
sudo ufw status verbose
```

If you terminate TLS at a reverse proxy, the proxy listens on **443/tcp** and forwards to Fulla’s `KEYSERVER_BIND` on localhost; firewall rules then protect **443** at the proxy, not necessarily the backend port.

### Outbound

- **SMTP**: usually **587/tcp** (STARTTLS) to your mail provider (`KEYSERVER_SMTP_HOST` / `KEYSERVER_SMTP_PORT`).
- **Mesh peers**: outbound **HTTPS** (or HTTP if configured) toward each peer `address` host and **`sync_api_port`**.
- **Litestream**: whatever your `replica_url` requires (**443** for S3-compatible APIs, **22** for SFTP targets, etc.).

Configure egress rules if your organisation requires explicit allowlists.

## Debugging and troubleshooting

### Structured logs

Fulla logs with **tracing** in **JSON** format by default (`tracing_subscriber` with `fmt().json()` in `main.rs`). To control verbosity:

```bash
export RUST_LOG=info
export RUST_LOG=fulla=debug,sqlx::query=warn
fulla   # or: ./target/release/fulla
```

Use `trace` sparingly on production workloads; it is verbose.

### Process panics and stack traces

```bash
export RUST_BACKTRACE=1
```

For deeper traces:

```bash
export RUST_BACKTRACE=full
```

### Inspect the compiled binary quickly

```bash
cargo build
./target/debug/fulla           # faster compile, easier to debug
cargo build --release
./target/release/fulla
```

### Common failure classes (operator checklist)

- **Missing environment variable**: startup fails with a clear `anyhow` message about the required `KEYSERVER_*` or `DATABASE_URL` name.
- **Mesh enabled but CR-SQLite file missing**: process exits at startup; install the extension and set `crsqlite_extension_path` correctly.
- **SQLite `load_extension` disabled**: CR-SQLite cannot load; you need a SQLite build that enables extension loading (see replication section and upstream CR-SQLite docs).
- **Litestream / SSH enabled but binaries missing**: startup continues; a **warning** is logged and that replication task is **not** started.

### Interactive debugging (developers)

- **gdb / lldb**: attach to the `fulla` process or run `rust-gdb target/debug/fulla` after `cargo build` without `--release`.
- **IDE**: open the crate in an editor with rust-analyzer; set breakpoints in `src/` and run the `fulla` binary under the debugger.

This repository is a standard Rust binary crate; there is no separate debug server.

## Replication

Fulla supports an optional global replication mesh of up to 14 nodes, designed to be placed in separate geographic regions so that no single outage, natural disaster, or network partition can make all registered keys unreachable without recovery paths.

Litestream and SSH/rsync replication provide **additional** offline backup snapshots. **All replication is disabled by default.**

Configuration lives in `[replication]` inside the TOML file pointed at by `FULLA_CONFIG`. Other Fulla settings still come from `.env`/environment variables.

### Designed regions

Place one node in each region for maximum resilience:

1. Northern Europe (Norway, Sweden, Finland)
2. Western Europe (Germany, Netherlands, Belgium)
3. Southern Europe (France, Italy, Spain)
4. Eastern Europe (Poland, Czech Republic, Austria)
5. UK / Ireland
6. Eastern North America (US East Coast, Toronto)
7. Western North America (US West Coast, Vancouver)
8. Canada Central (Montreal, Calgary)
9. South America (Brazil, Argentina)
10. Southern Africa (South Africa)
11. East Africa (Kenya, Tanzania)
12. Middle East (UAE, Israel)
13. East Asia / Southeast Asia (Japan, Singapore, Hong Kong)
14. Oceania (Australia, New Zealand)

Each production node requires on the order of **300 GB** of disk space for the database, WAL, CR-SQLite state, and snapshots.

### Bidirectional mesh sync (CR-SQLite)

[CR-SQLite](https://github.com/vlcn-io/cr-sqlite) gives SQLite CRDT-backed tables. Fulla records local changes under `mesh.enabled = true`; peers periodically exchange logs so a node partitioned from the mesh can accept submissions locally for hours or days and merge cleanly when connectivity returns.

The peer sync listener runs on `sync_api_port` (HTTPS if `sync_tls_cert`/`sync_tls_key` are both set). Endpoints accept only `Authorization: Bearer <sync_authorization_secret>` and are meant for operators’ private meshes, not the public Internet.

Cron-style sync pulls from each configured peer concurrently (up to 13 peers plus the local node, 14 nodes total). After applying remote changes Fulla resolves “same active email twice” collisions by keeping the earliest `submitted_at` and revoking the rest with reason `mesh_conflict`.

Prerequisites:

- Build or install the CR-SQLite loadable extension (`crsqlite.so` / `.dylib` / `.dll`), for example from the [releases](https://github.com/vlcn-io/cr-sqlite/releases).
- SQLite must expose `load_extension` (build with `SQLITE_ENABLE_LOAD_EXTENSION` where applicable).

Enable in `config.toml`:

```toml
[replication.mesh]
enabled = true
node_id_path = "/var/lib/fulla/node_id"
crsqlite_extension_path = "/usr/local/lib/crsqlite.so"
sync_authorization_secret = "long-random-shared-secret"
sync_interval_minutes = 60
sync_api_port = 9443
sync_tls_cert = "/etc/fulla/sync.crt"
sync_tls_key  = "/etc/fulla/sync.key"

[[replication.mesh.peers]]
node_id  = "a1b2c3d4-0000-0000-0000-000000000001"
region   = "Western Europe"
address  = "https://fulla-de.example.com:9443"
# dynamic_dns_host = "router.dyndns.example.com"

# Add one [[replication.mesh.peers]] block per remote peer (max 13).
```

### Disaster recovery (Litestream)

[Litestream](https://litestream.io/) streams SQLite WAL checkpoints to durable object storage or other supported backends. Fulla invokes `litestream replicate -once` on a configurable interval when enabled. Litestream is **not** mesh sync: after a bare-metal rebuild, restore from Litestream, then rely on CR-SQLite to catch up peers.

Requires the `litestream` CLI on `PATH`. If Litestream is enabled but missing, startup logs a warning and the cron is not started.

```toml
[replication.litestream]
enabled = true
replica_url = "s3://mybucket/fulla-node-1"
interval_minutes = 60
# dynamic_dns_host = "dyn.example.com"
```

### SSH / rsync fallback

A simpler alternative or supplement for operators copying the SQLite file directly. Requires `ssh` and `rsync` on `PATH`. If SSH sync is enabled but either binary is missing, startup logs a warning and the cron is not started.

```toml
[replication.ssh]
enabled = true
remote_user = "fulla"
remote_host = "backup.example.com"
remote_path = "/var/lib/fulla/keyserver.db"
ssh_key_path = "/etc/fulla/replication_id_ed25519"
interval_minutes = 60
offset_minutes = 5
```

If both Litestream and SSH are enabled and both run, the first SSH sync is delayed by Litestream’s `interval_minutes` plus SSH `offset_minutes`; later SSH runs repeat every SSH `interval_minutes`.

### Dynamic DNS support

`replication.mesh.peers`, `replication.litestream`, and `replication.ssh` may set `dynamic_dns_host`. Immediately before each cycle Fulla resolves the hostname (`tokio::net::lookup_host`) and substitutes the literal token from the configured URL/host field with the resolved address so changing home IPs are handled transparently.

## Maintainer scope and support

**Project maintainers may not be able to diagnose or fix problems in your deployment, your infrastructure, or third-party components** (CR-SQLite builds, Litestream object storage, SMTP providers, TLS certificates, firewalls, systemd units, or custom patches). They also may **not commit to repairing every defect** in this codebase on your schedule.

Operators should assume **production responsibility** for: backups, replication behaviour, upgrades, dependency supply chain, penetration testing appropriate to their threat model, and incident response.

For **confirmed bugs or security issues** in this repository itself, follow the contribution or security reporting workflow your organisation or the upstream project publishes (GitHub Issues, advisory process, internal fork policy, etc.), and attach minimal reproduction steps plus versions (Rust toolchain, Ubuntu release, `fulla` commit hash, relevant config redacted).

