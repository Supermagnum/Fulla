# Fulla codemap

Guide to how the Fulla registry is structured, which modules own which behaviour, and where to look when changing submission, confirmation, search, or replication.

For operator setup see [README.md](../README.md). For Galdralag client integration see [FULLA_INTEGRATION.md](FULLA_INTEGRATION.md). For executed security probes see [SECURITY_TEST_RESULTS.md](SECURITY_TEST_RESULTS.md).

---

## Overview

Fulla is a single Rust binary (`fulla`) built on **Axum** + **SQLx (SQLite)**. It serves:

- A **web UI** (Minijinja HTML templates)
- A **JSON API** compatible with `galdra keyserver push` / `fetch`
- Optional **CR-SQLite mesh replication**, Litestream, and SSH/rsync backup crons

Every new key registration (first-time or replacement) goes through **mailbox confirmation**: rows live in `pending_submissions` until the recipient opens `/confirm/{token}`. Only then does the key appear in `keys` with `status = 'active'`.

There is **no client authentication** on push/fetch/revoke today; trust comes from OpenPGP validation, email confirmation, per-IP mutation rate limits, and network placement.

---

## Repository layout

```
Fulla/
├── src/
│   ├── main.rs           # Entry, router, TLS bind, background pending cleaner
│   ├── config.rs         # Env + optional FULLA_CONFIG TOML (replication)
│   ├── models.rs         # KeyRecord, SubmitPayload, PendingSubmission, filters
│   ├── db.rs             # All SQLx queries (keys, pending, mesh CR-SQLite)
│   ├── openpgp.rs        # sequoia-openpgp parse/validate/revoke
│   ├── mail.rs           # Outbound SMTP (lettre)
│   ├── templates.rs      # Minijinja loader
│   ├── rate_limit.rs     # Per-IP hourly limit on POST mutations
│   ├── handlers/
│   │   ├── mod.rs        # normalize_base_url
│   │   ├── submit.rs     # POST submit + process_submission core logic
│   │   ├── confirm.rs    # GET confirm/reject token handlers
│   │   ├── revoke.rs     # POST revoke (form + API)
│   │   └── web.rs        # GET pages and key search/detail
│   └── replication/
│       ├── mod.rs        # start() — mesh, Litestream, SSH
│       ├── mesh.rs       # CR-SQLite peer sync HTTP API + cron
│       ├── litestream.rs # Periodic litestream replicate
│       ├── ssh.rs        # rsync over SSH cron
│       └── dns.rs        # Dynamic-DNS resolution for peers
├── migrations/           # Applied automatically on startup (sqlx migrate!)
├── templates/            # HTML + plain-text email bodies
├── docker/               # Fulla + MailHog stack for local/security testing
├── adversarial-tests/    # Black-box HTTP probe binary (fulla-adversarial)
└── docs/                 # Integration, security results, this file
```

---

## Startup sequence

`main()` in `src/main.rs`:

1. Load `.env` (`dotenvy`), init JSON tracing.
2. `Config::from_env()` — required `KEYSERVER_*` and `DATABASE_URL`; optional `FULLA_CONFIG` TOML for replication.
3. Open SQLite pool; optionally load **CR-SQLite extension** on each connection when mesh is enabled.
4. Run `migrations/`; if mesh active: activate CR-SQLite on `keys`, sync peer rows from config.
5. `replication::start()` — spawn mesh sync server/cron, Litestream cron, SSH cron as configured.
6. Build `Mailer`, load `WebTemplates`, construct `MutationRateLimit`.
7. Assemble Axum router (read routes + mutate routes), layers: 128 KiB body limit, compression, trace.
8. Bind plain HTTP or rustls TLS (`KEYSERVER_TLS_CERT` + `KEYSERVER_TLS_KEY`).
9. Spawn `run_pending_cleaner` — hourly `db::expire_pending`.

Shared handler state:

```rust
pub struct AppState {
    pub pool: SqlitePool,
    pub config: Arc<Config>,
    pub mailer: Arc<Mailer>,
    pub templates: Arc<WebTemplates>,
    pub rate_limit: MutationRateLimit,
}
```

---

## HTTP routes

| Method | Path | Handler | Rate limited | Notes |
|--------|------|---------|--------------|-------|
| GET | `/` | `web::index` | No | Home page |
| GET | `/keys` | `web::key_list` | No | Search / list; JSON with `Accept: application/json` |
| GET | `/keys/:fingerprint` | `web::key_detail` | No | 40-char hex fingerprint |
| GET | `/submit` | `web::submit_form` | No | HTML form |
| POST | `/submit` | `submit::handle_form` | **Yes** | Form-urlencoded submit |
| POST | `/api/v1/keys` | `submit::handle_api` | **Yes** | JSON submit (`galdra` push) |
| GET | `/revoke` | `web::revoke_form` | No | HTML form |
| POST | `/revoke` | `revoke::handle_form` | **Yes** | Form revoke |
| POST | `/api/v1/keys/revoke` | `revoke::handle_api` | **Yes** | JSON revoke |
| GET | `/confirm/:token` | `confirm::handle_confirm` | No | 64-char hex token |
| GET | `/reject/:token` | `confirm::handle_reject` | No | Deletes pending row |

Mesh replication (when enabled) adds a **separate listener** on `replication.mesh.sync_api_port` — see [Replication](#replication).

---

## Core flows

### Key submission

```
POST /api/v1/keys  or  POST /submit
        │
        ▼
mutation_rate_guard          (rate_limit.rs)
        │
        ▼
handle_api / handle_form     (submit.rs)
        │
        ▼
process_submission           (submit.rs)  ← unit-tested entry point
        │
        ├─ validate_typed()              field length, email shape
        ├─ parse_and_validate()          (openpgp.rs) — hardware policy + UID email match
        ├─ get_active_key_by_fingerprint — idempotent re-push if identical armored material
        ├─ get_active_keys_by_email
        │     └─ different FP → replacement pending + email_new_key template
        └─ else first signup pending + email_first_signup template
                │
                ▼
        enqueue_pending_confirmation     (submit.rs)
                ├─ has_pending_for_email (db.rs) — LOWER(email), unexpired
                ├─ insert_pending
                └─ mailer.send_plain + Minijinja email body
```

**Outcomes** (`SubmitDecision`):

| Decision | HTTP (API) | Meaning |
|----------|------------|---------|
| `Accepted { fingerprint }` | 200 | Active row already exists with same key bytes |
| `PendingConfirmation` | 202 | Email sent; row in `pending_submissions` |
| Error (validation) | 422 / 400 | OpenPGP, email, field limits, pending duplicate |
| Error (internal) | 500 | SMTP failure, DB errors |

Key functions:

- `process_submission` — business logic without HTTP framing.
- `enqueue_pending_confirmation` — pending guard, DB insert, email render/send.
- `build_pending_submission` — maps parsed cert + payload into `PendingSubmission`.
- `random_token_64_hex` — 256-bit confirm token (32 random bytes, hex).
- `classify_submit_anyhow` — maps errors to status codes and JSON/HTML bodies.

### Mailbox confirmation

```
GET /confirm/:token
        │
        ▼
run_confirm                  (confirm.rs)
        ├─ get_pending(token) — 404 if missing/expired
        ├─ get_active_keys_by_email — if active old key: revoke_key("superseded")
        ├─ insert_key(NewKeyRecord) — email stored lowercase
        └─ delete_pending(token)
```

`handle_reject` deletes the pending row without touching `keys`.

First-time confirm skips revoke when no active key exists for that email.

### Revocation

```
POST /api/v1/keys/revoke
        │
        ▼
run_revoke                   (revoke.rs)
        ├─ cert_from_armored(revocation cert) → fingerprint
        ├─ get_active_key_by_fingerprint
        ├─ email must match registered owner (case-insensitive)
        ├─ apply_and_verify_revocation(stored cert, rev cert)  (openpgp.rs)
        └─ revoke_key(fp, reason)
```

No OpenPGP **challenge** on submit; revoke requires a valid revocation certificate and matching email.

### Key search and detail

`web::key_list` branches on query shape and `Accept` header:

- **JSON + email-only query:** `get_active_keys_by_email` (default) or `get_keys_by_email` when `include_revoked=true`. Returns 404 if empty.
- **HTML + email-only:** all statuses, paginated in memory.
- **Multi-filter query:** `db::list_keys` / `count_keys` via `KeyFilter` — **includes revoked rows** (known gap for JSON multi-filter).

`web::key_detail`:

- `normalize_fingerprint` — strip whitespace, require 40 hex chars, uppercase.
- `get_key_by_fingerprint` — any status.

Helper: `accepts_json_ok(headers)` — true when `Accept` contains `application/json`.

---

## Module reference

### `config.rs`

| Item | Role |
|------|------|
| `Config::from_env()` | Load all `KEYSERVER_*`, `DATABASE_URL`, `KEYSERVER_SMTP_TLS` (default true) |
| `ReplicationConfig` | Parsed from `FULLA_CONFIG` TOML `[replication]` |
| `MeshConfig`, `LitestreamConfig`, `SshSyncConfig` | Sub-sections with `validate()` |
| `sqlite_database_file_path(url)` | Extract on-disk path for replication; `None` for `:memory:` |

Environment variables (required unless noted):

| Variable | Purpose |
|----------|---------|
| `DATABASE_URL` | SQLx SQLite URL |
| `KEYSERVER_BASE_URL` | Public URL for links in confirmation emails |
| `KEYSERVER_BIND` | Listen address (e.g. `0.0.0.0:8080`) |
| `KEYSERVER_SMTP_HOST/PORT/USER/PASSWORD/FROM` | Outbound mail |
| `KEYSERVER_SMTP_TLS` | Optional; `false` for plain SMTP (MailHog) |
| `KEYSERVER_RATE_LIMIT_SUBMISSIONS` | Per-IP hourly POST cap (default 5) |
| `KEYSERVER_TLS_CERT`, `KEYSERVER_TLS_KEY` | Optional native TLS |
| `FULLA_CONFIG` | Optional path to replication TOML |

### `models.rs`

| Type | Use |
|------|-----|
| `KeyRecord` | API/search row; `from_db_row` converts `dmr_id` |
| `DbKeyRow` | SQLx `FromRow` mirror |
| `NewKeyRecord` | Insert on confirm |
| `PendingSubmission` | Staging row before confirm |
| `SubmitPayload` | JSON API body |
| `PushResponseJson` | Standard API error/success envelope |
| `KeyFilter` | Multi-column search in `list_keys` |

### `db.rs`

**Keys table**

| Function | Description |
|----------|-------------|
| `insert_key` | New active row on confirm |
| `get_key_by_fingerprint` | Any status |
| `get_active_key_by_fingerprint` | `status = 'active'` only |
| `get_keys_by_email` / `get_active_keys_by_email` | `LOWER(email)` match |
| `revoke_key` | Set `status = 'revoked'`, timestamps |
| `list_keys`, `count_keys` | Dynamic `KeyFilter` query builder |

**Pending table**

| Function | Description |
|----------|-------------|
| `insert_pending` | Stage submission |
| `has_pending_for_email` | Case-insensitive; checks `expires_at >= now` |
| `get_pending`, `delete_pending` | Token lookup / cleanup |
| `expire_pending` | Hourly housekeeping |

**CR-SQLite mesh** (when extension loaded)

| Function | Description |
|----------|-------------|
| `crsql_activate_keys` | Enable CRDT on `keys` |
| `pull_crsql_changes_since`, `apply_crsql_wire_rows` | Change feed exchange |
| `resolve_mesh_email_conflicts` | Post-sync email uniqueness |
| `mesh_peer_states`, `update_mesh_peer_progress` | Peer cursor tracking |
| `upsert_mesh_peers_from_config`, `prune_mesh_peers` | Config-driven peer list |

All queries use bound parameters (sqlx); fingerprint path traversal returns 404 from normal routing/validation.

### `openpgp.rs`

| Function | Description |
|----------|-------------|
| `parse_and_validate(armored, email)` | Parse cert, enforce Galdralag hardware policy, match submitted email to a User ID (`eq_ignore_ascii_case`) |
| `policy_check_keys` | Reject RSA, Ed25519, Brainpool P-512, etc.; allow Cv25519, NIST P-256/P-384, Brainpool P-384 |
| `deny_self_revoked` | Reject certs with revocation signatures |
| `apply_and_verify_revocation` | Apply rev cert to stored cert; extract reason |
| `cert_from_armored`, `cert_fingerprint_hex` | Helpers for revoke path |

Max upload size: 128 KiB (also enforced at HTTP layer).

### `mail.rs`

| Function | Description |
|----------|-------------|
| `Mailer::new` | TLS relay (`AsyncSmtpTransport::relay`) or plain (`builder_dangerous`) when `KEYSERVER_SMTP_TLS=false` |
| `send_plain(to, subject, body)` | Single-part text email |

### `rate_limit.rs`

| Function | Description |
|----------|-------------|
| `MutationRateLimit::new(per_hour)` | `governor` keyed limiter by source IP |
| `mutation_rate_guard` | Axum middleware on mutate router; 429 JSON or plain text |
| `rate_over_response` | Content negotiation for limit responses |

Uses `ConnectInfo<SocketAddr>`; falls back to loopback if missing.

### `templates.rs`

Loads templates once at startup from `templates/` (or `CARGO_MANIFEST_DIR/templates`). Logical names map to files — e.g. `email_first_signup` → `email/first_signup_notification.txt`. `render(name, ctx)` for HTML pages and email bodies.

### `handlers/submit.rs`

Form bridge: `SubmitFormFields::into_payload()` parses optional numeric `dmr_id`.

Validation helpers: `validate_rfc_like_email`, `validate_typed` (field max lengths — note 4096 for `note`).

Email templates receive sidecar JSON (callsign, organisation, role, badge_number, etc.) plus `confirm_url` / `reject_url` built with `normalize_base_url`.

### `handlers/confirm.rs`

`run_confirm` is `pub(crate)` for integration tests. Errors: `ConfirmError::Gone` (404) vs `Internal` (500).

### `handlers/revoke.rs`

`RevErr` distinguishes missing key (404), user/validation (422), internal (500).

### `handlers/web.rs`

`KeyBrowseQuery` — query parameters for `/keys`. `WebErr` — typed handler errors (400/404/500).

---

## Database schema

Migrations run in order (`001` … `008`):

| Migration | Adds |
|-----------|------|
| `001_keys.sql` | `keys` table, indexes on email/fingerprint/callsign/dmr_id |
| `002_pending.sql` | `pending_submissions` |
| `003_radio_affiliation.sql` | `radio_affiliation` column |
| `004_postal_sidecar.sql` | Address fields |
| `005_optional_name_fluxer_discord_irc.sql` | Contact/social sidecar |
| `006_mesh_peers.sql` | Mesh peer state table |
| `007_mesh_peer_push_cursor.sql` | Push cursor column |
| `008_contact_org_role_note.sql` | `organisation`, `role`, `note`, `badge_number` |

`keys.status`: `'active'` or `'revoked'`. Pending rows expire after 72 hours (set in `pending_expires_at_rfc3339`).

---

## Replication

Configured via `FULLA_CONFIG` TOML, validated in `ReplicationConfig::validate()`.

### CR-SQLite mesh (`replication/mesh.rs`)

When `replication.mesh.enabled`:

- Loads CR-SQLite `.so` from `crsqlite_extension_path`.
- Spawns HTTPS (or HTTP) sync API on `sync_api_port` with bearer auth (`sync_authorization_secret`).
- Endpoints exchange CR-SQLite wire-format changes; cron pulls from configured peers (max 13 peers).
- `resolve_mesh_email_conflicts` after apply — keeps one active key per normalized email across nodes.
- `dns.rs` resolves `dynamic_dns_host` tokens in peer addresses.

### Litestream (`replication/litestream.rs`)

Periodic `litestream replicate` to `replica_url` if binary on PATH.

### SSH/rsync (`replication/ssh.rs`)

Periodic rsync of SQLite file to remote host; offset from Litestream interval to avoid overlap.

`replication::start` is non-blocking — spawns background tasks only.

---

## Middleware and limits

Applied to the merged router in `main.rs`:

| Layer | Effect |
|-------|--------|
| `RequestBodyLimitLayer(128 KiB)` | HTTP 413 on oversized bodies |
| `CompressionLayer` | Response compression |
| `TraceLayer` | Request/response tracing |
| `mutation_rate_guard` | Only on POST submit/revoke routes |

Read paths (`GET /keys`, etc.) are **not** rate limited.

---

## Security testing harness

Not part of the production binary:

| Path | Role |
|------|------|
| `docker/` | Compose stack: Fulla + MailHog, `run-adversarial.sh` |
| `adversarial-tests/` | `fulla-adversarial` binary — malformed input, rate limit, identity/homoglyph, confirm flow |

See [SECURITY_TEST_RESULTS.md](SECURITY_TEST_RESULTS.md) for executed results.

Known behaviour documented there:

- Case-variant emails share one pending slot (`LOWER`).
- Unicode homoglyphs do **not** — separate pending rows possible.
- Multi-filter JSON search may return revoked keys.

---

## Where to change what

| Goal | Start here |
|------|------------|
| Add API field to submit/fetch | `models.rs`, `submit.rs` validation, `db.rs` insert/list, migration, templates |
| Change confirmation email text | `templates/email/*.txt`, `enqueue_pending_confirmation` context |
| Tighten OpenPGP policy | `openpgp.rs` `policy_check_keys` |
| Add auth to an endpoint | New middleware or handler checks in `handlers/`; no existing pattern |
| Fix pending duplicate logic | `db::has_pending_for_email`, `enqueue_pending_confirmation` |
| Mesh sync behaviour | `replication/mesh.rs`, `db.rs` CR-SQLite helpers |
| Rate limit scope | `main.rs` mutate router, `rate_limit.rs` |

---

## Related documents

| Document | Content |
|----------|---------|
| [FULLA_INTEGRATION.md](FULLA_INTEGRATION.md) | Galdralag `galdra keyserver` client, deployment posture |
| [SECURITY_TEST_RESULTS.md](SECURITY_TEST_RESULTS.md) | Docker adversarial run output |
| [../docker/README.md](../docker/README.md) | Local MailHog stack |
| [../adversarial-tests/README.md](../adversarial-tests/README.md) | How to run probes |
