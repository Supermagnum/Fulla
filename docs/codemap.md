# Fulla codemap

Guide to how the Fulla registry is structured, which modules own which behaviour, and where to look when changing submission, confirmation, search, or replication.

For operator setup see [README.md](../README.md). For Galdralag client integration see [FULLA_INTEGRATION.md](FULLA_INTEGRATION.md). For **GUI / third-party HTTP clients** see [API.md](API.md). For executed security probes see [SECURITY_TEST_RESULTS.md](SECURITY_TEST_RESULTS.md).

---

## Overview

Fulla is a single Rust binary (`fulla`) built on **Axum** + **SQLx (SQLite)**. It serves:

- A **web UI** (Minijinja HTML templates)
- A **JSON API** compatible with `galdra keyserver push` / `fetch`
- Optional **CR-SQLite mesh replication**, Litestream, and SSH/rsync backup crons

Every new key registration (first-time or replacement) goes through **mailbox confirmation**: rows live in `pending_submissions` until the recipient opens `/confirm/{token}`. Only then does the key appear in `keys` with `status = 'active'`.

There is **no client authentication** on fetch/confirm by default; optional **`KEYSERVER_MUTATION_AUTH_SECRET`** gates POST submit/revoke for closed registries. Trust also comes from OpenPGP validation (including SKS-poisoning structural limits), email confirmation, per-IP (and optional global) rate limits, and network placement.

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
│   ├── auth.rs             # Optional Bearer auth on mutation routes
│   ├── email_normalize.rs # Mailbox identity canonicalization (case + confusables)
│   ├── rate_limit.rs     # Per-IP and optional global rate limits (mutate + read)
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
6. Build `Mailer`, load `WebTemplates`, construct `RateLimits` from config.
7. Assemble Axum router (read routes split: limited vs confirm/reject exempt; mutate routes), layers: 128 KiB body limit, compression, trace.
8. Bind plain HTTP or rustls TLS (`KEYSERVER_TLS_CERT` + `KEYSERVER_TLS_KEY`).
9. Spawn `run_pending_cleaner` — hourly `db::expire_pending`.

Shared handler state:

```rust
pub struct AppState {
    pub pool: SqlitePool,
    pub config: Arc<Config>,
    pub mailer: Arc<Mailer>,
    pub templates: Arc<WebTemplates>,
    pub rate_limits: RateLimits,
}
```

---

## HTTP routes

| Method | Path | Handler | Rate limited | Notes |
|--------|------|---------|--------------|-------|
| GET | `/` | `web::index` | Optional | Home page |
| GET | `/keys` | `web::key_list` | Optional | Search / list; JSON with `Accept: application/json` |
| GET | `/keys/:fingerprint` | `web::key_detail` | Optional | 40-char hex fingerprint |
| GET | `/submit` | `web::submit_form` | Optional | HTML form |
| POST | `/submit` | `submit::handle_form` | **Yes** | Form-urlencoded submit |
| POST | `/api/v1/keys` | `submit::handle_api` | **Yes** | JSON submit (`galdra` push) |
| GET | `/revoke` | `web::revoke_form` | Optional | HTML form |
| POST | `/revoke` | `revoke::handle_form` | **Yes** | Form revoke |
| POST | `/api/v1/keys/revoke` | `revoke::handle_api` | **Yes** | JSON revoke |
| GET | `/confirm/:token` | `confirm::handle_confirm` | No | 64-char hex token; exempt from read limit |
| GET | `/reject/:token` | `confirm::handle_reject` | No | Deletes pending row; exempt from read limit |

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
                ├─ has_pending_for_email (db.rs) — `email_canonical`, unexpired
                ├─ insert_pending (stores `email` + `email_canonical`)
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
| `insert_pending` | Stage submission; writes `email_canonical` |
| `has_pending_for_email` | Matches `email_canonical` (case + non-ASCII confusables); `datetime(expires_at)` |
| `get_pending`, `delete_pending` | Token lookup / cleanup |
| `expire_pending` | Hourly housekeeping (`datetime(expires_at) < datetime('now')`) |

**CR-SQLite mesh** (when extension loaded)

| Function | Description |
|----------|-------------|
| `crsql_activate_keys` | Enable CRDT on `keys` |
| `pull_crsql_changes_since`, `apply_crsql_wire_rows` | Change feed exchange; apply calls `observe_keys_from_wire_rows` for `first_seen_at` |
| `record_local_key_confirmation` | Set only from `confirm.rs` after local mailbox confirm |
| `record_key_first_seen_if_absent`, `observe_keys_from_wire_rows` | Local observation clock for mesh-only conflict tier |
| `resolve_mesh_email_conflicts`, `mesh_conflict_pick_winner` | Post-sync email uniqueness (local-confirm / first-seen) |
| `mesh_peer_states`, `update_mesh_peer_progress` | Peer cursor tracking |
| `upsert_mesh_peers_from_config`, `prune_mesh_peers` | Config-driven peer list |

All queries use bound parameters (sqlx); fingerprint path traversal returns 404 from normal routing/validation.

### `openpgp.rs`

| Function | Description |
|----------|-------------|
| `parse_and_validate(armored, email, policy)` | Parse cert, enforce Galdralag hardware policy + structural limits (`CertPolicy`), match email to User ID |
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

### `email_normalize.rs`

| Function | Description |
|----------|-------------|
| `normalize_email_identity(raw)` | Lowercase trim; ASCII left as-is; non-ASCII chars mapped via UTS #39 confusables data |

Used by `insert_pending` and `has_pending_for_email`. Does **not** rewrite ASCII letters (whole-string skeleton would map `m` → `rn`).

### `rate_limit.rs`

| Function | Description |
|----------|-------------|
| `RateLimits::from_config` | Per-IP mutate/read + optional global limiters from env |
| `mutation_rate_guard` | Axum middleware on mutate router; 429 JSON or plain text |
| `read_rate_guard` | Axum middleware on read router (except confirm/reject) |
| `rate_over_response` | Content negotiation for limit responses |

Uses `ConnectInfo<SocketAddr>`; falls back to loopback if missing.

Env: `KEYSERVER_RATE_LIMIT_SUBMISSIONS` (default 5), `KEYSERVER_RATE_LIMIT_READS` (default 1200; `0` disables), `KEYSERVER_RATE_LIMIT_SUBMISSIONS_GLOBAL` (default **300**/hour; `0` disables), optional `KEYSERVER_RATE_LIMIT_READS_GLOBAL`.

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

Migrations run in order (`001` … `010`):

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
| `009_pending_email_canonical.sql` | Canonical email column for homoglyph defense |
| `010_key_local_provenance.sql` | `key_local_confirmations`, `key_local_first_seen` (local-only, not CR-SQLite) |

`keys.status`: `'active'` or `'revoked'`. Pending rows expire after 72 hours (set in `pending_expires_at_rfc3339`).

---

## Replication

Configured via `FULLA_CONFIG` TOML, validated in `ReplicationConfig::validate()`.

### CR-SQLite mesh (`replication/mesh.rs`)

When `replication.mesh.enabled`:

- Loads CR-SQLite `.so` from `crsqlite_extension_path` after `extension_integrity::validate_native_extension` (permission + optional SHA-256 pin).
- Spawns HTTPS (or HTTP) sync API on `sync_api_port` with constant-time bearer auth (`sync_authorization_secret`, min 16 chars).
- **`GET /sync/changes`** — paginated (`limit`, `protocol_version=2` query); response headers `X-DB-Version`, `X-Mesh-Protocol-Version`, `X-Changes-Truncated`. Peer cron pages until batch smaller than limit. **Fail closed:** full page from pre-v2 peer aborts sync (`TruncationBlockedError`, cursor unchanged). Small batches allowed during staged rollout.
- **`POST /sync/apply`** — batched apply capped by `sync_max_changes_per_request`; `RequestBodyLimitLayer` (`sync_max_body_bytes`); optional global rate limit.
- Cron pulls/pushes in pages from configured peers (max 13 peers).
- `resolve_mesh_email_conflicts` after apply — keeps one active key per normalized email using local-confirm / first-seen precedence (`key_local_confirmations`, `key_local_first_seen`); revokes others as `mesh_conflict`
- `dns.rs` resolves `dynamic_dns_host` tokens in peer addresses.

**Peer compatibility:** JSON wire format unchanged; all nodes must page. Mixed versions that ignore truncation headers could miss changes.

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
| `mutation_rate_guard` | POST submit/revoke routes |
| `read_rate_guard` | GET pages/search (when read limits enabled); confirm/reject exempt |

Read paths are rate limited when `KEYSERVER_RATE_LIMIT_READS` or `KEYSERVER_RATE_LIMIT_READS_GLOBAL` is set (default 1200/hour per IP). Set `KEYSERVER_RATE_LIMIT_READS=0` to disable per-IP read limits.

---

## Security testing harness

Not part of the production binary:

| Path | Role |
|------|------|
| `docker/` | Compose stack: Fulla + MailHog, `run-adversarial.sh` |
| `adversarial-tests/` | `fulla-adversarial` binary — malformed input, rate limit, identity/homoglyph, confirm flow |

See [SECURITY_TEST_RESULTS.md](SECURITY_TEST_RESULTS.md) for executed results.

Known behaviour documented there:

- Case-variant and confusable Unicode emails share one pending slot (`email_canonical`).
- Multi-filter JSON search may return revoked keys.

Migration `009_pending_email_canonical.sql` adds `email_canonical` to `pending_submissions`.

---

## Where to change what

| Goal | Start here |
|------|------------|
| Add API field to submit/fetch | `models.rs`, `submit.rs` validation, `db.rs` insert/list, migration, templates |
| Change confirmation email text | `templates/email/*.txt`, `enqueue_pending_confirmation` context |
| Add auth to an endpoint | `auth.rs` (`mutation_auth_guard`), `main.rs` mutate router |
| Tighten OpenPGP policy / SKS limits | `openpgp.rs` `CertPolicy`, `check_cert_structure`, `config.rs` `KEYSERVER_MAX_CERT_*` |
| Fix pending duplicate logic | `email_normalize.rs`, `db::has_pending_for_email`, `enqueue_pending_confirmation` |
| Mesh sync behaviour | `replication/mesh.rs`, `db.rs` CR-SQLite helpers |
| Rate limit scope | `main.rs` read/mutate routers, `rate_limit.rs`, `config.rs` |

---

## Related documents

| Document | Content |
|----------|---------|
| [API.md](API.md) | HTTP API for GUI and third-party clients |
| [FULLA_INTEGRATION.md](FULLA_INTEGRATION.md) | Galdralag `galdra keyserver` client, deployment posture |
| [SECURITY_TEST_RESULTS.md](SECURITY_TEST_RESULTS.md) | Docker adversarial run output |
| [../docker/README.md](../docker/README.md) | Local MailHog stack |
| [../adversarial-tests/README.md](../adversarial-tests/README.md) | How to run probes |
