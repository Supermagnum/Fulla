# Galdralag client integration with Fulla

This document describes how **Galdralag** components (`galdra`, devices running **galdrad**) should interact with a **Fulla** key registry over HTTP. It complements the operator-focused [README](../README.md) and the Docker adversarial stack in [docker/README.md](../docker/README.md).

**GUI and third-party clients:** see **[API.md](API.md)** for complete request/response schemas, status codes, and search parameters.

Fulla on GitHub: [Supermagnum/Fulla](https://github.com/Supermagnum/Fulla).  
Galdralag firmware / `galdra`: [Supermagnum/Galdralag-firmware](https://github.com/Supermagnum/Galdralag-firmware).

---

## Design intent: open registry vs closed deployment

Fulla defaults to a **public keyserver-style registry**: anyone who can produce a valid Galdralag-profile OpenPGP certificate with a matching email User ID may **request** registration. **Mailbox confirmation** (link in email) is required before a key becomes **active** and searchable. That model suits a community registry.

A **closed registry** (only authorized operators or devices may submit/revoke) uses the same HTTP API but sets:

```bash
KEYSERVER_MUTATION_AUTH_SECRET="your-long-shared-secret-min-16-chars"
```

When set, `POST /submit`, `POST /api/v1/keys`, `POST /revoke`, and `POST /api/v1/keys/revoke` require `Authorization: Bearer <secret>`. **GET** search, detail, confirm, and reject paths stay public so confirmation links in email continue to work without embedding the secret.

Layered controls for private deployments:

- **`KEYSERVER_MUTATION_AUTH_SECRET`** — application-level closed submit/revoke (recommended for operator-only registries).
- **Network placement** — firewall/VPN, reverse-proxy allowlists (still recommended even when auth is enabled).
- **TLS** — terminate at a reverse proxy or via Fulla's built-in rustls (`KEYSERVER_TLS_*`).

Fetch (`GET /keys`, `GET /keys/{fingerprint}`) remains unauthenticated by design so Galdra devices and the web UI can look up keys without provisioning API tokens on every handset.

---

## How `galdra keyserver` talks to Fulla today

From the Galdralag-firmware `galdra` sources (`galdra/src/commands/keyserver/`):

| Operation | HTTP | Client authentication |
|-----------|------|------------------------|
| **push** | `POST {base}/api/v1/keys` JSON | **None** by default; `Authorization: Bearer` when `KEYSERVER_MUTATION_AUTH_SECRET` is set |
| **fetch** | `GET {base}/keys?email=` or `GET {base}/keys/{fingerprint}` with `Accept: application/json` | **None** |
| **revoke** | `POST {base}/api/v1/keys/revoke` JSON | Same optional Bearer as push |

The HTTP client is **reqwest** (blocking), with **rustls** for HTTPS. There is **no** custom client certificate, token header, or request signing on push/fetch.

Push exports the token's OpenPGP **public certificate** from the device (`Device`, slot) via **sequoia-openpgp**, then POSTs JSON including `email`, `armored_public_key`, and optional sidecar fields.

---

## Configuring `[keyserver]` / CLI for your Fulla instance

In Galdralag host config (TOML) or environment:

```toml
[keyserver]
url = "https://keys.example.com"
```

Or per invocation:

```bash
galdra keyserver push --keyserver-url https://keys.example.com --slot 1 --email you@example.com
```

Resolution order in `galdra`: `--keyserver-url` → `GALDRA_KEYSERVER_URL` → `[keyserver].url`.

### TLS verification

- **HTTPS:** reqwest uses the **platform/WebPKI trust store** by default (rustls). Public CA certificates work out of the box.
- **Private CA or self-signed:** the stock `galdra` client does **not** expose a documented custom CA bundle or certificate pin in the keyserver module. For lab use with the Docker stack, use **plain HTTP** on localhost. For production with a private CA, terminate TLS at a reverse proxy with a public cert, or extend `galdra`/reqwest to trust your CA (not yet in upstream keyserver client).
- **Plain HTTP:** allowed for Fulla local/dev; Galdralag's **HKP/WKD** helpers reject plain `http://` for *those* protocols, but the Fulla registry client uses the URL you configure for push/fetch.

### Fulla base URL

Set Fulla's `KEYSERVER_BASE_URL` to the **public URL users click in confirmation emails** (e.g. `https://keys.example.com`), not an internal Docker service name.

---

## Push / fetch behaviour after mailbox confirmation

### Push responses

| `status` | Meaning |
|----------|---------|
| `pending_confirmation` | Email sent; key **not** searchable until recipient confirms (normal for **first registration** and **replacement**). HTTP **202**. |
| `accepted` | Key already **active** with identical material (idempotent re-push). HTTP **200**. |
| `error` | Validation failure; see `reason`. Often HTTP **422**. |

**CLI UX gap:** `galdra keyserver push` prints the message and exits. There is **no** `galdra keyserver status` or poll for pending submissions. The operator must **check email** and open the confirm link (or use MailHog in Docker tests). After confirmation, `galdra keyserver fetch --email …` should return the key.

### Fetch

- `GET /keys?email=` with `Accept: application/json` returns **active** keys only by default (`include_revoked=true` optional).
- Pending keys never appear in fetch results.

### Revoke

Fulla exposes `POST /api/v1/keys/revoke` (OpenPGP revocation certificate). **`galdra keyserver revoke` is not implemented** in Galdralag-firmware as of this writing; use the web form or API directly.

---

## Recommended deployment posture

1. **TLS:** Prefer reverse proxy (nginx/Caddy) on `:443` → Fulla `KEYSERVER_BIND` on localhost, or Fulla native rustls with operator-managed certs.
2. **Firewall:** Public `:443` (or your chosen port) for users; **do not** expose mesh `sync_api_port` (see README replication section).
3. **SMTP:** Real provider for confirmation mail in production; MailHog only for Docker tests. Set `KEYSERVER_SMTP_TLS=false` for plain SMTP sinks (MailHog). For non-ASCII recipient addresses, the relay must support **SMTPUTF8**.
4. **Rate limits:** `KEYSERVER_RATE_LIMIT_SUBMISSIONS` (per-IP hourly on POST submit/revoke). **`KEYSERVER_RATE_LIMIT_SUBMISSIONS_GLOBAL` defaults to 300/hour** when unset (`0` disables) — caps cluster-wide registration spam that bypasses per-IP limits via botnets or rotating proxies. Optional `KEYSERVER_RATE_LIMIT_READS_GLOBAL`. Read paths are limited per IP via `KEYSERVER_RATE_LIMIT_READS` (default 1200/hour; `0` disables). Confirm/reject links are exempt. One pending row per **canonical** mailbox identity limits confirmation-mail spam.
5. **Spam vs openness:** Open self-registration inherently trades spam-resistance for accessibility. Per-IP and global rate limits are **mitigations**, not guarantees against distributed abuse. For deployments where unsolicited registration spam is unacceptable, set **`KEYSERVER_MUTATION_AUTH_SECRET`** (closed registry — Bearer on POST submit/revoke only; fetch/confirm stay public). Proof-of-work was not added: it would complicate Galdra handset push and the web form without replacing the need for mailbox confirmation.
6. **Private single-operator:** Same software; restrict who can reach the listener. Open submission remains possible for anyone on that network unless you add front-door controls.
7. **Open / community registry:** If you accept public self-registration, be aware that confusable Unicode mailboxes can each obtain a separate pending confirmation for the same human operator unless you add IDNA/confusable normalization or manual review. Internationalized mailbox addresses also require an **SMTPUTF8**-capable relay.
8. **Supply chain:** Run `docker/run-supply-chain.sh` (or `cargo audit` + `cargo deny check`) before deploy. CI runs both on every push (`.github/workflows/ci.yml`).

---

## CR-SQLite mesh replication (operators)

Fulla’s optional mesh sync is configured via `[replication.mesh]` in `FULLA_CONFIG` (see [README replication section](../README.md#replication)). This is separate from Galdra client push/fetch on `:8080`.

### CR-SQLite native extension integrity

`replication.mesh.crsqlite_extension_path` is loaded via SQLite `load_extension` — unmanaged native code inside the Fulla process.

- Startup rejects group/world-writable extension files (Unix).
- Optional `crsqlite_extension_sha256` in `config.toml` pins the binary before load.
- Install as root/service user, mode `0755` or stricter; see `src/extension_integrity.rs`.

### Staged rollout and truncation fail-closed (protocol v2)

Mesh sync **protocol version 2** paginates `GET /sync/changes` using:

- Query: `limit`, `protocol_version=2`
- Response headers: `X-Mesh-Protocol-Version`, `X-Changes-Truncated: true` when a page is full

**Routine mixed-version rollouts are supported when the backlog fits in one page.** If a pull receives fewer rows than `sync_max_changes_per_request`, sync completes normally even when the peer omits `X-Mesh-Protocol-Version` (pre-v2). This is the expected state while upgrading a 14-node geographic mesh one node at a time with modest change volume.

**Fail closed on silent truncation risk:** When a pull receives a **full page** (`batch_len >= sync_max_changes_per_request`) from a peer on **protocol version below 2** (missing or `< 2`), Fulla **aborts that sync cycle**:

- The batch is **not applied**
- `last_sync_db_version` / `our_push_cursor` in `mesh_peers` are **not advanced**
- The cron logs **`tracing::error!`** with a distinct `TruncationBlockedError` message (visible in the same surfaces as other failed peer sync cycles)
- The next scheduled sync interval retries automatically

During a staged rollout you may see **short-term, expected** truncation-block errors on nodes that still lag behind while a large backlog exists — sync cursors stall until the peer upgrades or the backlog shrinks below one page. **Ignore these briefly** while rolling out. If the same peer hits **3+ consecutive** truncation-block failures, logs escalate to an **upgrade-now** message — treat a persistently stalled peer as requiring immediate upgrade (late-propagating revocations are a real security consequence).

Once all peers run protocol v2, full pages continue with pagination until the backlog is drained.

### CR-SQLite wire format compatibility

The JSON body exchanged on `/sync/changes` and `/sync/apply` (`CrsqlWireChange` rows) is **unchanged**. Protocol version is negotiated only via HTTP query parameters and response headers.

| Scenario | Behaviour |
|----------|-----------|
| New puller, small batch from old sender | **Allowed** — sync completes; no truncation-block. |
| New puller, full page from old sender | **Fail closed** — `TruncationBlockedError`; cursor unchanged; retry next cycle. |
| Old puller → new sender (full page) | Old node may still stop after one page — upgrade the old puller. |
| New ↔ new (full page) | Pagination continues until under-limit batch; truncation logged at `warn`. |

Keep mesh `sync_api_port` off the public Internet regardless of version.

### Email conflict resolution (`mesh_conflict`)

When two active `keys` rows share the same normalized email after mesh merge, Fulla keeps **one** row and revokes the others with `revocation_reason = 'mesh_conflict'`.

**Trust boundary:** Mailbox control is the recovery authority. Whether **this node** processed `GET /confirm/{token}` for a key is witnessed locally and cannot be forged via mesh replication. Replicated column data (`submitted_at`, fingerprint) is asserted peer data and must not drive precedence alone.

| Tier | Precedence | Attacker with mesh inject only |
|------|------------|--------------------------------|
| 1 | Exactly one **locally confirmed** row on this node | Cannot win — needs mailbox confirmation on this node |
| 2 | Both locally confirmed on this node | Earliest `confirmed_at` (server-set at confirm time) |
| 3 | Neither locally confirmed on this node | Earliest `first_seen_at` (local observation clock; `INSERT OR IGNORE`, not mesh-writable) |

**Local-only tables** (`key_local_confirmations`, `key_local_first_seen`): created by migration `010_key_local_provenance.sql`, **not** registered with `crsql_as_crr`. `apply_crsql_wire_rows` only inserts into `crsql_changes`; hostile wire rows targeting these table names do not populate local provenance.

**Why not fingerprint?** Victim fp is public via `GET /keys?email=`. Attacker generates Cv25519/Ed25519 keypairs until `fp_attacker < fp_victim` — ~50% per attempt, ~2 tries average, milliseconds of CPU. Same class of “free” attack as backdated `submitted_at`.

**Why not `submitted_at`?** Set server-side at confirm but **replicates as-is** through CR-SQLite; hostile peer can inject backdated values.

| Policy | Peer-compatibility |
|--------|-------------------|
| Pre-fix: earliest `submitted_at` | Vulnerable to backdated replication |
| Interim: lowest fingerprint | Vulnerable to trivial fingerprint grinding |
| Current: local-confirm / first-seen | **Algorithm + local schema change** — upgrade all mesh nodes together; mixed old/new can diverge on replication-only tier |

**Recovery if wrongly revoked:** Fulla does **not** send email on `mesh_conflict` revocation. The affected party can **re-register** via normal submit (`POST /api/v1/keys`): if another active key holds the email, the replacement confirmation flow emails the mailbox; after confirm, the legitimate key supersedes the attacker (`confirm.rs` revokes prior active with `superseded`). Mailbox control remains the recovery authority.

---

## Worked example (Docker + MailHog)

This matches the stack in [docker/README.md](../docker/README.md).

### 1. Start Fulla and MailHog

```bash
cd docker
docker compose up -d --build
```

### 2. Push from a token (on host with `galdra` installed)

```bash
export GALDRA_KEYSERVER_URL=http://127.0.0.1:8080
galdra keyserver push --slot 1 --email you@example.com
```

Expect output like: `Confirmation email sent to the submitted address.` (or JSON `pending_confirmation`).

### 3. Confirm via email

1. Open **http://localhost:8025** (MailHog).
2. Open the latest message from `fulla@test.local`.
3. Click **confirm** (link targets `http://localhost:8080/confirm/…` per `docker/fulla.env`).

Alternatively submit via curl:

```bash
curl -sS -X POST http://127.0.0.1:8080/api/v1/keys \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -d '{"email":"you@example.com","armored_public_key":"-----BEGIN PGP PUBLIC KEY BLOCK-----..."}'
```

### 4. Fetch back

```bash
galdra keyserver fetch --email you@example.com --output json
```

Or:

```bash
curl -sS 'http://127.0.0.1:8080/keys?email=you@example.com' -H 'Accept: application/json'
```

### 5. Run adversarial suite

```bash
./docker/run-adversarial.sh
```

---

## Cross-links

| Document | Repository |
|----------|------------|
| This file | Fulla `docs/FULLA_INTEGRATION.md` |
| Operator README | Fulla `README.md` |
| Docker + MailHog | Fulla `docker/README.md` |
| Adversarial test results (executed) | Fulla `docs/SECURITY_TEST_RESULTS.md` |
| HTTP API reference (GUI / third-party) | Fulla `docs/API.md` |
| `galdra keyserver` implementation | Galdralag-firmware `galdra/src/commands/keyserver/` |

When updating Galdralag-firmware, add a short pointer in that repo's docs (e.g. `docs/FULLA.md`) linking here for registry URL, `pending_confirmation`, and fetch semantics.
