# Galdralag client integration with Fulla

This document describes how **Galdralag** components (`galdra`, devices running **galdrad**) should interact with a **Fulla** key registry over HTTP. It complements the operator-focused [README](../README.md) and the Docker adversarial stack in [docker/README.md](../docker/README.md).

**GUI and third-party clients:** see **[API.md](API.md)** for complete request/response schemas, status codes, and search parameters.

Fulla on GitHub: [Supermagnum/Fulla](https://github.com/Supermagnum/Fulla).  
Galdralag firmware / `galdra`: [Supermagnum/Galdralag-firmware](https://github.com/Supermagnum/Galdralag-firmware).

---

## Design intent: open registry vs private deployment

Fulla is built as a **public keyserver-style registry**: anyone who can produce a valid Galdralag-profile OpenPGP certificate with a matching email User ID may **request** registration. **Mailbox confirmation** (link in email) is required before a key becomes **active** and searchable. That model suits a community registry.

A **single-operator private deployment** (your tokens, your Fulla instance) still uses the same API, but you typically:

- Restrict network access (firewall/VPN, reverse proxy allowlists).
- Terminate **TLS** at a reverse proxy or via Fulla's built-in rustls (`KEYSERVER_TLS_*`).
- Accept that **push/fetch carry no client authentication** today; security relies on OpenPGP validation, confirmation email, and network placement—not on mTLS or API keys.

If you need a **closed** registry (only your devices may submit), Fulla does not enforce that in application code yet; use network policy or a front proxy. See the auth design discussion in project issues/docs for challenge-signature revoke and optional hardening.

---

## How `galdra keyserver` talks to Fulla today

From the Galdralag-firmware `galdra` sources (`galdra/src/commands/keyserver/`):

| Operation | HTTP | Client authentication |
|-----------|------|------------------------|
| **push** | `POST {base}/api/v1/keys` JSON | **None** (no `Authorization` header) |
| **fetch** | `GET {base}/keys?email=` or `GET {base}/keys/{fingerprint}` with `Accept: application/json` | **None** |

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
4. **Rate limits:** `KEYSERVER_RATE_LIMIT_SUBMISSIONS` (per-IP hourly on POST submit/revoke). Optional global caps via `KEYSERVER_RATE_LIMIT_SUBMISSIONS_GLOBAL` and `KEYSERVER_RATE_LIMIT_READS_GLOBAL`. Read paths (`GET /keys`, etc.) are limited per IP via `KEYSERVER_RATE_LIMIT_READS` (default 1200/hour; `0` disables). Confirm/reject links are exempt. One pending row per **canonical** mailbox identity (case + Unicode confusables) limits confirmation spam.
5. **Private single-operator:** Same software; restrict who can reach the listener. Open submission remains possible for anyone on that network unless you add front-door controls.
6. **Open / community registry:** If you accept public self-registration, be aware that confusable Unicode mailboxes can each obtain a separate pending confirmation for the same human operator unless you add IDNA/confusable normalization or manual review. Internationalized mailbox addresses also require an **SMTPUTF8**-capable relay.

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
