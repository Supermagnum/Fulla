# Fulla HTTP API reference

Machine-readable reference for **GUI clients**, desktop tools, and any third-party integration with a Fulla key registry.

For deployment context and Galdralag CLI behaviour see [FULLA_INTEGRATION.md](FULLA_INTEGRATION.md). For internal module layout see [codemap.md](codemap.md).

---

## Overview

| Property | Value |
|----------|--------|
| Base URL | Operator-configured (e.g. `https://keys.example.com`) |
| API prefix | `/api/v1/` for JSON mutations; reads use `/keys` |
| Authentication | **None** on push, fetch, or revoke |
| Content type | `application/json` for API endpoints |
| Request body limit | **128 KiB** (HTTP 413 if exceeded) |
| TLS | Recommended in production; plain HTTP allowed for local dev |

Send **`Accept: application/json`** on read endpoints to receive JSON instead of HTML.

---

## Typical GUI client workflow

```
1. User exports OpenPGP public key (armored) from token or key manager
2. GUI POST /api/v1/keys  →  status pending_confirmation (202)
3. User opens confirmation email and clicks link (browser)
   GET /confirm/{token}  →  key becomes active
4. GUI polls GET /keys?email=…  until key appears (or user confirms manually)
5. Optional: POST /api/v1/keys/revoke with revocation certificate
```

There is **no** API to list or poll pending submissions. After push, the GUI should tell the user to check email. Confirmation links target `KEYSERVER_BASE_URL` on the server (must be reachable from the user's browser).

---

## Endpoints summary

| Method | Path | Rate limited | JSON | Purpose |
|--------|------|--------------|------|---------|
| POST | `/api/v1/keys` | Yes | Request + response | Register or replace key |
| POST | `/api/v1/keys/revoke` | Yes | Request + response | Revoke active key |
| GET | `/keys?…` | No | Response (with `Accept`) | Search / list keys |
| GET | `/keys/{fingerprint}` | No | Response (with `Accept`) | Key by fingerprint |
| GET | `/confirm/{token}` | No | Optional response | Confirm pending registration (usually browser) |
| GET | `/reject/{token}` | No | Optional response | Reject pending registration |

HTML-only helpers (same origin, no JSON API): `GET /`, `GET /submit`, `POST /submit`, `GET /revoke`, `POST /revoke`.

---

## POST `/api/v1/keys` — register or replace

Submit an OpenPGP public key for mailbox confirmation.

### Request headers

```
Content-Type: application/json
Accept: application/json
```

### Request body (`SubmitPayload`)

Required fields:

| Field | Type | Description |
|-------|------|-------------|
| `email` | string | Mailbox to confirm; must match a User ID on the certificate (case-insensitive) |
| `armored_public_key` | string | ASCII-armored OpenPGP **public** certificate |

Optional sidecar fields (all omitted or null if unused):

| Field | Type | Max length / rules |
|-------|------|-------------------|
| `first_name` | string | 64 characters |
| `last_name` | string | 64 characters |
| `callsign` | string | 2–16 ASCII alphanumeric |
| `dmr_id` | integer | 1–16777215 |
| `radio_affiliation` | string | 128 characters |
| `fluxer_id` | string | 128 characters |
| `discord_id` | string | 32 characters |
| `irc_id` | string | 128 characters |
| `street` | string | 512 characters |
| `country` | string | 128 characters |
| `postal_code` | string | 32 characters |
| `region` | string | 128 characters |
| `organisation` | string | 128 characters |
| `role` | string | 128 characters |
| `note` | string | 4096 characters |
| `badge_number` | string | 64 characters |

Minimal example:

```json
{
  "email": "operator@example.com",
  "armored_public_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----"
}
```

Full example with sidecar:

```json
{
  "email": "operator@example.com",
  "armored_public_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
  "first_name": "Alex",
  "last_name": "Example",
  "callsign": "LB1ABC",
  "dmr_id": 1234567,
  "organisation": "Example Radio Club",
  "role": "operator",
  "badge_number": "42"
}
```

### Success responses (`PushResponseJson`)

**Already active (idempotent re-push)** — HTTP **200**

```json
{
  "status": "accepted",
  "fingerprint": "A1B2C3D4E5F6..."
}
```

**Confirmation email sent** — HTTP **202**

First registration and fingerprint replacement both return this. Key is **not** searchable until confirmed.

```json
{
  "status": "pending_confirmation",
  "message": "Confirmation email sent to the submitted address."
}
```

### Error responses — HTTP **422** (`PushResponseJson`)

```json
{
  "status": "error",
  "reason": "Email address 'x' does not match any User ID on the certificate."
}
```

Common `reason` strings (non-exhaustive):

- Email validation failures (`Email address has invalid length.`, etc.)
- OpenPGP parse / policy failures (`Invalid OpenPGP certificate`, `Algorithm … is not supported by Galdralag hardware.`)
- User ID mismatch
- Field length / callsign / DMR ID validation messages
- `A confirmation is already pending for this email address.`
- `This fingerprint already has an active entry with different key material.`

### Other errors

| HTTP | Body | Cause |
|------|------|--------|
| 413 | (empty or plain) | Request body &gt; 128 KiB |
| 429 | `{"status":"error","reason":"Rate limit exceeded."}` | Per-IP hourly mutation limit |
| 500 | `{"status":"error","reason":"Internal error."}` | SMTP failure, database error, etc. |

### Server behaviour notes

- Email stored as **lowercase** after confirm; pending guard uses **canonical identity** (lowercase + Unicode confusable mapping per UTS #39).
- Certificate email match uses **case-insensitive** ASCII comparison against normalized User ID emails.
- Pending rows expire after **72 hours** (server housekeeping).

---

## GET `/keys` — search and list

### Request headers

```
Accept: application/json
```

Without this header the server returns HTML pages.

### Query parameters

| Parameter | Type | Match semantics |
|-----------|------|-----------------|
| `email` | string | Case-insensitive **exact** email |
| `fingerprint` | string | **Prefix** on fingerprint (whitespace stripped, prefix uppercased) |
| `callsign` | string | Case-insensitive **exact** |
| `dmr_id` | integer | **Exact** |
| `discord_id`, `irc_id`, `fluxer_id` | string | **Exact** (trimmed) |
| `first_name`, `last_name` | string | Case-insensitive **substring** |
| `page` | integer | Default `1` (multi-filter / HTML paths) |
| `per_page` | integer | Default `25`, max `200` |
| `include_revoked` | boolean | Only applies to **email-only** JSON lookup; default false |

Multiple parameters are combined with **AND**.

### Response shapes

**Email-only JSON lookup** (`?email=…` and no other filters):

- HTTP **200**: one `KeyRecord` object if exactly one row, or a **JSON array** if multiple.
- HTTP **404**: no matching keys.
- Default: **active** keys only. Set `include_revoked=true` to include revoked rows.

**Multi-filter JSON lookup** (any filter besides email alone, or email plus other filters):

- HTTP **200**: JSON **array** of `KeyRecord` (may be empty).
- Includes **revoked** rows when present (no active-only filter on this path).

**Pagination**: email-only JSON returns all matches (no `page`). Multi-filter JSON uses `page` / `per_page` internally but returns a flat array for the current page only (no total count in JSON).

### `KeyRecord` response object

| Field | Type | Always present | Description |
|-------|------|----------------|-------------|
| `fingerprint` | string | yes | 40-char hex, uppercase |
| `armored_key` | string | yes | Canonical armored public key |
| `email` | string | yes | Registered mailbox |
| `submitted_at` | string | yes | RFC 3339 timestamp |
| `status` | string | yes | `active` or `revoked` |
| `first_name`, `last_name` | string | no | Display name |
| `callsign` | string | no | Radio callsign |
| `dmr_id` | integer | no | DMR radio ID |
| `radio_affiliation` | string | no | |
| `fluxer_id`, `discord_id`, `irc_id` | string | no | Contact IDs |
| `street`, `country`, `postal_code`, `region` | string | no | Postal sidecar |
| `organisation`, `role`, `note`, `badge_number` | string | no | Org / role sidecar |
| `revoked_at` | string | no | RFC 3339 when revoked |
| `revocation_reason` | string | no | |

Omitted optional fields are absent from JSON (not `null`).

Example:

```json
{
  "fingerprint": "A1B2C3D4E5F6789012345678901234567890ABCD",
  "armored_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...",
  "email": "operator@example.com",
  "callsign": "LB1ABC",
  "dmr_id": 1234567,
  "submitted_at": "2026-07-03T12:00:00+00:00",
  "status": "active"
}
```

---

## GET `/keys/{fingerprint}` — key detail

### Path parameter

- **40 hexadecimal characters** (whitespace allowed in URL; stripped server-side).
- Returns HTTP **400** if malformed.

### Response

- HTTP **200**: single `KeyRecord` (any status, including revoked).
- HTTP **404**: unknown fingerprint.

Send `Accept: application/json` for JSON; otherwise HTML detail page.

---

## POST `/api/v1/keys/revoke` — revoke

Revoke an **active** key using an OpenPGP revocation certificate.

### Request body

```json
{
  "email": "operator@example.com",
  "armored_revocation_cert": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `email` | string | Must match registered owner (case-insensitive) |
| `armored_revocation_cert` | string | Armored revocation certificate for the key |

The server derives the fingerprint from the revocation cert, loads the active key, verifies the cert revokes that key cryptographically, then marks the row revoked.

### Success — HTTP **200**

```json
{
  "status": "ok"
}
```

### Errors

| HTTP | Body | Meaning |
|------|------|---------|
| 404 | `{"status":"error","reason":"No active key for that fingerprint."}` | No active row for cert fingerprint |
| 422 | `{"status":"error","reason":"…"}` | Email mismatch, invalid revocation material, etc. |
| 429 | `{"status":"error","reason":"Rate limit exceeded."}` | Rate limit |
| 500 | `{"status":"error","reason":"Internal error."}` | Server error |

---

## GET `/confirm/{token}` and `/reject/{token}`

Used from confirmation emails. Token is **64 lowercase hex characters** (256-bit).

### Browser (default)

- **Confirm**: HTTP 200 HTML success page; promotes pending row to active key.
- **Reject**: HTTP 200 HTML; deletes pending row.
- Unknown or expired token: HTTP **404** HTML.

### JSON (`Accept: application/json`)

**Confirm success** — HTTP 200:

```json
{
  "status": "confirmed"
}
```

**Reject success** — HTTP 200:

```json
{
  "status": "rejected"
}
```

**Missing / expired token** — HTTP 404:

```json
{
  "status": "error",
  "reason": "Not found."
}
```

A GUI normally does **not** call these endpoints directly; the user's mail client opens the link. Programmatic confirm is possible if the GUI obtains the token (e.g. custom mail integration).

---

## OpenPGP requirements

Keys must be valid OpenPGP **public** certificates acceptable to Galdralag hardware policy (`openpgp.rs`):

| Algorithm | Policy |
|-----------|--------|
| **Cv25519 / X25519** | Allowed (typical Galdralag keys) |
| **Ed25519** | Allowed for signing |
| **NIST P-256, P-384** | Allowed |
| **Brainpool P-256, P-384, P-512** | Allowed |
| **RSA** | Allowed if ≥ 2048 bits |
| **DSA, ElGamal, Ed25519-only ECDH, Brainpool P-512 for ECDH, etc.** | Rejected |

Additional rules:

- Maximum armored upload **128 KiB**
- Self-revoked certificates rejected at registration
- Submitted `email` must match a certificate User ID (`eq_ignore_ascii_case` after normalization)
- Revocation must be a valid hard revocation verifiable against the stored certificate

---

## Rate limiting

Applies to **POST** `/api/v1/keys`, `/api/v1/keys/revoke`, and form POST equivalents.

| Variable | Default | Scope |
|----------|---------|--------|
| `KEYSERVER_RATE_LIMIT_SUBMISSIONS` | `5` | Per source IP, rolling hour |
| `KEYSERVER_RATE_LIMIT_SUBMISSIONS_GLOBAL` | `300` | Global hourly cap on POST submit/revoke (`0` disables). Default on since v0.1 hardening round 12 |
| `KEYSERVER_RATE_LIMIT_READS` | `1200` | Per source IP on `GET /`, `/keys`, `/keys/{fp}`, form pages. Set `0` to disable |
| `KEYSERVER_RATE_LIMIT_READS_GLOBAL` | (off) | Optional global hourly cap on those GET paths |

**Excluded from read limits:** `GET /confirm/{token}` and `GET /reject/{token}` (one-shot email links).

When limited, JSON clients receive:

```json
{
  "status": "error",
  "reason": "Rate limit exceeded."
}
```

HTTP status **429**.

---

## Error envelope

Most JSON errors from mutation endpoints use:

```json
{
  "status": "error",
  "reason": "Human-readable message."
}
```

Success mutations use `status` of `accepted`, `pending_confirmation`, or `ok` (revoke). Optional fields `fingerprint` and `message` appear on push success responses.

---

## GUI implementation checklist

1. **Base URL** — configurable; use HTTPS in production.
2. **Push** — POST minimal or full `SubmitPayload`; handle 200, 202, 422, 429, 413.
3. **Confirmation UX** — explain email step; no status poll API exists.
4. **Fetch** — poll `GET /keys?email=` with `Accept: application/json` after user confirms; handle 404 as "not yet active".
5. **Fingerprint fetch** — `GET /keys/{fp}` for detail views.
6. **Search UI** — map filters to query params; remember multi-filter JSON may return revoked keys.
7. **Revoke** — collect email + armored revocation cert; POST revoke API.
8. **Errors** — display `reason` from JSON body.
9. **No secrets** — do not expect API keys or OAuth; optional network-layer access control only.

---

## Related documents

| Document | Audience |
|----------|----------|
| [FULLA_INTEGRATION.md](FULLA_INTEGRATION.md) | Galdralag operators, TLS, deployment |
| [SECURITY_TEST_RESULTS.md](SECURITY_TEST_RESULTS.md) | Known gaps (read rate limit, homoglyph pending, revoked filter) |
| [codemap.md](codemap.md) | Contributors changing server code |
| [../README.md](../README.md) | Build, configure, operate Fulla |
