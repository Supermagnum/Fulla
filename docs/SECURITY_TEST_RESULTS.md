# Adversarial security test results (executed)

Real results from the Docker adversarial harness. Not predicted or static-review output.

**Run date:** 2026-07-03  
**Repository path:** Fulla @ adversarial harness + first-time confirmation flow  
**Runner:** `./docker/run-adversarial.sh` (two consecutive fresh-stack runs)

## Environment

| Item | Value |
|------|--------|
| Host OS | Linux 6.17.0-35-generic (Ubuntu 24.04 base), x86_64 |
| Container runtime | Podman 4.9.3 via `DOCKER_HOST=unix:///run/user/1000/podman/podman.sock` (`docker` CLI emulates Docker) |
| Compose | docker-compose 1.29.2 |
| Fulla image | `docker/Dockerfile` multi-stage build (Rust 1 bookworm → debian bookworm-slim) |
| Mail sink | MailHog v1.0.1 (`docker.io/mailhog/mailhog:v1.0.1`) |
| Fulla endpoint | `http://127.0.0.1:8080/` (HTTP 200 on `/`) |
| MailHog UI | `http://127.0.0.1:8025/` (HTTP 200) |

### Stack startup

After harness fixes (see below), `docker compose up -d --build` starts both services cleanly. SQLite file appears at `docker/data/keyserver.db`. No panics on boot. Example startup log line:

```json
{"timestamp":"2026-07-03T00:51:53.972597Z","level":"ERROR","fields":{"message":"submit api failure","error":"SMTP send failed: internal client error: Envelope contains non-ascii chars but server does not support SMTPUTF8"},"target":"fulla::handlers::submit"}
```

That ERROR appears only during the homoglyph probe (see Findings), not during container boot.

### Harness adjustments required to execute (not product silent fixes)

These were needed so Podman/MailHog/SQLite could run the suite; they are documented here rather than assumed:

1. **`DATABASE_URL=sqlite:/data/keyserver.db?mode=rwc`** — without `?mode=rwc`, sqlx returned SQLite code 14 (unable to open database file) in the container.
2. **`KEYSERVER_SMTP_TLS=false`** — default lettre relay STARTTLS against MailHog caused `InvalidContentType` and HTTP 500 on confirmation email send.
3. **`KEYSERVER_RATE_LIMIT_SUBMISSIONS=50`** — full suite sends many POSTs before the rate-limit probe; limit=5 caused earlier tests to receive HTTP 429. The probe sends `limit + 2` requests and expects HTTP 429 on the last (52nd with limit=50).
4. **Bind mount `docker/data:/data`** — Podman rootless named volume could not open SQLite reliably in this environment.

## Results table (Run A and Run B — identical)

| Category | Test | Result | Detail |
|----------|------|--------|--------|
| malformed | oversized_request_body | PASS | HTTP 413 Payload Too Large |
| malformed | bad_openpgp | PASS | HTTP 422 with reason |
| malformed | oversized_note_field | PASS | HTTP 422 |
| malformed | invalid_utf8_json | PASS | HTTP 400 Bad Request |
| malformed | fingerprint_path_short | PASS | HTTP 400 |
| malformed | fingerprint_path_non_hex | PASS | HTTP 400 |
| malformed | fingerprint_path_traversal | PASS | HTTP 404 |
| malformed | fingerprint_path_sqli | PASS | HTTP 400 |
| identity | email_case_variant_pending_guard | PASS | `USER-…@EXAMPLE.COM` blocked while `user-…@example.com` pending (`LOWER(email)`) |
| identity | unicode_homoglyph_pending_guard | **FINDING** | HTTP 500 — pending guard did not block Cyrillic `е` homoglyph local part; second pending inserted; SMTP fails without SMTPUTF8 |
| tokens | confirm_once | PASS | HTTP 200 |
| tokens | confirm_replay | PASS | second GET `/confirm/{token}` returns HTTP 404 |
| tokens | token_timing_side_channel | SKIP | avg wrong confirm ~0.000s vs wrong reject ~0.000s (256-bit token) |
| automated | json_fuzz_0 | PASS | HTTP 422 |
| automated | json_fuzz_1 | PASS | HTTP 422 |
| automated | json_fuzz_2 | PASS | HTTP 422 |
| automated | json_fuzz_3 | PASS | HTTP 422 |
| automated | search_revoked_filter_gap | KNOWN_GAP | multi-filter GET `/keys` includes revoked rows |
| automated | slow_partial_post | PASS | connection closed or completed within ~8.0s |
| rate_limit | mutate_per_ip_hourly | PASS | 52nd submit returned HTTP 429 (limit=50) |
| rate_limit | read_side_unlimited | KNOWN_GAP | 40 rapid GET `/keys` returned no HTTP 429 |

**Summary:** 21 tests, **1 finding**, 2 known gaps, 1 skip — same on both runs (not flaky).

## Predicted vs actual discrepancies

| Test | Prior prediction (static review) | Actual | Notes |
|------|----------------------------------|--------|-------|
| oversized_request_body | 413 or 422 | **413** | Matches `RequestBodyLimitLayer` |
| email_case_pending_guard | PASS | **PASS** | Case variant correctly blocked with 422 |
| mutate_per_ip_hourly | 429 on 7th with limit=5 | **429 on 52nd with limit=50** | Suite uses higher limit so earlier POST probes are not starved; probe uses `limit + 2` |
| json_fuzz_* | PASS (non-500) | **422** | Stricter than minimum expectation |
| confirm flow | PASS | **PASS** | Required SMTP plain + quoted-printable URL parsing in test harness |
| unicode homoglyph | Theoretical FINDING, not automated | **FINDING confirmed** | See below |
| First run before harness fixes | — | SMTP TLS / DB URL failures | Not counted as product regressions; environment configuration |

## Findings requiring a decision

### 1. Unicode homoglyph bypass of `has_pending_for_email` (NEW)

**Probe:** Register `user-{id}@example.com` (pending). Re-submit `usеr-{id}@example.com` (Cyrillic U+0435 replacing Latin `e`) with a matching OpenPGP User ID.

**Observed:**

- Case-variant re-submit returns HTTP **422** with reason containing `confirmation is already pending` — expected.
- Homoglyph re-submit returns HTTP **500** (`Internal error.`). Server log: `Envelope contains non-ascii chars but server does not support SMTPUTF8`.
- The 500 occurs **after** `insert_pending` (mail send is last in `enqueue_pending_confirmation`), so a **second pending row** is created for the homoglyph mailbox while the Latin mailbox remains pending.

**Root cause:** `has_pending_for_email` uses `LOWER(email)` only. Confusable Unicode characters are not normalized, so visually similar mailboxes are treated as distinct.

**Not fixed in this pass** — report only. Possible directions: Unicode confusable mapping (e.g. UTS #39), punycode/IDNA normalization policy, or operator acceptance for open registries.

### 2. Non-ASCII mailbox SMTP (related)

Homoglyph mailboxes trigger SMTPUTF8 requirement. Many relays (including MailHog in tests) do not advertise SMTPUTF8, producing HTTP 500 after DB insert. Production deployments accepting internationalized mailboxes need SMTPUTF8-capable relay configuration.

## Known gaps (unchanged, confirmed)

- No rate limit on read paths (`GET /keys`, etc.).
- Multi-filter search can return revoked keys without an active-only filter.

## Reproduce

```bash
export DOCKER_HOST=unix:///run/user/1000/podman/podman.sock   # Podman rootless
systemctl --user start podman.socket
./docker/run-adversarial.sh
```

Exit code **1** when any row is **FINDING** (expected with current homoglyph result).
