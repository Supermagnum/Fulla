# Adversarial security test results (executed)

Real results from the Docker adversarial harness. Not predicted or static-review output.

**Run date:** 2026-07-05  
**Repository path:** Fulla @ security hardening (read limits, homoglyph pending guard)  
**Runner:** `./docker/run-adversarial.sh` (fresh stack)

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

### Harness configuration

| Setting | Value |
|---------|--------|
| `KEYSERVER_RATE_LIMIT_SUBMISSIONS` | 50 (Docker env; probe expects 429 on 52nd POST) |
| `KEYSERVER_RATE_LIMIT_READS` | 500 (Docker env; probe expects 429 on 502nd GET) |
| `KEYSERVER_SMTP_TLS` | false (MailHog plain SMTP) |
| `DATABASE_URL` | `sqlite:/data/keyserver.db?mode=rwc` |

## Results table

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
| identity | email_case_variant_pending_guard | PASS | `User@Example.com` blocked while `user@example.com` pending |
| identity | unicode_homoglyph_pending_guard | PASS | HTTP 422 — pending guard blocks Cyrillic homoglyph when Latin pending exists |
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
| rate_limit | read_side_per_ip_hourly | PASS | 502nd GET `/keys` returned HTTP 429 (limit=500) |

**Summary:** 21 tests, **0 findings**, 1 known gap, 1 skip. Exit code **0**.

## Resolved since 2026-07-03 run

| Issue | Fix |
|-------|-----|
| Unicode homoglyph bypass of pending guard | `email_canonical` column + `email_normalize.rs` (UTS #39 confusables on non-ASCII code points) |
| No read-side rate limit | `KEYSERVER_RATE_LIMIT_READS` (default 1200/hour per IP; `0` disables); confirm/reject exempt |
| RFC3339 expiry comparison | `datetime(expires_at)` in `has_pending_for_email` and `expire_pending` |

## Known gaps (unchanged)

- Multi-filter search can return revoked keys without an active-only filter.

## Reproduce

```bash
export DOCKER_HOST=unix:///run/user/1000/podman/podman.sock   # Podman rootless
systemctl --user start podman.socket
./docker/run-adversarial.sh
```

Exit code **1** when any row is **FINDING**; **0** when all probes pass or only KNOWN_GAP/SKIP remain.
