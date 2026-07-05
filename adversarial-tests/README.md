# Adversarial HTTP tests

Black-box security probes against a **running** Fulla instance. Requires the Docker stack in [`../docker/`](../docker/README.md).

## Run

```bash
# from repository root
./docker/run-adversarial.sh
```

Environment:

| Variable | Default |
|----------|---------|
| `FULLA_BASE_URL` | `http://127.0.0.1:8080` |
| `MAILHOG_API` | `http://127.0.0.1:8025` |

Exit code **1** if any row is marked **FINDING** (not for **KNOWN_GAP** or **SKIP**).

Executed results (not predictions): [docs/SECURITY_TEST_RESULTS.md](../docs/SECURITY_TEST_RESULTS.md).

## Expected results (static review — superseded for run data)

When Docker is available, the suite prints a markdown table. The table below is from implementation review only; **real executed results** are in `docs/SECURITY_TEST_RESULTS.md`.

| Category | Test | Expected |
|----------|------|----------|
| malformed | oversized_request_body | PASS (413 or 422 via `RequestBodyLimitLayer` / validation) |
| malformed | bad_openpgp | PASS (422, not 500) |
| malformed | oversized_note_field | PASS (422, 4096 char limit) |
| malformed | invalid_utf8_json | PASS (4xx, not 500) |
| malformed | fingerprint_path_* | PASS (400/404; sqlx parameterized queries) |
| malformed | bloated_cert_excess_* | PASS (HTTP 422 on excess UIDs/subkeys) |
| malformed | sks_poison_uid_selfsig_flood | PASS (HTTP 422; raw import stream per-UID self-sig cap) |
| rate_limit | email_case_pending_guard | PASS (`email_canonical` pending guard) |
| rate_limit | mutate_per_ip_hourly | PASS (429 on 6th+ with limit=5) |
| rate_limit | read_side_per_ip_hourly | PASS when `KEYSERVER_RATE_LIMIT_READS` > 0 (default 1200; Docker harness uses 500) |
| identity | unicode_homoglyph_pending_guard | PASS (422 when Cyrillic homoglyph matches pending Latin mailbox) |
| automated | json_fuzz_* | PASS (no 500 on bad JSON) |
| automated | search_revoked_filter_gap | PASS (multi-filter active-only; include_revoked opt-in) |
| automated | slow_partial_post | PASS or informational (tokio/axum body read) |
| tokens | confirm_once / confirm_replay | PASS (404 on second confirm) |
| tokens | token_timing_side_channel | **SKIP** (harness timing resolution too coarse; see SECURITY_TEST_RESULTS.md) |

Set `FULLA_EXPECT_READ_RATE_LIMIT=500` (or match `KEYSERVER_RATE_LIMIT_READS` in `docker/fulla.env`) when running via `./docker/run-adversarial.sh`.
