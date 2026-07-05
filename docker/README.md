# Docker test stack (Fulla + MailHog)

Brings up Fulla on **http://localhost:8080** with SMTP delivered to **MailHog** (mail UI **http://localhost:8025**).

## Start

```bash
cd docker
docker compose up -d --build
```

Wait until healthy (`docker compose ps` shows healthy for `fulla`, or `curl -sf http://127.0.0.1:8080/` succeeds).

## Reset state (fresh DB + mail sink)

```bash
cd docker
docker compose down -v
docker compose up -d --build
```

This removes bind-mounted SQLite under `docker/data/` and clears MailHog's in-memory store on restart.

## Configuration notes

- **TLS:** disabled in this stack (plain HTTP). Production should terminate TLS at a reverse proxy or via `KEYSERVER_TLS_*`.
- **SQLite:** `DATABASE_URL=sqlite:/data/keyserver.db?mode=rwc` in `fulla.env` (`?mode=rwc` required for sqlx file creation in-container).
- **SMTP:** MailHog on port 1025; `KEYSERVER_SMTP_TLS=false` for plain SMTP. MailHog does not support SMTPUTF8.
- **Rate limit:** `KEYSERVER_RATE_LIMIT_SUBMISSIONS=50`, `KEYSERVER_RATE_LIMIT_READS=500`, and `KEYSERVER_RATE_LIMIT_SUBMISSIONS_GLOBAL=5000` so the adversarial suite can finish before the 429 probes (see `docs/SECURITY_TEST_RESULTS.md`).

## Run full adversarial pipeline

From the repository root:

```bash
./docker/run-adversarial.sh
```

Stages (exit 1 on any blocking finding):

1. **`docker/run-supply-chain.sh`** — `cargo audit` + `cargo deny check`
2. **Docker stack** — `docker compose up -d --build` (Fulla + MailHog)
3. **`docker/run-scanners.sh`** — trivy, nuclei, nikto, sqlmap, OWASP ZAP baseline (via Docker images when host tools absent)
4. **Custom probes** — `adversarial-tests/` Rust harness

Supply-chain only (no Docker):

```bash
./docker/run-supply-chain.sh
```

Scanner stage only (stack must already be up):

```bash
./docker/run-scanners.sh
```

## View confirmation emails

1. Submit a key via the web form or `POST /api/v1/keys`.
2. Open **http://localhost:8025**.
3. Open the latest message; follow the **confirm** link (uses `KEYSERVER_BASE_URL` from `fulla.env`, default `http://localhost:8080`).

For links inside MailHog to work from your browser, `KEYSERVER_BASE_URL` must match how you reach Fulla (usually `http://localhost:8080`, not the Docker service name).
