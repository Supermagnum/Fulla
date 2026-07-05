# SMTP and outbound mail

Fulla uses **outbound SMTP only** to deliver mailbox confirmation and rejection links. It does **not** receive inbound mail and does **not** require you to run a full mail server on the same host.

This document explains what is mandatory at startup, what is mandatory for registration to work, and how to configure production SMTP versus local testing with MailHog.

See also: [README](../README.md) (operator overview), [FULLA_INTEGRATION.md](FULLA_INTEGRATION.md) (Galdra client flow), [REPLICATION.md](REPLICATION.md) (mesh replication), [docker/README.md](../docker/README.md) (disposable test stack).

---

## Do I need a mail server?

| Question | Answer |
|----------|--------|
| Must SMTP settings be present to **start** Fulla? | **Yes.** All `KEYSERVER_SMTP_*` variables are required at startup (`Config::from_env` in `src/config.rs`). |
| Must mail actually **deliver** for the registry to work? | **Yes**, for any path that publishes a new or replacement key. Submissions stay in `pending_submissions` until the mailbox owner confirms via the link in email. |
| Must I **host** my own mail server? | **No.** Any outbound SMTP relay works (provider API, corporate relay, transactional mail service). |
| Does Fulla need **inbound** SMTP (MX records, IMAP)? | **No.** Confirm and reject are ordinary HTTP `GET` requests to your public `KEYSERVER_BASE_URL`. |

---

## How mailbox confirmation uses mail

Every new registration (`POST /submit`, `POST /api/v1/keys`) and every **replacement** of an existing email's active fingerprint follows the same flow:

1. Fulla validates the OpenPGP material and inserts a row in `pending_submissions` (72-hour expiry).
2. Fulla sends a confirmation email to the submitted mailbox (or the address on file for replacements).
3. The recipient opens **`GET /confirm/:token`** to publish the key as **active**, or **`GET /reject/:token`** to discard the pending row.
4. Until step 3 succeeds, the key is **not** in `keys` and does not appear in search or fetch.

Re-submitting the **same** fingerprint and armored material while the key is already active is **idempotent**: Fulla returns **`accepted`** without sending mail.

Only one unexpired pending row is allowed per canonical email at a time.

### What works if SMTP is misconfigured or mail never arrives

These paths do **not** require a successful outbound send:

- Browsing and searching **already active** keys (`GET /keys`, fetch by fingerprint, HTML listings).
- Idempotent re-submit of identical active key material (`accepted`, no email).

These paths **do** require working outbound mail:

- First-time registration.
- Replacement when a different active fingerprint already holds the email.
- Any flow that returns **`pending_confirmation`** (HTTP 202).

If SMTP credentials are wrong or the relay blocks messages, submissions accumulate in `pending_submissions` and expire after 72 hours without ever becoming searchable.

### Closed registry does not skip email

`KEYSERVER_MUTATION_AUTH_SECRET` restricts **who may POST** submit and revoke (Bearer token). It does **not** bypass mailbox confirmation. Confirm and reject links remain public HTTP endpoints so email recipients do not need the secret.

---

## Environment variables

All of the following are **required** for the process to start. Copy from [`.env.example`](../.env.example) and adjust for your deployment.

| Variable | Purpose |
|----------|---------|
| `KEYSERVER_SMTP_HOST` | SMTP relay hostname |
| `KEYSERVER_SMTP_PORT` | SMTP port (often **587** for STARTTLS) |
| `KEYSERVER_SMTP_USER` | Authentication username (may be empty string if your relay allows unauthenticated local delivery — still set the variable) |
| `KEYSERVER_SMTP_PASSWORD` | Authentication password |
| `KEYSERVER_SMTP_FROM` | Envelope / From address Fulla uses for confirmation mail |
| `KEYSERVER_SMTP_TLS` | Optional; defaults to **`true`**. Set **`false`** for plain SMTP (MailHog, some internal relays) |

Related (not SMTP, but required for correct confirmation links):

| Variable | Purpose |
|----------|---------|
| `KEYSERVER_BASE_URL` | Public URL embedded in confirmation emails (e.g. `https://keys.example.com`). Must match how users reach Fulla in a browser — not an internal Docker service name. |

Implementation: `src/mail.rs` (`Mailer`), invoked from `src/handlers/submit.rs` after a pending row is stored.

---

## Production setup

Typical configuration:

```bash
KEYSERVER_BASE_URL=https://keys.example.com
KEYSERVER_SMTP_HOST=smtp.example.com
KEYSERVER_SMTP_PORT=587
KEYSERVER_SMTP_USER=keyserver@example.com
KEYSERVER_SMTP_PASSWORD=secret
KEYSERVER_SMTP_FROM=keyserver@example.com
# KEYSERVER_SMTP_TLS defaults to true (STARTTLS on port 587)
```

Checklist:

1. **Outbound firewall:** allow **587/tcp** (or your provider's port) from the Fulla host to the relay.
2. **SPF / DKIM / DMARC:** configure at your DNS and mail provider so confirmation mail is not classified as spam.
3. **`KEYSERVER_BASE_URL`:** must be the HTTPS URL users click in email (usually the same host as your reverse proxy).
4. **Internationalized mailboxes:** if submitters use non-ASCII addresses, the relay must support **SMTPUTF8**. Many production providers do; MailHog does **not**.

Fulla does not ship provider-specific integration (SendGrid templates, SES API keys, etc.) — only standard SMTP via [lettre](https://github.com/lettre/lettre).

---

## Local development and testing (MailHog)

The Docker test stack includes **MailHog** as a fake SMTP sink. No real mail infrastructure is required for development or the adversarial harness.

```bash
cd docker
docker compose up -d --build
```

| Service | URL / port |
|---------|------------|
| Fulla | http://localhost:8080 |
| MailHog web UI | http://localhost:8025 |
| MailHog SMTP | `mailhog:1025` (inside compose) / `localhost:1025` (from host) |

`docker/fulla.env` points Fulla at MailHog:

```bash
KEYSERVER_BASE_URL=http://localhost:8080
KEYSERVER_SMTP_HOST=mailhog
KEYSERVER_SMTP_PORT=1025
KEYSERVER_SMTP_TLS=false
```

After submitting a key, open the MailHog UI and follow the **confirm** link in the latest message.

See [docker/README.md](../docker/README.md) for reset, adversarial runs, and troubleshooting compose networking.

---

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| Process exits on startup with missing env | One of `KEYSERVER_SMTP_*` is unset. All are required even for read-only intent. |
| Submit returns `pending_confirmation` but no email | Wrong `KEYSERVER_SMTP_HOST` / credentials; relay blocking; mail in spam. Check Fulla logs (`tracing`) for SMTP errors from `mail.rs`. |
| Confirm link 404 or wrong host | `KEYSERVER_BASE_URL` does not match the URL users use (common Docker mistake: internal hostname instead of `http://localhost:8080`). |
| Submit works in Docker but links fail from browser | `KEYSERVER_BASE_URL` must be reachable from the **user's machine**, not only from inside the compose network. |
| Internationalized address fails to send | Relay lacks SMTPUTF8; use ASCII mailbox or a UTF-8-capable provider. |

Confirm and reject endpoints are **not** rate-limited the same way as search; they must stay reachable when the user clicks the email link.

---

## Network summary

| Direction | Protocol | When |
|-----------|----------|------|
| Outbound | SMTP (usually 587/tcp STARTTLS) | Every new or replacement submission that enters `pending_submissions` |
| Inbound | HTTP(S) on `KEYSERVER_BIND` | User clicks confirm/reject link in email |

Fulla never listens for SMTP.
