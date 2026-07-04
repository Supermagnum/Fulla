-- Canonical mailbox identity for pending guard (case + Unicode confusables).
ALTER TABLE pending_submissions ADD COLUMN email_canonical TEXT;

UPDATE pending_submissions SET email_canonical = LOWER(TRIM(email)) WHERE email_canonical IS NULL;

CREATE INDEX IF NOT EXISTS idx_pending_email_canonical ON pending_submissions(email_canonical);
