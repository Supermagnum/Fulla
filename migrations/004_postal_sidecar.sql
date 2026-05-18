ALTER TABLE keys ADD COLUMN street TEXT;
ALTER TABLE keys ADD COLUMN country TEXT;
ALTER TABLE keys ADD COLUMN postal_code TEXT;
ALTER TABLE keys ADD COLUMN region TEXT;
ALTER TABLE pending_submissions ADD COLUMN street TEXT;
ALTER TABLE pending_submissions ADD COLUMN country TEXT;
ALTER TABLE pending_submissions ADD COLUMN postal_code TEXT;
ALTER TABLE pending_submissions ADD COLUMN region TEXT;
