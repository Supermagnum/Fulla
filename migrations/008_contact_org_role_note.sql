-- Galdralag contact-style fields (organisation, role, free-form note, badge number).
ALTER TABLE keys ADD COLUMN organisation TEXT;
ALTER TABLE keys ADD COLUMN role TEXT;
ALTER TABLE keys ADD COLUMN note TEXT;
ALTER TABLE keys ADD COLUMN badge_number TEXT;

ALTER TABLE pending_submissions ADD COLUMN organisation TEXT;
ALTER TABLE pending_submissions ADD COLUMN role TEXT;
ALTER TABLE pending_submissions ADD COLUMN note TEXT;
ALTER TABLE pending_submissions ADD COLUMN badge_number TEXT;
