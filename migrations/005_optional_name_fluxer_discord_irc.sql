ALTER TABLE keys ADD COLUMN fluxer_id TEXT;
ALTER TABLE keys ADD COLUMN discord_id TEXT;
ALTER TABLE keys ADD COLUMN irc_id TEXT;
ALTER TABLE pending_submissions ADD COLUMN fluxer_id TEXT;
ALTER TABLE pending_submissions ADD COLUMN discord_id TEXT;
ALTER TABLE pending_submissions ADD COLUMN irc_id TEXT;

CREATE INDEX IF NOT EXISTS idx_keys_fluxer_id ON keys(fluxer_id);
CREATE INDEX IF NOT EXISTS idx_keys_discord_id ON keys(discord_id);
CREATE INDEX IF NOT EXISTS idx_keys_irc_id ON keys(irc_id);
