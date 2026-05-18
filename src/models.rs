//! Database and API structs.

use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Public key row returned by `GET /keys/...` (matches Galdra `KeyRecord`).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct KeyRecord {
    pub fingerprint: String,
    pub armored_key: String,
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callsign: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dmr_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub radio_affiliation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fluxer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discord_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub irc_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub street: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organisation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub badge_number: Option<String>,
    pub submitted_at: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<String>,
}

impl KeyRecord {
    pub fn from_db_row(row: DbKeyRow) -> Self {
        KeyRecord {
            fingerprint: row.fingerprint,
            armored_key: row.armored_key,
            email: row.email,
            first_name: row.first_name,
            last_name: row.last_name,
            callsign: row.callsign,
            dmr_id: row.dmr_id.and_then(|i| {
                let u = u32::try_from(i).ok()?;
                if u == 0 {
                    None
                } else {
                    Some(u)
                }
            }),
            radio_affiliation: row.radio_affiliation,
            fluxer_id: row.fluxer_id,
            discord_id: row.discord_id,
            irc_id: row.irc_id,
            street: row.street,
            country: row.country,
            postal_code: row.postal_code,
            region: row.region,
            organisation: row.organisation,
            role: row.role,
            note: row.note,
            badge_number: row.badge_number,
            submitted_at: row.submitted_at,
            status: row.status,
            revoked_at: row.revoked_at,
            revocation_reason: row.revocation_reason,
        }
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct DbKeyRow {
    pub fingerprint: String,
    pub armored_key: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub callsign: Option<String>,
    pub dmr_id: Option<i64>,
    pub radio_affiliation: Option<String>,
    pub fluxer_id: Option<String>,
    pub discord_id: Option<String>,
    pub irc_id: Option<String>,
    pub street: Option<String>,
    pub country: Option<String>,
    pub postal_code: Option<String>,
    pub region: Option<String>,
    pub organisation: Option<String>,
    pub role: Option<String>,
    pub note: Option<String>,
    pub badge_number: Option<String>,
    pub submitted_at: String,
    pub status: String,
    pub revoked_at: Option<String>,
    pub revocation_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewKeyRecord {
    pub fingerprint: String,
    pub armored_key: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub fluxer_id: Option<String>,
    pub discord_id: Option<String>,
    pub irc_id: Option<String>,
    pub callsign: Option<String>,
    pub dmr_id: Option<u32>,
    pub radio_affiliation: Option<String>,
    pub street: Option<String>,
    pub country: Option<String>,
    pub postal_code: Option<String>,
    pub region: Option<String>,
    pub organisation: Option<String>,
    pub role: Option<String>,
    pub note: Option<String>,
    pub badge_number: Option<String>,
    pub submitted_at: String,
}

#[derive(Debug, Clone, FromRow)]
pub struct PendingSubmission {
    pub token: String,
    pub new_fingerprint: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub fluxer_id: Option<String>,
    pub discord_id: Option<String>,
    pub irc_id: Option<String>,
    pub callsign: Option<String>,
    pub dmr_id: Option<i64>,
    pub radio_affiliation: Option<String>,
    pub street: Option<String>,
    pub country: Option<String>,
    pub postal_code: Option<String>,
    pub region: Option<String>,
    pub organisation: Option<String>,
    pub role: Option<String>,
    pub note: Option<String>,
    pub badge_number: Option<String>,
    pub armored_key: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SubmitPayload {
    pub email: String,
    pub armored_public_key: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub callsign: Option<String>,
    pub dmr_id: Option<u32>,
    pub radio_affiliation: Option<String>,
    pub fluxer_id: Option<String>,
    pub discord_id: Option<String>,
    pub irc_id: Option<String>,
    pub street: Option<String>,
    pub country: Option<String>,
    pub postal_code: Option<String>,
    pub region: Option<String>,
    pub organisation: Option<String>,
    pub role: Option<String>,
    pub note: Option<String>,
    pub badge_number: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PushResponseJson {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Default, Debug)]
pub struct KeyFilter {
    pub email: Option<String>,
    pub fingerprint_prefix: Option<String>,
    pub callsign: Option<String>,
    pub dmr_id: Option<i64>,
    pub discord_id: Option<String>,
    pub irc_id: Option<String>,
    pub fluxer_id: Option<String>,
    pub first_name_contains: Option<String>,
    pub last_name_contains: Option<String>,
}
