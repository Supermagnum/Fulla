//! SQLx accessors.

use std::path::Path;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqliteConnection;
use sqlx::{QueryBuilder, Row, SqlitePool};

use crate::config::PeerConfig;
use crate::email_normalize::normalize_email_identity;
use crate::models::{DbKeyRow, KeyFilter, KeyRecord, NewKeyRecord, PendingSubmission};

pub async fn insert_key(pool: &SqlitePool, record: &NewKeyRecord) -> Result<()> {
    let dmr: Option<i64> = record.dmr_id.map(|n| n as i64);
    sqlx::query(
        r#"
        INSERT INTO keys (
            fingerprint, armored_key, email, first_name, last_name,
            fluxer_id, discord_id, irc_id,
            callsign, dmr_id, radio_affiliation,
            street, country, postal_code, region,
            organisation, role, note, badge_number,
            submitted_at, revoked_at, revocation_reason, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, 'active')
        "#,
    )
    .bind(&record.fingerprint)
    .bind(&record.armored_key)
    .bind(&record.email)
    .bind(&record.first_name)
    .bind(&record.last_name)
    .bind(&record.fluxer_id)
    .bind(&record.discord_id)
    .bind(&record.irc_id)
    .bind(&record.callsign)
    .bind(dmr)
    .bind(&record.radio_affiliation)
    .bind(&record.street)
    .bind(&record.country)
    .bind(&record.postal_code)
    .bind(&record.region)
    .bind(&record.organisation)
    .bind(&record.role)
    .bind(&record.note)
    .bind(&record.badge_number)
    .bind(&record.submitted_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_key_by_fingerprint(pool: &SqlitePool, fp: &str) -> Result<Option<KeyRecord>> {
    let row = sqlx::query_as::<_, DbKeyRow>(
        r#"
        SELECT fingerprint, armored_key, email, first_name, last_name,
               callsign, dmr_id, radio_affiliation, fluxer_id, discord_id, irc_id,
               street, country, postal_code, region,
               organisation, role, note, badge_number,
               submitted_at, status, revoked_at, revocation_reason
        FROM keys WHERE fingerprint = ?"#,
    )
    .bind(fp)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(KeyRecord::from_db_row))
}

pub async fn get_active_key_by_fingerprint(
    pool: &SqlitePool,
    fp: &str,
) -> Result<Option<KeyRecord>> {
    let row = sqlx::query_as::<_, DbKeyRow>(
        r#"
        SELECT fingerprint, armored_key, email, first_name, last_name,
               callsign, dmr_id, radio_affiliation, fluxer_id, discord_id, irc_id,
               street, country, postal_code, region,
               organisation, role, note, badge_number,
               submitted_at, status, revoked_at, revocation_reason
        FROM keys WHERE fingerprint = ? AND status = 'active'"#,
    )
    .bind(fp)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(KeyRecord::from_db_row))
}

/// All keys for an email address (any `status`), newest first.
pub async fn get_keys_by_email(pool: &SqlitePool, email: &str) -> Result<Vec<KeyRecord>> {
    let rows = sqlx::query_as::<_, DbKeyRow>(
        r#"
        SELECT fingerprint, armored_key, email, first_name, last_name,
               callsign, dmr_id, radio_affiliation, fluxer_id, discord_id, irc_id,
               street, country, postal_code, region,
               organisation, role, note, badge_number,
               submitted_at, status, revoked_at, revocation_reason
        FROM keys WHERE LOWER(email) = LOWER(?)
        ORDER BY submitted_at DESC"#,
    )
    .bind(email)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(KeyRecord::from_db_row).collect())
}

pub async fn get_active_keys_by_email(pool: &SqlitePool, email: &str) -> Result<Vec<KeyRecord>> {
    let rows = sqlx::query_as::<_, DbKeyRow>(
        r#"
        SELECT fingerprint, armored_key, email, first_name, last_name,
               callsign, dmr_id, radio_affiliation, fluxer_id, discord_id, irc_id,
               street, country, postal_code, region,
               organisation, role, note, badge_number,
               submitted_at, status, revoked_at, revocation_reason
        FROM keys WHERE LOWER(email) = LOWER(?) AND status = 'active'
        ORDER BY submitted_at DESC"#,
    )
    .bind(email)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(KeyRecord::from_db_row).collect())
}

pub async fn revoke_key(pool: &SqlitePool, fp: &str, reason: Option<&str>) -> Result<u64> {
    let now = chrono::Utc::now().to_rfc3339();
    let res = sqlx::query(
        r#"UPDATE keys SET status = 'revoked', revoked_at = ?, revocation_reason = ?
            WHERE fingerprint = ? AND status = 'active'"#,
    )
    .bind(&now)
    .bind(reason)
    .bind(fp)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

pub async fn insert_pending(pool: &SqlitePool, pending: &PendingSubmission) -> Result<()> {
    let email_canonical = normalize_email_identity(&pending.email);
    sqlx::query(
        r#"
        INSERT INTO pending_submissions (
            token, new_fingerprint, email, email_canonical, first_name, last_name,
            fluxer_id, discord_id, irc_id,
            callsign, dmr_id, radio_affiliation,
            street, country, postal_code, region,
            organisation, role, note, badge_number,
            armored_key, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&pending.token)
    .bind(&pending.new_fingerprint)
    .bind(&pending.email)
    .bind(&email_canonical)
    .bind(&pending.first_name)
    .bind(&pending.last_name)
    .bind(&pending.fluxer_id)
    .bind(&pending.discord_id)
    .bind(&pending.irc_id)
    .bind(&pending.callsign)
    .bind(pending.dmr_id)
    .bind(&pending.radio_affiliation)
    .bind(&pending.street)
    .bind(&pending.country)
    .bind(&pending.postal_code)
    .bind(&pending.region)
    .bind(&pending.organisation)
    .bind(&pending.role)
    .bind(&pending.note)
    .bind(&pending.badge_number)
    .bind(&pending.armored_key)
    .bind(&pending.expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Whether an unexpired pending row exists for this mailbox identity.
pub async fn has_pending_for_email(pool: &SqlitePool, email: &str) -> Result<bool> {
    let canonical = normalize_email_identity(email);
    let n: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM pending_submissions
           WHERE email_canonical = ?
             AND datetime(expires_at) >= datetime('now')"#,
    )
    .bind(&canonical)
    .fetch_one(pool)
    .await?;
    Ok(n > 0)
}

pub async fn get_pending(pool: &SqlitePool, token: &str) -> Result<Option<PendingSubmission>> {
    let row = sqlx::query_as::<_, PendingSubmission>(
        r#"SELECT token, new_fingerprint, email, first_name, last_name,
                  fluxer_id, discord_id, irc_id,
                  callsign, dmr_id, radio_affiliation,
                  street, country, postal_code, region,
                  organisation, role, note, badge_number,
                  armored_key, expires_at
           FROM pending_submissions WHERE token = ?"#,
    )
    .bind(token)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn delete_pending(pool: &SqlitePool, token: &str) -> Result<()> {
    sqlx::query(r#"DELETE FROM pending_submissions WHERE token = ?"#)
        .bind(token)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn expire_pending(pool: &SqlitePool) -> Result<u64> {
    let res = sqlx::query(
        r#"DELETE FROM pending_submissions WHERE datetime(expires_at) < datetime('now')"#,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

#[derive(Clone)]
enum BindArg {
    S(String),
    I(i64),
}

pub async fn list_keys(
    pool: &SqlitePool,
    filter: &KeyFilter,
    page: u32,
    per_page: u32,
) -> Result<Vec<KeyRecord>> {
    let per = per_page.clamp(1, 200) as i64;
    let off = ((page.saturating_sub(1)) as i64) * per;
    let mut q = String::from(
        r#"SELECT fingerprint, armored_key, email, first_name, last_name,
                  callsign, dmr_id, radio_affiliation, fluxer_id, discord_id, irc_id,
                  street, country, postal_code, region,
                  organisation, role, note, badge_number,
                  submitted_at, status, revoked_at, revocation_reason
           FROM keys WHERE 1 = 1"#,
    );

    let mut binds: Vec<BindArg> = Vec::new();
    push_key_filter_clauses(&mut q, &mut binds, filter);

    q.push_str(" ORDER BY submitted_at DESC LIMIT ? OFFSET ?");

    let mut qb = sqlx::query_as::<_, DbKeyRow>(&q);

    for b in binds {
        qb = match b {
            BindArg::S(v) => qb.bind(v),
            BindArg::I(v) => qb.bind(v),
        };
    }

    qb = qb.bind(per).bind(off);

    let rows = qb.fetch_all(pool).await?;
    Ok(rows.into_iter().map(KeyRecord::from_db_row).collect())
}

fn normalize_fp_prefix(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect::<String>()
        .to_ascii_uppercase()
}

fn push_key_filter_clauses(q: &mut String, binds: &mut Vec<BindArg>, filter: &KeyFilter) {
    if let Some(em) = &filter.email {
        if !em.is_empty() {
            q.push_str(" AND LOWER(email) = LOWER(?)");
            binds.push(BindArg::S(em.clone()));
        }
    }

    if let Some(fp) = &filter.fingerprint_prefix {
        let n = normalize_fp_prefix(fp);
        if !n.is_empty() {
            let pat = format!("{n}%");
            q.push_str(" AND fingerprint LIKE ?");
            binds.push(BindArg::S(pat));
        }
    }

    if let Some(cs) = &filter.callsign {
        if !cs.is_empty() {
            q.push_str(" AND callsign IS NOT NULL AND LOWER(callsign) = LOWER(?)");
            binds.push(BindArg::S(cs.clone()));
        }
    }

    if let Some(dm) = filter.dmr_id {
        q.push_str(" AND dmr_id = ?");
        binds.push(BindArg::I(dm));
    }

    if let Some(v) = &filter.discord_id {
        if !v.is_empty() {
            q.push_str(" AND discord_id IS NOT NULL AND discord_id = ?");
            binds.push(BindArg::S(v.clone()));
        }
    }

    if let Some(v) = &filter.irc_id {
        if !v.is_empty() {
            q.push_str(" AND irc_id IS NOT NULL AND irc_id = ?");
            binds.push(BindArg::S(v.clone()));
        }
    }

    if let Some(v) = &filter.fluxer_id {
        if !v.is_empty() {
            q.push_str(" AND fluxer_id IS NOT NULL AND fluxer_id = ?");
            binds.push(BindArg::S(v.clone()));
        }
    }

    if let Some(v) = &filter.first_name_contains {
        if !v.is_empty() {
            q.push_str(
                " AND first_name IS NOT NULL AND instr(LOWER(first_name), LOWER(?)) > 0",
            );
            binds.push(BindArg::S(v.clone()));
        }
    }

    if let Some(v) = &filter.last_name_contains {
        if !v.is_empty() {
            q.push_str(" AND last_name IS NOT NULL AND instr(LOWER(last_name), LOWER(?)) > 0");
            binds.push(BindArg::S(v.clone()));
        }
    }

    if !filter.include_revoked {
        q.push_str(" AND status = 'active'");
    }
}

pub async fn count_keys(pool: &SqlitePool, filter: &KeyFilter) -> Result<i64> {
    let mut q = String::from("SELECT COUNT(*) FROM keys WHERE 1 = 1");
    let mut binds: Vec<BindArg> = Vec::new();
    push_key_filter_clauses(&mut q, &mut binds, filter);

    let mut qb = sqlx::query_scalar::<_, i64>(&q);
    for b in binds {
        qb = match b {
            BindArg::S(v) => qb.bind(v),
            BindArg::I(v) => qb.bind(v),
        };
    }

    Ok(qb.fetch_one(pool).await?)
}

/// JSON wire format for CR-SQLite `crsql_changes` rows (binary fields as standard base64).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrsqlWireChange {
    #[serde(rename = "table")]
    pub table_name: String,
    pub pk_b64: String,
    pub cid: String,
    #[serde(default)]
    pub val_b64: Option<String>,
    pub col_version: i64,
    pub db_version: i64,
    pub site_id_b64: String,
    #[serde(default)]
    pub cl_b64: Option<String>,
    #[serde(default)]
    pub seq: Option<i64>,
}

pub async fn sqlite_connection_load_extension(
    conn: &mut SqliteConnection,
    extension_path: &str,
) -> anyhow::Result<()> {
    let attempt = sqlx::query("SELECT load_extension(?)")
        .bind(extension_path)
        .execute(&mut *conn)
        .await;
    match attempt {
        Ok(_) => Ok(()),
        Err(e1) => {
            sqlx::query("SELECT load_extension(?, 'sqlite3_crsqlite_extension_init')")
                .bind(extension_path)
                .execute(&mut *conn)
                .await
                .map_err(|e2| {
                    anyhow::anyhow!(
                        "load_extension failed (default init: {e1}; crsql init: {e2}). \
                         Ensure SQLite is built with SQLITE_ENABLE_LOAD_EXTENSION and the CR-SQLite \
                         shared library path is correct."
                    )
                })?;
            Ok(())
        }
    }
}

/// Load CR-SQLite on a dedicated pooled connection (tools/tests).
/// Running instances load the extension in the SQLite pool `after_connect` hook instead.
#[allow(dead_code)]
pub async fn load_crsqlite_extension(pool: &SqlitePool, path: &Path) -> anyhow::Result<()> {
    let s = path.to_string_lossy().to_string();
    let mut conn = pool.acquire().await?;
    sqlite_connection_load_extension(&mut conn, &s).await?;
    Ok(())
}

pub async fn crsql_activate_keys(pool: &SqlitePool) -> anyhow::Result<()> {
    sqlx::query("SELECT crsql_as_crr('keys');")
        .execute(pool)
        .await
        .context(
            "crsql_as_crr('keys') failed — is the CR-SQLite extension loaded on this connection?",
        )?;
    Ok(())
}

pub async fn crsql_db_version(pool: &SqlitePool) -> anyhow::Result<i64> {
    let v = sqlx::query_scalar::<_, i64>("SELECT crsql_db_version();")
        .fetch_one(pool)
        .await
        .context("crsql_db_version() failed")?;
    Ok(v)
}

pub async fn crsql_site_id_bytes(pool: &SqlitePool) -> anyhow::Result<Vec<u8>> {
    let b = sqlx::query_scalar::<_, Vec<u8>>("SELECT crsql_siteid();")
        .fetch_one(pool)
        .await
        .context("crsql_siteid() failed — is CR-SQLite active?")?;
    Ok(b)
}

pub async fn pull_crsql_changes_since(
    pool: &SqlitePool,
    since_db_version: i64,
    limit: usize,
) -> anyhow::Result<(Vec<CrsqlWireChange>, i64)> {
    let cap = limit.max(1) as i64;
    let rows = sqlx::query(
        r#"
        SELECT CAST("table" AS TEXT) AS tbl,
               pk AS pk_blob,
               CAST(cid AS TEXT) AS cid_str,
               val AS val_blob,
               CAST(col_version AS INTEGER) AS cv,
               CAST(db_version AS INTEGER) AS dv,
               site_id AS site_blob,
               cl AS cl_blob,
               CAST(seq AS INTEGER) AS seqv
          FROM crsql_changes
         WHERE CAST(db_version AS INTEGER) > ?
         ORDER BY CAST(db_version AS INTEGER) ASC
         LIMIT ?
        "#,
    )
    .bind(since_db_version)
    .bind(cap)
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let tbl: String = r.try_get("tbl")?;
        let pk_blob: Vec<u8> = r.try_get("pk_blob")?;
        let cid: String = r.try_get("cid_str")?;
        let val_blob: Option<Vec<u8>> = r.try_get::<Option<Vec<u8>>, _>("val_blob").ok().flatten();
        let col_version: i64 = r.try_get("cv")?;
        let db_version: i64 = r.try_get("dv")?;
        let site_blob: Vec<u8> = r.try_get("site_blob")?;
        let cl_blob: Option<Vec<u8>> = r.try_get::<Option<Vec<u8>>, _>("cl_blob").ok().flatten();
        let seq: Option<i64> = r.try_get("seqv").ok();
        out.push(CrsqlWireChange {
            table_name: tbl,
            pk_b64: B64.encode(pk_blob),
            cid,
            val_b64: val_blob.map(|v| B64.encode(v)),
            col_version,
            db_version,
            site_id_b64: B64.encode(site_blob),
            cl_b64: cl_blob.map(|v| B64.encode(v)),
            seq,
        });
    }
    let head = crsql_db_version(pool).await?;
    Ok((out, head))
}

pub async fn pull_own_site_changes_since(
    pool: &SqlitePool,
    since_db_version: i64,
    site_id: &[u8],
    limit: usize,
) -> anyhow::Result<Vec<CrsqlWireChange>> {
    let cap = limit.max(1) as i64;
    let rows = sqlx::query(
        r#"
        SELECT CAST("table" AS TEXT) AS tbl,
               pk AS pk_blob,
               CAST(cid AS TEXT) AS cid_str,
               val AS val_blob,
               CAST(col_version AS INTEGER) AS cv,
               CAST(db_version AS INTEGER) AS dv,
               site_id AS site_blob,
               cl AS cl_blob,
               CAST(seq AS INTEGER) AS seqv
          FROM crsql_changes
         WHERE CAST(db_version AS INTEGER) > ?
           AND site_id = ?
         ORDER BY CAST(db_version AS INTEGER) ASC
         LIMIT ?
        "#,
    )
    .bind(since_db_version)
    .bind(site_id)
    .bind(cap)
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let tbl: String = r.try_get("tbl")?;
        let pk_blob: Vec<u8> = r.try_get("pk_blob")?;
        let cid: String = r.try_get("cid_str")?;
        let val_blob: Option<Vec<u8>> = r.try_get::<Option<Vec<u8>>, _>("val_blob").ok().flatten();
        let col_version: i64 = r.try_get("cv")?;
        let db_version: i64 = r.try_get("dv")?;
        let site_blob: Vec<u8> = r.try_get("site_blob")?;
        let cl_blob: Option<Vec<u8>> = r.try_get::<Option<Vec<u8>>, _>("cl_blob").ok().flatten();
        let seq: Option<i64> = r.try_get("seqv").ok();
        out.push(CrsqlWireChange {
            table_name: tbl,
            pk_b64: B64.encode(pk_blob),
            cid,
            val_b64: val_blob.map(|v| B64.encode(v)),
            col_version,
            db_version,
            site_id_b64: B64.encode(site_blob),
            cl_b64: cl_blob.map(|v| B64.encode(v)),
            seq,
        });
    }
    Ok(out)
}

pub async fn apply_crsql_wire_rows(
    pool: &SqlitePool,
    rows: &[CrsqlWireChange],
) -> anyhow::Result<()> {
    // Trust boundary: column values in replicated `keys` rows (including `submitted_at`)
    // originate from the writing node's local confirm path and are not re-stamped here.
    // Post-apply `resolve_mesh_email_conflicts` must not use `submitted_at` for precedence.
    if rows.is_empty() {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    for ch in rows {
        let pk = B64
            .decode(ch.pk_b64.trim())
            .with_context(|| "pk_b64 decode")?;
        let val = match &ch.val_b64 {
            Some(s) => Some(B64.decode(s.trim()).with_context(|| "val_b64 decode")?),
            None => None,
        };
        let site = B64
            .decode(ch.site_id_b64.trim())
            .with_context(|| "site_id_b64 decode")?;
        let cl = match &ch.cl_b64 {
            Some(s) => Some(B64.decode(s.trim()).with_context(|| "cl_b64 decode")?),
            None => None,
        };
        sqlx::query(
            r#"INSERT INTO crsql_changes ("table", pk, cid, val, col_version, db_version, site_id, cl, seq)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(&ch.table_name)
        .bind(pk)
        .bind(&ch.cid)
        .bind(val)
        .bind(ch.col_version)
        .bind(ch.db_version)
        .bind(site)
        .bind(cl)
        .bind(ch.seq)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    observe_keys_from_wire_rows(pool, rows).await?;
    Ok(())
}

/// Record that this node completed GET `/confirm/{token}` for `fingerprint`.
/// Must only be called from the local confirm handler — never from mesh apply.
pub async fn record_local_key_confirmation(pool: &SqlitePool, fingerprint: &str) -> Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        r#"INSERT INTO key_local_confirmations (fingerprint, confirmed_at)
           VALUES (?, ?)
           ON CONFLICT(fingerprint) DO NOTHING"#,
    )
    .bind(fingerprint)
    .bind(&now)
    .execute(pool)
    .await?;
    record_key_first_seen_if_absent(pool, fingerprint).await?;
    Ok(())
}

/// First time this node observed `fingerprint` as active (confirm or mesh apply).
pub async fn record_key_first_seen_if_absent(pool: &SqlitePool, fingerprint: &str) -> Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        r#"INSERT OR IGNORE INTO key_local_first_seen (fingerprint, first_seen_at)
           VALUES (?, ?)"#,
    )
    .bind(fingerprint)
    .bind(&now)
    .execute(pool)
    .await?;
    Ok(())
}

fn decode_crsql_rowid_pk(pk: &[u8]) -> Option<i64> {
    if pk.is_empty() {
        return None;
    }
    if pk.len() <= 8 {
        let mut buf = [0u8; 8];
        buf[(8 - pk.len())..].copy_from_slice(pk);
        return Some(i64::from_be_bytes(buf));
    }
    None
}

/// After mesh apply, stamp first-seen for active keys touched by the batch.
pub async fn observe_keys_from_wire_rows(
    pool: &SqlitePool,
    rows: &[CrsqlWireChange],
) -> anyhow::Result<()> {
    let mut key_ids = Vec::new();
    for ch in rows {
        if ch.table_name != "keys" {
            continue;
        }
        let pk = B64
            .decode(ch.pk_b64.trim())
            .with_context(|| "pk_b64 decode in observe")?;
        if let Some(id) = decode_crsql_rowid_pk(&pk) {
            key_ids.push(id);
        }
    }
    key_ids.sort_unstable();
    key_ids.dedup();
    for id in key_ids {
        if let Some(fp) = sqlx::query_scalar::<_, String>(
            "SELECT fingerprint FROM keys WHERE id = ? AND status = 'active'",
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
        {
            record_key_first_seen_if_absent(pool, &fp).await?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshConflictCandidate {
    pub fingerprint: String,
    /// Set only when this node ran `/confirm/{token}` locally (`key_local_confirmations`).
    pub locally_confirmed_at: Option<String>,
    /// Earliest local observation of this fingerprint as active on this node.
    pub first_seen_at: Option<String>,
}

fn rfc3339_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.cmp(b)
}

/// Fingerprint-only tiebreak (gameable — ~50% success per keygen attempt vs a known victim fp).
pub fn mesh_conflict_winner_fingerprint_only(fingerprints: &[String]) -> Option<String> {
    fingerprints.iter().min_by(|a, b| {
        a.to_ascii_lowercase()
            .cmp(&b.to_ascii_lowercase())
    }).cloned()
}

/// Pick the active key to keep after a mesh merge on **this node**.
///
/// Precedence:
/// 1. Exactly one locally confirmed row (this node witnessed `/confirm/{token}`) wins outright.
/// 2. If multiple locally confirmed (abnormal race on one node), earliest `confirmed_at`.
/// 3. If none locally confirmed (replication-only on this node), earliest `first_seen_at`
///    (local wall clock when this node first saw the key active — not mesh-writable).
///
/// Fingerprint is **not** used. An attacker with mesh inject-only access cannot set
/// `key_local_confirmations` or backdate `key_local_first_seen` via `apply_crsql_wire_rows`.
pub fn mesh_conflict_pick_winner(candidates: &[MeshConflictCandidate]) -> Option<String> {
    if candidates.is_empty() {
        return None;
    }

    let locally_confirmed: Vec<&MeshConflictCandidate> = candidates
        .iter()
        .filter(|c| c.locally_confirmed_at.is_some())
        .collect();

    match locally_confirmed.len() {
        1 => Some(locally_confirmed[0].fingerprint.clone()),
        n if n >= 2 => locally_confirmed
            .iter()
            .min_by(|a, b| {
                rfc3339_cmp(
                    a.locally_confirmed_at.as_deref().unwrap_or(""),
                    b.locally_confirmed_at.as_deref().unwrap_or(""),
                )
            })
            .map(|c| c.fingerprint.clone()),
        _ => candidates
            .iter()
            .min_by(|a, b| {
                rfc3339_cmp(
                    a.first_seen_at.as_deref().unwrap_or("\u{10ffff}"),
                    b.first_seen_at.as_deref().unwrap_or("\u{10ffff}"),
                )
            })
            .map(|c| c.fingerprint.clone()),
    }
}

async fn load_mesh_conflict_candidates(
    pool: &SqlitePool,
    email_lower: &str,
) -> Result<Vec<MeshConflictCandidate>> {
    let rows = sqlx::query(
        r#"SELECT k.fingerprint,
                  lc.confirmed_at AS locally_confirmed_at,
                  fs.first_seen_at
             FROM keys k
             LEFT JOIN key_local_confirmations lc ON lc.fingerprint = k.fingerprint
             LEFT JOIN key_local_first_seen fs ON fs.fingerprint = k.fingerprint
            WHERE k.status = 'active' AND LOWER(k.email) = LOWER(?)"#,
    )
    .bind(email_lower)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .filter_map(|r| {
            Some(MeshConflictCandidate {
                fingerprint: r.try_get(0).ok()?,
                locally_confirmed_at: r.try_get(1).ok().flatten(),
                first_seen_at: r.try_get(2).ok().flatten(),
            })
        })
        .collect())
}

/// Resolve duplicate-active keys for one email introduced by concurrent mesh writes.
pub async fn resolve_mesh_email_conflicts(pool: &SqlitePool) -> anyhow::Result<u64> {
    let dup_emails: Vec<String> = sqlx::query_scalar(
        r#"SELECT LOWER(email) FROM keys
            WHERE status = 'active'
            GROUP BY LOWER(email)
           HAVING COUNT(*) > 1"#,
    )
    .fetch_all(pool)
    .await?;

    let now = chrono::Utc::now().to_rfc3339();
    let mut revoked = 0u64;

    for lem in dup_emails {
        let candidates = load_mesh_conflict_candidates(pool, &lem).await?;
        if candidates.len() <= 1 {
            continue;
        }

        let Some(keep_fp) = mesh_conflict_pick_winner(&candidates) else {
            continue;
        };

        for fp in candidates.iter().map(|c| &c.fingerprint) {
            if fp == &keep_fp {
                continue;
            }
            let _ = sqlx::query(
                r#"UPDATE keys
                      SET status = 'revoked',
                          revoked_at = ?,
                          revocation_reason = 'mesh_conflict'
                    WHERE fingerprint = ?
                      AND LOWER(email) = LOWER(?)
                      AND status = 'active'"#,
            )
            .bind(&now)
            .bind(fp)
            .bind(&lem)
            .execute(pool)
            .await?;

            tracing::warn!(
                email = %lem,
                kept = %keep_fp,
                revoked = %fp,
                "Mesh conflict resolved for email {}: kept {} (local-confirm / first-seen precedence), revoked {}",
                lem,
                keep_fp,
                fp
            );
            revoked += 1;
        }
    }

    Ok(revoked)
}

pub async fn upsert_mesh_peers_from_config(pool: &SqlitePool, peers: &[PeerConfig]) -> Result<()> {
    for p in peers {
        sqlx::query(
            r#"INSERT INTO mesh_peers (
                node_id, region, address, dynamic_dns_host,
                ssh_fallback_user, ssh_fallback_key, last_sync_at, last_sync_db_version, our_push_cursor
              ) VALUES (?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL)
              ON CONFLICT(node_id) DO UPDATE SET
                region = excluded.region,
                address = excluded.address,
                dynamic_dns_host = excluded.dynamic_dns_host,
                last_sync_at = mesh_peers.last_sync_at,
                last_sync_db_version = mesh_peers.last_sync_db_version,
                our_push_cursor = mesh_peers.our_push_cursor
            "#,
        )
        .bind(&p.node_id)
        .bind(&p.region)
        .bind(&p.address)
        .bind(&p.dynamic_dns_host)
        .execute(pool)
        .await?;
    }
    Ok(())
}

#[derive(Debug, sqlx::FromRow, Clone)]
pub struct MeshPeerDbRow {
    pub node_id: String,
    pub region: String,
    pub address: String,
    pub dynamic_dns_host: Option<String>,
    pub last_sync_at: Option<String>,
    pub last_sync_db_version: Option<i64>,
    pub our_push_cursor: Option<i64>,
}

pub async fn mesh_peer_states(pool: &SqlitePool) -> Result<Vec<MeshPeerDbRow>> {
    let rows = sqlx::query_as::<_, MeshPeerDbRow>(
        r#"SELECT node_id, region, address, dynamic_dns_host,
                  last_sync_at, last_sync_db_version, our_push_cursor
             FROM mesh_peers"#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn update_mesh_peer_progress(
    pool: &SqlitePool,
    peer_node_id: &str,
    last_peer_db_version: i64,
    our_push_cursor: i64,
) -> Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        r#"UPDATE mesh_peers
               SET last_sync_at = ?, last_sync_db_version = ?, our_push_cursor = ?
             WHERE node_id = ?"#,
    )
    .bind(now)
    .bind(last_peer_db_version)
    .bind(our_push_cursor)
    .bind(peer_node_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Remove stale mesh peer rows whose `node_id` is absent from config.
pub async fn prune_mesh_peers(pool: &SqlitePool, keep_node_ids: &[String]) -> Result<()> {
    if keep_node_ids.is_empty() {
        return Ok(());
    }
    let mut qb = QueryBuilder::new("DELETE FROM mesh_peers WHERE node_id NOT IN (");
    {
        let mut sep = qb.separated(", ");
        for id in keep_node_ids {
            sep.push_bind(id);
        }
    }
    qb.push(")");
    qb.build().execute(pool).await?;
    Ok(())
}

#[cfg(test)]
mod mesh_conflict_tests {
    use super::*;
    use base64::Engine;
    use sqlx::sqlite::SqlitePoolOptions;

    static B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::STANDARD;

    async fn conflict_test_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    fn candidate(fp: &str, confirmed: Option<&str>, first_seen: Option<&str>) -> MeshConflictCandidate {
        MeshConflictCandidate {
            fingerprint: fp.into(),
            locally_confirmed_at: confirmed.map(str::to_string),
            first_seen_at: first_seen.map(str::to_string),
        }
    }

    #[test]
    fn fingerprint_tiebreak_is_gameable_with_known_victim_fp() {
        // Victim published fp via GET /keys?email=; attacker grinds until fp < victim (~2 tries avg).
        let victim = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
        let attacker = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(
            attacker < victim,
            "attacker chose a lower hex fingerprint than victim"
        );
        assert_eq!(
            mesh_conflict_winner_fingerprint_only(&[victim.into(), attacker.into()]).as_deref(),
            Some(attacker),
            "fingerprint-only tiebreak lets attacker win with trivial keygen"
        );
    }

    #[test]
    fn local_confirm_beats_replication_only_despite_lower_attacker_fp() {
        let victim = candidate(
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            Some("2024-06-01T12:00:00Z"),
            Some("2024-06-01T12:00:00Z"),
        );
        let attacker = candidate(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            None,
            Some("2020-01-01T00:00:00Z"),
        );
        assert_eq!(
            mesh_conflict_pick_winner(&[victim, attacker]).as_deref(),
            Some("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
            "locally confirmed row wins even when attacker has lower fp and earlier first_seen"
        );
    }

    #[test]
    fn both_locally_confirmed_uses_earliest_confirmed_at() {
        let a = candidate(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            Some("2024-06-02T12:00:00Z"),
            None,
        );
        let b = candidate(
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            Some("2024-06-01T12:00:00Z"),
            None,
        );
        assert_eq!(
            mesh_conflict_pick_winner(&[a, b]).as_deref(),
            Some("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
            "when both locally confirmed, earliest confirmed_at wins (not fingerprint)"
        );
    }

    #[test]
    fn replication_only_uses_first_seen_not_fingerprint() {
        let victim = candidate(
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            None,
            Some("2020-01-01T00:00:00Z"),
        );
        let attacker = candidate(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            None,
            Some("2024-01-01T00:00:00Z"),
        );
        assert_eq!(
            mesh_conflict_pick_winner(&[victim, attacker]).as_deref(),
            Some("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
            "replication-only tier uses earliest local first_seen, not grindable fingerprint"
        );
    }

    #[tokio::test]
    async fn resolve_keeps_locally_confirmed_over_mesh_only_attacker() {
        let pool = conflict_test_pool().await;

        sqlx::query(
            r#"INSERT INTO keys (fingerprint, armored_key, email, submitted_at, status)
               VALUES ('CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC', 'armor-victim', 'victim@test', '2024-06-01T12:00:00Z', 'active'),
                      ('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'armor-attacker', 'victim@test', '2020-01-01T00:00:00Z', 'active')"#,
        )
        .execute(&pool)
        .await
        .unwrap();

        record_local_key_confirmation(&pool, "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
            .await
            .unwrap();
        record_key_first_seen_if_absent(&pool, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .await
            .unwrap();
        // Attacker has lower fp and earlier first_seen — must still lose.
        sqlx::query(
            "UPDATE key_local_first_seen SET first_seen_at = '2019-01-01T00:00:00Z' WHERE fingerprint = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'",
        )
        .execute(&pool)
        .await
        .unwrap();

        let n = resolve_mesh_email_conflicts(&pool).await.unwrap();
        assert_eq!(n, 1);

        let kept: String = sqlx::query_scalar(
            "SELECT fingerprint FROM keys WHERE email = 'victim@test' AND status = 'active'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            kept, "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            "locally confirmed victim must beat mesh-only attacker"
        );
    }

    #[tokio::test]
    async fn resolve_replication_only_uses_first_seen_not_backdated_submitted_at() {
        let pool = conflict_test_pool().await;

        sqlx::query(
            r#"INSERT INTO keys (fingerprint, armored_key, email, submitted_at, status)
               VALUES ('CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC', 'armor-victim', 'victim@test', '2024-06-01T12:00:00Z', 'active'),
                      ('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'armor-attacker', 'victim@test', '2020-01-01T00:00:00Z', 'active')"#,
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            r#"INSERT INTO key_local_first_seen (fingerprint, first_seen_at) VALUES
               ('CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC', '2024-06-01T12:00:00Z'),
               ('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', '2019-01-01T00:00:00Z')"#,
        )
        .execute(&pool)
        .await
        .unwrap();

        let n = resolve_mesh_email_conflicts(&pool).await.unwrap();
        assert_eq!(n, 1);

        let kept: String = sqlx::query_scalar(
            "SELECT fingerprint FROM keys WHERE email = 'victim@test' AND status = 'active'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        // Attacker has lower fp AND backdated submitted_at AND earlier first_seen on this node.
        assert_eq!(
            kept, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "when neither locally confirmed, earliest first_seen wins (attacker observed first on this node)"
        );

        // Prove fingerprint-only would also pick attacker here — tiebreak is not the protection;
        // local confirmation tier is.
        assert_eq!(
            mesh_conflict_winner_fingerprint_only(&[
                "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".into(),
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            ])
            .as_deref(),
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        );
    }

    #[tokio::test]
    async fn apply_crsql_wire_rows_cannot_inject_local_confirmation() {
        let pool = conflict_test_pool().await;

        sqlx::query(
            r#"INSERT INTO keys (id, fingerprint, armored_key, email, submitted_at, status)
               VALUES (1, 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', 'armor', 'inj@test', '2024-01-01T00:00:00Z', 'active')"#,
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS crsql_changes (
                "table" TEXT NOT NULL,
                pk BLOB NOT NULL,
                cid TEXT NOT NULL,
                val BLOB,
                col_version INTEGER NOT NULL,
                db_version INTEGER NOT NULL,
                site_id BLOB NOT NULL,
                cl BLOB,
                seq INTEGER
            )"#,
        )
        .execute(&pool)
        .await
        .unwrap();

        let hostile = vec![
            CrsqlWireChange {
                table_name: "key_local_confirmations".into(),
                pk_b64: B64.encode(b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
                cid: "confirmed_at".into(),
                val_b64: Some(B64.encode(b"2019-01-01T00:00:00Z")),
                col_version: 1,
                db_version: 99,
                site_id_b64: B64.encode([0xDEu8]),
                cl_b64: None,
                seq: None,
            },
            CrsqlWireChange {
                table_name: "key_local_first_seen".into(),
                pk_b64: B64.encode(b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
                cid: "first_seen_at".into(),
                val_b64: Some(B64.encode(b"2019-01-01T00:00:00Z")),
                col_version: 1,
                db_version: 100,
                site_id_b64: B64.encode([0xDEu8]),
                cl_b64: None,
                seq: None,
            },
        ];

        apply_crsql_wire_rows(&pool, &hostile).await.unwrap();

        let confirmed: Option<String> = sqlx::query_scalar(
            "SELECT confirmed_at FROM key_local_confirmations WHERE fingerprint = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'",
        )
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert!(
            confirmed.is_none(),
            "apply path must not create local confirmation rows from hostile wire data"
        );

        // first_seen may be set by observe_keys for keys table rows only, not from forged provenance wire rows.
        let first_seen: Option<String> = sqlx::query_scalar(
            "SELECT first_seen_at FROM key_local_first_seen WHERE fingerprint = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'",
        )
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert!(
            first_seen.is_none(),
            "forged key_local_first_seen wire rows must not populate local provenance"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::NewKeyRecord;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn pool_migrated() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn round_trip_insert_and_get_by_email() {
        let pool = pool_migrated().await;
        let rec = NewKeyRecord {
            fingerprint: "ABCDEF0123456789ABCDEF0123456789ABCDEF01".into(),
            armored_key: "-----BEGIN stub-----".into(),
            email: "ops@test.example".into(),
            first_name: None,
            last_name: None,
            fluxer_id: None,
            discord_id: None,
            irc_id: None,
            callsign: Some("LB9TST".into()),
            dmr_id: None,
            radio_affiliation: None,
            street: None,
            country: None,
            postal_code: None,
            region: None,
            organisation: None,
            role: None,
            note: None,
            badge_number: None,
            submitted_at: chrono::Utc::now().to_rfc3339(),
        };

        insert_key(&pool, &rec).await.unwrap();
        let rows = get_keys_by_email(&pool, "ops@test.example").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].fingerprint, rec.fingerprint);
        assert_eq!(rows[0].email, rec.email);
        assert_eq!(rows[0].status, "active");
    }

    #[tokio::test]
    async fn list_keys_optional_field_filters() {
        use crate::models::KeyFilter;

        let pool = pool_migrated().await;
        let ts = chrono::Utc::now().to_rfc3339();

        let r1 = NewKeyRecord {
            fingerprint: "1000000000000000000000000000000000000001".into(),
            armored_key: "a1".into(),
            email: "a@example.com".into(),
            first_name: Some("Marie".into()),
            last_name: None,
            fluxer_id: Some("fx-one".into()),
            discord_id: Some("snow#1".into()),
            irc_id: Some("ircbob".into()),
            callsign: None,
            dmr_id: None,
            radio_affiliation: None,
            street: None,
            country: None,
            postal_code: None,
            region: None,
            organisation: None,
            role: None,
            note: None,
            badge_number: None,
            submitted_at: ts.clone(),
        };
        let r2 = NewKeyRecord {
            fingerprint: "2000000000000000000000000000000000000002".into(),
            armored_key: "a2".into(),
            email: "b@example.com".into(),
            first_name: Some("Claude".into()),
            last_name: Some("Dupont".into()),
            fluxer_id: None,
            discord_id: Some("other".into()),
            irc_id: None,
            callsign: Some("LB9ZZZ".into()),
            dmr_id: Some(12345),
            radio_affiliation: None,
            street: None,
            country: None,
            postal_code: None,
            region: None,
            organisation: None,
            role: None,
            note: None,
            badge_number: None,
            submitted_at: ts,
        };
        insert_key(&pool, &r1).await.unwrap();
        insert_key(&pool, &r2).await.unwrap();

        let mut f = KeyFilter {
            discord_id: Some("snow#1".into()),
            ..Default::default()
        };
        let rows = list_keys(&pool, &f, 1, 50).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].fingerprint, r1.fingerprint);

        f = KeyFilter {
            first_name_contains: Some("arie".into()),
            ..Default::default()
        };
        let rows = list_keys(&pool, &f, 1, 50).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].first_name.as_deref(), Some("Marie"));

        f = KeyFilter {
            last_name_contains: Some("upon".into()),
            ..Default::default()
        };
        let rows = list_keys(&pool, &f, 1, 50).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].fingerprint, r2.fingerprint);

        f = KeyFilter {
            fluxer_id: Some("fx-one".into()),
            ..Default::default()
        };
        let rows = list_keys(&pool, &f, 1, 50).await.unwrap();
        assert_eq!(rows.len(), 1);

        f = KeyFilter {
            irc_id: Some("ircbob".into()),
            ..Default::default()
        };
        let rows = list_keys(&pool, &f, 1, 50).await.unwrap();
        assert_eq!(rows.len(), 1);

        f = KeyFilter {
            callsign: Some("lb9zzz".into()),
            ..Default::default()
        };
        let rows = list_keys(&pool, &f, 1, 50).await.unwrap();
        assert_eq!(rows.len(), 1);

        f = KeyFilter {
            dmr_id: Some(12345),
            ..Default::default()
        };
        let rows = list_keys(&pool, &f, 1, 50).await.unwrap();
        assert_eq!(rows.len(), 1);

        f = KeyFilter {
            fingerprint_prefix: Some("2000".into()),
            discord_id: Some("other".into()),
            ..Default::default()
        };
        let rows = list_keys(&pool, &f, 1, 50).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].fingerprint, r2.fingerprint);
    }

    #[tokio::test]
    async fn list_keys_excludes_revoked_by_default() {
        use crate::models::KeyFilter;

        let pool = pool_migrated().await;
        let ts = chrono::Utc::now().to_rfc3339();
        let rec = NewKeyRecord {
            fingerprint: "3000000000000000000000000000000000000003".into(),
            armored_key: "a3".into(),
            email: "revoked@example.com".into(),
            first_name: None,
            last_name: None,
            fluxer_id: None,
            discord_id: None,
            irc_id: None,
            callsign: Some("REVOKED1".into()),
            dmr_id: None,
            radio_affiliation: None,
            street: None,
            country: None,
            postal_code: None,
            region: None,
            organisation: None,
            role: None,
            note: None,
            badge_number: None,
            submitted_at: ts,
        };
        insert_key(&pool, &rec).await.unwrap();
        revoke_key(&pool, &rec.fingerprint, Some("test")).await.unwrap();

        let f = KeyFilter {
            callsign: Some("REVOKED1".into()),
            ..Default::default()
        };
        let rows = list_keys(&pool, &f, 1, 50).await.unwrap();
        assert!(rows.is_empty(), "default filter must exclude revoked keys");

        let f_all = KeyFilter {
            callsign: Some("REVOKED1".into()),
            include_revoked: true,
            ..Default::default()
        };
        let rows = list_keys(&pool, &f_all, 1, 50).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, "revoked");
    }
}
