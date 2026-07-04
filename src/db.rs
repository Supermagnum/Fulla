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
) -> anyhow::Result<(Vec<CrsqlWireChange>, i64)> {
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
        "#,
    )
    .bind(since_db_version)
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
) -> anyhow::Result<Vec<CrsqlWireChange>> {
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
        "#,
    )
    .bind(since_db_version)
    .bind(site_id)
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
    Ok(())
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
        let rows = sqlx::query(
            r#"SELECT fingerprint, submitted_at FROM keys
                WHERE status = 'active' AND LOWER(email) = LOWER(?)
                ORDER BY submitted_at ASC"#,
        )
        .bind(&lem)
        .fetch_all(pool)
        .await?;

        if rows.len() <= 1 {
            continue;
        }

        let keep_fp: String = rows[0].try_get::<String, _>(0)?;

        for r in rows.into_iter().skip(1) {
            let fp: String = r.try_get(0)?;
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
            .bind(&fp)
            .bind(&lem)
            .execute(pool)
            .await?;

            tracing::warn!(
                email = %lem,
                kept = %keep_fp,
                revoked = %fp,
                "Mesh conflict resolved for email {}: kept {}, revoked {}",
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
    use sqlx::sqlite::SqlitePoolOptions;

    #[tokio::test]
    async fn resolve_duplicate_active_same_email_keeps_earliest_submitted() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        sqlx::query(
            r#"CREATE TABLE keys (
              fingerprint TEXT NOT NULL UNIQUE,
              armored_key TEXT NOT NULL,
              email TEXT NOT NULL,
              first_name TEXT, last_name TEXT,
              fluxer_id TEXT, discord_id TEXT, irc_id TEXT,
              callsign TEXT, dmr_id INTEGER, radio_affiliation TEXT,
              street TEXT, country TEXT, postal_code TEXT, region TEXT,
              submitted_at TEXT NOT NULL,
              revoked_at TEXT, revocation_reason TEXT,
              status TEXT NOT NULL DEFAULT 'active'
            )"#,
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            r#"INSERT INTO keys (fingerprint, armored_key, email, submitted_at, status)
               VALUES ('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'armor1', 'e@test', '2020-01-01T00:00:00Z', 'active'),
                      ('BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', 'armor2', 'e@test', '2022-01-01T00:00:00Z', 'active')"#,
        )
        .execute(&pool)
        .await
        .unwrap();

        let n = resolve_mesh_email_conflicts(&pool).await.unwrap();
        assert_eq!(n, 1);

        let active_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM keys WHERE email = 'e@test' AND status = 'active'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(active_count, 1);

        let reason: Option<String> =
            sqlx::query_scalar("SELECT revocation_reason FROM keys WHERE fingerprint LIKE 'BBBB%'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(reason.as_deref(), Some("mesh_conflict"));
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
}
