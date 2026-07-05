//! Read-only HTTP pages and lookups.

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Json, Response},
};

use serde::{Deserialize, Serialize};
use url::form_urlencoded::Serializer;

use crate::db;
use crate::models::{KeyFilter, KeyRecord};
use crate::AppState;

pub fn accepts_json_ok(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase().contains("application/json"))
        .unwrap_or(false)
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct KeyBrowseQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callsign: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dmr_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discord_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub irc_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fluxer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<u32>,
    /// When set on multi-filter GET `/keys`, include revoked keys (default: active only for JSON clients).
    #[serde(default)]
    pub include_revoked: bool,
}

pub async fn index(State(app): State<AppState>) -> Result<Response, WebErr> {
    let html = app
        .templates
        .render("index", serde_json::json!({}))
        .map_err(internal)?;
    Ok(Html(html).into_response())
}

pub async fn key_list(
    State(app): State<AppState>,
    Query(q): Query<KeyBrowseQuery>,
    headers: HeaderMap,
) -> Result<Response, WebErr> {
    let json_client = accepts_json_ok(&headers);
    let em = trim(&q.email);
    let fp = trim(&q.fingerprint);
    let cs = trim(&q.callsign);
    let discord = trim(&q.discord_id);
    let irc = trim(&q.irc_id);
    let fluxer = trim(&q.fluxer_id);
    let first = trim(&q.first_name);
    let last = trim(&q.last_name);

    let email_only = em.is_some()
        && fp.is_none()
        && cs.is_none()
        && q.dmr_id.is_none()
        && discord.is_none()
        && irc.is_none()
        && fluxer.is_none()
        && first.is_none()
        && last.is_none();

    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(25).clamp(1, 200);

    if json_client && email_only {
        let rows = if q.include_revoked {
            db::get_keys_by_email(&app.pool, em.as_deref().unwrap())
                .await
                .map_err(internal)?
        } else {
            db::get_active_keys_by_email(&app.pool, em.as_deref().unwrap())
                .await
                .map_err(internal)?
        };
        if rows.is_empty() {
            return Ok((axum::http::StatusCode::NOT_FOUND).into_response());
        }
        return Ok(json_bundle(rows));
    }

    if !json_client && email_only {
        let all = db::get_keys_by_email(&app.pool, em.as_deref().unwrap())
            .await
            .map_err(internal)?;
        let total = all.len() as i64;
        let off = ((page.saturating_sub(1)) as usize).saturating_mul(per_page as usize);
        let rows: Vec<KeyRecord> = all.into_iter().skip(off).take(per_page as usize).collect();
        let (pager_prev, pager_next) = pager_query_strings(&q, page, per_page, total);
        let html = app
            .templates
            .render(
                "key_list",
                serde_json::json!({
                    "rows": rows,
                    "page": page,
                    "per_page": per_page,
                    "total": total,
                    "query": q,
                    "pager_qs_prev": pager_prev,
                    "pager_qs_next": pager_next,
                }),
            )
            .map_err(internal)?;
        return Ok(Html(html).into_response());
    }

    let filter = KeyFilter {
        email: em.clone(),
        fingerprint_prefix: fp.clone(),
        callsign: cs.clone(),
        dmr_id: q.dmr_id,
        discord_id: discord.clone(),
        irc_id: irc.clone(),
        fluxer_id: fluxer.clone(),
        first_name_contains: first.clone(),
        last_name_contains: last.clone(),
        include_revoked: if json_client {
            q.include_revoked
        } else {
            true
        },
    };

    let total = db::count_keys(&app.pool, &filter).await.map_err(internal)?;
    let rows = db::list_keys(&app.pool, &filter, page, per_page)
        .await
        .map_err(internal)?;

    if json_client {
        return Ok(Json(rows).into_response());
    }

    let (pager_prev, pager_next) = pager_query_strings(&q, page, per_page, total);
    let html = app
        .templates
        .render(
            "key_list",
            serde_json::json!({
                "rows": rows,
                "page": page,
                "per_page": per_page,
                "total": total,
                "query": q,
                "pager_qs_prev": pager_prev,
                "pager_qs_next": pager_next,
            }),
        )
        .map_err(internal)?;
    Ok(Html(html).into_response())
}

pub async fn key_detail(
    State(app): State<AppState>,
    Path(raw_fp): Path<String>,
    headers: HeaderMap,
) -> Result<Response, WebErr> {
    let fp =
        normalize_fingerprint(&raw_fp).ok_or_else(|| WebErr::Status(400, "bad fingerprint"))?;
    let row = db::get_key_by_fingerprint(&app.pool, &fp)
        .await
        .map_err(internal)?
        .ok_or_else(|| WebErr::Status(404, "not found"))?;

    if accepts_json_ok(&headers) {
        return Ok(Json(row).into_response());
    }

    let html = app
        .templates
        .render(
            "key_detail",
            serde_json::to_value(&row).map_err(|e| WebErr::Any(e.into()))?,
        )
        .map_err(internal)?;
    Ok(Html(html).into_response())
}

pub async fn submit_form(State(app): State<AppState>) -> Result<Response, WebErr> {
    let html = app
        .templates
        .render("submit", serde_json::json!({}))
        .map_err(internal)?;
    Ok(Html(html).into_response())
}

pub async fn revoke_form(State(app): State<AppState>) -> Result<Response, WebErr> {
    let html = app
        .templates
        .render("revoke", serde_json::json!({}))
        .map_err(internal)?;
    Ok(Html(html).into_response())
}

fn trim(s: &Option<String>) -> Option<String> {
    s.as_ref()
        .map(|x| x.trim())
        .filter(|x| !x.is_empty())
        .map(|x| x.to_string())
}

fn append_trim(ser: &mut Serializer<'_, String>, key: &'static str, opt: &Option<String>) {
    if let Some(s) = trim(opt) {
        ser.append_pair(key, &s);
    }
}

fn serialize_keys_browse_query(q: &KeyBrowseQuery, page: u32, per_page: u32) -> String {
    let mut ser = Serializer::new(String::new());
    append_trim(&mut ser, "email", &q.email);
    append_trim(&mut ser, "fingerprint", &q.fingerprint);
    append_trim(&mut ser, "callsign", &q.callsign);
    if let Some(dm) = q.dmr_id {
        ser.append_pair("dmr_id", &dm.to_string());
    }
    append_trim(&mut ser, "discord_id", &q.discord_id);
    append_trim(&mut ser, "irc_id", &q.irc_id);
    append_trim(&mut ser, "fluxer_id", &q.fluxer_id);
    append_trim(&mut ser, "first_name", &q.first_name);
    append_trim(&mut ser, "last_name", &q.last_name);
    if q.include_revoked {
        ser.append_pair("include_revoked", "true");
    }
    ser.append_pair("page", &page.to_string());
    ser.append_pair("per_page", &per_page.to_string());
    ser.finish()
}

fn pager_query_strings(q: &KeyBrowseQuery, page: u32, per_page: u32, total: i64) -> (String, String) {
    let prev = if page > 1 {
        serialize_keys_browse_query(q, page - 1, per_page)
    } else {
        String::new()
    };

    let next = if i64::from(page).saturating_mul(i64::from(per_page)) < total {
        serialize_keys_browse_query(q, page + 1, per_page)
    } else {
        String::new()
    };

    (prev, next)
}

fn normalize_fingerprint(raw: &str) -> Option<String> {
    let compact: String = raw.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if compact.len() != 40 || !compact.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(compact.to_ascii_uppercase())
}

fn json_bundle(rows: Vec<KeyRecord>) -> Response {
    if rows.len() == 1 {
        Json(rows[0].clone()).into_response()
    } else {
        Json(rows).into_response()
    }
}

#[derive(Debug)]
pub enum WebErr {
    Status(u16, &'static str),
    Any(anyhow::Error),
}

impl IntoResponse for WebErr {
    fn into_response(self) -> Response {
        match self {
            WebErr::Status(c, m) => {
                (axum::http::StatusCode::from_u16(c).unwrap(), m).into_response()
            }
            WebErr::Any(e) => {
                tracing::error!(error=?e, "web");
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error",
                )
                    .into_response()
            }
        }
    }
}

fn internal(e: anyhow::Error) -> WebErr {
    WebErr::Any(e)
}
