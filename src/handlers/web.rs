//! Read-only HTTP pages and lookups.

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Json, Response},
};

use serde::{Deserialize, Serialize};

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
    pub email: Option<String>,
    pub fingerprint: Option<String>,
    pub callsign: Option<String>,
    pub dmr_id: Option<i64>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    /// When set with `email` only and `Accept: application/json`, include revoked keys (default: active only, for device clients).
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
    let email_only = em.is_some() && fp.is_none() && cs.is_none() && q.dmr_id.is_none();

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
    };

    let total = db::count_keys(&app.pool, &filter).await.map_err(internal)?;
    let rows = db::list_keys(&app.pool, &filter, page, per_page)
        .await
        .map_err(internal)?;

    if json_client {
        return Ok(Json(rows).into_response());
    }

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
