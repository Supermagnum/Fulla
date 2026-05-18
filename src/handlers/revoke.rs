//! POST `/revoke` and POST `/api/v1/keys/revoke`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::{Form, Json};

use serde::Deserialize;

use crate::db;
use crate::models::PushResponseJson;
use crate::openpgp::{apply_and_verify_revocation, cert_fingerprint_hex, cert_from_armored};
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    pub email: String,
    pub armored_revocation_cert: String,
}

#[derive(Debug, Deserialize)]
pub struct RevokeApiBody {
    pub email: String,
    pub armored_revocation_cert: String,
}

pub async fn handle_form(State(app): State<AppState>, Form(f): Form<RevokeForm>) -> Response {
    match run_revoke(
        &app.pool,
        f.email.trim().to_lowercase(),
        &f.armored_revocation_cert,
    )
    .await
    {
        Ok(()) => (StatusCode::OK, Html("<pre>Revocation processed.</pre>")).into_response(),
        Err(RevErr::Missing) => StatusCode::NOT_FOUND.into_response(),
        Err(RevErr::User(msg)) => {
            (StatusCode::UNPROCESSABLE_ENTITY, Html(html(&msg))).into_response()
        }
        Err(RevErr::Internal(e)) => {
            tracing::error!(error=?e, "revoke form");
            (StatusCode::INTERNAL_SERVER_ERROR, Html("Internal error.")).into_response()
        }
    }
}

fn html(s: &str) -> String {
    format!("<pre>{}</pre>", submit_like_esc(s))
}

fn submit_like_esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub async fn handle_api(State(app): State<AppState>, Json(b): Json<RevokeApiBody>) -> Response {
    match run_revoke(
        &app.pool,
        b.email.trim().to_lowercase(),
        &b.armored_revocation_cert,
    )
    .await
    {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"status":"ok"}))).into_response(),
        Err(RevErr::Missing) => (
            StatusCode::NOT_FOUND,
            Json(PushResponseJson {
                status: "error".into(),
                fingerprint: None,
                message: None,
                reason: Some("No active key for that fingerprint.".into()),
            }),
        )
            .into_response(),
        Err(RevErr::User(s)) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(PushResponseJson {
                status: "error".into(),
                fingerprint: None,
                message: None,
                reason: Some(s),
            }),
        )
            .into_response(),
        Err(RevErr::Internal(e)) => {
            tracing::error!(error=?e, "revoke api");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(PushResponseJson {
                    status: "error".into(),
                    fingerprint: None,
                    message: None,
                    reason: Some("Internal error.".into()),
                }),
            )
                .into_response()
        }
    }
}

enum RevErr {
    Missing,
    User(String),
    Internal(anyhow::Error),
}

async fn run_revoke(
    pool: &sqlx::SqlitePool,
    email: String,
    rev_armored: &str,
) -> Result<(), RevErr> {
    let rev_cert = cert_from_armored(rev_armored).map_err(|e| RevErr::User(e.to_string()))?;
    let fp = cert_fingerprint_hex(&rev_cert);

    let row = db::get_active_key_by_fingerprint(pool, &fp)
        .await
        .map_err(RevErr::Internal)?
        .ok_or(RevErr::Missing)?;

    if row.email.to_lowercase() != email {
        return Err(RevErr::User(
            "Email does not match the registered key owner.".into(),
        ));
    }

    let stored = cert_from_armored(&row.armored_key).map_err(RevErr::Internal)?;
    let reason = apply_and_verify_revocation(&stored, rev_armored)
        .map_err(|e| RevErr::User(e.to_string()))?;

    db::revoke_key(pool, &fp, reason.as_deref())
        .await
        .map_err(RevErr::Internal)?;

    Ok(())
}
