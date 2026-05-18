//! Duplicate-identity confirmation endpoints and pending cleanup.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

use crate::db;
use crate::handlers::web::accepts_json_ok;
use crate::models::{NewKeyRecord, PushResponseJson};
use crate::templates::WebTemplates;
use crate::AppState;

fn parse_expiry(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&chrono::Utc))
}

pub async fn handle_confirm(
    State(app): State<AppState>,
    Path(token): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    match run_confirm(&app, &token).await {
        Ok(()) => {
            simple_page(
                &app.templates,
                accepts_json_ok(&headers),
                "confirm",
                StatusCode::OK,
            )
            .await
        }
        Err(ConfirmError::Gone) => missing_token(&app.templates, accepts_json_ok(&headers)).await,
        Err(ConfirmError::Internal(e)) => {
            tracing::error!(error=?e, "confirm");
            internal().await
        }
    }
}

pub async fn handle_reject(
    State(app): State<AppState>,
    Path(token): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let existed = db::get_pending(&app.pool, &token)
        .await
        .unwrap_or(None)
        .is_some();
    if let Err(e) = db::delete_pending(&app.pool, &token).await {
        tracing::error!(error=?e, "reject");
        return internal().await;
    }
    if !existed {
        return missing_token(&app.templates, accepts_json_ok(&headers)).await;
    }
    simple_page(
        &app.templates,
        accepts_json_ok(&headers),
        "rejected",
        StatusCode::OK,
    )
    .await
}

enum ConfirmError {
    Gone,
    Internal(anyhow::Error),
}

async fn run_confirm(app: &AppState, token: &str) -> Result<(), ConfirmError> {
    let pending = db::get_pending(&app.pool, token)
        .await
        .map_err(ConfirmError::Internal)?;
    let Some(p) = pending else {
        return Err(ConfirmError::Gone);
    };

    let Some(expires) = parse_expiry(&p.expires_at) else {
        return Err(ConfirmError::Internal(anyhow::anyhow!(
            "invalid expiry timestamp in pending row"
        )));
    };

    if chrono::Utc::now() > expires {
        let _ = db::delete_pending(&app.pool, token).await;
        return Err(ConfirmError::Gone);
    }

    let active_old = db::get_active_keys_by_email(&app.pool, &p.email)
        .await
        .map_err(ConfirmError::Internal)?;
    let Some(old_row) = active_old.first() else {
        let _ = db::delete_pending(&app.pool, token).await;
        return Err(ConfirmError::Gone);
    };

    db::revoke_key(&app.pool, &old_row.fingerprint, Some("superseded"))
        .await
        .map_err(ConfirmError::Internal)?;

    let dmr_u = p.dmr_id.and_then(|i| {
        let u = u32::try_from(i).ok()?;
        if u == 0 {
            None
        } else {
            Some(u)
        }
    });

    db::insert_key(
        &app.pool,
        &NewKeyRecord {
            fingerprint: p.new_fingerprint.clone(),
            armored_key: p.armored_key.clone(),
            email: p.email.to_lowercase(),
            first_name: p.first_name.clone(),
            last_name: p.last_name.clone(),
            fluxer_id: p.fluxer_id.clone(),
            discord_id: p.discord_id.clone(),
            irc_id: p.irc_id.clone(),
            callsign: p
                .callsign
                .as_ref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_ascii_uppercase()),
            dmr_id: dmr_u,
            radio_affiliation: p.radio_affiliation.clone(),
            street: p.street.clone(),
            country: p.country.clone(),
            postal_code: p.postal_code.clone(),
            region: p.region.clone(),
            organisation: p.organisation.clone(),
            role: p.role.clone(),
            note: p.note.clone(),
            badge_number: p.badge_number.clone(),
            submitted_at: chrono::Utc::now().to_rfc3339(),
        },
    )
    .await
    .map_err(ConfirmError::Internal)?;

    db::delete_pending(&app.pool, token)
        .await
        .map_err(ConfirmError::Internal)?;
    Ok(())
}

async fn simple_page(
    tmpl: &WebTemplates,
    json: bool,
    template: &'static str,
    status: StatusCode,
) -> Response {
    if json {
        return (
            status,
            axum::Json(serde_json::json!({
              "status": if template == "confirm" { "confirmed" } else { "rejected" }
            })),
        )
            .into_response();
    }
    match tmpl.render(template, serde_json::json!({})) {
        Ok(html) => (status, Html(html)).into_response(),
        Err(_) => (status, Html(template)).into_response(),
    }
}

async fn missing_token(tmpl: &WebTemplates, json: bool) -> Response {
    if json {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(PushResponseJson {
                status: "error".into(),
                fingerprint: None,
                message: None,
                reason: Some("Not found.".into()),
            }),
        )
            .into_response();
    }
    match tmpl.render("rejected", serde_json::json!({"expired": true})) {
        Ok(html) => (StatusCode::NOT_FOUND, Html(html)).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, Html("Not found.")).into_response(),
    }
}

async fn internal() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, Html("Internal error.")).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expired_pending_token_is_gone_and_row_removed() {
        use std::sync::Arc;

        use crate::models::PendingSubmission;

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();

        let app = crate::AppState {
            pool: pool.clone(),
            config: Arc::new(crate::config::Config::test_local()),
            mailer: Arc::new(crate::mail::Mailer::noop_for_tests()),
            templates: Arc::new(
                crate::templates::WebTemplates::load_from_dir(
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates"),
                )
                .unwrap(),
            ),
            rate_limit: crate::rate_limit::MutationRateLimit::new(999),
        };

        let token = "c".repeat(64);
        let expires = chrono::Utc::now()
            .checked_sub_signed(chrono::Duration::hours(5))
            .unwrap()
            .to_rfc3339();

        db::insert_pending(
            &pool,
            &PendingSubmission {
                token: token.clone(),
                new_fingerprint: "FEDCBA0987654321FEDCBA0987654321FEDCBA09".into(),
                email: "pend@test.example".into(),
                first_name: None,
                last_name: None,
                fluxer_id: None,
                discord_id: None,
                irc_id: None,
                callsign: Some("LB9PND".into()),
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
                armored_key: "-----BEGIN stub-----".into(),
                expires_at: expires,
            },
        )
        .await
        .unwrap();

        assert!(matches!(
            run_confirm(&app, &token).await,
            Err(ConfirmError::Gone)
        ));
        assert!(db::get_pending(&pool, &token).await.unwrap().is_none());
    }

    #[test]
    fn expiry_parses() {
        let t = chrono::Utc::now().to_rfc3339();
        assert!(parse_expiry(&t).is_some());
        assert!(parse_expiry("not a date").is_none());
    }
}
