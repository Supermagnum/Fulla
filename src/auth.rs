//! Optional shared-secret authentication for mutation routes (closed registries).

use axum::body::Body;
use axum::extract::State;
use axum::http::{header::AUTHORIZATION, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use subtle::ConstantTimeEq;

use crate::rate_limit::accept_prefers_json;
use crate::AppState;

/// Constant-time Bearer token comparison (shared with mesh sync listener).
pub fn bearer_token_matches(auth_header: &str, secret: &str) -> bool {
    let Some(rest) = auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))
    else {
        return false;
    };
    let a = rest.as_bytes();
    let b = secret.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// When `KEYSERVER_MUTATION_AUTH_SECRET` is set, require `Authorization: Bearer <secret>`
/// on POST submit/revoke routes. Unset env = open registry (no check).
pub async fn mutation_auth_guard(
    State(app): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let Some(expected) = app.config.keyserver_mutation_auth_secret.as_deref() else {
        return next.run(req).await;
    };

    let authorized = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| bearer_token_matches(h, expected));

    if authorized {
        return next.run(req).await;
    }

    if accept_prefers_json(req.headers()) {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "status": "error",
                "reason": "Missing or invalid Authorization bearer token.",
            })),
        )
            .into_response()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            "Unauthorized: missing or invalid bearer token.",
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_match_is_constant_time_friendly() {
        assert!(bearer_token_matches("Bearer secret-token", "secret-token"));
        assert!(bearer_token_matches("bearer secret-token", "secret-token"));
        assert!(!bearer_token_matches("Bearer wrong", "secret-token"));
        assert!(!bearer_token_matches("Basic secret-token", "secret-token"));
        assert!(!bearer_token_matches("Bearer secret-token", "secret-token-x"));
    }
}
