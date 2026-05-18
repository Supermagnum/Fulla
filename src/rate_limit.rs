//! Per-source-IP mutation rate limiting (`governor`).

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::AppState;

pub type IpLimiter = governor::DefaultKeyedRateLimiter<std::net::IpAddr>;

#[derive(Clone)]
pub struct MutationRateLimit {
    pub limiter: Arc<IpLimiter>,
}

impl MutationRateLimit {
    pub fn new(per_hour: u32) -> Self {
        let n = NonZeroU32::new(per_hour.max(1)).expect("normalized");
        MutationRateLimit {
            limiter: Arc::new(IpLimiter::keyed(governor::Quota::per_hour(n))),
        }
    }
}

fn accept_prefers_json(headers: &HeaderMap) -> bool {
    let Some(v) = headers.get(axum::http::header::ACCEPT) else {
        return false;
    };
    let Ok(s) = v.to_str() else {
        return false;
    };
    s.to_ascii_lowercase().contains("application/json")
}

pub fn rate_over_response(headers: &HeaderMap) -> Response {
    if accept_prefers_json(headers) {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"status":"error","reason":"Rate limit exceeded."})),
        )
            .into_response()
    } else {
        (
            StatusCode::TOO_MANY_REQUESTS,
            [("content-type", "text/plain; charset=utf-8")],
            "Too many requests from your address in the past hour.\n",
        )
            .into_response()
    }
}

pub async fn mutation_rate_guard(
    State(app): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
        .unwrap_or_else(|| {
            tracing::warn!(
                "request missing ConnectInfo; applying rate-limit to loopback surrogate"
            );
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        });
    if app.rate_limit.limiter.check_key(&ip).is_err() {
        return rate_over_response(req.headers());
    }
    next.run(req).await
}
