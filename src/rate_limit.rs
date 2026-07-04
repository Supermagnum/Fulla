//! Per-IP and optional global rate limiting (`governor`).

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use governor::{clock::DefaultClock, state::direct::NotKeyed, state::InMemoryState, Quota, RateLimiter};
use serde_json::json;

use crate::config::Config;
use crate::AppState;

pub type IpLimiter = governor::DefaultKeyedRateLimiter<std::net::IpAddr>;
pub type GlobalLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

#[derive(Clone)]
pub struct RateLimits {
    pub mutate_per_ip: Arc<IpLimiter>,
    pub read_per_ip: Option<Arc<IpLimiter>>,
    pub mutate_global: Option<Arc<GlobalLimiter>>,
    pub read_global: Option<Arc<GlobalLimiter>>,
}

impl RateLimits {
    pub fn from_config(config: &Config) -> Self {
        Self {
            mutate_per_ip: Arc::new(per_ip_limiter(config.keyserver_rate_limit_submissions)),
            read_per_ip: config
                .keyserver_rate_limit_reads
                .map(|n| Arc::new(per_ip_limiter(n))),
            mutate_global: config
                .keyserver_rate_limit_submissions_global
                .map(|n| Arc::new(global_limiter(n))),
            read_global: config
                .keyserver_rate_limit_reads_global
                .map(|n| Arc::new(global_limiter(n))),
        }
    }

    /// High limits for unit tests.
    pub fn permissive_for_tests() -> Self {
        Self {
            mutate_per_ip: Arc::new(per_ip_limiter(999)),
            read_per_ip: None,
            mutate_global: None,
            read_global: None,
        }
    }
}

fn per_ip_limiter(per_hour: u32) -> IpLimiter {
    let n = NonZeroU32::new(per_hour.max(1)).expect("normalized");
    IpLimiter::keyed(Quota::per_hour(n))
}

fn global_limiter(per_hour: u32) -> GlobalLimiter {
    let n = NonZeroU32::new(per_hour.max(1)).expect("normalized");
    RateLimiter::direct(Quota::per_hour(n))
}

fn client_ip(req: &Request<Body>) -> std::net::IpAddr {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
        .unwrap_or_else(|| {
            tracing::warn!(
                "request missing ConnectInfo; applying rate-limit to loopback surrogate"
            );
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        })
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

fn allow(global: Option<&GlobalLimiter>, per_ip: Option<&IpLimiter>, ip: std::net::IpAddr) -> bool {
    if let Some(g) = global {
        if g.check().is_err() {
            return false;
        }
    }
    match per_ip {
        Some(l) => l.check_key(&ip).is_ok(),
        None => true,
    }
}

pub async fn mutation_rate_guard(
    State(app): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let ip = client_ip(&req);
    let limits = &app.rate_limits;
    if !allow(
        limits.mutate_global.as_deref(),
        Some(limits.mutate_per_ip.as_ref()),
        ip,
    ) {
        return rate_over_response(req.headers());
    }
    next.run(req).await
}

pub async fn read_rate_guard(
    State(app): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let ip = client_ip(&req);
    let limits = &app.rate_limits;
    if !allow(
        limits.read_global.as_deref(),
        limits.read_per_ip.as_deref(),
        ip,
    ) {
        return rate_over_response(req.headers());
    }
    next.run(req).await
}
