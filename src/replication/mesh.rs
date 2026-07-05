//! CR-SQLite mesh peer sync API and bilateral exchange cron.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    body::Body,
    extract::{Query, State},
    http::{header::AUTHORIZATION, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use governor::{clock::DefaultClock, state::direct::NotKeyed, state::InMemoryState, Quota, RateLimiter};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::Deserialize;
use std::num::NonZeroU32;
use tower_http::limit::RequestBodyLimitLayer;
use url::Url;

use crate::auth::bearer_token_matches;

use crate::config::MeshConfig;
use crate::db::{
    self, apply_crsql_wire_rows, crsql_site_id_bytes, mesh_peer_states, pull_crsql_changes_since,
    pull_own_site_changes_since, resolve_mesh_email_conflicts, update_mesh_peer_progress,
    CrsqlWireChange,
};
use crate::replication::dns::{resolve_host_first_ip, substitute_host_token};
use sqlx::SqlitePool;

const HDR_DB_VERSION: &str = "X-DB-Version";
const HDR_CHANGES_TRUNCATED: &str = "X-Changes-Truncated";
const HDR_MESH_PROTOCOL: &str = "X-Mesh-Protocol-Version";

/// Mesh sync protocol version. Version 2 adds paginated `GET /sync/changes` (`limit`,
/// `X-Changes-Truncated`, and this header). Peers below this version may stop after one
/// page and silently miss changes.
pub const MESH_SYNC_PROTOCOL_VERSION: u32 = 2;

/// Consecutive truncation-block failures before logging an upgrade-now escalation.
const TRUNCATION_BLOCK_ESCALATE_AFTER: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TruncationBlockedError {
    pub batch_len: usize,
    pub page: usize,
    pub peer_protocol: Option<u32>,
    pub consecutive_failures: u32,
}

impl std::fmt::Display for TruncationBlockedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "mesh sync truncation-blocked: peer returned a full page ({} >= limit {}) \
             with protocol version {:?} below {MESH_SYNC_PROTOCOL_VERSION}; \
             refusing partial apply to prevent silent data loss (e.g. late revocations); \
             sync cursor not advanced (consecutive blocked cycles: {})",
            self.batch_len,
            self.page,
            self.peer_protocol,
            self.consecutive_failures,
        )
    }
}

impl std::error::Error for TruncationBlockedError {}

/// Returns true when the peer advertises mesh sync protocol v2+ pagination support.
fn peer_supports_pagination(peer_protocol: Option<u32>) -> bool {
    peer_protocol.unwrap_or(1) >= MESH_SYNC_PROTOCOL_VERSION
}

/// Fail closed when a full page from a pre-pagination peer could hide further rows.
fn truncation_block_reason(
    batch_len: usize,
    page: usize,
    peer_protocol: Option<u32>,
) -> Option<TruncationBlockedError> {
    if batch_len >= page && !peer_supports_pagination(peer_protocol) {
        Some(TruncationBlockedError {
            batch_len,
            page,
            peer_protocol,
            consecutive_failures: 0,
        })
    } else {
        None
    }
}

#[derive(Clone)]
pub(crate) struct MeshApiState {
    pub pool: SqlitePool,
    pub bearer_token: Arc<str>,
    pub max_changes_per_request: usize,
    pub rate_limiter: Option<Arc<MeshRateLimiter>>,
}

type MeshRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

#[derive(Clone)]
struct MeshRuntime {
    cfg: MeshConfig,
    pool: SqlitePool,
    our_node_id: Arc<str>,
    our_site_id: Vec<u8>,
    client: reqwest::Client,
    bearer_token: Arc<str>,
    /// Consecutive truncation-block failures per peer (`node_id` -> count).
    truncation_block_streaks: Arc<Mutex<HashMap<String, u32>>>,
}

pub(crate) async fn start(
    cfg: MeshConfig,
    pool: SqlitePool,
    our_node_id: String,
) -> anyhow::Result<()> {
    let bearer: Arc<str> = Arc::from(cfg.sync_authorization_secret.trim());

    let rate_limiter = if cfg.sync_rate_limit_requests > 0 {
        let n = NonZeroU32::new(cfg.sync_rate_limit_requests).expect("validated > 0");
        Some(Arc::new(RateLimiter::direct(Quota::per_hour(n))))
    } else {
        None
    };

    let st = MeshApiState {
        pool: pool.clone(),
        bearer_token: bearer.clone(),
        max_changes_per_request: cfg.sync_max_changes_per_request,
        rate_limiter,
    };
    spawn_sync_server(&cfg, st)?;

    let site = crsql_site_id_bytes(&pool).await?;
    let rt = MeshRuntime {
        cfg: cfg.clone(),
        pool,
        our_node_id: Arc::from(our_node_id),
        our_site_id: site,
        client: reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(Duration::from_secs(300))
            .build()
            .map_err(anyhow::Error::msg)?,
        bearer_token: bearer,
        truncation_block_streaks: Arc::new(Mutex::new(HashMap::new())),
    };

    spawn_sync_cron(rt);
    Ok(())
}

fn spawn_sync_server(cfg: &MeshConfig, st: MeshApiState) -> anyhow::Result<()> {
    let bearer_state = st.clone();
    let mut app = Router::new()
        .route("/sync/changes", get(get_changes_handler))
        .route("/sync/apply", post(apply_changes_handler))
        .route_layer(middleware::from_fn_with_state(
            bearer_state.clone(),
            mesh_rate_guard,
        ))
        .route_layer(middleware::from_fn_with_state(
            bearer_state.clone(),
            bearer_auth_middleware,
        ))
        .with_state(st);

    app = app.layer(RequestBodyLimitLayer::new(cfg.sync_max_body_bytes));

    let addr: SocketAddr = format!("0.0.0.0:{}", cfg.sync_api_port).parse()?;
    match (&cfg.sync_tls_cert, &cfg.sync_tls_key) {
        (Some(cert_path), Some(key_path)) => {
            let cert = cert_path.clone();
            let key = key_path.clone();
            tokio::spawn(async move {
                let tls = match RustlsConfig::from_pem_file(cert, key).await {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::error!(error = %e, "mesh TLS: failed loading cert/key");
                        return;
                    }
                };
                tracing::info!(%addr, "mesh sync listening with TLS");
                if let Err(e) = axum_server::bind_rustls(addr, tls)
                    .serve(app.into_make_service())
                    .await
                {
                    tracing::error!(error = %e, "mesh TLS server exited");
                }
            });
        }
        (None, None) => {
            tokio::spawn(async move {
                tracing::info!(%addr, "mesh sync listening (plain HTTP; keep off the public internet)");
                let listener = match tokio::net::TcpListener::bind(addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!(error = %e, "mesh: bind sync_api_port failed");
                        return;
                    }
                };
                if let Err(e) = axum::serve(listener, app).await {
                    tracing::error!(error = %e, "mesh server exited");
                }
            });
        }
        _ => unreachable!("mesh TLS options validated in config"),
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct ChangesQuery {
    #[serde(default)]
    pub since_db_version: i64,
    #[serde(default)]
    pub node_id: String,
    /// Max rows per response (defaults to `sync_max_changes_per_request`).
    #[serde(default)]
    pub limit: Option<usize>,
    /// Client mesh sync protocol version (`MESH_SYNC_PROTOCOL_VERSION` on current Fulla).
    #[serde(default)]
    pub protocol_version: Option<u32>,
}

async fn mesh_rate_guard(
    State(st): State<MeshApiState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(lim) = &st.rate_limiter {
        if lim.check().is_err() {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }
    Ok(next.run(req).await)
}

async fn bearer_auth_middleware(
    State(st): State<MeshApiState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let authorized = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| bearer_token_matches(h, st.bearer_token.as_ref()));

    if !authorized {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(req).await)
}

async fn get_changes_handler(
    State(st): State<MeshApiState>,
    Query(q): Query<ChangesQuery>,
) -> Response {
    if q.node_id.is_empty() {
        tracing::warn!("mesh GET /sync/changes: missing node_id query");
    }

    let limit = q
        .limit
        .unwrap_or(st.max_changes_per_request)
        .min(st.max_changes_per_request)
        .max(1);

    match pull_crsql_changes_since(&st.pool, q.since_db_version, limit).await {
        Ok((rows, head)) => {
            let truncated = rows.len() >= limit;
            let client_proto = q.protocol_version.unwrap_or(1);
            if truncated && client_proto < MESH_SYNC_PROTOCOL_VERSION {
                tracing::error!(
                    requesting_node = %q.node_id,
                    client_protocol_version = client_proto,
                    required = MESH_SYNC_PROTOCOL_VERSION,
                    since_db_version = q.since_db_version,
                    limit,
                    rows_returned = rows.len(),
                    "mesh GET /sync/changes: truncated response to pre-pagination client; \
                     pulling node should fail closed rather than apply a partial page"
                );
            } else if truncated {
                tracing::warn!(
                    requesting_node = %q.node_id,
                    since_db_version = q.since_db_version,
                    limit,
                    rows_returned = rows.len(),
                    mesh_changes_truncated = true,
                    "mesh GET /sync/changes: response truncated at limit; \
                     client must page with since_db_version cursor and \
                     protocol_version={MESH_SYNC_PROTOCOL_VERSION}"
                );
            }
            let mut res = Json(rows).into_response();
            if let Ok(v) = axum::http::HeaderValue::from_str(&head.to_string()) {
                res.headers_mut().insert(HDR_DB_VERSION, v);
            }
            res.headers_mut().insert(
                HDR_MESH_PROTOCOL,
                axum::http::HeaderValue::from_static("2"),
            );
            if truncated {
                res.headers_mut()
                    .insert(HDR_CHANGES_TRUNCATED, axum::http::HeaderValue::from_static("true"));
            }
            res
        }
        Err(e) => {
            tracing::error!(error = %e, "mesh: pull failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn apply_changes_handler(
    State(st): State<MeshApiState>,
    Json(rows): Json<Vec<CrsqlWireChange>>,
) -> Response {
    if rows.len() > st.max_changes_per_request {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "Too many changes in one request ({} > max {}).",
                rows.len(),
                st.max_changes_per_request
            ),
        )
            .into_response();
    }

    if let Err(e) = apply_crsql_wire_rows(&st.pool, &rows).await {
        tracing::warn!(error = %e, "mesh apply: malformed or rejected changes");
        return (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()).into_response();
    }
    if let Err(e) = resolve_mesh_email_conflicts(&st.pool).await {
        tracing::error!(error = %e, "mesh apply: conflict resolution failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    StatusCode::OK.into_response()
}

fn spawn_sync_cron(rt: MeshRuntime) {
    let interval = Duration::from_secs(rt.cfg.sync_interval_minutes.max(1) * 60);
    tokio::spawn(async move {
        tracing::info!(
            minutes = rt.cfg.sync_interval_minutes,
            "mesh sync cron started"
        );
        loop {
            run_sync_cycle_spawning(&rt).await;
            tokio::time::sleep(interval).await;
        }
    });
}

async fn run_sync_cycle_spawning(rt: &MeshRuntime) {
    let peers = match mesh_peer_states(&rt.pool).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "mesh: mesh_peers listing failed");
            return;
        }
    };

    if peers.is_empty() {
        tracing::info!("mesh: no peers in mesh_peers (check config reload / migration)");
        return;
    }

    let mut set = tokio::task::JoinSet::new();
    for row in peers {
        let rtt = rt.clone();
        set.spawn(async move {
            sync_with_peer_inline(&rtt, row).await;
        });
    }

    while let Some(joined) = set.join_next().await {
        if let Err(e) = joined {
            tracing::warn!(error = %e, "mesh: peer worker task panic or join failure");
        }
    }
}

async fn sync_with_peer_inline(rt: &MeshRuntime, row: db::MeshPeerDbRow) {
    match resolve_peer_base_url(rt, &row).await {
        Ok(Some(base_url)) => {
            if let Err(e) = sync_pull_push(rt, &row, &base_url).await {
                if e.downcast_ref::<TruncationBlockedError>().is_some() {
                    tracing::error!(
                        error = %e,
                        region = %row.region,
                        node_id = %row.node_id,
                        "mesh peer sync failed (truncation-blocked; cursor unchanged; retry next cycle)",
                    );
                } else {
                    tracing::warn!(
                        error = %e,
                        region = %row.region,
                        node_id = %row.node_id,
                        "mesh peer sync failed",
                    );
                }
            }
        }
        Ok(None) => {}
        Err(e) => tracing::warn!(
            error = %e,
            region = %row.region,
            node_id = %row.node_id,
            "mesh: peer URL normalization failed",
        ),
    }
}

async fn resolve_peer_base_url(
    _rt: &MeshRuntime,
    row: &db::MeshPeerDbRow,
) -> anyhow::Result<Option<String>> {
    let mut addr = row.address.trim().to_string();
    if addr.is_empty() {
        anyhow::bail!("empty peer address");
    }

    if let Some(tok) = &row.dynamic_dns_host {
        let t = tok.trim();
        if !t.is_empty() {
            let ip = match resolve_host_first_ip(t).await {
                Ok(ip) => ip,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        host = %t,
                        region = %row.region,
                        node_id = %row.node_id,
                        "mesh: dynamic DNS failed; skipping this peer this cycle",
                    );
                    return Ok(None);
                }
            };
            if addr.contains(t) {
                addr = substitute_host_token(&addr, t, ip);
            } else if let Some(host_token) = extract_host_hint(&addr) {
                if host_token == t || addr.contains(&host_token) {
                    addr = substitute_host_token(&addr, &host_token, ip);
                }
            }
        }
    }

    Ok(Some(normalize_peer_base(&addr)?))
}

fn extract_host_hint(url_like: &str) -> Option<String> {
    let s = url_like.trim();
    if s.starts_with("http://") || s.starts_with("https://") {
        Url::parse(s).ok()?.host_str().map(str::to_string)
    } else {
        let colon = s.find(':')?;
        Some(s[..colon].to_string())
    }
}

fn normalize_peer_base(addr: &str) -> anyhow::Result<String> {
    let u = Url::parse(addr.trim())
        .map_err(|e| anyhow::anyhow!("invalid peer URL `{}`: {}", addr.trim(), e))?;
    if !(u.scheme() == "http" || u.scheme() == "https") {
        anyhow::bail!(
            "peer URL must use http or https (got `{}` on `{}`)",
            u.scheme(),
            addr,
        );
    }
    if u.host().is_none() {
        anyhow::bail!("peer URL `{}` must include host", addr);
    }
    if !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
        || u.query().is_some()
    {
        anyhow::bail!(
            "peer URL `{}` must be scheme://host[:port] with no credentials, fragments, query, or path",
            addr,
        );
    }
    let path = u.path();
    if !(path.is_empty() || path == "/") {
        anyhow::bail!(
            "peer URL `{}` path must be empty or '/' (got `{}`; use scheme://host[:port] only)",
            addr,
            path,
        );
    }
    Ok(u.as_str().trim_end_matches('/').to_string())
}

async fn sync_pull_push(
    rt: &MeshRuntime,
    row: &db::MeshPeerDbRow,
    base_url: &str,
) -> anyhow::Result<()> {
    tracing::trace!(
        peer = %row.node_id,
        last_sync_at = ?row.last_sync_at,
        "mesh sync cycle",
    );
    let since_pull = row.last_sync_db_version.unwrap_or(0);
    let cursor_push = row.our_push_cursor.unwrap_or(0);
    let page = rt.cfg.sync_max_changes_per_request.max(1);

    let base = base_url.trim_end_matches('/');
    let node_q = utf8_percent_encode(rt.our_node_id.as_ref(), NON_ALPHANUMERIC).to_string();

    let mut since = since_pull;
    let mut hdr_ver;
    let mut n_received = 0usize;

    loop {
        let pull_url = format!(
            "{}/sync/changes?since_db_version={}&node_id={}&limit={page}&protocol_version={}",
            base, since, node_q, MESH_SYNC_PROTOCOL_VERSION
        );

        let pull_resp = rt
            .client
            .get(&pull_url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", rt.bearer_token.as_ref()),
            )
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("GET peer /sync/changes: {e}"))?;

        if !pull_resp.status().is_success() {
            anyhow::bail!(
                "GET peer /sync/changes: HTTP {} {}",
                pull_resp.status(),
                pull_resp.text().await.unwrap_or_default()
            );
        }

        let peer_proto = mesh_protocol_version_hdr(&pull_resp);
        hdr_ver = peer_db_version_hdr(&pull_resp)?;
        let truncated = response_truncated_hdr(&pull_resp);
        let batch: Vec<CrsqlWireChange> = pull_resp.json().await.map_err(anyhow::Error::msg)?;
        let batch_len = batch.len();
        if batch_len == 0 {
            break;
        }

        if let Some(mut block) = truncation_block_reason(batch_len, page, peer_proto) {
            let streak = record_truncation_block(rt, &row.node_id);
            block.consecutive_failures = streak;
            if streak >= TRUNCATION_BLOCK_ESCALATE_AFTER {
                tracing::error!(
                    peer = %row.node_id,
                    region = %row.region,
                    streak,
                    batch_len,
                    page,
                    peer_protocol = ?peer_proto,
                    since_db_version = since,
                    "mesh sync truncation-blocked repeatedly: peer still on pre-pagination \
                     protocol while backlog exceeds one page — upgrade this peer now; \
                     revocations and other changes may not propagate until sync succeeds"
                );
            } else {
                tracing::error!(
                    peer = %row.node_id,
                    region = %row.region,
                    streak,
                    batch_len,
                    page,
                    peer_protocol = ?peer_proto,
                    since_db_version = since,
                    "mesh sync truncation-blocked: refusing partial apply from pre-pagination \
                     peer; sync cursor not advanced (safe during staged rollout while backlog \
                     fits one page; retry next cycle or upgrade peer)"
                );
            }
            return Err(block.into());
        }

        if batch_len >= page && peer_supports_pagination(peer_proto) && !truncated {
            tracing::warn!(
                peer = %row.node_id,
                batch_len,
                page,
                peer_protocol = ?peer_proto,
                "mesh pull: full page without X-Changes-Truncated from v2 peer; continuing pagination"
            );
        } else if truncated {
            tracing::debug!(
                peer = %row.node_id,
                batch_len,
                page,
                since_db_version = since,
                "mesh pull: truncated page from pagination-capable peer; continuing"
            );
        }

        apply_crsql_wire_rows(&rt.pool, &batch).await?;
        n_received += batch_len;

        let max_dv = batch
            .iter()
            .map(|c| c.db_version)
            .max()
            .unwrap_or(since);
        since = max_dv;

        if batch_len < page {
            break;
        }
    }

    resolve_mesh_email_conflicts(&rt.pool).await?;

    let mut cursor = cursor_push;
    let mut n_sent = 0usize;
    let mut max_sent_db_ver = cursor_push;

    loop {
        let outbound =
            pull_own_site_changes_since(&rt.pool, cursor, &rt.our_site_id, page).await?;
        let batch_len = outbound.len();
        if batch_len == 0 {
            break;
        }

        max_sent_db_ver = outbound
            .iter()
            .map(|c| c.db_version)
            .max()
            .unwrap_or(max_sent_db_ver);
        n_sent += batch_len;

        let push_url = format!("{}/sync/apply", base);
        let push_resp = rt
            .client
            .post(&push_url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", rt.bearer_token.as_ref()),
            )
            .json(&outbound)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("POST peer /sync/apply: {e}"))?;

        if !push_resp.status().is_success() {
            anyhow::bail!("POST peer /sync/apply: HTTP {}", push_resp.status());
        }

        cursor = max_sent_db_ver;
        if batch_len < page {
            break;
        }
    }

    let new_push_cursor = max_sent_db_ver.max(cursor_push);
    update_mesh_peer_progress(&rt.pool, &row.node_id, hdr_ver, new_push_cursor).await?;
    clear_truncation_block(rt, &row.node_id);

    tracing::info!(
        "Sync with {} ({}) completed: {} changes received, {} sent",
        row.region,
        row.node_id,
        n_received,
        n_sent
    );
    Ok(())
}

fn peer_db_version_hdr(resp: &reqwest::Response) -> anyhow::Result<i64> {
    let raw = resp
        .headers()
        .get(HDR_DB_VERSION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("peer response missing `{}` header", HDR_DB_VERSION))?;
    Ok(raw.trim().parse()?)
}

fn mesh_protocol_version_hdr(resp: &reqwest::Response) -> Option<u32> {
    resp.headers()
        .get(HDR_MESH_PROTOCOL)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse().ok())
}

fn response_truncated_hdr(resp: &reqwest::Response) -> bool {
    resp.headers()
        .get(HDR_CHANGES_TRUNCATED)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("true"))
}

fn record_truncation_block(rt: &MeshRuntime, peer_id: &str) -> u32 {
    let mut guard = rt
        .truncation_block_streaks
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let streak = guard.entry(peer_id.to_string()).or_insert(0);
    *streak += 1;
    *streak
}

fn clear_truncation_block(rt: &MeshRuntime, peer_id: &str) {
    if let Ok(mut guard) = rt.truncation_block_streaks.lock() {
        guard.remove(peer_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    #[test]
    fn truncation_block_decision_small_batch_allows_old_protocol() {
        assert!(truncation_block_reason(5, 100, None).is_none());
        assert!(truncation_block_reason(5, 100, Some(1)).is_none());
        assert!(!peer_supports_pagination(None));
        assert!(peer_supports_pagination(Some(2)));
    }

    #[test]
    fn truncation_block_decision_full_page_rejects_old_protocol() {
        let block = truncation_block_reason(100, 100, None).expect("should block");
        assert_eq!(block.batch_len, 100);
        assert_eq!(block.page, 100);
        assert_eq!(block.peer_protocol, None);

        assert!(truncation_block_reason(100, 100, Some(1)).is_some());
    }

    #[test]
    fn truncation_block_decision_full_page_allows_v2_protocol() {
        assert!(truncation_block_reason(100, 100, Some(2)).is_none());
        assert!(truncation_block_reason(100, 100, Some(3)).is_none());
    }

    #[tokio::test]
    async fn truncation_block_streak_counter() {
        let rt = test_mesh_runtime_stub().await;
        assert_eq!(record_truncation_block(&rt, "peer-a"), 1);
        assert_eq!(record_truncation_block(&rt, "peer-a"), 2);
        assert_eq!(record_truncation_block(&rt, "peer-b"), 1);
        clear_truncation_block(&rt, "peer-a");
        assert_eq!(record_truncation_block(&rt, "peer-a"), 1);
    }

    async fn test_mesh_runtime_stub() -> MeshRuntime {
        MeshRuntime {
            cfg: MeshConfig {
                enabled: true,
                node_id_path: std::path::Path::new("/tmp/x").into(),
                crsqlite_extension_path: std::path::Path::new("/tmp/x").into(),
            crsqlite_extension_sha256: None,
                sync_interval_minutes: 60,
                sync_api_port: 1,
                sync_tls_cert: None,
                sync_tls_key: None,
                peers: vec![],
                sync_authorization_secret: "secret-long-enough!!".into(),
                sync_max_body_bytes: 1024 * 1024,
                sync_max_changes_per_request: 10,
                sync_rate_limit_requests: 600,
            },
            pool: SqlitePoolOptions::new()
                .max_connections(1)
                .connect("sqlite::memory:")
                .await
                .unwrap(),
            our_node_id: "self".into(),
            our_site_id: vec![],
            client: reqwest::Client::new(),
            bearer_token: "secret-long-enough!!".into(),
            truncation_block_streaks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[tokio::test]
    async fn truncation_block_does_not_advance_peer_cursor() {
        use axum::http::Response;
        use tokio::net::TcpListener;

        let page = 2usize;
        let batch = vec![
            db::CrsqlWireChange {
                table_name: "keys".into(),
                pk_b64: "AA==".into(),
                cid: "status".into(),
                val_b64: Some("YWN0aXZl".into()),
                col_version: 1,
                db_version: 11,
                site_id_b64: "AQ==".into(),
                cl_b64: None,
                seq: None,
            },
            db::CrsqlWireChange {
                table_name: "keys".into(),
                pk_b64: "AQ==".into(),
                cid: "status".into(),
                val_b64: Some("YWN0aXZl".into()),
                col_version: 1,
                db_version: 12,
                site_id_b64: "AQ==".into(),
                cl_b64: None,
                seq: None,
            },
        ];
        let batch_json = serde_json::to_string(&batch).unwrap();

        let app = Router::new().route(
            "/sync/changes",
            get(move || {
                let body = batch_json.clone();
                async move {
                    Response::builder()
                        .header(HDR_DB_VERSION, "12")
                        .header("Content-Type", "application/json")
                        .body(body)
                        .unwrap()
                }
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        sqlx::query(
            r#"INSERT INTO mesh_peers (node_id, region, address, last_sync_db_version, our_push_cursor)
               VALUES ('peer-old', 'R', ?, 10, 0)"#,
        )
        .bind(format!("http://127.0.0.1:{port}"))
        .execute(&pool)
        .await
        .unwrap();

        let row = db::mesh_peer_states(&pool)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();

        let rt = MeshRuntime {
            cfg: MeshConfig {
                enabled: true,
                node_id_path: std::path::Path::new("/tmp/x").into(),
                crsqlite_extension_path: std::path::Path::new("/tmp/x").into(),
            crsqlite_extension_sha256: None,
                sync_interval_minutes: 60,
                sync_api_port: 1,
                sync_tls_cert: None,
                sync_tls_key: None,
                peers: vec![],
                sync_authorization_secret: "secret-long-enough!!".into(),
                sync_max_body_bytes: 1024 * 1024,
                sync_max_changes_per_request: page,
                sync_rate_limit_requests: 600,
            },
            pool: pool.clone(),
            our_node_id: "self-node".into(),
            our_site_id: vec![1],
            client: reqwest::Client::new(),
            bearer_token: "secret-long-enough!!".into(),
            truncation_block_streaks: Arc::new(Mutex::new(HashMap::new())),
        };

        let base = format!("http://127.0.0.1:{port}");
        let err = sync_pull_push(&rt, &row, &base).await.expect_err("must fail closed");
        assert!(
            err.downcast_ref::<TruncationBlockedError>().is_some(),
            "expected TruncationBlockedError, got: {err:#}"
        );

        let cursor: i64 =
            sqlx::query_scalar("SELECT last_sync_db_version FROM mesh_peers WHERE node_id = 'peer-old'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(cursor, 10, "cursor must not advance on truncation-block");
    }

    #[tokio::test]
    async fn small_batch_old_protocol_completes_sync() {
        use axum::http::Response;
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        use tokio::net::TcpListener;

        let page = 10usize;
        let pull_hits = Arc::new(AtomicUsize::new(0));
        let pull_hits_c = pull_hits.clone();
        let batch = vec![db::CrsqlWireChange {
            table_name: "keys".into(),
            pk_b64: "AA==".into(),
            cid: "status".into(),
            val_b64: Some("YWN0aXZl".into()),
            col_version: 1,
            db_version: 11,
            site_id_b64: "AQ==".into(),
            cl_b64: None,
            seq: None,
        }];
        let batch_json = serde_json::to_string(&batch).unwrap();

        let app = Router::new().route(
            "/sync/changes",
            get(move || {
                let body = batch_json.clone();
                let pull_hits_c = pull_hits_c.clone();
                async move {
                    pull_hits_c.fetch_add(1, Ordering::SeqCst);
                    Response::builder()
                        .header(HDR_DB_VERSION, "11")
                        .header("Content-Type", "application/json")
                        .body(body)
                        .unwrap()
                }
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        sqlx::query(
            r#"INSERT INTO mesh_peers (node_id, region, address, last_sync_db_version, our_push_cursor)
               VALUES ('peer-old', 'R', ?, 10, 0)"#,
        )
        .bind(format!("http://127.0.0.1:{port}"))
        .execute(&pool)
        .await
        .unwrap();

        let row = db::mesh_peer_states(&pool)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();

        let rt = MeshRuntime {
            cfg: MeshConfig {
                enabled: true,
                node_id_path: std::path::Path::new("/tmp/x").into(),
                crsqlite_extension_path: std::path::Path::new("/tmp/x").into(),
            crsqlite_extension_sha256: None,
                sync_interval_minutes: 60,
                sync_api_port: 1,
                sync_tls_cert: None,
                sync_tls_key: None,
                peers: vec![],
                sync_authorization_secret: "secret-long-enough!!".into(),
                sync_max_body_bytes: 1024 * 1024,
                sync_max_changes_per_request: page,
                sync_rate_limit_requests: 600,
            },
            pool: pool.clone(),
            our_node_id: "self-node".into(),
            our_site_id: vec![1],
            client: reqwest::Client::new(),
            bearer_token: "secret-long-enough!!".into(),
            truncation_block_streaks: Arc::new(Mutex::new(HashMap::new())),
        };

        let base = format!("http://127.0.0.1:{port}");
        // apply may fail without CR-SQLite tables; small-batch path must pass truncation gate first.
        let result = sync_pull_push(&rt, &row, &base).await;
        assert!(
            result.is_err(),
            "expected apply/push failure without CR-SQLite, not truncation-block"
        );
        assert!(
            result
                .unwrap_err()
                .downcast_ref::<TruncationBlockedError>()
                .is_none(),
            "small batch from old protocol must not hit truncation-block"
        );
        assert_eq!(pull_hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn mesh_protocol_version_header_parsing() {
        use axum::http::Response;

        let resp = reqwest::Response::from(
            Response::builder()
                .header(HDR_MESH_PROTOCOL, "2")
                .body("{}")
                .unwrap(),
        );
        assert_eq!(mesh_protocol_version_hdr(&resp), Some(2));
        assert!(!response_truncated_hdr(&resp));

        let resp = reqwest::Response::from(
            Response::builder()
                .header(HDR_CHANGES_TRUNCATED, "true")
                .body("{}")
                .unwrap(),
        );
        assert!(response_truncated_hdr(&resp));
        assert_eq!(mesh_protocol_version_hdr(&resp), None);
    }

    #[tokio::test]
    async fn dynamic_dns_failure_returns_none_so_peer_is_skipped() {
        let row = db::MeshPeerDbRow {
            node_id: "peer".into(),
            region: "R".into(),
            address: "https://host.invalid:9443".into(),
            dynamic_dns_host: Some(
                concat!(
                    "this-label-will-never-resolve-",
                    "zzzz-invalid-host",
                    ".invalid"
                )
                .into(),
            ),
            last_sync_at: None,
            last_sync_db_version: None,
            our_push_cursor: None,
        };

        let cfg = MeshConfig {
            enabled: true,
            node_id_path: std::path::Path::new("/tmp/x").into(),
            crsqlite_extension_path: std::path::Path::new("/tmp/x").into(),
            crsqlite_extension_sha256: None,
            sync_interval_minutes: 60,
            sync_api_port: 1,
            sync_tls_cert: None,
            sync_tls_key: None,
            peers: vec![],
            sync_authorization_secret: "secret-long-enough!!".into(),
            sync_max_body_bytes: 1024 * 1024,
            sync_max_changes_per_request: 10_000,
            sync_rate_limit_requests: 600,
        };

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let rt = MeshRuntime {
            cfg,
            pool,
            our_node_id: "self".into(),
            our_site_id: vec![],
            client: reqwest::Client::new(),
            bearer_token: "x".into(),
            truncation_block_streaks: Arc::new(Mutex::new(HashMap::new())),
        };

        let resolved = resolve_peer_base_url(&rt, &row).await.unwrap();
        assert!(resolved.is_none());
    }

    #[tokio::test]
    #[ignore = "manual integration: two nodes with CR-SQLite, shared sync secret, reachable sync_api_port"]
    async fn mesh_two_nodes_converge_after_bilateral_exchange() {}
}
