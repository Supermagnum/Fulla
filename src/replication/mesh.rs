//! CR-SQLite mesh peer sync API and bilateral exchange cron.

use std::net::SocketAddr;
use std::sync::Arc;
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
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::Deserialize;
use url::Url;

use crate::config::MeshConfig;
use crate::db::{
    self, apply_crsql_wire_rows, crsql_site_id_bytes, mesh_peer_states, pull_crsql_changes_since,
    pull_own_site_changes_since, resolve_mesh_email_conflicts, update_mesh_peer_progress,
    CrsqlWireChange,
};
use crate::replication::dns::{resolve_host_first_ip, substitute_host_token};
use sqlx::SqlitePool;

const HDR_DB_VERSION: &str = "X-DB-Version";

#[derive(Clone)]
pub(crate) struct MeshApiState {
    pub pool: SqlitePool,
    pub bearer_token: Arc<str>,
}

#[derive(Clone)]
struct MeshRuntime {
    cfg: MeshConfig,
    pool: SqlitePool,
    our_node_id: Arc<str>,
    our_site_id: Vec<u8>,
    client: reqwest::Client,
    bearer_token: Arc<str>,
}

pub(crate) async fn start(
    cfg: MeshConfig,
    pool: SqlitePool,
    our_node_id: String,
) -> anyhow::Result<()> {
    let bearer: Arc<str> = Arc::from(cfg.sync_authorization_secret.trim());

    let st = MeshApiState {
        pool: pool.clone(),
        bearer_token: bearer.clone(),
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
    };

    spawn_sync_cron(rt);
    Ok(())
}

fn spawn_sync_server(cfg: &MeshConfig, st: MeshApiState) -> anyhow::Result<()> {
    let bearer_state = st.clone();
    let app = Router::new()
        .route("/sync/changes", get(get_changes_handler))
        .route("/sync/apply", post(apply_changes_handler))
        .route_layer(middleware::from_fn_with_state(
            bearer_state.clone(),
            bearer_auth_middleware,
        ))
        .with_state(st);

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
}

async fn bearer_auth_middleware(
    State(st): State<MeshApiState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok());
    let ok = matches!(
        auth,
        Some(a)
            if a.len() >= 8
                && a[..7].eq_ignore_ascii_case("bearer ")
                && a[7..].eq(st.bearer_token.as_ref()),
    );
    if !ok {
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

    match pull_crsql_changes_since(&st.pool, q.since_db_version).await {
        Ok((rows, head)) => {
            let mut res = Json(rows).into_response();
            match axum::http::HeaderValue::from_str(&head.to_string()) {
                Ok(v) => {
                    res.headers_mut().insert(HDR_DB_VERSION, v);
                }
                Err(e) => {
                    tracing::error!(error = %e, "mesh: invalid {}", HDR_DB_VERSION);
                }
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
                tracing::warn!(
                    error = %e,
                    region = %row.region,
                    node_id = %row.node_id,
                    "mesh peer sync failed",
                );
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

    let base = base_url.trim_end_matches('/');
    let node_q = utf8_percent_encode(rt.our_node_id.as_ref(), NON_ALPHANUMERIC).to_string();
    let pull_url = format!(
        "{}/sync/changes?since_db_version={}&node_id={}",
        base, since_pull, node_q
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

    let hdr_ver = peer_db_version_hdr(&pull_resp)?;
    let received: Vec<CrsqlWireChange> = pull_resp.json().await.map_err(anyhow::Error::msg)?;
    let n_received = received.len();

    apply_crsql_wire_rows(&rt.pool, &received).await?;
    resolve_mesh_email_conflicts(&rt.pool).await?;

    let outbound = pull_own_site_changes_since(&rt.pool, cursor_push, &rt.our_site_id).await?;
    let n_sent = outbound.len();
    let max_sent_db_ver = outbound.iter().map(|c| c.db_version).max().unwrap_or(0);

    if !outbound.is_empty() {
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
    }

    let new_push_cursor = max_sent_db_ver.max(cursor_push);
    update_mesh_peer_progress(&rt.pool, &row.node_id, hdr_ver, new_push_cursor).await?;

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

#[cfg(test)]
mod tests {
    use super::*;

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
            sync_interval_minutes: 60,
            sync_api_port: 1,
            sync_tls_cert: None,
            sync_tls_key: None,
            peers: vec![],
            sync_authorization_secret: "s".into(),
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
        };

        let resolved = resolve_peer_base_url(&rt, &row).await.unwrap();
        assert!(resolved.is_none());
    }

    #[tokio::test]
    #[ignore = "manual integration: two nodes with CR-SQLite, shared sync secret, reachable sync_api_port"]
    async fn mesh_two_nodes_converge_after_bilateral_exchange() {}
}
