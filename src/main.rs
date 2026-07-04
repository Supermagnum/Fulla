#![forbid(unsafe_code)]

mod config;
mod db;
mod email_normalize;
mod handlers;
mod mail;
mod models;
mod openpgp;
mod rate_limit;
mod replication;
mod templates;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use tower_http::compression::CompressionLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::handlers::{confirm, revoke, submit, web};
use crate::mail::Mailer;
use crate::rate_limit::RateLimits;
use crate::templates::WebTemplates;

/// Shared server state (`RegistryKeyserverConfig` lives in firmware; avoid that name here).
#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub config: Arc<Config>,
    pub mailer: Arc<Mailer>,
    pub templates: Arc<WebTemplates>,
    pub rate_limits: RateLimits,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let config = Arc::new(Config::from_env()?);
    tracing::info!(bind = %config.keyserver_bind, "starting Fulla registry");

    let mesh_active = config.replication.mesh.as_ref().is_some_and(|m| m.enabled);

    let mesh_extension_path: Option<String> = if mesh_active {
        let mesh = config
            .replication
            .mesh
            .as_ref()
            .expect("mesh config when mesh_active");
        let path = mesh.crsqlite_extension_path.as_path();
        if !path.exists() {
            tracing::error!(
                path = %path.display(),
                "CR-SQLite extension file missing; mesh replication cannot start",
            );
            None
        } else {
            Some(path.to_string_lossy().into_owned())
        }
    } else {
        None
    };

    if mesh_active && mesh_extension_path.is_none() {
        anyhow::bail!(
            "CR-SQLite extension file missing — install the extension at the configured replication.mesh.crsqlite_extension_path or disable replication.mesh.enabled",
        );
    }

    let mut pool_opts = SqlitePoolOptions::new().max_connections(5);
    if let Some(ext) = mesh_extension_path.clone() {
        pool_opts = pool_opts.after_connect(move |conn, _meta| {
            let ext_owned = ext.clone();
            Box::pin(async move {
                db::sqlite_connection_load_extension(conn, ext_owned.as_str())
                    .await
                    .map_err(|e| sqlx::Error::protocol(e.to_string()))?;
                Ok(())
            })
        });
    }

    let pool = pool_opts.connect(&config.database_url).await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    if mesh_active {
        db::crsql_activate_keys(&pool).await?;
        let peers_cfg = config.replication.mesh.as_ref().expect("mesh when active");
        db::upsert_mesh_peers_from_config(&pool, &peers_cfg.peers).await?;
        let keep: Vec<String> = peers_cfg.peers.iter().map(|p| p.node_id.clone()).collect();
        db::prune_mesh_peers(&pool, &keep).await?;
    }

    let db_for_replication = config::sqlite_database_file_path(&config.database_url);
    replication::start(&config.replication, db_for_replication.as_deref(), &pool).await?;

    let mailer = Arc::new(Mailer::new(config.as_ref())?);
    let templates = Arc::new(WebTemplates::load_from_dir(template_dir()?)?);

    let rate_limits = RateLimits::from_config(config.as_ref());

    let state = AppState {
        pool: pool.clone(),
        config: config.clone(),
        mailer,
        templates,
        rate_limits,
    };

    tokio::spawn(run_pending_cleaner(pool));

    let read_public = Router::new()
        .route("/confirm/:token", get(confirm::handle_confirm))
        .route("/reject/:token", get(confirm::handle_reject))
        .with_state(state.clone());

    let mut read_limited = Router::new()
        .route("/", get(web::index))
        .route("/keys", get(web::key_list))
        .route("/keys/:fingerprint", get(web::key_detail))
        .route("/submit", get(web::submit_form))
        .route("/revoke", get(web::revoke_form));

    if config.keyserver_rate_limit_reads.is_some() || config.keyserver_rate_limit_reads_global.is_some()
    {
        read_limited = read_limited.layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit::read_rate_guard,
        ));
    }

    let read_only = read_limited
        .with_state(state.clone())
        .merge(read_public);

    let mutate = Router::new()
        .route("/submit", post(submit::handle_form))
        .route("/api/v1/keys", post(submit::handle_api))
        .route("/revoke", post(revoke::handle_form))
        .route("/api/v1/keys/revoke", post(revoke::handle_api))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit::mutation_rate_guard,
        ))
        .with_state(state.clone());

    let app = Router::new()
        .merge(read_only)
        .merge(mutate)
        .layer(RequestBodyLimitLayer::new(128 * 1024))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = config.keyserver_bind.parse()?;

    if let (Some(cert), Some(key)) = (
        config.keyserver_tls_cert.as_ref(),
        config.keyserver_tls_key.as_ref(),
    ) {
        let tls = RustlsConfig::from_pem_file(cert, key).await?;
        tracing::info!(%addr, "listening with TLS");
        axum_server::bind_rustls(addr, tls)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        tracing::warn!(
            "TLS credential paths unset; binding plain HTTP (development / reverse-proxy mode)"
        );
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
    }

    Ok(())
}

fn template_dir() -> anyhow::Result<std::path::PathBuf> {
    let cwd = Path::new("templates");
    if cwd.is_dir() {
        return Ok(cwd.into());
    }
    let exe = Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
    anyhow::ensure!(
        exe.is_dir(),
        "templates directory missing (try running from workspace root)"
    );
    Ok(exe)
}

async fn run_pending_cleaner(pool: SqlitePool) {
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    loop {
        tick.tick().await;
        match db::expire_pending(&pool).await {
            Ok(n) => {
                if n > 0 {
                    tracing::info!(removed = n, "expired pending submissions");
                }
            }
            Err(e) => tracing::error!(error=?e, "pending housekeeping failed"),
        }
    }
}
