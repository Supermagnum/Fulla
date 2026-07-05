#![forbid(unsafe_code)]

mod auth;
mod config;
mod db;
mod email_normalize;
mod extension_integrity;
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
            extension_integrity::validate_native_extension(
                path,
                mesh.crsqlite_extension_sha256.as_deref(),
            )
            .map_err(|e| {
                tracing::error!(
                    path = %path.display(),
                    error = %e,
                    "CR-SQLite extension integrity check failed"
                );
                e
            })?;
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

    let app = build_app(&state);

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

/// Assemble the HTTP router (shared by production and integration tests).
pub(crate) fn build_app(state: &AppState) -> Router {
    let config = state.config.as_ref();

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
            auth::mutation_auth_guard,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit::mutation_rate_guard,
        ))
        .with_state(state.clone());

    Router::new()
        .merge(read_only)
        .merge(mutate)
        .layer(RequestBodyLimitLayer::new(config.keyserver_max_key_upload_bytes))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
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

#[cfg(test)]
mod http_integration_tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sqlx::sqlite::SqlitePoolOptions;
    use tower::ServiceExt;

    use super::*;
    use crate::rate_limit::RateLimits;

    const AUTH_SECRET: &str = "integration-test-secret";

    async fn test_state(auth: bool) -> AppState {
        let pool = SqlitePoolOptions::new()
            .max_connections(2)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();

        let mut cfg = Config::test_local();
        cfg.keyserver_mutation_auth_secret = if auth {
            Some(AUTH_SECRET.into())
        } else {
            None
        };

        AppState {
            pool,
            config: Arc::new(cfg),
            mailer: Arc::new(Mailer::noop_for_tests()),
            templates: Arc::new(
                WebTemplates::load_from_dir(template_dir().expect("templates")).expect("load"),
            ),
            rate_limits: RateLimits::permissive_for_tests(),
        }
    }

    fn armored_key(email: &str) -> String {
        use sequoia_openpgp::armor;
        use sequoia_openpgp::cert::CertBuilder;
        use sequoia_openpgp::cert::CipherSuite;
        use sequoia_openpgp::serialize::Serialize as PgpSerialize;

        let cert = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_userid(format!("T <{email}>"))
            .add_signing_subkey()
            .generate()
            .expect("gen")
            .0;
        let mut buf = Vec::new();
        let mut w = armor::Writer::new(&mut buf, armor::Kind::PublicKey).unwrap();
        cert.serialize(&mut w).unwrap();
        w.finalize().unwrap();
        String::from_utf8(buf).unwrap()
    }

    async fn request(
        app: &mut Router,
        method: &str,
        uri: &str,
        auth: Option<&str>,
        body: Option<String>,
    ) -> StatusCode {
        let mut builder = Request::builder().method(method).uri(uri);
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        builder = builder.header("accept", "application/json");
        if let Some(token) = auth {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let req = builder
            .body(Body::from(body.unwrap_or_default()))
            .unwrap();
        let resp = app.oneshot(req).await.expect("response");
        resp.status()
    }

    #[tokio::test]
    async fn mutation_auth_rejects_missing_and_wrong_bearer() {
        let state = test_state(true).await;
        let mut app = build_app(&state);
        let email = "auth-test@example.com";
        let body = serde_json::json!({
            "email": email,
            "armored_public_key": armored_key(email),
        })
        .to_string();

        assert_eq!(
            request(&mut app, "POST", "/api/v1/keys", None, Some(body.clone())).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(&mut app, "POST", "/api/v1/keys", Some("wrong-token"), Some(body.clone()))
                .await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(
                &mut app,
                "POST",
                "/api/v1/keys",
                Some(AUTH_SECRET),
                Some(body.clone())
            )
            .await,
            StatusCode::ACCEPTED
        );

        let revoke_body = serde_json::json!({
            "email": email,
            "armored_revocation_cert": "-----BEGIN PGP PUBLIC KEY BLOCK-----\ninvalid\n-----END PGP PUBLIC KEY BLOCK-----",
        })
        .to_string();
        assert_eq!(
            request(&mut app, "POST", "/api/v1/keys/revoke", None, Some(revoke_body.clone()))
                .await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(
                &mut app,
                "POST",
                "/api/v1/keys/revoke",
                Some(AUTH_SECRET),
                Some(revoke_body)
            )
            .await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[tokio::test]
    async fn mutation_auth_does_not_block_public_read_or_confirm_paths() {
        let state = test_state(true).await;
        let mut app = build_app(&state);

        assert_eq!(
            request(&mut app, "GET", "/keys?email=nobody@example.com", None, None).await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            request(
                &mut app,
                "GET",
                "/keys/ABCDEF0123456789ABCDEF0123456789ABCDEF01",
                None,
                None
            )
            .await,
            StatusCode::NOT_FOUND
        );

        let wrong = "0".repeat(64);
        assert_eq!(
            request(&mut app, "GET", &format!("/confirm/{wrong}"), None, None).await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            request(&mut app, "GET", &format!("/reject/{wrong}"), None, None).await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn open_registry_allows_unauthenticated_submit() {
        let state = test_state(false).await;
        let mut app = build_app(&state);
        let email = "open@test.example";
        let body = serde_json::json!({
            "email": email,
            "armored_public_key": armored_key(email),
        })
        .to_string();
        assert_eq!(
            request(&mut app, "POST", "/api/v1/keys", None, Some(body)).await,
            StatusCode::ACCEPTED
        );
    }
}
