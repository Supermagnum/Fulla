//! Environment-driven configuration (no `KeyserverConfig` — that name is reserved in Galdra for HKP).
//! Optional `[replication]` is read from `FULLA_CONFIG` (path to `config.toml`).

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub keyserver_base_url: String,
    pub keyserver_bind: String,
    pub keyserver_tls_cert: Option<PathBuf>,
    pub keyserver_tls_key: Option<PathBuf>,
    pub keyserver_smtp_host: String,
    pub keyserver_smtp_port: u16,
    pub keyserver_smtp_user: String,
    pub keyserver_smtp_password: String,
    pub keyserver_smtp_from: String,
    pub keyserver_smtp_tls: bool,
    pub keyserver_rate_limit_submissions: u32,
    pub replication: ReplicationConfig,
}

/// Optional replication: CR-SQLite mesh (disabled by default), Litestream, SSH (see `FULLA_CONFIG` TOML).
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ReplicationConfig {
    pub mesh: Option<MeshConfig>,
    pub litestream: Option<LitestreamConfig>,
    pub ssh: Option<SshSyncConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MeshConfig {
    #[serde(default)]
    pub enabled: bool,
    pub node_id_path: PathBuf,
    pub crsqlite_extension_path: PathBuf,
    #[serde(default = "default_interval")]
    pub sync_interval_minutes: u64,
    pub sync_api_port: u16,
    pub sync_tls_cert: Option<PathBuf>,
    pub sync_tls_key: Option<PathBuf>,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    #[serde(default)]
    pub sync_authorization_secret: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PeerConfig {
    pub node_id: String,
    pub region: String,
    pub address: String,
    pub dynamic_dns_host: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LitestreamConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub replica_url: String,
    pub dynamic_dns_host: Option<String>,
    #[serde(default = "default_interval")]
    pub interval_minutes: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SshSyncConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub remote_user: String,
    #[serde(default)]
    pub remote_host: String,
    #[serde(default)]
    pub remote_path: String,
    #[serde(default)]
    pub ssh_key_path: String,
    pub dynamic_dns_host: Option<String>,
    #[serde(default = "default_interval")]
    pub interval_minutes: u64,
    #[serde(default = "default_offset")]
    pub offset_minutes: u64,
}

fn default_interval() -> u64 {
    60
}

fn default_offset() -> u64 {
    5
}

pub const MAX_MESH_PEERS: usize = 13;

impl ReplicationConfig {
    pub fn validate(&self) -> Result<()> {
        if let Some(mesh) = &self.mesh {
            if mesh.enabled && mesh.sync_authorization_secret.trim().is_empty() {
                return Err(anyhow!(
                    "[replication.mesh] enabled requires a non-empty sync_authorization_secret"
                ));
            }
            if mesh.enabled && mesh.peers.len() > MAX_MESH_PEERS {
                return Err(anyhow!(
                    "Mesh supports a maximum of {MAX_MESH_PEERS} peers (14 nodes total including self)."
                ));
            }
            if mesh.enabled {
                match (&mesh.sync_tls_cert, &mesh.sync_tls_key) {
                    (Some(_), Some(_)) | (None, None) => {}
                    _ => {
                        return Err(anyhow!(
                            "replication.mesh: sync_tls_cert and sync_tls_key must both be set or both omitted"
                        ));
                    }
                }
            }
        }

        if let Some(ls) = &self.litestream {
            if ls.enabled && ls.replica_url.trim().is_empty() {
                return Err(anyhow!(
                    "[replication.litestream] enabled requires a non-empty replica_url"
                ));
            }
        }

        if let Some(ssh) = &self.ssh {
            if ssh.enabled
                && (ssh.remote_user.trim().is_empty() || ssh.remote_host.trim().is_empty())
            {
                return Err(anyhow!(
                    "[replication.ssh] enabled requires remote_user and remote_host"
                ));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize, Default)]
struct TomlEnvelope {
    #[serde(default)]
    replication: ReplicationConfig,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let database_url = req_var("DATABASE_URL")?;
        let keyserver_base_url = req_var("KEYSERVER_BASE_URL")?;
        let keyserver_bind = req_var("KEYSERVER_BIND")?;
        let keyserver_tls_cert = opt_path("KEYSERVER_TLS_CERT");
        let keyserver_tls_key = opt_path("KEYSERVER_TLS_KEY");
        let keyserver_smtp_host = req_var("KEYSERVER_SMTP_HOST")?;
        let keyserver_smtp_port = parse_u16("KEYSERVER_SMTP_PORT")?;
        let keyserver_smtp_user = req_var("KEYSERVER_SMTP_USER")?;
        let keyserver_smtp_password = req_var("KEYSERVER_SMTP_PASSWORD")?;
        let keyserver_smtp_from = req_var("KEYSERVER_SMTP_FROM")?;
        let keyserver_smtp_tls = parse_bool("KEYSERVER_SMTP_TLS", true);
        let mut keyserver_rate_limit_submissions =
            parse_u32("KEYSERVER_RATE_LIMIT_SUBMISSIONS").unwrap_or(5);
        if keyserver_rate_limit_submissions == 0 {
            keyserver_rate_limit_submissions = 5;
        }

        let replication = replication_from_optional_toml()?;

        Ok(Config {
            database_url,
            keyserver_base_url,
            keyserver_bind,
            keyserver_tls_cert,
            keyserver_tls_key,
            keyserver_smtp_host,
            keyserver_smtp_port,
            keyserver_smtp_user,
            keyserver_smtp_password,
            keyserver_smtp_from,
            keyserver_smtp_tls,
            keyserver_rate_limit_submissions,
            replication,
        })
    }
}

fn replication_from_optional_toml() -> Result<ReplicationConfig> {
    let Some(raw) = std::env::var("FULLA_CONFIG")
        .ok()
        .map(|v| v.trim().to_owned())
    else {
        return Ok(ReplicationConfig::default());
    };
    if raw.is_empty() {
        return Ok(ReplicationConfig::default());
    }

    let path = PathBuf::from(&raw);
    let txt = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read FULLA_CONFIG `{}`", path.display()))?;
    let env: TomlEnvelope =
        toml::from_str(&txt).with_context(|| format!("Invalid TOML in `{}`", path.display()))?;
    env.replication.validate()?;
    Ok(env.replication)
}

/// Returns the SQLite file backing `DATABASE_URL`, or [`None`] for in-memory databases.
pub fn sqlite_database_file_path(database_url: &str) -> Option<PathBuf> {
    let url = database_url.trim();
    let lower = url.to_ascii_lowercase();
    if lower.contains(":memory:") {
        return None;
    }

    let after_sqlite_prefix = url.strip_prefix("sqlite:")?;

    let path_part = match after_sqlite_prefix.strip_prefix("//") {
        Some(rest) => {
            if rest.is_empty() {
                None
            } else {
                Some(rest.trim_start_matches('/'))
            }
        }
        None => Some(after_sqlite_prefix.trim_start_matches('@')),
    }?;

    let path_part = path_part.trim();
    if path_part.is_empty()
        || path_part.eq_ignore_ascii_case("memory")
        || path_part.eq_ignore_ascii_case(":memory:")
    {
        return None;
    }

    Some(Path::new(path_part).to_owned())
}

fn req_var(name: &'static str) -> Result<String> {
    std::env::var(name)
        .with_context(|| format!("Required environment variable `{name}` is not set"))
}

fn opt_path(name: &'static str) -> Option<PathBuf> {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => Some(PathBuf::from(v.trim())),
        _ => None,
    }
}

fn parse_u16(name: &'static str) -> Result<u16> {
    let s = req_var(name)?;
    s.parse::<u16>()
        .map_err(|_| anyhow!("`{name}` must be a valid u16 (got {s:?})"))
}

fn parse_u32(name: &'static str) -> Option<u32> {
    std::env::var(name).ok().and_then(|v| v.trim().parse().ok())
}

fn parse_bool(name: &'static str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

#[cfg(test)]
impl Config {
    pub fn test_local() -> Self {
        Config {
            database_url: "sqlite::memory:".into(),
            keyserver_base_url: "http://127.0.0.1:8080".into(),
            keyserver_bind: "127.0.0.1:0".into(),
            keyserver_tls_cert: None,
            keyserver_tls_key: None,
            keyserver_smtp_host: "localhost".into(),
            keyserver_smtp_port: 25,
            keyserver_smtp_user: "test".into(),
            keyserver_smtp_password: "test".into(),
            keyserver_smtp_from: "fulla-test@localhost".into(),
            keyserver_smtp_tls: true,
            keyserver_rate_limit_submissions: 1000,
            replication: ReplicationConfig::default(),
        }
    }
}

#[cfg(test)]
mod replication_validation_tests {
    use super::*;

    #[test]
    fn fourteen_peers_errors_at_validation() {
        let peers: Vec<PeerConfig> = (0..14)
            .map(|i| PeerConfig {
                node_id: format!("{i:08x}-0000-0000-0000-000000000001"),
                region: "R".into(),
                address: "https://example.com:9443".into(),
                dynamic_dns_host: None,
            })
            .collect();
        let mesh = MeshConfig {
            enabled: true,
            node_id_path: "/tmp/n".into(),
            crsqlite_extension_path: "/tmp/e".into(),
            sync_interval_minutes: 60,
            sync_api_port: 9443,
            sync_tls_cert: None,
            sync_tls_key: None,
            peers,
            sync_authorization_secret: "secret".into(),
        };
        let rep = ReplicationConfig {
            mesh: Some(mesh),
            litestream: None,
            ssh: None,
        };
        let msg = rep.validate().unwrap_err().to_string();
        assert!(
            msg.contains("Mesh supports a maximum of 13 peers (14 nodes total including self)."),
            "unexpected error: {msg}"
        );
    }
}

#[cfg(test)]
mod sqlite_path_tests {
    use super::*;

    #[test]
    fn file_urls() {
        assert_eq!(
            sqlite_database_file_path("sqlite:./keyserver.db"),
            Some(PathBuf::from("./keyserver.db"))
        );
        assert_eq!(
            sqlite_database_file_path("sqlite:relative.db"),
            Some(PathBuf::from("relative.db"))
        );
    }

    #[test]
    fn memory_urls() {
        assert_eq!(sqlite_database_file_path("sqlite::memory:"), None);
        assert_eq!(sqlite_database_file_path("sqlite:memory:"), None);
    }
}
