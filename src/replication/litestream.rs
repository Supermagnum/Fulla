//! Periodic Litestream `replicate -once` (disaster recovery snapshots).

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::process::Command;

use crate::config::LitestreamConfig;
use crate::replication::dns::{resolve_host_first_ip, substitute_host_token};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(test)]
static LITESTREAM_SPAWN: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn litestream_spawn_count_for_test() -> usize {
    LITESTREAM_SPAWN.load(Ordering::SeqCst)
}

#[cfg(test)]
fn record_spawn() {
    LITESTREAM_SPAWN.fetch_add(1, Ordering::SeqCst);
}

pub fn litestream_available() -> bool {
    std::process::Command::new("litestream")
        .args(["version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub(crate) fn litestream_task_would_run(cfg: &crate::config::ReplicationConfig) -> bool {
    cfg.litestream
        .as_ref()
        .is_some_and(|l| l.enabled && litestream_available())
}

pub(crate) fn spawn_cron(cfg: LitestreamConfig, db_path: PathBuf) {
    #[cfg(test)]
    record_spawn();
    tokio::spawn(async move {
        loop {
            run_once(&cfg, &db_path).await;
            tokio::time::sleep(duration_minutes(cfg.interval_minutes)).await;
        }
    });
}

fn duration_minutes(m: u64) -> Duration {
    Duration::from_secs(m.max(1) * 60)
}

async fn run_once(cfg: &LitestreamConfig, db_path: &Path) {
    let mut url = cfg.replica_url.clone();
    if let Some(host) = &cfg.dynamic_dns_host {
        let host_trim = host.trim();
        if !host_trim.is_empty() {
            match resolve_host_first_ip(host_trim).await {
                Ok(ip) => {
                    url = substitute_host_token(&url, host_trim, ip);
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        host = %host_trim,
                        "Litestream: dynamic DNS resolution failed; skipping cycle"
                    );
                    return;
                }
            }
        }
    }

    if url.trim().is_empty() {
        tracing::error!("Litestream: replica_url is empty; skipping");
        return;
    }

    let out = Command::new("litestream")
        .args(["replicate", "-once"])
        .arg(db_path.as_os_str())
        .arg(&url)
        .output()
        .await;

    match out {
        Ok(o) if o.status.success() => {
            tracing::info!("Litestream sync completed");
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            let stdout = String::from_utf8_lossy(&o.stdout);
            tracing::error!(%stderr, %stdout, status = ?o.status, "Litestream sync failed");
        }
        Err(e) => {
            tracing::error!(error = %e, "Litestream sync failed to execute");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_binary_is_detected() {
        if litestream_available() {
            return;
        }
        assert!(!litestream_available());
    }
}
