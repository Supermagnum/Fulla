//! SSH/rsync file copy fallback.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::process::Command;

use crate::config::SshSyncConfig;
use crate::replication::dns::{resolve_host_first_ip, substitute_host_token};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(test)]
static SSH_SPAWN: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn ssh_spawn_count_for_test() -> usize {
    SSH_SPAWN.load(Ordering::SeqCst)
}

#[cfg(test)]
fn record_spawn() {
    SSH_SPAWN.fetch_add(1, Ordering::SeqCst);
}

pub fn ssh_tools_available() -> bool {
    rsync_available() && ssh_available()
}

fn rsync_available() -> bool {
    std::process::Command::new("rsync")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn ssh_available() -> bool {
    std::process::Command::new("ssh")
        .args(["-V"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub(crate) fn spawn_cron(
    cfg: SshSyncConfig,
    db_path: PathBuf,
    litestream_interval_when_active: Option<u64>,
) {
    #[cfg(test)]
    record_spawn();
    tokio::spawn(async move {
        let first_delay_secs = initial_ssh_delay_secs(&cfg, litestream_interval_when_active);
        tokio::time::sleep(Duration::from_secs(first_delay_secs)).await;
        loop {
            run_rsync_once(&cfg, &db_path).await;
            tokio::time::sleep(duration_minutes(cfg.interval_minutes)).await;
        }
    });
}

pub(crate) fn initial_ssh_delay_secs(
    cfg: &SshSyncConfig,
    litestream_interval_minutes: Option<u64>,
) -> u64 {
    match litestream_interval_minutes {
        Some(lit) => lit.saturating_add(cfg.offset_minutes).saturating_mul(60),
        None => cfg.interval_minutes.max(1).saturating_mul(60),
    }
}

fn duration_minutes(m: u64) -> Duration {
    Duration::from_secs(m.max(1) * 60)
}

fn shell_escape_unix(p: &str) -> String {
    let mut s = String::with_capacity(p.len() + 2);
    s.push('\'');
    for c in p.chars() {
        if c == '\'' {
            s.push_str("'\"'\"'");
        } else {
            s.push(c);
        }
    }
    s.push('\'');
    s
}

fn format_ip_for_ssh(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(_) => ip.to_string(),
        IpAddr::V6(_) => format!("[{ip}]"),
    }
}

async fn run_rsync_once(cfg: &SshSyncConfig, db_path: &Path) {
    let host_for_conn = if let Some(dynh) = &cfg.dynamic_dns_host {
        let t = dynh.trim();
        if t.is_empty() {
            cfg.remote_host.clone()
        } else {
            match resolve_host_first_ip(t).await {
                Ok(ip) => format_ip_for_ssh(&ip),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        host = %t,
                        "SSH sync: dynamic DNS resolution failed; skipping cycle"
                    );
                    return;
                }
            }
        }
    } else {
        cfg.remote_host.clone()
    };

    let remote = format!("{}@{}:{}", cfg.remote_user, host_for_conn, cfg.remote_path);
    let ssh_cmd = format!(
        "ssh -i {} -o StrictHostKeyChecking=no",
        shell_escape_unix(&cfg.ssh_key_path)
    );

    let out = Command::new("rsync")
        .args(["-az", "--delete", "-e", &ssh_cmd])
        .arg(db_path.as_os_str())
        .arg(&remote)
        .output()
        .await;

    match out {
        Ok(o) if o.status.success() => {
            tracing::info!("SSH sync completed to {}", host_for_conn);
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            let stdout = String::from_utf8_lossy(&o.stdout);
            tracing::error!(%stderr, %stdout, status = ?o.status, "SSH sync failed");
        }
        Err(e) => {
            tracing::error!(error = %e, "SSH sync failed to execute");
        }
    }
}

/// Replace `dynamic_dns_host` substring in SSH `remote_host` when both are aligned (best-effort).
#[allow(dead_code)]
pub(crate) fn ssh_substitute_dyn_host(
    remote_host_cfg: &str,
    dynh: Option<&str>,
    ip: IpAddr,
) -> String {
    if let Some(h) = dynh {
        let t = h.trim();
        if !t.is_empty() && remote_host_cfg.contains(t) {
            return substitute_host_token(remote_host_cfg, t, ip);
        }
    }
    remote_host_cfg.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SshSyncConfig;

    #[test]
    fn ssh_initial_delay_with_litestream() {
        let ssh = SshSyncConfig {
            enabled: true,
            remote_user: "u".into(),
            remote_host: "h".into(),
            remote_path: "/p".into(),
            ssh_key_path: "/k".into(),
            dynamic_dns_host: None,
            interval_minutes: 60,
            offset_minutes: 5,
        };
        assert_eq!(initial_ssh_delay_secs(&ssh, Some(60)), 65 * 60,);
    }

    #[test]
    fn ssh_initial_delay_standalone() {
        let ssh = SshSyncConfig {
            enabled: true,
            remote_user: "u".into(),
            remote_host: "h".into(),
            remote_path: "/p".into(),
            ssh_key_path: "/k".into(),
            dynamic_dns_host: None,
            interval_minutes: 45,
            offset_minutes: 5,
        };
        assert_eq!(initial_ssh_delay_secs(&ssh, None), 45 * 60);
    }
}
