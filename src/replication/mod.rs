//! Optional replication helpers: CR-SQLite mesh peer sync, Litestream snapshots, SSH/rsync.

mod dns;
mod litestream;
mod mesh;
mod ssh;

use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::config::ReplicationConfig;
use sqlx::SqlitePool;

pub(crate) async fn start(
    config: &ReplicationConfig,
    db_path: Option<&std::path::Path>,
    pool: &SqlitePool,
) -> anyhow::Result<()> {
    if let Some(mesh) = &config.mesh {
        if mesh.enabled {
            let node_id = load_or_create_node_id(&mesh.node_id_path)?;
            mesh::start(mesh.clone(), pool.clone(), node_id).await?;
        }
    }

    if let Some(ls) = &config.litestream {
        if ls.enabled {
            if !litestream::litestream_available() {
                tracing::warn!("Litestream replication enabled but the `litestream` binary was not found or is unusable on PATH; disabling Litestream cron");
            } else if let Some(p) = db_path.map(Path::to_owned) {
                litestream::spawn_cron(ls.clone(), p);
            } else {
                tracing::warn!("Litestream replication enabled but DATABASE_URL does not resolve to an on-disk SQLite file; disabling Litestream cron");
            }
        }
    }

    if let Some(ss) = &config.ssh {
        if ss.enabled {
            let litestream_iv = litestream::litestream_task_would_run(config)
                .then(|| config.litestream.as_ref().map(|x| x.interval_minutes))
                .flatten();

            if !ssh::ssh_tools_available() {
                tracing::warn!("SSH/rsync replication enabled but `ssh` or `rsync` was not found on PATH; disabling SSH cron");
            } else if let Some(p) = db_path.map(Path::to_owned) {
                ssh::spawn_cron(ss.clone(), p, litestream_iv);
            } else {
                tracing::warn!("SSH/rsync replication enabled but DATABASE_URL does not resolve to an on-disk SQLite file; disabling SSH cron");
            }
        }
    }

    Ok(())
}

pub fn load_or_create_node_id(path: &Path) -> anyhow::Result<String> {
    ensure_parent_dir(path)?;
    if path.exists() {
        let raw = std::fs::read_to_string(path)?;
        let id = uuid::Uuid::parse_str(raw.trim()).map_err(|e| {
            anyhow::anyhow!(
                "node id file `{}` exists but does not contain a UUID v4: {e}",
                path.display()
            )
        })?;
        return Ok(id.to_string());
    }

    let id = uuid::Uuid::new_v4();
    let txt = format!("{id}");

    #[cfg(unix)]
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.create_new(true).write(true);
        opts.mode(0o600);
        let mut file = opts.open(path)?;
        std::io::Write::write_all(&mut file, txt.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, txt.as_bytes())?;
    }

    Ok(id.to_string())
}

fn ensure_parent_dir(path: &Path) -> anyhow::Result<()> {
    let Some(dir) = path.parent() else {
        return Ok(());
    };
    if dir.as_os_str().is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(dir)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    #[tokio::test]
    async fn node_id_file_is_created_readable_and_stable() {
        let dir = std::env::temp_dir().join(format!("fulla-node-id-{}", uuid::Uuid::new_v4()));
        let path = dir.join("node_id");
        let a = load_or_create_node_id(&path).unwrap();
        let b = load_or_create_node_id(&path).unwrap();
        assert_eq!(a, b);
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
}
