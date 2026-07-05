//! Pre-load checks for native SQLite extensions (CR-SQLite).
//!
//! `load_extension` executes unmanaged native code inside the Fulla process.
//! These checks reject obviously tampered paths before load.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

/// Validate extension path permissions and optional SHA-256 pin before `load_extension`.
pub fn validate_native_extension(path: &Path, expected_sha256: Option<&str>) -> Result<()> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("CR-SQLite extension not readable: {}", path.display()))?;
    if !meta.is_file() {
        bail!(
            "CR-SQLite extension path is not a regular file: {}",
            path.display()
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o022 != 0 {
            bail!(
                "CR-SQLite extension {} is group- or world-writable (mode {:o}); \
                 refuse load_extension — install as root/service-owned with mode 0755 or stricter",
                path.display(),
                mode & 0o777
            );
        }
        if mode & 0o111 == 0 {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{:o}", mode & 0o777),
                "CR-SQLite extension is not marked executable; load may still succeed via dlopen"
            );
        }
    }

    #[cfg(not(unix))]
    {
        tracing::warn!(
            path = %path.display(),
            "native extension permission checks are limited on non-Unix platforms; \
             verify file ownership and ACLs in deployment"
        );
    }

    if let Some(expected) = expected_sha256 {
        let expected = expected.trim().to_ascii_lowercase();
        if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("crsqlite_extension_sha256 must be 64 hex characters when set");
        }
        let actual = sha256_file(path)?;
        if actual != expected {
            bail!(
                "CR-SQLite extension SHA-256 mismatch for {} (expected {}, got {})",
                path.display(),
                expected,
                actual
            );
        }
        tracing::info!(
            path = %path.display(),
            "CR-SQLite extension SHA-256 pin verified"
        );
    }

    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut reader = BufReader::new(f);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf).context("read extension for hash")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_encode(hasher.finalize().as_slice()))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    #[test]
    fn rejects_world_writable_extension() {
        let p = std::env::temp_dir().join(format!(
            "fulla-ext-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        std::fs::write(&p, b"fake-ext").unwrap();
        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o666);
        std::fs::set_permissions(&p, perms).unwrap();
        let err = validate_native_extension(&p, None).unwrap_err();
        assert!(
            err.to_string().contains("world-writable")
                || err.to_string().contains("group-"),
            "{err}"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn sha256_pin_matches() {
        let p = std::env::temp_dir().join(format!(
            "fulla-ext-hash-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        std::fs::write(&p, b"fake-ext").unwrap();
        #[cfg(unix)]
        {
            let mut perms = std::fs::metadata(&p).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&p, perms).unwrap();
        }
        let hash = sha256_file(&p).unwrap();
        validate_native_extension(&p, Some(&hash)).unwrap();
        let _ = std::fs::remove_file(&p);
    }
}
