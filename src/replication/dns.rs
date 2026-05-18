//! DNS helpers for replication (dynamic DNS hostnames).

use std::net::{IpAddr, SocketAddr};

/// Resolve `host` to the first IPv4, or first IPv6 if no IPv4.
pub async fn resolve_host_first_ip(host: &str) -> anyhow::Result<IpAddr> {
    let host = host.trim().to_string();
    if host.is_empty() {
        anyhow::bail!("empty hostname");
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0_u16))
        .await?
        .collect();
    if addrs.is_empty() {
        anyhow::bail!("no addresses returned");
    }
    let ips: Vec<IpAddr> = addrs.into_iter().map(|a| a.ip()).collect();
    if let Some(ip) = ips.iter().copied().find(|i| i.is_ipv4()) {
        return Ok(ip);
    }
    ips.into_iter()
        .find(|i| i.is_ipv6())
        .ok_or_else(|| anyhow::anyhow!("only resolved to unexpected address families"))
}

fn format_ip_for_url(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(_) => ip.to_string(),
        IpAddr::V6(v6) => format!("[{}]", v6),
    }
}

/// Replace occurrences of `host_token` in `original` with the resolved IP (IPv6 bracketed for URLs).
pub fn substitute_host_token(original: &str, host_token: &str, ip: IpAddr) -> String {
    let replacement = format_ip_for_url(ip);
    original.replace(host_token, &replacement)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn localhost_resolves() {
        let ip = resolve_host_first_ip("localhost").await.expect("dns");
        assert!(ip.is_loopback(), "{ip}");
    }

    #[test]
    fn substitute_ipv4() {
        let u = substitute_host_token(
            "https://dyn.example.net:9443/sync",
            "dyn.example.net",
            "127.0.0.1".parse().unwrap(),
        );
        assert_eq!(u, "https://127.0.0.1:9443/sync");
    }
}
