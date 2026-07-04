//! Shared helpers for HTTP adversarial tests against a running Fulla instance.

use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;
use sequoia_openpgp::armor;
use sequoia_openpgp::cert::CertBuilder;
use sequoia_openpgp::cert::CipherSuite;
use sequoia_openpgp::serialize::Serialize as PgpSerialize;

#[derive(Clone)]
pub struct Env {
    pub fulla: String,
    pub mailhog: String,
    pub client: Client,
}

impl Env {
    pub fn from_env() -> Result<Self> {
        let fulla = std::env::var("FULLA_BASE_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8080".into())
            .trim_end_matches('/')
            .to_string();
        let mailhog = std::env::var("MAILHOG_API")
            .unwrap_or_else(|_| "http://127.0.0.1:8025".into())
            .trim_end_matches('/')
            .to_string();
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("HTTP client")?;
        Ok(Self {
            fulla,
            mailhog,
            client,
        })
    }

    pub fn api_keys(&self) -> String {
        format!("{}/api/v1/keys", self.fulla)
    }

    /// Expected hourly mutation limit (must match `docker/fulla.env` for rate-limit tests).
    pub fn expected_rate_limit(&self) -> u32 {
        std::env::var("FULLA_EXPECT_RATE_LIMIT")
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(50)
    }

    /// Expected hourly GET limit; `None` when read limiting is disabled.
    pub fn expected_read_rate_limit(&self) -> Option<u32> {
        std::env::var("FULLA_EXPECT_READ_RATE_LIMIT")
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .or(Some(500))
    }
}

pub fn armored_cv25519(email: &str) -> Result<String> {
    let cert = CertBuilder::new()
        .set_cipher_suite(CipherSuite::Cv25519)
        .add_userid(format!("Test <{email}>"))
        .add_signing_subkey()
        .generate()
        .context("cert gen")?
        .0;
    let mut buf = Vec::new();
    let mut w = armor::Writer::new(&mut buf, armor::Kind::PublicKey).context("armor")?;
    cert.serialize(&mut w).context("serialize")?;
    w.finalize().context("finalize")?;
    Ok(String::from_utf8(buf).context("utf8")?)
}

pub fn unique_email(prefix: &str) -> String {
    let n: u32 = rand::random();
    format!("{prefix}-{n:x}@adv.test")
}

pub async fn post_submit_json(env: &Env, body: &serde_json::Value) -> Result<reqwest::Response> {
    Ok(env
        .client
        .post(env.api_keys())
        .header("Accept", "application/json")
        .json(body)
        .send()
        .await?)
}

pub async fn post_submit_raw(
    env: &Env,
    content_type: &str,
    body: Vec<u8>,
) -> Result<reqwest::Response> {
    Ok(env
        .client
        .post(env.api_keys())
        .header("Content-Type", content_type)
        .body(body)
        .send()
        .await?)
}

pub async fn clear_mailhog(env: &Env) -> Result<()> {
    env.client
        .delete(format!("{}/api/v1/messages", env.mailhog))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

pub async fn latest_confirm_token(env: &Env) -> Result<String> {
    let resp = env
        .client
        .get(format!("{}/api/v2/messages", env.mailhog))
        .send()
        .await?
        .error_for_status()?;
    let v: serde_json::Value = resp.json().await?;
    let body = v["items"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|m| m["Content"]["Body"].as_str())
        .context("no mailhog message body")?;
    // Soft line breaks from quoted-printable encoding (common in SMTP).
    let body = body.replace("=\r\n", "").replace("=\n", "");
    for line in body.lines() {
        if line.contains("/confirm/") {
            let token = line
                .split("/confirm/")
                .nth(1)
                .unwrap_or("")
                .trim()
                .trim_end_matches(|c: char| !c.is_ascii_hexdigit());
            if token.len() == 64 {
                return Ok(token.to_string());
            }
        }
    }
    anyhow::bail!("confirm URL not found in latest mailhog message")
}

pub async fn wait_for_mail(env: &Env, timeout: Duration) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let resp = env
            .client
            .get(format!("{}/api/v2/messages", env.mailhog))
            .send()
            .await?;
        let v: serde_json::Value = resp.json().await?;
        let count = v["total"].as_u64().unwrap_or(0);
        if count > 0 {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for mailhog message");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
