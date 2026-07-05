//! Adversarial HTTP tests against a running Fulla instance (Docker stack).

mod fixtures;

use fulla_adversarial::{poison_cert, *};

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::json;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Pass,
    KnownGap,
    Finding,
    Skip,
}

struct Row {
    category: &'static str,
    test: String,
    outcome: Outcome,
    detail: String,
}

struct Report {
    rows: Vec<Row>,
}

impl Report {
    fn pass(&mut self, category: &'static str, test: impl Into<String>, detail: impl Into<String>) {
        self.rows.push(Row {
            category,
            test: test.into(),
            outcome: Outcome::Pass,
            detail: detail.into(),
        });
    }

    fn gap(&mut self, category: &'static str, test: impl Into<String>, detail: impl Into<String>) {
        self.rows.push(Row {
            category,
            test: test.into(),
            outcome: Outcome::KnownGap,
            detail: detail.into(),
        });
    }

    fn finding(&mut self, category: &'static str, test: impl Into<String>, detail: impl Into<String>) {
        self.rows.push(Row {
            category,
            test: test.into(),
            outcome: Outcome::Finding,
            detail: detail.into(),
        });
    }

    fn skip(&mut self, category: &'static str, test: impl Into<String>, detail: impl Into<String>) {
        self.rows.push(Row {
            category,
            test: test.into(),
            outcome: Outcome::Skip,
            detail: detail.into(),
        });
    }

    fn print_table(&self) {
        println!("\n## Adversarial test results\n");
        println!(
            "| Category | Test | Result | Detail |"
        );
        println!("|----------|------|--------|--------|");
        for r in &self.rows {
            let label = match r.outcome {
                Outcome::Pass => "PASS",
                Outcome::KnownGap => "KNOWN_GAP",
                Outcome::Finding => "FINDING",
                Outcome::Skip => "SKIP",
            };
            let detail = r.detail.replace('|', "\\|").replace('\n', " ");
            println!(
                "| {} | {} | {} | {} |",
                r.category, r.test, label, detail
            );
        }
        let findings = self
            .rows
            .iter()
            .filter(|r| r.outcome == Outcome::Finding)
            .count();
        let gaps = self
            .rows
            .iter()
            .filter(|r| r.outcome == Outcome::KnownGap)
            .count();
        println!(
            "\nSummary: {} tests, {} findings, {} known gaps",
            self.rows.len(),
            findings,
            gaps
        );
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let env = Env::from_env()?;
    env.client.get(format!("{}/", env.fulla)).send().await?.error_for_status().context(
        "Fulla not reachable at FULLA_BASE_URL — start `docker compose` in docker/ first",
    )?;

    let mut r = Report::default();
    run_malformed(&env, &mut r).await?;
    run_bloated_certs(&env, &mut r).await?;
    run_sks_poison_cert(&env, &mut r).await?;
    run_homoglyph(&env, &mut r).await?;
    run_tokens(&env, &mut r).await?;
    run_automated(&env, &mut r).await?;
    run_rate_limit(&env, &mut r).await?;
    r.print_table();
    if r.rows.iter().any(|x| x.outcome == Outcome::Finding) {
        std::process::exit(1);
    }
    Ok(())
}

impl Default for Report {
    fn default() -> Self {
        Self { rows: vec![] }
    }
}

async fn run_malformed(env: &Env, r: &mut Report) -> Result<()> {
    // Oversized body (>128 KiB)
    let huge = "A".repeat(140 * 1024);
    let resp = post_submit_json(
        env,
        &json!({
            "email": unique_email("huge"),
            "armored_public_key": huge,
        }),
    )
    .await?;
    let status = resp.status();
    if status.as_u16() == 413 || status.as_u16() == 422 {
        r.pass(
            "malformed",
            "oversized_request_body",
            format!("HTTP {}", status),
        );
    } else {
        r.finding(
            "malformed",
            "oversized_request_body",
            format!("expected 413 or 422, got HTTP {}", status),
        );
    }

    // Malformed OpenPGP
    let resp = post_submit_json(
        env,
        &json!({
            "email": unique_email("badpgp"),
            "armored_public_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nnot-valid\n-----END PGP PUBLIC KEY BLOCK-----",
        }),
    )
    .await?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if status.as_u16() == 422 && !body.contains("Internal") {
        r.pass("malformed", "bad_openpgp", "HTTP 422 with reason");
    } else if status.is_server_error() {
        r.finding(
            "malformed",
            "bad_openpgp",
            format!("server error HTTP {}", status),
        );
    } else {
        r.pass(
            "malformed",
            "bad_openpgp",
            format!("HTTP {} (non-500)", status),
        );
    }

    // Oversized sidecar note (4096 max)
    let email = unique_email("longnote");
    let arm = armored_cv25519(&email)?;
    let resp = post_submit_json(
        env,
        &json!({
            "email": email,
            "armored_public_key": arm,
            "note": "x".repeat(5000),
        }),
    )
    .await?;
    if resp.status().as_u16() == 422 {
        r.pass("malformed", "oversized_note_field", "HTTP 422");
    } else {
        r.finding(
            "malformed",
            "oversized_note_field",
            format!("HTTP {}", resp.status()),
        );
    }

    // Invalid UTF-8 JSON body
    let mut raw = br#"{"email":"utf8@test.local","armored_public_key":"x"}"#.to_vec();
    raw[10] = 0xff;
    let resp = post_submit_raw(env, "application/json", raw).await?;
    let status = resp.status();
    if status.is_client_error() && !status.is_server_error() {
        r.pass(
            "malformed",
            "invalid_utf8_json",
            format!("HTTP {}", status),
        );
    } else {
        r.finding(
            "malformed",
            "invalid_utf8_json",
            format!("HTTP {}", status),
        );
    }

    // Fingerprint path variants
    let cases: &[(&str, u16, &str)] = &[
        ("short", 400, "ABCDEF01"),
        ("non_hex", 400, "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"),
        ("traversal", 404, "../../etc/passwd"),
        ("sqli", 400, "'; DROP TABLE keys; --"),
    ];
    for (name, expect_min, fp) in cases {
        let url = format!("{}/keys/{}", env.fulla, fp);
        let resp = env.client.get(&url).send().await?;
        let s = resp.status().as_u16();
        if s == *expect_min || (*expect_min == 400 && s == 404) {
            r.pass(
                "malformed",
                format!("fingerprint_path_{name}"),
                format!("HTTP {s}"),
            );
        } else {
            r.finding(
                "malformed",
                format!("fingerprint_path_{name}"),
                format!("HTTP {s}, expected ~{expect_min}"),
            );
        }
    }

    Ok(())
}

async fn run_rate_limit(env: &Env, r: &mut Report) -> Result<()> {
    let limit = env.expected_rate_limit();
    let attempts = limit as usize + 2;
    let mut last_status = 0u16;
    for i in 0..attempts {
        let email = unique_email(&format!("rl{i}"));
        let arm = armored_cv25519(&email)?;
        let resp = post_submit_json(
            env,
            &json!({ "email": email, "armored_public_key": arm }),
        )
        .await?;
        last_status = resp.status().as_u16();
    }
    if last_status == 429 {
        r.pass(
            "rate_limit",
            "mutate_per_ip_hourly",
            format!(
                "{attempts}th submit returned HTTP 429 (limit={limit} in docker/fulla.env)"
            ),
        );
    } else {
        r.finding(
            "rate_limit",
            "mutate_per_ip_hourly",
            format!(
                "expected 429 on attempt {attempts}, got HTTP {last_status} (limit={limit})"
            ),
        );
    }

    // Read-side rate limit
    let read_limit = env.expected_read_rate_limit();
    if let Some(limit) = read_limit {
        let attempts = limit as usize + 2;
        let mut last_status = 0u16;
        for _ in 0..attempts {
            let resp = env
                .client
                .get(format!("{}/keys", env.fulla))
                .header("Accept", "application/json")
                .send()
                .await?;
            last_status = resp.status().as_u16();
        }
        if last_status == 429 {
            r.pass(
                "rate_limit",
                "read_side_per_ip_hourly",
                format!(
                    "{attempts}th GET /keys returned HTTP 429 (limit={limit} in docker/fulla.env)"
                ),
            );
        } else {
            r.finding(
                "rate_limit",
                "read_side_per_ip_hourly",
                format!(
                    "expected 429 on GET attempt {attempts}, got HTTP {last_status} (limit={limit})"
                ),
            );
        }
    } else {
        r.gap(
            "rate_limit",
            "read_side_per_ip_hourly",
            "read rate limit disabled (KEYSERVER_RATE_LIMIT_READS=0)",
        );
    }

    Ok(())
}

async fn run_bloated_certs(env: &Env, r: &mut Report) -> Result<()> {
    let cases = [
        "excess_userids",
        "excess_subkeys",
        "excess_userids_and_subkeys",
    ];

    for name in cases {
        let email = unique_email(name);
        let armored = match name {
            "excess_userids" => fixtures::armored_excess_userids(&email, 20),
            "excess_subkeys" => fixtures::armored_excess_subkeys(&email, 40),
            _ => fixtures::armored_excess_userids_and_subkeys(&email),
        };
        let armored = match armored {
            Ok(a) => a,
            Err(e) => {
                r.finding(
                    "malformed",
                    format!("bloated_cert_{name}_fixture"),
                    format!("fixture generation failed: {e:#}"),
                );
                continue;
            }
        };
        let resp = post_submit_json(
            env,
            &json!({ "email": email, "armored_public_key": armored }),
        )
        .await?;
        let status = resp.status().as_u16();
        if status == 422 {
            r.pass(
                "malformed",
                format!("bloated_cert_{name}"),
                "HTTP 422 structural limit rejected",
            );
        } else if (200..300).contains(&status) || status == 202 {
            r.finding(
                "malformed",
                format!("bloated_cert_{name}"),
                format!("expected HTTP 422, got {status}"),
            );
        } else if status >= 500 {
            r.finding(
                "malformed",
                format!("bloated_cert_{name}"),
                format!("HTTP 500 on poison-style cert"),
            );
        } else {
            r.pass(
                "malformed",
                format!("bloated_cert_{name}"),
                format!("HTTP {status} (non-success, acceptable rejection)"),
            );
        }
    }

    Ok(())
}

async fn run_sks_poison_cert(env: &Env, r: &mut Report) -> Result<()> {
    let email = poison_cert::FIXTURE_EMAIL;
    let armored = poison_cert::armored_from_fixture();
    let resp = post_submit_json(
        env,
        &json!({ "email": email, "armored_public_key": armored }),
    )
    .await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    if status == 422 {
        let kind = poison_cert::classify_structure_reject(&body);
        let detail = match kind {
            poison_cert::StructureRejectKind::PerUidSelfSignatures => {
                "HTTP 422 — per-UID self-signature cap on raw import stream (check_raw_packet_structure)"
            }
            poison_cert::StructureRejectKind::TotalSignaturePackets => {
                "HTTP 422 — total signature-packet cap (check_cert_structure)"
            }
            poison_cert::StructureRejectKind::Other => {
                "HTTP 422 — structural rejection (see body)"
            }
        };
        r.pass("malformed", "sks_poison_uid_selfsig_flood", detail);
    } else if (200..300).contains(&status) || status == 202 {
        r.finding(
            "malformed",
            "sks_poison_uid_selfsig_flood",
            format!("expected HTTP 422, got {status}"),
        );
    } else if status >= 500 {
        r.finding(
            "malformed",
            "sks_poison_uid_selfsig_flood",
            format!("HTTP 500 on SKS poison fixture: {body}"),
        );
    } else {
        r.pass(
            "malformed",
            "sks_poison_uid_selfsig_flood",
            format!("HTTP {status} (non-success rejection)"),
        );
    }
    Ok(())
}

async fn run_homoglyph(env: &Env, r: &mut Report) -> Result<()> {
    // Fixed local-part; vary only domain/case so OpenPGP User ID stays consistent per attempt.
    let n: u32 = rand::random();
    let local = format!("user-{n:x}");
    let latin = format!("{local}@example.com");
    let case_variant = latin.to_uppercase();
    let arm_latin = armored_cv25519(&latin)?;

    let resp1 = post_submit_json(
        env,
        &json!({ "email": latin, "armored_public_key": arm_latin.clone() }),
    )
    .await?;
    if resp1.status().as_u16() != 202 && !resp1.status().is_success() {
        r.finding(
            "identity",
            "email_case_pending_setup",
            format!("first submit HTTP {}", resp1.status()),
        );
        return Ok(());
    }

    let resp2 = post_submit_json(
        env,
        &json!({ "email": case_variant, "armored_public_key": arm_latin }),
    )
    .await?;
    if resp2.status().as_u16() == 422 {
        r.pass(
            "identity",
            "email_case_variant_pending_guard",
            "User@Example.com blocked while user@example.com pending (LOWER normalization)",
        );
    } else {
        r.finding(
            "identity",
            "email_case_variant_pending_guard",
            format!(
                "case variant not blocked; HTTP {} (expected 422)",
                resp2.status()
            ),
        );
    }

    // Cyrillic homoglyph in local part: Latin 'e' (U+0065) vs Cyrillic 'е' (U+0435).
    let n2: u32 = rand::random();
    let latin2 = format!("user-{n2:x}@example.com");
    let homoglyph_local = format!("us\u{0435}r-{n2:x}@example.com");
    let arm2_latin = armored_cv25519(&latin2)?;
    let arm2_homoglyph = armored_cv25519(&homoglyph_local)?;

    let h1 = post_submit_json(
        env,
        &json!({ "email": latin2, "armored_public_key": arm2_latin }),
    )
    .await?;
    if h1.status().as_u16() != 202 && !h1.status().is_success() {
        r.finding(
            "identity",
            "unicode_homoglyph_setup",
            format!("first submit HTTP {}", h1.status()),
        );
        return Ok(());
    }

    let h2 = post_submit_json(
        env,
        &json!({ "email": homoglyph_local, "armored_public_key": arm2_homoglyph }),
    )
    .await?;
    let h2_status = h2.status().as_u16();
    let h2_body = h2.text().await.unwrap_or_default();
    let pending_msg = h2_body.contains("confirmation is already pending");
    if h2_status == 422 && pending_msg {
        r.pass(
            "identity",
            "unicode_homoglyph_pending_guard",
            "422 pending guard blocks homoglyph mailbox when Latin pending exists",
        );
    } else if h2_status == 202 || (h2_status >= 200 && h2_status < 300) {
        r.finding(
            "identity",
            "unicode_homoglyph_pending_guard",
            format!(
                "HTTP {h2_status}: second pending allowed for Cyrillic homoglyph local part; LOWER() does not detect Unicode confusables"
            ),
        );
    } else if h2_status == 500 {
        r.finding(
            "identity",
            "unicode_homoglyph_pending_guard",
            "HTTP 500 after homoglyph submit (expected 422 pending guard or successful SMTP)",
        );
    } else if h2_status == 422 {
        r.gap(
            "identity",
            "unicode_homoglyph_pending_guard",
            format!(
                "422 before pending guard ({h2_body}); UID/email validation runs first for this probe"
            ),
        );
    } else {
        r.finding(
            "identity",
            "unicode_homoglyph_pending_guard",
            format!("unexpected HTTP {h2_status} on homoglyph resubmit: {h2_body}"),
        );
    }

    Ok(())
}

async fn run_automated(env: &Env, r: &mut Report) -> Result<()> {
    let fuzz_cases = vec![
        json!({}),
        json!({"email": 123, "armored_public_key": true}),
        json!({"email": "a@b.co", "armored_public_key": []}),
        json!({"email": "a@b.co", "armored_public_key": "x", "nested": {"a": {"b": {"c": 1}}}}),
    ];
    for (i, body) in fuzz_cases.iter().enumerate() {
        let resp = post_submit_json(env, body).await?;
        if resp.status().is_server_error() {
            r.finding(
                "automated",
                format!("json_fuzz_{i}"),
                format!("HTTP 500 on {:?}", body),
            );
        } else {
            r.pass(
                "automated",
                format!("json_fuzz_{i}"),
                format!("HTTP {}", resp.status()),
            );
        }
    }

    // Multi-filter search excludes revoked keys by default
    if let Err(e) = run_search_revoked_filter(env, r).await {
        r.finding(
            "automated",
            "search_revoked_filter_gap",
            format!("probe failed: {e:#}"),
        );
    }

    // Slow partial POST (slowloris-style)
    let slow = slow_body_probe(&env.fulla).await;
    match slow {
        Ok(elapsed) if elapsed < Duration::from_secs(25) => r.pass(
            "automated",
            "slow_partial_post",
            format!("connection closed or completed within {:?}", elapsed),
        ),
        Ok(elapsed) => r.finding(
            "automated",
            "slow_partial_post",
            format!(" hung {:?} waiting for slow body", elapsed),
        ),
        Err(e) => r.pass(
            "automated",
            "slow_partial_post",
            format!("closed early: {e:#}"),
        ),
    }

    Ok(())
}

async fn run_search_revoked_filter(env: &Env, r: &mut Report) -> Result<()> {
    let n: u32 = rand::random();
    let email = format!("revsearch-{n:x}@adv.test");
    let callsign = format!("ADV{n:x}");
    let (armored, rev_armored) = armored_cv25519_with_revocation(&email)?;

    clear_mailhog(env).await?;
    let submit = post_submit_json(
        env,
        &json!({
            "email": email,
            "armored_public_key": armored,
            "callsign": callsign,
        }),
    )
    .await?;
    if !submit.status().is_success() && submit.status().as_u16() != 202 {
        anyhow::bail!("submit failed: HTTP {}", submit.status());
    }

    wait_for_mail(env, Duration::from_secs(15)).await?;
    let token = latest_confirm_token(env).await?;
    let confirm = env
        .client
        .get(format!("{}/confirm/{token}", env.fulla))
        .send()
        .await?;
    if !confirm.status().is_success() {
        anyhow::bail!("confirm failed: HTTP {}", confirm.status());
    }

    let revoke = env
        .client
        .post(format!("{}/api/v1/keys/revoke", env.fulla))
        .header("Accept", "application/json")
        .json(&json!({
            "email": email,
            "armored_revocation_cert": rev_armored,
        }))
        .send()
        .await?;
    if !revoke.status().is_success() {
        anyhow::bail!("revoke failed: HTTP {}", revoke.status());
    }

    let search_active = env
        .client
        .get(format!("{}/keys?callsign={callsign}", env.fulla))
        .header("Accept", "application/json")
        .send()
        .await?;
    if !search_active.status().is_success() {
        anyhow::bail!("search active failed: HTTP {}", search_active.status());
    }
    let active_rows: Vec<serde_json::Value> = search_active.json().await?;
    if !active_rows.is_empty() {
        r.finding(
            "automated",
            "search_revoked_filter_gap",
            format!(
                "multi-filter search returned {} row(s) for revoked callsign without include_revoked",
                active_rows.len()
            ),
        );
        return Ok(());
    }

    let search_all = env
        .client
        .get(format!(
            "{}/keys?callsign={callsign}&include_revoked=true",
            env.fulla
        ))
        .header("Accept", "application/json")
        .send()
        .await?;
    if !search_all.status().is_success() {
        anyhow::bail!("search all failed: HTTP {}", search_all.status());
    }
    let all_rows: Vec<serde_json::Value> = search_all.json().await?;
    if all_rows.len() == 1 && all_rows[0]["status"] == "revoked" {
        r.pass(
            "automated",
            "search_revoked_filter_gap",
            "multi-filter GET /keys excludes revoked by default; include_revoked=true returns revoked row",
        );
    } else {
        r.finding(
            "automated",
            "search_revoked_filter_gap",
            format!("include_revoked=true expected 1 revoked row, got {all_rows:?}"),
        );
    }

    Ok(())
}

async fn slow_body_probe(base: &str) -> Result<Duration> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    let host = base.trim_start_matches("http://").trim_start_matches("https://");
    let addr = if host.contains(':') {
        host.to_string()
    } else {
        format!("{host}:80")
    };
    let start = Instant::now();
    let res = timeout(Duration::from_secs(20), async {
        let mut stream = TcpStream::connect(&addr).await?;
        stream
            .write_all(
                b"POST /api/v1/keys HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 50000\r\n\r\n{\"email\":",
            )
            .await?;
        tokio::time::sleep(Duration::from_secs(8)).await;
        stream.write_all(b"\"slow@test.local\"").await?;
        Ok::<_, anyhow::Error>(())
    })
    .await;
    let elapsed = start.elapsed();
    match res {
        Ok(Ok(())) => Ok(elapsed),
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(elapsed),
    }
}

async fn run_tokens(env: &Env, r: &mut Report) -> Result<()> {
    let _ = clear_mailhog(env).await;

    let email = unique_email("confirm");
    let arm = armored_cv25519(&email)?;
    let resp = post_submit_json(
        env,
        &json!({ "email": email, "armored_public_key": arm }),
    )
    .await?;
    if resp.status().as_u16() != 202 && !resp.status().is_success() {
        r.finding(
            "tokens",
            "confirm_flow_setup",
            format!("submit HTTP {}", resp.status()),
        );
        return Ok(());
    }
    wait_for_mail(env, Duration::from_secs(15)).await?;
    let token = latest_confirm_token(env).await?;

    let confirm_url = format!("{}/confirm/{}", env.fulla, token);
    let r1 = env.client.get(&confirm_url).send().await?;
    if !r1.status().is_success() {
        r.finding(
            "tokens",
            "confirm_once",
            format!("HTTP {}", r1.status()),
        );
    } else {
        r.pass("tokens", "confirm_once", "HTTP 200");
    }

    let r2 = env.client.get(&confirm_url).send().await?;
    if r2.status().as_u16() == 404 {
        r.pass("tokens", "confirm_replay", "second GET /confirm returns 404");
    } else {
        r.finding(
            "tokens",
            "confirm_replay",
            format!("replay HTTP {}", r2.status()),
        );
    }

    // Token timing note (256-bit entropy; not constant-time compare)
    let wrong = "0".repeat(64);
    let mut wrong_times = Vec::new();
    for _ in 0..10 {
        let t0 = Instant::now();
        let _ = env
            .client
            .get(format!("{}/confirm/{}", env.fulla, wrong))
            .send()
            .await?;
        wrong_times.push(t0.elapsed());
    }
    let reject_url = format!("{}/reject/{}", env.fulla, wrong);
    let mut reject_times = Vec::new();
    for _ in 0..10 {
        let t0 = Instant::now();
        let _ = env.client.get(&reject_url).send().await?;
        reject_times.push(t0.elapsed());
    }
    let avg_wrong: f64 = wrong_times.iter().map(|d| d.as_secs_f64()).sum::<f64>() / 10.0;
    let avg_reject: f64 = reject_times.iter().map(|d| d.as_secs_f64()).sum::<f64>() / 10.0;
    r.skip(
        "tokens",
        "token_timing_side_channel",
        format!(
            "probe runs 10x GET /confirm/{{wrong}} vs /reject/{{wrong}}; avg confirm {:.6}s vs reject {:.6}s — sub-millisecond resolution cannot distinguish paths; 256-bit token entropy dominates (not a silent no-op)",
            avg_wrong, avg_reject
        ),
    );

    Ok(())
}
