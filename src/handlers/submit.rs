//! POST `/submit` and POST `/api/v1/keys`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::{Form, Json};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Serialize;
use sqlx::SqlitePool;

use crate::db;
use crate::handlers::normalize_base_url;
use crate::mail::Mailer;
use crate::models::{NewKeyRecord, PendingSubmission, PushResponseJson, SubmitPayload};
use crate::openpgp::parse_and_validate;
use crate::templates::WebTemplates;
use crate::AppState;

#[derive(Debug, serde::Deserialize)]
pub struct SubmitFormFields {
    pub email: String,
    pub armored_public_key: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub callsign: Option<String>,
    pub dmr_id: Option<String>,
    pub radio_affiliation: Option<String>,
    pub fluxer_id: Option<String>,
    pub discord_id: Option<String>,
    pub irc_id: Option<String>,
    pub street: Option<String>,
    pub country: Option<String>,
    pub postal_code: Option<String>,
    pub region: Option<String>,
    pub organisation: Option<String>,
    pub role: Option<String>,
    pub note: Option<String>,
    pub badge_number: Option<String>,
}

impl SubmitFormFields {
    fn into_payload(self) -> Result<SubmitPayload, &'static str> {
        let dmr_id = match self
            .dmr_id
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            None => None,
            Some(t) => {
                let v: u32 = t.parse().map_err(|_| "DMR ID must be numeric.")?;
                Some(v)
            }
        };

        Ok(SubmitPayload {
            email: self.email,
            armored_public_key: self.armored_public_key,
            first_name: self.first_name,
            last_name: self.last_name,
            callsign: self.callsign,
            dmr_id,
            radio_affiliation: self.radio_affiliation,
            fluxer_id: self.fluxer_id,
            discord_id: self.discord_id,
            irc_id: self.irc_id,
            street: self.street,
            country: self.country,
            postal_code: self.postal_code,
            region: self.region,
            organisation: self.organisation,
            role: self.role,
            note: self.note,
            badge_number: self.badge_number,
        })
    }
}

#[derive(Debug)]
pub enum SubmitDecision {
    Accepted { fingerprint: String },
    DuplicatePending,
}

fn trim_opt(s: Option<String>) -> Option<String> {
    s.as_ref()
        .map(|x| x.trim())
        .filter(|x| !x.is_empty())
        .map(|x| x.to_string())
}

fn validate_rfc_like_email(em: &str) -> Result<(), &'static str> {
    let t = em.trim();
    if !(3..254).contains(&t.chars().count()) {
        return Err("Email address has invalid length.");
    }
    let Some((lhs, rhs)) = t.split_once('@') else {
        return Err("Email address must contain `@`.");
    };
    if lhs.is_empty()
        || rhs.is_empty()
        || !rhs.contains('.')
        || rhs.starts_with('.')
        || rhs.ends_with('.')
    {
        return Err("Email address is invalid.");
    }
    Ok(())
}

fn validate_typed(payload: &SubmitPayload) -> Result<(), &'static str> {
    validate_rfc_like_email(&payload.email)?;

    macro_rules! len {
        ($field:literal, $f:expr, $max:expr) => {{
            if let Some(v) = &$f {
                let t = v.trim();
                if !t.is_empty() && t.chars().count() > $max {
                    return Err($field);
                }
            }
        }};
    }
    len!(
        "`first_name` must be at most 64 characters.",
        payload.first_name,
        64
    );
    len!(
        "`last_name` must be at most 64 characters.",
        payload.last_name,
        64
    );
    len!(
        "`fluxer_id` must be at most 128 characters.",
        payload.fluxer_id,
        128
    );
    len!(
        "`discord_id` must be at most 32 characters.",
        payload.discord_id,
        32
    );
    len!(
        "`irc_id` must be at most 128 characters.",
        payload.irc_id,
        128
    );
    len!(
        "`radio_affiliation` must be at most 128 characters.",
        payload.radio_affiliation,
        128
    );
    len!(
        "`street` must be at most 512 characters.",
        payload.street,
        512
    );
    len!(
        "`country` must be at most 128 characters.",
        payload.country,
        128
    );
    len!(
        "`postal_code` must be at most 32 characters.",
        payload.postal_code,
        32
    );
    len!(
        "`region` must be at most 128 characters.",
        payload.region,
        128
    );
    len!(
        "`organisation` must be at most 128 characters.",
        payload.organisation,
        128
    );
    len!("`role` must be at most 128 characters.", payload.role, 128);
    len!(
        "`note` must be at most 4096 characters.",
        payload.note,
        4096
    );
    len!(
        "`badge_number` must be at most 64 characters.",
        payload.badge_number,
        64
    );

    if let Some(id) = payload.dmr_id {
        if !(1..=16_777_215).contains(&id) {
            return Err("DMR ID must be between 1 and 16777215.");
        }
    }

    if let Some(ref cs) = payload.callsign {
        let t = cs.trim();
        if !t.is_empty() {
            let len_ok = (2..=16).contains(&t.chars().count());
            let chars_ok = t.chars().all(|c| c.is_ascii_alphanumeric());
            if !len_ok || !chars_ok {
                return Err("Callsign must be alphanumeric, 2-16 characters.");
            }
        }
    }

    Ok(())
}

fn random_token_64_hex() -> String {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    let mut out = String::with_capacity(64);
    for b in buf {
        use std::fmt::Write as _;
        write!(&mut out, "{b:02x}").unwrap();
    }
    out
}

#[derive(Clone, Serialize)]
pub struct AcceptedPage {
    pub fingerprint: String,
}

#[derive(Clone, Serialize)]
pub struct PendingPage {
    pub message: String,
}

pub async fn process_submission(
    payload: SubmitPayload,
    pool: &SqlitePool,
    cfg: &crate::config::Config,
    mailer: &Mailer,
    tmpl: &WebTemplates,
) -> Result<SubmitDecision, anyhow::Error> {
    validate_typed(&payload).map_err(anyhow::Error::msg)?;

    let parsed = parse_and_validate(&payload.armored_public_key, payload.email.trim())
        .map_err(|e| anyhow::Error::msg(e.to_string()))?;

    if let Some(row) = db::get_active_key_by_fingerprint(pool, &parsed.fingerprint).await? {
        if row.armored_key == parsed.armored {
            return Ok(SubmitDecision::Accepted {
                fingerprint: parsed.fingerprint,
            });
        }
        anyhow::bail!("This fingerprint already has an active entry with different key material.");
    }

    let email_norm = payload.email.trim().to_lowercase();

    let by_email = db::get_active_keys_by_email(pool, &email_norm).await?;
    if let Some(existing) = by_email.first() {
        if existing.fingerprint != parsed.fingerprint {
            let token = random_token_64_hex();
            let expires_at = chrono::Utc::now()
                .checked_add_signed(chrono::Duration::hours(72))
                .expect("chrono expiry")
                .to_rfc3339();

            let pending = PendingSubmission {
                token: token.clone(),
                new_fingerprint: parsed.fingerprint.clone(),
                email: email_norm.clone(),
                first_name: trim_opt(payload.first_name.clone()),
                last_name: trim_opt(payload.last_name.clone()),
                fluxer_id: trim_opt(payload.fluxer_id.clone()),
                discord_id: trim_opt(payload.discord_id.clone()),
                irc_id: trim_opt(payload.irc_id.clone()),
                callsign: trim_opt(payload.callsign.clone()),
                dmr_id: payload.dmr_id.map(|x| x as i64),
                radio_affiliation: trim_opt(payload.radio_affiliation.clone()),
                street: trim_opt(payload.street.clone()),
                country: trim_opt(payload.country.clone()),
                postal_code: trim_opt(payload.postal_code.clone()),
                region: trim_opt(payload.region.clone()),
                organisation: trim_opt(payload.organisation.clone()),
                role: trim_opt(payload.role.clone()),
                note: trim_opt(payload.note.clone()),
                badge_number: trim_opt(payload.badge_number.clone()),
                armored_key: parsed.armored.clone(),
                expires_at,
            };

            db::insert_pending(pool, &pending).await?;

            let base = normalize_base_url(&cfg.keyserver_base_url);
            let ctx = serde_json::json!({
              "old_fingerprint": existing.fingerprint,
              "new_fingerprint": parsed.fingerprint,
              "callsign": pending.callsign,
              "dmr_id": pending.dmr_id,
              "radio_affiliation": pending.radio_affiliation,
              "fluxer_id": pending.fluxer_id,
              "discord_id": pending.discord_id,
              "irc_id": pending.irc_id,
              "street": pending.street,
              "country": pending.country,
              "postal_code": pending.postal_code,
              "organisation": pending.organisation,
              "role": pending.role,
              "note": pending.note,
              "badge_number": pending.badge_number,
              "confirm_url": format!("{base}/confirm/{token}"),
              "reject_url": format!("{base}/reject/{token}"),
              "expires_hours": 72_u32,
            });

            let body = tmpl.render("email_new_key", ctx)?;

            mailer
                .send_plain(
                    &existing.email,
                    "Galdralag key registry: confirm key replacement",
                    &body,
                )
                .await?;

            return Ok(SubmitDecision::DuplicatePending);
        }
    }

    db::insert_key(
        pool,
        &NewKeyRecord {
            fingerprint: parsed.fingerprint.clone(),
            armored_key: parsed.armored,
            email: email_norm.clone(),
            first_name: trim_opt(payload.first_name),
            last_name: trim_opt(payload.last_name),
            fluxer_id: trim_opt(payload.fluxer_id),
            discord_id: trim_opt(payload.discord_id),
            irc_id: trim_opt(payload.irc_id),
            callsign: trim_opt(payload.callsign).map(|c| c.to_ascii_uppercase()),
            dmr_id: payload.dmr_id,
            radio_affiliation: trim_opt(payload.radio_affiliation),
            street: trim_opt(payload.street),
            country: trim_opt(payload.country),
            postal_code: trim_opt(payload.postal_code),
            region: trim_opt(payload.region),
            organisation: trim_opt(payload.organisation),
            role: trim_opt(payload.role),
            note: trim_opt(payload.note),
            badge_number: trim_opt(payload.badge_number),
            submitted_at: chrono::Utc::now().to_rfc3339(),
        },
    )
    .await?;

    Ok(SubmitDecision::Accepted {
        fingerprint: parsed.fingerprint,
    })
}

fn classify_submit_anyhow(e: anyhow::Error, api: bool) -> Response {
    let msg = e.to_string();
    let validation = msg.starts_with("Email")
        || msg.starts_with("DMR")
        || msg.starts_with("Callsign")
        || msg.contains("characters.")
        || msg.contains("maximum")
        || msg.contains("numeric")
        || msg.contains("`")
        || msg.contains("not supported by Galdralag hardware")
        || msg.contains("Invalid OpenPGP")
        || msg.contains("does not match any User ID")
        || msg.contains("already revoked")
        || msg.contains("uncertain revocation")
        || msg.contains("Key material exceeds");

    let fp_conflict = msg.contains("fingerprint already has");

    if api {
        let code = if validation || fp_conflict {
            StatusCode::UNPROCESSABLE_ENTITY
        } else {
            tracing::error!(error=?e, "submit api failure");
            StatusCode::INTERNAL_SERVER_ERROR
        };
        let reason = if matches!(code, StatusCode::INTERNAL_SERVER_ERROR) {
            "Internal error.".to_string()
        } else {
            msg.clone()
        };
        return (
            code,
            Json(PushResponseJson {
                status: "error".into(),
                fingerprint: None,
                message: None,
                reason: Some(reason),
            }),
        )
            .into_response();
    }

    let code = if validation || fp_conflict {
        StatusCode::BAD_REQUEST
    } else {
        tracing::error!(error=?e, "submit web failure");
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (code, Html(format!("<pre>{}</pre>", html_esc(&msg)))).into_response()
}

fn html_esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub async fn handle_form(
    State(app): State<AppState>,
    Form(form): Form<SubmitFormFields>,
) -> Response {
    let payload = match form.into_payload() {
        Ok(p) => p,
        Err(m) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Html(format!("<pre>{}</pre>", html_esc(m))),
            )
                .into_response();
        }
    };

    match process_submission(
        payload,
        &app.pool,
        app.config.as_ref(),
        app.mailer.as_ref(),
        app.templates.as_ref(),
    )
    .await
    {
        Ok(SubmitDecision::Accepted { fingerprint }) => {
            match app.templates.render(
                "submit_accepted",
                AcceptedPage {
                    fingerprint: fingerprint.clone(),
                },
            ) {
                Ok(html) => (StatusCode::OK, Html(html)).into_response(),
                Err(_e) => (
                    StatusCode::OK,
                    Html(format!(
                        "<!DOCTYPE html><html><body><p>Accepted</p><pre>{fp}</pre></body></html>",
                        fp = html_esc(&fingerprint),
                    )),
                )
                    .into_response(),
            }
        }
        Ok(SubmitDecision::DuplicatePending) => match app.templates.render(
            "submit_pending",
            PendingPage {
                message: "Confirmation email sent to address on file.".into(),
            },
        ) {
            Ok(html) => (StatusCode::OK, Html(html)).into_response(),
            Err(_) => (
                StatusCode::OK,
                Html("<pre>Confirmation email sent to address on file.</pre>"),
            )
                .into_response(),
        },
        Err(e) => classify_submit_anyhow(e, false),
    }
}

pub async fn handle_api(State(app): State<AppState>, Json(mut p): Json<SubmitPayload>) -> Response {
    p.email = p.email.trim().to_string();
    match process_submission(
        p,
        &app.pool,
        app.config.as_ref(),
        app.mailer.as_ref(),
        app.templates.as_ref(),
    )
    .await
    {
        Ok(SubmitDecision::Accepted { fingerprint }) => (
            StatusCode::OK,
            Json(PushResponseJson {
                status: "accepted".into(),
                fingerprint: Some(fingerprint),
                message: None,
                reason: None,
            }),
        )
            .into_response(),
        Ok(SubmitDecision::DuplicatePending) => (
            StatusCode::ACCEPTED,
            Json(PushResponseJson {
                status: "pending_confirmation".into(),
                fingerprint: None,
                message: Some("Confirmation email sent to address on file.".into()),
                reason: None,
            }),
        )
            .into_response(),
        Err(e) => classify_submit_anyhow(e, true),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sequoia_openpgp::armor;
    use sequoia_openpgp::cert::CertBuilder;
    use sequoia_openpgp::cert::CipherSuite;
    use sequoia_openpgp::serialize::Serialize as PgpSerialize;
    use sqlx::sqlite::SqlitePoolOptions;

    use super::{process_submission, SubmitDecision, SubmitPayload};
    use crate::config::Config;
    use crate::db;
    use crate::mail::Mailer;
    use crate::models::NewKeyRecord;
    use crate::openpgp::parse_and_validate;
    use crate::templates::WebTemplates;

    async fn pool_migrated() -> sqlx::SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    fn templates() -> WebTemplates {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
        WebTemplates::load_from_dir(dir).unwrap()
    }

    fn armored_cv25519(email: &str) -> String {
        let cert = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_userid(format!("Holda <{email}>"))
            .add_signing_subkey()
            .generate()
            .unwrap()
            .0;
        let mut buf = Vec::new();
        let mut w = armor::Writer::new(&mut buf, armor::Kind::PublicKey).unwrap();
        cert.serialize(&mut w).unwrap();
        w.finalize().unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn base_payload(email: &str, armored: String) -> SubmitPayload {
        SubmitPayload {
            email: email.to_string(),
            armored_public_key: armored,
            first_name: None,
            last_name: None,
            callsign: Some("LB9AAA".into()),
            dmr_id: None,
            radio_affiliation: None,
            fluxer_id: None,
            discord_id: None,
            irc_id: None,
            street: None,
            country: None,
            postal_code: None,
            region: None,
            organisation: None,
            role: None,
            note: None,
            badge_number: None,
        }
    }

    #[tokio::test]
    async fn accept_registry_push_email_and_key_only() {
        let pool = pool_migrated().await;
        let tmpl = templates();
        let cfg = Arc::new(Config::test_local());
        let payload = SubmitPayload {
            callsign: None,
            fluxer_id: None,
            ..base_payload("solo@test.example", armored_cv25519("solo@test.example"))
        };
        match process_submission(
            payload,
            &pool,
            cfg.as_ref(),
            &Mailer::noop_for_tests(),
            &tmpl,
        )
        .await
        .unwrap()
        {
            SubmitDecision::Accepted { .. } => {}
            other => panic!("expected accepted minimal payload, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reject_bad_openpgp() {
        let pool = pool_migrated().await;
        let tmpl = templates();
        let cfg = Arc::new(Config::test_local());
        let payload = base_payload("bad@test.example", "-----BEGIN NOTHING-----".into());
        assert!(process_submission(
            payload,
            &pool,
            cfg.as_ref(),
            &Mailer::noop_for_tests(),
            &tmpl
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn idempotent_repeat_submission_same_key() {
        let pool = pool_migrated().await;
        let tmpl = templates();
        let cfg = Arc::new(Config::test_local());
        let mail = Mailer::noop_for_tests();
        let em = "idempo@test.example";
        let arm = armored_cv25519(em);
        let p = base_payload(em, arm.clone());
        let r = process_submission(p.clone(), &pool, cfg.as_ref(), &mail, &tmpl)
            .await
            .unwrap();
        let SubmitDecision::Accepted { fingerprint } = r else {
            panic!("expected accepted");
        };
        match process_submission(p, &pool, cfg.as_ref(), &mail, &tmpl)
            .await
            .unwrap()
        {
            SubmitDecision::Accepted { fingerprint: fp2 } => assert_eq!(fingerprint, fp2),
            _ => panic!("expected accepted"),
        };
    }

    #[tokio::test]
    async fn duplicate_identity_sends_stub_pending_mail() {
        let pool = pool_migrated().await;
        let tmpl = templates();
        let cfg = Arc::new(Config::test_local());
        let mail = Mailer::noop_for_tests();
        let email = "shared@test.example";

        let arm_a = armored_cv25519(email);
        let parsed_a = parse_and_validate(&arm_a, email).unwrap();
        db::insert_key(
            &pool,
            &NewKeyRecord {
                fingerprint: parsed_a.fingerprint.clone(),
                armored_key: parsed_a.armored.clone(),
                email: email.to_string(),
                first_name: None,
                last_name: None,
                fluxer_id: None,
                discord_id: None,
                irc_id: None,
                callsign: Some("LB9OLD".into()),
                dmr_id: None,
                radio_affiliation: None,
                street: None,
                country: None,
                postal_code: None,
                region: None,
                organisation: None,
                role: None,
                note: None,
                badge_number: None,
                submitted_at: chrono::Utc::now().to_rfc3339(),
            },
        )
        .await
        .unwrap();

        let arm_b = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_userid(format!("Other <{email}>"))
            .add_signing_subkey()
            .generate()
            .unwrap()
            .0;
        let mut buf = Vec::new();
        let mut w = armor::Writer::new(&mut buf, armor::Kind::PublicKey).unwrap();
        arm_b.serialize(&mut w).unwrap();
        w.finalize().unwrap();
        let arm_b_armor = String::from_utf8(buf).unwrap();

        let second = SubmitPayload {
            email: email.to_string(),
            armored_public_key: arm_b_armor.clone(),
            first_name: None,
            last_name: None,
            callsign: Some("LB9NEW".into()),
            dmr_id: None,
            radio_affiliation: None,
            fluxer_id: None,
            discord_id: None,
            irc_id: None,
            street: None,
            country: None,
            postal_code: None,
            region: None,
            organisation: None,
            role: None,
            note: None,
            badge_number: None,
        };

        let r = process_submission(second, &pool, cfg.as_ref(), &mail, &tmpl)
            .await
            .unwrap();
        assert!(matches!(r, SubmitDecision::DuplicatePending));

        let n_pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pending_submissions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n_pending, 1);
    }

    #[tokio::test]
    async fn fresh_insert_accepted() {
        let pool = pool_migrated().await;
        let tmpl = templates();
        let cfg = Arc::new(Config::test_local());
        let em = "fresh@test.example";
        let p = base_payload(em, armored_cv25519(em));
        let r = process_submission(p, &pool, cfg.as_ref(), &Mailer::noop_for_tests(), &tmpl)
            .await
            .unwrap();
        assert!(matches!(r, SubmitDecision::Accepted { .. }));
    }

    #[tokio::test]
    async fn active_fingerprint_storage_mismatch_errors() {
        let pool = pool_migrated().await;
        let tmpl = templates();
        let cfg = Arc::new(Config::test_local());
        let em = "mismatch@test.example";
        let arm = armored_cv25519(em);
        let parsed = parse_and_validate(&arm, em).unwrap();

        db::insert_key(
            &pool,
            &NewKeyRecord {
                fingerprint: parsed.fingerprint.clone(),
                armored_key: "-----BEGIN bogus material-----".into(),
                email: em.to_string(),
                first_name: None,
                last_name: None,
                fluxer_id: None,
                discord_id: None,
                irc_id: None,
                callsign: Some("LB9BBB".into()),
                dmr_id: None,
                radio_affiliation: None,
                street: None,
                country: None,
                postal_code: None,
                region: None,
                organisation: None,
                role: None,
                note: None,
                badge_number: None,
                submitted_at: chrono::Utc::now().to_rfc3339(),
            },
        )
        .await
        .unwrap();

        let p = base_payload(em, arm);
        let err = process_submission(p, &pool, cfg.as_ref(), &Mailer::noop_for_tests(), &tmpl)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("different key material"));
    }
}
