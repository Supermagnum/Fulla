//! OpenPGP certificate parsing and validation (Galdralag hardware policy).

use std::borrow::Cow;
use std::fmt::Display;
use std::time::SystemTime;

use anyhow::{anyhow, Context, Result};
use sequoia_openpgp::armor;
use sequoia_openpgp::crypto::mpi::PublicKey as MpiPk;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::Serialize as PgpSerialize;
use sequoia_openpgp::types::{Curve, ReasonForRevocation, RevocationStatus, SignatureType};
use sequoia_openpgp::{Cert, Packet, PacketPile};

use crate::config::Config;

#[derive(Debug)]
pub struct ParsedCert {
    pub fingerprint: String,
    pub armored: String,
    /// Canonicalised lowercase emails extracted from certificate User IDs.
    #[allow(dead_code)]
    pub emails: Vec<String>,
}

/// Structural limits against SKS-poisoning-style oversized certificates.
///
/// Defaults are conservative relative to normal keys and inspired by public
/// keyserver operator practice (Hockeypuck `max_key_parts`, Hagrid rejection
/// of certificates with excessive signature counts on a User ID).
#[derive(Clone, Copy, Debug)]
pub struct CertPolicy {
    pub max_upload_bytes: usize,
    pub max_userids: u32,
    pub max_keys: u32,
    pub max_uid_self_signatures: u32,
}

impl CertPolicy {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            max_upload_bytes: cfg.keyserver_max_key_upload_bytes,
            max_userids: cfg.keyserver_max_cert_userids,
            max_keys: cfg.keyserver_max_cert_keys,
            max_uid_self_signatures: cfg.keyserver_max_uid_self_signatures,
        }
    }

    /// High limits for unit tests and generated minimal certificates.
    pub fn permissive() -> Self {
        Self {
            max_upload_bytes: 128 * 1024,
            max_userids: 256,
            max_keys: 256,
            max_uid_self_signatures: 256,
        }
    }
}

fn hardware_reject<D: Display>(name: D) -> anyhow::Error {
    anyhow!("Algorithm {} is not supported by Galdralag hardware.", name)
}

pub fn parse_and_validate(
    armored: &str,
    submitted_email: &str,
    policy: &CertPolicy,
) -> Result<ParsedCert> {
    let trimmed = armored.trim();
    if trimmed.len() > policy.max_upload_bytes {
        return Err(anyhow!(
            "Key material exceeds {} bytes.",
            policy.max_upload_bytes
        ));
    }

    check_raw_packet_structure(trimmed.as_bytes(), policy)?;

    let cert = Cert::from_bytes(trimmed.as_bytes()).context("Invalid OpenPGP certificate")?;

    check_cert_structure(&cert, policy)?;
    policy_check_keys(&cert)?;

    let mut buf = Vec::new();
    {
        let mut w = armor::Writer::new(&mut buf, armor::Kind::PublicKey)
            .map_err(|e| anyhow!("Could not initialise ASCII armour: {}", e))?;
        cert.serialize(&mut w)
            .map_err(|e| anyhow!("Could not serialize key: {}", e))?;
        w.finalize()
            .map_err(|e| anyhow!("Could not finalize armour: {}", e))?;
    }
    let normal_armor = String::from_utf8(buf).context("Armoured export was not UTF-8")?;

    let fingerprint = cert.fingerprint().to_hex();

    deny_self_revoked(&cert)?;

    let mut emails: Vec<String> = Vec::new();
    for uid in cert.userids() {
        if let Ok(Some(em)) = uid.userid().email_normalized() {
            emails.push(em);
        }
    }
    emails.sort_unstable();
    emails.dedup();

    let want = normalize_email_local(submitted_email);
    emails
        .iter()
        .find(|e| e.eq_ignore_ascii_case(want.as_ref()))
        .with_context(|| {
            anyhow!(
                "Email address '{}' does not match any User ID on the certificate.",
                submitted_email
            )
        })?;

    Ok(ParsedCert {
        fingerprint,
        armored: normal_armor.trim().to_string(),
        emails,
    })
}

/// Structural limits on the raw OpenPGP packet stream (pre-`Cert` deduplication).
///
/// Real SKS-poison certificates flood a User ID with many distinct self-signature packets.
/// Sequoia's `Cert` parser deduplicates them during amalgamation, so limits must be
/// enforced on the import stream, matching Hockeypuck/Hagrid-style rejection.
fn check_raw_packet_structure(bytes: &[u8], policy: &CertPolicy) -> Result<()> {
    let pile = PacketPile::from_bytes(bytes).context("Invalid OpenPGP packet stream")?;
    let packets: Vec<Packet> = pile.into_children().collect();

    let mut uid_count = 0u32;
    let mut key_count = 0u32;
    let mut total_sigs = 0u32;
    let mut uid_index = 0u32;
    let mut uid_self_sigs = 0u32;
    let mut in_uid_binding = false;

    for p in &packets {
        match p {
            Packet::UserID(_) => {
                uid_count += 1;
                uid_index = uid_count;
                uid_self_sigs = 0;
                in_uid_binding = true;
            }
            Packet::PublicKey(_)
            | Packet::PublicSubkey(_)
            | Packet::SecretKey(_)
            | Packet::SecretSubkey(_) => {
                key_count += 1;
                in_uid_binding = false;
            }
            Packet::Signature(sig) => {
                total_sigs += 1;
                if in_uid_binding && sig.typ() == SignatureType::PositiveCertification {
                    uid_self_sigs += 1;
                    if uid_self_sigs > policy.max_uid_self_signatures {
                        return Err(anyhow!(
                            "User ID #{} has {uid_self_sigs} self-signatures in import stream (maximum {}).",
                            uid_index,
                            policy.max_uid_self_signatures
                        ));
                    }
                }
            }
            _ => {}
        }
    }

    if uid_count == 0 {
        return Err(anyhow!("Certificate has no User IDs."));
    }
    if uid_count > policy.max_userids {
        return Err(anyhow!(
            "Certificate has {uid_count} User IDs (maximum {}).",
            policy.max_userids
        ));
    }

    let max_total_sigs = policy
        .max_uid_self_signatures
        .saturating_mul(policy.max_userids);
    if total_sigs > max_total_sigs {
        return Err(anyhow!(
            "Certificate has {total_sigs} signatures in import stream (maximum {max_total_sigs})."
        ));
    }

    if key_count > policy.max_keys {
        return Err(anyhow!(
            "Certificate has {key_count} key components (maximum {}).",
            policy.max_keys
        ));
    }

    Ok(())
}

fn check_cert_structure(cert: &Cert, policy: &CertPolicy) -> Result<()> {
    let uid_count = cert.userids().count() as u32;
    if uid_count == 0 {
        return Err(anyhow!("Certificate has no User IDs."));
    }
    if uid_count > policy.max_userids {
        return Err(anyhow!(
            "Certificate has {uid_count} User IDs (maximum {}).",
            policy.max_userids
        ));
    }

    for (i, uid) in cert.userids().enumerate() {
        let sig_count = uid.self_signatures().count() as u32;
        if sig_count > policy.max_uid_self_signatures {
            return Err(anyhow!(
                "User ID #{} has {sig_count} self-signatures (maximum {}).",
                i + 1,
                policy.max_uid_self_signatures
            ));
        }
    }

    // SKS-style flooding attaches many signature packets; cap total count.
    let total_sigs = count_signature_packets(cert);
    let max_total_sigs = policy
        .max_uid_self_signatures
        .saturating_mul(policy.max_userids);
    if total_sigs > max_total_sigs {
        return Err(anyhow!(
            "Certificate has {total_sigs} signatures (maximum {max_total_sigs})."
        ));
    }

    let key_count = cert.keys().count() as u32;
    if key_count > policy.max_keys {
        return Err(anyhow!(
            "Certificate has {key_count} key components (maximum {}).",
            policy.max_keys
        ));
    }

    Ok(())
}

fn count_signature_packets(cert: &Cert) -> u32 {
    cert.clone()
        .into_packets()
        .filter(|p| matches!(p, Packet::Signature(_)))
        .count() as u32
}

fn normalize_email_local(email: &str) -> Cow<'_, str> {
    Cow::Owned(email.trim().to_lowercase())
}

fn deny_self_revoked(cert: &Cert) -> Result<()> {
    let p = StandardPolicy::new();
    match cert.revocation_status(&p, SystemTime::now()) {
        RevocationStatus::Revoked(_) => Err(anyhow!(
            "Certificate is already revoked and cannot be registered."
        )),
        RevocationStatus::NotAsFarAsWeKnow => Ok(()),
        RevocationStatus::CouldBe(_) => Err(anyhow!(
            "Certificate has uncertain revocation status; registration rejected."
        )),
    }
}

fn policy_check_keys(cert: &Cert) -> Result<()> {
    for ka in cert.keys() {
        check_public_mpis(ka.key().mpis())
            .context("disallowed key cryptography for Galdralag hardware")?;
    }
    Ok(())
}

fn curve_is_brainpool_p384(c: &Curve) -> bool {
    matches!(c, Curve::Unknown(b) if b.as_ref() == BRAINPOOL_P384_OID)
}

const BRAINPOOL_P384_OID: &[u8] = &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B];

fn curve_display(c: &Curve) -> String {
    match c {
        Curve::NistP256 => "NIST-P-256".into(),
        Curve::NistP384 => "NIST-P-384".into(),
        Curve::NistP521 => "NIST-P-521".into(),
        Curve::BrainpoolP256 => "Brainpool P-256r1".into(),
        Curve::BrainpoolP512 => "Brainpool P-512r1".into(),
        Curve::Unknown(_) if curve_is_brainpool_p384(c) => "Brainpool P-384r1".into(),
        Curve::Ed25519 => "Ed25519".into(),
        Curve::Cv25519 => "X25519".into(),
        Curve::Unknown(oid) => format!("curve(OID {:?})", oid),
        _ => "unsupported post-quantum or experimental curve".into(),
    }
}

fn curve_allowed_rsa_bits(n_bits: usize) -> Result<()> {
    if n_bits < 2048 {
        Err(hardware_reject(format!("RSA-{}-bit", n_bits)))
    } else {
        Ok(())
    }
}

fn curve_allowed_ecdh(c: &Curve) -> Result<()> {
    match c {
        Curve::Cv25519 => Ok(()),
        Curve::NistP256 | Curve::NistP384 => Ok(()),
        Curve::BrainpoolP256 => Ok(()),
        Curve::BrainpoolP512 => Ok(()),
        Curve::Unknown(_) if curve_is_brainpool_p384(c) => Ok(()),
        _ => Err(hardware_reject(format!("ECDH {}", curve_display(c)))),
    }
}

fn curve_allowed_ecdsa(c: &Curve) -> Result<()> {
    match c {
        Curve::Ed25519 => Ok(()),
        Curve::NistP256 | Curve::NistP384 => Ok(()),
        Curve::BrainpoolP256 => Ok(()),
        Curve::BrainpoolP512 => Ok(()),
        Curve::Unknown(_) if curve_is_brainpool_p384(c) => Ok(()),
        Curve::Cv25519 => Err(hardware_reject(format!("ECDSA {}", curve_display(c)))),
        _ => Err(hardware_reject(format!("ECDSA {}", curve_display(c)))),
    }
}

pub fn check_public_mpis(mpis: &MpiPk) -> Result<()> {
    use MpiPk::*;

    match mpis {
        RSA { ref n, .. } => curve_allowed_rsa_bits(n.bits()),
        EdDSA { ref curve, .. } => curve_allowed_ecdsa(curve),
        ECDSA { ref curve, .. } => curve_allowed_ecdsa(curve),
        ECDH { ref curve, .. } => curve_allowed_ecdh(curve),
        DSA { .. } => Err(hardware_reject("DSA")),
        ElGamal { .. } => Err(hardware_reject("ElGamal")),
        Unknown { .. } => Err(hardware_reject("unknown public-key format")),
        _ => Err(hardware_reject("unsupported public-key MPI layout")),
    }
}

/// Merge revocation material into `stored_cert`; require a cryptographic hard revocation.
pub fn apply_and_verify_revocation(
    stored_cert: &Cert,
    revocation_armored: &str,
    policy: &CertPolicy,
) -> Result<Option<String>> {
    let trimmed = revocation_armored.trim();
    if trimmed.len() > policy.max_upload_bytes {
        return Err(anyhow!(
            "Revocation material exceeds {} bytes.",
            policy.max_upload_bytes
        ));
    }

    let rev = Cert::from_bytes(trimmed.as_bytes()).context("Invalid revocation certificate")?;

    let merged = stored_cert
        .clone()
        .merge_public(rev)
        .context("Revocation certificate does not correspond to stored public key")?;

    let p = StandardPolicy::new();
    match merged.revocation_status(&p, SystemTime::now()) {
        RevocationStatus::Revoked(revs) => {
            let reason = revs
                .iter()
                .find_map(|sig| first_rev_reason_string(sig))
                .or_else(|| Some("revoked".to_string()));
            Ok(reason)
        }
        RevocationStatus::CouldBe(_) | RevocationStatus::NotAsFarAsWeKnow => Err(anyhow!(
            "Revocation signature could not be verified against the stored certificate."
        )),
    }
}

fn first_rev_reason_string(sig: &Signature) -> Option<String> {
    sig.reason_for_revocation()
        .map(|(code, slice)| rev_reason_fmt(code, slice))
}

fn rev_reason_fmt(code: ReasonForRevocation, msg: &[u8]) -> String {
    let hint = std::str::from_utf8(msg).unwrap_or("").trim();
    let prefix = code_as_str(code);
    if hint.is_empty() {
        prefix
    } else {
        format!("{prefix}: {hint}")
    }
}

fn code_as_str(code: ReasonForRevocation) -> String {
    format!("{code:?}")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

pub fn cert_from_armored(armored: &str) -> Result<Cert> {
    Cert::from_bytes(armored.trim().as_bytes()).context("Invalid OpenPGP material")
}

pub fn cert_fingerprint_hex(cert: &Cert) -> String {
    cert.fingerprint().to_hex()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sequoia_openpgp::armor;
    use sequoia_openpgp::cert::CertBuilder;
    use sequoia_openpgp::crypto::mpi;

    fn policy() -> CertPolicy {
        CertPolicy::permissive()
    }

    #[test]
    fn reject_rsa_below_2048_bits() {
        let mp = MpiPk::RSA {
            e: mpi::MPI::new(&[3]),
            n: mpi::MPI::new(&[3]),
        };
        let err = check_public_mpis(&mp).unwrap_err().to_string();
        assert!(
            err.contains("Algorithm RSA") && err.contains("Galdralag hardware"),
            "{}",
            err
        );
    }

    #[test]
    fn ed25519_key_accepts_matching_email() {
        let cert = CertBuilder::new()
            .set_cipher_suite(sequoia_openpgp::cert::CipherSuite::Cv25519)
            .add_userid("T <u@example.com>")
            .add_signing_subkey()
            .generate()
            .expect("gen")
            .0;
        let mut buf = Vec::new();
        let mut w = armor::Writer::new(&mut buf, armor::Kind::PublicKey).unwrap();
        cert.serialize(&mut w).unwrap();
        w.finalize().unwrap();
        let arm = String::from_utf8(buf).unwrap();
        let p = parse_and_validate(&arm, "u@example.com", &policy()).expect("ok");
        assert_eq!(p.emails, vec!["u@example.com".to_string()]);
        assert_eq!(p.fingerprint.len(), 40);
    }

    #[test]
    fn email_mismatch_fails() {
        let cert = CertBuilder::new()
            .set_cipher_suite(sequoia_openpgp::cert::CipherSuite::Cv25519)
            .add_userid("T <u@example.com>")
            .add_signing_subkey()
            .generate()
            .expect("gen")
            .0;
        let mut buf = Vec::new();
        let mut w = armor::Writer::new(&mut buf, armor::Kind::PublicKey).unwrap();
        cert.serialize(&mut w).unwrap();
        w.finalize().unwrap();
        let arm = String::from_utf8(buf).unwrap();
        assert!(parse_and_validate(&arm, "other@example.com", &policy()).is_err());
    }

    #[test]
    fn self_revoked_rejected() {
        let (cert, rev) = CertBuilder::new()
            .set_cipher_suite(sequoia_openpgp::cert::CipherSuite::Cv25519)
            .add_userid("T <u@example.com>")
            .add_signing_subkey()
            .generate()
            .expect("gen");
        let revoked = cert.insert_packets(rev).expect("insert rev");
        let mut buf = Vec::new();
        let mut w = armor::Writer::new(&mut buf, armor::Kind::PublicKey).unwrap();
        revoked.0.serialize(&mut w).unwrap();
        w.finalize().unwrap();
        let arm = String::from_utf8(buf).unwrap();
        assert!(parse_and_validate(&arm, "u@example.com", &policy()).is_err());
    }

    #[test]
    fn nist_p521_rejected() {
        let cert = CertBuilder::new()
            .set_cipher_suite(sequoia_openpgp::cert::CipherSuite::P521)
            .add_userid("T <u@example.com>")
            .add_signing_subkey()
            .generate()
            .expect("gen")
            .0;
        let mut buf = Vec::new();
        let mut w = armor::Writer::new(&mut buf, armor::Kind::PublicKey).unwrap();
        cert.serialize(&mut w).unwrap();
        w.finalize().unwrap();
        let arm = String::from_utf8(buf).unwrap();
        let err = parse_and_validate(&arm, "u@example.com", &policy()).expect_err("P-521 must be rejected");
        let s = format!("{err:#}");
        assert!(s.contains("is not supported by Galdralag hardware"), "{s}");
    }

    #[test]
    fn strict_policy_rejects_many_userids() {
        let mut builder = CertBuilder::new()
            .set_cipher_suite(sequoia_openpgp::cert::CipherSuite::Cv25519);
        for i in 0..20 {
            builder = builder.add_userid(format!("U{i} <u{i}@example.com>"));
        }
        let cert = builder.add_signing_subkey().generate().expect("gen").0;
        let mut buf = Vec::new();
        let mut w = armor::Writer::new(&mut buf, armor::Kind::PublicKey).unwrap();
        cert.serialize(&mut w).unwrap();
        w.finalize().unwrap();
        let arm = String::from_utf8(buf).unwrap();
        let strict = CertPolicy {
            max_upload_bytes: 128 * 1024,
            max_userids: 16,
            max_keys: 32,
            max_uid_self_signatures: 32,
        };
        let err = parse_and_validate(&arm, "u0@example.com", &strict).expect_err("too many uids");
        assert!(err.to_string().contains("User IDs"), "{}", err);
    }

    #[test]
    fn strict_policy_rejects_many_keys() {
        let mut builder = CertBuilder::new()
            .set_cipher_suite(sequoia_openpgp::cert::CipherSuite::Cv25519)
            .add_userid("T <u@example.com>");
        for _ in 0..40 {
            builder = builder.add_signing_subkey();
        }
        let cert = builder.generate().expect("gen").0;
        let mut buf = Vec::new();
        let mut w = armor::Writer::new(&mut buf, armor::Kind::PublicKey).unwrap();
        cert.serialize(&mut w).unwrap();
        w.finalize().unwrap();
        let arm = String::from_utf8(buf).unwrap();
        let strict = CertPolicy {
            max_upload_bytes: 128 * 1024,
            max_userids: 16,
            max_keys: 32,
            max_uid_self_signatures: 32,
        };
        let err = parse_and_validate(&arm, "u@example.com", &strict).expect_err("too many keys");
        assert!(err.to_string().contains("key components"), "{}", err);
    }

    #[test]
    fn strict_policy_rejects_sks_uid_selfsig_flood() {
        const FIXTURE: &str =
            include_str!("../adversarial-tests/fixtures/sks_uid_selfsig_flood.asc");
        let strict = CertPolicy {
            max_upload_bytes: 128 * 1024,
            max_userids: 16,
            max_keys: 32,
            max_uid_self_signatures: 32,
        };
        let err = parse_and_validate(FIXTURE, "sks-poison@adv.test", &strict)
            .expect_err("SKS poison fixture must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("self-signatures"),
            "expected per-UID self-signature cap, got: {msg}"
        );
        assert!(
            msg.contains("import stream"),
            "raw packet stream check must fire before Cert dedup: {msg}"
        );
    }
}
