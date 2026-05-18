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
use sequoia_openpgp::types::{Curve, ReasonForRevocation, RevocationStatus};
use sequoia_openpgp::Cert;

#[derive(Debug)]
pub struct ParsedCert {
    pub fingerprint: String,
    pub armored: String,
    /// Canonicalised lowercase emails extracted from certificate User IDs.
    #[allow(dead_code)]
    pub emails: Vec<String>,
}

const MAX_UPLOAD: usize = 128 * 1024;

fn hardware_reject<D: Display>(name: D) -> anyhow::Error {
    anyhow!("Algorithm {} is not supported by Galdralag hardware.", name)
}

pub fn parse_and_validate(armored: &str, submitted_email: &str) -> Result<ParsedCert> {
    let trimmed = armored.trim();
    if trimmed.len() > MAX_UPLOAD {
        return Err(anyhow!("Key material exceeds {} bytes.", MAX_UPLOAD));
    }

    let cert = Cert::from_bytes(trimmed.as_bytes()).context("Invalid OpenPGP certificate")?;

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

    policy_check_keys(&cert)?;
    deny_self_revoked(&cert)?;

    let mut emails = Vec::new();
    for uid in cert.userids() {
        if let Ok(Some(em)) = uid.email_normalized() {
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
) -> Result<Option<String>> {
    let rev = Cert::from_bytes(revocation_armored.trim().as_bytes())
        .context("Invalid revocation certificate")?;

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
        let p = parse_and_validate(&arm, "u@example.com").expect("ok");
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
        assert!(parse_and_validate(&arm, "other@example.com").is_err());
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
        revoked.serialize(&mut w).unwrap();
        w.finalize().unwrap();
        let arm = String::from_utf8(buf).unwrap();
        assert!(parse_and_validate(&arm, "u@example.com").is_err());
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
        let err = parse_and_validate(&arm, "u@example.com").expect_err("P-521 must be rejected");
        let s = format!("{err:#}");
        assert!(s.contains("is not supported by Galdralag hardware"), "{s}");
    }
}
