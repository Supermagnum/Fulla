//! Raw SKS-style User ID self-signature flood (2019 poison pattern).
//!
//! Built at the OpenPGP packet level so sequoia's `insert_packets` dedup path is
//! never used. Each flooded binding signature uses a distinct creation time.

use std::io::Write;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use sequoia_openpgp::armor;
use sequoia_openpgp::cert::CertBuilder;
use sequoia_openpgp::cert::CipherSuite;
use sequoia_openpgp::packet::signature::SignatureBuilder;
use sequoia_openpgp::packet::Packet;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::Marshal;
use sequoia_openpgp::PacketPile;
use sequoia_openpgp::types::SignatureType;
use sequoia_openpgp::Cert;

/// Email baked into the committed binary fixture (`fixtures/sks_uid_selfsig_flood.asc`).
pub const FIXTURE_EMAIL: &str = "sks-poison@adv.test";

/// Self-signatures on the primary User ID (default policy max is 32).
pub const FLOOD_SELF_SIG_COUNT: usize = 40;

/// Armored poison cert from the committed fixture (regenerate with `regenerate_fixture()`).
pub fn armored_from_fixture() -> &'static str {
    include_str!("../fixtures/sks_uid_selfsig_flood.asc")
}

/// Build a fresh poison cert for `email` with `flood_count` UID self-signatures.
pub fn build_armored(email: &str, flood_count: usize) -> Result<String> {
    let (cert, _rev) = CertBuilder::new()
        .set_cipher_suite(CipherSuite::Cv25519)
        .add_userid(format!("SKS Poison Test <{email}>"))
        .add_signing_subkey()
        .generate()
        .context("base cert")?;

    let policy = StandardPolicy::new();
    let vc = cert.with_policy(&policy, None).context("policy")?;
    let pk = cert.primary_key().key();
    let mut signer = pk
        .clone()
        .parts_into_secret()
        .context("secret key")?
        .into_keypair()
        .context("keypair")?;

    let ua = vc.userids().next().context("userid")?;
    let template = ua.binding_signature().clone();
    let userid = ua.userid().clone();

    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_546_300_000);

    let mut out: Vec<Packet> = Vec::new();
    let mut flood_after_uid = false;
    let mut flooded = false;

    for p in cert.clone().into_packets() {
        match &p {
            Packet::UserID(_) if !flooded => {
                flood_after_uid = true;
                out.push(p);
            }
            Packet::Signature(sig)
                if flood_after_uid
                    && !flooded
                    && sig.typ() == SignatureType::PositiveCertification =>
            {
                out.push(p);
                for i in 1..flood_count {
                    let t = base_time + Duration::from_secs(i as u64);
                    let sig = SignatureBuilder::from(template.clone())
                        .set_signature_creation_time(t)
                        .context("creation time")?
                        .set_notation(
                            "sks-poison@adv.test",
                            format!("flood-{i}"),
                            None,
                            false,
                        )
                        .context("notation")?
                        .sign_userid_binding(&mut signer, pk, &userid)
                        .context("sign binding")?;
                    out.push(sig.into());
                }
                flooded = true;
                flood_after_uid = false;
            }
            _ => out.push(p),
        }
    }

    anyhow::ensure!(flooded, "failed to inject self-signature flood packets");

    let sig_packets = out
        .iter()
        .filter(|p| matches!(p, Packet::Signature(_)))
        .count();
    anyhow::ensure!(
        sig_packets >= flood_count,
        "packet list has {sig_packets} signature packets, expected >= {flood_count}"
    );

    let mut binary = Vec::new();
    for p in &out {
        Marshal::serialize(p, &mut binary).context("serialize packet")?;
    }

    let poison = Cert::from_bytes(&binary).context("parse poison cert")?;
    let _ = poison; // amalgamation deduplicates; Fulla rejects via raw stream check

    let mut buf = Vec::new();
    let mut w = armor::Writer::new(&mut buf, armor::Kind::PublicKey).context("armor")?;
    // Armor the raw packet stream (not Cert::serialize) so every flooded signature packet is kept.
    w.write_all(&binary).context("write armored body")?;
    w.finalize().context("finalize")?;
    Ok(String::from_utf8(buf).context("utf8")?)
}

/// Which Fulla structural check rejects a poison cert (for tests and docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructureRejectKind {
    PerUidSelfSignatures,
    TotalSignaturePackets,
    Other,
}

/// Classify a `check_cert_structure`-style error message from Fulla.
pub fn classify_structure_reject(err: &str) -> StructureRejectKind {
    if err.contains("self-signatures") && err.contains("import stream") {
        StructureRejectKind::PerUidSelfSignatures
    } else if err.contains("self-signatures") {
        StructureRejectKind::PerUidSelfSignatures
    } else if err.contains("signatures") && err.contains("import stream") {
        StructureRejectKind::TotalSignaturePackets
    } else if err.contains("signatures (maximum") {
        StructureRejectKind::TotalSignaturePackets
    } else {
        StructureRejectKind::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_poison_has_flooded_signature_packets() {
        let armored = build_armored(FIXTURE_EMAIL, FLOOD_SELF_SIG_COUNT).expect("build");
        let pile = PacketPile::from_bytes(armored.as_bytes()).expect("parse");
        let sigs = pile
            .children()
            .filter(|p| matches!(p, Packet::Signature(_)))
            .count();
        assert!(
            sigs >= FLOOD_SELF_SIG_COUNT,
            "expected >= {FLOOD_SELF_SIG_COUNT} signature packets, got {sigs}"
        );
    }

    /// Regenerate `fixtures/sks_uid_selfsig_flood.asc` after changing flood logic.
    #[test]
    #[ignore = "manual: refresh committed binary fixture"]
    fn regenerate_fixture() {
        let armored = build_armored(FIXTURE_EMAIL, FLOOD_SELF_SIG_COUNT).expect("build");
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/fixtures/sks_uid_selfsig_flood.asc"
            ),
            armored,
        )
        .expect("write fixture");
    }
}
