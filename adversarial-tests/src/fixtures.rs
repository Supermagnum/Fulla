//! OpenPGP certificate fixtures for adversarial probes (SKS-poisoning limits).

use anyhow::{Context, Result};
use sequoia_openpgp::armor;
use sequoia_openpgp::cert::CertBuilder;
use sequoia_openpgp::cert::CipherSuite;
use sequoia_openpgp::serialize::Serialize as PgpSerialize;
use sequoia_openpgp::Cert;

fn cert_to_armored(cert: &Cert) -> Result<String> {
    let mut buf = Vec::new();
    let mut w = armor::Writer::new(&mut buf, armor::Kind::PublicKey).context("armor")?;
    cert.serialize(&mut w).context("serialize")?;
    w.finalize().context("finalize")?;
    Ok(String::from_utf8(buf).context("utf8")?)
}

fn base_builder(email: &str) -> CertBuilder {
    CertBuilder::new()
        .set_cipher_suite(CipherSuite::Cv25519)
        .add_userid(format!("Test <{email}>"))
}

/// Certificate with more User IDs than `KEYSERVER_MAX_CERT_USERIDS` (default 16).
pub fn armored_excess_userids(email: &str, count: usize) -> Result<String> {
    let mut builder = CertBuilder::new().set_cipher_suite(CipherSuite::Cv25519);
    for i in 0..count {
        builder = builder.add_userid(format!("U{i} <{email}>"));
    }
    let cert = builder.add_signing_subkey().generate().context("gen")?.0;
    cert_to_armored(&cert)
}

/// Certificate with more key components than `KEYSERVER_MAX_CERT_KEYS` (default 32).
pub fn armored_excess_subkeys(email: &str, extra_subkeys: usize) -> Result<String> {
    let mut builder = base_builder(email);
    for _ in 0..extra_subkeys {
        builder = builder.add_signing_subkey();
    }
    let cert = builder.generate().context("gen")?.0;
    cert_to_armored(&cert)
}

/// Combines excess User IDs and subkeys (first structural limit hit wins server-side).
pub fn armored_excess_userids_and_subkeys(email: &str) -> Result<String> {
    armored_excess_userids(email, 20)
}
