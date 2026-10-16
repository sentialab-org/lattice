//! Shared local certificate verification; no I/O or authority freshness dependency.
use crate::{
    canonical_json, encode_key, fingerprint, public_key, sha256_hex, sign_domain, verify_domain,
};
use lattice_protocol::*;
use std::collections::BTreeSet;

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
fn signing_key(value: &str) -> Result<(), String> {
    ed25519_dalek::VerifyingKey::from_bytes(&crate::decode_key::<32>(value)?)
        .map(|_| ())
        .map_err(|_| "invalid subject signing key".into())
}
fn address(value: &str) -> Result<(), String> {
    let ip = value
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| "invalid subject address")?;
    if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
        return Err("invalid subject address".into());
    }
    Ok(())
}
fn endpoint(value: &str) -> bool {
    if value.parse::<std::net::SocketAddr>().is_ok() {
        return true;
    }
    value.rsplit_once(':').is_some_and(|(host, port)| {
        !host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
            && port.parse::<u16>().is_ok_and(|p| p != 0)
    })
}
pub fn certificate_id(
    network: &str,
    issuer: &str,
    subject: &CertificateSubject,
) -> Result<String, String> {
    Ok(sha256_hex(&canonical_json(&(network, issuer, subject))?))
}
pub fn issue_certificate(
    private_key: &[u8; 32],
    network: &str,
    subject: CertificateSubject,
    scopes: BTreeSet<CommandScope>,
    revision: u64,
    now: u64,
) -> Result<SignedCertificate, String> {
    let key = encode_key(&public_key(private_key));
    let issuer = fingerprint(&key)?;
    let certificate = CapabilityCertificate {
        schema_version: AUTHORITY_VERSION,
        network_id: network.into(),
        issuer_key_id: issuer.clone(),
        authority_epoch: 1,
        certificate_id: certificate_id(network, &issuer, &subject)?,
        subject,
        scopes,
        revision,
        issued_at_ms: now,
        not_before_ms: now,
        expires_at_ms: None,
    };
    let result = SignedCertificate {
        signature: sign_domain(private_key, CERTIFICATE_DOMAIN, &certificate)?,
        certificate,
    };
    verify_certificate(&key, network, &result, now)?;
    Ok(result)
}
pub fn verify_certificate<'a>(
    supervisor_key: &str,
    network: &str,
    signed: &'a SignedCertificate,
    now: u64,
) -> Result<&'a CapabilityCertificate, String> {
    let c = &signed.certificate;
    verify_domain(supervisor_key, CERTIFICATE_DOMAIN, &signed.signature, c)?;
    if !identifier(network)
        || c.schema_version != AUTHORITY_VERSION
        || c.network_id != network
        || c.issuer_key_id != fingerprint(supervisor_key)?
        || c.authority_epoch == 0
        || c.revision == 0
        || c.issued_at_ms == 0
        || c.issued_at_ms > now.saturating_add(30_000)
        || c.not_before_ms > now.saturating_add(30_000)
        || c.expires_at_ms
            .is_some_and(|end| end <= c.not_before_ms || now >= end)
        || c.certificate_id != certificate_id(network, &c.issuer_key_id, &c.subject)?
        || !identifier(c.subject.node_id())
    {
        return Err("certificate binding or validity rejected".into());
    }
    signing_key(c.subject.node_public_key())?;
    match &c.subject {
        CertificateSubject::Membership {
            terms_version,
            terms_sha256,
            ..
        } => {
            if terms_version.is_empty()
                || terms_version.len() > 128
                || !crate::valid_sha256_hex(terms_sha256)
                || !c.scopes.is_empty()
            {
                return Err("invalid membership certificate".into());
            }
        }
        CertificateSubject::Master {
            control_id,
            control_public_key,
            overlay_ipv4,
            ..
        } => {
            signing_key(control_public_key)?;
            address(overlay_ipv4)?;
            if !identifier(control_id)
                || c.scopes.is_empty()
                || c.scopes.contains(&CommandScope::NetworkForwarding)
            {
                return Err("invalid master capability".into());
            }
        }
        CertificateSubject::Relay {
            transport_public_key,
            overlay_ipv4,
            endpoint: e,
            bandwidth_limit_bps,
            ..
        } => {
            address(overlay_ipv4)?;
            if crate::decode_wireguard_key(transport_public_key)? == [0; 32]
                || !endpoint(e)
                || *bandwidth_limit_bps == 0
                || c.scopes != BTreeSet::from([CommandScope::NetworkForwarding])
            {
                return Err("invalid relay capability".into());
            }
        }
    }
    Ok(c)
}
pub fn verify_snapshot<'a>(
    supervisor_key: &str,
    network: &str,
    signed: &'a SignedAuthoritySnapshot,
    now: u64,
) -> Result<&'a AuthoritySnapshot, String> {
    let s = &signed.snapshot;
    verify_domain(supervisor_key, SNAPSHOT_DOMAIN, &signed.signature, s)?;
    if s.schema_version != AUTHORITY_VERSION
        || s.network_id != network
        || s.issuer_key_id != fingerprint(supervisor_key)?
        || s.authority_epoch == 0
        || s.revision == 0
        || s.issued_at_ms == 0
        || s.issued_at_ms > now.saturating_add(30_000)
        || s.certificates.len() > 4096
        || s.revocations.len() > 16384
    {
        return Err("authority snapshot binding rejected".into());
    }
    let mut ids = BTreeSet::new();
    for c in &s.certificates {
        verify_certificate(supervisor_key, network, c, now)?;
        if !ids.insert(&c.certificate.certificate_id) {
            return Err("duplicate certificate".into());
        }
    }
    for (key, through_revision) in &s.revocations {
        if *through_revision == 0
            || !key.split_once('/').is_some_and(|(kind, id)| {
                matches!(kind, "node" | "master" | "relay") && identifier(id)
            })
        {
            return Err("invalid revocation subject".into());
        }
    }
    Ok(s)
}
