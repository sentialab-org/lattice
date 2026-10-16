//! Local authority state. Callers must atomically persist successful mutations before effects.
use crate::{
    authority::{verify_certificate, verify_snapshot},
    verify_domain,
};
use lattice_protocol::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCache {
    pub supervisor_key: String,
    pub network_id: String,
    snapshot: Option<SignedAuthoritySnapshot>,
    certificates: BTreeMap<String, SignedCertificate>,
    revocations: BTreeMap<String, u64>,
    accepted_sequences: BTreeMap<String, u64>,
    outgoing_sequence: u64,
    observed_time_ms: u64,
}
pub struct CommandBinding<'a> {
    pub control_id: &'a str,
    pub control_public_key: &'a str,
    pub target_node_id: &'a str,
    pub request_id: &'a str,
    pub sequence: u64,
    pub payload_sha256: &'a str,
    pub scopes: &'a [CommandScope],
}
impl AuthorityCache {
    pub fn new(supervisor_key: String, network_id: String) -> Self {
        Self {
            supervisor_key,
            network_id,
            snapshot: None,
            certificates: BTreeMap::new(),
            revocations: BTreeMap::new(),
            accepted_sequences: BTreeMap::new(),
            outgoing_sequence: 0,
            observed_time_ms: 0,
        }
    }
    pub fn validate(&self, now: u64) -> Result<(), String> {
        let now = now.max(self.observed_time_ms);
        if let Some(s) = &self.snapshot {
            verify_snapshot(&self.supervisor_key, &self.network_id, s, now)?;
        }
        for (subject, c) in &self.certificates {
            verify_certificate(
                &self.supervisor_key,
                &self.network_id,
                c,
                c.certificate.issued_at_ms,
            )?;
            if subject != &c.certificate.subject.revocation_key()
                || c.certificate.issued_at_ms > now.saturating_add(30_000)
            {
                return Err("stored authority binding rejected".into());
            }
        }
        Ok(())
    }
    pub fn snapshot(&self) -> Option<&SignedAuthoritySnapshot> {
        self.snapshot.as_ref()
    }
    pub fn observed_time_ms(&self) -> u64 {
        self.observed_time_ms
    }
    pub fn observe_time(&mut self, now: u64) {
        self.observed_time_ms = self.observed_time_ms.max(now);
    }
    pub fn certificates(&self) -> impl Iterator<Item = &SignedCertificate> {
        self.certificates.values()
    }
    pub fn ingest(&mut self, context: &AuthorityContext, now: u64) -> Result<(), String> {
        self.apply_context(context, now, false)
    }
    pub fn ingest_presented(&mut self, context: &AuthorityContext, now: u64) -> Result<(), String> {
        self.apply_context(context, now, true)
    }
    fn apply_context(
        &mut self,
        context: &AuthorityContext,
        now: u64,
        presented: bool,
    ) -> Result<(), String> {
        let now = now.max(self.observed_time_ms);
        let mut next = self.clone();
        next.observe_time(now);
        if let Some(signed) = &context.snapshot {
            let s = verify_snapshot(&self.supervisor_key, &self.network_id, signed, now)?;
            let mut replace = true;
            if let Some(old) = &self.snapshot {
                if s.authority_epoch != old.snapshot.authority_epoch
                    || (!presented && s.revision < old.snapshot.revision)
                    || (s.revision == old.snapshot.revision && signed != old)
                {
                    return Err("authority snapshot rollback or conflict rejected".into());
                }
                replace = s.revision >= old.snapshot.revision;
            }
            for (subject, floor) in &s.revocations {
                next.revocations
                    .entry(subject.clone())
                    .and_modify(|v| *v = (*v).max(*floor))
                    .or_insert(*floor);
            }
            for c in &s.certificates {
                next.insert_certificate(c, now, false)?;
            }
            if replace {
                next.snapshot = Some(signed.clone());
            }
        }
        for c in [
            &context.membership_certificate,
            &context.master_certificate,
            &context.relay_certificate,
        ]
        .into_iter()
        .flatten()
        {
            next.insert_certificate(c, now, true)?;
        }
        *self = next;
        Ok(())
    }
    fn insert_certificate(
        &mut self,
        c: &SignedCertificate,
        now: u64,
        strict: bool,
    ) -> Result<(), String> {
        // An expired grant in a valid historical snapshot must not hide its revocations.
        verify_certificate(
            &self.supervisor_key,
            &self.network_id,
            c,
            c.certificate.issued_at_ms,
        )?;
        if c.certificate.issued_at_ms > now.saturating_add(30_000) {
            return Err("future certificate rejected".into());
        }
        if self
            .snapshot
            .as_ref()
            .is_some_and(|s| s.snapshot.authority_epoch != c.certificate.authority_epoch)
        {
            return Err("authority epoch mismatch".into());
        }
        let id = c.certificate.subject.revocation_key();
        if let Some(old) = self.certificates.get(&id) {
            if c.certificate.authority_epoch != old.certificate.authority_epoch {
                return Err("certificate epoch mismatch".into());
            }
            if c.certificate.revision < old.certificate.revision {
                return if strict {
                    Err("certificate rollback rejected".into())
                } else {
                    Ok(())
                };
            }
            if c.certificate.revision == old.certificate.revision && c != old {
                return Err("certificate conflict rejected".into());
            }
        }
        self.certificates.insert(id, c.clone());
        Ok(())
    }
    fn current(&self, id: &str, now: u64) -> Result<&SignedCertificate, String> {
        let now = now.max(self.observed_time_ms);
        let c = self.certificates.get(id).ok_or("certificate unavailable")?;
        verify_certificate(&self.supervisor_key, &self.network_id, c, now)?;
        if self
            .revocations
            .get(id)
            .is_some_and(|floor| c.certificate.revision <= *floor)
        {
            return Err("certificate revoked".into());
        }
        Ok(c)
    }
    pub fn require_membership(
        &self,
        node_id: &str,
        key: &str,
        now: u64,
    ) -> Result<&SignedCertificate, String> {
        let c = self.current(&format!("node/{node_id}"), now)?;
        match &c.certificate.subject {
            CertificateSubject::Membership {
                node_id: id,
                node_public_key,
                ..
            } if id == node_id && node_public_key == key => Ok(c),
            _ => Err("membership identity mismatch".into()),
        }
    }
    pub fn require_master(
        &self,
        control_id: &str,
        key: &str,
        scope: &CommandScope,
        now: u64,
    ) -> Result<&SignedCertificate, String> {
        let c = self.current(&format!("master/{control_id}"), now)?;
        match &c.certificate.subject {
            CertificateSubject::Master {
                control_id: id,
                control_public_key,
                ..
            } if id == control_id
                && control_public_key == key
                && c.certificate.scopes.contains(scope) =>
            {
                Ok(c)
            }
            _ => Err("master identity or scope mismatch".into()),
        }
    }
    pub fn require_relay(
        &self,
        node_id: &str,
        key: &str,
        now: u64,
    ) -> Result<&SignedCertificate, String> {
        let c = self.current(&format!("relay/{node_id}"), now)?;
        match &c.certificate.subject {
            CertificateSubject::Relay {
                node_public_key, ..
            } if node_public_key == key => Ok(c),
            _ => Err("relay identity mismatch".into()),
        }
    }
    pub fn next_sequence(&mut self, minimum: u64) -> Result<u64, String> {
        self.outgoing_sequence = self
            .outgoing_sequence
            .checked_add(1)
            .ok_or("sequence exhausted")?
            .max(minimum);
        Ok(self.outgoing_sequence)
    }
    pub fn accept_command(
        &mut self,
        proof: &SignedCommandProof,
        b: &CommandBinding<'_>,
        now: u64,
    ) -> Result<(), String> {
        let now = now.max(self.observed_time_ms);
        let p = &proof.context;
        if p.schema_version != AUTHORITY_VERSION
            || p.network_id != self.network_id
            || p.control_id != b.control_id
            || b.scopes.is_empty()
            || p.target_node_id != b.target_node_id
            || p.request_id != b.request_id
            || p.sequence != b.sequence
            || p.sequence == 0
            || p.payload_sha256 != b.payload_sha256
            || !crate::valid_sha256_hex(&p.payload_sha256)
            || p.issued_at_ms > now.saturating_add(30_000)
            || now >= p.expires_at_ms
            || p.expires_at_ms <= p.issued_at_ms
            || p.expires_at_ms - p.issued_at_ms > 120_000
        {
            return Err("command context rejected".into());
        }
        verify_domain(b.control_public_key, COMMAND_DOMAIN, &proof.signature, p)?;
        let mut next = self.clone();
        next.observe_time(now);
        next.insert_certificate(&proof.certificate, now, true)?;
        for scope in b.scopes {
            next.require_master(b.control_id, b.control_public_key, scope, now)?;
        }
        let id = format!("{}/{}", b.control_id, b.target_node_id);
        if next
            .accepted_sequences
            .get(&id)
            .is_some_and(|old| p.sequence <= *old)
        {
            return Err("command replay rejected".into());
        }
        next.accepted_sequences.insert(id, p.sequence);
        *self = next;
        Ok(())
    }
}

/// Preserve legacy payload serialization, including floats, inside a signed digest.
pub fn heartbeat_payload_hash(r: &HeartbeatResponse) -> Result<String, String> {
    serde_json::to_vec(&(&r.receipt, &r.signature, &r.job_lease, &r.control_revision))
        .map(|b| crate::sha256_hex(&b))
        .map_err(|e| e.to_string())
}
