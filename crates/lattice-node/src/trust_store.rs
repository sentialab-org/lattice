//! Protected, atomic authority and replay state. A damaged store never enables legacy fallback.
use crate::{
    AppState,
    identity::{IdentityState, unix_time_ms},
};
use lattice_crypto::authority_cache::{AuthorityCache, CommandBinding, heartbeat_payload_hash};
use lattice_protocol::*;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustStore {
    pub(crate) cache: Option<AuthorityCache>,
    sequence: u64,
    #[serde(skip)]
    failure: Option<String>,
}
impl TrustStore {
    pub(crate) fn load(config: &Path, identity: &IdentityState) -> Self {
        let result = (|| -> Result<Self, String> {
            let bytes = match std::fs::read(config.with_file_name("offline-authority.json")) {
                Ok(b) => b,
                Err(e)
                    if e.kind() == std::io::ErrorKind::NotFound
                        && !identity.offline_authority_required() =>
                {
                    return Ok(Self::default());
                }
                Err(_) => return Err("authority store unavailable; restore protected state".into()),
            };
            let store: Self =
                serde_json::from_slice(&bytes).map_err(|_| "authority store corrupt")?;
            if let Some(cache) = &store.cache {
                if identity
                    .bootstrap()
                    .is_some_and(|root| cache.supervisor_key != root.bootstrap_public_key)
                {
                    return Err("Supervisor pin mismatch".into());
                }
                cache.validate(unix_time_ms())?;
            } else if identity.offline_authority_required() {
                return Err("certified authority missing".into());
            }
            Ok(store)
        })();
        result.unwrap_or_else(|e| Self {
            failure: Some(e),
            ..Self::default()
        })
    }
    pub(crate) fn checked(&self) -> Result<Option<&AuthorityCache>, String> {
        if let Some(e) = &self.failure {
            return Err(e.clone());
        }
        Ok(self.cache.as_ref())
    }
}
pub(crate) async fn ingest(s: &AppState, context: &AuthorityContext) -> Result<(), String> {
    ingest_context(s, context, false).await
}
pub(crate) async fn ingest_presented(
    s: &AppState,
    context: &AuthorityContext,
) -> Result<(), String> {
    ingest_context(s, context, true).await
}
async fn ingest_context(
    s: &AppState,
    context: &AuthorityContext,
    presented: bool,
) -> Result<(), String> {
    let identity = s.identity.read().await.clone();
    let root = identity.bootstrap().ok_or("Supervisor pin required")?;
    let terms = s
        .setup
        .lock()
        .await
        .terms
        .clone()
        .ok_or("participation terms required")?;
    let mut store = s.offline_authority.lock().await;
    store.checked()?;
    let network = context
        .snapshot
        .as_ref()
        .map(|x| &x.snapshot.network_id)
        .or_else(|| {
            context
                .membership_certificate
                .as_ref()
                .map(|x| &x.certificate.network_id)
        })
        .or_else(|| {
            context
                .master_certificate
                .as_ref()
                .map(|x| &x.certificate.network_id)
        })
        .ok_or("empty authority context")?;
    let mut cache = store
        .cache
        .clone()
        .unwrap_or_else(|| AuthorityCache::new(root.bootstrap_public_key.clone(), network.clone()));
    if cache.supervisor_key != root.bootstrap_public_key {
        return Err("Supervisor pin mismatch".into());
    }
    if presented {
        cache.ingest_presented(context, unix_time_ms())?;
    } else {
        cache.ingest(context, unix_time_ms())?;
    }
    let member=cache.certificates().find(|c|matches!(&c.certificate.subject,CertificateSubject::Membership{node_id,node_public_key,terms_version,terms_sha256}
        if node_id==&identity.identity().node_id && node_public_key==&identity.identity().public_key
        && terms_version==&terms.version && terms_sha256==&terms.sha256));
    if member.is_none() {
        return Err("membership identity or terms mismatch".into());
    }
    // Persist the no-downgrade marker first; a crash can deny privilege, never weaken trust.
    s.identity.write().await.require_offline_authority().await?;
    let next = TrustStore {
        cache: Some(cache),
        sequence: store.sequence,
        failure: None,
    };
    crate::setup::write_private(
        &s.config_path.with_file_name("offline-authority.json"),
        &next,
    )
    .map_err(|e| e.to_string())?;
    *store = next;
    Ok(())
}
pub(crate) async fn next_sequence(s: &AppState) -> Result<u64, String> {
    let mut store = s.offline_authority.lock().await;
    store.checked()?;
    let sequence = store
        .sequence
        .checked_add(1)
        .ok_or("heartbeat sequence exhausted")?
        .max(unix_time_ms().saturating_mul(1_048_576));
    let mut cache = store.cache.clone();
    if let Some(c) = &mut cache {
        c.observe_time(unix_time_ms());
    }
    let next = TrustStore {
        cache,
        sequence,
        failure: None,
    };
    crate::setup::write_private(
        &s.config_path.with_file_name("offline-authority.json"),
        &next,
    )
    .map_err(|e| e.to_string())?;
    *store = next;
    Ok(sequence)
}
pub(crate) async fn observe_time(s: &AppState) -> Result<(), String> {
    let mut store = s.offline_authority.lock().await;
    let now = unix_time_ms();
    let Some(cache) = store.checked()? else {
        return Ok(());
    };
    if cache.observed_time_ms() >= now {
        return Ok(());
    }
    let mut cache = cache.clone();
    cache.observe_time(now);
    let next = TrustStore {
        cache: Some(cache),
        sequence: store.sequence,
        failure: None,
    };
    crate::setup::write_private(
        &s.config_path.with_file_name("offline-authority.json"),
        &next,
    )
    .map_err(|e| e.to_string())?;
    *store = next;
    Ok(())
}
pub(crate) async fn accept_response(
    s: &AppState,
    trust: &ControlTrust,
    claim: &HeartbeatClaim,
    response: &HeartbeatResponse,
) -> Result<(), String> {
    if let Some(context) = &response.authority {
        ingest_presented(s, context).await?;
    }
    let mut store = s.offline_authority.lock().await;
    let Some(cache) = store.checked()? else {
        return Ok(());
    };
    let mut next = cache.clone();
    let proof = response
        .command_proof
        .as_ref()
        .ok_or("certified command proof required")?;
    let digest = heartbeat_payload_hash(response)?;
    let mut scopes = vec![CommandScope::Inventory, CommandScope::ResourceControl];
    if response.job_lease.is_some() || response.control_revision.is_some() {
        scopes.push(CommandScope::Workloads);
    }
    next.accept_command(
        proof,
        &CommandBinding {
            control_id: &trust.control_id,
            control_public_key: &trust.control_public_key,
            target_node_id: &claim.node_id,
            request_id: &claim.request_id,
            sequence: claim.sequence,
            payload_sha256: &digest,
            scopes: &scopes,
        },
        unix_time_ms(),
    )?;
    let record = TrustStore {
        cache: Some(next),
        sequence: store.sequence,
        failure: None,
    };
    crate::setup::write_private(
        &s.config_path.with_file_name("offline-authority.json"),
        &record,
    )
    .map_err(|e| e.to_string())?;
    *store = record;
    Ok(())
}
