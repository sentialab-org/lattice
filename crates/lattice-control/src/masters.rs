use crate::{
    ApiResponseError, AppState,
    auth::{OperatorScope, authorize_operator},
    onboarding::{membership_for, sign_value},
    tokens::ActivationBinding,
};
use axum::{Json, extract::State, http::HeaderMap};
use lattice_crypto::verify;
use lattice_protocol::*;
use serde::Deserialize;
#[derive(Debug)]
pub enum ActivationError {
    Signature,
    Binding,
    Network,
    Expiry,
    Revocation,
}
pub fn endpoint_from_grant(
    control: &crate::ControlIdentity,
    a: &MasterAuthority,
) -> Result<(String, String), ApiResponseError> {
    verify(&a.coordinator_key, &a.grant.signature, &a.grant.grant)
        .and_then(|_| {
            verify(
                &a.coordinator_key,
                &a.directory.signature,
                &a.directory.directory,
            )
        })
        .map_err(|_| {
            ApiResponseError::unauthorized("invalid_authority", "master endpoint proof rejected")
        })?;
    let g = &a.grant.grant;
    let ip = g.overlay_ipv4.parse::<std::net::Ipv4Addr>().map_err(|_| {
        ApiResponseError::bad_request("invalid_master_address", "IPv4 master address required")
    })?;
    if g.schema_version != PRODUCT_SCHEMA_VERSION
        || g.control_id != control.control_id
        || g.control_public_key != control.public_key
        || g.network_id != a.network_id
        || a.directory.directory.network_id != a.network_id
        || ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
    {
        return Err(ApiResponseError::unauthorized(
            "invalid_authority",
            "master endpoint binding rejected",
        ));
    }
    Ok((format!("{ip}:7443"), format!("http://{ip}:7443")))
}
pub fn verify_membership(
    m: &SignedMembership,
    key: &str,
    network: &str,
    now: u64,
) -> Result<Membership, ActivationError> {
    verify(key, &m.signature, &m.membership).map_err(|_| ActivationError::Signature)?;
    let c = &m.membership;
    if c.schema_version != PRODUCT_SCHEMA_VERSION || c.network_id != network {
        return Err(ActivationError::Network);
    }
    if c.issued_at_ms > now.saturating_add(30_000)
        || c.expires_at_ms <= now
        || c.expires_at_ms.saturating_sub(c.issued_at_ms) > 900_000
    {
        return Err(ActivationError::Expiry);
    }
    Ok(c.clone())
}
pub async fn activate(
    s: &AppState,
    r: MasterActivationRequest,
    now: u64,
) -> Result<SignedMasterGrant, ApiResponseError> {
    let c = &r.claim;
    if c.schema_version != PRODUCT_SCHEMA_VERSION
        || now.abs_diff(c.issued_at_ms) > 120_000
        || c.request_id.is_empty()
        || c.request_id.len() > 128
        || c.control_id.is_empty()
        || c.control_id.len() > 128
        || !c
            .control_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    {
        return Err(ApiResponseError::bad_request(
            "invalid_activation",
            "activation claim invalid or stale",
        ));
    }
    let m = membership_for(s, &c.node_id, now).await?;
    verify(&m.membership.node_public_key, &r.node_signature, c)
        .and_then(|_| verify(&c.control_public_key, &r.control_signature, c))
        .map_err(|_| {
            ApiResponseError::unauthorized(
                "invalid_activation_proof",
                "both identity signatures are required",
            )
        })?;
    let binding = ActivationBinding {
        node_id: c.node_id.clone(),
        node_public_key: m.membership.node_public_key.clone(),
        control_id: c.control_id.clone(),
        control_public_key: c.control_public_key.clone(),
    };
    if r.activation_token.is_empty() {
        return s.master_tokens.recover(&binding).await.map_err(Into::into);
    }
    let net = s.network.read().await;
    let a = net
        .allocations
        .get(&c.node_id)
        .filter(|a| {
            a.enabled
                && !a.virtual_ipv4.is_empty()
                && !matches!(
                    a.status,
                    NetworkNodeStatus::Revoked | NetworkNodeStatus::Disabled
                )
        })
        .ok_or_else(|| {
            ApiResponseError::conflict(
                "overlay_required",
                "join the overlay before activating master",
            )
        })?;
    let previous = s.master_tokens.snapshot().await;
    let revision = if let Some(old) = previous
        .grants
        .get(&c.control_id)
        .filter(|_| previous.revoked.contains(&c.control_id))
    {
        let g = &old.grant;
        if g.node_id != binding.node_id
            || g.node_public_key != binding.node_public_key
            || g.control_public_key != binding.control_public_key
        {
            return Err(ApiResponseError::conflict(
                "master_identity_conflict",
                "re-authorization must retain the device's identity and control key",
            ));
        }
        g.revision
            .checked_add(1)
            .ok_or_else(|| ApiResponseError::internal("master revision exhausted"))?
    } else {
        1
    };
    let g = MasterGrant {
        schema_version: PRODUCT_SCHEMA_VERSION,
        network_id: net.network_id.clone(),
        node_id: c.node_id.clone(),
        node_public_key: binding.node_public_key.clone(),
        control_id: c.control_id.clone(),
        control_public_key: c.control_public_key.clone(),
        overlay_ipv4: a.virtual_ipv4.split('/').next().unwrap_or("").into(),
        revision,
        issued_at_ms: now,
    };
    drop(net);
    let signed = SignedMasterGrant {
        signature: sign_value(s, &g)?,
        grant: g,
    };
    Ok(s.master_tokens
        .redeem(&r.activation_token, &binding, signed, now)
        .await?
        .grant)
}
pub async fn activation_handler(
    State(s): State<AppState>,
    Json(r): Json<MasterActivationRequest>,
) -> Result<Json<SignedMasterGrant>, ApiResponseError> {
    let now = s.clock.now_ms();
    Ok(Json(activate(&s, r, now).await?))
}
pub async fn operator_directory(
    State(s): State<AppState>,
    h: HeaderMap,
) -> Result<Json<SignedMasterDirectory>, ApiResponseError> {
    authorize_operator(&s, &h, None, OperatorScope::FleetRead)?;
    Ok(Json(directory(&s, s.clock.now_ms()).await?))
}
pub async fn directory(s: &AppState, now: u64) -> Result<SignedMasterDirectory, ApiResponseError> {
    let store = s.master_tokens.snapshot().await;
    let d = MasterDirectory {
        schema_version: PRODUCT_SCHEMA_VERSION,
        network_id: s.network.read().await.network_id.clone(),
        revision: store.revision,
        issued_at_ms: now,
        active_master_id: None,
        masters: store
            .grants
            .into_iter()
            .filter(|(id, _)| !store.revoked.contains(id))
            .map(|(_, g)| g)
            .collect(),
    };
    Ok(SignedMasterDirectory {
        signature: sign_value(s, &d)?,
        directory: d,
    })
}
pub async fn discovery(
    State(s): State<AppState>,
    Json(r): Json<DiscoveryRequest>,
) -> Result<Json<DiscoveryResponse>, ApiResponseError> {
    let now = s.clock.now_ms();
    let c = &r.claim;
    if c.schema_version != PRODUCT_SCHEMA_VERSION
        || now.abs_diff(c.issued_at_ms) > 120_000
        || c.request_id.is_empty()
        || c.request_id.len() > 128
    {
        return Err(ApiResponseError::bad_request(
            "invalid_discovery",
            "discovery claim rejected",
        ));
    }
    let m = membership_for(&s, &c.node_id, now).await?;
    verify(&m.membership.node_public_key, &r.signature, c).map_err(|_| {
        ApiResponseError::unauthorized(
            "invalid_discovery_proof",
            "discovery identity proof rejected",
        )
    })?;
    s.onboarding
        .accept_request(&c.node_id, &c.request_id, now)
        .await?;
    if let Some(choice) = &c.master_choice {
        s.onboarding.record_choice(&c.node_id, choice).await?;
    }
    Ok(Json(DiscoveryResponse {
        authority: Some(crate::authority::member_context(&s, &c.node_id).await?),
        membership: m,
        directory: directory(&s, now).await?,
    }))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MasterSelection {
    control_id: String,
}
pub async fn select(
    State(s): State<AppState>,
    h: HeaderMap,
    Json(r): Json<MasterSelection>,
) -> Result<Json<serde_json::Value>, ApiResponseError> {
    authorize_operator(&s, &h, None, OperatorScope::MastersWrite)?;
    let _ = r;
    Err(ApiResponseError::conflict(
        "local_master_choice_required",
        "choose a workload master on the participating device",
    ))
}
pub async fn revoke(
    State(s): State<AppState>,
    h: HeaderMap,
    Json(r): Json<MasterSelection>,
) -> Result<Json<serde_json::Value>, ApiResponseError> {
    authorize_operator(&s, &h, None, OperatorScope::MastersWrite)?;
    s.master_tokens.revoke_master(&r.control_id).await?;
    Ok(Json(serde_json::json!({"ok":true})))
}
pub fn authority(s: &AppState, now: u64) -> Result<MasterAuthority, ApiResponseError> {
    let path = s
        .registry_path
        .parent()
        .ok_or_else(|| ApiResponseError::internal("authority unavailable"))?
        .join("master-authority.json");
    let a: MasterAuthority = serde_json::from_slice(&std::fs::read(path).map_err(|_| {
        ApiResponseError::unauthorized("master_not_activated", "master activation required")
    })?)
    .map_err(|_| {
        ApiResponseError::unauthorized("invalid_authority", "master authority rejected")
    })?;
    if a.authority.is_some() {
        let cache = offline_cache(s, &a, now)?;
        cache
            .require_master(
                &s.control.control_id,
                &s.control.public_key,
                &CommandScope::Workloads,
                now,
            )
            .map_err(|e| ApiResponseError::unauthorized("invalid_authority", &e))?;
        endpoint_from_grant(&s.control, &a)?;
        return Ok(a);
    }
    if s.registry_path
        .with_file_name("master-offline-authority.json")
        .exists()
    {
        return Err(ApiResponseError::unauthorized(
            "authority_downgrade",
            "certified Master authority required",
        ));
    }
    let d = &a.directory.directory;
    verify(&a.coordinator_key, &a.directory.signature, d)
        .and_then(|_| verify(&a.coordinator_key, &a.grant.signature, &a.grant.grant))
        .map_err(|_| {
            ApiResponseError::unauthorized("invalid_authority", "coordinator signature rejected")
        })?;
    if d.schema_version != PRODUCT_SCHEMA_VERSION
        || d.network_id != a.network_id
        || a.grant.grant.network_id != a.network_id
        || d.issued_at_ms > now.saturating_add(30_000)
        || now.saturating_sub(d.issued_at_ms) > 120_000
        || a.grant.grant.control_id != s.control.control_id
        || a.grant.grant.control_public_key != s.control.public_key
        || !d.masters.contains(&a.grant)
    {
        return Err(ApiResponseError::unauthorized(
            "master_authority_expired",
            "refresh designated master authority",
        ));
    }
    Ok(a)
}

pub fn authorize_operation(
    s: &AppState,
    operation: &WorkloadOperation,
    now: u64,
) -> Result<(), ApiResponseError> {
    let a = authority(s, now)?;
    if a.authority.is_some() {
        let cache = offline_cache(s, &a, now)?;
        for scope in operation.required_scopes() {
            cache
                .require_master(&s.control.control_id, &s.control.public_key, scope, now)
                .map_err(|_| {
                    ApiResponseError::new(
                        axum::http::StatusCode::FORBIDDEN,
                        "operation_scope_denied",
                        "Master certificate does not authorize this operation",
                    )
                })?;
        }
    }
    Ok(())
}

static OFFLINE_CACHE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub(crate) fn offline_cache(
    s: &AppState,
    a: &MasterAuthority,
    now: u64,
) -> Result<lattice_crypto::authority_cache::AuthorityCache, ApiResponseError> {
    let _lock = OFFLINE_CACHE_LOCK
        .lock()
        .map_err(|_| ApiResponseError::internal("authority lock failed"))?;
    let path = s
        .registry_path
        .with_file_name("master-offline-authority.json");
    let mut cache = match std::fs::read(&path) {
        Ok(b) => serde_json::from_slice::<lattice_crypto::authority_cache::AuthorityCache>(&b)
            .map_err(|_| ApiResponseError::internal("authority cache corrupt"))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            lattice_crypto::authority_cache::AuthorityCache::new(
                a.coordinator_key.clone(),
                a.network_id.clone(),
            )
        }
        Err(_) => return Err(ApiResponseError::internal("authority cache unavailable")),
    };
    if cache.supervisor_key != a.coordinator_key || cache.network_id != a.network_id {
        return Err(ApiResponseError::unauthorized(
            "authority_pin_mismatch",
            "authority pin cannot change",
        ));
    }
    cache.validate(now).map_err(ApiResponseError::internal)?;
    let old = cache.clone();
    cache
        .ingest(
            a.authority.as_ref().ok_or_else(|| {
                ApiResponseError::unauthorized("authority_required", "certified authority required")
            })?,
            now,
        )
        .map_err(|e| ApiResponseError::unauthorized("invalid_authority", &e))?;
    if cache != old {
        crate::auth::atomic_json(&path, &cache)?;
    }
    Ok(cache)
}
pub async fn certified_workload_join(
    State(s): State<AppState>,
    Json(r): Json<CertifiedWorkloadJoinRequest>,
) -> Result<Json<CertifiedEnrollmentResponse>, ApiResponseError> {
    let now = s.clock.now_ms();
    let a = authority(&s, now)?;
    let mut cache = offline_cache(&s, &a, now)?;
    let c = &r.claim;
    let e = &c.enrollment;
    if c.schema_version != AUTHORITY_VERSION
        || e.protocol_version != PROTOCOL_VERSION
        || e.request_id.is_empty()
        || e.request_id.len() > 128
        || e.issued_at_ms.abs_diff(now) > 120_000
        || c.master_control_id != s.control.control_id
        || c.owner_choice.control_id.as_deref() != Some(s.control.control_id.as_str())
        || c.owner_choice.revision == 0
    {
        return Err(ApiResponseError::unauthorized(
            "invalid_workload_binding",
            "certified admission binding rejected",
        ));
    }
    lattice_crypto::verify_domain(&e.public_key, ADMISSION_DOMAIN, &r.signature, c).map_err(
        |_| ApiResponseError::unauthorized("invalid_signature", "node possession proof rejected"),
    )?;
    cache
        .ingest(
            &AuthorityContext {
                membership_certificate: Some(c.membership_certificate.clone()),
                ..Default::default()
            },
            now,
        )
        .and_then(|_| {
            cache
                .require_membership(&e.node_id, &e.public_key, now)
                .map(|_| ())
        })
        .map_err(|e| ApiResponseError::unauthorized("invalid_membership", &e))?;
    s.onboarding
        .accept_request(&e.node_id, &e.request_id, now)
        .await?;
    s.onboarding
        .record_choice(&e.node_id, &c.owner_choice)
        .await?;
    s.onboarding
        .record_certified_member(&e.node_id, &c.membership_certificate)
        .await?;
    let enrollment = enroll_workload(&s, e, now).await?;
    let master = cache
        .require_master(
            &s.control.control_id,
            &s.control.public_key,
            &CommandScope::Workloads,
            now,
        )
        .map_err(ApiResponseError::internal)?
        .clone();
    Ok(Json(CertifiedEnrollmentResponse {
        enrollment,
        authority: AuthorityContext {
            snapshot: cache.snapshot().cloned(),
            master_certificate: Some(master),
            membership_certificate: None,
            relay_certificate: None,
        },
    }))
}
pub async fn workload_join(
    State(s): State<AppState>,
    Json(r): Json<WorkloadJoinRequest>,
) -> Result<Json<EnrollmentResponse>, ApiResponseError> {
    let now = s.clock.now_ms();
    let a = authority(&s, now)?;
    let c = &r.claim;
    let m = verify_membership(&c.membership, &a.coordinator_key, &a.network_id, now)
        .map_err(|_| ApiResponseError::unauthorized("invalid_membership", "membership rejected"))?;
    let e = &c.enrollment;
    if c.schema_version != PRODUCT_SCHEMA_VERSION
        || c.master_control_id != s.control.control_id
        || e.node_id != m.node_id
        || e.public_key != m.node_public_key
        || e.issued_at_ms.abs_diff(now) > 120_000
    {
        return Err(ApiResponseError::unauthorized(
            "invalid_workload_binding",
            "workload enrollment binding rejected",
        ));
    }
    verify(&e.public_key, &r.signature, c).map_err(|_| {
        ApiResponseError::unauthorized("invalid_signature", "workload identity proof rejected")
    })?;
    Ok(Json(enroll_workload(&s, e, now).await?))
}
async fn enroll_workload(
    s: &AppState,
    e: &EnrollmentClaim,
    now: u64,
) -> Result<EnrollmentResponse, ApiResponseError> {
    let mut registry = s.registry.write().await;
    if registry
        .nodes
        .get(&e.node_id)
        .is_some_and(|n| n.public_key != e.public_key)
    {
        return Err(ApiResponseError::conflict(
            "node_identity_conflict",
            "identity conflicts with pinned key",
        ));
    }
    let mut next = registry.clone();
    next.nodes
        .entry(e.node_id.clone())
        .or_insert_with(|| crate::EnrolledNode {
            node_id: e.node_id.clone(),
            node_name: e.node_name.clone(),
            public_key: e.public_key.clone(),
            platform: e.platform.clone(),
            architecture: e.architecture.clone(),
            client_version: e.client_version.clone(),
            enrolled_at_ms: now,
            last_seen_ms: None,
            online_until_ms: None,
            last_sequence: 0,
            capabilities: None,
            health: None,
            effective_policy: None,
        });
    crate::auth::atomic_json(&s.registry_path, &next)?;
    *registry = next;
    let receipt = EnrollmentReceipt {
        protocol_version: PROTOCOL_VERSION,
        request_id: e.request_id.clone(),
        node_id: e.node_id.clone(),
        control_id: s.control.control_id.clone(),
        control_public_key: s.control.public_key.clone(),
        policy_revision: s.policy.revision,
        issued_at_ms: now,
    };
    Ok(EnrollmentResponse {
        signature: sign_value(&s, &receipt)?,
        receipt,
    })
}

pub fn require_workload_authority(s: &AppState) -> Result<(), ApiResponseError> {
    if s.control_role.as_str() == "master" && s.enrollment_token.is_empty() {
        authority(s, s.clock.now_ms())?;
    }
    Ok(())
}

pub async fn require_workload_node(s: &AppState, id: &str) -> Result<(), ApiResponseError> {
    if let Some(member) = s.onboarding.certified_member(id).await {
        let now = s.clock.now_ms();
        let a = authority(s, now)?;
        let mut cache = offline_cache(s, &a, now)?;
        cache
            .ingest(
                &AuthorityContext {
                    membership_certificate: Some(member.clone()),
                    ..Default::default()
                },
                now,
            )
            .and_then(|_| {
                cache
                    .require_membership(id, member.certificate.subject.node_public_key(), now)
                    .map(|_| ())
            })
            .map_err(|e| ApiResponseError::unauthorized("membership_revoked", &e))?;
        if s.onboarding.recorded_choice(id).await.control_id.as_deref()
            != Some(s.control.control_id.as_str())
        {
            return Err(ApiResponseError::unauthorized(
                "master_not_selected",
                "owner has not selected this Master",
            ));
        }
    }
    Ok(())
}

pub fn certify_heartbeat(
    s: &AppState,
    sequence: u64,
    response: &mut HeartbeatResponse,
    now: u64,
) -> Result<(), ApiResponseError> {
    let a = authority(s, now)?;
    if a.authority.is_none() {
        return Ok(());
    }
    let cache = offline_cache(s, &a, now)?;
    let cert = cache
        .require_master(
            &s.control.control_id,
            &s.control.public_key,
            &CommandScope::Workloads,
            now,
        )
        .map_err(ApiResponseError::internal)?
        .clone();
    if !cert.certificate.scopes.contains(&CommandScope::Content) {
        response.job_lease = None;
    }
    if !cert
        .certificate
        .scopes
        .contains(&CommandScope::ResourceControl)
        && response
            .control_revision
            .as_ref()
            .is_some_and(|revision| revision.revision.action != JobControlAction::Stop)
    {
        response.control_revision = None;
    }
    let context = CommandContext {
        schema_version: AUTHORITY_VERSION,
        network_id: a.network_id,
        control_id: s.control.control_id.clone(),
        target_node_id: response.receipt.node_id.clone(),
        request_id: response.receipt.request_id.clone(),
        sequence,
        issued_at_ms: now,
        expires_at_ms: now.saturating_add(120_000),
        payload_sha256: lattice_crypto::authority_cache::heartbeat_payload_hash(response)
            .map_err(ApiResponseError::internal)?,
    };
    let secret = lattice_crypto::decode_key::<32>(&s.control.private_key)
        .map_err(ApiResponseError::internal)?;
    response.command_proof = Some(SignedCommandProof {
        signature: lattice_crypto::sign_domain(&secret, COMMAND_DOMAIN, &context)
            .map_err(ApiResponseError::internal)?,
        context,
        certificate: cert.clone(),
    });
    response.authority = Some(AuthorityContext {
        snapshot: cache.snapshot().cloned(),
        master_certificate: Some(cert),
        membership_certificate: None,
        relay_certificate: None,
    });
    Ok(())
}
