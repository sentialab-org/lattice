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
    let g = MasterGrant {
        schema_version: PRODUCT_SCHEMA_VERSION,
        network_id: net.network_id.clone(),
        node_id: c.node_id.clone(),
        node_public_key: binding.node_public_key.clone(),
        control_id: c.control_id.clone(),
        control_public_key: c.control_public_key.clone(),
        overlay_ipv4: a.virtual_ipv4.split('/').next().unwrap_or("").into(),
        revision: 1,
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
pub async fn directory(s: &AppState, now: u64) -> Result<SignedMasterDirectory, ApiResponseError> {
    let store = s.master_tokens.snapshot().await;
    let d = MasterDirectory {
        schema_version: PRODUCT_SCHEMA_VERSION,
        network_id: s.network.read().await.network_id.clone(),
        revision: store.revision,
        issued_at_ms: now,
        active_master_id: store.active_master_id,
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
    Ok(Json(DiscoveryResponse {
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
    s.master_tokens.select_active(&r.control_id).await?;
    Ok(Json(serde_json::json!({"ok":true})))
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
        || d.active_master_id.as_deref() != Some(&s.control.control_id)
        || !d.masters.contains(&a.grant)
    {
        return Err(ApiResponseError::unauthorized(
            "master_authority_expired",
            "refresh designated master authority",
        ));
    }
    Ok(a)
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
    Ok(Json(EnrollmentResponse {
        signature: sign_value(&s, &receipt)?,
        receipt,
    }))
}
