//! Supervisor issuance is separate from local use of a previously issued certificate.
use crate::{
    ApiResponseError, AppState,
    auth::{self, OperatorScope},
};
use axum::{Json, extract::State, http::HeaderMap};
use lattice_crypto::{
    authority::{issue_certificate, verify_snapshot},
    decode_key, sign_domain,
};
use lattice_protocol::*;
use serde::Deserialize;
use std::collections::BTreeSet;

fn private(s: &AppState) -> Result<[u8; 32], ApiResponseError> {
    decode_key(&s.control.private_key).map_err(ApiResponseError::internal)
}
fn supervisor(s: &AppState) -> Result<(), ApiResponseError> {
    if !matches!(
        s.control_role.as_str(),
        "supervisor" | "bootstrapper" | "combined"
    ) {
        return Err(ApiResponseError::new(
            axum::http::StatusCode::FORBIDDEN,
            "supervisor_required",
            "authority issuance requires Supervisor",
        ));
    }
    Ok(())
}
fn signing(error: String) -> ApiResponseError {
    ApiResponseError::bad_request("invalid_certificate", &error)
}
pub fn master_scopes() -> BTreeSet<CommandScope> {
    BTreeSet::from([
        CommandScope::Workloads,
        CommandScope::ResourceControl,
        CommandScope::Inventory,
        CommandScope::Content,
        CommandScope::Updates,
    ])
}
pub async fn publish_snapshot(s: &AppState) -> Result<SignedAuthoritySnapshot, ApiResponseError> {
    supervisor(s)?;
    let now = s.clock.now_ms();
    let secret = private(s)?;
    let (network, revoked_nodes) = {
        let n = s.network.read().await;
        (
            n.network_id.clone(),
            n.allocations
                .values()
                .filter(|a| {
                    matches!(
                        a.status,
                        NetworkNodeStatus::Revoked | NetworkNodeStatus::Disabled
                    )
                })
                .map(|a| (a.node_id.clone(), a.revision))
                .collect::<Vec<_>>(),
        )
    };
    for (id, revision) in revoked_nodes {
        s.master_tokens.revoke_node_authority(&id, revision).await?;
    }
    s.master_tokens
        .update_authority(|store| {
            if let Some(old) = &store.offline.snapshot {
                verify_snapshot(&s.control.public_key, &network, old, now)
                    .map_err(ApiResponseError::internal)?;
            }
            for id in &store.revoked {
                if let Some(grant) = store.grants.get(id) {
                    store
                        .offline
                        .revocations
                        .entry(format!("master/{id}"))
                        .and_modify(|v| *v = (*v).max(grant.grant.revision))
                        .or_insert(grant.grant.revision);
                }
            }
            let mut certificates = Vec::new();
            for grant in store.grants.values() {
                let g = &grant.grant;
                if g.network_id != network || g.schema_version != PRODUCT_SCHEMA_VERSION {
                    return Err(ApiResponseError::internal("master grant network mismatch"));
                }
                if store.revoked.contains(&g.control_id) {
                    continue;
                }
                lattice_crypto::verify(&s.control.public_key, &grant.signature, g)
                    .map_err(ApiResponseError::internal)?;
                let subject = CertificateSubject::Master {
                    node_id: g.node_id.clone(),
                    node_public_key: g.node_public_key.clone(),
                    control_id: g.control_id.clone(),
                    control_public_key: g.control_public_key.clone(),
                    overlay_ipv4: g.overlay_ipv4.clone(),
                };
                certificates.push(
                    issue_certificate(
                        &secret,
                        &network,
                        subject,
                        master_scopes(),
                        g.revision,
                        g.issued_at_ms,
                    )
                    .map_err(signing)?,
                );
            }
            for c in store.offline.relays.values() {
                if store
                    .offline
                    .revocations
                    .get(&c.certificate.subject.revocation_key())
                    .is_none_or(|floor| c.certificate.revision > *floor)
                {
                    certificates.push(c.clone());
                }
            }
            certificates.sort_by(|a, b| {
                a.certificate
                    .certificate_id
                    .cmp(&b.certificate.certificate_id)
            });
            if let Some(old) = &store.offline.snapshot {
                if old.snapshot.certificates == certificates
                    && old.snapshot.revocations == store.offline.revocations
                {
                    return Ok(old.clone());
                }
            }
            let revision = store.offline.snapshot.as_ref().map_or(Ok(1), |old| {
                old.snapshot
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| ApiResponseError::internal("authority revision exhausted"))
            })?;
            let snapshot = AuthoritySnapshot {
                schema_version: AUTHORITY_VERSION,
                network_id: network.clone(),
                issuer_key_id: lattice_crypto::fingerprint(&s.control.public_key)
                    .map_err(ApiResponseError::internal)?,
                authority_epoch: 1,
                revision,
                issued_at_ms: now,
                certificates,
                revocations: store.offline.revocations.clone(),
            };
            let signed = SignedAuthoritySnapshot {
                signature: sign_domain(&secret, SNAPSHOT_DOMAIN, &snapshot)
                    .map_err(ApiResponseError::internal)?,
                snapshot,
            };
            store.offline.snapshot = Some(signed.clone());
            Ok(signed)
        })
        .await
}
pub async fn membership_certificate(
    s: &AppState,
    id: &str,
) -> Result<SignedCertificate, ApiResponseError> {
    supervisor(s)?;
    let m = crate::onboarding::membership_for(s, id, s.clock.now_ms()).await?;
    let terms = s.onboarding.accepted_terms(id).await.ok_or_else(|| {
        ApiResponseError::unauthorized(
            "participation_terms_required",
            "accepted participation terms required",
        )
    })?;
    let registry = s.registry.read().await;
    let node = registry.nodes.get(id).ok_or_else(|| {
        ApiResponseError::unauthorized("unknown_node", "node membership required")
    })?;
    let subject = CertificateSubject::Membership {
        node_id: id.into(),
        node_public_key: m.membership.node_public_key,
        terms_version: terms.version,
        terms_sha256: terms.sha256,
    };
    issue_certificate(
        &private(s)?,
        &m.membership.network_id,
        subject,
        BTreeSet::new(),
        m.membership.revision,
        node.enrolled_at_ms,
    )
    .map_err(signing)
}
pub async fn member_context(s: &AppState, id: &str) -> Result<AuthorityContext, ApiResponseError> {
    Ok(AuthorityContext {
        membership_certificate: Some(membership_certificate(s, id).await?),
        snapshot: Some(publish_snapshot(s).await?),
        master_certificate: None,
    })
}
pub async fn public(
    State(s): State<AppState>,
) -> Result<Json<SignedAuthoritySnapshot>, ApiResponseError> {
    if s.control_role.as_str() == "master" {
        let a = crate::masters::authority(&s, s.clock.now_ms())?;
        return a
            .authority
            .and_then(|a| a.snapshot)
            .map(Json)
            .ok_or_else(|| {
                ApiResponseError::new(
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "offline_authority_unavailable",
                    "upgrade and synchronize authority first",
                )
            });
    }
    Ok(Json(publish_snapshot(&s).await?))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayGrantRequest {
    pub node_id: String,
    pub endpoint: String,
    pub bandwidth_limit_bps: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayRevocation {
    pub node_id: String,
}
pub async fn issue_relay(
    s: &AppState,
    r: RelayGrantRequest,
) -> Result<SignedCertificate, ApiResponseError> {
    supervisor(s)?;
    let now = s.clock.now_ms();
    crate::onboarding::membership_for(s, &r.node_id, now).await?;
    let node = s
        .registry
        .read()
        .await
        .nodes
        .get(&r.node_id)
        .cloned()
        .ok_or_else(|| ApiResponseError::bad_request("unknown_node", "registered node required"))?;
    let (network, allocation) = {
        let net = s.network.read().await;
        (
            net.network_id.clone(),
            net.allocations.get(&r.node_id).cloned(),
        )
    };
    let a = allocation
        .filter(|a| a.enabled)
        .ok_or_else(|| ApiResponseError::conflict("overlay_required", "join the overlay first"))?;
    let subject = CertificateSubject::Relay {
        node_id: r.node_id.clone(),
        node_public_key: node.public_key,
        transport_public_key: a.wireguard_public_key.ok_or_else(|| {
            ApiResponseError::conflict("transport_required", "registered transport key required")
        })?,
        overlay_ipv4: a.virtual_ipv4.split('/').next().unwrap_or("").into(),
        endpoint: r.endpoint,
        bandwidth_limit_bps: r.bandwidth_limit_bps,
    };
    s.master_tokens
        .update_authority(|store| {
            if let Some(old) = store.offline.relays.get(&r.node_id) {
                let floor = store
                    .offline
                    .revocations
                    .get(&old.certificate.subject.revocation_key())
                    .copied()
                    .unwrap_or(0);
                if old.certificate.subject == subject && old.certificate.revision > floor {
                    return Ok(old.clone());
                }
            }
            let previous = store
                .offline
                .relays
                .get(&r.node_id)
                .map_or(0, |c| c.certificate.revision);
            let revision = previous
                .checked_add(1)
                .ok_or_else(|| ApiResponseError::internal("relay revision exhausted"))?;
            let c = issue_certificate(
                &private(s)?,
                &network,
                subject,
                BTreeSet::from([CommandScope::NetworkForwarding]),
                revision,
                now,
            )
            .map_err(signing)?;
            if previous > 0 {
                store
                    .offline
                    .revocations
                    .entry(c.certificate.subject.revocation_key())
                    .and_modify(|v| *v = (*v).max(previous))
                    .or_insert(previous);
            }
            store.offline.relays.insert(r.node_id, c.clone());
            Ok(c)
        })
        .await
}
pub async fn grant_relay(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(r): Json<RelayGrantRequest>,
) -> Result<Json<SignedCertificate>, ApiResponseError> {
    auth::authorize_operator(&s, &headers, None, OperatorScope::NetworkWrite)?;
    let c = issue_relay(&s, r).await?;
    publish_snapshot(&s).await?;
    Ok(Json(c))
}
pub async fn revoke_relay(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(r): Json<RelayRevocation>,
) -> Result<Json<serde_json::Value>, ApiResponseError> {
    auth::authorize_operator(&s, &headers, None, OperatorScope::NetworkWrite)?;
    supervisor(&s)?;
    s.master_tokens
        .update_authority(|store| {
            let c = store.offline.relays.get(&r.node_id).ok_or_else(|| {
                ApiResponseError::bad_request("unknown_relay", "registered relay required")
            })?;
            let revision = c.certificate.revision;
            store
                .offline
                .revocations
                .entry(c.certificate.subject.revocation_key())
                .and_modify(|v| *v = (*v).max(revision))
                .or_insert(revision);
            Ok(())
        })
        .await?;
    publish_snapshot(&s).await?;
    Ok(Json(serde_json::json!({"ok":true})))
}
