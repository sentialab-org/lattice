//! This router is merged only into the private managed Supervisor backend.
use crate::{ApiResponseError, AppState};
use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use lattice_protocol::*;
use subtle::ConstantTimeEq;

pub fn router(app: Router, state: AppState) -> Router {
    app.merge(
        Router::new()
            .route("/api/v2/local/host", post(provision))
            .with_state(state),
    )
}
fn service_authorized(state: &AppState, headers: &HeaderMap) -> Result<(), ApiResponseError> {
    use std::io::Read;
    let denied = || {
        ApiResponseError::unauthorized(
            "private_service_required",
            "private module credential required",
        )
    };
    let path = state
        .network_path
        .parent()
        .ok_or_else(denied)?
        .join("module-service-token.json");
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|_| denied())?;
    let meta = file.metadata().map_err(|_| denied())?;
    if !meta.is_file() || meta.len() > 512 {
        return Err(denied());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err(denied());
        }
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|_| denied())?;
    let token: String = serde_json::from_slice(&bytes).map_err(|_| denied())?;
    let supplied = headers
        .get("x-lattice-module-service")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(denied)?;
    if token.len() != 64
        || !token.bytes().all(|b| b.is_ascii_hexdigit())
        || supplied.len() != 64
        || !bool::from(token.as_bytes().ct_eq(supplied.as_bytes()))
    {
        return Err(denied());
    }
    Ok(())
}
async fn provision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<LocalHostProvisionRequest>,
) -> Result<Json<LocalHostProvisionResponse>, ApiResponseError> {
    service_authorized(&state, &headers)?;
    if !matches!(
        state.control_role.as_str(),
        "supervisor" | "bootstrapper" | "combined"
    ) {
        return Err(ApiResponseError::unauthorized(
            "supervisor_required",
            "host provisioning requires Supervisor",
        ));
    }
    let claim = &request.claim;
    let node = &claim.join.claim.enrollment;
    if claim.schema_version != AUTHORITY_VERSION
        || !claim
            .join
            .claim
            .terms
            .as_ref()
            .is_some_and(|t| t.is_current(state.clock.now_ms()))
    {
        return Err(ApiResponseError::bad_request(
            "invalid_host_claim",
            "current participation consent required",
        ));
    }
    lattice_crypto::verify_domain(
        &node.public_key,
        LOCAL_HOST_DOMAIN,
        &request.signature,
        claim,
    )
    .map_err(|_| {
        ApiResponseError::unauthorized("invalid_host_signature", "host transport proof rejected")
    })?;
    if lattice_crypto::decode_wireguard_key(&claim.wireguard_public_key)
        .map_err(ApiResponseError::internal)?
        == [0; 32]
    {
        return Err(ApiResponseError::bad_request(
            "invalid_transport",
            "transport public key required",
        ));
    }
    let _host = state.gateway_lock.lock().await;
    {
        let net = state.network.read().await;
        if claim.interface_name != net.interface_name
            || claim.forwarding_limit_bps == Some(0)
            || (!claim.adopt_gateway && claim.forwarding_limit_bps.is_some())
        {
            return Err(ApiResponseError::bad_request(
                "invalid_host_binding",
                "local interface or forwarding policy rejected",
            ));
        }
        if claim.adopt_gateway
            && (claim.wireguard_public_key != net.gateway_wireguard_public_key
                || net.allocations.values().any(|a| {
                    a.node_id != node.node_id
                        && a.virtual_ipv4.split('/').next() == Some(net.gateway_ipv4.as_str())
                })
                || net.allocations.get(&node.node_id).is_some_and(|a| {
                    a.virtual_ipv4.split('/').next() != Some(net.gateway_ipv4.as_str())
                        || a.wireguard_public_key
                            .as_deref()
                            .is_some_and(|k| k != claim.wireguard_public_key)
                }))
        {
            return Err(ApiResponseError::conflict(
                "gateway_adoption_conflict",
                "preserved gateway and Node allocation must match",
            ));
        }
        if net.allocations.get(&node.node_id).is_some_and(|a| {
            matches!(
                a.status,
                NetworkNodeStatus::Revoked | NetworkNodeStatus::Disabled
            )
        }) {
            return Err(ApiResponseError::unauthorized(
                "membership_revoked",
                "host membership requires explicit readmission",
            ));
        }
    }
    // A retained module credential never silently reissues a revoked or narrowed Relay grant.
    let authorization = state.master_tokens.snapshot().await;
    if let Some(c) = authorization.offline.relays.get(&node.node_id) {
        if authorization
            .offline
            .revocations
            .get(&c.certificate.subject.revocation_key())
            .is_some_and(|floor| c.certificate.revision <= *floor)
        {
            return Err(ApiResponseError::unauthorized(
                "relay_revoked",
                "Relay readmission requires an explicit owner grant",
            ));
        }
    }
    let Json(mut joined) =
        crate::onboarding::public_join(State(state.clone()), Json(claim.join.clone())).await?;
    {
        let mut guard = state.network.write().await;
        let mut net = guard.clone();
        if claim.adopt_gateway {
            let ip = format!("{}/32", net.gateway_ipv4);
            if let Some(a) = net.allocations.get(&node.node_id) {
                if a.virtual_ipv4 != ip
                    || a.wireguard_public_key
                        .as_deref()
                        .is_some_and(|k| k != claim.wireguard_public_key)
                {
                    return Err(ApiResponseError::conflict(
                        "gateway_adoption_conflict",
                        "gateway allocation changed during provisioning",
                    ));
                }
            } else {
                net.allocations.insert(
                    node.node_id.clone(),
                    crate::network::NetworkAllocation {
                        node_id: node.node_id.clone(),
                        virtual_ipv4: ip,
                        wireguard_public_key: Some(claim.wireguard_public_key.clone()),
                        revision: 1,
                        enabled: true,
                        status: NetworkNodeStatus::Allocated,
                        last_applied_revision: 0,
                        last_sequence: 0,
                        last_error: None,
                        endpoint_candidates: Vec::new(),
                        gateway_endpoint_override: None,
                        gateway_binding_sha256: None,
                        updated_at_ms: state.clock.now_ms(),
                    },
                );
            }
        } else {
            crate::network::ensure_public_allocation(
                &mut net,
                &node.node_id,
                &claim.wireguard_public_key,
                state.clock.now_ms(),
            )?;
        }
        crate::network::save(&state.network_path, &net)
            .await
            .map_err(ApiResponseError::internal)?;
        *guard = net;
    }
    if claim.adopt_gateway {
        let endpoint = state.network.read().await.gateway_endpoint.clone();
        if let Some(current) = authorization.offline.relays.get(&node.node_id) {
            if !matches!(&current.certificate.subject,CertificateSubject::Relay{transport_public_key,endpoint:e,..} if transport_public_key==&claim.wireguard_public_key && e==&endpoint)
            {
                return Err(ApiResponseError::conflict(
                    "relay_binding_changed",
                    "changed gateway binding requires an explicit owner grant",
                ));
            }
        } else {
            crate::authority::issue_relay(
                &state,
                crate::authority::RelayGrantRequest {
                    node_id: node.node_id.clone(),
                    endpoint,
                    bandwidth_limit_bps: claim.forwarding_limit_bps.unwrap_or(8_000_000),
                },
            )
            .await?;
        }
    }
    joined.authority = Some(crate::authority::member_context(&state, &node.node_id).await?);
    // Release the per-host lock before the intent publisher takes the same serialization boundary.
    drop(_host);
    let gateway_intent = if claim.adopt_gateway {
        crate::network::reconcile::intent_for(&state, &node.node_id).await?
    } else {
        None
    };
    Ok(Json(LocalHostProvisionResponse {
        join: joined,
        gateway_intent,
    }))
}
