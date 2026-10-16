//! Supervisor publishes signed public plans; only the Base Node applies them.
use crate::{ApiResponseError, AppState};
use lattice_crypto::{authority_cache::AuthorityCache, decode_key, sign_domain};
use lattice_protocol::*;

pub async fn intent_for(
    s: &AppState,
    node_id: &str,
) -> Result<Option<SignedGatewayIntent>, ApiResponseError> {
    if !matches!(
        s.control_role.as_str(),
        "supervisor" | "bootstrapper" | "combined"
    ) {
        return Ok(None);
    }
    if !s
        .master_tokens
        .snapshot()
        .await
        .offline
        .relays
        .contains_key(node_id)
    {
        return Ok(None);
    }
    let _guard = s.gateway_lock.lock().await;
    let net = s.network.read().await.clone();
    let Some(allocation) = net.allocations.get(node_id).filter(|a| {
        a.enabled
            && !matches!(
                a.status,
                NetworkNodeStatus::Revoked | NetworkNodeStatus::Disabled
            )
    }) else {
        return Ok(None);
    };
    let Some(transport) = allocation.wireguard_public_key.as_deref() else {
        return Ok(None);
    };
    let membership = crate::authority::membership_certificate(s, node_id).await?;
    let secret = decode_key::<32>(&s.control.private_key).map_err(ApiResponseError::internal)?;
    s.master_tokens
        .update_authority(|store| {
            let Some(certificate) = store.offline.relays.get(node_id).cloned() else {
                return Ok(None);
            };
            if store
                .offline
                .revocations
                .get(&certificate.certificate.subject.revocation_key())
                .is_some_and(|floor| certificate.certificate.revision <= *floor)
                || store
                    .offline
                    .revocations
                    .get(&membership.certificate.subject.revocation_key())
                    .is_some_and(|floor| membership.certificate.revision <= *floor)
            {
                return Ok(None);
            }
            let (key, own, endpoint) = match &certificate.certificate.subject {
                CertificateSubject::Relay {
                    transport_public_key,
                    overlay_ipv4,
                    endpoint,
                    ..
                } => (transport_public_key, overlay_ipv4, endpoint),
                _ => return Err(ApiResponseError::internal("stored Relay subject rejected")),
            };
            if transport != key || allocation.virtual_ipv4.split('/').next() != Some(own.as_str()) {
                return Err(ApiResponseError::conflict(
                    "relay_binding_changed",
                    "Relay transport or allocation requires a new capability",
                ));
            }
            let listen_port = endpoint
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse::<u16>().ok())
                .filter(|p| *p > 0)
                .ok_or_else(|| ApiResponseError::internal("Relay endpoint rejected"))?;
            let mut authority =
                AuthorityCache::new(s.control.public_key.clone(), net.network_id.clone());
            authority
                .ingest(
                    &AuthorityContext {
                        membership_certificate: Some(membership.clone()),
                        relay_certificate: Some(certificate.clone()),
                        ..Default::default()
                    },
                    s.clock.now_ms(),
                )
                .map_err(ApiResponseError::internal)?;
            let shape = NetworkDesiredConfig {
                schema_version: 1,
                node_id: node_id.into(),
                control_id: s.control.control_id.clone(),
                network_id: net.network_id.clone(),
                revision: 1,
                enabled: true,
                status: NetworkNodeStatus::Allocated,
                virtual_ipv4: Some(allocation.virtual_ipv4.clone()),
                overlay_cidr: Some(net.overlay_cidr.clone()),
                gateway_ipv4: Some(own.clone()),
                gateway_endpoint: Some(endpoint.clone()),
                gateway_wireguard_public_key: Some(key.clone()),
                allowed_overlay_routes: vec![net.overlay_cidr.clone()],
                keepalive_seconds: net.keepalive_seconds,
                issued_at_ms: s.clock.now_ms(),
            };
            let mut peers = Vec::new();
            for a in net.allocations.values().filter(|a| {
                a.node_id != node_id
                    && a.enabled
                    && !matches!(
                        a.status,
                        NetworkNodeStatus::Revoked | NetworkNodeStatus::Disabled
                    )
            }) {
                let Some(public) = &a.wireguard_public_key else {
                    continue;
                };
                let p = NetworkPeerEntry {
                    node_id: a.node_id.clone(),
                    wireguard_public_key: public.clone(),
                    virtual_ipv4: a.virtual_ipv4.clone(),
                    endpoint_candidates: a.endpoint_candidates.clone(),
                    status: a.status.clone(),
                    revision: a.revision,
                    updated_at_ms: a.updated_at_ms,
                };
                if !lattice_network::valid_direct_peer(&shape, &p) {
                    continue;
                }
                peers.push(NetworkPeerIntent {
                    node_id: p.node_id,
                    public_key: p.wireguard_public_key,
                    allowed_ipv4: p.virtual_ipv4,
                    endpoint: p.endpoint_candidates.into_iter().next(),
                });
            }
            peers.sort_by(|a, b| a.node_id.cmp(&b.node_id));
            let address = if own == &net.gateway_ipv4 && key == &net.gateway_wireguard_public_key {
                format!(
                    "{own}/{}",
                    net.overlay_cidr
                        .split('/')
                        .nth(1)
                        .ok_or_else(|| ApiResponseError::internal("overlay prefix required"))?
                )
            } else {
                allocation.virtual_ipv4.clone()
            };
            let mut intent = GatewayIntent {
                schema_version: AUTHORITY_VERSION,
                network_id: net.network_id.clone(),
                target_node_id: node_id.into(),
                revision: 1,
                interface_name: net.interface_name.clone(),
                address,
                overlay_cidr: net.overlay_cidr.clone(),
                listen_port,
                transport_public_key: key.clone(),
                peers,
            };
            if let Some(previous) = store.offline.gateway_intents.get(node_id) {
                let mut old = previous.intent.clone();
                old.revision = 1;
                if old == intent && previous.certificate == certificate {
                    return Ok(Some(previous.clone()));
                }
                intent.revision = previous.intent.revision.checked_add(1).ok_or_else(|| {
                    ApiResponseError::internal("network intent revision exhausted")
                })?;
            }
            let signed = SignedGatewayIntent {
                signature: sign_domain(&secret, NETWORK_INTENT_DOMAIN, &intent)
                    .map_err(ApiResponseError::internal)?,
                intent,
                certificate,
            };
            lattice_network::validate_gateway_intent(
                &authority,
                &signed,
                &lattice_network::NetworkBinding {
                    node_id,
                    node_public_key: membership.certificate.subject.node_public_key(),
                    transport_public_key: transport,
                    interface_name: &net.interface_name,
                    address: None,
                    overlay_cidr: Some(&net.overlay_cidr),
                },
                s.clock.now_ms(),
            )
            .map_err(ApiResponseError::internal)?;
            store
                .offline
                .gateway_intents
                .insert(node_id.into(), signed.clone());
            Ok(Some(signed))
        })
        .await
}
