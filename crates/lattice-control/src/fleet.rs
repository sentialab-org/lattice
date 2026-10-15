use crate::{
    ApiResponseError, AppState,
    auth::{self, OperatorScope, authorize_operator},
    delegation,
};
use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Request, State},
    response::Response,
};
use base64::Engine;
use lattice_protocol::*;
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WorkloadInventory {
    pub control_id: String,
    pub network_id: String,
    pub issued_at_ms: u64,
    pub nodes: Vec<crate::operator::OperatorNode>,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedWorkloadInventory {
    pub inventory: WorkloadInventory,
    pub signature: String,
}
pub async fn workload_inventory(
    State(s): State<AppState>,
    h: axum::http::HeaderMap,
    principal: Option<axum::Extension<auth::OperatorPrincipal>>,
) -> Result<Json<SignedWorkloadInventory>, ApiResponseError> {
    authorize_operator(
        &s,
        &h,
        principal.as_ref().map(|p| &p.0),
        OperatorScope::WorkloadRead,
    )?;
    let authority = crate::masters::authority(&s, s.clock.now_ms())?;
    let Json(nodes) = crate::operator::list_nodes(State(s.clone()), h, principal).await?;
    let inventory = WorkloadInventory {
        control_id: s.control.control_id.clone(),
        network_id: authority.network_id,
        issued_at_ms: s.clock.now_ms(),
        nodes,
    };
    Ok(Json(SignedWorkloadInventory {
        signature: crate::onboarding::sign_value(&s, &inventory)?,
        inventory,
    }))
}
pub async fn inventory(
    State(s): State<AppState>,
    h: axum::http::HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, ApiResponseError> {
    authorize_operator(&s, &h, None, OperatorScope::FleetRead)?;
    let mut reports = Vec::new();
    if s.control_role.as_str() == "bootstrapper" {
        let store = s.master_tokens.snapshot().await;
        let limit = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
        let mut tasks = tokio::task::JoinSet::new();
        for id in store
            .grants
            .keys()
            .filter(|id| !store.revoked.contains(*id))
        {
            let state = s.clone();
            let id = id.clone();
            let limit = limit.clone();
            tasks.spawn(async move {
                let _permit = limit.acquire_owned().await.ok()?;
                let response =
                    forward_to(&state, &id, WorkloadOperation::FleetInventory, Bytes::new())
                        .await
                        .ok()?;
                if !response.status().is_success() {
                    return None;
                }
                let bytes = axum::body::to_bytes(response.into_body(), 2 * 1024 * 1024)
                    .await
                    .ok()?;
                serde_json::from_slice::<SignedWorkloadInventory>(&bytes).ok()
            });
        }
        while let Some(result) = tasks.join_next().await {
            if let Ok(Some(report)) = result {
                reports.push(report);
            }
        }
    }
    Ok(Json(merge_inventories(&s, &reports).await))
}
pub async fn merge_inventory(
    s: &AppState,
    remote: Option<&SignedWorkloadInventory>,
) -> Vec<serde_json::Value> {
    merge_inventories(s, &remote.cloned().into_iter().collect::<Vec<_>>()).await
}
pub async fn merge_inventories(
    s: &AppState,
    reports: &[SignedWorkloadInventory],
) -> Vec<serde_json::Value> {
    let choices = s.onboarding.choices().await;
    let masters = s.master_tokens.snapshot().await;
    let registry = s.registry.read().await;
    let net = s.network.read().await;
    let now = s.clock.now_ms();
    let verified: Vec<_> = reports
        .iter()
        .filter(|r| {
            masters
                .grants
                .get(&r.inventory.control_id)
                .filter(|_| !masters.revoked.contains(&r.inventory.control_id))
                .is_some_and(|g| {
                    r.inventory.network_id == net.network_id
                        && r.inventory.issued_at_ms.abs_diff(now) <= 30000
                        && lattice_crypto::verify(
                            &g.grant.control_public_key,
                            &r.signature,
                            &r.inventory,
                        )
                        .is_ok()
                })
        })
        .collect();
    let mut nodes = vec![
        serde_json::json!({"node_id":s.control.control_id,"node_name":"Network coordinator","role":s.control_role.as_str(),"virtual_ipv4":net.gateway_ipv4,"online":true,"online_until_ms":now+30000,"workload_status":"coordinator"}),
    ];
    for n in registry.nodes.values() {
        let a = net.allocations.get(&n.node_id);
        let master = masters
            .grants
            .iter()
            .any(|(id, g)| g.grant.node_id == n.node_id && !masters.revoked.contains(id));
        let choice = choices.get(&n.node_id).cloned().unwrap_or_default();
        let report = verified
            .iter()
            .find(|r| Some(&r.inventory.control_id) == choice.control_id.as_ref());
        let remote_node = report.and_then(|r| {
            r.inventory
                .nodes
                .iter()
                .find(|v| v.node_id == n.node_id && v.public_key == n.public_key)
        });
        let separated = s.control_role.as_str() == "bootstrapper";
        let (capabilities, health, policy, last_seen, online_until) = if separated {
            (
                remote_node.and_then(|v| v.capabilities.clone()),
                remote_node.and_then(|v| v.health.clone()),
                remote_node.and_then(|v| v.effective_policy.clone()),
                remote_node.and_then(|v| v.last_seen_ms),
                remote_node.and_then(|v| v.online_until_ms),
            )
        } else {
            (
                n.capabilities.clone(),
                n.health.clone(),
                n.effective_policy.clone(),
                n.last_seen_ms,
                n.online_until_ms,
            )
        };
        let status = if separated && choice.control_id.is_none() {
            "not_selected"
        } else if separated && report.is_none() {
            "unavailable"
        } else if separated && remote_node.is_none() {
            "not_attached"
        } else if online_until.is_some_and(|t| t > now) {
            "current"
        } else {
            "stale"
        };
        nodes.push(serde_json::json!({"node_id":n.node_id,"node_name":n.node_name,"role":if master{"master"}else{"node"},"virtual_ipv4":a.map(|a|&a.virtual_ipv4),"network_status":a.map(|a|&a.status),"capabilities":capabilities,"health":health,"effective_policy":policy,"last_seen_ms":last_seen,"online_until_ms":online_until,"platform":n.platform,"architecture":n.architecture,"client_version":remote_node.map(|v|v.client_version.as_str()).unwrap_or(&n.client_version),"online":online_until.map(|t|t>now),"workload_status":status,"workload_master_id":choice.control_id}));
    }
    nodes
}
pub async fn handler(
    State(s): State<AppState>,
    request: Request,
) -> Result<Response, ApiResponseError> {
    let op = delegation::operation(request.method(), request.uri().path())?;
    if request.uri().query().is_some() {
        return Err(ApiResponseError::bad_request(
            "unsupported_query",
            "queries are not supported",
        ));
    }
    authorize_operator(&s, request.headers(), None, delegation::scope(&op))?;
    let target = request
        .headers()
        .get("x-lattice-master-id")
        .map(|h| h.to_str().map(String::from))
        .transpose()
        .map_err(|_| ApiResponseError::bad_request("invalid_master_id", "invalid master ID"))?;
    let body = delegation::body_request(request).await?;
    if let Some(id) = target {
        forward_to(&s, &id, op, body).await
    } else {
        forward(&s, op, body).await
    }
}
pub async fn forward(
    s: &AppState,
    op: WorkloadOperation,
    body: Bytes,
) -> Result<Response, ApiResponseError> {
    let store = s.master_tokens.snapshot().await;
    let ids: Vec<_> = store
        .grants
        .keys()
        .filter(|id| !store.revoked.contains(*id))
        .collect();
    if ids.len() != 1 {
        return Err(ApiResponseError::conflict(
            "workload_target_required",
            "select the target master for this operation",
        ));
    }
    forward_to(s, ids[0], op, body).await
}
pub async fn forward_to(
    s: &AppState,
    id: &str,
    op: WorkloadOperation,
    body: Bytes,
) -> Result<Response, ApiResponseError> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    {
        return Err(ApiResponseError::bad_request(
            "invalid_master_id",
            "a known master identity is required",
        ));
    }
    let store = s.master_tokens.snapshot().await;
    let grant = store
        .grants
        .get(id)
        .filter(|_| !store.revoked.contains(id))
        .ok_or_else(|| {
            ApiResponseError::conflict("waiting_for_master", "selected master is unavailable")
        })?;
    let ip = grant
        .grant
        .overlay_ipv4
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| ApiResponseError::internal("invalid master address"))?;
    let net = s.network.read().await;
    let alloc = net
        .allocations
        .get(&grant.grant.node_id)
        .filter(|a| {
            a.enabled
                && !matches!(
                    a.status,
                    NetworkNodeStatus::Revoked | NetworkNodeStatus::Disabled
                )
                && a.virtual_ipv4.split('/').next() == Some(grant.grant.overlay_ipv4.as_str())
        })
        .ok_or_else(|| {
            ApiResponseError::conflict(
                "master_network_unavailable",
                "master address is not allocated",
            )
        })?;
    let _ = alloc;
    if grant.grant.network_id != net.network_id {
        return Err(ApiResponseError::conflict(
            "invalid_master_network",
            "master network rejected",
        ));
    }
    drop(net);
    let (method, path) = delegation::route(&op)?;
    let now = s.clock.now_ms();
    let d = OperatorDelegation {
        schema_version: PRODUCT_SCHEMA_VERSION,
        request_id: uuid::Uuid::new_v4().to_string(),
        network_id: grant.grant.network_id.clone(),
        master_control_id: id.into(),
        operation: op,
        request_sha256: auth::digest(&body),
        issued_at_ms: now,
        expires_at_ms: now.saturating_add(60_000),
    };
    let signed = SignedOperatorDelegation {
        signature: crate::onboarding::sign_value(s, &d)?,
        delegation: d,
    };
    let encoded = base64::engine::general_purpose::STANDARD
        .encode(serde_json::to_vec(&signed).map_err(ApiResponseError::internal)?);
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(
            if matches!(
                signed.delegation.operation,
                WorkloadOperation::FleetInventory
            ) {
                3
            } else {
                30
            },
        ))
        .build()
        .map_err(ApiResponseError::internal)?;
    let r = client
        .request(method, format!("http://{ip}:7443{path}"))
        .header("x-lattice-delegation", encoded)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|_| {
            ApiResponseError::new(
                axum::http::StatusCode::BAD_GATEWAY,
                "master_unreachable",
                "designated master request failed",
            )
        })?;
    let status = r.status();
    if r.content_length().is_some_and(|n| n > 64 * 1024 * 1024) {
        return Err(ApiResponseError::internal("master response too large"));
    }
    let ct = r
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    let data = r
        .bytes()
        .await
        .map_err(|_| ApiResponseError::internal("master response unavailable"))?;
    Response::builder()
        .status(status)
        .header("content-type", ct)
        .body(Body::from(data))
        .map_err(ApiResponseError::internal)
}
