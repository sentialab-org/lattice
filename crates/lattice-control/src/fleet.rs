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
pub async fn inventory(
    State(s): State<AppState>,
    h: axum::http::HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, ApiResponseError> {
    authorize_operator(&s, &h, None, OperatorScope::FleetRead)?;
    let registry = s.registry.read().await;
    let net = s.network.read().await;
    let masters = s.master_tokens.snapshot().await;
    let mut nodes = vec![
        serde_json::json!({"node_id":s.control.control_id,"node_name":"Network coordinator","role":s.control_role.as_str(),"virtual_ipv4":net.gateway_ipv4,"online":true}),
    ];
    for n in registry.nodes.values() {
        let a = net.allocations.get(&n.node_id);
        let master = masters
            .grants
            .iter()
            .find(|(id, g)| g.grant.node_id == n.node_id && !masters.revoked.contains(*id));
        nodes.push(serde_json::json!({"node_id":n.node_id,"node_name":n.node_name,"role":if master.is_some(){"master"}else{"node"},"virtual_ipv4":a.map(|a|&a.virtual_ipv4),"network_status":a.map(|a|&a.status),"capabilities":n.capabilities,"health":n.health,"effective_policy":n.effective_policy,"last_seen_ms":n.last_seen_ms,"online_until_ms":n.online_until_ms,"platform":n.platform,"architecture":n.architecture,"online":n.online_until_ms.is_some_and(|t|t>s.clock.now_ms())}));
    }
    Ok(Json(nodes))
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
    let body = delegation::body_request(request).await?;
    forward(&s, op, body).await
}
pub async fn forward(
    s: &AppState,
    op: WorkloadOperation,
    body: Bytes,
) -> Result<Response, ApiResponseError> {
    let store = s.master_tokens.snapshot().await;
    let id = store.active_master_id.as_ref().ok_or_else(|| {
        ApiResponseError::conflict("waiting_for_master", "no designated workload master")
    })?;
    let grant = store
        .grants
        .get(id)
        .filter(|_| !store.revoked.contains(id))
        .ok_or_else(|| {
            ApiResponseError::conflict("waiting_for_master", "designated master is unavailable")
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
        master_control_id: id.clone(),
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
        .timeout(std::time::Duration::from_secs(30))
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
