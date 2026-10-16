use crate::{
    ApiResponseError, AppState,
    auth::{self, OperatorPrincipal, OperatorScope},
};
use axum::{
    body::{Body, Bytes, to_bytes},
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::Engine;
use lattice_protocol::*;
use serde::{Deserialize, Serialize};
pub fn scope(op: &WorkloadOperation) -> OperatorScope {
    if matches!(
        op,
        WorkloadOperation::FleetInventory
            | WorkloadOperation::ListJobs
            | WorkloadOperation::ListRuntimes
            | WorkloadOperation::ListArtifacts
    ) {
        OperatorScope::WorkloadRead
    } else {
        OperatorScope::WorkloadWrite
    }
}
pub fn route(op: &WorkloadOperation) -> Result<(Method, String), ApiResponseError> {
    use WorkloadOperation::*;
    Ok(match op {
        FleetInventory => (Method::GET, "/api/v1/master/fleet".into()),
        ListJobs => (Method::GET, "/api/v1/operator/jobs".into()),
        ListRuntimes => (Method::GET, "/api/v1/operator/runtimes".into()),
        ListArtifacts => (Method::GET, "/api/v1/operator/artifacts".into()),
        QueueMining => (Method::POST, "/api/v1/operator/jobs/mining".into()),
        ControlJob => (Method::POST, "/api/v1/operator/jobs/control".into()),
        CancelJob => (Method::POST, "/api/v1/operator/jobs/cancel".into()),
        PublishRuntime {
            version,
            platform,
            architecture,
        } => {
            semver::Version::parse(version).map_err(|_| invalid())?;
            let p = match platform {
                Platform::Linux => "linux",
                Platform::Macos => "macos",
                Platform::Windows => "windows",
                _ => return Err(invalid()),
            };
            let a = match architecture {
                Architecture::X86_64 => "x86_64",
                Architecture::Aarch64 => "aarch64",
                _ => return Err(invalid()),
            };
            (
                Method::POST,
                format!("/api/v1/operator/xmrig/runtimes/{version}/{p}/{a}"),
            )
        }
    })
}
pub fn operation(method: &Method, path: &str) -> Result<WorkloadOperation, ApiResponseError> {
    for op in [
        WorkloadOperation::FleetInventory,
        WorkloadOperation::ListJobs,
        WorkloadOperation::ListRuntimes,
        WorkloadOperation::ListArtifacts,
        WorkloadOperation::QueueMining,
        WorkloadOperation::ControlJob,
        WorkloadOperation::CancelJob,
    ] {
        if route(&op)?.0 == *method && route(&op)?.1 == path {
            return Ok(op);
        }
    }
    let parts: Vec<_> = path.split('/').collect();
    if *method == Method::POST
        && parts.len() == 9
        && parts[1..6] == ["api", "v1", "operator", "xmrig", "runtimes"]
    {
        let op = WorkloadOperation::PublishRuntime {
            version: parts[6].into(),
            platform: serde_json::from_value(serde_json::json!(parts[7])).map_err(|_| invalid())?,
            architecture: serde_json::from_value(serde_json::json!(parts[8]))
                .map_err(|_| invalid())?,
        };
        route(&op)?;
        return Ok(op);
    }
    Err(invalid())
}
fn invalid() -> ApiResponseError {
    ApiResponseError::unauthorized("invalid_delegation", "delegated request rejected")
}
pub fn verify(
    s: &AppState,
    envelope: &SignedOperatorDelegation,
    op: WorkloadOperation,
    body: &str,
    now: u64,
) -> Result<OperatorPrincipal, ApiResponseError> {
    let a = crate::masters::authority(s, now)?;
    let d = &envelope.delegation;
    lattice_crypto::verify(&a.coordinator_key, &envelope.signature, d).map_err(|_| invalid())?;
    if d.schema_version != PRODUCT_SCHEMA_VERSION
        || d.network_id != a.network_id
        || d.master_control_id != s.control.control_id
        || d.operation != op
        || d.request_sha256 != body
        || d.request_id.len() > 128
        || uuid::Uuid::parse_str(&d.request_id).is_err()
        || d.issued_at_ms > now.saturating_add(5_000)
        || d.expires_at_ms <= now
        || d.expires_at_ms.saturating_sub(d.issued_at_ms) > 60_000
    {
        return Err(invalid());
    }
    Ok(OperatorPrincipal {
        username: format!("delegation/{}", d.request_id),
        scope: Some(scope(&op)),
    })
}
#[derive(Serialize, Deserialize)]
struct Cached {
    binding: String,
    status: u16,
    content_type: String,
    body: Vec<u8>,
}
pub async fn middleware(State(s): State<AppState>, request: Request, next: Next) -> Response {
    match delegated(s, request, next).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}
async fn delegated(
    s: AppState,
    request: Request,
    next: Next,
) -> Result<Response, ApiResponseError> {
    if s.control_role.as_str() == "master" {
        if let Ok(operation) = operation(request.method(), request.uri().path()) {
            crate::masters::authorize_operation(&s, &operation, s.clock.now_ms())?;
        }
    }
    let Some(header) = request.headers().get("x-lattice-delegation") else {
        return Ok(next.run(request).await);
    };
    if header.len() > 16_384 {
        return Err(invalid());
    }
    let encoded = header.to_str().map_err(|_| invalid())?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| invalid())?;
    let envelope: SignedOperatorDelegation =
        serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let op = operation(request.method(), request.uri().path())?;
    if request.uri().query().is_some() {
        return Err(invalid());
    }
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, 64 * 1024 * 1024)
        .await
        .map_err(|_| invalid())?;
    let principal = verify(&s, &envelope, op, &auth::digest(&bytes), s.clock.now_ms())?;
    if principal.scope == Some(OperatorScope::WorkloadRead) {
        let mut request = Request::from_parts(parts, Body::from(bytes));
        request.extensions_mut().insert(principal);
        return Ok(next.run(request).await);
    }
    let _guard = s.delegation_lock.lock().await;
    let id = &envelope.delegation.request_id;
    let path = s
        .registry_path
        .parent()
        .ok_or_else(invalid)?
        .join("delegation-results")
        .join(format!("{id}.json"));
    let binding = auth::digest(&serde_json::to_vec(&envelope.delegation).map_err(|_| invalid())?);
    if let Ok(data) = std::fs::read(&path) {
        let c: Cached = serde_json::from_slice(&data).map_err(|_| invalid())?;
        if c.binding != binding {
            return Err(invalid());
        }
        if c.status == 0 {
            return Err(ApiResponseError::conflict(
                "delegation_in_doubt",
                "previous execution was interrupted; inspect job state before issuing another command",
            ));
        }
        return Response::builder()
            .status(c.status)
            .header("content-type", c.content_type)
            .body(Body::from(c.body))
            .map_err(ApiResponseError::internal);
    }
    auth::atomic_json(
        &path,
        &Cached {
            binding: binding.clone(),
            status: 0,
            content_type: "application/json".into(),
            body: Vec::new(),
        },
    )?;
    let mut request = Request::from_parts(parts, Body::from(bytes));
    request.extensions_mut().insert(principal);
    let response = next.run(request).await;
    let status = response.status();
    let ct = response
        .headers()
        .get("content-type")
        .and_then(|s| s.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    let data = to_bytes(response.into_body(), 64 * 1024 * 1024)
        .await
        .map_err(|_| invalid())?;
    let cached = Cached {
        binding,
        status: status.as_u16(),
        content_type: ct.clone(),
        body: data.to_vec(),
    };
    auth::atomic_json(&path, &cached)?;
    Response::builder()
        .status(status)
        .header("content-type", ct)
        .body(Body::from(data))
        .map_err(ApiResponseError::internal)
}
pub fn request_job_id(p: Option<&OperatorPrincipal>) -> Option<String> {
    p.and_then(|p| p.username.strip_prefix("delegation/"))
        .map(|id| format!("job_{}", id.replace('-', "")))
}
pub async fn body_request(request: Request) -> Result<Bytes, ApiResponseError> {
    to_bytes(request.into_body(), 64 * 1024 * 1024)
        .await
        .map_err(|_| {
            ApiResponseError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
                "request body exceeds limit",
            )
        })
}
