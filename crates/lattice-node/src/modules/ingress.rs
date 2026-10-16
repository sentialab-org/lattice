//! One public HTTP ingress, with fixed private module destinations.
use super::*;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};

fn backend(path: &str, supervisor: bool, master: bool) -> Option<ModuleKind> {
    let workload = path.starts_with("/api/v1/master/")
        || path.starts_with("/api/v2/master/")
        || path == "/api/v1/heartbeat"
        || path.starts_with("/api/v1/content/")
        || path == "/api/v1/releases/latest"
        || matches!(
            path,
            "/api/v1/jobs/decision" | "/api/v1/jobs/status" | "/api/v1/jobs/control-ack"
        );
    if workload {
        return master.then_some(ModuleKind::Master);
    }
    if supervisor {
        Some(ModuleKind::Supervisor)
    } else if master {
        Some(ModuleKind::Master)
    } else {
        None
    }
}
fn strip_hop_headers(headers: &mut HeaderMap) {
    if let Some(value) = headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
    {
        for name in value.split(',').map(str::trim) {
            headers.remove(name);
        }
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "x-lattice-module-service",
    ] {
        headers.remove(name);
    }
}
pub(crate) fn router(state: Arc<AppState>) -> Router {
    Router::new().fallback(proxy).with_state(state)
}
fn unavailable() -> Response {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .body(Body::from("Required Lattice module is unavailable"))
        .unwrap()
}
async fn proxy(State(s): State<Arc<AppState>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    if parts.uri.path().starts_with("/api/v2/local/") {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap();
    }
    let manager = s.modules.lock().await;
    let statuses = manager.statuses();
    let available = |kind| {
        statuses.iter().any(|m| {
            m.kind == kind
                && m.enabled
                && matches!(m.state, ModuleState::Active | ModuleState::Starting)
        })
    };
    let role = if parts.headers.contains_key("x-lattice-delegation")
        && parts.uri.path().starts_with("/api/v1/operator/")
    {
        // This chooses a destination only; the Master verifies the signed delegation.
        available(ModuleKind::Master).then_some(ModuleKind::Master)
    } else {
        backend(
            parts.uri.path(),
            available(ModuleKind::Supervisor),
            available(ModuleKind::Master),
        )
    };
    let data = match role {
        Some(ModuleKind::Master) => default_master_data(&s),
        Some(ModuleKind::Supervisor) => match manager
            .records
            .get(&ModuleKind::Supervisor)
            .and_then(|r| r.authority_data_dir.clone())
        {
            Some(p) => p,
            None => return unavailable(),
        },
        _ => {
            let relay = available(ModuleKind::Relay);
            drop(manager);
            if relay
                && parts.method == axum::http::Method::GET
                && parts.uri.path() == "/api/v2/authority"
            {
                let store = s.offline_authority.lock().await;
                if let Ok(Some(cache)) = store.checked() {
                    if let Some(snapshot) = cache.snapshot() {
                        return Response::builder()
                            .header("content-type", "application/json")
                            .body(Body::from(serde_json::to_vec(snapshot).unwrap_or_default()))
                            .unwrap();
                    }
                }
            }
            return unavailable();
        }
    };
    drop(manager);
    let client = match private_client(&data) {
        Ok(c) => c,
        Err(_) => return unavailable(),
    };
    let body = match to_bytes(body, 64 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(Body::empty())
                .unwrap();
        }
    };
    let mut headers = parts.headers;
    strip_hop_headers(&mut headers);
    headers.remove("content-length");
    let path = parts
        .uri
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or("/");
    let upstream = match client
        .request(parts.method, format!("http://localhost{path}"))
        .headers(headers)
        .body(body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return unavailable(),
    };
    let mut headers = upstream.headers().clone();
    strip_hop_headers(&mut headers);
    let mut builder = Response::builder().status(upstream.status());
    *builder.headers_mut().unwrap() = headers;
    builder
        .body(Body::from_stream(upstream.bytes_stream()))
        .unwrap_or_else(|_| unavailable())
}
pub(crate) async fn run(s: Arc<AppState>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        let enabled =
            s.modules.lock().await.statuses().iter().any(|m| {
                m.enabled && matches!(m.state, ModuleState::Active | ModuleState::Starting)
            });
        if !enabled {
            tokio::select! {_=tokio::time::sleep(std::time::Duration::from_secs(1))=>{},_=shutdown.changed()=>{}};
            continue;
        }
        let address =
            std::env::var("LATTICE_INGRESS_BIND").unwrap_or_else(|_| "0.0.0.0:7443".into());
        let parsed = address
            .parse::<std::net::SocketAddr>()
            .ok()
            .filter(|a| a.port() == 7443);
        let listener = match parsed {
            Some(a) => tokio::net::TcpListener::bind(a).await.ok(),
            None => None,
        };
        let Some(listener) = listener else {
            let mut manager = s.modules.lock().await;
            manager.ingress_ready = false;
            manager.ingress_error = Some("ingress_bind_failed".into());
            drop(manager);
            tokio::select! {_=tokio::time::sleep(std::time::Duration::from_secs(2))=>{},_=shutdown.changed()=>{}};
            continue;
        };
        {
            let mut manager = s.modules.lock().await;
            manager.ingress_ready = true;
            manager.ingress_error = None;
        }
        let server = axum::serve(listener, router(s.clone()));
        let watch_s = s.clone();
        let mut watch_shutdown = shutdown.clone();
        let _=server.with_graceful_shutdown(async move {
            loop {
                if *watch_shutdown.borrow(){return;}
                if !watch_s.modules.lock().await.statuses().iter().any(|m|m.enabled && matches!(m.state,ModuleState::Active|ModuleState::Starting)){return;}
                tokio::select!{_=tokio::time::sleep(std::time::Duration::from_secs(1))=>{},_=watch_shutdown.changed()=>{}}
            }
        }).await;
        s.modules.lock().await.ingress_ready = false;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cohost_routes_workload_messages_to_master_and_owner_dashboard_to_supervisor() {
        assert_eq!(
            backend("/api/v2/master/join", true, true),
            Some(ModuleKind::Master)
        );
        assert_eq!(
            backend("/api/v1/heartbeat", true, true),
            Some(ModuleKind::Master)
        );
        assert_eq!(
            backend("/api/v1/content/abc", true, true),
            Some(ModuleKind::Master)
        );
        assert_eq!(
            backend("/api/v1/jobs/control-ack", true, true),
            Some(ModuleKind::Master)
        );
        assert_eq!(
            backend("/api/v1/operator/jobs", true, true),
            Some(ModuleKind::Supervisor)
        );
        assert_eq!(
            backend("/api/v1/bootstrap/discovery", true, true),
            Some(ModuleKind::Supervisor)
        );
        assert_eq!(backend("/api/v1/heartbeat", true, false), None);
        assert_eq!(backend("/", false, true), Some(ModuleKind::Master));
        assert_eq!(backend("/", false, false), None);
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn cohost_http_preserves_sessions_and_routes_over_separate_private_sockets() {
        use axum::http::{HeaderValue, Method};
        async fn echo(State(role): State<&'static str>, request: Request) -> Response {
            let (parts, body) = request.into_parts();
            let bytes = to_bytes(body, 1024).await.unwrap();
            assert!(!parts.headers.contains_key("x-hop-test"));
            Response::builder().status(201).header("set-cookie", "session=renewed; HttpOnly")
                .header("content-type", "application/json").body(Body::from(serde_json::to_vec(&serde_json::json!({
                    "role":role,"path":parts.uri.to_string(),"body":String::from_utf8(bytes.to_vec()).unwrap(),
                    "cookie":parts.headers.get("cookie").and_then(|v|v.to_str().ok()),
                    "origin":parts.headers.get("origin").and_then(|v|v.to_str().ok()),
                    "host":parts.headers.get("host").and_then(|v|v.to_str().ok())
                })).unwrap())).unwrap()
        }
        let dir = tempfile::tempdir().unwrap();
        let node = crate::load_state_at(dir.path().join("node.json"))
            .await
            .unwrap();
        let supervisor = dir.path().join("supervisor");
        let master = default_master_data(&node);
        let (shutdown, watch) = tokio::sync::watch::channel(false);
        let mut tasks = Vec::new();
        for (role, data) in [
            ("supervisor", supervisor.clone()),
            ("master", master.clone()),
        ] {
            std::fs::create_dir_all(&data).unwrap();
            let app = Router::new().fallback(echo).with_state(role);
            let watch = watch.clone();
            tasks.push(tokio::spawn(async move {
                lattice_control::private_backend::serve(app, &data, watch)
                    .await
                    .unwrap();
            }));
        }
        for _ in 0..100 {
            if supervisor.join("module-http.sock").exists()
                && master.join("module-http.sock").exists()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        {
            let mut manager = node.modules.lock().await;
            for kind in [ModuleKind::Supervisor, ModuleKind::Master] {
                manager.set_enabled(
                    kind,
                    None,
                    (kind == ModuleKind::Supervisor).then(|| supervisor.clone()),
                    false,
                );
                manager.status.insert(
                    kind,
                    ModuleStatus {
                        kind,
                        enabled: true,
                        state: ModuleState::Active,
                        process_id: None,
                        certificate_id: None,
                        error_code: None,
                    },
                );
            }
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = router(node.clone());
        let front = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        for (path, role) in [
            ("/api/v1/operator/jobs?view=all", "supervisor"),
            ("/api/v1/heartbeat", "master"),
        ] {
            let response = client
                .request(Method::POST, format!("{url}{path}"))
                .header("cookie", "session=owner")
                .header("origin", "https://lattice.test")
                .header("host", "lattice.test")
                .header("connection", HeaderValue::from_static("x-hop-test"))
                .header("x-hop-test", "remove-me")
                .body("payload")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 201);
            assert_eq!(
                response.headers()["set-cookie"],
                "session=renewed; HttpOnly"
            );
            let body: serde_json::Value = response.json().await.unwrap();
            assert_eq!(body["role"], role);
            assert_eq!(body["path"], path);
            assert_eq!(body["body"], "payload");
            assert_eq!(body["cookie"], "session=owner");
            assert_eq!(body["host"], "lattice.test");
            assert_eq!(body["origin"], "https://lattice.test");
        }
        let delegated: serde_json::Value = client
            .post(format!("{url}/api/v1/operator/jobs"))
            .header("x-lattice-delegation", "signed-fixture-header")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            delegated["role"], "master",
            "co-hosted Supervisor delegation must reach the private Master rather than return to the Supervisor"
        );
        super::super::disable(&node, ModuleKind::Master)
            .await
            .unwrap();
        assert_eq!(
            client
                .get(format!("{url}/api/v1/heartbeat"))
                .send()
                .await
                .unwrap()
                .status(),
            503
        );
        assert_eq!(
            client
                .get(format!("{url}/api/v1/bootstrap/discovery"))
                .send()
                .await
                .unwrap()
                .status(),
            201
        );
        front.abort();
        shutdown.send(true).unwrap();
        for task in tasks {
            task.await.unwrap();
        }
    }
}
