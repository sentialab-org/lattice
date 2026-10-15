use lattice_node::setup::{NetworkEvidence, evaluate_readiness};
use lattice_protocol::*;
#[test]
fn ordinary_setup_sends_no_token() {
    let o = SetupOptions {
        role: NodeRole::Node,
        bootstrap_url: "https://coordinator.test".into(),
        master_token: None,
    };
    let j = serde_json::to_value(&o).unwrap();
    assert!(j.get("master_token").is_none());
}
#[test]
fn master_setup_never_logs_secret() {
    let o = SetupOptions {
        role: NodeRole::Master,
        bootstrap_url: "https://coordinator.test".into(),
        master_token: Some("secret-activation".into()),
    };
    assert!(!format!("{o:?}").contains("secret-activation"));
    let report = SetupReport::initial(NodeRole::Master);
    assert!(!serde_json::to_string(&report).unwrap().contains("token"));
}
#[test]
fn service_without_handshake_is_not_ready() {
    assert!(
        !evaluate_readiness(
            &NetworkEvidence {
                handshake_age_ms: None,
                route_verified: true,
                probe_success: true
            },
            false
        )
        .0
    );
    assert!(
        !evaluate_readiness(
            &NetworkEvidence {
                handshake_age_ms: Some(190_000),
                route_verified: true,
                probe_success: true
            },
            true
        )
        .0
    );
    assert!(
        !evaluate_readiness(
            &NetworkEvidence {
                handshake_age_ms: Some(1000),
                route_verified: false,
                probe_success: true
            },
            true
        )
        .0
    );
}
#[test]
fn setup_retry_preserves_identity_policy_and_ip() {
    let mut c = NodeConfig::default();
    let old = c.policy.clone();
    lattice_node::setup::enable_network(&mut c, "https://coordinator.test");
    assert_eq!(c.policy, old);
    assert!(c.network.enabled);
}
#[test]
fn no_master_reports_waiting_without_tearing_down_network() {
    let (n, w, stage) = evaluate_readiness(
        &NetworkEvidence {
            handshake_age_ms: Some(1000),
            route_verified: true,
            probe_success: true,
        },
        false,
    );
    assert!(n);
    assert!(!w);
    assert_eq!(stage, SetupStage::WaitingForMaster);
}
#[test]
fn interrupted_master_recovers_grant_without_saved_token() {
    let o = SetupOptions {
        role: NodeRole::Master,
        bootstrap_url: "https://coordinator.test".into(),
        master_token: Some("must-not-persist".into()),
    };
    let stored = lattice_node::setup::durable_options(&o);
    assert!(stored.master_token.is_none());
    assert!(
        !serde_json::to_string(&stored)
            .unwrap()
            .contains("must-not-persist")
    );
}
#[test]
fn setup_help_exits_without_starting_daemon() {
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_lattice-node"))
        .args(["setup", "--help"])
        .output()
        .unwrap();
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).contains("--bootstrap-url"));
}
#[cfg(unix)]
#[tokio::test]
async fn daemon_owned_setup_joins_over_real_ipc_and_never_reports_unverified_network() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("coordinator");
    let state = lattice_control::load_state(
        &data,
        String::new(),
        None,
        "http://127.0.0.1:7443".into(),
        "bootstrapper".into(),
    )
    .await
    .unwrap();
    let inspect = state.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, lattice_control::build_router(state))
            .await
            .unwrap();
    });
    let socket = dir.path().join("node.sock");
    let config = dir.path().join("node.json");
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_lattice-node"))
        .env("LATTICE_CONFIG", &config)
        .env("LATTICE_SOCKET", &socket)
        .env("LATTICE_WG_QUICK", "/usr/bin/false")
        .env("LATTICE_NETWORK_INTERVAL_SECS", "2")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    struct Kill(std::process::Child);
    impl Drop for Kill {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let _guard = Kill(child);
    for _ in 0..60 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    async fn ipc(socket: &std::path::Path, r: IpcRequest) -> IpcResponse {
        let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
        stream
            .write_all(format!("{}\n", serde_json::to_string(&r).unwrap()).as_bytes())
            .await
            .unwrap();
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).await.unwrap();
        serde_json::from_str(&line).unwrap()
    }
    assert!(matches!(
        ipc(
            &socket,
            IpcRequest::BeginSetup {
                options: SetupOptions {
                    role: NodeRole::Node,
                    bootstrap_url: url,
                    master_token: None
                }
            }
        )
        .await,
        IpcResponse::SetupStatus(_)
    ));
    for _ in 0..80 {
        if !inspect.registry.read().await.nodes.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(inspect.registry.read().await.nodes.len(), 1);
    let r = ipc(&socket, IpcRequest::GetSetupStatus).await;
    let IpcResponse::SetupStatus(report) = r else {
        panic!("expected setup status")
    };
    assert!(!report.network_ready);
    assert!(!report.workload_ready);
    assert_ne!(report.stage, SetupStage::Ready);
    let stored = std::fs::read_to_string(dir.path().join("setup.json")).unwrap();
    assert!(!stored.contains("private_key"));
    assert!(!stored.contains("master_token"));
    server.abort();
}
#[test]
fn bundle_verifier_rejects_missing_or_unlisted_files() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("manifest.json"),r#"{"schema_version":1,"version":"0.2.0","target":"linux-x86_64","role":"node","files":[]}"#).unwrap();
    assert!(lattice_node::bundle::validate(d.path(), NodeRole::Node).is_err());
}
