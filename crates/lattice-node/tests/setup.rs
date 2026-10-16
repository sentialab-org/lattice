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
async fn installer_can_wait_for_master_without_restarting_setup_or_reentering_token() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let d = tempfile::tempdir().unwrap();
    let socket = d.path().join("wait.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert!(matches!(
            serde_json::from_str::<IpcRequest>(&line).unwrap(),
            IpcRequest::GetSetupStatus
        ));
        let mut report = SetupReport::initial(NodeRole::Master);
        report.stage = SetupStage::Ready;
        report.network_ready = true;
        report.workload_ready = true;
        reader
            .get_mut()
            .write_all(
                format!(
                    "{}\n",
                    serde_json::to_string(&IpcResponse::SetupStatus(report)).unwrap()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });
    let result = tokio::process::Command::new(env!("CARGO_BIN_EXE_lattice-node"))
        .args(["setup", "--wait", "--timeout-secs", "1"])
        .env("LATTICE_SOCKET", &socket)
        .output()
        .await
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    task.await.unwrap();
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
    assert!(
        matches!(ipc(&socket,IpcRequest::AcceptParticipation {version:PARTICIPATION_VERSION.into(),sha256:PARTICIPATION_SHA256.into()}).await,IpcResponse::Participation(p) if p.accepted)
    );
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
#[test]
fn macos_repair_uses_live_sync_when_address_is_unchanged() {
    assert!(lattice_node::network::can_sync_live_config(
        "[Interface]\nAddress = 10.77.0.2/32\n",
        "[Interface]\nAddress = 10.77.0.2/32\n[Peer]\n",
        true
    ));
    assert!(!lattice_node::network::can_sync_live_config(
        "Address = 10.77.0.2/32\n",
        "Address = 10.77.0.3/32\n",
        true
    ));
    assert!(!lattice_node::network::can_sync_live_config(
        "Address = 10.77.0.2/32\n",
        "Address = 10.77.0.2/32\n",
        false
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn incomplete_master_installations_fail_before_setup_and_explain_upgrade() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    for manifest in [
        None,
        Some("invalid"),
        Some(
            r#"{"source_revision":"1111111111111111111111111111111111111111","schema_version":1,"version":"0.3.2","target":"linux-x86_64","role":"master","files":[{"path":"lattice-master","sha256":"0000000000000000000000000000000000000000000000000000000000000000","size_bytes":4,"executable":true}]}"#,
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("lattice-node");
        std::fs::copy(env!("CARGO_BIN_EXE_lattice-node"), &exe).unwrap();
        if let Some(manifest) = manifest {
            std::fs::write(dir.path().join("manifest.json"), manifest).unwrap();
        }
        let socket = dir.path().join("node.sock");
        let config = dir.path().join("node.json");
        let child = std::process::Command::new(&exe)
            .env("LATTICE_CONFIG", &config)
            .env("LATTICE_SOCKET", &socket)
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
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        async fn ipc(socket: &std::path::Path, request: IpcRequest) -> IpcResponse {
            let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
            stream
                .write_all(format!("{}\n", serde_json::to_string(&request).unwrap()).as_bytes())
                .await
                .unwrap();
            let mut line = String::new();
            BufReader::new(stream).read_line(&mut line).await.unwrap();
            serde_json::from_str(&line).unwrap()
        }
        assert!(matches!(ipc(&socket, IpcRequest::AcceptParticipation {
            version: PARTICIPATION_VERSION.into(), sha256: PARTICIPATION_SHA256.into()
        }).await, IpcResponse::Participation(p) if p.accepted));
        let result = ipc(
            &socket,
            IpcRequest::BeginSetup {
                options: SetupOptions {
                    role: NodeRole::Master,
                    bootstrap_url: "https://coordinator.test".into(),
                    master_token: Some("must-not-be-consumed".into()),
                },
            },
        )
        .await;
        assert!(
            matches!(result, IpcResponse::Error { .. }),
            "a missing manifest or master executable must block activation, got {result:?}"
        );
        assert!(!dir.path().join("master/control-identity.json").exists());
        if config.exists() {
            let c: NodeConfig = serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
            assert!(
                !c.network.enabled,
                "failed promotion must not start admission"
            );
        }
        let output = tokio::process::Command::new(&exe)
            .args([
                "setup",
                "--role",
                "master",
                "--bootstrap-url",
                "https://coordinator.test",
                "--master-token-stdin",
                "--accept-terms",
                "--timeout-secs",
                "1",
            ])
            .env("LATTICE_SOCKET", &socket)
            .stdin(std::process::Stdio::null())
            .output()
            .await
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("LATTICE_ROLE=master"),
            "CLI must preserve the actionable daemon error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
