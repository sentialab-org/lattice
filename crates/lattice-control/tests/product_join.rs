mod support;
use lattice_control::{
    clock::Clock,
    network::{self, reconcile::*},
};
use lattice_protocol::*;
use serde_json::json;
use std::sync::Mutex;
use support::{Device, Fixture};
async fn join(f: &Fixture, d: &Device) -> reqwest::Response {
    f.client
        .post(format!("{}/api/v1/bootstrap/join", f.url))
        .json(&d.join(f.clock.now_ms()))
        .send()
        .await
        .unwrap()
}
async fn allocate(
    f: &Fixture,
    d: &Device,
    key: &str,
) -> Result<network::NetworkAllocation, lattice_control::ApiResponseError> {
    let mut n = f.state.network.write().await;
    n.overlay_cidr = "10.77.0.0/16".into();
    n.gateway_ipv4 = "10.77.0.1".into();
    network::ensure_public_allocation(&mut n, &d.id, key, f.clock.now_ms())
}
#[tokio::test]
async fn public_join_needs_no_token() {
    let f = Fixture::new("bootstrapper").await;
    let d = Device::new();
    let r = join(&f, &d).await;
    assert_eq!(r.status(), 200);
    let r: PublicJoinResponse = r.json().await.unwrap();
    assert_eq!(r.membership.membership.node_id, d.id);
    lattice_crypto::verify(
        &f.state.control.public_key,
        &r.membership.signature,
        &r.membership.membership,
    )
    .unwrap();
}
#[tokio::test]
async fn legacy_pending_allocation_is_repaired_by_public_registration() {
    let f = Fixture::new("bootstrapper").await;
    let d = Device::new();
    assert_eq!(join(&f, &d).await.status(), 200);
    let key = lattice_crypto::encode_wireguard_key(&lattice_crypto::generate_wireguard_keypair().1);
    let first = allocate(&f, &d, &key).await.unwrap();
    {
        let mut n = f.state.network.write().await;
        let a = n.allocations.get_mut(&d.id).unwrap();
        a.virtual_ipv4.clear();
        a.status = NetworkNodeStatus::PendingApproval;
        a.enabled = false;
    }
    let repaired = allocate(&f, &d, &key).await.unwrap();
    assert!(!repaired.virtual_ipv4.is_empty());
    assert_eq!(repaired.status, NetworkNodeStatus::Allocated);
    assert!(repaired.enabled);
    assert_eq!(
        allocate(&f, &d, &key).await.unwrap().virtual_ipv4,
        repaired.virtual_ipv4
    );
    assert_eq!(first.node_id, repaired.node_id);
}
#[tokio::test]
async fn public_join_cannot_request_master_or_ip() {
    let f = Fixture::new("bootstrapper").await;
    for field in ["role", "virtual_ipv4"] {
        let mut j = serde_json::to_value(Device::new().join(f.clock.now_ms())).unwrap();
        j[field] = json!("master");
        assert_eq!(
            f.client
                .post(format!("{}/api/v1/bootstrap/join", f.url))
                .json(&j)
                .send()
                .await
                .unwrap()
                .status(),
            422
        );
    }
}
#[tokio::test]
async fn join_retries_preserve_identity_and_ip() {
    let f = Fixture::new("bootstrapper").await;
    let d = Device::new();
    assert_eq!(join(&f, &d).await.status(), 200);
    let k = lattice_crypto::encode_wireguard_key(&lattice_crypto::public_key(
        &lattice_crypto::generate_private_key(),
    ));
    let a = allocate(&f, &d, &k).await.unwrap();
    assert_eq!(join(&f, &d).await.status(), 200);
    let b = allocate(&f, &d, &k).await.unwrap();
    assert_eq!(a.virtual_ipv4, b.virtual_ipv4);
    assert_eq!(f.state.registry.read().await.nodes.len(), 1);
}
#[tokio::test]
async fn simultaneous_joins_allocate_unique_ips() {
    let f = Fixture::new("bootstrapper").await;
    let mut tasks = Vec::new();
    for _ in 0..50 {
        let state = f.state.clone();
        tasks.push(tokio::spawn(async move {
            let d = Device::new();
            let _ = lattice_control::onboarding::public_join(
                axum::extract::State(state.clone()),
                axum::Json(d.join(state.clock.now_ms())),
            )
            .await
            .map_err(|e| e.body.code)
            .unwrap();
            let mut n = state.network.write().await;
            n.overlay_cidr = "10.77.0.0/16".into();
            n.gateway_ipv4 = "10.77.0.1".into();
            network::ensure_public_allocation(
                &mut n,
                &d.id,
                &lattice_crypto::encode_wireguard_key(&lattice_crypto::public_key(&d.private)),
                state.clock.now_ms(),
            )
            .map_err(|e| e.body.code)
            .unwrap()
            .virtual_ipv4
        }));
    }
    let mut ips = std::collections::BTreeSet::new();
    for task in tasks {
        ips.insert(task.await.unwrap());
    }
    assert_eq!(ips.len(), 50);
    assert!(!ips.contains("10.77.0.1/32"));
}
#[tokio::test]
async fn concurrent_reuse_of_wireguard_key_accepts_one_node() {
    let f = Fixture::new("bootstrapper").await;
    let a = Device::new();
    let b = Device::new();
    let k = lattice_crypto::encode_wireguard_key(&lattice_crypto::public_key(&a.private));
    let (x, y) = tokio::join!(allocate(&f, &a, &k), allocate(&f, &b, &k));
    assert_ne!(x.is_ok(), y.is_ok());
}
#[tokio::test]
async fn public_rejoin_does_not_reverse_revocation() {
    let f = Fixture::new("bootstrapper").await;
    let d = Device::new();
    assert_eq!(join(&f, &d).await.status(), 200);
    allocate(
        &f,
        &d,
        &lattice_crypto::encode_wireguard_key(&lattice_crypto::public_key(&d.private)),
    )
    .await
    .unwrap();
    f.state
        .network
        .write()
        .await
        .allocations
        .get_mut(&d.id)
        .unwrap()
        .status = NetworkNodeStatus::Revoked;
    assert_eq!(join(&f, &d).await.status(), 403);
    assert!(
        allocate(
            &f,
            &d,
            &lattice_crypto::encode_wireguard_key(&lattice_crypto::public_key(&d.private))
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn legacy_enroll_still_requires_token() {
    let f = Fixture::new("combined").await;
    let d = Device::new();
    let claim = d.join(f.clock.now_ms()).claim.enrollment;
    let signature = lattice_crypto::sign(&d.private, &claim).unwrap();
    let r = f
        .client
        .post(format!("{}/api/v1/enroll", f.url))
        .json(&EnrollmentRequest {
            claim,
            signature,
            enrollment_token: String::new(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}
#[derive(Default)]
struct Recorder {
    commands: Mutex<Vec<GatewayCommand>>,
    fail: bool,
}
impl GatewayCommandRunner for Recorder {
    fn execute<'a>(&'a self, c: GatewayCommand) -> CommandFuture<'a> {
        self.commands.lock().unwrap().push(c.clone());
        Box::pin(async move {
            if self.fail && matches!(c, GatewayCommand::SyncConfig { .. }) {
                Err(GatewayError::Apply)
            } else {
                Ok(Vec::new())
            }
        })
    }
}
#[tokio::test]
async fn gateway_applies_new_peer_without_manual_command() {
    let f = Fixture::new("bootstrapper").await;
    let d = Device::new();
    allocate(
        &f,
        &d,
        &lattice_crypto::encode_wireguard_key(&lattice_crypto::public_key(&d.private)),
    )
    .await
    .unwrap();
    let r = Recorder::default();
    let report = reconcile_once(&f.state, &r).await.unwrap();
    assert_eq!(report.applied_revision, Some(report.desired_revision));
    assert!(
        r.commands
            .lock()
            .unwrap()
            .iter()
            .any(|c| matches!(c, GatewayCommand::SyncConfig { .. }))
    );
}
#[tokio::test]
async fn revoke_removes_live_peer_before_reporting_applied() {
    let f = Fixture::new("bootstrapper").await;
    let d = Device::new();
    allocate(
        &f,
        &d,
        &lattice_crypto::encode_wireguard_key(&lattice_crypto::public_key(&d.private)),
    )
    .await
    .unwrap();
    let r = Recorder::default();
    reconcile_once(&f.state, &r).await.unwrap();
    let config = f.dir.path().join("gateway-applied.conf");
    assert!(std::fs::read_to_string(&config).unwrap().contains(&d.id));
    {
        let mut n = f.state.network.write().await;
        let a = n.allocations.get_mut(&d.id).unwrap();
        a.status = NetworkNodeStatus::Revoked;
        a.enabled = false;
        a.revision += 1;
    }
    reconcile_once(&f.state, &r).await.unwrap();
    assert!(!std::fs::read_to_string(config).unwrap().contains(&d.id));
}
#[tokio::test]
async fn failed_gateway_apply_preserves_previous_config_and_reports_degraded() {
    let f = Fixture::new("bootstrapper").await;
    reconcile_once(&f.state, &Recorder::default())
        .await
        .unwrap();
    let path = f.dir.path().join("gateway-applied.conf");
    let old = std::fs::read(&path).unwrap();
    let d = Device::new();
    allocate(
        &f,
        &d,
        &lattice_crypto::encode_wireguard_key(&lattice_crypto::public_key(&d.private)),
    )
    .await
    .unwrap();
    assert!(
        reconcile_once(
            &f.state,
            &Recorder {
                fail: true,
                ..Default::default()
            }
        )
        .await
        .is_err()
    );
    assert_eq!(std::fs::read(path).unwrap(), old);
}
#[tokio::test]
async fn public_registration_automatically_allocates_over_http() {
    let f = Fixture::new("bootstrapper").await;
    let d = Device::new();
    assert_eq!(join(&f, &d).await.status(), 200);
    let claim = NetworkRegisterClaim {
        local_opt_in: true,
        protocol_version: NETWORK_PROTOCOL_VERSION,
        request_id: uuid::Uuid::new_v4().to_string(),
        node_id: d.id.clone(),
        sequence: 1,
        wireguard_public_key: lattice_crypto::encode_wireguard_key(
            &lattice_crypto::generate_wireguard_keypair().1,
        ),
        issued_at_ms: f.clock.now_ms(),
    };
    let request = NetworkRegisterRequest {
        signature: lattice_crypto::sign(&d.private, &claim).unwrap(),
        claim,
    };
    let r = f
        .client
        .post(format!("{}/api/v1/network/register", f.url))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let net = f.state.network.read().await;
    let a = &net.allocations[&d.id];
    assert!(a.enabled);
    assert_eq!(a.virtual_ipv4, "10.77.0.2/32");
    assert_eq!(a.status, NetworkNodeStatus::Allocated);
}
#[tokio::test]
async fn public_identity_cannot_inject_gateway_configuration() {
    let f = Fixture::new("bootstrapper").await;
    let mut d = Device::new();
    d.id = "node\n[Peer]\nAllowedIPs = 0.0.0.0/0".into();
    assert_eq!(join(&f, &d).await.status(), 400);
}
