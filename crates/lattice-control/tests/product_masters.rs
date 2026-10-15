mod support;
use lattice_control::{clock::Clock, masters, network};
use lattice_protocol::*;
use support::{Device, Fixture};
async fn joined(f: &Fixture, d: &Device) {
    let _ = lattice_control::onboarding::public_join(
        axum::extract::State(f.state.clone()),
        axum::Json(d.join(f.clock.now_ms())),
    )
    .await
    .unwrap();
    let mut n = f.state.network.write().await;
    network::ensure_public_allocation(
        &mut n,
        &d.id,
        &lattice_crypto::encode_wireguard_key(&lattice_crypto::generate_wireguard_keypair().1),
        f.clock.now_ms(),
    )
    .unwrap();
}
fn request(d: &Device, c: &Device, token: &str, now: u64) -> MasterActivationRequest {
    let claim = MasterActivationClaim {
        schema_version: PRODUCT_SCHEMA_VERSION,
        request_id: uuid::Uuid::new_v4().to_string(),
        node_id: d.id.clone(),
        control_id: c.id.clone(),
        control_public_key: c.public.clone(),
        issued_at_ms: now,
    };
    MasterActivationRequest {
        node_signature: lattice_crypto::sign(&d.private, &claim).unwrap(),
        control_signature: lattice_crypto::sign(&c.private, &claim).unwrap(),
        activation_token: token.into(),
        claim,
    }
}
#[tokio::test]
async fn activation_proves_both_keys() {
    let f = Fixture::new("bootstrapper").await;
    let d = Device::new();
    let c = Device::new();
    joined(&f, &d).await;
    let t = f
        .state
        .master_tokens
        .create("master", f.clock.now_ms())
        .await
        .unwrap();
    let r = request(&d, &c, &t.activation_token, f.clock.now_ms());
    let mut wrong = r.clone();
    wrong.node_signature = lattice_crypto::sign(&c.private, &r.claim).unwrap();
    assert!(
        masters::activate(&f.state, wrong, f.clock.now_ms())
            .await
            .is_err()
    );
    let mut wrong = r.clone();
    wrong.control_signature = lattice_crypto::sign(&d.private, &r.claim).unwrap();
    assert!(
        masters::activate(&f.state, wrong, f.clock.now_ms())
            .await
            .is_err()
    );
    assert!(
        masters::activate(&f.state, r, f.clock.now_ms())
            .await
            .is_ok()
    );
}
#[tokio::test]
async fn activation_retry_after_lost_response_returns_same_grant() {
    let f = Fixture::new("bootstrapper").await;
    let d = Device::new();
    let c = Device::new();
    joined(&f, &d).await;
    let t = f
        .state
        .master_tokens
        .create("master", f.clock.now_ms())
        .await
        .unwrap();
    let g = masters::activate(
        &f.state,
        request(&d, &c, &t.activation_token, f.clock.now_ms()),
        f.clock.now_ms(),
    )
    .await
    .unwrap();
    let mut state = f.state.clone();
    state.master_tokens =
        std::sync::Arc::new(lattice_control::tokens::TokenStore::load(f.dir.path()).unwrap());
    let retry = masters::activate(
        &state,
        request(&d, &c, "", f.clock.now_ms()),
        f.clock.now_ms(),
    )
    .await
    .unwrap();
    assert_eq!(g, retry);
}
#[tokio::test]
async fn another_device_cannot_redeem_consumed_token() {
    let f = Fixture::new("bootstrapper").await;
    let a = Device::new();
    let b = Device::new();
    let c = Device::new();
    joined(&f, &a).await;
    joined(&f, &b).await;
    let t = f
        .state
        .master_tokens
        .create("master", f.clock.now_ms())
        .await
        .unwrap();
    masters::activate(
        &f.state,
        request(&a, &c, &t.activation_token, f.clock.now_ms()),
        f.clock.now_ms(),
    )
    .await
    .unwrap();
    assert!(
        masters::activate(
            &f.state,
            request(&b, &c, &t.activation_token, f.clock.now_ms()),
            f.clock.now_ms()
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn activation_does_not_create_second_node_or_ip() {
    let f = Fixture::new("bootstrapper").await;
    let d = Device::new();
    joined(&f, &d).await;
    let t = f
        .state
        .master_tokens
        .create("master", f.clock.now_ms())
        .await
        .unwrap();
    masters::activate(
        &f.state,
        request(&d, &Device::new(), &t.activation_token, f.clock.now_ms()),
        f.clock.now_ms(),
    )
    .await
    .unwrap();
    assert_eq!(f.state.registry.read().await.nodes.len(), 1);
    assert_eq!(f.state.network.read().await.allocations.len(), 1);
}
#[tokio::test]
async fn revoked_master_disappears_from_discovery() {
    let f = Fixture::new("bootstrapper").await;
    let d = Device::new();
    let c = Device::new();
    joined(&f, &d).await;
    let t = f
        .state
        .master_tokens
        .create("master", f.clock.now_ms())
        .await
        .unwrap();
    masters::activate(
        &f.state,
        request(&d, &c, &t.activation_token, f.clock.now_ms()),
        f.clock.now_ms(),
    )
    .await
    .unwrap();
    assert_eq!(
        masters::directory(&f.state, f.clock.now_ms())
            .await
            .unwrap()
            .directory
            .masters
            .len(),
        1
    );
    f.state.master_tokens.revoke_master(&c.id).await.unwrap();
    let dir = masters::directory(&f.state, f.clock.now_ms())
        .await
        .unwrap();
    assert!(dir.directory.masters.is_empty());
    assert!(dir.directory.active_master_id.is_none());
    assert!(f.state.network.read().await.allocations[&d.id].enabled);
}
#[tokio::test]
async fn workload_admission_rejects_wrong_network_or_expired_membership() {
    let f = Fixture::new("bootstrapper").await;
    let d = Device::new();
    joined(&f, &d).await;
    let m = lattice_control::onboarding::membership_for(&f.state, &d.id, f.clock.now_ms())
        .await
        .unwrap();
    let net = f.state.network.read().await.network_id.clone();
    assert!(
        masters::verify_membership(&m, &f.state.control.public_key, &net, f.clock.now_ms()).is_ok()
    );
    assert!(
        masters::verify_membership(&m, &f.state.control.public_key, "wrong", f.clock.now_ms())
            .is_err()
    );
    assert!(
        masters::verify_membership(
            &m,
            &f.state.control.public_key,
            &net,
            m.membership.expires_at_ms
        )
        .is_err()
    );
}
#[tokio::test]
async fn unactivated_master_cannot_issue_workload_authority() {
    let f = Fixture::new("master").await;
    let mut s = f.state.clone();
    s.enrollment_token = std::sync::Arc::new(String::new());
    assert!(masters::require_workload_authority(&s).is_err());
}
#[tokio::test]
async fn master_directory_management_requires_account() {
    let f = Fixture::new("bootstrapper").await;
    assert_eq!(
        f.request(
            "GET",
            "/api/v1/operator/masters",
            serde_json::json!(null),
            "",
            ""
        )
        .await
        .status(),
        401
    );
    let (_, c, _) = f.login("owner", " password with spaces ").await;
    assert_eq!(
        f.request(
            "GET",
            "/api/v1/operator/masters",
            serde_json::json!(null),
            &c,
            ""
        )
        .await
        .status(),
        200
    );
}
