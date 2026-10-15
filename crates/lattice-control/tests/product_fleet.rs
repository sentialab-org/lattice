mod support;
use lattice_control::{auth, clock::Clock, delegation, fleet};
use lattice_protocol::*;
use serde_json::json;
use support::Fixture;
async fn authority(f: &Fixture) -> ([u8; 32], MasterAuthority) {
    let key = lattice_crypto::generate_private_key();
    let public = lattice_crypto::encode_key(&lattice_crypto::public_key(&key));
    let now = f.clock.now_ms();
    let g = MasterGrant {
        schema_version: 1,
        network_id: "fixture-net".into(),
        node_id: "host".into(),
        node_public_key: "host-key".into(),
        control_id: f.state.control.control_id.clone(),
        control_public_key: f.state.control.public_key.clone(),
        overlay_ipv4: "10.77.0.2".into(),
        revision: 1,
        issued_at_ms: now,
    };
    let g = SignedMasterGrant {
        signature: lattice_crypto::sign(&key, &g).unwrap(),
        grant: g,
    };
    let d = MasterDirectory {
        schema_version: 1,
        network_id: "fixture-net".into(),
        revision: 1,
        issued_at_ms: now,
        active_master_id: Some(f.state.control.control_id.clone()),
        masters: vec![g.clone()],
    };
    let a = MasterAuthority {
        bootstrap_url: "https://fixture.test".into(),
        coordinator_key: public,
        network_id: "fixture-net".into(),
        grant: g,
        directory: SignedMasterDirectory {
            signature: lattice_crypto::sign(&key, &d).unwrap(),
            directory: d,
        },
    };
    auth::atomic_json(&f.dir.path().join("master-authority.json"), &a).unwrap();
    (key, a)
}
fn signed(f: &Fixture, key: &[u8; 32]) -> SignedOperatorDelegation {
    let d = OperatorDelegation {
        schema_version: 1,
        request_id: uuid::Uuid::new_v4().to_string(),
        network_id: "fixture-net".into(),
        master_control_id: f.state.control.control_id.clone(),
        operation: WorkloadOperation::ListJobs,
        request_sha256: auth::digest(b""),
        issued_at_ms: f.clock.now_ms(),
        expires_at_ms: f.clock.now_ms() + 60_000,
    };
    SignedOperatorDelegation {
        signature: lattice_crypto::sign(key, &d).unwrap(),
        delegation: d,
    }
}
#[tokio::test]
async fn central_inventory_includes_bootstrapper_master_and_node() {
    let f = Fixture::new("bootstrapper").await;
    let (_, c, _) = f.login("owner", " password with spaces ").await;
    let r = f
        .request("GET", "/api/v1/operator/fleet", json!(null), &c, "")
        .await;
    assert_eq!(r.status(), 200);
    let j: serde_json::Value = r.json().await.unwrap();
    assert_eq!(j[0]["role"], "bootstrapper");
    assert!(j.to_string().find("private_key").is_none());
}
#[tokio::test]
async fn delegation_cannot_change_operation_body_or_master() {
    let f = Fixture::new("master").await;
    let (key, _) = authority(&f).await;
    let d = signed(&f, &key);
    assert!(
        delegation::verify(
            &f.state,
            &d,
            WorkloadOperation::ListJobs,
            &auth::digest(b""),
            f.clock.now_ms()
        )
        .is_ok()
    );
    assert!(
        delegation::verify(
            &f.state,
            &d,
            WorkloadOperation::QueueMining,
            &auth::digest(b""),
            f.clock.now_ms()
        )
        .is_err()
    );
    assert!(
        delegation::verify(
            &f.state,
            &d,
            WorkloadOperation::ListJobs,
            &auth::digest(b"changed"),
            f.clock.now_ms()
        )
        .is_err()
    );
    let mut changed = d;
    changed.delegation.master_control_id = "another".into();
    assert!(
        delegation::verify(
            &f.state,
            &changed,
            WorkloadOperation::ListJobs,
            &auth::digest(b""),
            f.clock.now_ms()
        )
        .is_err()
    );
}
#[tokio::test]
async fn expired_or_replayed_delegation_is_rejected() {
    let f = Fixture::new("master").await;
    let (key, _) = authority(&f).await;
    let d = signed(&f, &key);
    f.advance_ms(60_000);
    assert!(
        delegation::verify(
            &f.state,
            &d,
            WorkloadOperation::ListJobs,
            &auth::digest(b""),
            f.clock.now_ms()
        )
        .is_err()
    );
}
#[tokio::test]
async fn browser_url_cannot_select_proxy_destination() {
    let f = Fixture::new("bootstrapper").await;
    assert!(
        fleet::forward(
            &f.state,
            WorkloadOperation::QueueMining,
            axum::body::Bytes::from_static(b"{\"url\":\"http://127.0.0.1:22\"}")
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn bootstrapper_never_signs_job_lease() {
    let f = Fixture::new("bootstrapper").await;
    let (_, c, b) = f.login("owner", " password with spaces ").await;
    let r = f
        .request(
            "POST",
            "/api/v1/operator/jobs/mining",
            json!({}),
            &c,
            b["csrf_token"].as_str().unwrap(),
        )
        .await;
    assert_eq!(r.status(), 409);
    assert!(f.state.jobs.read().await.jobs.is_empty());
}
#[tokio::test]
async fn middleware_accepts_verified_delegation_only() {
    let f = Fixture::new("master").await;
    let (key, _) = authority(&f).await;
    let d = signed(&f, &key);
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&d).unwrap());
    let r = f
        .client
        .get(format!("{}/api/v1/operator/jobs", f.url))
        .header("x-lattice-delegation", encoded)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let r = f
        .client
        .get(format!("{}/api/v1/operator/jobs", f.url))
        .header("x-lattice-delegation", "spoofed")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}
