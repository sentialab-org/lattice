mod support;
use lattice_control::{auth, clock::Clock, delegation, fleet};
use lattice_protocol::*;
use serde_json::json;
use support::Fixture;
#[tokio::test]
async fn central_inventory_merges_signed_master_health_and_rejects_spoofed_nodes() {
    use support::Device;
    let f = Fixture::new("bootstrapper").await;
    let node = Device::new();
    let host = Device::new();
    let control = Device::new();
    for d in [&node, &host] {
        let _ = lattice_control::onboarding::public_join(
            axum::extract::State(f.state.clone()),
            axum::Json(d.join(f.clock.now_ms())),
        )
        .await
        .unwrap();
    }
    {
        let mut n = f.state.network.write().await;
        lattice_control::network::ensure_public_allocation(
            &mut n,
            &host.id,
            &lattice_crypto::encode_wireguard_key(&lattice_crypto::generate_wireguard_keypair().1),
            f.clock.now_ms(),
        )
        .unwrap();
    }
    let t = f
        .state
        .master_tokens
        .create("master", f.clock.now_ms())
        .await
        .unwrap();
    let c = MasterActivationClaim {
        schema_version: 1,
        request_id: uuid::Uuid::new_v4().to_string(),
        node_id: host.id.clone(),
        control_id: control.id.clone(),
        control_public_key: control.public.clone(),
        issued_at_ms: f.clock.now_ms(),
    };
    let g = lattice_control::masters::activate(
        &f.state,
        MasterActivationRequest {
            node_signature: lattice_crypto::sign(&host.private, &c).unwrap(),
            control_signature: lattice_crypto::sign(&control.private, &c).unwrap(),
            claim: c,
            activation_token: t.activation_token,
        },
        f.clock.now_ms(),
    )
    .await
    .unwrap();
    f.state
        .onboarding
        .record_choice(
            &node.id,
            &MasterChoice {
                control_id: Some(control.id.clone()),
                revision: 1,
            },
        )
        .await
        .unwrap();
    let inventory= fleet::WorkloadInventory{network_id:g.grant.network_id,control_id:control.id,issued_at_ms:f.clock.now_ms(),nodes:vec![serde_json::from_value(json!({"node_id":node.id,"public_key":node.public,"node_name":"worker","platform":"linux","architecture":"x86_64","client_version":"0.2.0","last_seen_ms":f.clock.now_ms(),"online_until_ms":f.clock.now_ms()+30000,"health":{"runtime_state":"idle","cpu_usage_percent":4.0,"memory_used_mb":100,"active_jobs":0},"effective_policy":null,"capabilities":{"os":"Linux","kernel":"fixture","architecture":"aarch64","cpu_model":"CPU fixture","logical_cores":8,"physical_cores":4,"memory_total_mb":16384,"gpus":[]}})).unwrap()]};
    let mut snapshot = fleet::SignedWorkloadInventory {
        signature: lattice_crypto::sign(&control.private, &inventory).unwrap(),
        inventory,
    };
    let rows = fleet::merge_inventory(&f.state, Some(&snapshot)).await;
    let n = rows.iter().find(|n| n["node_id"] == node.id).unwrap();
    assert_eq!(n["capabilities"]["logical_cores"], 8);
    assert_eq!(n["workload_status"], "current");
    assert_eq!(n["online"], true);
    snapshot.inventory.nodes[0].public_key = "other-key".into();
    snapshot.signature = lattice_crypto::sign(&control.private, &snapshot.inventory).unwrap();
    let rows = fleet::merge_inventory(&f.state, Some(&snapshot)).await;
    let n = rows.iter().find(|n| n["node_id"] == node.id).unwrap();
    assert!(n["capabilities"].is_null());
    assert_eq!(n["workload_status"], "not_attached");
    snapshot.signature = "spoofed".into();
    let rows = fleet::merge_inventory(&f.state, Some(&snapshot)).await;
    assert!(
        rows.iter()
            .filter(|n| n["node_id"] == node.id)
            .all(|n| n["workload_status"] == "unavailable")
    );
}
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
#[tokio::test]
async fn master_endpoint_comes_from_its_signed_overlay_grant() {
    let f = Fixture::new("master").await;
    let (_, mut a) = authority(&f).await;
    let endpoint = lattice_control::masters::endpoint_from_grant(&f.state.control, &a).unwrap();
    assert_eq!(
        endpoint,
        ("10.77.0.2:7443".into(), "http://10.77.0.2:7443".into())
    );
    a.grant.grant.overlay_ipv4 = "127.0.0.1".into();
    assert!(lattice_control::masters::endpoint_from_grant(&f.state.control, &a).is_err());
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
    assert!(!f.dir.path().join("delegation-results").exists());
    let r = f
        .client
        .get(format!("{}/api/v1/operator/jobs", f.url))
        .header("x-lattice-delegation", "spoofed")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}
#[tokio::test]
async fn delegated_inventory_response_is_signed_by_selected_master() {
    let f = Fixture::new("master").await;
    let (key, _) = authority(&f).await;
    let mut d = signed(&f, &key);
    d.delegation.operation = WorkloadOperation::FleetInventory;
    d.signature = lattice_crypto::sign(&key, &d.delegation).unwrap();
    use base64::Engine;
    let r = f
        .client
        .get(format!("{}/api/v1/master/fleet", f.url))
        .header(
            "x-lattice-delegation",
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&d).unwrap()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let response: fleet::SignedWorkloadInventory = r.json().await.unwrap();
    lattice_crypto::verify(
        &f.state.control.public_key,
        &response.signature,
        &response.inventory,
    )
    .unwrap();
    assert_eq!(response.inventory.control_id, f.state.control.control_id);
}
