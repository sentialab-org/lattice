#![cfg(unix)]
mod support;
use lattice_protocol::*;
use support::{Device, Fixture};
#[tokio::test]
async fn private_host_provisioning_requires_a_service_credential_and_preserves_the_gateway_identity()
 {
    use lattice_control::clock::Clock;
    let root = Fixture::new("supervisor").await;
    let node = Device::new();
    let token = "1".repeat(64);
    lattice_control::auth::atomic_json(&root.dir.path().join("module-service-token.json"), &token)
        .unwrap();
    let transport = root
        .state
        .network
        .read()
        .await
        .gateway_wireguard_public_key
        .clone();
    let old = std::fs::read(root.dir.path().join("gateway_wireguard.json")).unwrap();
    let (shutdown, watch) = tokio::sync::watch::channel(false);
    let app = lattice_control::host_provision::router(
        lattice_control::build_router(root.state.clone()),
        root.state.clone(),
    );
    let directory = root.dir.path().to_path_buf();
    let task = tokio::spawn(async move {
        lattice_control::private_backend::serve(app, &directory, watch)
            .await
            .unwrap();
    });
    for _ in 0..100 {
        if root.dir.path().join("module-http.sock").exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let client = reqwest::Client::builder()
        .unix_socket(root.dir.path().join("module-http.sock"))
        .build()
        .unwrap();
    let claim = LocalHostProvisionClaim {
        schema_version: AUTHORITY_VERSION,
        join: node.join(root.clock.now_ms()),
        wireguard_public_key: transport.clone(),
        interface_name: root.state.network.read().await.interface_name.clone(),
        adopt_gateway: true,
        forwarding_limit_bps: Some(8_000_000),
    };
    let signed = LocalHostProvisionRequest {
        signature: lattice_crypto::sign_domain(&node.private, LOCAL_HOST_DOMAIN, &claim).unwrap(),
        claim,
    };
    let denied = client
        .post("http://localhost/api/v2/local/host")
        .json(&signed)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 401);
    assert!(root.state.registry.read().await.nodes.is_empty());
    let public = root
        .client
        .post(format!("{}/api/v2/local/host", root.url))
        .header("x-lattice-module-service", &token)
        .json(&signed)
        .send()
        .await
        .unwrap();
    assert_eq!(
        public.status(),
        404,
        "the public Control router must not expose host provisioning"
    );
    let response = client
        .post("http://localhost/api/v2/local/host")
        .header("x-lattice-module-service", &token)
        .json(&signed)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let text = response.text().await.unwrap();
    assert!(!text.contains("private_key"));
    let result: LocalHostProvisionResponse = serde_json::from_str(&text).unwrap();
    let intent = result.gateway_intent.unwrap();
    assert_eq!(intent.intent.address, "10.77.0.1/16");
    assert_eq!(intent.intent.transport_public_key, transport);
    assert_eq!(result.join.receipt.node_id, node.id);
    assert_eq!(
        root.state.network.read().await.allocations[&node.id].virtual_ipv4,
        "10.77.0.1/32"
    );
    assert_eq!(
        std::fs::read(root.dir.path().join("gateway_wireguard.json")).unwrap(),
        old
    );
    let narrowed = lattice_control::authority::issue_relay(
        &root.state,
        lattice_control::authority::RelayGrantRequest {
            node_id: node.id.clone(),
            endpoint: "127.0.0.1:51820".into(),
            bandwidth_limit_bps: 4_000_000,
        },
    )
    .await
    .unwrap();
    let response = client
        .post("http://localhost/api/v2/local/host")
        .header("x-lattice-module-service", &token)
        .json(&signed)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let kept: LocalHostProvisionResponse = response.json().await.unwrap();
    assert_eq!(
        kept.gateway_intent.unwrap().certificate,
        narrowed,
        "retained service access cannot widen a narrowed Relay grant"
    );
    root.state
        .master_tokens
        .update_authority(|store| {
            store.offline.revocations.insert(
                narrowed.certificate.subject.revocation_key(),
                narrowed.certificate.revision,
            );
            Ok(())
        })
        .await
        .unwrap();
    let denied = client
        .post("http://localhost/api/v2/local/host")
        .header("x-lattice-module-service", &token)
        .json(&signed)
        .send()
        .await
        .unwrap();
    assert_eq!(
        denied.status(),
        401,
        "retained service access cannot reauthorize a revoked Relay"
    );
    shutdown.send(true).unwrap();
    task.await.unwrap();
}
