use super::*;
use lattice_crypto::{
    authority::issue_certificate, authority_cache::AuthorityCache, encode_key, public_key,
};
use std::collections::BTreeSet;

fn key(seed: u8) -> String {
    encode_key(&public_key(&[seed; 32]))
}
fn grant() -> SignedCertificate {
    issue_certificate(
        &[1; 32],
        "network-test",
        CertificateSubject::Master {
            node_id: "node-host".into(),
            node_public_key: key(2),
            control_id: "control-host".into(),
            control_public_key: key(3),
            overlay_ipv4: "10.77.0.4".into(),
        },
        BTreeSet::from([CommandScope::Workloads]),
        1,
        1000,
    )
    .unwrap()
}
#[test]
fn enabling_a_module_requires_opt_in_and_authority_for_this_device() {
    let mut cache = AuthorityCache::new(key(1), "network-test".into());
    cache
        .ingest(
            &AuthorityContext {
                master_certificate: Some(grant()),
                ..Default::default()
            },
            1000,
        )
        .unwrap();
    assert!(validate_grant(ModuleKind::Master, "node-host", &key(2), &cache, 1000).is_ok());
    assert!(validate_grant(ModuleKind::Master, "other-device", &key(2), &cache, 1000).is_err());
    assert!(validate_grant(ModuleKind::Relay, "node-host", &key(2), &cache, 1000).is_err());
    let mut manager = ModuleManager::default();
    assert!(
        manager
            .statuses()
            .iter()
            .all(|s| !s.enabled && s.state == ModuleState::Disabled)
    );
    manager.set_enabled(
        ModuleKind::Master,
        Some(grant().certificate.certificate_id),
        None,
        false,
    );
    assert!(
        manager
            .statuses()
            .iter()
            .find(|s| s.kind == ModuleKind::Master)
            .unwrap()
            .enabled
    );
    assert!(
        !manager
            .statuses()
            .iter()
            .find(|s| s.kind == ModuleKind::Relay)
            .unwrap()
            .enabled
    );
}
#[test]
fn module_opt_in_survives_restart_but_process_ids_do_not() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("modules.json");
    let mut manager = ModuleManager::default();
    manager.set_enabled(ModuleKind::Master, Some("certificate".into()), None, false);
    manager.save(&path).unwrap();
    let restored = ModuleManager::load(&path).unwrap();
    let master = restored
        .statuses()
        .into_iter()
        .find(|s| s.kind == ModuleKind::Master)
        .unwrap();
    assert!(master.enabled);
    assert_eq!(master.state, ModuleState::Verifying);
    assert!(master.process_id.is_none());
    assert!(
        restored
            .statuses()
            .iter()
            .filter(|s| s.kind != ModuleKind::Master)
            .all(|s| !s.enabled)
    );
}
#[test]
fn optional_module_failure_keeps_other_modules_enabled() {
    let mut manager = ModuleManager::default();
    manager.set_enabled(ModuleKind::Master, None, None, false);
    manager.set_enabled(ModuleKind::Relay, None, None, false);
    manager.fail(
        ModuleKind::Master,
        ModuleState::Revoked,
        "certificate_revoked",
    );
    assert!(
        manager
            .statuses()
            .iter()
            .find(|s| s.kind == ModuleKind::Relay)
            .unwrap()
            .enabled
    );
    assert_eq!(
        manager
            .statuses()
            .iter()
            .find(|s| s.kind == ModuleKind::Master)
            .unwrap()
            .state,
        ModuleState::Revoked
    );
}
#[tokio::test]
async fn ordinary_ipc_cannot_provision_supervisor_authority() {
    let dir = tempfile::tempdir().unwrap();
    let node = crate::load_state_at(dir.path().join("node.json"))
        .await
        .unwrap();
    let original = node.identity.read().await.identity().clone();
    let response = crate::dispatch(
        IpcRequest::EnableModule {
            activation: ModuleActivation {
                kind: ModuleKind::Supervisor,
                certificate: None,
                authority_data_dir: Some(dir.path().display().to_string()),
                adopt_gateway: false,
                forwarding_limit_bps: None,
                activation_token: None,
            },
        },
        &node,
    )
    .await;
    assert!(matches!(response,IpcResponse::Error{message} if message.contains("administrator")));
    assert_eq!(node.identity.read().await.identity(), &original);
}

#[test]
fn private_backend_health_does_not_hide_an_unavailable_public_ingress() {
    let mut manager = ModuleManager::default();
    manager.set_enabled(ModuleKind::Master, None, None, false);
    manager.status.insert(
        ModuleKind::Master,
        ModuleStatus {
            kind: ModuleKind::Master,
            enabled: true,
            state: ModuleState::Active,
            process_id: Some(123),
            certificate_id: None,
            error_code: None,
        },
    );
    let status = manager
        .statuses()
        .into_iter()
        .find(|s| s.kind == ModuleKind::Master)
        .unwrap();
    assert_eq!(status.state, ModuleState::Starting);
    assert_eq!(status.error_code.as_deref(), Some("ingress_starting"));
    manager.ingress_error = Some("ingress_bind_failed".into());
    assert_eq!(
        manager.statuses()[0].error_code.as_deref(),
        Some("ingress_bind_failed")
    );
    manager.ingress_ready = true;
    manager.ingress_error = None;
    assert_eq!(manager.statuses()[0].state, ModuleState::Active);
}

#[cfg(unix)]
#[tokio::test]
async fn local_master_admin_works_without_supervisor_and_stops_when_owner_disables_network() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let f =
        crate::setup::review_regressions::fixture_with_network("10.77.0.0/16", "10.77.0.1").await;
    crate::setup::review_regressions::reconcile_ready(&f)
        .await
        .unwrap();
    f.server.abort();
    let data = default_master_data(&f.node);
    let master = lattice_control::load_state(
        &data,
        String::new(),
        Some(Arc::new("private-test-operator".into())),
        "http://10.77.0.2:7443".into(),
        "master".into(),
    )
    .await
    .unwrap();
    crate::setup::write_private(
        &data.join("module-operator-token.json"),
        &"private-test-operator",
    )
    .unwrap();
    let (shutdown, watch) = tokio::sync::watch::channel(false);
    let backend_data = data.clone();
    let task = tokio::spawn(async move {
        lattice_control::private_backend::serve(
            lattice_control::build_router(master),
            &backend_data,
            watch,
        )
        .await
        .unwrap();
    });
    for _ in 0..100 {
        if data.join("module-http.sock").exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    enable(
        &f.node,
        ModuleActivation {
            kind: ModuleKind::Master,
            certificate: None,
            authority_data_dir: None,
            adopt_gateway: false,
            forwarding_limit_bps: None,
            activation_token: None,
        },
        false,
    )
    .await
    .unwrap();
    {
        let mut manager = f.node.modules.lock().await;
        manager.status.insert(
            ModuleKind::Master,
            ModuleStatus {
                kind: ModuleKind::Master,
                enabled: true,
                state: ModuleState::Active,
                process_id: None,
                certificate_id: None,
                error_code: None,
            },
        );
    }
    let request = LocalMasterRequest {
        operation: WorkloadOperation::ListJobs,
        body_base64: String::new(),
    };
    let reply = local_master(&f.node, request.clone()).await.unwrap();
    assert_eq!(
        reply.status, 200,
        "private operator administration must not contact the Supervisor"
    );
    let body = STANDARD.decode(reply.body_base64).unwrap();
    assert!(serde_json::from_slice::<serde_json::Value>(&body).is_ok());
    let mut limited = f
        .node
        .offline_authority
        .lock()
        .await
        .checked()
        .unwrap()
        .unwrap()
        .certificates()
        .find(|c| matches!(c.certificate.subject, CertificateSubject::Master { .. }))
        .unwrap()
        .clone();
    limited.certificate.revision += 1;
    limited.certificate.scopes = BTreeSet::from([CommandScope::Workloads]);
    limited.signature = lattice_crypto::sign_domain(
        &lattice_crypto::decode_key::<32>(&f.coordinator.control.private_key).unwrap(),
        CERTIFICATE_DOMAIN,
        &limited.certificate,
    )
    .unwrap();
    crate::trust_store::ingest(
        &f.node,
        &AuthorityContext {
            master_certificate: Some(limited),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let identity = f.node.identity.read().await.clone();
    synchronize_master_authority(
        &data,
        &identity,
        f.node
            .offline_authority
            .lock()
            .await
            .checked()
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(
        local_master(&f.node, request.clone()).await.is_err(),
        "local inventory requires Inventory scope, even with a valid Workloads grant"
    );
    assert_eq!(
        private_client(&data)
            .unwrap()
            .get("http://localhost/api/v1/operator/jobs")
            .bearer_auth("private-test-operator")
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "the private controller must enforce the same operation scope"
    );
    f.node.config.write().await.network.enabled = false;
    let denied = local_master(
        &f.node,
        LocalMasterRequest {
            operation: WorkloadOperation::QueueMining,
            body_base64: String::new(),
        },
    )
    .await;
    shutdown.send(true).unwrap();
    task.await.unwrap();
    assert!(
        denied.is_err(),
        "owner withdrawal must be checked before local operator effects, not only by the next background tick"
    );
}

#[tokio::test]
async fn imported_authority_reaches_private_master_without_a_live_supervisor() {
    let f = crate::setup::review_regressions::fixture().await;
    crate::setup::review_regressions::reconcile_ready(&f)
        .await
        .unwrap();
    f.server.abort();
    let data = default_master_data(&f.node);
    let identity = f.node.identity.read().await.clone();
    let mut snapshot = f
        .node
        .offline_authority
        .lock()
        .await
        .checked()
        .unwrap()
        .unwrap()
        .snapshot()
        .unwrap()
        .clone();
    snapshot.snapshot.revision += 1;
    snapshot
        .snapshot
        .revocations
        .insert("node/previous-worker".into(), 9);
    snapshot.signature = lattice_crypto::sign_domain(
        &lattice_crypto::decode_key::<32>(&f.coordinator.control.private_key).unwrap(),
        SNAPSHOT_DOMAIN,
        &snapshot.snapshot,
    )
    .unwrap();
    crate::trust_store::ingest(
        &f.node,
        &AuthorityContext {
            snapshot: Some(snapshot.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let store = f.node.offline_authority.lock().await;
    synchronize_master_authority(&data, &identity, store.checked().unwrap().unwrap()).unwrap();
    let saved: MasterAuthority =
        serde_json::from_slice(&std::fs::read(data.join("master-authority.json")).unwrap())
            .unwrap();
    assert_eq!(saved.authority.unwrap().snapshot, Some(snapshot));
}

#[cfg(unix)]
#[tokio::test]
async fn revocation_reaps_only_the_optional_master_and_preserves_base_node() {
    use std::os::unix::fs::PermissionsExt;
    let f =
        crate::setup::review_regressions::fixture_with_network("10.77.0.0/16", "10.77.0.1").await;
    crate::setup::review_regressions::reconcile_ready(&f)
        .await
        .unwrap();
    f.server.abort();
    let original = f.node.identity.read().await.identity().clone();
    let config = serde_json::to_value(&*f.node.config.read().await).unwrap();
    let choice = f.node.setup.lock().await.master_choice.clone();
    let bundle = tempfile::tempdir().unwrap();
    let body = b"#!/bin/sh\nexec sleep 100\n";
    std::fs::write(bundle.path().join("lattice-master"), body).unwrap();
    std::fs::set_permissions(
        bundle.path().join("lattice-master"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    crate::setup::write_private(
        &bundle.path().join("manifest.json"),
        &ReleaseBundleManifest {
            schema_version: 1,
            version: env!("CARGO_PKG_VERSION").into(),
            source_revision: "1".repeat(40),
            target: "linux-x86_64".into(),
            role: NodeRole::Master,
            files: vec![BundleFile {
                path: "lattice-master".into(),
                sha256: lattice_crypto::sha256_hex(body),
                size_bytes: body.len() as u64,
                executable: true,
            }],
        },
    )
    .unwrap();
    let child = process::VerifiedComponent::load(bundle.path(), ModuleKind::Master)
        .unwrap()
        .spawn(
            &default_master_data(&f.node),
            "https://supervisor-unreachable.invalid",
        )
        .unwrap();
    let pid = child.id().unwrap();
    {
        let mut manager = f.node.modules.lock().await;
        manager.set_enabled(ModuleKind::Master, None, None, false);
        manager.children.insert(ModuleKind::Master, child);
    }
    let mut snapshot = f
        .node
        .offline_authority
        .lock()
        .await
        .checked()
        .unwrap()
        .unwrap()
        .snapshot()
        .unwrap()
        .clone();
    let cert = snapshot
        .snapshot
        .certificates
        .iter()
        .find(|c| matches!(c.certificate.subject, CertificateSubject::Master { .. }))
        .unwrap();
    snapshot.snapshot.revocations.insert(
        cert.certificate.subject.revocation_key(),
        cert.certificate.revision,
    );
    snapshot.snapshot.revision += 1;
    snapshot.signature = lattice_crypto::sign_domain(
        &lattice_crypto::decode_key::<32>(&f.coordinator.control.private_key).unwrap(),
        SNAPSHOT_DOMAIN,
        &snapshot.snapshot,
    )
    .unwrap();
    crate::trust_store::ingest(
        &f.node,
        &AuthorityContext {
            snapshot: Some(snapshot),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    reconcile(&f.node).await;
    assert_eq!(
        unsafe { libc::kill(pid as i32, 0) },
        -1,
        "revoked module child must be reaped"
    );
    assert_eq!(f.node.identity.read().await.identity(), &original);
    assert_eq!(
        serde_json::to_value(&*f.node.config.read().await).unwrap(),
        config
    );
    assert_eq!(f.node.setup.lock().await.master_choice, choice);
    assert!(
        !f.node
            .modules
            .lock()
            .await
            .children
            .contains_key(&ModuleKind::Master)
    );
    assert_eq!(
        f.node.modules.lock().await.statuses()[0].state,
        ModuleState::Revoked
    );
}

#[cfg(unix)]
#[test]
fn supervisor_preflight_does_not_read_authority_private_keys_or_password_hashes() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["control-identity.json", "account.json", "network.json"] {
        let path = directory.path().join(name);
        std::fs::write(&path, b"authority service validates and owns these bytes").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    assert_eq!(
        authority_directory(directory.path().to_str().unwrap()).unwrap(),
        std::fs::canonicalize(directory.path()).unwrap()
    );
}

#[test]
fn relay_owner_budget_survives_restart_and_is_not_widened_by_a_new_grant() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("modules.json");
    let mut manager = ModuleManager::default();
    manager.set_enabled(ModuleKind::Relay, None, None, false);
    manager.set_forwarding_budget(8_000_000, None).unwrap();
    manager.save(&path).unwrap();
    let mut restored = ModuleManager::load(&path).unwrap();
    assert_eq!(restored.forwarding_budget(), Some(8_000_000));
    restored.set_forwarding_budget(80_000_000, None).unwrap();
    assert_eq!(restored.forwarding_budget(), Some(8_000_000));
    restored
        .set_forwarding_budget(80_000_000, Some(4_000_000))
        .unwrap();
    assert_eq!(restored.forwarding_budget(), Some(4_000_000));
    assert!(restored.set_forwarding_budget(80_000_000, Some(0)).is_err());
    assert_eq!(restored.forwarding_budget(), Some(4_000_000));
}
