mod support;
use lattice_control::{clock::Clock, masters, network};
use lattice_crypto::{
    authority::{verify_certificate, verify_snapshot},
    sign,
};
use lattice_protocol::*;
use support::{Device, Fixture};

async fn join(f: &Fixture, d: &Device) -> PublicJoinResponse {
    let response = f
        .client
        .post(format!("{}/api/v1/bootstrap/join", f.url))
        .json(&d.join(f.clock.now_ms()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let response: PublicJoinResponse = response.json().await.unwrap();
    let transport =
        lattice_crypto::encode_wireguard_key(&lattice_crypto::generate_wireguard_keypair().1);
    let mut net = f.state.network.write().await;
    network::ensure_public_allocation(&mut net, &d.id, &transport, f.clock.now_ms()).unwrap();
    response
}
async fn activate(f: &Fixture, d: &Device, c: &Device) -> SignedMasterGrant {
    let token = f
        .state
        .master_tokens
        .create("owner", f.clock.now_ms())
        .await
        .unwrap();
    let claim = MasterActivationClaim {
        schema_version: 1,
        request_id: uuid::Uuid::new_v4().to_string(),
        node_id: d.id.clone(),
        control_id: c.id.clone(),
        control_public_key: c.public.clone(),
        issued_at_ms: f.clock.now_ms(),
    };
    masters::activate(
        &f.state,
        MasterActivationRequest {
            node_signature: sign(&d.private, &claim).unwrap(),
            control_signature: sign(&c.private, &claim).unwrap(),
            activation_token: token.activation_token,
            claim,
        },
        f.clock.now_ms(),
    )
    .await
    .unwrap()
}
async fn snapshot(f: &Fixture) -> SignedAuthoritySnapshot {
    let response = f
        .client
        .get(format!("{}/api/v2/authority", f.url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        200,
        "signed authority must be distributable without a dashboard session"
    );
    response.json().await.unwrap()
}
#[tokio::test]
async fn certified_master_admits_new_workload_offline_after_legacy_membership_expires() {
    let root = Fixture::new("supervisor").await;
    root.state.network.write().await.network_id = "fixture-custom-network".into();
    let host = Device::new();
    let control = Device::new();
    let worker = Device::new();
    join(&root, &host).await;
    let membership = join(&root, &worker)
        .await
        .authority
        .unwrap()
        .membership_certificate
        .unwrap();
    let grant = activate(&root, &host, &control).await;
    let update = snapshot(&root).await;
    let cert=update.snapshot.certificates.iter().find(|c|matches!(&c.certificate.subject,CertificateSubject::Master{control_id,..} if control_id==&control.id)).unwrap().clone();
    let master = Fixture::new("master").await;
    let mut state = master.state.clone();
    state.control = std::sync::Arc::new(lattice_control::ControlIdentity {
        control_id: control.id.clone(),
        public_key: control.public.clone(),
        private_key: lattice_crypto::encode_key(&control.private),
        created_at_ms: root.clock.now_ms(),
    });
    let authority = MasterAuthority {
        bootstrap_url: "https://supervisor-unreachable.invalid".into(),
        coordinator_key: root.state.control.public_key.clone(),
        network_id: grant.grant.network_id.clone(),
        grant,
        directory: masters::directory(&root.state, root.clock.now_ms())
            .await
            .unwrap(),
        authority: Some(AuthorityContext {
            snapshot: Some(update),
            master_certificate: Some(cert),
            membership_certificate: None,
            relay_certificate: None,
        }),
    };
    lattice_control::auth::atomic_json(
        &master.dir.path().join("master-authority.json"),
        &authority,
    )
    .unwrap();
    let (_, passive) = network::load_passive(master.dir.path()).await.unwrap();
    assert_eq!(
        passive.network_id, authority.network_id,
        "passive modules must derive their public network from the retained authority"
    );
    assert!(!master.dir.path().join("gateway_wireguard.json").exists());
    root.advance_ms(31_536_000_000);
    state.clock = root.clock.clone();
    assert!(
        masters::authority(&state, root.clock.now_ms()).is_ok(),
        "an offline Master must not renew the directory"
    );
    let receipt = HeartbeatReceipt {
        protocol_version: PROTOCOL_VERSION,
        request_id: "new-heartbeat".into(),
        node_id: worker.id.clone(),
        control_id: control.id.clone(),
        policy: (*state.policy).clone(),
        issued_at_ms: root.clock.now_ms(),
    };
    let mut response = HeartbeatResponse {
        signature: sign(&control.private, &receipt).unwrap(),
        receipt,
        job_lease: None,
        control_revision: None,
        authority: None,
        command_proof: None,
    };
    masters::certify_heartbeat(&state, 9, &mut response, root.clock.now_ms()).unwrap();
    let mut local = lattice_crypto::authority_cache::AuthorityCache::new(
        root.state.control.public_key.clone(),
        authority.network_id.clone(),
    );
    let digest = lattice_crypto::authority_cache::heartbeat_payload_hash(&response).unwrap();
    local
        .accept_command(
            response
                .command_proof
                .as_ref()
                .expect("offline heartbeat must carry the Supervisor certificate"),
            &lattice_crypto::authority_cache::CommandBinding {
                control_id: &control.id,
                control_public_key: &control.public,
                target_node_id: &worker.id,
                request_id: "new-heartbeat",
                sequence: 9,
                payload_sha256: &digest,
                scopes: &[CommandScope::Inventory, CommandScope::ResourceControl],
            },
            root.clock.now_ms(),
        )
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, lattice_control::build_router(state))
            .await
            .unwrap();
    });
    let claim = CertifiedWorkloadJoin {
        schema_version: AUTHORITY_VERSION,
        enrollment: worker.join(root.clock.now_ms()).claim.enrollment,
        membership_certificate: membership.clone(),
        master_control_id: control.id.clone(),
        owner_choice: MasterChoice {
            control_id: Some(control.id.clone()),
            revision: 1,
        },
    };
    let request = CertifiedWorkloadJoinRequest {
        signature: lattice_crypto::sign_domain(&worker.private, ADMISSION_DOMAIN, &claim).unwrap(),
        claim,
    };
    let response = master
        .client
        .post(format!("{url}/api/v2/master/join"))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        200,
        "durable membership must permit a new offline attachment"
    );
    let joined: CertifiedEnrollmentResponse = response.json().await.unwrap();
    assert_eq!(joined.enrollment.receipt.control_id, control.id);
    lattice_crypto::verify(
        &control.public,
        &joined.enrollment.signature,
        &joined.enrollment.receipt,
    )
    .unwrap();
    assert!(joined.authority.master_certificate.is_some());
    let replay = master
        .client
        .post(format!("{url}/api/v2/master/join"))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert!(!replay.status().is_success());
    let mut wrong = request.claim.clone();
    wrong.enrollment.request_id = uuid::Uuid::new_v4().to_string();
    wrong.owner_choice.control_id = Some("other-master".into());
    let wrong = CertifiedWorkloadJoinRequest {
        signature: lattice_crypto::sign_domain(&worker.private, ADMISSION_DOMAIN, &wrong).unwrap(),
        claim: wrong,
    };
    assert!(
        !master
            .client
            .post(format!("{url}/api/v2/master/join"))
            .json(&wrong)
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    task.abort();
}
#[tokio::test]
async fn public_join_issues_durable_membership_and_supervisor_role_serves_signed_authority() {
    let f = Fixture::new("supervisor").await;
    let d = Device::new();
    let joined = join(&f, &d).await;
    let context = joined
        .authority
        .expect("join must issue offline membership authority");
    let member = context.membership_certificate.unwrap();
    let c = verify_certificate(
        &f.state.control.public_key,
        &f.state.network.read().await.network_id,
        &member,
        f.clock.now_ms() + 31_536_000_000,
    )
    .unwrap()
    .clone();
    assert!(
        matches!(c.subject,CertificateSubject::Membership {node_id, node_public_key,..} if node_id==d.id && node_public_key==d.public)
    );
    assert!(c.expires_at_ms.is_none());
    let s = snapshot(&f).await;
    verify_snapshot(
        &f.state.control.public_key,
        &s.snapshot.network_id,
        &s,
        f.clock.now_ms() + 31_536_000_000,
    )
    .unwrap();
}
#[tokio::test]
async fn concurrent_master_announcements_have_stable_monotonic_revisions_and_signed_revocations() {
    let f = Fixture::new("bootstrapper").await;
    let a = Device::new();
    let b = Device::new();
    let ca = Device::new();
    let cb = Device::new();
    join(&f, &a).await;
    join(&f, &b).await;
    let first = snapshot(&f).await;
    activate(&f, &a, &ca).await;
    activate(&f, &b, &cb).await;
    let (one, two) = tokio::join!(snapshot(&f), snapshot(&f));
    assert_eq!(one, two);
    assert!(one.snapshot.revision > first.snapshot.revision);
    assert_eq!(one.snapshot.certificates.len(), 2);
    assert!(
        one.snapshot
            .certificates
            .iter()
            .all(|c| c.certificate.scopes.contains(&CommandScope::Workloads))
    );
    f.state.master_tokens.revoke_master(&ca.id).await.unwrap();
    let removed = snapshot(&f).await;
    assert!(removed.snapshot.revision > one.snapshot.revision);
    assert_eq!(
        removed
            .snapshot
            .revocations
            .get(&format!("master/{}", ca.id)),
        Some(&1)
    );
    assert!(removed.snapshot.certificates.iter().any(|c| matches!(&c.certificate.subject,CertificateSubject::Master {control_id,..} if control_id==&cb.id)));
    f.advance_ms(31_536_000_000);
    assert_eq!(
        removed,
        snapshot(&f).await,
        "passage of offline time does not renew or expire unchanged authority"
    );
}
#[tokio::test]
async fn relay_eligibility_requires_owner_account_and_revocation_does_not_revoke_membership() {
    let f = Fixture::new("bootstrapper").await;
    let d = Device::new();
    join(&f, &d).await;
    let body = serde_json::json!({"node_id":d.id,"endpoint":"relay.example.test:51820","bandwidth_limit_bps":10_000_000});
    assert_eq!(
        f.request(
            "POST",
            "/api/v2/operator/relays/grant",
            body.clone(),
            "",
            ""
        )
        .await
        .status(),
        401
    );
    let (_, cookie, session) = f.login("owner", " password with spaces ").await;
    let csrf = session["csrf_token"].as_str().unwrap();
    let response = f
        .request(
            "POST",
            "/api/v2/operator/relays/grant",
            body.clone(),
            &cookie,
            csrf,
        )
        .await;
    assert_eq!(response.status(), 200);
    let cert: SignedCertificate = response.json().await.unwrap();
    assert_eq!(
        cert.certificate.scopes,
        std::collections::BTreeSet::from([CommandScope::NetworkForwarding])
    );
    let response = f
        .request(
            "POST",
            "/api/v2/operator/relays/revoke",
            serde_json::json!({"node_id":d.id}),
            &cookie,
            csrf,
        )
        .await;
    assert_eq!(response.status(), 200);
    let revoked = snapshot(&f).await;
    assert_eq!(
        revoked.snapshot.revocations.get(&format!("relay/{}", d.id)),
        Some(&1)
    );
    assert!(
        lattice_control::onboarding::membership_for(&f.state, &d.id, f.clock.now_ms())
            .await
            .is_ok()
    );
    let response = f
        .request("POST", "/api/v2/operator/relays/grant", body, &cookie, csrf)
        .await;
    assert_eq!(response.status(), 200);
    let next: SignedCertificate = response.json().await.unwrap();
    assert_eq!(next.certificate.revision, 2);
    assert_eq!(next.certificate.subject.node_id(), d.id);
    assert_eq!(
        snapshot(&f)
            .await
            .snapshot
            .revocations
            .get(&format!("relay/{}", d.id)),
        Some(&1)
    );
}

#[tokio::test]
async fn explicit_master_reauthorization_preserves_device_keys_but_does_not_revive_old_certificate()
{
    let f = Fixture::new("bootstrapper").await;
    let d = Device::new();
    let c = Device::new();
    join(&f, &d).await;
    let old = activate(&f, &d, &c).await;
    f.state.master_tokens.revoke_master(&c.id).await.unwrap();
    let renewed = activate(&f, &d, &c).await;
    assert_eq!(renewed.grant.revision, old.grant.revision + 1);
    assert_eq!(renewed.grant.node_id, old.grant.node_id);
    assert_eq!(
        renewed.grant.control_public_key,
        old.grant.control_public_key
    );
    let announcement = snapshot(&f).await;
    assert_eq!(
        announcement
            .snapshot
            .revocations
            .get(&format!("master/{}", c.id)),
        Some(&old.grant.revision)
    );
    let new=announcement.snapshot.certificates.iter().find(|x|matches!(&x.certificate.subject,CertificateSubject::Master {control_id,..} if control_id==&c.id)).unwrap();
    assert_eq!(new.certificate.revision, 2);
}
#[tokio::test]
async fn revoke_then_reassign_without_intermediate_poll_keeps_revocation_across_restart() {
    let f = Fixture::new("bootstrapper").await;
    let d = Device::new();
    let c = Device::new();
    join(&f, &d).await;
    activate(&f, &d, &c).await;
    let (_, cookie, session) = f.login("owner", " password with spaces ").await;
    let csrf = session["csrf_token"].as_str().unwrap();
    assert_eq!(
        f.request(
            "POST",
            "/api/v1/operator/network/revoke",
            serde_json::json!({"node_id":d.id,"reason":"test"}),
            &cookie,
            csrf
        )
        .await
        .status(),
        200
    );
    assert_eq!(
        f.request(
            "POST",
            "/api/v1/operator/network/assign",
            serde_json::json!({"node_id":d.id}),
            &cookie,
            csrf
        )
        .await
        .status(),
        200
    );
    let announcement = snapshot(&f).await;
    assert!(
        announcement
            .snapshot
            .revocations
            .contains_key(&format!("node/{}", d.id))
    );
    assert_eq!(
        announcement
            .snapshot
            .revocations
            .get(&format!("master/{}", c.id)),
        Some(&1)
    );
    let mut restored = lattice_control::load_state(
        f.dir.path(),
        "legacy-enrollment".into(),
        None,
        "https://lattice.test".into(),
        "bootstrapper".into(),
    )
    .await
    .unwrap();
    restored.clock = f.clock.clone();
    let recovered = lattice_control::authority::publish_snapshot(&restored)
        .await
        .unwrap();
    assert_eq!(announcement, recovered);
}

#[tokio::test]
async fn supervisor_issues_only_signed_public_relay_intent_and_retains_monotonic_revisions() {
    let root = Fixture::new("supervisor").await;
    let relay = Device::new();
    let worker = Device::new();
    join(&root, &relay).await;
    join(&root, &worker).await;
    let grant = lattice_control::authority::issue_relay(
        &root.state,
        lattice_control::authority::RelayGrantRequest {
            node_id: relay.id.clone(),
            endpoint: "198.51.100.1:51820".into(),
            bandwidth_limit_bps: 8_000_000,
        },
    )
    .await
    .unwrap();
    let key_path = root.dir.path().join("gateway_wireguard.json");
    let original_key = std::fs::read(&key_path).unwrap();
    let first = network::reconcile::intent_for(&root.state, &relay.id)
        .await
        .unwrap()
        .unwrap();
    lattice_crypto::verify_domain(
        &root.state.control.public_key,
        NETWORK_INTENT_DOMAIN,
        &first.signature,
        &first.intent,
    )
    .unwrap();
    assert_eq!(first.certificate, grant);
    assert_eq!(first.intent.target_node_id, relay.id);
    assert_eq!(first.intent.revision, 1);
    assert!(first.intent.peers.iter().any(|p| p.node_id == worker.id));
    let same = network::reconcile::intent_for(&root.state, &relay.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(same, first);
    {
        let mut net = root.state.network.write().await;
        net.allocations.get_mut(&worker.id).unwrap().enabled = false;
    }
    let next = network::reconcile::intent_for(&root.state, &relay.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(next.intent.revision, 2);
    assert!(!next.intent.peers.iter().any(|p| p.node_id == worker.id));
    let mut restarted = root.state.clone();
    restarted.master_tokens =
        std::sync::Arc::new(lattice_control::tokens::TokenStore::load(root.dir.path()).unwrap());
    assert_eq!(
        network::reconcile::intent_for(&restarted, &relay.id)
            .await
            .unwrap()
            .unwrap(),
        next
    );
    assert_eq!(
        std::fs::read(&key_path).unwrap(),
        original_key,
        "issuing intent cannot alter the transport private key"
    );
    for filename in [
        "gateway-candidate.conf",
        "gateway-applied.conf",
        "gateway-owned.nft",
    ] {
        assert!(
            !root.dir.path().join(filename).exists(),
            "Supervisor must not produce privileged apply files"
        );
    }
}

#[tokio::test]
async fn a_master_load_is_passive_and_does_not_create_a_gateway_transport_identity() {
    let master = Fixture::new("master").await;
    assert!(!master.dir.path().join("gateway_wireguard.json").exists());
    assert!(
        network::reconcile::intent_for(&master.state, "any-node")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn selecting_an_independent_relay_uses_its_certified_key_and_overlay_address_together() {
    let root = Fixture::new("supervisor").await;
    let relay = Device::new();
    let worker = Device::new();
    join(&root, &relay).await;
    join(&root, &worker).await;
    let grant = lattice_control::authority::issue_relay(
        &root.state,
        lattice_control::authority::RelayGrantRequest {
            node_id: relay.id.clone(),
            endpoint: "198.51.100.7:51820".into(),
            bandwidth_limit_bps: 8_000_000,
        },
    )
    .await
    .unwrap();
    {
        let mut net = root.state.network.write().await;
        net.allocations
            .get_mut(&worker.id)
            .unwrap()
            .gateway_endpoint_override = Some("198.51.100.7:51820".into());
    }
    let claim = NetworkSyncClaim {
        protocol_version: NETWORK_PROTOCOL_VERSION,
        request_id: uuid::Uuid::new_v4().to_string(),
        node_id: worker.id.clone(),
        sequence: 1,
        last_applied_revision: 0,
        issued_at_ms: root.clock.now_ms(),
    };
    let response = root
        .client
        .post(format!("{}/api/v1/network/sync", root.url))
        .json(&NetworkSyncRequest {
            signature: sign(&worker.private, &claim).unwrap(),
            claim,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let result: NetworkSyncResponse = response.json().await.unwrap();
    let CertificateSubject::Relay {
        transport_public_key,
        overlay_ipv4,
        endpoint,
        ..
    } = grant.certificate.subject
    else {
        panic!("Relay required")
    };
    assert_eq!(
        result.desired_config.config.gateway_endpoint.as_deref(),
        Some(endpoint.as_str())
    );
    assert_eq!(
        result
            .desired_config
            .config
            .gateway_wireguard_public_key
            .as_deref(),
        Some(transport_public_key.as_str())
    );
    assert_eq!(
        result.desired_config.config.gateway_ipv4.as_deref(),
        Some(overlay_ipv4.as_str())
    );
    let first_revision = result.desired_config.config.revision;
    let new_key =
        lattice_crypto::encode_wireguard_key(&lattice_crypto::generate_wireguard_keypair().1);
    root.state
        .network
        .write()
        .await
        .allocations
        .get_mut(&relay.id)
        .unwrap()
        .wireguard_public_key = Some(new_key.clone());
    lattice_control::authority::issue_relay(
        &root.state,
        lattice_control::authority::RelayGrantRequest {
            node_id: relay.id.clone(),
            endpoint: "198.51.100.7:51820".into(),
            bandwidth_limit_bps: 8_000_000,
        },
    )
    .await
    .unwrap();
    let claim = NetworkSyncClaim {
        protocol_version: NETWORK_PROTOCOL_VERSION,
        request_id: uuid::Uuid::new_v4().to_string(),
        node_id: worker.id.clone(),
        sequence: 2,
        last_applied_revision: first_revision,
        issued_at_ms: root.clock.now_ms(),
    };
    let response = root
        .client
        .post(format!("{}/api/v1/network/sync", root.url))
        .json(&NetworkSyncRequest {
            signature: sign(&worker.private, &claim).unwrap(),
            claim,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let changed: NetworkSyncResponse = response.json().await.unwrap();
    assert!(
        changed.desired_config.config.revision > first_revision,
        "changed gateway binding needs a fresh revision even when its endpoint is unchanged"
    );
    assert_eq!(
        changed.desired_config.config.gateway_wireguard_public_key,
        Some(new_key)
    );
}

#[tokio::test]
async fn master_presents_its_certificate_when_the_snapshot_predates_registration() {
    let root = Fixture::new("supervisor").await;
    let host = Device::new();
    let control = Device::new();
    join(&root, &host).await;
    let old_snapshot = snapshot(&root).await;
    let grant = activate(&root, &host, &control).await;
    let current = snapshot(&root).await;
    let cert = current.snapshot.certificates.iter().find(|c| matches!(&c.certificate.subject, CertificateSubject::Master { control_id, .. } if control_id == &control.id)).unwrap().clone();
    let master = Fixture::new("master").await;
    let mut state = master.state.clone();
    state.control = std::sync::Arc::new(lattice_control::ControlIdentity {
        control_id: control.id.clone(),
        public_key: control.public.clone(),
        private_key: lattice_crypto::encode_key(&control.private),
        created_at_ms: root.clock.now_ms(),
    });
    let authority = MasterAuthority {
        bootstrap_url: "https://unreachable.invalid".into(),
        coordinator_key: root.state.control.public_key.clone(),
        network_id: grant.grant.network_id.clone(),
        grant,
        directory: masters::directory(&root.state, root.clock.now_ms())
            .await
            .unwrap(),
        authority: Some(AuthorityContext {
            snapshot: Some(old_snapshot),
            master_certificate: Some(cert.clone()),
            ..Default::default()
        }),
    };
    lattice_control::auth::atomic_json(
        &master.dir.path().join("master-authority.json"),
        &authority,
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, lattice_control::build_router(state))
            .await
            .unwrap();
    });
    let response = master
        .client
        .get(format!("{url}/api/v2/master/authority"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let context: AuthorityContext = response.json().await.unwrap();
    assert_eq!(context.master_certificate, Some(cert));
    let mut cache = lattice_crypto::authority_cache::AuthorityCache::new(
        root.state.control.public_key.clone(),
        authority.network_id,
    );
    cache
        .ingest_presented(&context, root.clock.now_ms())
        .unwrap();
    cache
        .require_master(
            &control.id,
            &control.public,
            &CommandScope::Workloads,
            root.clock.now_ms(),
        )
        .unwrap();
    task.abort();
}
