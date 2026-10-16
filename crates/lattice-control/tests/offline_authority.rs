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
