mod support;
use lattice_control::tokens::{ActivationBinding, TokenStore};
use lattice_protocol::{MasterGrant, PRODUCT_SCHEMA_VERSION, SignedMasterGrant};
use serde_json::json;
use support::Fixture;
fn binding(n: &str) -> ActivationBinding {
    ActivationBinding {
        node_id: n.into(),
        node_public_key: format!("key-{n}"),
        control_id: format!("master-{n}"),
        control_public_key: format!("control-key-{n}"),
    }
}
fn grant(n: &str) -> SignedMasterGrant {
    SignedMasterGrant {
        grant: MasterGrant {
            schema_version: PRODUCT_SCHEMA_VERSION,
            network_id: "net".into(),
            node_id: n.into(),
            node_public_key: format!("key-{n}"),
            control_id: format!("master-{n}"),
            control_public_key: format!("control-key-{n}"),
            overlay_ipv4: "10.77.0.2".into(),
            revision: 1,
            issued_at_ms: 100,
        },
        signature: "signed".into(),
    }
}
#[tokio::test]
async fn tokens_require_account_management() {
    let f = Fixture::new("bootstrapper").await;
    assert_eq!(
        f.request(
            "POST",
            "/api/v1/operator/master-tokens",
            json!({"label":"Mac"}),
            "",
            ""
        )
        .await
        .status(),
        401
    );
    let (_, c, b) = f.login("owner", " password with spaces ").await;
    assert_eq!(
        f.request(
            "POST",
            "/api/v1/operator/master-tokens",
            json!({"label":"Mac"}),
            &c,
            ""
        )
        .await
        .status(),
        403
    );
    assert_eq!(
        f.request(
            "POST",
            "/api/v1/operator/master-tokens",
            json!({"label":"Mac"}),
            &c,
            b["csrf_token"].as_str().unwrap()
        )
        .await
        .status(),
        200
    );
}
#[tokio::test]
async fn token_plaintext_is_creation_only() {
    let dir = tempfile::tempdir().unwrap();
    let s = TokenStore::load(dir.path()).unwrap();
    let t = s.create("one", 100).await.unwrap();
    let list = serde_json::to_string(&s.list().await).unwrap();
    assert!(!list.contains(&t.activation_token));
    assert!(!list.contains("sha256"));
    let file = std::fs::read_to_string(dir.path().join("master-authorizations.json")).unwrap();
    assert!(!file.contains(&t.activation_token));
    assert!(!format!("{t:?}").contains(&t.activation_token));
}
#[tokio::test]
async fn token_expires_after_86400000_ms() {
    let d = tempfile::tempdir().unwrap();
    let s = TokenStore::load(d.path()).unwrap();
    let t = s.create("test", 100).await.unwrap();
    assert_eq!(t.expires_at_ms, 86_400_100);
    assert!(
        s.redeem(
            &t.activation_token,
            &binding("a"),
            grant("a"),
            t.expires_at_ms
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn token_cannot_activate_two_bindings() {
    let d = tempfile::tempdir().unwrap();
    let s = TokenStore::load(d.path()).unwrap();
    let t = s.create("test", 100).await.unwrap();
    let a = binding("a");
    let b = binding("b");
    let ga = grant("a");
    let gb = grant("b");
    let (x, y) = tokio::join!(
        s.redeem(&t.activation_token, &a, ga, 101),
        s.redeem(&t.activation_token, &b, gb, 101)
    );
    assert_ne!(x.is_ok(), y.is_ok());
    let (n, first) = if x.is_ok() {
        ("a", x.unwrap())
    } else {
        ("b", y.unwrap())
    };
    assert!(first.first_use);
    drop(s);
    let s = TokenStore::load(d.path()).unwrap();
    let retry = s
        .redeem(&t.activation_token, &binding(n), grant(n), 102)
        .await
        .unwrap();
    assert!(!retry.first_use);
    assert_eq!(retry.grant, first.grant);
}
#[tokio::test]
async fn revoked_token_cannot_activate() {
    let d = tempfile::tempdir().unwrap();
    let s = TokenStore::load(d.path()).unwrap();
    let t = s.create("test", 100).await.unwrap();
    s.revoke(&t.token_id, 101).await.unwrap();
    assert!(
        s.redeem(&t.activation_token, &binding("a"), grant("a"), 102)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn failed_persistence_does_not_consume_token() {
    let d = tempfile::tempdir().unwrap();
    let s = TokenStore::load(d.path()).unwrap();
    let t = s.create("test", 100).await.unwrap();
    std::fs::remove_file(d.path().join("master-authorizations.json")).unwrap();
    std::fs::create_dir(d.path().join("master-authorizations.json")).unwrap();
    assert!(
        s.redeem(&t.activation_token, &binding("a"), grant("a"), 101)
            .await
            .is_err()
    );
    std::fs::remove_dir(d.path().join("master-authorizations.json")).unwrap();
    assert!(
        s.redeem(&t.activation_token, &binding("b"), grant("b"), 102)
            .await
            .unwrap()
            .first_use
    );
}
