mod support;
use serde_json::json;
use support::Fixture;
#[tokio::test]
async fn password_bytes_are_not_trimmed() {
    let f = Fixture::new("combined").await;
    assert_eq!(f.login("owner", "password with spaces").await.0, 401);
    assert_eq!(f.login("owner", " password with spaces ").await.0, 200);
    assert_eq!(f.login("wrong", " password with spaces ").await.0, 401);
}
#[tokio::test]
async fn login_sets_protected_cookie_without_operator_token() {
    let f = Fixture::new("combined").await;
    let (s, c, b) = f.login("owner", " password with spaces ").await;
    assert_eq!(s, 200);
    for flag in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"] {
        assert!(c.contains(flag));
    }
    assert!(!c.contains("Domain="));
    assert!(b.get("operator_token").is_none());
    let files = std::fs::read_to_string(f.dir.path().join("sessions.json")).unwrap();
    assert!(!files.contains(c.split(';').next().unwrap().split('=').nth(1).unwrap()));
    assert!(
        !std::fs::read_to_string(f.dir.path().join("account.json"))
            .unwrap()
            .contains("password with spaces")
    );
}
#[tokio::test]
async fn session_idle_and_absolute_expiry() {
    let f = Fixture::new("combined").await;
    let (_, c, _) = f.login("owner", " password with spaces ").await;
    f.advance_ms(1_800_000);
    assert_eq!(
        f.request("GET", "/api/v1/auth/session", json!(null), &c, "")
            .await
            .status(),
        401
    );
    let (_, c, _) = f.login("owner", " password with spaces ").await;
    for _ in 0..31 {
        f.advance_ms(900_000);
        assert_eq!(
            f.request("GET", "/api/v1/auth/session", json!(null), &c, "")
                .await
                .status(),
            200
        );
    }
    f.advance_ms(900_000);
    assert_eq!(
        f.request("GET", "/api/v1/auth/session", json!(null), &c, "")
            .await
            .status(),
        401
    );
}
#[tokio::test]
async fn logout_invalidates_cookie() {
    let f = Fixture::new("combined").await;
    let (_, c, b) = f.login("owner", " password with spaces ").await;
    assert_eq!(
        f.request(
            "POST",
            "/api/v1/auth/logout",
            json!({}),
            &c,
            b["csrf_token"].as_str().unwrap()
        )
        .await
        .status(),
        200
    );
    assert_eq!(
        f.request("GET", "/api/v1/auth/session", json!(null), &c, "")
            .await
            .status(),
        401
    );
}
#[tokio::test]
async fn cookie_mutation_requires_origin_and_csrf() {
    let f = Fixture::new("combined").await;
    let (_, c, b) = f.login("owner", " password with spaces ").await;
    for csrf in ["", "wrong"] {
        assert_eq!(
            f.request("POST", "/api/v1/auth/logout", json!({}), &c, csrf)
                .await
                .status(),
            403
        );
    }
    let r = f
        .client
        .post(format!("{}/api/v1/auth/logout", f.url))
        .header("cookie", c.split(';').next().unwrap())
        .header("origin", "https://evil.test")
        .header("x-lattice-csrf", b["csrf_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    assert_eq!(
        f.request("GET", "/api/v1/operator/network/nodes", json!(null), "", "")
            .await
            .status(),
        401
    );
}
#[tokio::test]
async fn legacy_bearer_is_explicitly_separate() {
    let f = Fixture::new("combined").await;
    let r = f
        .client
        .get(format!("{}/api/v1/operator/network/nodes", f.url))
        .bearer_auth("not-configured")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let mut state = f.state.clone();
    state.operator_token = Some(std::sync::Arc::new("compat-secret".into()));
    let mut h = axum::http::HeaderMap::new();
    h.insert("authorization", "Bearer compat-secret".parse().unwrap());
    assert!(
        lattice_control::auth::authorize_operator(
            &state,
            &h,
            None,
            lattice_control::auth::OperatorScope::FleetRead
        )
        .is_ok()
    );
}
