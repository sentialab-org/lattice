#![cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[tokio::test]
async fn managed_backend_uses_private_socket_and_cannot_replace_a_live_owner() {
    let dir = tempfile::tempdir().unwrap();
    let state = lattice_control::load_state(
        dir.path(),
        String::new(),
        None,
        "https://lattice.test".into(),
        "supervisor".into(),
    )
    .await
    .unwrap();
    let app = lattice_control::build_router(state.clone());
    let (shutdown, rx) = tokio::sync::watch::channel(false);
    let root = dir.path().to_owned();
    let server =
        tokio::spawn(async move { lattice_control::private_backend::serve(app, &root, rx).await });
    let path = dir.path().join("module-http.sock");
    for _ in 0..100 {
        if path.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let client = reqwest::Client::builder()
        .unix_socket(path.as_path())
        .no_proxy()
        .build()
        .unwrap();
    assert_eq!(
        client
            .get("http://localhost/health")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let (_, rx) = tokio::sync::watch::channel(false);
    assert!(
        lattice_control::private_backend::serve(
            lattice_control::build_router(state),
            dir.path(),
            rx
        )
        .await
        .is_err(),
        "second backend must not unlink a running service socket"
    );
    assert_eq!(
        client
            .get("http://localhost/health")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    shutdown.send(true).unwrap();
    server.await.unwrap().unwrap();
}
