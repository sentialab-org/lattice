use std::{
    io::Write,
    process::{Command, Stdio},
};
#[test]
fn offline_supervisor_initialization_is_repeatable_and_never_replaces_keys() {
    let dir = tempfile::tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_lattice-admin");
    let mut provision = Command::new(binary)
        .args([
            "provision",
            "--data-dir",
            dir.path().to_str().unwrap(),
            "--username",
            "owner",
            "--password-stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    provision
        .stdin
        .take()
        .unwrap()
        .write_all(b"fixture private account password")
        .unwrap();
    assert!(provision.wait().unwrap().success());
    let initialize = || {
        Command::new(binary)
            .args([
                "initialize-supervisor",
                "--data-dir",
                dir.path().to_str().unwrap(),
                "--public-url",
                "https://authority.test",
            ])
            .output()
            .unwrap()
    };
    let first = initialize();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let names = [
        "control-identity.json",
        "gateway_wireguard.json",
        "network.json",
        "account.json",
    ];
    let before: Vec<_> = names
        .iter()
        .map(|name| {
            std::fs::read(dir.path().join(name)).expect(
                "initialization must prepare protected authority state without running a service",
            )
        })
        .collect();
    assert!(initialize().status.success());
    for (name, bytes) in names.iter().zip(before) {
        assert_eq!(std::fs::read(dir.path().join(name)).unwrap(), bytes);
    }
    assert!(
        !dir.path().join("identity.json").exists(),
        "the authority cannot create a Base Node identity"
    );
    let network: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("network.json")).unwrap()).unwrap();
    assert!(
        network["gateway_wireguard_public_key"]
            .as_str()
            .unwrap()
            .len()
            > 20
    );
    std::fs::remove_file(dir.path().join("control-identity.json")).unwrap();
    assert!(
        !initialize().status.success(),
        "a partial authority must be recovered, never assigned a replacement root key"
    );
    assert!(!dir.path().join("control-identity.json").exists());
}
