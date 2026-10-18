//! Real daemon lifecycle checks; no network privileges, external authority or worker execution.
#![cfg(unix)]
use lattice_protocol::*;
use std::{
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn start(dir: &Path) -> Daemon {
    let socket = dir.join("node.sock");
    let child = Command::new(env!("CARGO_BIN_EXE_lattice-node"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("LATTICE_CONFIG", dir.join("node.json"))
        .env("LATTICE_SOCKET", &socket)
        .env("LATTICE_NETWORK_OWNER_LOCK", dir.join("owner.lock"))
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut daemon = Daemon(child);
    let until = Instant::now() + Duration::from_secs(12);
    loop {
        assert!(
            daemon.0.try_wait().unwrap().is_none(),
            "daemon exited before IPC became ready"
        );
        if let Ok(mut connection) = std::os::unix::net::UnixStream::connect(&socket) {
            connection
                .set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
            if connection.write_all(b"{\"method\":\"ping\"}\n").is_ok() {
                let mut response = String::new();
                if BufReader::new(connection).read_line(&mut response).is_ok()
                    && response.contains("pong")
                {
                    return daemon;
                }
            }
        }
        assert!(Instant::now() < until, "daemon IPC startup timed out");
        std::thread::sleep(Duration::from_millis(40));
    }
}
fn terminate(daemon: &mut Daemon, signal: i32) {
    assert_eq!(unsafe { libc::kill(daemon.0.id() as i32, signal) }, 0);
    let until = Instant::now() + Duration::from_secs(12);
    loop {
        if let Some(status) = daemon.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "service must shut down through its lifecycle, got {status}"
            );
            return;
        }
        assert!(Instant::now() < until, "daemon shutdown timed out");
        std::thread::sleep(Duration::from_millis(40));
    }
}
fn assigned_fixture(dir: &Path, expired: bool) -> Vec<u8> {
    let mut initial = start(dir);
    terminate(&mut initial, libc::SIGINT);
    let identity: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("identity.json")).unwrap()).unwrap();
    let deadline = if expired { 1 } else { u64::MAX };
    let status = JobLeaseStatus {
        control_state_required: false,
        lease: JobLease {
            lease_id: "restart-lease".into(),
            node_id: identity["identity"]["node_id"].as_str().unwrap().into(),
            offer: JobOffer {
                job_id: "restart-job".into(),
                workload_kind: WorkloadKind::Research,
                runtime: "lattice-wasm".into(),
                runtime_version: "fixture".into(),
                artifact_id: "fixture".into(),
                artifact_version: "fixture".into(),
                limits: ResourceLimits::default(),
                parameters: Default::default(),
                expires_at_ms: deadline,
            },
            issued_at_ms: 0,
            decision_deadline_ms: deadline,
            expires_at_ms: deadline,
        },
        state: JobState::Running,
        reason: None,
        events: vec![],
        pending_event: None,
    };
    let bytes = serde_json::to_vec_pretty(&status).unwrap();
    std::fs::write(dir.join("active-lease.json"), &bytes).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        dir.join("active-lease.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    bytes
}
#[test]
fn graceful_interrupt_preserves_the_durable_assignment() {
    let dir = tempfile::tempdir().unwrap();
    let before = assigned_fixture(dir.path(), false);
    let mut daemon = start(dir.path());
    terminate(&mut daemon, libc::SIGINT);
    assert_eq!(
        std::fs::read(dir.path().join("active-lease.json")).unwrap(),
        before,
        "daemon shutdown is not workload completion or cancellation"
    );
}
#[test]
fn service_termination_uses_the_same_graceful_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let before = assigned_fixture(dir.path(), false);
    let mut daemon = start(dir.path());
    terminate(&mut daemon, libc::SIGTERM);
    assert_eq!(
        std::fs::read(dir.path().join("active-lease.json")).unwrap(),
        before
    );
}
#[test]
fn expired_execution_retains_the_assignment_for_explicit_cancellation() {
    let dir = tempfile::tempdir().unwrap();
    let before = assigned_fixture(dir.path(), true);
    let _daemon = start(dir.path());
    assert_eq!(
        std::fs::read(dir.path().join("active-lease.json"))
            .expect("signed execution expiry must not delete the assignment"),
        before
    );
}
