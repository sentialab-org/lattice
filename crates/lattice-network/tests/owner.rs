use lattice_network::HostLock;
#[test]
fn second_owner_is_rejected_and_kernel_release_allows_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("network-owner.lock");
    let owner = HostLock::acquire(&path).unwrap();
    assert!(HostLock::acquire(&path).is_err());
    drop(owner);
    assert!(path.exists());
    let _replacement = HostLock::acquire(&path).unwrap();
}
#[cfg(unix)]
#[test]
fn owner_lock_cannot_follow_a_symlink_or_accept_unprotected_state() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("other");
    let path = dir.path().join("network-owner.lock");
    std::fs::write(&target, b"unrelated state").unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(HostLock::acquire(&path).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"unrelated state");
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, b"unprotected").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(HostLock::acquire(&path).is_err());
}
