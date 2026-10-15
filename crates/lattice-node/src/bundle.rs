use lattice_protocol::{NodeRole, ReleaseBundleManifest};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path};
pub fn validate(dir: &Path, role: NodeRole) -> Result<(), String> {
    let fail = || "bundle validation failed".to_string();
    let bytes = std::fs::read(dir.join("manifest.json")).map_err(|_| fail())?;
    if bytes.len() > 65536 {
        return Err(fail());
    }
    let m: ReleaseBundleManifest = serde_json::from_slice(&bytes).map_err(|_| fail())?;
    if m.source_revision.len() != 40
        || !m.source_revision.bytes().all(|b| b.is_ascii_hexdigit())
        || m.schema_version != 1
        || m.role != role
        || semver::Version::parse(&m.version).is_err()
    {
        return Err(fail());
    }
    let win = m.target == "windows-x86_64";
    let mac = matches!(m.target.as_str(), "macos-arm64" | "macos-x86_64");
    if !win && !mac && !matches!(m.target.as_str(), "linux-x86_64" | "linux-aarch64") {
        return Err(fail());
    }
    let suffix = if win { ".exe" } else { "" };
    let mut required = BTreeSet::from([
        format!("lattice-node{suffix}"),
        format!("lattice-worker{suffix}"),
        if win { "install.ps1" } else { "install.sh" }.into(),
    ]);
    if role == NodeRole::Master {
        required.insert(format!("lattice-master{suffix}"));
    }
    if win {
        required.extend(
            [
                "lattice-update-helper.exe",
                "wireguard.msi",
                "THIRD_PARTY_NOTICES.txt",
                "provenance.json",
            ]
            .map(String::from),
        );
    }
    if mac {
        required.extend(
            [
                "wg",
                "wg-quick",
                "wireguard-go",
                "bash",
                "THIRD_PARTY_NOTICES.txt",
                "provenance.json",
            ]
            .map(String::from),
        );
    }
    let names: BTreeSet<_> = m.files.iter().map(|e| e.path.clone()).collect();
    if names != required || names.len() != m.files.len() {
        return Err(fail());
    }
    for file in m.files {
        let p = dir.join(&file.path);
        let meta = std::fs::symlink_metadata(&p).map_err(|_| fail())?;
        if !meta.is_file()
            || meta.file_type().is_symlink()
            || meta.len() != file.size_bytes
            || meta.len() > 256 * 1024 * 1024
        {
            return Err(fail());
        }
        let data = std::fs::read(p).map_err(|_| fail())?;
        let hash: String = Sha256::digest(&data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if hash != file.sha256 {
            return Err(fail());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if !win && (meta.permissions().mode() & 0o111 != 0) != file.executable {
                return Err(fail());
            }
        }
    }
    let mut actual = BTreeSet::new();
    for entry in std::fs::read_dir(dir).map_err(|_| fail())? {
        let e = entry.map_err(|_| fail())?;
        actual.insert(e.file_name().to_string_lossy().into_owned());
    }
    required.insert("manifest.json".into());
    if actual != required {
        return Err(fail());
    }
    Ok(())
}
pub fn run(args: &[String]) -> Result<(), String> {
    let value = |flag: &str| {
        args.iter()
            .position(|s| s == flag)
            .and_then(|i| args.get(i + 1))
    };
    let dir = value("--artifact-dir").ok_or("artifact directory required")?;
    let role = match value("--role").map(String::as_str) {
        Some("node") => NodeRole::Node,
        Some("master") => NodeRole::Master,
        _ => return Err("role required".into()),
    };
    validate(Path::new(dir), role)
}
