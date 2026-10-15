use lattice_protocol::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallationReport {
    pub source_revision: Option<String>,
    pub artifact_sha256: Option<String>,
    pub artifact_verified: bool,
    pub os: String,
    pub role: NodeRole,
    pub service_state: String,
    pub master_service_state: Option<String>,
    pub node_id: Option<String>,
    pub virtual_ipv4: Option<String>,
    pub handshake_age_ms: Option<u64>,
    pub overlay_probe: bool,
    pub route_verified: bool,
    pub workload_ready: bool,
    pub peer_tcp: Option<bool>,
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit())
}
pub fn validate_report(r: &InstallationReport) -> bool {
    r.source_revision.as_deref().is_some_and(|s| hex(s, 40))
        && r.artifact_sha256.as_deref().is_some_and(|s| hex(s, 64))
        && r.artifact_verified
        && r.service_state == "running"
        && (r.role != NodeRole::Master || r.master_service_state.as_deref() == Some("running"))
        && r.node_id.as_ref().is_some_and(|s| !s.is_empty())
        && r.virtual_ipv4.as_ref().is_some_and(|s| {
            s.split('/')
                .next()
                .is_some_and(|s| s.parse::<std::net::Ipv4Addr>().is_ok())
        })
        && r.handshake_age_ms.is_some_and(|age| age <= 180_000)
        && r.overlay_probe
        && r.route_verified
        && r.workload_ready
        && r.peer_tcp == Some(true)
}
pub fn check_file(path: &Path) -> bool {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<InstallationReport>(&bytes).ok())
        .as_ref()
        .is_some_and(validate_report)
}
async fn command(program: &str, args: &[&str]) -> Option<String> {
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::process::Command::new(program)
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if result.status.success() {
        Some(String::from_utf8_lossy(&result.stdout).into())
    } else {
        None
    }
}
async fn service(role: &str, pid: Option<u32>) -> String {
    #[cfg(target_os = "macos")]
    {
        let name = format!("system/com.lattice.{role}");
        if let Some(text) = command("launchctl", &["print", &name]).await {
            if text.lines().any(|l| l.trim() == "state = running")
                && pid.is_none_or(|p| text.lines().any(|l| l.trim() == format!("pid = {p}")))
            {
                return "running".into();
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        let name = format!("lattice-{role}.service");
        let output = command(
            "systemctl",
            &[
                "show",
                &name,
                "--property=ActiveState",
                "--property=MainPID",
            ],
        )
        .await;
        if let Some(text) = output {
            if text.lines().any(|l| l == "ActiveState=active")
                && pid.is_none_or(|p| text.lines().any(|l| l == format!("MainPID={p}")))
            {
                return "running".into();
            }
        }
    }
    #[cfg(windows)]
    {
        let name = if role == "master" {
            "LatticeMaster"
        } else {
            "LatticeNode"
        };
        let script = format!(
            "$s=Get-CimInstance Win32_Service -Filter \"Name='{name}'\"; if($s.State -eq 'Running' -and {} ){{ 'running' }}else{{exit 1}}",
            pid.map(|p| format!("$s.ProcessId -eq {p}"))
                .unwrap_or_else(|| "$true".into())
        );
        if command(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", &script],
        )
        .await
        .is_some()
        {
            return "running".into();
        }
    }
    "not_running".into()
}
fn is_second_node(
    j: &crate::network::NetworkJournal,
    local: Option<&str>,
    peer: std::net::Ipv4Addr,
) -> bool {
    let address = |s: &str| s.split('/').next()?.parse::<std::net::Ipv4Addr>().ok();
    let Some(local) = local.and_then(address) else {
        return false;
    };
    if peer == local || j.gateway_ipv4.as_deref().and_then(address) == Some(peer) {
        return false;
    }
    j.overlay_cidr
        .as_deref()
        .and_then(|s| s.split_once('/'))
        .and_then(|(ip, prefix)| {
            Some((
                ip.parse::<std::net::Ipv4Addr>().ok()?,
                prefix.parse::<u32>().ok()?,
            ))
        })
        .is_some_and(|(ip, prefix)| {
            if prefix > 32 {
                return false;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(ip) & mask == u32::from(peer) & mask
        })
}
pub async fn run(args: &[String]) -> Result<i32, String> {
    let value = |flag: &str| {
        args.iter()
            .position(|s| s == flag)
            .and_then(|i| args.get(i + 1))
            .map(String::as_str)
    };
    let mut r = InstallationReport {
        source_revision: None,
        artifact_sha256: None,
        artifact_verified: false,
        os: std::env::consts::OS.into(),
        role: NodeRole::Node,
        service_state: "not_tested".into(),
        master_service_state: None,
        node_id: None,
        virtual_ipv4: None,
        handshake_age_ms: None,
        overlay_probe: false,
        route_verified: false,
        workload_ready: false,
        peer_tcp: None,
    };
    if let Ok(IpcResponse::SetupStatus(setup)) =
        lattice_ipc::request(&IpcRequest::GetSetupStatus).await
    {
        r.role = setup.role;
        r.node_id = Some(setup.node_id);
        r.virtual_ipv4 = setup.virtual_ipv4;
        r.workload_ready = setup.workload_ready;
    }
    if let Ok(IpcResponse::BuildInfo(info)) = lattice_ipc::request(&IpcRequest::GetBuildInfo).await
    {
        r.source_revision = info.source_revision.clone();
        r.service_state = service("node", Some(info.process_id)).await;
        if r.role == NodeRole::Master {
            r.master_service_state = Some(service("master", None).await);
        }
        if let Ok(bytes) = std::fs::read(&info.executable_path) {
            let hash: String = Sha256::digest(bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            r.artifact_sha256 = Some(hash.clone());
            let path = Path::new(&info.executable_path).with_file_name("manifest.json");
            if let Ok(bytes) = std::fs::read(path) {
                if let Ok(m) = serde_json::from_slice::<ReleaseBundleManifest>(&bytes) {
                    r.artifact_verified = r.source_revision.as_deref()
                        == Some(m.source_revision.as_str())
                        && value("--expected-revision") == Some(m.source_revision.as_str())
                        && m.files.iter().any(|f| {
                            f.path
                                == if cfg!(windows) {
                                    "lattice-node.exe"
                                } else {
                                    "lattice-node"
                                }
                                && f.sha256 == hash
                        });
                }
            }
        }
    }
    let journal =
        crate::network::load_journal(&crate::network::network_journal_path(&crate::config_path()))
            .await;
    let evidence = crate::setup::probe_journal(&journal).await;
    r.handshake_age_ms = evidence.handshake_age_ms;
    r.route_verified = evidence.route_verified;
    r.overlay_probe = evidence.probe_success;
    if let Some(peer) = value("--tcp-peer") {
        let addr = peer
            .parse::<std::net::SocketAddrV4>()
            .map_err(|_| "Use an overlay IPv4:port TCP peer")?;
        let in_overlay = is_second_node(&journal, r.virtual_ipv4.as_deref(), *addr.ip());
        let route = crate::setup::route_verified(
            &addr.ip().to_string(),
            &crate::network::active_interface_name(),
        )
        .await;
        let connected = if in_overlay && route {
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                tokio::net::TcpStream::connect(addr),
            )
            .await
            .is_ok_and(|r| r.is_ok())
        } else {
            false
        };
        r.peer_tcp = Some(connected);
    }
    let gates = serde_json::json!({"service":if r.service_state=="not_tested"{"not_tested"}else if r.service_state=="running"{"pass"}else{"fail"},"artifact":if r.source_revision.is_none(){"not_tested"}else if r.artifact_verified{"pass"}else{"fail"},"network":if r.handshake_age_ms.is_some_and(|a|a<=180000)&&r.route_verified&&r.overlay_probe{"pass"}else{"fail"},"workload":if r.workload_ready{"pass"}else{"fail"},"peer_tcp":match r.peer_tcp{Some(true)=>"pass",Some(false)=>"fail",None=>"not_tested"}});
    let ok = validate_report(&r);
    let mut output = serde_json::to_value(r).map_err(|e| e.to_string())?;
    output["gates"] = gates;
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())?
    );
    Ok(if ok { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tcp_probe_requires_a_distinct_overlay_participant() {
        let j = crate::network::NetworkJournal {
            overlay_cidr: Some("10.77.0.0/16".into()),
            gateway_ipv4: Some("10.77.0.1".into()),
            ..Default::default()
        };
        assert!(!is_second_node(
            &j,
            Some("10.77.0.5/32"),
            "10.77.0.5".parse().unwrap()
        ));
        assert!(!is_second_node(
            &j,
            Some("10.77.0.5/32"),
            "10.77.0.1".parse().unwrap()
        ));
        assert!(!is_second_node(&j, None, "10.77.0.6".parse().unwrap()));
        assert!(!is_second_node(
            &j,
            Some("10.77.0.5/32"),
            "192.168.1.2".parse().unwrap()
        ));
        assert!(is_second_node(
            &j,
            Some("10.77.0.5/32"),
            "10.77.0.6".parse().unwrap()
        ));
    }
}
