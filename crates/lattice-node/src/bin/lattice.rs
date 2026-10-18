//! `lattice` — the owner-facing device inspector installed alongside the daemon.
//!
//! `lattice list` renders the local mesh picture: this device, the network
//! gateway, every meshed peer from the daemon-owned signed peers cache, and
//! the local network interface that actually carries the virtual address.

use lattice_node::config_path;
use lattice_node::network::{load_peers_cache, network_peers_path};
use lattice_protocol::NetworkPeerEntry;
use serde_json::Value;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.iter().find(|arg| !arg.starts_with("--"));
    match command.map(String::as_str) {
        None | Some("list") => {}
        Some("help" | "--help" | "-h") => {
            print_help();
            return;
        }
        Some(other) => {
            eprintln!("unknown command: {other}");
            print_help();
            std::process::exit(2);
        }
    }
    let json = args.iter().any(|arg| arg == "--json");
    match run(json) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("lattice list failed: {error}");
            eprintln!(
                "state may require the same account that runs the daemon (try sudo, or set LATTICE_CONFIG=<path to node.json> or pass --config)."
            );
            std::process::exit(1);
        }
    }
}

fn print_help() {
    println!("Lattice");
    println!("  lattice list [--json]");
    println!("      show this device, the gateway and every signed mesh peer");
}

fn run(json: bool) -> Result<i32, String> {
    let config = config_path();
    let peers_path = network_peers_path(&config);
    let state_dir = peers_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let cache = runtime.block_on(load_peers_cache(&peers_path));

    let records = read_interface_records(&state_dir);
    let nics = collect_nics();
    let state_protected = std::fs::File::open(interface_conf_path(&state_dir))
        .err()
        .is_some_and(|error| error.kind() == ErrorKind::PermissionDenied);

    if json {
        let document = serde_json::json!({
            "state_dir": state_dir,
            "updated_at_ms": cache.updated_at_ms,
            "path_policy": cache.path_policy,
            "this_device": records
                .address
                .as_ref()
                .map(|address| {
                    serde_json::json!({
                        "virtual_ipv4": address,
                        "interface": records.interface_holder(&nics),
                    })
                })
                .unwrap_or(Value::Null),
            "gateway_endpoint": records.endpoint,
            "peers": cache.peers,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&document).map_err(|error| error.to_string())?
        );
        return Ok(0);
    }

    let now = unix_time_ms();
    let age = if cache.updated_at_ms > 0 {
        format_age(cache.updated_at_ms, now)
    } else {
        "never".to_string()
    };
    println!(
        "Lattice network | {} peer(s) | path policy: {} | signed directory updated {}",
        cache.peers.len(),
        if cache.path_policy.is_empty() {
            "hub"
        } else {
            cache.path_policy.as_str()
        },
        age
    );

    let mut rows: Vec<Vec<String>> = Vec::new();

    if let Some(address) = records.address.as_deref() {
        rows.push(vec![
            "this device".to_string(),
            address.to_string(),
            "local".to_string(),
            records
                .interface_holder(&nics)
                .unwrap_or_else(|| "unattached".to_string()),
        ]);
    } else {
        rows.push(vec![
            "this device".to_string(),
            "(no address applied yet)".to_string(),
            "local".to_string(),
            "(none)".to_string(),
        ]);
    }

    if let Some(endpoint) = records.endpoint.as_deref() {
        rows.push(vec![
            "gateway (bootstrapper)".to_string(),
            "(hub virtual base)".to_string(),
            "gateway".to_string(),
            endpoint.to_string(),
        ]);
    }

    for peer in cache.peers.iter() {
        rows.push(peer_row(peer));
    }

    print_table(
        &["node", "virtual IPv4 / address", "state", "public endpoint"],
        &rows,
    );

    if records.address.is_none() && cache.peers.is_empty() && state_protected {
        eprintln!(
            "daemon state exists but is protected: rerun with sudo or under the daemon's account to see the mesh table"
        );
    } else if records.address.is_none() && cache.peers.is_empty() {
        eprintln!(
            "no mesh data yet: the daemon writes network_peers.json once the coordinator is reachable"
        );
    }

    if !nics.is_empty() {
        println!("network interfaces:");
        for (name, address) in nics.iter() {
            let applied = records.address.as_ref().map(String::as_str);
            let virtual_marker = match applied {
                Some(applied) if address_base(address) == address_base(applied) => {
                    " <- lattice virtual address"
                }
                _ => "",
            };
            println!("  {name:>14}  {address}{virtual_marker}");
        }
    }

    Ok(0)
}

fn peer_row(peer: &NetworkPeerEntry) -> Vec<String> {
    vec![
        peer.node_id.clone(),
        peer.virtual_ipv4.clone(),
        status_text(peer.status.clone()),
        peer.endpoint_candidates
            .first()
            .cloned()
            .unwrap_or_else(|| "—".to_string()),
    ]
}

fn status_text(status: lattice_protocol::NetworkNodeStatus) -> String {
    serde_json::to_value(status)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

/// The applied `wg-lattice.conf` next to the state directory is the source of
/// truth for what the daemon actually rendered: own address, the recorded
/// interface name and the gateway endpoint, without touching protected
/// identity material.
#[derive(Debug, Default)]
struct InterfaceRecords {
    address: Option<String>,
    endpoint: Option<String>,
    interface_name: Option<String>,
}

impl InterfaceRecords {
    /// Find the interface whose address matches the applied lattice address,
    /// falling back to the recorded interface name from the daemon.
    fn interface_holder(&self, nics: &[(String, String)]) -> Option<String> {
        let applied = self.address.as_deref()?;
        nics.iter()
            .find(|(_, nic_address)| address_base(nic_address) == address_base(applied))
            .map(|(name, _)| name.clone())
            .or_else(|| self.interface_name.clone())
    }
}

fn address_base(address: &str) -> &str {
    match address.split_once('/') {
        Some((base, _)) => base,
        None => address,
    }
}

fn interface_conf_path(parent: &Path) -> PathBuf {
    parent.join("wg-lattice.conf")
}

fn read_interface_records(state_dir: &Path) -> InterfaceRecords {
    let mut records = InterfaceRecords::default();
    let Ok(content) = std::fs::read_to_string(interface_conf_path(state_dir)) else {
        return records;
    };
    for line in content.lines() {
        let line = line.trim();
        if let Some(address) = line.strip_prefix("Address = ") {
            records.address = Some(address.trim().to_string());
        } else if let Some(endpoint) = line.strip_prefix("Endpoint = ") {
            records.endpoint = Some(endpoint.trim().to_string());
        } else if let Some(interface) = line.strip_prefix("# interface_name = ") {
            records.interface_name = Some(interface.trim().to_string());
        }
    }
    records
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn format_age(past_ms: u64, now_ms: u64) -> String {
    let seconds = now_ms.saturating_sub(past_ms) / 1000;
    if seconds < 60 {
        format!("{seconds}s ago")
    } else if seconds < 3600 {
        format!("{}m ago", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}h ago", seconds / 3600)
    } else {
        format!("{}d ago", seconds / 86_400)
    }
}

/// Enumerate live network interfaces with their IPv4 addresses so the printed
/// mapping ties the virtual lattice address to a concrete interface the owner
/// can also see through `ifconfig` or `ip addr`.
fn collect_nics() -> Vec<(String, String)> {
    #[cfg(target_os = "linux")]
    {
        let mut entries = Vec::new();
        if let Ok(output) = Command::new("ip")
            .args(["-j", "-4", "address", "show"])
            .output()
        {
            if output.status.success() {
                if let Ok(document) = serde_json::from_slice::<Value>(&output.stdout) {
                    if let Some(devices) = document.as_array() {
                        for device in devices {
                            let name = device["ifname"].as_str().unwrap_or_default().to_string();
                            if let Some(infos) = device["addr_info"].as_array() {
                                for info in infos {
                                    if info["family"].as_str() != Some("inet") {
                                        continue;
                                    }
                                    if let Some(address) = info["local"].as_str() {
                                        let prefix = info["prefixlen"].as_u64().unwrap_or(0);
                                        entries.push((name.clone(), format!("{address}/{prefix}")));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return entries;
    }

    #[cfg(target_os = "macos")]
    {
        let mut entries = Vec::new();
        if let Ok(output) = Command::new("ifconfig").output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                let mut current = String::new();
                for line in text.lines() {
                    if line.starts_with(char::is_whitespace) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 && parts[0] == "inet" {
                            entries.push((current.clone(), parts[1].to_string()));
                        }
                        continue;
                    }
                    if let Some((name, _)) = line.split_once(':') {
                        current = name.trim().to_string();
                    }
                }
            }
        }
        return entries;
    }

    #[cfg(windows)]
    {
        let mut entries = Vec::new();
        if let Ok(output) = Command::new("ipconfig").output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                if !line.contains("IPv4") {
                    continue;
                }
                if let Some((_, address)) = line.split_once(':') {
                    entries.push(("ipconfig".to_string(), address.trim().to_string()));
                }
            }
        }
        return entries;
    }
}

fn width_of(value: &str) -> usize {
    value.chars().count()
}

fn border(widths: &[usize]) -> String {
    let total = widths.iter().sum::<usize>() + widths.len() * 3 - 1;
    format!("+{:-<total$}+", "", total = total)
}

fn render_row(cells: &[String], widths: &[usize]) -> String {
    let mut rendered = String::from("| ");
    for (index, width) in widths.iter().enumerate() {
        let cell = cells.get(index).map(String::as_str).unwrap_or_default();
        rendered.push_str(cell);
        rendered.push_str(&" ".repeat(width.saturating_sub(width_of(cell))));
        if index + 1 < widths.len() {
            rendered.push_str(" | ");
        } else {
            rendered.push_str(" |");
        }
    }
    rendered
}

fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = headers.iter().map(|header| width_of(header)).collect();
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            if let Some(slot) = widths.get_mut(index) {
                *slot = (*slot).max(width_of(cell));
            }
        }
    }

    println!("{}", border(&widths));
    let header_cells: Vec<String> = headers.iter().map(|header| header.to_string()).collect();
    println!("{}", render_row(&header_cells, &widths));
    println!("{}", border(&widths));
    for row in rows {
        println!("{}", render_row(row, &widths));
    }
    println!("{}", border(&widths));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_columns_align_by_widest_value() {
        let widths = [4usize, 6];
        let row = render_row(&["ab".to_string(), "cd".to_string()], &widths);
        assert_eq!(row, "| ab   | cd     |");
        let header = render_row(&["x".to_string(), "y".to_string()], &widths);
        assert_eq!(header, "| x    | y      |");
        assert_eq!(border(&widths), "+---------------+");
    }

    #[test]
    fn interface_records_parse_rendered_conf_lines() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wg-lattice.conf");
        std::fs::write(
            &path,
            "[Interface]\n# interface_name = wg-lattice\nAddress = 10.77.0.6/32\nListenPort = 47026\nPrivateKey = secret\n[Peer]\nEndpoint = 192.168.2.252:51820\nAllowedIPs = 10.77.0.0/16\n",
        )
        .unwrap();
        let records = read_interface_records(directory.path());
        assert_eq!(records.address.as_deref(), Some("10.77.0.6/32"));
        assert_eq!(records.endpoint.as_deref(), Some("192.168.2.252:51820"));
        assert_eq!(records.interface_name.as_deref(), Some("wg-lattice"));
    }

    #[test]
    fn interface_holder_matches_base_address_across_masks() {
        let records = InterfaceRecords {
            address: Some("10.77.0.6/32".to_string()),
            endpoint: None,
            interface_name: Some("wg-lattice".to_string()),
        };
        let nics = vec![
            ("enp1s0".to_string(), "192.168.2.238".to_string()),
            ("utun7".to_string(), "10.77.0.6".to_string()),
        ];
        assert_eq!(records.interface_holder(&nics).as_deref(), Some("utun7"));
        let without_nic_match: Vec<(String, String)> =
            vec![("enp1s0".to_string(), "192.168.2.238".to_string())];
        assert_eq!(
            records.interface_holder(&without_nic_match).as_deref(),
            Some("wg-lattice")
        );
    }

    #[test]
    fn reported_age_uses_unit_buckets() {
        assert_eq!(format_age(0, 30_000), "30s ago");
        assert_eq!(format_age(0, 125_000), "2m ago");
        assert_eq!(format_age(0, 7_400_000), "2h ago");
        assert_eq!(format_age(0, 172_800_000), "2d ago");
    }
}
