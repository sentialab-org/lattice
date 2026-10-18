use crate::{NetworkCommand, NetworkFuture, NetworkRunner, NetworkSnapshot, OwnedRoute};
use std::process::{Output, Stdio};

/// The production OS executor is used only by the Base Node NetworkManager.
pub struct SystemRunner;
fn available() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    if unsafe { libc::geteuid() } == 0 {
        return Ok(());
    }
    Err("privileged Linux networking is required for Relay forwarding".into())
}
fn executable(name: &str) -> Result<std::path::PathBuf, String> {
    for directory in ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
        let path = std::path::Path::new(directory).join(name);
        if let Ok(meta) = std::fs::metadata(&path) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if !meta.is_file()
                    || meta.uid() != 0
                    || meta.mode() & 0o022 != 0
                    || meta.mode() & 0o111 == 0
                {
                    continue;
                }
            }
            return Ok(path);
        }
    }
    Err("required protected system networking tool is unavailable".into())
}
async fn output(program: &str, args: &[&str], input: Option<&str>) -> Result<Output, String> {
    use tokio::io::AsyncWriteExt;
    available()?;
    let mut command = tokio::process::Command::new(executable(program)?);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C")
        .current_dir("/")
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut child = command
            .spawn()
            .map_err(|_| "managed network command could not start")?;
        if let Some(input) = input {
            let mut stdin = child
                .stdin
                .take()
                .ok_or("managed network stdin unavailable")?;
            stdin
                .write_all(input.as_bytes())
                .await
                .map_err(|_| "managed network configuration write failed")?;
        }
        child
            .wait_with_output()
            .await
            .map_err(|_| "managed network command failed".to_string())
    })
    .await
    .map_err(|_| "managed network command timed out")?
}
async fn required(program: &str, args: &[&str], input: Option<&str>) -> Result<Vec<u8>, String> {
    let result = output(program, args, input).await?;
    if !result.status.success() || result.stdout.len() > 8 * 1024 * 1024 {
        return Err("managed network command rejected".into());
    }
    Ok(result.stdout)
}
async fn json(program: &str, args: &[&str]) -> Result<serde_json::Value, String> {
    serde_json::from_slice(&required(program, args, None).await?)
        .map_err(|_| "managed network inspection was not valid JSON".into())
}
fn ipv4_range(cidr: &str) -> Result<(u32, u32), String> {
    let (address, prefix) = cidr.split_once('/').unwrap_or((cidr, "32"));
    let address: std::net::Ipv4Addr = address
        .parse()
        .map_err(|_| "invalid inspected IPv4 address")?;
    let prefix: u32 = prefix
        .parse()
        .map_err(|_| "invalid inspected IPv4 prefix")?;
    if prefix > 32 {
        return Err("invalid inspected IPv4 prefix".into());
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let first = u32::from(address) & mask;
    Ok((first, first | !mask))
}
fn reject_foreign_overlap(
    interface: &str,
    overlay: &str,
    addresses: &serde_json::Value,
    routes: &serde_json::Value,
) -> Result<(), String> {
    let (first, last) = ipv4_range(overlay)?;
    let overlaps = |cidr: &str| -> Result<bool, String> {
        let (other_first, other_last) = ipv4_range(cidr)?;
        Ok(first <= other_last && other_first <= last)
    };
    for device in addresses.as_array().ok_or("invalid address inspection")? {
        if device["ifname"].as_str() == Some(interface) {
            continue;
        }
        for address in device["addr_info"]
            .as_array()
            .ok_or("invalid address inspection")?
        {
            if address["family"] != "inet" {
                continue;
            }
            let local = address["local"]
                .as_str()
                .ok_or("invalid local address inspection")?;
            let prefix = address["prefixlen"]
                .as_u64()
                .filter(|prefix| *prefix <= 32)
                .ok_or("invalid local prefix inspection")?;
            if overlaps(&format!("{local}/{prefix}"))? {
                return Err("overlay overlaps an address owned by another interface".into());
            }
        }
    }
    for route in routes.as_array().ok_or("invalid route inspection")? {
        if route["dev"].as_str() == Some(interface) {
            continue;
        }
        let Some(destination) = route["dst"].as_str() else {
            continue;
        };
        // Ordinary default routing is expected; a foreign specific overlay route is not.
        if destination == "default" || destination == "0.0.0.0/0" {
            continue;
        }
        if overlaps(destination)? {
            return Err("overlay overlaps a route owned by another interface".into());
        }
    }
    Ok(())
}

async fn capture(interface: &str, overlay: &str) -> Result<NetworkSnapshot, String> {
    available()?;
    let all_addresses = json("ip", &["-j", "-4", "address", "show"]).await?;
    let all_routes = json("ip", &["-j", "-4", "route", "show", "table", "main"]).await?;
    reject_foreign_overlap(interface, overlay, &all_addresses, &all_routes)?;
    let link = output("ip", &["-j", "link", "show", "dev", interface], None).await?;
    let existed = link.status.success();
    let link_up = if existed {
        let data: serde_json::Value =
            serde_json::from_slice(&link.stdout).map_err(|_| "invalid link inspection")?;
        data[0]["flags"]
            .as_array()
            .is_some_and(|flags| flags.iter().any(|v| v == "UP"))
    } else {
        false
    };
    let (transport_public_key, wireguard_config, addresses) = if existed {
        let public =
            String::from_utf8(required("wg", &["show", interface, "public-key"], None).await?)
                .map_err(|_| "invalid transport inspection")?;
        let public = public.trim();
        let public = if public.is_empty() || public == "(none)" {
            None
        } else {
            lattice_crypto::decode_wireguard_key(public)?;
            Some(public.to_owned())
        };
        let config = String::from_utf8(required("wg", &["showconf", interface], None).await?)
            .map_err(|_| "invalid private transport inspection")?;
        let data = json("ip", &["-j", "-4", "address", "show", "dev", interface]).await?;
        let mut addresses = Vec::new();
        for device in data.as_array().ok_or("invalid interface inspection")? {
            for address in device["addr_info"]
                .as_array()
                .ok_or("invalid address inspection")?
            {
                if address["family"] != "inet" {
                    continue;
                }
                let ip = address["local"]
                    .as_str()
                    .ok_or("invalid interface address")?
                    .parse::<std::net::Ipv4Addr>()
                    .map_err(|_| "invalid interface address")?;
                let prefix = address["prefixlen"]
                    .as_u64()
                    .filter(|p| *p <= 32)
                    .ok_or("invalid interface prefix")?;
                addresses.push(format!("{ip}/{prefix}"));
            }
        }
        (public, Some(config), addresses)
    } else {
        (None, None, Vec::new())
    };
    let routes = json(
        "ip",
        &[
            "-j", "-4", "route", "show", "table", "main", "exact", overlay,
        ],
    )
    .await?;
    let routes = routes.as_array().ok_or("invalid route inspection")?;
    if routes.len() > 1 {
        return Err("ambiguous overlay route belongs to another owner".into());
    }
    let route = routes
        .first()
        .map(|r| -> Result<OwnedRoute, String> {
            if r.get("multipath").is_some() {
                return Err("multipath overlay route cannot be replaced".into());
            }
            Ok(OwnedRoute {
                destination: r["dst"].as_str().ok_or("invalid route destination")?.into(),
                interface: r["dev"]
                    .as_str()
                    .ok_or("overlay route has no owned interface")?
                    .into(),
                gateway: r["gateway"].as_str().map(str::to_owned),
                metric: r["metric"]
                    .as_u64()
                    .map(u32::try_from)
                    .transpose()
                    .map_err(|_| "invalid route metric")?,
                source: r["prefsrc"].as_str().map(str::to_owned),
                protocol: r["protocol"].as_str().map(str::to_owned),
                scope: r["scope"].as_str().map(str::to_owned),
            })
        })
        .transpose()?;
    let forwarding =
        String::from_utf8(required("sysctl", &["-n", "net.ipv4.ip_forward"], None).await?)
            .map_err(|_| "invalid forwarding inspection")?;
    let forwarding = match forwarding.trim() {
        "0" => false,
        "1" => true,
        _ => return Err("invalid forwarding state".into()),
    };
    let tables = json("nft", &["-j", "list", "tables"]).await?;
    let exists = tables["nftables"]
        .as_array()
        .ok_or("invalid firewall inspection")?
        .iter()
        .any(|v| v["table"]["family"] == "inet" && v["table"]["name"] == "lattice_overlay");
    let owned_firewall = if exists {
        Some(
            String::from_utf8(
                required("nft", &["list", "table", "inet", "lattice_overlay"], None).await?,
            )
            .map_err(|_| "invalid owned firewall inspection")?,
        )
    } else {
        None
    };
    Ok(NetworkSnapshot {
        interface_name: interface.into(),
        overlay_cidr: overlay.into(),
        existed,
        link_up,
        transport_public_key,
        wireguard_config,
        addresses,
        route,
        forwarding,
        owned_firewall,
    })
}
async fn replace_firewall(rules: &str) -> Result<(), String> {
    // The empty declaration makes replacing an absent or existing owned table atomic.
    let batch =
        format!("table inet lattice_overlay {{ }}\ndelete table inet lattice_overlay\n{rules}");
    required("nft", &["-f", "-"], Some(&batch)).await?;
    Ok(())
}
async fn restore(
    snapshot: NetworkSnapshot,
    expected_transport: &str,
    applied_address: &str,
    restore_forwarding: bool,
) -> Result<(), String> {
    let i = &snapshot.interface_name;
    let current = capture(i, &snapshot.overlay_cidr).await?;
    if current
        .transport_public_key
        .as_deref()
        .is_some_and(|key| key != expected_transport)
        || current.route.as_ref().is_some_and(|r| r.interface != *i)
    {
        return Err("rollback will not replace an external network owner".into());
    }
    if !snapshot.existed && current.addresses.iter().any(|a| a != applied_address) {
        return Err("rollback found unrelated addresses on a newly created interface".into());
    }
    if let Some(rules) = &snapshot.owned_firewall {
        replace_firewall(rules).await?;
    } else if current.owned_firewall.is_some() {
        required("nft", &["delete", "table", "inet", "lattice_overlay"], None).await?;
    }
    if snapshot.existed {
        if !current.existed {
            required("ip", &["link", "add", "dev", i, "type", "wireguard"], None).await?;
        }
        let conf = snapshot
            .wireguard_config
            .as_deref()
            .ok_or("rollback transport snapshot unavailable")?;
        required("wg", &["syncconf", i, "/dev/stdin"], Some(conf)).await?;
        if current.addresses.iter().any(|a| a == applied_address)
            && !snapshot.addresses.iter().any(|a| a == applied_address)
        {
            required("ip", &["address", "del", applied_address, "dev", i], None).await?;
        }
        for address in &snapshot.addresses {
            required("ip", &["address", "replace", address, "dev", i], None).await?;
        }
        required(
            "ip",
            &[
                "link",
                "set",
                "dev",
                i,
                if snapshot.link_up { "up" } else { "down" },
            ],
            None,
        )
        .await?;
    } else if current.existed {
        required("ip", &["link", "delete", "dev", i], None).await?;
    }
    if let Some(route) = &snapshot.route {
        let mut args = vec![
            "route".to_string(),
            "replace".into(),
            route.destination.clone(),
            "dev".into(),
            route.interface.clone(),
        ];
        if let Some(gateway) = &route.gateway {
            args.extend(["via".into(), gateway.clone()]);
        }
        if let Some(metric) = route.metric {
            args.extend(["metric".into(), metric.to_string()]);
        }
        if let Some(source) = &route.source {
            args.extend(["src".into(), source.clone()]);
        }
        if let Some(protocol) = &route.protocol {
            args.extend(["proto".into(), protocol.clone()]);
        }
        if let Some(scope) = &route.scope {
            args.extend(["scope".into(), scope.clone()]);
        }
        let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
        required("ip", &refs, None).await?;
    } else if snapshot.existed && current.route.is_some() {
        required(
            "ip",
            &["route", "del", &snapshot.overlay_cidr, "dev", i],
            None,
        )
        .await?;
    }
    if restore_forwarding && current.forwarding != snapshot.forwarding {
        required(
            "sysctl",
            &[
                "-w",
                if snapshot.forwarding {
                    "net.ipv4.ip_forward=1"
                } else {
                    "net.ipv4.ip_forward=0"
                },
            ],
            None,
        )
        .await?;
    }
    Ok(())
}
impl NetworkRunner for SystemRunner {
    fn capture<'a>(
        &'a self,
        interface: &'a str,
        overlay: &'a str,
    ) -> NetworkFuture<'a, NetworkSnapshot> {
        Box::pin(capture(interface, overlay))
    }
    fn execute<'a>(&'a self, command: NetworkCommand) -> NetworkFuture<'a, ()> {
        Box::pin(async move {
            available()?;
            match command {
                NetworkCommand::CreateInterface { interface } => {
                    required(
                        "ip",
                        &["link", "add", "dev", &interface, "type", "wireguard"],
                        None,
                    )
                    .await?;
                }
                NetworkCommand::SyncWireguard { interface, config } => {
                    required("wg", &["syncconf", &interface, "/dev/stdin"], Some(&config)).await?;
                }
                NetworkCommand::SetAddress { interface, address } => {
                    required(
                        "ip",
                        &["address", "replace", &address, "dev", &interface],
                        None,
                    )
                    .await?;
                    required("ip", &["link", "set", "dev", &interface, "up"], None).await?;
                }
                NetworkCommand::SetRoute { interface, overlay } => {
                    required(
                        "ip",
                        &["route", "replace", &overlay, "dev", &interface],
                        None,
                    )
                    .await?;
                }
                NetworkCommand::SetForwarding { enabled } => {
                    required(
                        "sysctl",
                        &[
                            "-w",
                            if enabled {
                                "net.ipv4.ip_forward=1"
                            } else {
                                "net.ipv4.ip_forward=0"
                            },
                        ],
                        None,
                    )
                    .await?;
                }
                NetworkCommand::ReplaceOwnedFirewall { rules } => replace_firewall(&rules).await?,
                NetworkCommand::DisconnectOwned {
                    interface,
                    transport_public_key,
                    overlay,
                } => {
                    let current = capture(&interface, &overlay).await?;
                    if current.existed {
                        if current.transport_public_key.as_deref()
                            != Some(transport_public_key.as_str())
                            || current
                                .route
                                .as_ref()
                                .is_some_and(|r| r.interface != interface)
                        {
                            return Err("disconnect cannot delete another transport owner".into());
                        }
                        required("ip", &["link", "delete", "dev", &interface], None).await?;
                    }
                }
                NetworkCommand::Restore {
                    snapshot,
                    transport_public_key,
                    applied_address,
                    restore_forwarding,
                } => {
                    restore(
                        snapshot,
                        &transport_public_key,
                        &applied_address,
                        restore_forwarding,
                    )
                    .await?
                }
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn foreign_lan_addresses_and_more_specific_routes_must_not_overlap_the_overlay() {
        let empty = serde_json::json!([]);
        let addresses = serde_json::json!([{"ifname":"eth0","addr_info":[{"family":"inet","local":"10.78.2.5","prefixlen":24}]}]);
        assert!(reject_foreign_overlap("wg-test", "10.78.0.0/16", &addresses, &empty).is_err());
        let routes = serde_json::json!([{"dst":"10.78.2.0/24","dev":"foreign-vpn"}]);
        assert!(reject_foreign_overlap("wg-test", "10.78.0.0/16", &empty, &routes).is_err());
        let safe = serde_json::json!([{"dst":"default","dev":"eth0"},{"dst":"192.0.2.0/24","dev":"eth0"},{"dst":"10.78.0.0/16","dev":"wg-test"}]);
        assert!(reject_foreign_overlap("wg-test", "10.78.0.0/16", &empty, &safe).is_ok());
    }
}
