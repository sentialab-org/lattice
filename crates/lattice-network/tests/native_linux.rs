#![cfg(target_os = "linux")]
mod support;
use lattice_crypto::{encode_wireguard_key, sign_domain};
use lattice_network::{NetworkCommand, NetworkFuture, NetworkRunner, SystemRunner};
use lattice_protocol::{NETWORK_INTENT_DOMAIN, NetworkPeerIntent};
use std::{
    io::{Read, Write},
    process::Stdio,
    sync::atomic::{AtomicBool, Ordering},
};
use support::*;

fn isolated() {
    assert_eq!(
        std::env::var("LATTICE_NETWORK_NAMESPACE_TEST").as_deref(),
        Ok("1")
    );
    assert_eq!(unsafe { libc::geteuid() }, 0);
    for kind in ["net", "mnt"] {
        assert_ne!(
            std::fs::read_link(format!("/proc/self/ns/{kind}")).unwrap(),
            std::fs::read_link(format!("/proc/1/ns/{kind}")).unwrap(),
            "native acceptance requires private network and mount namespaces"
        );
    }
}
async fn command(program: &str, args: &[&str], input: Option<&str>) -> Vec<u8> {
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .kill_on_drop(true)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("native fixture tool unavailable");
    if let Some(text) = input {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(text.as_bytes()).await.unwrap();
    }
    let result = tokio::time::timeout(std::time::Duration::from_secs(15), child.wait_with_output())
        .await
        .expect("native fixture timed out")
        .unwrap();
    assert!(
        result.status.success(),
        "native fixture command failed: {program}"
    );
    result.stdout
}
async fn client(name: &str, own: &str, underlay: &str, server: &str, port: &str, seed: u8) {
    command("ip", &["netns", "add", name], None).await;
    let outer = format!("veth-{name}");
    command(
        "ip",
        &[
            "link", "add", &outer, "type", "veth", "peer", "name", "eth0", "netns", name,
        ],
        None,
    )
    .await;
    command("ip", &["address", "add", underlay, "dev", &outer], None).await;
    command("ip", &["link", "set", &outer, "up"], None).await;
    let peer = if seed == 5 {
        "192.0.2.2/30"
    } else {
        "192.0.2.6/30"
    };
    command(
        "ip",
        &["-n", name, "address", "add", peer, "dev", "eth0"],
        None,
    )
    .await;
    command("ip", &["-n", name, "link", "set", "eth0", "up"], None).await;
    command("ip", &["-n", name, "link", "set", "lo", "up"], None).await;
    command(
        "ip",
        &["-n", name, "link", "add", "wg0", "type", "wireguard"],
        None,
    )
    .await;
    let conf = format!(
        "[Interface]\nPrivateKey = {}\nListenPort = {port}\n[Peer]\nPublicKey = {}\nEndpoint = {server}:51820\nAllowedIPs = 10.77.0.0/16\nPersistentKeepalive = 1\n",
        encode_wireguard_key(&[seed; 32]),
        transport(4)
    );
    command(
        "ip",
        &["netns", "exec", name, "wg", "setconf", "wg0", "/dev/stdin"],
        Some(&conf),
    )
    .await;
    command(
        "ip",
        &["-n", name, "address", "add", own, "dev", "wg0"],
        None,
    )
    .await;
    command("ip", &["-n", name, "link", "set", "wg0", "up"], None).await;
    command(
        "ip",
        &["-n", name, "route", "add", "10.77.0.0/16", "dev", "wg0"],
        None,
    )
    .await;
}
struct InterruptOnce {
    failed: AtomicBool,
}
impl NetworkRunner for InterruptOnce {
    fn capture<'a>(
        &'a self,
        interface: &'a str,
        overlay: &'a str,
    ) -> NetworkFuture<'a, lattice_network::NetworkSnapshot> {
        SystemRunner.capture(interface, overlay)
    }
    fn execute<'a>(&'a self, command: NetworkCommand) -> NetworkFuture<'a, ()> {
        Box::pin(async move {
            let firewall = command.kind() == "firewall";
            SystemRunner.execute(command).await?;
            if firewall && !self.failed.swap(true, Ordering::SeqCst) {
                return Err("native interrupted apply".into());
            }
            Ok(())
        })
    }
}
async fn probe(executable: &str, blocked: bool) -> bool {
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        tokio::process::Command::new("ip")
            .args([
                "netns",
                "exec",
                "client-a",
                executable,
                "native_echo_probe",
                "--ignored",
                "--exact",
            ])
            .env("LATTICE_ECHO_EXPECT_BLOCK", if blocked { "1" } else { "0" })
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output(),
    )
    .await;
    result.is_ok_and(|r| {
        r.is_ok_and(|o| {
            o.status.success()
                && String::from_utf8_lossy(&o.stdout).contains("test native_echo_probe ... ok")
        })
    })
}
#[test]
#[ignore = "invoked as a helper by native_linux_gateway"]
fn native_echo_server() {
    isolated();
    let listener = std::net::TcpListener::bind("10.77.0.6:38081").unwrap();
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        let mut bytes = [0; 64];
        if let Ok(count) = stream.read(&mut bytes) {
            let _ = stream.write_all(&bytes[..count]);
        }
    }
}
#[test]
#[ignore = "invoked as a helper by native_linux_gateway"]
fn native_echo_probe() {
    isolated();
    let result = (|| -> std::io::Result<()> {
        let mut stream = std::net::TcpStream::connect_timeout(
            &"10.77.0.6:38081".parse().unwrap(),
            std::time::Duration::from_secs(2),
        )?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(2)))?;
        stream.write_all(b"lattice-native-forwarding")?;
        let mut bytes = [0; 25];
        stream.read_exact(&mut bytes)?;
        if &bytes != b"lattice-native-forwarding" {
            return Err(std::io::Error::other("echo mismatch"));
        }
        Ok(())
    })();
    if std::env::var("LATTICE_ECHO_EXPECT_BLOCK").as_deref() == Ok("1") {
        assert!(result.is_err(), "withdrawn Relay still forwarded TCP");
    } else {
        assert!(result.is_ok(), "authorized Relay did not forward TCP");
    }
}
#[tokio::test]
#[ignore = "requires root inside disposable private mount/network namespaces"]
async fn native_linux_gateway() {
    isolated();
    command("ip", &["link", "set", "lo", "up"], None).await;
    command(
        "nft",
        &["-f", "-"],
        Some("table inet unrelated {\n chain sentinel {\n }\n}\n"),
    )
    .await;
    let unrelated = command("nft", &["list", "table", "inet", "unrelated"], None).await;
    client(
        "client-a",
        "10.77.0.5/32",
        "192.0.2.1/30",
        "192.0.2.1",
        "51821",
        5,
    )
    .await;
    client(
        "client-b",
        "10.77.0.6/32",
        "192.0.2.5/30",
        "192.0.2.5",
        "51822",
        6,
    )
    .await;
    let (cache, mut signed) = fixture();
    signed.intent.peers = vec![
        NetworkPeerIntent {
            node_id: "client-a".into(),
            public_key: transport(5),
            allowed_ipv4: "10.77.0.5/32".into(),
            endpoint: Some("192.0.2.2:51821".into()),
        },
        NetworkPeerIntent {
            node_id: "client-b".into(),
            public_key: transport(6),
            allowed_ipv4: "10.77.0.6/32".into(),
            endpoint: Some("192.0.2.6:51822".into()),
        },
    ];
    signed.signature = sign_domain(&[1; 32], NETWORK_INTENT_DOMAIN, &signed.intent).unwrap();
    let plan = check(&cache, &signed).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let journal = directory.path().join("transaction.json");
    lattice_network::apply_gateway(&SystemRunner, &plan, &[4; 32], 4_000_000, &journal)
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8(command("wg", &["show", "lattice0", "public-key"], None).await)
            .unwrap()
            .trim(),
        transport(4)
    );
    let executable = std::env::current_exe().unwrap();
    let executable = executable.to_str().unwrap();
    let mut server = tokio::process::Command::new("ip")
        .args([
            "netns",
            "exec",
            "client-b",
            executable,
            "native_echo_server",
            "--ignored",
            "--exact",
        ])
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut reachable = false;
    for _ in 0..5 {
        if probe(executable, false).await {
            reachable = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(
        reachable,
        "TCP must pass through the actual WireGuard Relay"
    );
    let before = SystemRunner
        .capture("lattice0", "10.77.0.0/16")
        .await
        .unwrap();
    let interruption = InterruptOnce {
        failed: AtomicBool::new(false),
    };
    assert!(
        lattice_network::apply_gateway(&interruption, &plan, &[4; 32], 4_000_000, &journal)
            .await
            .is_err()
    );
    let restored = SystemRunner
        .capture("lattice0", "10.77.0.0/16")
        .await
        .unwrap();
    assert!(
        before.wireguard_config == restored.wireguard_config,
        "native rollback must preserve the complete private transport configuration"
    );
    assert_eq!(before.addresses, restored.addresses);
    assert_eq!(before.route, restored.route);
    assert_eq!(before.forwarding, restored.forwarding);
    assert!(
        probe(executable, false).await,
        "TCP must survive native rollback"
    );
    lattice_network::withdraw_forwarding(&SystemRunner, "lattice0", &transport(4), "10.77.0.0/16")
        .await
        .unwrap();
    assert!(
        probe(executable, true).await,
        "TCP must stop after forwarding withdrawal"
    );
    let after = SystemRunner
        .capture("lattice0", "10.77.0.0/16")
        .await
        .unwrap();
    assert_eq!(after.transport_public_key, before.transport_public_key);
    assert_eq!(after.addresses, before.addresses);
    assert_eq!(after.forwarding, before.forwarding);
    assert_eq!(
        command("nft", &["list", "table", "inet", "unrelated"], None).await,
        unrelated
    );
    server.start_kill().unwrap();
    let _ = server.wait().await;
    for name in ["client-a", "client-b"] {
        command("ip", &["netns", "del", name], None).await;
    }
}
