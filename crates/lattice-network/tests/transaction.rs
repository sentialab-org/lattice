mod support;
use lattice_network::{
    NetworkCommand, NetworkFuture, NetworkRunner, NetworkSnapshot, OwnedRoute, apply_gateway,
    recover_gateway_transaction,
};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use support::*;
struct Fake {
    state: Mutex<NetworkSnapshot>,
    events: Mutex<Vec<&'static str>>,
    fail: Option<&'static str>,
    failed: AtomicBool,
    fail_restore: AtomicBool,
    unrelated_firewall: String,
}
impl Fake {
    fn new(existed: bool, fail: Option<&'static str>) -> Self {
        Self {
            state: Mutex::new(NetworkSnapshot {
                interface_name: "lattice0".into(),
                overlay_cidr: "10.77.0.0/16".into(),
                existed,
                link_up: existed,
                transport_public_key: existed.then(|| transport(4)),
                wireguard_config: existed.then(|| "original private configuration".into()),
                addresses: if existed {
                    vec!["10.77.0.4/32".into()]
                } else {
                    vec![]
                },
                route: existed.then(|| OwnedRoute {
                    destination: "10.77.0.0/16".into(),
                    interface: "lattice0".into(),
                    gateway: None,
                    metric: Some(37),
                    source: Some("10.77.0.4".into()),
                    protocol: Some("static".into()),
                    scope: Some("link".into()),
                }),
                forwarding: true,
                owned_firewall: Some("table inet lattice_overlay { chain old { } }".into()),
            }),
            events: Mutex::new(vec![]),
            fail,
            failed: AtomicBool::new(false),
            fail_restore: AtomicBool::new(false),
            unrelated_firewall: "table inet unrelated { preserve everything }".into(),
        }
    }
}
impl NetworkRunner for Fake {
    fn capture<'a>(
        &'a self,
        _interface: &'a str,
        _overlay: &'a str,
    ) -> NetworkFuture<'a, NetworkSnapshot> {
        Box::pin(async move { Ok(self.state.lock().unwrap().clone()) })
    }
    fn execute<'a>(&'a self, command: NetworkCommand) -> NetworkFuture<'a, ()> {
        Box::pin(async move {
            let kind = command.kind();
            self.events.lock().unwrap().push(kind);
            let mut state = self.state.lock().unwrap();
            match command {
                NetworkCommand::CreateInterface { .. } => state.existed = true,
                NetworkCommand::SyncWireguard { config, .. } => {
                    state.wireguard_config = Some(config);
                    state.transport_public_key = Some(transport(4));
                }
                NetworkCommand::SetAddress { address, .. } => {
                    state.link_up = true;
                    if !state.addresses.contains(&address) {
                        state.addresses.push(address);
                    }
                }
                NetworkCommand::SetRoute { interface, overlay } => {
                    state.route = Some(OwnedRoute {
                        destination: overlay,
                        interface,
                        gateway: None,
                        metric: None,
                        source: None,
                        protocol: None,
                        scope: None,
                    })
                }
                NetworkCommand::SetForwarding { enabled } => state.forwarding = enabled,
                NetworkCommand::ReplaceOwnedFirewall { rules } => {
                    state.owned_firewall = Some(rules)
                }
                NetworkCommand::DisconnectOwned { .. } => {
                    state.existed = false;
                    state.addresses.clear();
                    state.route = None;
                }
                NetworkCommand::Restore { snapshot, .. } => {
                    if self.fail_restore.load(Ordering::SeqCst) {
                        return Err("fixture rollback failure".into());
                    }
                    *state = snapshot;
                }
            }
            if self.fail == Some(kind) && !self.failed.swap(true, Ordering::SeqCst) {
                return Err("fixture interrupted apply".into());
            }
            Ok(())
        })
    }
}
fn value(r: &Fake) -> serde_json::Value {
    serde_json::to_value(&*r.state.lock().unwrap()).unwrap()
}
#[tokio::test]
async fn failed_steps_restore_original_interface_routes_forwarding_and_owned_firewall() {
    let (cache, intent) = fixture();
    let plan = check(&cache, &intent).unwrap();
    for step in [
        "create",
        "wireguard",
        "address",
        "route",
        "forwarding",
        "firewall",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transaction.json");
        let runner = Fake::new(step != "create", Some(step));
        let before = value(&runner);
        assert!(
            apply_gateway(&runner, &plan, &[4; 32], 4_000_000, &path)
                .await
                .is_err(),
            "step {step}"
        );
        assert_eq!(
            value(&runner),
            before,
            "rollback must restore all owned state after {step}"
        );
        assert_eq!(
            runner.unrelated_firewall,
            "table inet unrelated { preserve everything }"
        );
        assert!(runner.events.lock().unwrap().contains(&"restore"));
    }
}
#[tokio::test]
async fn interrupted_rollback_is_recovered_before_new_work() {
    let (cache, intent) = fixture();
    let plan = check(&cache, &intent).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transaction.json");
    let runner = Fake::new(true, Some("firewall"));
    let before = value(&runner);
    runner.fail_restore.store(true, Ordering::SeqCst);
    assert!(
        apply_gateway(&runner, &plan, &[4; 32], 4_000_000, &path)
            .await
            .is_err()
    );
    assert_ne!(value(&runner), before);
    runner.fail_restore.store(false, Ordering::SeqCst);
    assert!(
        recover_gateway_transaction(
            &runner,
            &path,
            "network-test",
            "lattice0",
            &transport(4),
            "10.77.0.0/16"
        )
        .await
        .unwrap()
    );
    assert_eq!(value(&runner), before);
}
#[tokio::test]
async fn another_interfaces_transport_key_or_route_cannot_be_overwritten() {
    let (cache, intent) = fixture();
    let plan = check(&cache, &intent).unwrap();
    for other_route in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transaction.json");
        let runner = Fake::new(true, None);
        if other_route {
            runner
                .state
                .lock()
                .unwrap()
                .route
                .as_mut()
                .unwrap()
                .interface = "other0".into();
        } else {
            runner.state.lock().unwrap().transport_public_key = Some(transport(9));
        }
        assert!(
            apply_gateway(&runner, &plan, &[4; 32], 4_000_000, &path)
                .await
                .is_err()
        );
        assert!(runner.events.lock().unwrap().is_empty());
    }
}
#[tokio::test]
async fn successful_transaction_records_commit_and_preserves_unrelated_rules() {
    let (cache, intent) = fixture();
    let plan = check(&cache, &intent).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transaction.json");
    let runner = Fake::new(true, None);
    let applied = apply_gateway(&runner, &plan, &[4; 32], 4_000_000, &path)
        .await
        .unwrap();
    assert_eq!(applied.revision, 1);
    let journal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(journal["phase"], "committed");
    assert_eq!(
        runner.unrelated_firewall,
        "table inet unrelated { preserve everything }"
    );
    assert!(
        !recover_gateway_transaction(
            &runner,
            &path,
            "network-test",
            "lattice0",
            &transport(4),
            "10.77.0.0/16"
        )
        .await
        .unwrap()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
            0
        );
    }
}

#[tokio::test]
async fn base_plan_preserves_host_forwarding_and_blocks_only_its_owned_interface() {
    let d = lattice_protocol::NetworkDesiredConfig {
        schema_version: 1,
        node_id: "node-test".into(),
        control_id: "root-test".into(),
        network_id: "network-test".into(),
        revision: 3,
        enabled: true,
        status: lattice_protocol::NetworkNodeStatus::Allocated,
        virtual_ipv4: Some("10.77.0.4/32".into()),
        overlay_cidr: Some("10.77.0.0/16".into()),
        gateway_ipv4: Some("10.77.0.1".into()),
        gateway_endpoint: Some("198.51.100.1:51820".into()),
        gateway_wireguard_public_key: Some(transport(5)),
        allowed_overlay_routes: vec!["10.77.0.0/16".into()],
        keepalive_seconds: 25,
        issued_at_ms: 1000,
    };
    let conf = format!(
        "[Interface]\nPrivateKey = {}\nAddress = 10.77.0.4/32\n[Peer]\nPublicKey = {}\nEndpoint = 198.51.100.1:51820\nAllowedIPs = 10.77.0.0/16\nPersistentKeepalive = 25\n",
        lattice_crypto::encode_wireguard_key(&[4; 32]),
        transport(5)
    );
    let plan =
        lattice_network::validate_base_configuration(&d, "lattice0", &transport(4), &conf).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let runner = Fake::new(true, None);
    lattice_network::apply_base(&runner, &plan, &directory.path().join("transaction.json"))
        .await
        .unwrap();
    assert!(!runner.events.lock().unwrap().contains(&"forwarding"));
    let state = runner.state.lock().unwrap();
    assert!(
        state.forwarding,
        "unrelated VM routing must retain its host setting"
    );
    let rules = state.owned_firewall.as_deref().unwrap();
    assert!(rules.contains("iifname \"lattice0\" drop"));
    assert!(!rules.contains("flush ruleset"));
}

#[tokio::test]
async fn relay_withdrawal_blocks_only_forwarding_and_preserves_keys_addresses_and_vm_routing() {
    let runner = Fake::new(true, None);
    let before = runner.state.lock().unwrap().clone();
    lattice_network::withdraw_forwarding(&runner, "lattice0", &transport(4), "10.77.0.0/16")
        .await
        .unwrap();
    let after = runner.state.lock().unwrap().clone();
    assert_eq!(after.transport_public_key, before.transport_public_key);
    assert_eq!(after.wireguard_config, before.wireguard_config);
    assert_eq!(after.addresses, before.addresses);
    assert_eq!(after.route, before.route);
    assert_eq!(after.forwarding, before.forwarding);
    assert_eq!(*runner.events.lock().unwrap(), vec!["firewall"]);
    assert!(
        after
            .owned_firewall
            .unwrap()
            .contains("iifname \"lattice0\" drop")
    );
    runner.events.lock().unwrap().clear();
    assert!(
        lattice_network::withdraw_forwarding(&runner, "lattice0", &transport(9), "10.77.0.0/16")
            .await
            .is_err()
    );
    assert!(runner.events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn disconnect_cannot_delete_an_interface_owned_by_a_different_transport() {
    let runner = Fake::new(true, None);
    assert!(
        lattice_network::disconnect_owned(&runner, "lattice0", &transport(9), "10.77.0.0/16")
            .await
            .is_err()
    );
    assert!(runner.events.lock().unwrap().is_empty());
    lattice_network::disconnect_owned(&runner, "lattice0", &transport(4), "10.77.0.0/16")
        .await
        .unwrap();
    let state = runner.state.lock().unwrap();
    assert!(!state.existed);
    assert!(
        state.forwarding,
        "the host may still route unrelated VM traffic"
    );
    assert!(
        runner
            .events
            .lock()
            .unwrap()
            .starts_with(&["firewall", "disconnect"])
    );
    assert_eq!(
        runner.unrelated_firewall,
        "table inet unrelated { preserve everything }"
    );
}
