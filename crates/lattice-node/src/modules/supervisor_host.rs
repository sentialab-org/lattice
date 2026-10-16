//! A private Supervisor exchange returns public membership and forwarding proof only.
use crate::{AppState, identity::unix_time_ms};
use lattice_protocol::*;
use std::path::Path;
#[derive(serde::Deserialize)]
struct Health {
    fingerprint: String,
    control_id: String,
    network_id: String,
    control_role: String,
}
pub(super) struct ProvisionedHost {
    pub certificate_id: Option<String>,
}
pub(super) async fn provision(
    s: &AppState,
    data: &Path,
    adopt_gateway: bool,
    budget: Option<u64>,
) -> Result<ProvisionedHost, String> {
    let identity = s.identity.read().await.clone();
    let node = identity.identity();
    let terms = s
        .setup
        .lock()
        .await
        .terms
        .clone()
        .ok_or("owner participation consent required")?;
    let token: String = serde_json::from_slice(&super::handoff::private_bytes(
        &data.join("module-service-token.json"),
        512,
    )?)
    .map_err(|_| "private service credential corrupt")?;
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("private service credential rejected".into());
    }
    let client = super::private_client(data)?;
    let health: Health = client
        .get("http://localhost/health")
        .send()
        .await
        .map_err(|_| "private Supervisor unavailable")?
        .json()
        .await
        .map_err(|_| "private Supervisor health invalid")?;
    if !matches!(
        health.control_role.as_str(),
        "supervisor" | "bootstrapper" | "combined"
    ) {
        return Err("selected module is not a Supervisor".into());
    }
    let join = PublicJoinClaim {
        schema_version: PRODUCT_SCHEMA_VERSION,
        terms: Some(terms),
        enrollment: EnrollmentClaim {
            protocol_version: PROTOCOL_VERSION,
            request_id: uuid::Uuid::new_v4().to_string(),
            node_id: node.node_id.clone(),
            node_name: node.node_name.clone(),
            platform: node.platform.clone(),
            architecture: node.architecture.clone(),
            public_key: node.public_key.clone(),
            client_version: env!("CARGO_PKG_VERSION").into(),
            issued_at_ms: unix_time_ms(),
        },
    };
    let public = crate::network_manager::transport_public_key(s).await?;
    let claim = LocalHostProvisionClaim {
        schema_version: AUTHORITY_VERSION,
        join: PublicJoinRequest {
            signature: lattice_crypto::sign(identity.private_key(), &join)?,
            claim: join,
        },
        wireguard_public_key: lattice_crypto::encode_wireguard_key(&public),
        interface_name: crate::network::configured_interface_name(),
        adopt_gateway,
        forwarding_limit_bps: if adopt_gateway { budget } else { None },
    };
    let request = LocalHostProvisionRequest {
        signature: lattice_crypto::sign_domain(identity.private_key(), LOCAL_HOST_DOMAIN, &claim)?,
        claim,
    };
    let mut response = client
        .post("http://localhost/api/v2/local/host")
        .header("x-lattice-module-service", token)
        .json(&request)
        .send()
        .await
        .map_err(|_| "private host provisioning unavailable")?;
    if !response.status().is_success() {
        return Err("private host provisioning rejected; check membership and Relay grants".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "private host reply unreadable")?
    {
        if bytes.len() + chunk.len() > 8 * 1024 * 1024 {
            return Err("private host reply too large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let response: LocalHostProvisionResponse =
        serde_json::from_slice(&bytes).map_err(|_| "private host reply invalid")?;
    let receipt = &response.join.receipt;
    let root = &receipt.control_public_key;
    let membership = &response.join.membership;
    if receipt.node_id != node.node_id
        || receipt.control_id != health.control_id
        || receipt.request_id != request.claim.join.claim.enrollment.request_id
        || lattice_crypto::fingerprint(root)? != health.fingerprint
        || membership.membership.node_id != node.node_id
        || membership.membership.node_public_key != node.public_key
        || membership.membership.network_id != health.network_id
    {
        return Err("private host reply identity binding rejected".into());
    }
    lattice_crypto::verify(root, &response.join.signature, receipt)?;
    lattice_crypto::verify(root, &membership.signature, &membership.membership)?;
    if let Some(pin) = identity.bootstrap() {
        if pin.bootstrap_public_key != *root || pin.bootstrap_id != receipt.control_id {
            return Err("private Supervisor conflicts with the pinned authority".into());
        }
    } else {
        s.identity
            .write()
            .await
            .set_bootstrap(BootstrapTrust {
                bootstrap_url: "http://127.0.0.1:7443".into(),
                bootstrap_id: receipt.control_id.clone(),
                bootstrap_public_key: root.clone(),
                bootstrap_fingerprint: health.fingerprint,
                enrolled_at_ms: unix_time_ms(),
            })
            .await?;
    }
    crate::trust_store::ingest(
        s,
        response
            .join
            .authority
            .as_ref()
            .ok_or("Supervisor membership certificate required")?,
    )
    .await?;
    let certificate_id = if let Some(intent) = response.gateway_intent {
        crate::network_manager::cache_gateway(s, &intent).await?;
        Some(intent.certificate.certificate.certificate_id)
    } else if adopt_gateway {
        return Err("Supervisor forwarding intent required".into());
    } else {
        None
    };
    let mut config = s.config.read().await.clone();
    if config.bootstrap_url.is_none() {
        config.bootstrap_url = Some(
            s.identity
                .read()
                .await
                .bootstrap()
                .ok_or("Supervisor pin required")?
                .bootstrap_url
                .clone(),
        );
        crate::save_config(&s.config_path, &config).await?;
        *s.config.write().await = config;
    }
    Ok(ProvisionedHost { certificate_id })
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Stopped;
    impl super::super::handoff::LegacyWriterStopper for Stopped {
        fn stop<'a>(&'a self) -> super::super::handoff::HandoffFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
    }
    #[tokio::test]
    #[cfg(unix)]
    async fn a_fresh_supervisor_host_pins_public_authority_and_caches_its_preserved_gateway_plan() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("authority");
        lattice_control::auth::credentials::provision(
            &source.join("account.json"),
            "owner",
            b"fixture-owner-password",
        )
        .unwrap();
        let root = lattice_control::load_state(
            &source,
            "legacy".into(),
            None,
            "http://127.0.0.1:7443".into(),
            "supervisor".into(),
        )
        .await
        .unwrap();
        let token = "1".repeat(64);
        crate::setup::write_private(&source.join("module-service-token.json"), &token).unwrap();
        let node = crate::load_state_at(directory.path().join("node/node.json"))
            .await
            .unwrap();
        crate::setup::accept_participation(
            &node,
            lattice_protocol::PARTICIPATION_VERSION,
            lattice_protocol::PARTICIPATION_SHA256,
        )
        .await
        .unwrap();
        node.config.write().await.network.enabled = true;
        let original = node.identity.read().await.identity().clone();
        super::super::handoff::adopt_gateway(&node, &source, &Stopped)
            .await
            .unwrap();
        let app = lattice_control::host_provision::router(
            lattice_control::build_router(root.clone()),
            root.clone(),
        );
        let (shutdown, watch) = tokio::sync::watch::channel(false);
        let backend = source.clone();
        let task = tokio::spawn(async move {
            lattice_control::private_backend::serve(app, &backend, watch)
                .await
                .unwrap();
        });
        for _ in 0..100 {
            if source.join("module-http.sock").exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let result = provision(&node, &source, true, Some(4_000_000))
            .await
            .unwrap();
        assert_eq!(result.certificate_id.is_some(), true);
        let identity = node.identity.read().await;
        assert_eq!(identity.identity(), &original);
        assert_eq!(
            identity.bootstrap().unwrap().bootstrap_public_key,
            root.control.public_key
        );
        assert!(identity.offline_authority_required());
        drop(identity);
        assert!(
            node.offline_authority
                .lock()
                .await
                .checked()
                .unwrap()
                .unwrap()
                .require_relay(
                    &original.node_id,
                    &original.public_key,
                    crate::identity::unix_time_ms()
                )
                .is_ok()
        );
        let status = node.network_manager.lock().await.status();
        assert_eq!(status.desired_revision, 1);
        assert_eq!(
            status.applied_revision, None,
            "provisioning cannot pretend that OS networking has already been applied"
        );
        {
            let mut modules = node.modules.lock().await;
            modules.set_enabled(ModuleKind::Supervisor, None, Some(source.clone()), true);
            modules
                .records
                .get_mut(&ModuleKind::Supervisor)
                .unwrap()
                .forwarding_limit_bps = Some(4_000_000);
            let record = modules.records[&ModuleKind::Supervisor].clone();
            super::super::complete_host_provision(&node, &mut modules, &source, &record)
                .await
                .unwrap();
        }
        let saved =
            super::super::ModuleManager::load(&node.config_path.with_file_name("modules.json"))
                .unwrap();
        assert!(saved.records[&ModuleKind::Supervisor].host_provisioned);
        assert_eq!(saved.forwarding_budget(), Some(4_000_000));
        shutdown.send(true).unwrap();
        task.await.unwrap();
    }
}
