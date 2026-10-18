use super::*;
use lattice_protocol::*;
async fn assigned_node() -> (crate::setup::review_regressions::Fixture, [u8; 32]) {
    let mut fixture =
        crate::setup::review_regressions::fixture_with_network("10.79.0.0/16", "10.79.0.1").await;
    crate::setup::review_regressions::reconcile_ready(&fixture)
        .await
        .unwrap();
    let control: serde_json::Value = serde_json::from_slice(
        &std::fs::read(crate::setup::master_dir(&fixture.node).join("control-identity.json"))
            .unwrap(),
    )
    .unwrap();
    let id = control["control_id"].as_str().unwrap();
    let key = control["public_key"].as_str().unwrap();
    crate::setup::select_master(&fixture.node, Some(id.into()))
        .await
        .unwrap();
    let target = crate::setup::master_catalog(&fixture.node)
        .await
        .unwrap()
        .into_iter()
        .find(|master| master.control_id == id)
        .unwrap();
    fixture
        .node
        .identity
        .write()
        .await
        .set_trust(ControlTrust {
            control_url: format!("http://{}:7443", target.overlay_ipv4),
            control_id: id.into(),
            control_public_key: key.into(),
            control_fingerprint: lattice_crypto::fingerprint(key).unwrap(),
            policy_revision: 1,
            enrolled_at_ms: unix_time_ms(),
        })
        .await
        .unwrap();
    let lease:JobLeaseStatus=serde_json::from_value(serde_json::json!({
        "lease":{"lease_id":"recovery-lease","node_id":fixture.node.identity.read().await.identity().node_id,"offer":{"job_id":"recovery-job","workload_kind":"research","runtime":"lattice-wasm","runtime_version":"fixture","artifact_id":"fixture","artifact_version":"fixture","limits":ResourceLimits::default(),"parameters":{},"expires_at_ms":u64::MAX},"issued_at_ms":unix_time_ms(),"decision_deadline_ms":u64::MAX,"expires_at_ms":u64::MAX},
        "state":"running","reason":null,"events":[],"pending_event":null
    })).unwrap();
    crate::setup::write_private(&fixture.node.active_lease_path, &lease).unwrap();
    *fixture.node.active_lease.write().await = Some(lease);
    let synthetic_endpoint = fixture
        .node
        .identity
        .read()
        .await
        .bootstrap()
        .unwrap()
        .bootstrap_url
        .clone();
    Arc::get_mut(&mut fixture.node)
        .expect("isolated fixture owner")
        .http = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(&synthetic_endpoint).unwrap())
        .timeout(Duration::from_millis(500))
        .build()
        .unwrap();
    fixture.server.abort();
    let secret =
        lattice_crypto::decode_key::<32>(control["private_key"].as_str().unwrap()).unwrap();
    (fixture, secret)
}
async fn command(
    state: &Arc<AppState>,
    secret: &[u8; 32],
    revision: u64,
    action: JobControlAction,
    patch: Option<ResourceLimitPatch>,
) -> SignedJobControlRevision {
    let lease = state.active_lease.read().await.clone().unwrap();
    let revision = JobControlRevision {
        protocol_version: PROTOCOL_VERSION,
        node_id: lease.lease.node_id,
        lease_id: lease.lease.lease_id,
        job_id: lease.lease.offer.job_id,
        revision,
        issued_at_ms: unix_time_ms(),
        expires_at_ms: unix_time_ms() + 60_000,
        action,
        resource_patch: patch,
        runtime_patch: None,
    };
    SignedJobControlRevision {
        signature: sign(secret, &revision).unwrap(),
        revision,
    }
}
#[tokio::test]
async fn offline_paused_assignment_keeps_controls_across_reload_and_missing_state_fails_closed() {
    let _serial = RECOVERY_SERIAL.lock().await;
    let _reset = RuntimeReset;
    let (fixture, secret) = assigned_node().await;
    let pause = command(&fixture.node, &secret, 1, JobControlAction::Pause, None).await;
    let paused = apply_control(&fixture.node, pause.clone())
        .await
        .expect("an assigned paused workload can remain dormant without a worker process");
    assert!(paused.ack.applied);
    assert_eq!(
        crate::build_status(&fixture.node).await.runtime_state,
        NodeRuntimeState::Paused,
        "telemetry must not call a retained paused assignment an executing worker"
    );
    assert_eq!(
        apply_control(&fixture.node, pause).await.unwrap().ack,
        paused.ack,
        "exact replay must retain its original acknowledgement"
    );
    let tighten = command(
        &fixture.node,
        &secret,
        2,
        JobControlAction::UpdateLimits,
        Some(ResourceLimitPatch {
            cpu_percent: Some(17),
            ..Default::default()
        }),
    )
    .await;
    assert_eq!(
        apply_control(&fixture.node, tighten)
            .await
            .unwrap()
            .ack
            .effective_limits
            .cpu_percent,
        17
    );
    let reloaded = crate::load_state_at(fixture.node.config_path.clone())
        .await
        .unwrap();
    let retained = reloaded.active_lease.read().await.clone().unwrap();
    let policy = reloaded.config.read().await.policy.clone();
    let restored = recovered_execution(&reloaded, &retained, &policy, None)
        .await
        .unwrap();
    assert_eq!(restored.limits.cpu_percent, 17);
    assert!(restored.paused);
    let mut tighter = policy;
    tighter.limits.cpu_percent = 9;
    assert_eq!(
        recovered_execution(&reloaded, &retained, &tighter, None)
            .await
            .unwrap()
            .limits
            .cpu_percent,
        9,
        "current owner ceilings still apply to recovered controls"
    );
    check_and_run(&reloaded)
        .await
        .expect("restart must keep paused work dormant");
    let path = control_state_path(&reloaded.config_path, "recovery-lease");
    assert!(path.exists());
    assert!(
        !job_work_dir(&reloaded.config_path, "recovery-lease")
            .join("descriptor.json")
            .exists()
    );
    std::fs::remove_file(path).unwrap();
    assert!(
        check_and_run(&reloaded)
            .await
            .unwrap_err()
            .contains("control checkpoint"),
        "a missing required checkpoint must not reset limits or pause state"
    );
    assert!(reloaded.active_lease.read().await.is_some());
}

#[tokio::test]
async fn signed_stop_cancels_an_expired_dormant_assignment_without_renewing_execution() {
    let _serial = RECOVERY_SERIAL.lock().await;
    let _reset = RuntimeReset;
    let (fixture, secret) = assigned_node().await;
    {
        let mut active = fixture.node.active_lease.write().await;
        let current = active.as_mut().unwrap();
        current.lease.expires_at_ms = unix_time_ms() - 1;
        crate::setup::write_private(&fixture.node.active_lease_path, current).unwrap();
    }
    let stop = command(&fixture.node, &secret, 1, JobControlAction::Stop, None).await;
    let retry = stop.clone();
    let ack = apply_control(&fixture.node, stop)
        .await
        .expect("execution expiry must not prevent an authenticated typed cancellation");
    assert!(ack.ack.applied);
    assert_eq!(ack.ack.runtime_state, JobState::Completed);
    let trust = fixture.node.identity.read().await.trust().cloned().unwrap();
    let previous = {
        let store = fixture.node.offline_authority.lock().await;
        store
            .checked()
            .unwrap()
            .unwrap()
            .require_master(
                &trust.control_id,
                &trust.control_public_key,
                &CommandScope::Workloads,
                unix_time_ms(),
            )
            .unwrap()
            .clone()
    };
    let issuer =
        lattice_crypto::decode_key::<32>(&fixture.coordinator.control.private_key).unwrap();
    let narrowed = lattice_crypto::authority::issue_certificate(
        &issuer,
        &previous.certificate.network_id,
        previous.certificate.subject.clone(),
        std::collections::BTreeSet::from([CommandScope::Workloads]),
        previous.certificate.revision + 1,
        unix_time_ms(),
    )
    .unwrap();
    crate::trust_store::ingest_presented(
        &fixture.node,
        &AuthorityContext {
            master_certificate: Some(narrowed.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        apply_control(&fixture.node, retry)
            .await
            .expect("cancellation requires Workloads scope without requiring ResourceControl")
            .ack,
        ack.ack
    );

    let directory = crate::setup::master_dir(&fixture.node);
    let authority_path = directory.join("master-authority.json");
    let mut authority: MasterAuthority =
        serde_json::from_slice(&std::fs::read(&authority_path).unwrap()).unwrap();
    authority.authority.as_mut().unwrap().master_certificate = Some(narrowed);
    crate::setup::write_private(&authority_path, &authority).unwrap();
    let mut master = fixture.coordinator.clone();
    master.control_role = Arc::new("master".into());
    master.registry_path = Arc::new(directory.join("nodes.json"));
    master.control = Arc::new(lattice_control::ControlIdentity {
        control_id: trust.control_id.clone(),
        public_key: trust.control_public_key.clone(),
        private_key: lattice_crypto::encode_key(&secret),
        created_at_ms: unix_time_ms(),
    });
    let claim = HeartbeatClaim {
        protocol_version: PROTOCOL_VERSION,
        request_id: "scope-bound-stop".into(),
        node_id: fixture
            .node
            .identity
            .read()
            .await
            .identity()
            .node_id
            .clone(),
        sequence: 50,
        issued_at_ms: unix_time_ms(),
        client_version: env!("CARGO_PKG_VERSION").into(),
        capabilities: NodeCapabilities {
            os: "fixture".into(),
            kernel: "fixture".into(),
            architecture: "fixture".into(),
            cpu_model: "fixture".into(),
            logical_cores: 1,
            physical_cores: Some(1),
            memory_total_mb: 8192,
            gpus: vec![],
        },
        effective_policy: NodePolicy::default(),
        health: NodeHealth {
            runtime_state: NodeRuntimeState::Paused,
            cpu_usage_percent: 0.0,
            memory_used_mb: 0,
            active_jobs: 1,
        },
    };
    let receipt = HeartbeatReceipt {
        protocol_version: PROTOCOL_VERSION,
        request_id: claim.request_id.clone(),
        node_id: claim.node_id.clone(),
        control_id: trust.control_id.clone(),
        policy: (*master.policy).clone(),
        issued_at_ms: unix_time_ms(),
    };
    let mut response = HeartbeatResponse {
        signature: sign(&secret, &receipt).unwrap(),
        receipt,
        job_lease: None,
        control_revision: Some(
            command(&fixture.node, &secret, 2, JobControlAction::Stop, None).await,
        ),
        authority: None,
        command_proof: None,
    };
    lattice_control::masters::certify_heartbeat(
        &master,
        claim.sequence,
        &mut response,
        unix_time_ms(),
    )
    .expect("a cancellation frame needs no policy-changing or inventory authority");
    crate::trust_store::accept_response(&fixture.node, &trust, &claim, &response)
        .await
        .unwrap();
    let previous_policy = fixture.node.remote_policy.read().await.clone();
    assert!(
        !crate::heartbeat::accept_authorized_policy(
            &fixture.node,
            &trust,
            &response.receipt.policy
        )
        .await
        .unwrap()
    );
    assert_eq!(
        *fixture.node.remote_policy.read().await,
        previous_policy,
        "Workloads scope cannot silently replace resource policy"
    );

    let active = fixture.node.active_lease.read().await.clone().unwrap();
    assert!(
        active
            .pending_event
            .as_ref()
            .is_some_and(|event| event.state == JobState::Completed)
    );
    assert!(
        active.lease.expires_at_ms < unix_time_ms(),
        "Stop does not grant more execution time"
    );
    check_and_run(&fixture.node).await.unwrap();
    assert!(
        !job_work_dir(&fixture.node.config_path, "recovery-lease")
            .join("descriptor.json")
            .exists()
    );
}

static RECOVERY_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
struct RuntimeReset;
impl Drop for RuntimeReset {
    fn drop(&mut self) {
        if let Ok(mut slot) = RUNNING_JOB.try_lock() {
            slot.take();
        }
    }
}
#[tokio::test]
async fn live_control_checkpoints_its_pending_revision_before_worker_delivery() {
    let _serial = RECOVERY_SERIAL.lock().await;
    let _reset = RuntimeReset;
    let (fixture, secret) = assigned_node().await;
    let (commands, mut incoming) = mpsc::channel(2);
    let (stop, stopped) = oneshot::channel();
    let (done, worker_done) = oneshot::channel();
    let waiters = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let quiescing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    *RUNNING_JOB.lock().await = Some(RunningJobHandle {
        job_id: "recovery-job".into(),
        lease_id: "recovery-lease".into(),
        effective_limits: ResourceLimits::default(),
        original_lease_limits: ResourceLimits::default(),
        cmd_tx: commands,
        ack_waiters: waiters.clone(),
        boundary: Arc::new(Mutex::new(None)),
        stop_tx: Some(stop),
        quiescing: quiescing.clone(),
        worker_done,
    });
    let checkpoint_path = control_state_path(&fixture.node.config_path, "recovery-lease");
    let active_path = fixture.node.active_lease_path.clone();
    let backend = tokio::spawn(async move {
        let Some(WorkerIpcMessage::ApplyControl {
            revision_seq,
            limits,
            ..
        }) = incoming.recv().await
        else {
            panic!("typed control command expected")
        };
        let pending: serde_json::Value = serde_json::from_slice(
            &std::fs::read(checkpoint_path).expect("checkpoint must precede worker side effects"),
        )
        .unwrap();
        assert_eq!(pending["pending"]["revision"]["revision"], revision_seq);
        let active: JobLeaseStatus =
            serde_json::from_slice(&std::fs::read(active_path).unwrap()).unwrap();
        assert!(active.control_state_required);
        let sender = waiters.lock().await.remove(&revision_seq).unwrap();
        sender
            .send(WorkerIpcMessage::ControlAck {
                revision_seq,
                applied: true,
                detail: None,
                effective_limits: limits,
            })
            .unwrap();
        let _ = stopped.await;
        assert!(quiescing.load(std::sync::atomic::Ordering::SeqCst));
        let _ = done.send(());
    });
    let request = command(
        &fixture.node,
        &secret,
        1,
        JobControlAction::UpdateLimits,
        Some(ResourceLimitPatch {
            cpu_percent: Some(17),
            ..Default::default()
        }),
    )
    .await;
    let ack = apply_control(&fixture.node, request).await.unwrap();
    assert!(ack.ack.applied);
    let active = fixture.node.active_lease.read().await.clone().unwrap();
    let policy = fixture.node.config.read().await.policy.clone();
    assert_eq!(
        recovered_execution(&fixture.node, &active, &policy, None)
            .await
            .unwrap()
            .limits
            .cpu_percent,
        17
    );
    suspend_active(&fixture.node, "test cleanup").await.unwrap();
    backend.await.unwrap();
}

#[tokio::test]
async fn expired_or_unacknowledged_assignments_cannot_be_replaced_by_a_new_offer() {
    let _serial = RECOVERY_SERIAL.lock().await;
    let _reset = RuntimeReset;
    let (fixture, _) = assigned_node().await;
    let mut active = fixture.node.active_lease.read().await.clone().unwrap();
    active.lease.expires_at_ms = 1;
    assert!(!crate::job::assignment_replaceable(&active, "new-lease"));
    active.state = JobState::Expired;
    assert!(!crate::job::assignment_replaceable(&active, "new-lease"));
    active.state = JobState::Completed;
    active.pending_event = Some(JobStatusEvent {
        event_id: "retained-event".into(),
        lease_id: active.lease.lease_id.clone(),
        job_id: active.lease.offer.job_id.clone(),
        state: JobState::Completed,
        sequence: 1,
        detail: None,
        exit_code: None,
        issued_at_ms: unix_time_ms(),
    });
    assert!(!crate::job::assignment_replaceable(&active, "new-lease"));
    active.pending_event = None;
    assert!(crate::job::assignment_replaceable(&active, "new-lease"));
}

#[tokio::test]
async fn old_stop_receipt_survives_expiry_and_a_new_assignment_without_touching_it() {
    let _serial = RECOVERY_SERIAL.lock().await;
    let _reset = RuntimeReset;
    let (fixture, secret) = assigned_node().await;
    let mut stop = command(&fixture.node, &secret, 1, JobControlAction::Stop, None).await;
    stop.revision.expires_at_ms = stop.revision.issued_at_ms + 1000;
    stop.signature = sign(&secret, &stop.revision).unwrap();
    let original = apply_control(&fixture.node, stop.clone()).await.unwrap();
    let mut next = fixture.node.active_lease.read().await.clone().unwrap();
    next.lease.lease_id = "new-assignment".into();
    next.lease.offer.job_id = "new-job".into();
    next.control_state_required = false;
    next.pending_event = None;
    next.state = JobState::Accepted;
    crate::setup::write_private(&fixture.node.active_lease_path, &next).unwrap();
    *fixture.node.active_lease.write().await = Some(next.clone());
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let retry = apply_control(&fixture.node, stop)
        .await
        .expect("a previously applied command replays its receipt, never its effects");
    assert_eq!(retry.ack, original.ack);
    assert_eq!(
        fixture.node.active_lease.read().await.as_ref().unwrap(),
        &next
    );
}

#[tokio::test]
async fn control_checkpoint_rejects_unsafe_lease_identifiers_before_path_resolution() {
    let dir = tempfile::tempdir().unwrap();
    for id in ["", "..", "../outside", "/absolute", "a/b", "a\\b"] {
        assert!(
            load_control_state(&dir.path().join("node.json"), id, false)
                .await
                .is_err(),
            "unsafe identifier: {id}"
        );
    }
}

#[tokio::test]
async fn failed_dormant_resume_persists_intent_and_keeps_assignment_suspended() {
    let _serial = RECOVERY_SERIAL.lock().await;
    let _reset = RuntimeReset;
    let (fixture, secret) = assigned_node().await;
    apply_control(
        &fixture.node,
        command(&fixture.node, &secret, 1, JobControlAction::Pause, None).await,
    )
    .await
    .unwrap();
    let resume = command(&fixture.node, &secret, 2, JobControlAction::Resume, None).await;
    assert!(
        apply_control(&fixture.node, resume.clone()).await.is_err(),
        "missing verified content cannot acknowledge execution"
    );
    let checkpoint = load_control_state(&fixture.node.config_path, "recovery-lease", true)
        .await
        .unwrap();
    assert_eq!(checkpoint.pending, Some(resume));
    assert!(checkpoint.last_successful.unwrap().paused);
    assert!(RUNNING_JOB.lock().await.is_none());
}

#[tokio::test]
#[ignore = "requires the compiled lattice-worker executable and native process execution"]
async fn dormant_resume_requires_real_worker_startup_and_retains_lower_limits() {
    let _serial = RECOVERY_SERIAL.lock().await;
    let _reset = RuntimeReset;
    let (fixture, secret) = assigned_node().await;
    find_worker_binary().expect("build lattice-worker before running this native test");
    let offer = fixture
        .node
        .active_lease
        .read()
        .await
        .as_ref()
        .unwrap()
        .lease
        .offer
        .clone();
    // A valid, harmless empty Wasm module exercises the real worker backend startup.
    let artifact = b"\0asm\x01\0\0\0";
    let runtime = b"fixture-builtin-wasm-marker";
    let identity = fixture.node.identity.read().await.identity().clone();
    let artifact_manifest = ArtifactManifest {
        schema_version: 1,
        artifact_id: offer.artifact_id.clone(),
        artifact_version: offer.artifact_version.clone(),
        runtime: offer.runtime.clone(),
        runtime_version: offer.runtime_version.clone(),
        sha256: sha256_hex(artifact),
        size_bytes: artifact.len() as u64,
        download_url: "https://fixture.invalid/artifact".into(),
        issued_at_ms: unix_time_ms(),
    };
    let runtime_manifest = RuntimeManifest {
        schema_version: 1,
        runtime_id: offer.runtime.clone(),
        runtime_version: offer.runtime_version.clone(),
        platform: identity.platform,
        architecture: identity.architecture,
        sha256: sha256_hex(runtime),
        size_bytes: runtime.len() as u64,
        download_url: "https://fixture.invalid/runtime".into(),
        issued_at_ms: unix_time_ms(),
    };
    crate::artifacts::cache_verified_manifest(
        &fixture.node.artifact_cache_path,
        &artifact_manifest,
    )
    .await
    .unwrap();
    crate::runtimes::cache_verified_manifest(&fixture.node.runtime_cache_path, &runtime_manifest)
        .await
        .unwrap();
    for (index, hash, bytes) in [
        (
            &fixture.node.artifact_cache_path,
            &artifact_manifest.sha256,
            artifact.as_slice(),
        ),
        (
            &fixture.node.runtime_cache_path,
            &runtime_manifest.sha256,
            runtime.as_slice(),
        ),
    ] {
        let path = index.parent().unwrap().join("objects").join(hash);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
    let artifact_path = fixture
        .node
        .artifact_cache_path
        .parent()
        .unwrap()
        .join("objects")
        .join(&artifact_manifest.sha256);
    let runtime_path = fixture
        .node
        .runtime_cache_path
        .parent()
        .unwrap()
        .join("objects")
        .join(&runtime_manifest.sha256);
    crate::artifacts::mark_content_verified(
        &fixture.node.artifact_cache_path,
        &artifact_path,
        &artifact_manifest,
    )
    .await
    .unwrap();
    crate::runtimes::mark_content_verified(
        &fixture.node.runtime_cache_path,
        &runtime_path,
        &runtime_manifest,
    )
    .await
    .unwrap();
    apply_control(
        &fixture.node,
        command(&fixture.node, &secret, 1, JobControlAction::Pause, None).await,
    )
    .await
    .unwrap();
    apply_control(
        &fixture.node,
        command(
            &fixture.node,
            &secret,
            2,
            JobControlAction::UpdateLimits,
            Some(ResourceLimitPatch {
                cpu_percent: Some(17),
                ..Default::default()
            }),
        )
        .await,
    )
    .await
    .unwrap();
    let outcome = apply_control(
        &fixture.node,
        command(&fixture.node, &secret, 3, JobControlAction::Resume, None).await,
    )
    .await;
    if outcome.is_err() {
        let _ = suspend_active(&fixture.node, "test cleanup").await;
    }
    let ack = outcome.expect("Resume must start the verified actual worker backend");
    assert!(ack.ack.applied);
    assert_eq!(ack.ack.runtime_state, JobState::Running);
    assert_eq!(ack.ack.effective_limits.cpu_percent, 17);
    let checkpoint = load_control_state(&fixture.node.config_path, "recovery-lease", true)
        .await
        .unwrap();
    assert!(checkpoint.pending.is_none());
    assert!(!checkpoint.last_successful.as_ref().unwrap().paused);
    assert!(RUNNING_JOB.lock().await.is_some());
    suspend_active(&fixture.node, "native test cleanup")
        .await
        .unwrap();
    assert!(RUNNING_JOB.lock().await.is_none());
}

#[tokio::test]
async fn late_worker_status_cannot_report_against_a_different_assignment() {
    let _serial = RECOVERY_SERIAL.lock().await;
    let _reset = RuntimeReset;
    let (fixture, _) = assigned_node().await;
    let before = std::fs::read(&fixture.node.active_lease_path).unwrap();
    assert!(
        crate::job::report_status_for_lease(
            &fixture.node,
            "previous-lease",
            JobState::Failed,
            Some("late worker exit".into()),
            Some(1)
        )
        .await
        .is_err()
    );
    assert_eq!(
        std::fs::read(&fixture.node.active_lease_path).unwrap(),
        before
    );
}
