//! Issuer deadline behavior after the trusted delegation boundary has authenticated a principal.
mod support;
use axum::{Extension, Json, extract::State, http::HeaderMap};
use lattice_control::{
    auth::{OperatorPrincipal, OperatorScope},
    operator,
};
use lattice_protocol::*;
#[tokio::test]
async fn cancellation_issues_a_fresh_bounded_stop_without_extending_the_expired_lease() {
    let fixture = support::Fixture::new("master").await;
    let record: lattice_control::jobs::JobRecord=serde_json::from_value(serde_json::json!({
        "offer":{"job_id":"expired-job","workload_kind":"research","runtime":"lattice-wasm","runtime_version":"fixture","artifact_id":"fixture","artifact_version":"fixture","limits":ResourceLimits::default(),"parameters":{},"expires_at_ms":1},
        "state":"running","lease":{"lease_id":"expired-lease","node_id":"fixture-node","offer":{"job_id":"expired-job","workload_kind":"research","runtime":"lattice-wasm","runtime_version":"fixture","artifact_id":"fixture","artifact_version":"fixture","limits":ResourceLimits::default(),"parameters":{},"expires_at_ms":1},"issued_at_ms":0,"decision_deadline_ms":1,"expires_at_ms":1}
    })).unwrap();
    fixture.state.jobs.write().await.jobs.push(record);
    let principal = || {
        Some(Extension(OperatorPrincipal {
            username: "verified-fixture-master".into(),
            scope: Some(OperatorScope::WorkloadWrite),
        }))
    };
    let Json(cancel) = operator::cancel_job(
        State(fixture.state.clone()),
        HeaderMap::new(),
        principal(),
        Json(operator::OperatorCancelJobRequest {
            job_id: "expired-job".into(),
            reason: None,
        }),
    )
    .await
    .unwrap();
    assert!(
        cancel.revision.expires_at_ms > cancel.revision.issued_at_ms,
        "an expired execution lease must remain cancellable"
    );
    assert!(cancel.revision.expires_at_ms - cancel.revision.issued_at_ms <= 60_000);
    lattice_crypto::verify(
        &fixture.state.control.public_key,
        &cancel.signature,
        &cancel.revision,
    )
    .unwrap();
    let Json(stop) = operator::control_job(
        State(fixture.state.clone()),
        HeaderMap::new(),
        principal(),
        Json(operator::OperatorControlJobRequest {
            job_id: "expired-job".into(),
            action: JobControlAction::Stop,
            resource_patch: None,
            runtime_patch: None,
        }),
    )
    .await
    .unwrap();
    assert!(stop.revision.expires_at_ms > stop.revision.issued_at_ms);
    assert!(stop.revision.expires_at_ms - stop.revision.issued_at_ms <= 60_000);
    fixture.state.jobs.write().await.jobs[0].state = JobState::Expired;
    assert_eq!(
        lattice_control::jobs::pending_control_for_node(
            &*fixture.state.jobs.read().await,
            "fixture-node"
        )
        .unwrap()
        .revision,
        stop.revision,
        "expired assignments still receive an authorized Stop"
    );
    assert_eq!(
        fixture.state.jobs.read().await.jobs[0]
            .lease
            .as_ref()
            .unwrap()
            .expires_at_ms,
        1
    );
}

#[tokio::test]
async fn cancellation_retains_provenance_for_late_status_and_duplicate_receipts() {
    let fixture = support::Fixture::new("master").await;
    let device = lattice_crypto::generate_private_key();
    let public = lattice_crypto::encode_key(&lattice_crypto::public_key(&device));
    fixture.state.registry.write().await.nodes.insert("fixture-node".into(),serde_json::from_value(serde_json::json!({"node_id":"fixture-node","node_name":"fixture","public_key":public,"platform":"linux","architecture":"x86_64","client_version":"fixture","enrolled_at_ms":0})).unwrap());
    let offer = JobOffer {
        job_id: "late-status-job".into(),
        workload_kind: WorkloadKind::Research,
        runtime: "lattice-wasm".into(),
        runtime_version: "fixture".into(),
        artifact_id: "fixture".into(),
        artifact_version: "fixture".into(),
        limits: ResourceLimits::default(),
        parameters: Default::default(),
        expires_at_ms: 1,
    };
    let lease = JobLease {
        lease_id: "late-status-lease".into(),
        node_id: "fixture-node".into(),
        offer: offer.clone(),
        issued_at_ms: 0,
        decision_deadline_ms: 1,
        expires_at_ms: 1,
    };
    fixture.state.jobs.write().await.jobs.push(
        serde_json::from_value(serde_json::json!({"offer":offer,"lease":lease,"state":"expired"}))
            .unwrap(),
    );
    let principal = Some(Extension(OperatorPrincipal {
        username: "verified-fixture-master".into(),
        scope: Some(OperatorScope::WorkloadWrite),
    }));
    let Json(stop) = operator::cancel_job(
        State(fixture.state.clone()),
        HeaderMap::new(),
        principal,
        Json(operator::OperatorCancelJobRequest {
            job_id: offer.job_id.clone(),
            reason: None,
        }),
    )
    .await
    .unwrap();
    let ack = JobControlAck {
        protocol_version: PROTOCOL_VERSION,
        node_id: lease.node_id.clone(),
        lease_id: lease.lease_id.clone(),
        job_id: offer.job_id.clone(),
        revision: stop.revision.revision,
        applied: true,
        effective_limits: offer.limits.clone(),
        runtime_state: JobState::Completed,
        reason: None,
        acknowledged_at_ms: lattice_control::unix_time_ms(),
    };
    let signed = SignedJobControlAck {
        signature: lattice_crypto::sign(&device, &ack).unwrap(),
        ack,
    };
    lattice_control::jobs::handle_control_ack(State(fixture.state.clone()), Json(signed.clone()))
        .await
        .unwrap();
    assert!(
        fixture.state.jobs.read().await.jobs[0].lease.is_some(),
        "terminal records retain identity and lease provenance"
    );
    lattice_control::jobs::handle_control_ack(State(fixture.state.clone()), Json(signed))
        .await
        .unwrap();
    for (sequence, state) in [(1, JobState::Preparing), (2, JobState::Completed)] {
        let event = JobStatusEvent {
            event_id: format!("delayed-{sequence}"),
            lease_id: lease.lease_id.clone(),
            job_id: offer.job_id.clone(),
            state: state.clone(),
            sequence,
            detail: None,
            exit_code: None,
            issued_at_ms: lattice_control::unix_time_ms() - 1_000_000,
        };
        let claim = JobStatusClaim {
            protocol_version: PROTOCOL_VERSION,
            node_id: lease.node_id.clone(),
            event,
        };
        let request = JobStatusRequest {
            signature: lattice_crypto::sign(&device, &claim).unwrap(),
            claim,
        };
        for _ in 0..2 {
            let Json(response) =
                lattice_control::jobs::status(State(fixture.state.clone()), Json(request.clone()))
                    .await
                    .expect(
                        "delayed audit delivery must neither lose its receipt nor revive execution",
                    );
            assert_eq!(response.receipt.state, state);
            lattice_crypto::verify(
                &fixture.state.control.public_key,
                &response.signature,
                &response.receipt,
            )
            .unwrap();
        }
        assert_eq!(
            fixture.state.jobs.read().await.jobs[0].state,
            JobState::Completed,
            "late reports cannot undo an explicit cancellation"
        );
    }
    assert_eq!(fixture.state.jobs.read().await.jobs[0].events.len(), 2);
}

#[tokio::test]
async fn a_closed_assignment_cannot_be_resumed_or_create_new_cancellation_intents() {
    let fixture = support::Fixture::new("master").await;
    fixture.state.jobs.write().await.jobs.push(serde_json::from_value(serde_json::json!({
        "offer":{"job_id":"closed-job","workload_kind":"research","runtime":"lattice-wasm","runtime_version":"fixture","artifact_id":"fixture","artifact_version":"fixture","limits":ResourceLimits::default(),"parameters":{},"expires_at_ms":1},
        "state":"completed","lease":{"lease_id":"closed-lease","node_id":"fixture-node","offer":{"job_id":"closed-job","workload_kind":"research","runtime":"lattice-wasm","runtime_version":"fixture","artifact_id":"fixture","artifact_version":"fixture","limits":ResourceLimits::default(),"parameters":{},"expires_at_ms":1},"issued_at_ms":0,"decision_deadline_ms":1,"expires_at_ms":1}
    })).unwrap());
    let principal = || {
        Some(Extension(OperatorPrincipal {
            username: "fixture-owner".into(),
            scope: Some(OperatorScope::WorkloadWrite),
        }))
    };
    assert!(
        operator::control_job(
            State(fixture.state.clone()),
            HeaderMap::new(),
            principal(),
            Json(operator::OperatorControlJobRequest {
                job_id: "closed-job".into(),
                action: JobControlAction::Resume,
                resource_patch: None,
                runtime_patch: None
            })
        )
        .await
        .is_err()
    );
    assert!(
        operator::cancel_job(
            State(fixture.state.clone()),
            HeaderMap::new(),
            principal(),
            Json(operator::OperatorCancelJobRequest {
                job_id: "closed-job".into(),
                reason: None
            })
        )
        .await
        .is_err()
    );
    assert_eq!(
        fixture.state.jobs.read().await.jobs[0].state,
        JobState::Completed
    );
    assert!(
        fixture.state.jobs.read().await.jobs[0]
            .desired_revision
            .is_none()
    );
}
