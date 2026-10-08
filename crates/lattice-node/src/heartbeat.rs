use crate::AppState;
use crate::identity::unix_time_ms;
use lattice_crypto::{sign, verify};
use lattice_protocol::{
    ApiError, GpuCapability, HeartbeatClaim, HeartbeatRequest, HeartbeatResponse, NodeCapabilities,
    NodeHealth, NodeRuntimeState, PROTOCOL_VERSION, PolicySnapshot,
};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::watch;
use uuid::Uuid;

pub async fn run(state: Arc<AppState>, mut shutdown: watch::Receiver<bool>) {
    let interval_seconds = std::env::var("LATTICE_HEARTBEAT_INTERVAL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(15)
        .clamp(1, 300);
    let mut interval = tokio::time::interval(Duration::from_secs(interval_seconds));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let enrolled = state.identity.read().await.trust().is_some();
                if !enrolled {
                    state.control_connected.store(false, Ordering::Relaxed);
                    continue;
                }

                let _ = crate::job::prepare_active_content(&state).await;
                let connected = send(&state).await.is_ok();
                state.control_connected.store(connected, Ordering::Relaxed);
            }
            result = shutdown.changed() => {
                if result.is_err() || *shutdown.borrow() {
                    state.control_connected.store(false, Ordering::Relaxed);
                    return;
                }
            }
        }
    }
}

async fn send(state: &Arc<AppState>) -> Result<(), String> {
    crate::job::expire_local(state).await?;
    crate::job::retry_pending(state).await?;
    let (identity, private_key, trust) = {
        let identity = state.identity.read().await;
        let trust = identity
            .trust()
            .cloned()
            .ok_or_else(|| "node is not enrolled".to_string())?;
        (identity.identity().clone(), *identity.private_key(), trust)
    };
    let hardware = crate::hardware_snapshot(state).await;
    let config = state.config.read().await.clone();
    let remote_policy = state.remote_policy.read().await.clone();
    let effective_policy = crate::policy::effective(&config.policy, remote_policy.as_ref());
    let runtime_state = if !effective_policy.enabled {
        NodeRuntimeState::Paused
    } else if state
        .active_lease
        .read()
        .await
        .as_ref()
        .is_some_and(|lease| {
            matches!(
                lease.state,
                lattice_protocol::JobState::Accepted
                    | lattice_protocol::JobState::Preparing
                    | lattice_protocol::JobState::Running
                    | lattice_protocol::JobState::Stopping
            )
        })
    {
        NodeRuntimeState::Running
    } else if state
        .active_lease
        .read()
        .await
        .as_ref()
        .is_some_and(|lease| lease.state == lattice_protocol::JobState::Failed)
    {
        NodeRuntimeState::Degraded
    } else {
        NodeRuntimeState::Idle
    };
    let issued_at_ms = unix_time_ms();
    let random_suffix = (Uuid::new_v4().as_u128() as u64) & 0x000f_ffff;
    let sequence = issued_at_ms
        .saturating_mul(1_048_576)
        .saturating_add(random_suffix);
    let claim =
        HeartbeatClaim {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4().to_string(),
            node_id: identity.node_id.clone(),
            sequence,
            issued_at_ms,
            client_version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities: NodeCapabilities {
                os: hardware.os,
                kernel: hardware.kernel,
                architecture: hardware.architecture,
                cpu_model: hardware.cpu.model,
                logical_cores: hardware.cpu.logical_cores,
                physical_cores: hardware.cpu.physical_cores,
                memory_total_mb: hardware.memory.total_mb,
                gpus: hardware
                    .gpus
                    .iter()
                    .map(|gpu| GpuCapability {
                        name: gpu.name.clone(),
                        memory_total_mb: gpu.memory_total_mb,
                    })
                    .collect(),
            },
            effective_policy: effective_policy.clone(),
            health: NodeHealth {
                runtime_state,
                cpu_usage_percent: hardware.cpu.usage_percent,
                memory_used_mb: hardware.memory.used_mb,
                active_jobs: u32::from(state.active_lease.read().await.as_ref().is_some_and(
                    |lease| {
                        matches!(
                            lease.state,
                            lattice_protocol::JobState::Accepted
                                | lattice_protocol::JobState::Preparing
                                | lattice_protocol::JobState::Running
                                | lattice_protocol::JobState::Stopping
                        )
                    },
                )),
            },
        };
    let request = HeartbeatRequest {
        signature: sign(&private_key, &claim)?,
        claim: claim.clone(),
    };
    let response = state
        .http
        .post(format!("{}/api/v1/heartbeat", trust.control_url))
        .json(&request)
        .send()
        .await
        .map_err(|error| format!("heartbeat request failed: {error}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if let Ok(error) = serde_json::from_str::<ApiError>(&body) {
            return Err(format!("{}: {}", error.code, error.message));
        }
        return Err(format!("control server returned HTTP {status}"));
    }

    let heartbeat: HeartbeatResponse = response.json().await.map_err(|error| error.to_string())?;
    let receipt = &heartbeat.receipt;

    if receipt.protocol_version != PROTOCOL_VERSION {
        return Err("control server protocol version mismatch".to_string());
    }

    if receipt.request_id != claim.request_id {
        return Err("heartbeat response request ID mismatch".to_string());
    }

    if receipt.node_id != identity.node_id {
        return Err("heartbeat response node ID mismatch".to_string());
    }

    if receipt.control_id != trust.control_id {
        return Err("heartbeat response control identity mismatch".to_string());
    }

    verify(
        &trust.control_public_key,
        &heartbeat.signature,
        &heartbeat.receipt,
    )
    .map_err(|error| format!("invalid heartbeat response signature: {error}"))?;

    accept_policy(state, &heartbeat.receipt.policy).await?;

    if let Some(job_lease) = heartbeat.job_lease {
        crate::job::handle(state, job_lease).await?;
    }

    if let Some(control_rev) = heartbeat.control_revision {
        let ack_result = crate::supervisor::apply_control(state, control_rev.clone()).await;
        let signed_ack = match ack_result {
            Ok(signed_ack) => Some(signed_ack),
            Err(err) => {
                // If revision signature is valid from control plane, emit signed negative ACK (HIGH-03)
                if verify(
                    &trust.control_public_key,
                    &control_rev.signature,
                    &control_rev.revision,
                )
                .is_ok()
                {
                    let (limits, runtime_state) = {
                        let active = state.active_lease.read().await.clone();
                        let l = active
                            .as_ref()
                            .map(|a| a.lease.offer.limits.clone())
                            .unwrap_or_else(|| lattice_protocol::ResourceLimits {
                                cpu_percent: 0,
                                memory_mb: 0,
                                gpu_percent: None,
                                gpu_memory_mb: None,
                            });
                        let s = active
                            .as_ref()
                            .map(|a| a.state.clone())
                            .unwrap_or(lattice_protocol::JobState::Failed);
                        (l, s)
                    };
                    let negative_ack = lattice_protocol::JobControlAck {
                        protocol_version: PROTOCOL_VERSION,
                        node_id: identity.node_id.clone(),
                        lease_id: control_rev.revision.lease_id.clone(),
                        job_id: control_rev.revision.job_id.clone(),
                        revision: control_rev.revision.revision,
                        applied: false,
                        effective_limits: limits,
                        runtime_state,
                        reason: Some(format!("apply_control_failed: {err}")),
                        acknowledged_at_ms: unix_time_ms(),
                    };
                    if let Ok(sig) = sign(&private_key, &negative_ack) {
                        Some(lattice_protocol::SignedJobControlAck {
                            ack: negative_ack,
                            signature: sig,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        };

        if let Some(ack) = signed_ack {
            let _ = state
                .http
                .post(format!("{}/api/v1/jobs/control-ack", trust.control_url))
                .json(&ack)
                .send()
                .await;
        }
    }

    Ok(())
}

async fn accept_policy(state: &Arc<AppState>, incoming: &PolicySnapshot) -> Result<(), String> {
    let current = state.remote_policy.read().await.clone();

    if let Some(current) = current.as_ref() {
        if incoming.revision < current.revision {
            return Err("control policy rollback rejected".to_string());
        }

        if incoming.revision == current.revision {
            if incoming != current {
                return Err("control policy changed without a revision increase".to_string());
            }
            return Ok(());
        }
    }

    crate::policy::save(&state.remote_policy_path, incoming).await?;
    *state.remote_policy.write().await = Some(incoming.clone());
    state
        .identity
        .write()
        .await
        .update_policy_revision(incoming.revision)
        .await
}
