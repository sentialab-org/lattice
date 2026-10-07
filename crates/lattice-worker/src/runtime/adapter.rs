#![allow(dead_code)]

use crate::runtime::context::RuntimeContext;
use crate::runtime::mining::MiningAdapter;
use crate::runtime::wasm::WasmAdapter;
use lattice_protocol::{JobControlAction, JobControlPatch, MiningTelemetry, ResourceLimits};
use std::process::ExitStatus;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ControlApplyResult {
    pub applied: bool,
    pub detail: Option<String>,
}

impl ControlApplyResult {
    pub fn success(detail: Option<String>) -> Self {
        Self {
            applied: true,
            detail,
        }
    }

    pub fn failed(detail: String) -> Self {
        Self {
            applied: false,
            detail: Some(detail),
        }
    }
}

#[derive(Debug, Clone)]
pub enum AdapterTelemetry {
    Mining(MiningTelemetry),
    Generic {
        cpu_usage_percent: f64,
        memory_used_mb: u64,
    },
}

#[allow(clippy::large_enum_variant)]
pub enum ExecutionAdapter {
    Mining(MiningAdapter),
    Wasm(WasmAdapter),
}

impl ExecutionAdapter {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Mining(a) => a.name(),
            Self::Wasm(a) => a.name(),
        }
    }

    pub async fn prepare(&mut self, ctx: &RuntimeContext) -> Result<(), String> {
        match self {
            Self::Mining(a) => a.prepare(ctx).await,
            Self::Wasm(a) => a.prepare(ctx).await,
        }
    }

    pub async fn start(&mut self, ctx: &RuntimeContext) -> Result<(), String> {
        match self {
            Self::Mining(a) => a.start(ctx).await,
            Self::Wasm(a) => a.start(ctx).await,
        }
    }

    pub async fn apply_control(
        &mut self,
        ctx: &mut RuntimeContext,
        revision_seq: u64,
        action: &JobControlAction,
        limits: &ResourceLimits,
        patch: &Option<JobControlPatch>,
    ) -> Result<ControlApplyResult, String> {
        match self {
            Self::Mining(a) => {
                a.apply_control(ctx, revision_seq, action, limits, patch)
                    .await
            }
            Self::Wasm(a) => {
                a.apply_control(ctx, revision_seq, action, limits, patch)
                    .await
            }
        }
    }

    pub async fn poll_status(&mut self) -> Result<Option<ExitStatus>, String> {
        match self {
            Self::Mining(a) => a.poll_status().await,
            Self::Wasm(a) => a.poll_status().await,
        }
    }

    pub async fn poll_telemetry(&mut self, ctx: &RuntimeContext) -> Option<AdapterTelemetry> {
        match self {
            Self::Mining(a) => a.poll_telemetry(ctx).await,
            Self::Wasm(a) => a.poll_telemetry(ctx).await,
        }
    }

    pub async fn stop(&mut self, grace: Duration) -> Result<(), String> {
        match self {
            Self::Mining(a) => a.stop(grace).await,
            Self::Wasm(a) => a.stop(grace).await,
        }
    }
}
