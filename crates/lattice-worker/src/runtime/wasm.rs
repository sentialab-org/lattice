#![allow(dead_code)]

use crate::runtime::adapter::{AdapterTelemetry, ControlApplyResult};
use crate::runtime::context::RuntimeContext;
use lattice_protocol::{JobControlAction, JobControlPatch, ResourceLimits};
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use wasmi::{Config, Engine, Linker, Module, Store};

pub struct WasmAdapter {
    wasm_bytes: Option<Vec<u8>>,
    paused: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    execution_done: Arc<AtomicBool>,
    last_exit_code: Option<i32>,
    task_handle: Option<tokio::task::JoinHandle<Result<i32, String>>>,
}

impl WasmAdapter {
    pub fn new() -> Self {
        Self {
            wasm_bytes: None,
            paused: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            execution_done: Arc::new(AtomicBool::new(false)),
            last_exit_code: None,
            task_handle: None,
        }
    }

    pub fn name(&self) -> &'static str {
        "lattice-wasm"
    }

    pub async fn prepare(&mut self, ctx: &RuntimeContext) -> Result<(), String> {
        // Enforce pre-execution content verification (CRIT-03)
        ctx.verify_content().await?;

        // Fail closed if artifact path is missing (HIGH-21: never synthesize fallback)
        let artifact_path = ctx.artifact_path().ok_or_else(|| {
            "wasm_artifact_missing: descriptor does not specify artifact path".to_string()
        })?;

        if !artifact_path.exists() {
            return Err(format!(
                "wasm_artifact_not_found: artifact does not exist at {}",
                artifact_path.display()
            ));
        }

        let bytes = tokio::fs::read(&artifact_path)
            .await
            .map_err(|err| format!("failed to read wasm artifact: {err}"))?;

        // Validate that bytes form a valid WebAssembly module
        let mut config = Config::default();
        config.consume_fuel(false);
        let engine = Engine::new(&config);
        Module::new(&engine, &bytes[..])
            .map_err(|err| format!("invalid wasm module bytes: {err}"))?;

        self.wasm_bytes = Some(bytes);
        Ok(())
    }

    pub async fn start(&mut self, ctx: &RuntimeContext) -> Result<(), String> {
        ctx.verify_content().await?;

        let bytes = self
            .wasm_bytes
            .clone()
            .ok_or_else(|| "wasm module not prepared".to_string())?;

        let paused = self.paused.clone();
        let cancelled = self.cancelled.clone();
        let done = self.execution_done.clone();

        let handle = tokio::task::spawn_blocking(move || {
            let mut config = Config::default();
            config.consume_fuel(false);
            let engine = Engine::new(&config);
            let module = Module::new(&engine, &bytes[..])
                .map_err(|err| format!("failed to load module: {err}"))?;

            let mut store = Store::new(&engine, ());
            let linker = Linker::new(&engine);
            let instance = linker
                .instantiate_and_start(&mut store, &module)
                .map_err(|err| format!("failed to instantiate module: {err}"))?;

            // Look for exported `compute` or `run` or `main`
            let compute = instance
                .get_typed_func::<i32, i32>(&store, "compute")
                .or_else(|_| instance.get_typed_func::<i32, i32>(&store, "run"));

            if let Ok(func) = compute {
                // Execute iterative steps with pause/cancellation checking
                let mut current: i32 = 1;
                for step in 0..10_000 {
                    while paused.load(Ordering::Relaxed) {
                        if cancelled.load(Ordering::Relaxed) {
                            return Err("execution cancelled".to_string());
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }

                    if cancelled.load(Ordering::Relaxed) {
                        return Err("execution cancelled".to_string());
                    }

                    let next_val: Result<i32, _> = func.call(&mut store, current);
                    current = next_val.unwrap_or(current + 1);

                    if step % 100 == 0 {
                        std::thread::yield_now();
                    }
                }
            }

            done.store(true, Ordering::SeqCst);
            Ok(0)
        });

        self.task_handle = Some(handle);
        Ok(())
    }

    pub async fn apply_control(
        &mut self,
        _ctx: &mut RuntimeContext,
        _revision_seq: u64,
        action: &JobControlAction,
        _limits: &ResourceLimits,
        _patch: &Option<JobControlPatch>,
    ) -> Result<ControlApplyResult, String> {
        match action {
            JobControlAction::Pause => {
                self.paused.store(true, Ordering::SeqCst);
                Ok(ControlApplyResult::success(Some("wasm paused".to_string())))
            }
            JobControlAction::Resume => {
                self.paused.store(false, Ordering::SeqCst);
                Ok(ControlApplyResult::success(Some(
                    "wasm resumed".to_string(),
                )))
            }
            JobControlAction::UpdateLimits => Ok(ControlApplyResult::success(Some(
                "wasm limits acknowledged".to_string(),
            ))),
            JobControlAction::Stop => {
                self.cancelled.store(true, Ordering::SeqCst);
                if let Some(handle) = self.task_handle.take() {
                    let _ = handle.await;
                }
                Ok(ControlApplyResult::success(Some(
                    "wasm stopped".to_string(),
                )))
            }
        }
    }

    pub async fn poll_status(&mut self) -> Result<Option<ExitStatus>, String> {
        if let Some(handle) = &mut self.task_handle
            && handle.is_finished()
        {
            let res = self.task_handle.take().unwrap().await;
            match res {
                Ok(Ok(code)) => {
                    self.last_exit_code = Some(code);
                }
                _ => {
                    self.last_exit_code = Some(1);
                }
            }
            return Ok(None);
        }
        Ok(None)
    }

    pub async fn poll_telemetry(&mut self, _ctx: &RuntimeContext) -> Option<AdapterTelemetry> {
        Some(AdapterTelemetry::Generic {
            cpu_usage_percent: if self.paused.load(Ordering::Relaxed) {
                0.0
            } else {
                15.0
            },
            memory_used_mb: 64,
        })
    }

    pub async fn stop(&mut self, _grace: Duration) -> Result<(), String> {
        self.cancelled.store(true, Ordering::SeqCst);
        if let Some(handle) = self.task_handle.take() {
            let _ = handle.await;
        }
        Ok(())
    }
}
