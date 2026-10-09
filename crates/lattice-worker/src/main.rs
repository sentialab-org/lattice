use lattice_protocol::{JobState, WorkerIpcMessage, WorkerJobDescriptor};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

mod process_supervisor;
mod runtime;

use runtime::context::RuntimeContext;
use runtime::select_adapter;

struct WorkerCliArgs {
    descriptor_path: PathBuf,
    endpoint: String,
    token: String,
    job_id: Option<String>,
}

fn parse_cli_args() -> Result<WorkerCliArgs, String> {
    let args: Vec<String> = std::env::args().collect();
    let mut descriptor_path = None;
    let mut endpoint = None;
    let mut token = None;
    let mut job_id = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--descriptor" => {
                if i + 1 < args.len() {
                    descriptor_path = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else {
                    return Err("missing value for --descriptor".to_string());
                }
            }
            "--endpoint" => {
                if i + 1 < args.len() {
                    endpoint = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err("missing value for --endpoint".to_string());
                }
            }
            "--token" => {
                if i + 1 < args.len() {
                    token = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err("missing value for --token".to_string());
                }
            }
            "--job-id" => {
                if i + 1 < args.len() {
                    job_id = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err("missing value for --job-id".to_string());
                }
            }
            other => {
                return Err(format!("unknown worker CLI argument: {other}"));
            }
        }
    }

    let descriptor_path =
        descriptor_path.ok_or_else(|| "missing required argument: --descriptor".to_string())?;

    Ok(WorkerCliArgs {
        descriptor_path,
        endpoint: endpoint.unwrap_or_default(),
        token: token.unwrap_or_default(),
        job_id,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = match parse_cli_args() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("[LATTICE WORKER ERROR] {err}");
            std::process::exit(1);
        }
    };

    let descriptor_content = tokio::fs::read_to_string(&args.descriptor_path).await?;
    let descriptor: WorkerJobDescriptor = serde_json::from_str(&descriptor_content)?;

    // Validate descriptor protocol version (HIGH-09)
    if descriptor.protocol_version != lattice_protocol::PROTOCOL_VERSION {
        eprintln!(
            "[LATTICE WORKER ERROR] Protocol version mismatch: descriptor protocol {} != worker supported {}",
            descriptor.protocol_version,
            lattice_protocol::PROTOCOL_VERSION
        );
        std::process::exit(1);
    }

    // Resolve endpoint and auth token (fall back to descriptor fields to avoid CLI exposure, HIGH-12)
    let endpoint = if !args.endpoint.is_empty() {
        args.endpoint
    } else {
        descriptor.ipc_socket_path.clone()
    };
    let auth_token = if !args.token.is_empty() {
        args.token
    } else {
        descriptor.ipc_auth_token.clone()
    };

    // Validate CLI job-id against descriptor (MED-09)
    if let Some(ref cli_job_id) = args.job_id
        && cli_job_id != &descriptor.job_id
    {
        eprintln!(
            "[LATTICE WORKER ERROR] Job ID mismatch: CLI argument '{cli_job_id}' does not match descriptor '{}'",
            descriptor.job_id
        );
        std::process::exit(1);
    }

    // Establish IPC connection to supervisor with retry
    #[cfg(unix)]
    let stream = {
        use tokio::net::UnixStream;
        let mut connected = None;
        for attempt in 1..=30 {
            match UnixStream::connect(&endpoint).await {
                Ok(s) => {
                    connected = Some(s);
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
            if attempt == 30 {
                eprintln!("[LATTICE WORKER ERROR] Failed to connect to IPC endpoint");
                std::process::exit(1);
            }
        }
        connected.unwrap()
    };

    #[cfg(windows)]
    let stream = {
        use tokio::net::windows::named_pipe::ClientOptions;
        let mut connected = None;
        for attempt in 1..=30 {
            match ClientOptions::new().open(&endpoint) {
                Ok(c) => {
                    connected = Some(c);
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
            if attempt == 30 {
                eprintln!("[LATTICE WORKER ERROR] Failed to open named pipe endpoint");
                std::process::exit(1);
            }
        }
        connected.unwrap()
    };

    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    // Authenticate with Node IPC supervisor (CRIT-16)
    let auth_msg = WorkerIpcMessage::Auth {
        token: auth_token.clone(),
        job_id: descriptor.job_id.clone(),
    };
    let mut auth_bytes = serde_json::to_vec(&auth_msg)?;
    auth_bytes.push(b'\n');
    write_half.write_all(&auth_bytes).await?;
    write_half.flush().await?;

    let mut auth_line = String::new();
    reader.read_line(&mut auth_line).await?;
    let auth_response: WorkerIpcMessage = serde_json::from_str(&auth_line)?;

    match auth_response {
        WorkerIpcMessage::AuthResult { success: true, .. } => {}
        WorkerIpcMessage::AuthResult {
            success: false,
            error,
        } => {
            eprintln!("[LATTICE WORKER ERROR] Authentication failed: {:?}", error);
            return Ok(());
        }
        other => {
            eprintln!(
                "[LATTICE WORKER ERROR] Unexpected response during authentication: {:?}",
                other
            );
            return Ok(());
        }
    }

    // Set up runtime context and pre-execution verification (CRIT-03)
    let mut ctx = RuntimeContext::new(descriptor);
    if let Err(err) = ctx.verify_content().await {
        let fail_msg = WorkerIpcMessage::StateChange {
            state: JobState::Failed,
            detail: Some(format!("content_verification_failed: {err}")),
            exit_code: None,
        };
        let mut b = serde_json::to_vec(&fail_msg)?;
        b.push(b'\n');
        let _ = write_half.write_all(&b).await;
        return Ok(());
    }

    let mut adapter = match select_adapter(&ctx) {
        Ok(adapter) => adapter,
        Err(err) => {
            let fail_msg = WorkerIpcMessage::StateChange {
                state: JobState::Failed,
                detail: Some(format!("adapter_selection_failed: {err}")),
                exit_code: None,
            };
            let mut b = serde_json::to_vec(&fail_msg)?;
            b.push(b'\n');
            let _ = write_half.write_all(&b).await;
            return Ok(());
        }
    };

    if let Err(err) = adapter.prepare(&ctx).await {
        let fail_msg = WorkerIpcMessage::StateChange {
            state: JobState::Failed,
            detail: Some(format!("adapter_prepare_failed: {err}")),
            exit_code: None,
        };
        let mut b = serde_json::to_vec(&fail_msg)?;
        b.push(b'\n');
        let _ = write_half.write_all(&b).await;
        return Ok(());
    }

    // IPC send channel
    let (tx, mut rx) = mpsc::channel::<WorkerIpcMessage>(64);

    // Spawn IPC writer task
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Ok(mut bytes) = serde_json::to_vec(&msg) {
                bytes.push(b'\n');
                if write_half.write_all(&bytes).await.is_err() {
                    break;
                }
                let _ = write_half.flush().await;
            }
        }
    });

    let mut is_started = false;
    let mut check_status_interval = tokio::time::interval(Duration::from_millis(500));
    let mut telemetry_interval = tokio::time::interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            // Read IPC commands from node supervisor
            line_result = reader.read_line(&mut auth_line) => {
                match line_result {
                    Ok(0) => {
                        // Supervisor closed the connection
                        break;
                    }
                    Ok(_) => {
                        let msg_str = auth_line.trim();
                        if !msg_str.is_empty()
                            && let Ok(cmd) = serde_json::from_str::<WorkerIpcMessage>(msg_str)
                        {
                            match cmd {
                                    WorkerIpcMessage::Start => {
                                        if is_started {
                                            // Reject duplicate start (MED-08)
                                            let _ = tx.send(WorkerIpcMessage::Error {
                                                message: "job already started".to_string(),
                                            }).await;
                                            continue;
                                        }
                                        match adapter.start(&ctx).await {
                                            Ok(()) => {
                                                is_started = true;
                                                let _ = tx.send(WorkerIpcMessage::StateChange {
                                                    state: JobState::Running,
                                                    detail: Some("workload started".to_string()),
                                                    exit_code: None,
                                                }).await;
                                            }
                                            Err(err) => {
                                                let _ = tx.send(WorkerIpcMessage::StateChange {
                                                    state: JobState::Failed,
                                                    detail: Some(format!("start_failed: {err}")),
                                                    exit_code: None,
                                                }).await;
                                                break;
                                            }
                                        }
                                    }
                                    WorkerIpcMessage::ApplyControl { revision_seq, action, limits, runtime_patch } => {
                                        // Wait for adapter/backend to confirm application before ACK (HIGH-11)
                                        match adapter.apply_control(&mut ctx, revision_seq, &action, &limits, &runtime_patch).await {
                                            Ok(res) => {
                                                let _ = tx.send(WorkerIpcMessage::ControlAck {
                                                    revision_seq,
                                                    applied: res.applied,
                                                    detail: res.detail,
                                                    effective_limits: ctx.current_limits.clone(),
                                                }).await;
                                                if action == lattice_protocol::JobControlAction::Stop && res.applied {
                                                    let _ = tx.send(WorkerIpcMessage::StateChange {
                                                        state: JobState::Completed,
                                                        detail: Some("workload stopped via control revision".to_string()),
                                                        exit_code: Some(0),
                                                    }).await;
                                                    break;
                                                }
                                            }
                                            Err(err) => {
                                                let _ = tx.send(WorkerIpcMessage::ControlAck {
                                                    revision_seq,
                                                    applied: false,
                                                    detail: Some(err),
                                                    effective_limits: ctx.current_limits.clone(),
                                                }).await;
                                            }
                                        }
                                    }
                                    WorkerIpcMessage::Stop { grace_ms } => {
                                        let _ = adapter.stop(Duration::from_millis(grace_ms)).await;
                                        let _ = tx.send(WorkerIpcMessage::StateChange {
                                            state: JobState::Completed,
                                            detail: Some("workload stopped by node request".to_string()),
                                            exit_code: Some(0),
                                        }).await;
                                        break;
                                    }
                                    WorkerIpcMessage::Ping => {
                                        let _ = tx.send(WorkerIpcMessage::Pong).await;
                                    }
                                    _ => {}
                                }
                            }
                            auth_line.clear();
                    }
                    Err(_) => {
                        break;
                    }
                }
            }

            // Poll child process exit status
            _ = check_status_interval.tick(), if is_started => {
                if let Ok(Some(status)) = adapter.poll_status().await {
                    let exit_code: Option<i32> = status.code();
                    if status.success() {
                        let _ = tx.send(WorkerIpcMessage::StateChange {
                            state: JobState::Completed,
                            detail: Some("workload exited cleanly".to_string()),
                            exit_code,
                        }).await;
                    } else {
                        let _ = tx.send(WorkerIpcMessage::StateChange {
                            state: JobState::Failed,
                            detail: Some(format!("workload exited with error code: {:?}", exit_code)),
                            exit_code,
                        }).await;
                    }
                    break;
                }
            }

            // Collect backend telemetry and send to supervisor
            _ = telemetry_interval.tick(), if is_started => {
                if let Some(telemetry) = adapter.poll_telemetry(&ctx).await {
                    match telemetry {
                        runtime::adapter::AdapterTelemetry::Mining(mining_telem) => {
                            let _ = tx.send(WorkerIpcMessage::Telemetry(mining_telem)).await;
                        }
                        runtime::adapter::AdapterTelemetry::Generic { .. } => {}
                    }
                }
            }
        }
    }

    // Clean exit (MED-07)
    let _ = adapter.stop(Duration::from_millis(1500)).await;
    drop(tx);
    let _ = writer_task.await;

    Ok(())
}
