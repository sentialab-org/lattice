#[cfg(windows)]
mod windows_service;

use lattice_node::{ipc_endpoint, run_node};
use tokio::sync::watch;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(windows)]
    {
        match std::env::args().nth(1).as_deref() {
            Some("--service") => return windows_service::run_dispatcher(),
            Some("--install-service") => return windows_service::install(),
            Some("--uninstall-service") => return windows_service::uninstall(),
            Some("--start-service") => return windows_service::start(),
            Some("--stop-service") => return windows_service::stop(),
            _ => {}
        }
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run_console())
}

async fn run_console() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown_tx.send(true);
    });

    println!("Lattice Node");
    println!("IPC endpoint: {}", ipc_endpoint());

    run_node(shutdown_rx).await
}
