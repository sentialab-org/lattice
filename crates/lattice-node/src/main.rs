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

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|a| a == "verify-report") {
        std::process::exit(
            if args
                .get(1)
                .is_some_and(|p| lattice_node::verification::check_file(std::path::Path::new(p)))
            {
                0
            } else {
                1
            },
        );
    }
    if args.first().is_some_and(|a| a == "verify-bundle") {
        if let Err(e) = lattice_node::bundle::run(&args[1..]) {
            eprintln!("{e}");
            std::process::exit(1);
        }
        return Ok(());
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|a| a == "verify-installation") {
        match runtime.block_on(lattice_node::verification::run(&args[1..])) {
            Ok(code) => std::process::exit(code),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }
    if args
        .first()
        .is_some_and(|a| matches!(a.as_str(), "masters" | "select-master" | "accept-terms"))
    {
        match runtime.block_on(lattice_node::setup_cli::owner_command(&args)) {
            Ok(code) => std::process::exit(code),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }
    if args.first().is_some_and(|a| a == "setup") {
        match runtime.block_on(lattice_node::setup_cli::run(&args[1..])) {
            Ok(code) => std::process::exit(code),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }
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
