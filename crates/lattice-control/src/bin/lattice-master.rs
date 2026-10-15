#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().collect();
    #[cfg(windows)]
    match args.get(1).map(String::as_str) {
        Some("--service") => return lattice_control::windows_service::run_dispatcher(),
        Some("--install-service") => return lattice_control::windows_service::install(),
        Some("--uninstall-service") => return lattice_control::windows_service::uninstall(),
        Some("--start-service") => return lattice_control::windows_service::start(),
        Some("--stop-service") => return lattice_control::windows_service::stop(),
        _ => {}
    }

    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("lattice-master");
        println!("Workload orchestration, scheduling, and command authority.");
        println!();
        println!("Usage: lattice-master");
        println!();
        println!("Environment:");
        println!("  LATTICE_CONTROL_DATA  data directory");
        println!("  LATTICE_CONTROL_BIND  bind address (default 127.0.0.1:7443)");
        println!("  LATTICE_ENROLLMENT_TOKEN  required");
        println!("  LATTICE_OPERATOR_TOKEN  required for operator APIs");
        println!("  LATTICE_CLUSTER_ID  cluster identity (default lattice-main)");
        return Ok(());
    }
    if args.iter().any(|arg| arg == "--version" || arg == "-V") {
        println!("lattice-master {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    lattice_control::run_server(Some("master".to_string())).await
}
