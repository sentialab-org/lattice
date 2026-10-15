#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().collect();
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
