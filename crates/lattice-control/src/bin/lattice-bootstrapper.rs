#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("lattice-bootstrapper");
        println!("Network coordination, IPAM, and peer discovery.");
        println!();
        println!("Usage: lattice-bootstrapper [gateway-config|gateway-nftables]");
        println!();
        println!("  gateway-config   print the local WireGuard gateway config with the");
        println!("                   real private key (run on the gateway host only)");
        println!("  gateway-nftables print the nftables overlay ruleset");
        println!();
        println!("Environment:");
        println!("  LATTICE_CONTROL_DATA  data directory");
        println!("  LATTICE_CONTROL_BIND  bind address (default 127.0.0.1:7443)");
        println!("  LATTICE_ENROLLMENT_TOKEN  required");
        println!("  LATTICE_OPERATOR_TOKEN  required for operator APIs");
        println!("  LATTICE_CLUSTER_ID  cluster identity (default lattice-main)");
        println!("  LATTICE_NETWORK_*  overlay configuration");
        return Ok(());
    }
    if args.iter().any(|arg| arg == "--version" || arg == "-V") {
        println!("lattice-bootstrapper {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.iter().any(|arg| arg == "gateway-config") {
        let data_dir = std::env::var_os("LATTICE_CONTROL_DATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("./data"));
        let files = lattice_control::network::local_gateway_files(&data_dir).await?;
        println!("# interface: {}", files.interface_name);
        println!("# address: {}", files.address);
        println!("# overlay: {}", files.overlay_cidr);
        println!("# listen-port: {}", files.listen_port);
        print!("{}", files.wireguard_config);
        return Ok(());
    }
    if args.iter().any(|arg| arg == "gateway-nftables") {
        let data_dir = std::env::var_os("LATTICE_CONTROL_DATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("./data"));
        let files = lattice_control::network::local_gateway_files(&data_dir).await?;
        print!("{}", files.nftables_ruleset);
        return Ok(());
    }
    lattice_control::run_server(Some("bootstrapper".to_string())).await
}
