use lattice_protocol::{Architecture, NodeIdentity, Platform};

fn main() {
    let node = NodeIdentity {
        node_id: "local-dev-node".to_string(),
        node_name: "dev-node".to_string(),
        platform: Platform::Linux,
        architecture: Architecture::X86_64,
    };

    println!("Lattice Control");
    println!("sample node: {node:#?}");
}
