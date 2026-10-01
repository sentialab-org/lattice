use lattice_ipc::request;
use lattice_protocol::{IpcRequest, IpcResponse, NodeConfig, NodeStatus};

fn response_error(response: IpcResponse) -> String {
    match response {
        IpcResponse::Error { message } => message,
        other => format!("unexpected lattice-node response: {other:?}"),
    }
}

#[tauri::command]
async fn ping_node() -> Result<bool, String> {
    match request(&IpcRequest::Ping).await? {
        IpcResponse::Pong => Ok(true),
        response => Err(response_error(response)),
    }
}

#[tauri::command]
async fn get_node_status() -> Result<NodeStatus, String> {
    match request(&IpcRequest::GetStatus).await? {
        IpcResponse::Status(status) => Ok(status),
        response => Err(response_error(response)),
    }
}

#[tauri::command]
async fn get_node_config() -> Result<NodeConfig, String> {
    match request(&IpcRequest::GetConfig).await? {
        IpcResponse::Config(config) => Ok(config),
        response => Err(response_error(response)),
    }
}

#[tauri::command]
async fn set_node_config(config: NodeConfig) -> Result<NodeConfig, String> {
    match request(&IpcRequest::SetConfig { config }).await? {
        IpcResponse::ConfigUpdated(config) => Ok(config),
        response => Err(response_error(response)),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            ping_node,
            get_node_status,
            get_node_config,
            set_node_config
        ])
        .run(tauri::generate_context!())
        .expect("error while running Lattice");
}
