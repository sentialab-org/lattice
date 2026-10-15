use lattice_ipc::request;
use lattice_protocol::{
    EnrollmentStatus, IpcRequest, IpcResponse, NetworkLocalConfig, NetworkStatusSummary,
    NodeConfig, NodeStatus,
};

fn response_error(response: IpcResponse) -> String {
    match response {
        IpcResponse::Error { message } => message,
        other => format!("unexpected lattice-node response: {other:?}"),
    }
}

fn setup_request(options: lattice_protocol::SetupOptions) -> IpcRequest {
    IpcRequest::BeginSetup { options }
}
#[tauri::command]
async fn get_participation() -> Result<lattice_protocol::ParticipationStatus, String> {
    match request(&IpcRequest::GetParticipation).await? {
        IpcResponse::Participation(p) => Ok(p),
        response => Err(response_error(response)),
    }
}
#[tauri::command]
async fn accept_participation(
    version: String,
    sha256: String,
) -> Result<lattice_protocol::ParticipationStatus, String> {
    match request(&IpcRequest::AcceptParticipation { version, sha256 }).await? {
        IpcResponse::Participation(p) => Ok(p),
        response => Err(response_error(response)),
    }
}
#[tauri::command]
async fn list_masters() -> Result<lattice_protocol::SignedMasterDirectory, String> {
    match request(&IpcRequest::ListMasters).await? {
        IpcResponse::Masters(d) => Ok(d),
        response => Err(response_error(response)),
    }
}
#[tauri::command]
async fn select_master(
    control_id: Option<String>,
) -> Result<lattice_protocol::ParticipationStatus, String> {
    match request(&IpcRequest::SelectMaster { control_id }).await? {
        IpcResponse::Participation(p) => Ok(p),
        response => Err(response_error(response)),
    }
}
#[tauri::command]
async fn setup_node(
    options: lattice_protocol::SetupOptions,
) -> Result<lattice_protocol::SetupReport, String> {
    match request(&setup_request(options)).await? {
        IpcResponse::SetupStatus(report) => Ok(report),
        response => Err(response_error(response)),
    }
}
#[tauri::command]
async fn get_setup_status() -> Result<lattice_protocol::SetupReport, String> {
    match request(&IpcRequest::GetSetupStatus).await? {
        IpcResponse::SetupStatus(report) => Ok(report),
        response => Err(response_error(response)),
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

#[tauri::command]
async fn get_enrollment_status() -> Result<EnrollmentStatus, String> {
    match request(&IpcRequest::GetEnrollmentStatus).await? {
        IpcResponse::EnrollmentStatus(status) => Ok(status),
        response => Err(response_error(response)),
    }
}

#[tauri::command]
async fn enroll_node(
    control_url: String,
    enrollment_token: String,
) -> Result<EnrollmentStatus, String> {
    match request(&IpcRequest::Enroll {
        control_url,
        enrollment_token,
    })
    .await?
    {
        IpcResponse::EnrollmentUpdated(status) => Ok(status),
        response => Err(response_error(response)),
    }
}

#[tauri::command]
async fn reset_enrollment() -> Result<EnrollmentStatus, String> {
    match request(&IpcRequest::ResetEnrollment).await? {
        IpcResponse::EnrollmentUpdated(status) => Ok(status),
        response => Err(response_error(response)),
    }
}

#[tauri::command]
async fn enroll_bootstrap(
    bootstrap_url: String,
    enrollment_token: String,
) -> Result<EnrollmentStatus, String> {
    match request(&IpcRequest::EnrollBootstrap {
        bootstrap_url,
        enrollment_token,
    })
    .await?
    {
        IpcResponse::EnrollmentUpdated(status) => Ok(status),
        response => Err(response_error(response)),
    }
}

#[tauri::command]
async fn reset_bootstrap() -> Result<EnrollmentStatus, String> {
    match request(&IpcRequest::ResetBootstrap).await? {
        IpcResponse::EnrollmentUpdated(status) => Ok(status),
        response => Err(response_error(response)),
    }
}

#[tauri::command]
async fn get_network_status() -> Result<NetworkStatusSummary, String> {
    match request(&IpcRequest::GetNetworkStatus).await? {
        IpcResponse::NetworkStatus(status) => Ok(status),
        response => Err(response_error(response)),
    }
}

#[tauri::command]
async fn set_network_enabled(enabled: bool) -> Result<NetworkLocalConfig, String> {
    match request(&IpcRequest::SetNetworkEnabled { enabled }).await? {
        IpcResponse::NetworkConfigUpdated(config) => Ok(config),
        response => Err(response_error(response)),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_participation,
            accept_participation,
            list_masters,
            select_master,
            setup_node,
            get_setup_status,
            ping_node,
            get_node_status,
            get_node_config,
            set_node_config,
            get_enrollment_status,
            enroll_node,
            reset_enrollment,
            enroll_bootstrap,
            reset_bootstrap,
            get_network_status,
            set_network_enabled
        ])
        .run(tauri::generate_context!())
        .expect("error while running Lattice");
}

#[cfg(test)]
mod setup_tests {
    use super::*;
    use lattice_protocol::{NodeRole, SetupOptions};
    #[test]
    fn ordinary_setup_uses_shared_ipc_without_a_token() {
        let options = SetupOptions {
            role: NodeRole::Node,
            bootstrap_url: "https://coordinator.test".into(),
            master_token: None,
        };
        assert!(
            matches!(setup_request(options),IpcRequest::BeginSetup{options} if options.master_token.is_none())
        );
    }
    #[test]
    fn setup_debug_never_discloses_master_token() {
        let request = setup_request(SetupOptions {
            role: NodeRole::Master,
            bootstrap_url: "https://coordinator.test".into(),
            master_token: Some("private-test-token".into()),
        });
        assert!(!format!("{request:?}").contains("private-test-token"));
    }
}
