use lattice_node::run_node;
use std::ffi::{OsStr, OsString};
use std::time::Duration;
use tokio::sync::watch;
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const SERVICE_NAME: &str = "LatticeNode";
const SERVICE_DISPLAY_NAME: &str = "Lattice Node";
const SERVICE_DESCRIPTION: &str = "Lattice distributed resource node runtime";

define_windows_service!(service_entry, service_main);

pub fn run_dispatcher() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    service_dispatcher::start(SERVICE_NAME, service_entry)?;
    Ok(())
}

pub fn install() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let manager = ServiceManager::local_computer(None::<&str>, manager_access)?;
    let executable_path = std::env::current_exe()?;
    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path,
        launch_arguments: vec![OsString::from("--service")],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let access = ServiceAccess::QUERY_CONFIG
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::QUERY_STATUS
        | ServiceAccess::START
        | ServiceAccess::STOP;
    let service = match manager.create_service(&service_info, access) {
        Ok(service) => service,
        Err(_) => {
            let service = manager.open_service(SERVICE_NAME, access)?;
            service.change_config(&service_info)?;
            service
        }
    };

    service.set_description(SERVICE_DESCRIPTION)?;
    service.set_delayed_auto_start(true)?;
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(15),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(30),
            },
        ]),
    })?;
    service.set_failure_actions_on_non_crash_failures(true)?;

    if service.query_status()?.current_state == ServiceState::Stopped {
        service.start::<&OsStr>(&[])?;
    }

    Ok(())
}

pub fn uninstall() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = match manager.open_service(SERVICE_NAME, access) {
        Ok(service) => service,
        Err(_) => return Ok(()),
    };

    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
        wait_for_state(&service, ServiceState::Stopped, Duration::from_secs(15))?;
    }

    service.delete()?;
    Ok(())
}

pub fn start() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::START,
    )?;

    if service.query_status()?.current_state == ServiceState::Stopped {
        service.start::<&OsStr>(&[])?;
    }

    Ok(())
}

pub fn stop() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
    )?;

    if service.query_status()?.current_state != ServiceState::Stopped {
        service.stop()?;
        wait_for_state(&service, ServiceState::Stopped, Duration::from_secs(15))?;
    }

    Ok(())
}

fn wait_for_state(
    service: &windows_service::service::Service,
    expected: ServiceState,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let started = std::time::Instant::now();

    while started.elapsed() < timeout {
        if service
            .query_status()
            .is_ok_and(|status| status.current_state == expected)
        {
            return Ok(());
        }

        std::thread::sleep(Duration::from_millis(200));
    }

    Err(format!("service did not reach {expected:?} before timeout").into())
}

fn service_main(_arguments: Vec<OsString>) {
    let _ = run_service();
}

fn run_service() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handler_tx = shutdown_tx.clone();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = handler_tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
    set_status(
        &status_handle,
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::Win32(0),
    )?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    set_status(
        &status_handle,
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::Win32(0),
    )?;

    let result = runtime.block_on(run_node(shutdown_rx));
    let exit_code = if result.is_ok() {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::ServiceSpecific(1)
    };

    set_status(
        &status_handle,
        ServiceState::StopPending,
        ServiceControlAccept::empty(),
        exit_code,
    )?;
    set_status(
        &status_handle,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit_code,
    )?;

    result
}

fn set_status(
    handle: &ServiceStatusHandle,
    state: ServiceState,
    controls: ServiceControlAccept,
    exit_code: ServiceExitCode,
) -> windows_service::Result<()> {
    let wait_hint = match state {
        ServiceState::StartPending | ServiceState::StopPending => Duration::from_secs(5),
        _ => Duration::ZERO,
    };

    handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: controls,
        exit_code,
        checkpoint: 0,
        wait_hint,
        process_id: None,
    })
}
