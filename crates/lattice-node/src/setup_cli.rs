use crate::setup::SetupError;
use lattice_protocol::*;
pub async fn run(args: &[String]) -> Result<i32, SetupError> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "Usage: lattice-node setup [--wait | --role node|master --bootstrap-url URL [--timeout-secs 120] [--json] [--master-token-stdin] [--accept-terms]]\nMaster activation is entered privately after elevation. The running daemon owns setup and retries."
        );
        return Ok(0);
    }
    let value = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .map(String::as_str)
    };
    let wait_only = args.iter().any(|s| s == "--wait");
    if !wait_only {
        confirm_participation(args).await?;
        let role = match value("--role").unwrap_or("node") {
            "node" => NodeRole::Node,
            "master" => NodeRole::Master,
            _ => return Err(SetupError::Preflight),
        };
        let url = value("--bootstrap-url").ok_or(SetupError::Preflight)?;
        let token = if role == NodeRole::Master {
            if args.iter().any(|a| a == "--master-token-stdin") {
                use std::io::Read;
                let mut bytes = Vec::new();
                std::io::stdin()
                    .take(1025)
                    .read_to_end(&mut bytes)
                    .map_err(|_| SetupError::Preflight)?;
                if bytes.len() > 1024 {
                    return Err(SetupError::Preflight);
                }
                let s = String::from_utf8(bytes).map_err(|_| SetupError::Preflight)?;
                Some(s.trim_end_matches(['\r', '\n']).into())
            } else {
                Some(
                    rpassword::prompt_password(
                        "Master activation token (leave empty to recover activation): ",
                    )
                    .map_err(|_| SetupError::Preflight)?,
                )
            }
        } else {
            None
        };
        let options = SetupOptions {
            role,
            bootstrap_url: url.into(),
            master_token: token,
        };
        match lattice_ipc::request(&IpcRequest::BeginSetup { options })
            .await
            .map_err(|_| SetupError::Preflight)?
        {
            IpcResponse::SetupStatus(_) => {}
            IpcResponse::Error { message } => {
                eprintln!("{message}");
                return Ok(1);
            }
            _ => return Err(SetupError::Preflight),
        }
    }
    let timeout = value("--timeout-secs")
        .unwrap_or("120")
        .parse::<u64>()
        .map_err(|_| SetupError::Preflight)?
        .clamp(1, 1800);
    let until = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout);
    loop {
        let r = match lattice_ipc::request(&IpcRequest::GetSetupStatus)
            .await
            .map_err(|_| SetupError::Preflight)?
        {
            IpcResponse::SetupStatus(r) => r,
            _ => return Err(SetupError::Preflight),
        };
        let code = match r.stage {
            SetupStage::Ready => Some(0),
            SetupStage::WaitingForMaster if !wait_only || tokio::time::Instant::now() >= until => {
                Some(2)
            }
            _ => None,
        };
        if code.is_some() || tokio::time::Instant::now() >= until {
            println!(
                "{}",
                serde_json::to_string(&r).map_err(|_| SetupError::Persistence)?
            );
            return Ok(code.unwrap_or(1));
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

async fn confirm_participation(args: &[String]) -> Result<(), SetupError> {
    let status = match lattice_ipc::request(&IpcRequest::GetParticipation)
        .await
        .map_err(|_| SetupError::Preflight)?
    {
        IpcResponse::Participation(p) => p,
        _ => return Err(SetupError::Preflight),
    };
    if status.accepted {
        return Ok(());
    }
    eprintln!(
        "{}\nVersion: {}\nSHA-256: {}",
        status.text, status.version, status.sha256
    );
    if !args.iter().any(|a| a == "--accept-terms") {
        eprintln!("Accept the participation terms above? [yes/no]");
        let answer = read_visible_answer()?;
        if !consents_to_terms(&answer) {
            eprintln!("Declined: installation stopped without accepting the participation terms.");
            return Err(SetupError::TermsRequired);
        }
    }
    match lattice_ipc::request(&IpcRequest::AcceptParticipation {
        version: status.version,
        sha256: status.sha256,
    })
    .await
    .map_err(|_| SetupError::Preflight)?
    {
        IpcResponse::Participation(p) if p.accepted => Ok(()),
        _ => Err(SetupError::TermsRequired),
    }
}
pub async fn owner_command(args: &[String]) -> Result<i32, SetupError> {
    let command = args.first().map(String::as_str).unwrap_or("");
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "lattice-node masters | select-master --id CONTROL_ID | select-master --clear | accept-terms [--accept-terms]"
        );
        return Ok(0);
    }
    if command == "accept-terms" {
        confirm_participation(args).await?;
        return Ok(0);
    }
    let request = if command == "masters" {
        IpcRequest::GetMasterCatalog
    } else {
        let id = args
            .iter()
            .position(|v| v == "--id")
            .and_then(|i| args.get(i + 1))
            .cloned();
        if id.is_none() && !args.iter().any(|a| a == "--clear") {
            return Err(SetupError::Preflight);
        }
        if id.is_some() && args.iter().any(|a| a == "--clear") {
            return Err(SetupError::Preflight);
        }
        IpcRequest::SelectMaster { control_id: id }
    };
    let response = lattice_ipc::request(&request)
        .await
        .map_err(|_| SetupError::Preflight)?;
    let value = match response {
        IpcResponse::Masters(d) => serde_json::to_value(d),
        IpcResponse::MasterCatalog(d) => serde_json::to_value(d),
        IpcResponse::Participation(p) => serde_json::to_value(p),
        IpcResponse::Error { message } => {
            eprintln!("{message}");
            return Ok(1);
        }
        _ => return Err(SetupError::Preflight),
    }
    .map_err(|_| SetupError::Persistence)?;
    println!("{}", value);
    Ok(0)
}

#[cfg(test)]
mod module_cli_tests {
    use super::*;
    #[test]
    fn supervisor_activation_is_explicit_and_preserves_the_public_ingress() {
        let args = [
            "module",
            "enable",
            "--kind",
            "supervisor",
            "--authority-data-dir",
            "/private/authority",
            "--public-url",
            "https://lattice.test",
            "--adopt-gateway",
            "--enable-network",
        ];
        let request = module_cli_request(&args.map(str::to_owned)).unwrap();
        assert!(
            matches!(request,IpcRequest::EnableModule {activation} if activation.kind==ModuleKind::Supervisor && activation.adopt_gateway && activation.enable_network && activation.authority_data_dir.as_deref()==Some("/private/authority") && activation.public_url.as_deref()==Some("https://lattice.test"))
        );
    }
    #[test]
    fn module_cli_rejects_unknown_or_incomplete_actions() {
        for args in [
            vec!["module"],
            vec!["module", "enable"],
            vec!["module", "enable", "--kind", "unknown"],
            vec!["module", "disable", "--kind", "relay", "--adopt-gateway"],
        ] {
            assert!(
                module_cli_request(&args.into_iter().map(str::to_owned).collect::<Vec<_>>())
                    .is_err()
            );
        }
    }
    #[test]
    fn visible_answer_accepts_only_explicit_yes_or_y() {
        for accepted in ["yes", "Yes", "YES", "y", "Y", " yes\n", "\ty\r"] {
            assert!(consents_to_terms(accepted), "{accepted:?} must consent");
        }
        for declined in [
            "", "\n", "accept", "accept\n", " y es", "yesextra", "no", "n", "ok",
        ] {
            assert!(!consents_to_terms(declined), "{declined:?} must decline");
        }
    }
}

fn read_visible_answer() -> Result<String, SetupError> {
    #[cfg(unix)]
    {
        use std::io::BufRead;
        let tty = std::fs::File::open("/dev/tty").map_err(|_| SetupError::TermsRequired)?;
        let mut line = String::new();
        std::io::BufReader::new(tty)
            .read_line(&mut line)
            .map_err(|_| SetupError::TermsRequired)?;
        Ok(line)
    }
    #[cfg(not(unix))]
    {
        use std::io::BufRead;
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|_| SetupError::TermsRequired)?;
        Ok(line)
    }
}

fn consents_to_terms(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "yes" | "y")
}

fn module_cli_request(args: &[String]) -> Result<IpcRequest, String> {
    let value = |flag: &str| {
        args.iter()
            .position(|v| v == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let kind = match value("--kind").as_deref() {
        Some("master") => ModuleKind::Master,
        Some("relay") => ModuleKind::Relay,
        Some("supervisor") => ModuleKind::Supervisor,
        _ => return Err("choose --kind master|relay|supervisor".into()),
    };
    match args.get(1).map(String::as_str) {
        Some("enable") => {
            let mut index = 2;
            while index < args.len() {
                match args[index].as_str() {
                    "--adopt-gateway" | "--enable-network" => index += 1,
                    "--kind"
                    | "--authority-data-dir"
                    | "--public-url"
                    | "--forwarding-limit-bps"
                        if index + 1 < args.len() =>
                    {
                        index += 2
                    }
                    _ => return Err("unknown or incomplete module option".into()),
                }
            }
            Ok(IpcRequest::EnableModule {
                activation: ModuleActivation {
                    kind,
                    certificate: None,
                    authority_data_dir: value("--authority-data-dir"),
                    public_url: value("--public-url"),
                    adopt_gateway: args.iter().any(|a| a == "--adopt-gateway"),
                    enable_network: args.iter().any(|a| a == "--enable-network"),
                    forwarding_limit_bps: value("--forwarding-limit-bps")
                        .map(|v| v.parse::<u64>())
                        .transpose()
                        .map_err(|_| "invalid forwarding budget")?,
                    activation_token: None,
                },
            })
        }
        Some("disable") if args.len() == 4 && args[2] == "--kind" => {
            Ok(IpcRequest::DisableModule { kind })
        }
        _ => Err("use module enable|disable --kind master|relay|supervisor".into()),
    }
}
pub async fn module_command(args: &[String]) -> Result<i32, String> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "lattice-node modules | network-manager | network enable|disable | module enable|disable --kind master|relay|supervisor [--authority-data-dir PATH --public-url URL --adopt-gateway --enable-network] [--forwarding-limit-bps BPS] | authority import|sync | local-master\nAuthority import and local-master read a bounded typed JSON request from standard input. Supervisor provisioning requires OS administrator rights."
        );
        return Ok(0);
    }
    fn input<T: serde::de::DeserializeOwned>() -> Result<T, String> {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(96 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "input unavailable")?;
        if bytes.len() > 96 * 1024 * 1024 {
            return Err("input exceeds IPC limit".into());
        }
        serde_json::from_slice(&bytes).map_err(|_| "invalid typed JSON request".into())
    }
    let request = match args.first().map(String::as_str) {
        Some("modules") if args.len() == 1 => IpcRequest::GetModules,
        Some("network-manager") if args.len() == 1 => IpcRequest::GetNetworkManager,
        Some("network") if args.len() == 2 && matches!(args[1].as_str(), "enable" | "disable") => {
            IpcRequest::SetNetworkEnabled {
                enabled: args[1] == "enable",
            }
        }
        Some("module") => module_cli_request(args)?,
        Some("authority") if args.len() == 2 => match args[1].as_str() {
            "import" => IpcRequest::ImportAuthority { context: input()? },
            "sync" => IpcRequest::SyncAuthority,
            _ => return Err("use authority import|sync".into()),
        },
        Some("local-master") if args.len() == 1 => IpcRequest::LocalMaster { request: input()? },
        _ => return Err("unknown module command; use --help".into()),
    };
    let response = lattice_ipc::request(&request).await?;
    if let IpcResponse::Error { message } = response {
        eprintln!("{message}");
        return Ok(1);
    }
    println!(
        "{}",
        serde_json::to_string(&response).map_err(|_| "response encoding failed")?
    );
    Ok(0)
}
