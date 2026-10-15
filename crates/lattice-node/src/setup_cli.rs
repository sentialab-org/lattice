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
        let answer = rpassword::prompt_password("Type yes to accept participation terms: ")
            .map_err(|_| SetupError::TermsRequired)?;
        if answer.trim() != "yes" {
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
        IpcRequest::ListMasters
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
