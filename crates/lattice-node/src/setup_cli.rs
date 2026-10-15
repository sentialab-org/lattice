use crate::setup::SetupError;
use lattice_protocol::*;
pub async fn run(args: &[String]) -> Result<i32, SetupError> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "Usage: lattice-node setup --role node|master --bootstrap-url URL [--timeout-secs 120] [--json] [--master-token-stdin]\nMaster activation is entered privately after elevation. The running daemon owns setup and retries."
        );
        return Ok(0);
    }
    let value = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .map(String::as_str)
    };
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
            SetupStage::WaitingForMaster => Some(2),
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
