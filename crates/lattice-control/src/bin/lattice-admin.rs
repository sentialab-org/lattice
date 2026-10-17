use std::{io::Read, path::PathBuf};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !matches!(
        args.first().map(String::as_str),
        Some("provision" | "initialize-supervisor")
    ) {
        println!(
            "Usage: lattice-admin provision --data-dir PATH --username USER [--password-stdin] | initialize-supervisor --data-dir PATH --public-url HTTPS_ORIGIN"
        );
        return Ok(());
    }
    let value = |flag: &str| {
        args.iter()
            .position(|v| v == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let dir = PathBuf::from(value("--data-dir").ok_or("--data-dir is required")?);
    if args[0] == "initialize-supervisor" {
        let public_url = value("--public-url").ok_or("--public-url is required")?;
        std::fs::create_dir_all(&dir)?;
        let metadata = std::fs::symlink_metadata(&dir)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("protected authority directory required".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if metadata.uid() != unsafe { libc::geteuid() } {
                return Err("authority directory ownership rejected".into());
            }
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let names = [
            "control-identity.json",
            "network.json",
            "gateway_wireguard.json",
        ];
        let present = names.iter().filter(|name| dir.join(name).exists()).count();
        if present != 0 && present != names.len() {
            return Err(
                "incomplete authority; recover original files before initialization".into(),
            );
        }
        if present == 0
            && std::fs::read_dir(&dir)?.any(|entry| {
                entry
                    .map(|entry| entry.file_name() != "account.json")
                    .unwrap_or(true)
            })
        {
            return Err("existing authority records without keys require recovery".into());
        }
        // The authority process alone creates or reads its signing/account state; no service or OS networking is started.
        let state =
            lattice_control::load_state(&dir, String::new(), None, public_url, "supervisor".into())
                .await?;
        println!(
            "Supervisor initialized. Public fingerprint: {}",
            lattice_crypto::fingerprint(&state.control.public_key)?
        );
        return Ok(());
    }
    let user = value("--username").ok_or("--username is required")?;
    let mut password = if args.iter().any(|v| v == "--password-stdin") {
        let mut bytes = Vec::new();
        std::io::stdin().take(1025).read_to_end(&mut bytes)?;
        bytes
    } else {
        rpassword::prompt_password("Account password: ")?.into_bytes()
    };
    let result =
        lattice_control::auth::credentials::provision(&dir.join("account.json"), &user, &password);
    password.fill(0);
    result?;
    println!(
        "Account provisioned. Existing sessions must be revoked before a credential rotation."
    );
    Ok(())
}
