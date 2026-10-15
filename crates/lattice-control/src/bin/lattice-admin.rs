use std::{io::Read, path::PathBuf};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("provision") {
        println!(
            "Usage: lattice-admin provision --data-dir PATH --username USER [--password-stdin]"
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
