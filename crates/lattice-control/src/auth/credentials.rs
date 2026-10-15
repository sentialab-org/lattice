use super::{AuthError, atomic_json};
use argon2::{
    Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version,
    password_hash::{PasswordHash, SaltString, rand_core::OsRng},
};
use serde::{Deserialize, Serialize};
use std::path::Path;
#[derive(Clone, Serialize, Deserialize)]
pub struct Account {
    pub username: String,
    password_hash: String,
}
fn hasher() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(19 * 1024, 2, 1, None).expect("fixed Argon2 parameters"),
    )
}
pub fn provision(path: &Path, username: &str, password: &[u8]) -> Result<(), AuthError> {
    if username.is_empty() || username.len() > 128 || password.is_empty() || password.len() > 1024 {
        return Err(AuthError::Credentials);
    }
    let hash = hasher()
        .hash_password(password, &SaltString::generate(&mut OsRng))
        .map_err(|_| AuthError::Credentials)?
        .to_string();
    atomic_json(
        path,
        &Account {
            username: username.into(),
            password_hash: hash,
        },
    )
}
pub fn verify(path: &Path, username: &str, password: &[u8]) -> Result<(), AuthError> {
    let account: Account =
        serde_json::from_slice(&std::fs::read(path).map_err(|_| AuthError::Credentials)?)
            .map_err(|_| AuthError::Credentials)?;
    let parsed = PasswordHash::new(&account.password_hash).map_err(|_| AuthError::Credentials)?;
    let password_ok = hasher().verify_password(password, &parsed).is_ok();
    if password_ok && crate::constant_time_token_match(username, &account.username) {
        Ok(())
    } else {
        Err(AuthError::Credentials)
    }
}
