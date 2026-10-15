pub mod credentials;
pub mod handlers;
pub mod sessions;
use crate::{ApiResponseError, AppState};
use axum::http::{HeaderMap, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
pub use sessions::{AuthConfig, AuthState};
use sha2::{Digest, Sha256};
use std::{io::Write, path::Path};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorScope {
    FleetRead,
    TokensWrite,
    NetworkWrite,
    WorkloadRead,
    WorkloadWrite,
    MastersWrite,
}
impl OperatorScope {
    pub fn is_write(self) -> bool {
        !matches!(self, Self::FleetRead | Self::WorkloadRead)
    }
}
#[derive(Debug, Clone)]
pub struct OperatorPrincipal {
    pub username: String,
    pub scope: Option<OperatorScope>,
}
#[derive(Debug)]
pub enum AuthError {
    Credentials,
    Expired,
    Csrf,
    Throttled,
    Persistence,
}
impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "authentication failed: {self:?}")
    }
}
impl std::error::Error for AuthError {}
impl From<AuthError> for ApiResponseError {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::Csrf => Self::new(
                StatusCode::FORBIDDEN,
                "csrf_rejected",
                "same-origin CSRF proof is required",
            ),
            AuthError::Throttled => Self::new(
                StatusCode::TOO_MANY_REQUESTS,
                "login_throttled",
                "retry later",
            ),
            AuthError::Persistence => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                "authentication storage unavailable",
            ),
            _ => Self::unauthorized("authentication_required", "authentication failed"),
        }
    }
}
pub fn digest(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub fn random_secret() -> String {
    use rand_core::{OsRng, RngCore};
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn atomic_json<T: Serialize>(path: &Path, value: &T) -> Result<(), AuthError> {
    let parent = path.parent().ok_or(AuthError::Persistence)?;
    std::fs::create_dir_all(parent).map_err(|_| AuthError::Persistence)?;
    let temp = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&temp).map_err(|_| AuthError::Persistence)?;
        let bytes = serde_json::to_vec(value).map_err(|_| AuthError::Persistence)?;
        f.write_all(&bytes)
            .and_then(|_| f.sync_all())
            .map_err(|_| AuthError::Persistence)?;
        std::fs::rename(&temp, path).map_err(|_| AuthError::Persistence)?;
        #[cfg(unix)]
        std::fs::File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|_| AuthError::Persistence)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}
pub fn read_json<T: DeserializeOwned + Default>(path: &Path) -> Result<T, AuthError> {
    match std::fs::read(path) {
        Ok(b) => serde_json::from_slice(&b).map_err(|_| AuthError::Persistence),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(_) => Err(AuthError::Persistence),
    }
}
pub fn authorize_operator(
    state: &AppState,
    headers: &HeaderMap,
    delegation: Option<&OperatorPrincipal>,
    scope: OperatorScope,
) -> Result<OperatorPrincipal, ApiResponseError> {
    if let Some(p) = delegation {
        if p.scope == Some(scope) {
            return Ok(p.clone());
        }
        return Err(ApiResponseError::new(
            StatusCode::FORBIDDEN,
            "invalid_scope",
            "delegation scope rejected",
        ));
    }
    // Supplying a legacy server-side token explicitly enables this compatibility path.
    if let Some(expected) = state.operator_token.as_deref() {
        if !expected.is_empty() {
            if let Some(value) = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
            {
                if crate::constant_time_token_match(value, expected) {
                    return Ok(OperatorPrincipal {
                        username: "legacy-operator".into(),
                        scope: None,
                    });
                }
            }
        }
    }
    Ok(state
        .auth
        .authenticate(headers, scope, state.clock.now_ms())?)
}
