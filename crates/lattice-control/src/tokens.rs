use lattice_protocol::EnrollmentTokenRecord;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnrollmentTokenRegistry {
    pub tokens: BTreeMap<String, EnrollmentTokenRecord>,
}

pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.trim().as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn tokens_match(provided_sha256: &str, expected_sha256: &str) -> bool {
    let provided = provided_sha256.as_bytes();
    let expected = expected_sha256.as_bytes();
    provided.len() == expected.len() && provided.ct_eq(expected).into()
}

pub async fn load_or_create(
    data_dir: &Path,
) -> Result<(PathBuf, EnrollmentTokenRegistry), Box<dyn std::error::Error + Send + Sync>> {
    let path = data_dir.join("enrollment-tokens.json");
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => Ok((path, serde_json::from_str(&content)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut registry = EnrollmentTokenRegistry::default();
            if let Ok(bootstrap) = std::env::var("LATTICE_ENROLLMENT_TOKEN") {
                let bootstrap = bootstrap.trim().to_string();
                if !bootstrap.is_empty() {
                    registry.tokens.insert(
                        "bootstrap".to_string(),
                        EnrollmentTokenRecord {
                            token_id: "bootstrap".to_string(),
                            label: "bootstrap".to_string(),
                            token_sha256: hash_token(&bootstrap),
                            created_at_ms: crate::unix_time_ms(),
                            revoked: false,
                        },
                    );
                }
            }
            let content = serde_json::to_vec_pretty(&registry)?;
            tokio::fs::write(&path, content).await?;
            crate::secure_file(&path)?;
            Ok((path, registry))
        }
        Err(error) => Err(error.into()),
    }
}

pub async fn save(path: &Path, registry: &EnrollmentTokenRegistry) -> Result<(), String> {
    let content = serde_json::to_vec_pretty(registry).map_err(|error| error.to_string())?;
    crate::network::write_atomic(path, &content).await
}

pub fn is_valid(registry: &EnrollmentTokenRegistry, token: &str) -> bool {
    let candidate = hash_token(token);
    registry
        .tokens
        .values()
        .any(|record| !record.revoked && tokens_match(&candidate, &record.token_sha256))
}

pub fn admin_credentials() -> Option<(String, String)> {
    let username = std::env::var("LATTICE_ADMIN_USER")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())?;
    let password_sha256 = std::env::var("LATTICE_ADMIN_PASSWORD_SHA256")
        .ok()
        .map(|value| value.trim().to_lowercase())
        .filter(|value| !value.is_empty())?;
    Some((username, password_sha256))
}

pub fn verify_admin(username: &str, password: &str) -> bool {
    let Some((expected_user, expected_hash)) = admin_credentials() else {
        return false;
    };
    let user_ok = username.trim().as_bytes().ct_eq(expected_user.as_bytes()).into();
    let provided_hash = hash_token(password);
    let pass_ok: bool = provided_hash
        .as_bytes()
        .ct_eq(expected_hash.as_bytes())
        .into();
    user_ok && pass_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_hash_is_stable_hex() {
        let first = hash_token("secret-token");
        assert_eq!(first.len(), 64);
        assert_eq!(first, hash_token(" secret-token "));
        assert_ne!(first, hash_token("other-token"));
    }

    #[test]
    fn registry_accepts_valid_and_rejects_revoked() {
        let mut registry = EnrollmentTokenRegistry::default();
        registry.tokens.insert(
            "t1".to_string(),
            EnrollmentTokenRecord {
                token_id: "t1".to_string(),
                label: "test".to_string(),
                token_sha256: hash_token("good-token"),
                created_at_ms: 1,
                revoked: false,
            },
        );
        assert!(is_valid(&registry, "good-token"));
        assert!(!is_valid(&registry, "bad-token"));
        registry.tokens.get_mut("t1").unwrap().revoked = true;
        assert!(!is_valid(&registry, "good-token"));
    }
}
