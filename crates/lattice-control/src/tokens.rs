use crate::{
    ApiResponseError, AppState,
    auth::{self, OperatorScope},
};
use axum::{Json, extract::State, http::HeaderMap};
use lattice_protocol::{CreatedMasterToken, MasterTokenSummary, SignedMasterGrant};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use tokio::sync::Mutex;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActivationBinding {
    pub node_id: String,
    pub node_public_key: String,
    pub control_id: String,
    pub control_public_key: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct MasterTokenRecord {
    token_id: String,
    label: String,
    token_sha256: String,
    created_at_ms: u64,
    expires_at_ms: u64,
    revoked_at_ms: Option<u64>,
    binding: Option<ActivationBinding>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct MasterAuthorizationStore {
    tokens: BTreeMap<String, MasterTokenRecord>,
    pub grants: BTreeMap<String, SignedMasterGrant>,
    pub revoked: BTreeSet<String>,
    pub revision: u64,
}
pub struct TokenStore {
    path: PathBuf,
    data: Mutex<MasterAuthorizationStore>,
}
#[derive(Debug)]
pub enum TokenError {
    Invalid,
    Expired,
    Revoked,
    ConflictingBinding,
    Persistence,
}
impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "master authorization rejected: {self:?}")
    }
}
impl std::error::Error for TokenError {}
impl From<TokenError> for ApiResponseError {
    fn from(e: TokenError) -> Self {
        match e {
            TokenError::Persistence => Self::new(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "authorization_storage_unavailable",
                "authorization storage unavailable",
            ),
            _ => Self::unauthorized(
                "master_authorization_rejected",
                "master authorization rejected",
            ),
        }
    }
}
#[derive(Debug)]
pub struct Redemption {
    pub grant: SignedMasterGrant,
    pub first_use: bool,
}
impl TokenStore {
    pub fn load(dir: &Path) -> Result<Self, TokenError> {
        let path = dir.join("master-authorizations.json");
        Ok(Self {
            data: Mutex::new(auth::read_json(&path).map_err(|_| TokenError::Persistence)?),
            path,
        })
    }
    fn save(&self, next: &MasterAuthorizationStore) -> Result<(), TokenError> {
        auth::atomic_json(&self.path, next).map_err(|_| TokenError::Persistence)
    }
    pub async fn snapshot(&self) -> MasterAuthorizationStore {
        self.data.lock().await.clone()
    }
    pub async fn create(&self, label: &str, now: u64) -> Result<CreatedMasterToken, TokenError> {
        if label.trim().is_empty() || label.len() > 128 {
            return Err(TokenError::Invalid);
        }
        let raw = auth::random_secret();
        let id = uuid::Uuid::new_v4().to_string();
        let expires = now.saturating_add(86_400_000);
        let record = MasterTokenRecord {
            token_id: id.clone(),
            label: label.into(),
            token_sha256: auth::digest(raw.as_bytes()),
            created_at_ms: now,
            expires_at_ms: expires,
            revoked_at_ms: None,
            binding: None,
        };
        let mut store = self.data.lock().await;
        let mut next = store.clone();
        next.tokens.insert(id.clone(), record);
        self.save(&next)?;
        *store = next;
        Ok(CreatedMasterToken {
            token_id: id,
            label: label.into(),
            activation_token: raw,
            created_at_ms: now,
            expires_at_ms: expires,
        })
    }
    pub async fn list(&self) -> Vec<MasterTokenSummary> {
        self.data
            .lock()
            .await
            .tokens
            .values()
            .map(|r| MasterTokenSummary {
                token_id: r.token_id.clone(),
                label: r.label.clone(),
                created_at_ms: r.created_at_ms,
                expires_at_ms: r.expires_at_ms,
                revoked_at_ms: r.revoked_at_ms,
                activated_node_id: r.binding.as_ref().map(|b| b.node_id.clone()),
            })
            .collect()
    }
    pub async fn revoke(&self, id: &str, now: u64) -> Result<(), TokenError> {
        let mut store = self.data.lock().await;
        let mut next = store.clone();
        next.tokens
            .get_mut(id)
            .ok_or(TokenError::Invalid)?
            .revoked_at_ms = Some(now);
        self.save(&next)?;
        *store = next;
        Ok(())
    }
    pub async fn redeem(
        &self,
        token: &str,
        binding: &ActivationBinding,
        grant: SignedMasterGrant,
        now: u64,
    ) -> Result<Redemption, TokenError> {
        if token.len() != 64 {
            return Err(TokenError::Invalid);
        }
        let hash = auth::digest(token.as_bytes());
        let mut store = self.data.lock().await;
        let id = store
            .tokens
            .values()
            .find(|r| crate::constant_time_token_match(&hash, &r.token_sha256))
            .map(|r| r.token_id.clone())
            .ok_or(TokenError::Invalid)?;
        let r = store.tokens.get(&id).ok_or(TokenError::Invalid)?;
        if r.revoked_at_ms.is_some() || store.revoked.contains(&binding.control_id) {
            return Err(TokenError::Revoked);
        }
        if let Some(existing) = &r.binding {
            if existing != binding {
                return Err(TokenError::ConflictingBinding);
            }
            return Ok(Redemption {
                grant: store
                    .grants
                    .get(&binding.control_id)
                    .ok_or(TokenError::Invalid)?
                    .clone(),
                first_use: false,
            });
        }
        if now >= r.expires_at_ms || now < r.created_at_ms {
            return Err(TokenError::Expired);
        }
        if store.grants.contains_key(&binding.control_id) {
            return Err(TokenError::ConflictingBinding);
        }
        if grant.grant.node_id != binding.node_id
            || grant.grant.node_public_key != binding.node_public_key
            || grant.grant.control_id != binding.control_id
            || grant.grant.control_public_key != binding.control_public_key
        {
            return Err(TokenError::ConflictingBinding);
        }
        let mut next = store.clone();
        next.tokens.get_mut(&id).ok_or(TokenError::Invalid)?.binding = Some(binding.clone());
        next.grants
            .insert(binding.control_id.clone(), grant.clone());
        next.revision += 1;
        self.save(&next)?;
        *store = next;
        Ok(Redemption {
            grant,
            first_use: true,
        })
    }
    pub async fn recover(
        &self,
        binding: &ActivationBinding,
    ) -> Result<SignedMasterGrant, TokenError> {
        let store = self.data.lock().await;
        if store.revoked.contains(&binding.control_id) {
            return Err(TokenError::Revoked);
        }
        let record = store
            .tokens
            .values()
            .find(|r| r.binding.as_ref() == Some(binding))
            .ok_or(TokenError::Invalid)?;
        if record.revoked_at_ms.is_some() {
            return Err(TokenError::Revoked);
        }
        store
            .grants
            .get(&binding.control_id)
            .cloned()
            .ok_or(TokenError::Invalid)
    }
    pub async fn revoke_master(&self, id: &str) -> Result<(), TokenError> {
        let mut store = self.data.lock().await;
        if !store.grants.contains_key(id) {
            return Err(TokenError::Invalid);
        }
        let mut next = store.clone();
        next.revoked.insert(id.into());
        next.revision += 1;
        self.save(&next)?;
        *store = next;
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateToken {
    label: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeToken {
    token_id: String,
}
pub async fn create(
    State(s): State<AppState>,
    h: HeaderMap,
    Json(r): Json<CreateToken>,
) -> Result<axum::response::Response, ApiResponseError> {
    use axum::response::IntoResponse;
    auth::authorize_operator(&s, &h, None, OperatorScope::TokensWrite)?;
    let t = s.master_tokens.create(&r.label, s.clock.now_ms()).await?;
    let mut response = Json(t).into_response();
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    Ok(response)
}
pub async fn list(
    State(s): State<AppState>,
    h: HeaderMap,
) -> Result<Json<Vec<MasterTokenSummary>>, ApiResponseError> {
    auth::authorize_operator(&s, &h, None, OperatorScope::FleetRead)?;
    Ok(Json(s.master_tokens.list().await))
}
pub async fn revoke(
    State(s): State<AppState>,
    h: HeaderMap,
    Json(r): Json<RevokeToken>,
) -> Result<Json<serde_json::Value>, ApiResponseError> {
    auth::authorize_operator(&s, &h, None, OperatorScope::TokensWrite)?;
    s.master_tokens
        .revoke(&r.token_id, s.clock.now_ms())
        .await?;
    Ok(Json(serde_json::json!({"ok":true})))
}
