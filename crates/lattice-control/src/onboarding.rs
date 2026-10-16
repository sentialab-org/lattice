use crate::{ApiResponseError, AppState, EnrolledNode, auth};
use axum::{Json, extract::State, http::StatusCode};
use lattice_crypto::{decode_key, sign, verify};
use lattice_protocol::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use tokio::sync::Mutex;
#[derive(Default, Clone, Serialize, Deserialize)]
struct PublicDirectory {
    nodes: BTreeMap<String, String>,
    #[serde(default)]
    master_choices: BTreeMap<String, MasterChoice>,
    #[serde(default)]
    terms: BTreeMap<String, TermsAcceptance>,
}
pub struct OnboardingStore {
    requests: Mutex<BTreeMap<String, u64>>,
    path: PathBuf,
    data: Mutex<PublicDirectory>,
}
impl OnboardingStore {
    pub fn load(dir: &Path) -> Result<Self, auth::AuthError> {
        let path = dir.join("public-memberships.json");
        Ok(Self {
            requests: Mutex::new(BTreeMap::new()),
            data: Mutex::new(auth::read_json(&path)?),
            path,
        })
    }
    pub async fn accept_request(
        &self,
        node: &str,
        id: &str,
        now: u64,
    ) -> Result<(), ApiResponseError> {
        let mut requests = self.requests.lock().await;
        requests.retain(|_, t| now.saturating_sub(*t) < 120_000);
        let key = format!("{node}/{id}");
        if requests.contains_key(&key) || requests.len() >= 10_000 {
            return Err(ApiResponseError::conflict(
                "replayed_discovery",
                "discovery request rejected",
            ));
        }
        requests.insert(key, now);
        Ok(())
    }
    pub async fn accepted_terms(&self, id: &str) -> Option<TermsAcceptance> {
        self.data.lock().await.terms.get(id).cloned()
    }
    pub async fn is_public(&self, id: &str) -> bool {
        self.data.lock().await.nodes.contains_key(id)
    }
    pub async fn recorded_choice(&self, id: &str) -> MasterChoice {
        self.data
            .lock()
            .await
            .master_choices
            .get(id)
            .cloned()
            .unwrap_or_default()
    }
    pub async fn choices(&self) -> BTreeMap<String, MasterChoice> {
        self.data.lock().await.master_choices.clone()
    }
    pub async fn record_choice(
        &self,
        id: &str,
        choice: &MasterChoice,
    ) -> Result<(), ApiResponseError> {
        if choice
            .control_id
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 128 || choice.revision == 0)
        {
            return Err(ApiResponseError::bad_request(
                "invalid_master_choice",
                "invalid owner choice",
            ));
        }
        let mut store = self.data.lock().await;
        if let Some(old) = store.master_choices.get(id) {
            if choice.revision < old.revision || (choice.revision == old.revision && choice != old)
            {
                return Err(ApiResponseError::conflict(
                    "master_choice_rollback",
                    "owner choice revision rejected",
                ));
            }
            if choice == old {
                return Ok(());
            }
        }
        let mut next = store.clone();
        next.master_choices.insert(id.into(), choice.clone());
        auth::atomic_json(&self.path, &next)?;
        *store = next;
        Ok(())
    }
}
pub fn rejected() -> ApiResponseError {
    ApiResponseError::new(
        StatusCode::FORBIDDEN,
        "membership_revoked",
        "network membership is revoked",
    )
}
pub fn sign_value<T: Serialize>(s: &AppState, value: &T) -> Result<String, ApiResponseError> {
    sign(
        &decode_key::<32>(&s.control.private_key).map_err(ApiResponseError::internal)?,
        value,
    )
    .map_err(ApiResponseError::internal)
}
pub async fn membership_for(
    s: &AppState,
    id: &str,
    now: u64,
) -> Result<SignedMembership, ApiResponseError> {
    let d = s.onboarding.data.lock().await;
    let key = d
        .nodes
        .get(id)
        .ok_or_else(|| {
            ApiResponseError::unauthorized("unknown_membership", "public membership required")
        })?
        .clone();
    let n = s.network.read().await;
    if n.allocations.get(id).is_some_and(|a| {
        matches!(
            a.status,
            NetworkNodeStatus::Revoked | NetworkNodeStatus::Disabled
        )
    }) {
        return Err(rejected());
    }
    let m = Membership {
        schema_version: PRODUCT_SCHEMA_VERSION,
        network_id: n.network_id.clone(),
        node_id: id.into(),
        node_public_key: key,
        revision: n.allocations.get(id).map_or(1, |a| a.revision),
        issued_at_ms: now,
        expires_at_ms: now.saturating_add(900_000),
    };
    Ok(SignedMembership {
        signature: sign_value(s, &m)?,
        membership: m,
    })
}
pub async fn public_join(
    State(s): State<AppState>,
    Json(r): Json<PublicJoinRequest>,
) -> Result<Json<PublicJoinResponse>, ApiResponseError> {
    let now = s.clock.now_ms();
    let c = &r.claim.enrollment;
    let terms = r
        .claim
        .terms
        .as_ref()
        .filter(|t| t.is_current(now))
        .ok_or_else(|| {
            ApiResponseError::bad_request(
                "participation_terms_required",
                "accept the current participation terms before joining",
            )
        })?;
    if r.claim.schema_version != PRODUCT_SCHEMA_VERSION
        || c.protocol_version != PROTOCOL_VERSION
        || now.abs_diff(c.issued_at_ms) > 120_000
        || c.node_id.is_empty()
        || !c
            .node_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        || c.node_id.len() > 128
        || c.request_id.len() > 128
        || c.node_name.len() > 128
        || c.client_version.len() > 64
    {
        return Err(ApiResponseError::bad_request(
            "invalid_join",
            "join claim invalid or stale",
        ));
    }
    verify(&c.public_key, &r.signature, &r.claim).map_err(|_| {
        ApiResponseError::unauthorized("invalid_signature", "join identity proof rejected")
    })?;
    // Keep registry + membership repair serialized. An interrupted second write is repaired by the same signed identity.
    {
        let mut registry = s.registry.write().await;
        let mut directory = s.onboarding.data.lock().await;
        if registry
            .nodes
            .get(&c.node_id)
            .is_some_and(|n| n.public_key != c.public_key)
            || directory
                .nodes
                .get(&c.node_id)
                .is_some_and(|k| *k != c.public_key)
        {
            return Err(ApiResponseError::conflict(
                "node_identity_conflict",
                "node identity conflicts with existing key",
            ));
        }
        if s.network
            .read()
            .await
            .allocations
            .get(&c.node_id)
            .is_some_and(|a| {
                matches!(
                    a.status,
                    NetworkNodeStatus::Revoked | NetworkNodeStatus::Disabled
                )
            })
        {
            return Err(rejected());
        }
        if !registry.nodes.contains_key(&c.node_id) {
            let mut next = registry.clone();
            next.nodes.insert(
                c.node_id.clone(),
                EnrolledNode {
                    node_id: c.node_id.clone(),
                    node_name: c.node_name.clone(),
                    public_key: c.public_key.clone(),
                    platform: c.platform.clone(),
                    architecture: c.architecture.clone(),
                    client_version: c.client_version.clone(),
                    enrolled_at_ms: now,
                    last_seen_ms: None,
                    online_until_ms: None,
                    last_sequence: 0,
                    capabilities: None,
                    health: None,
                    effective_policy: None,
                },
            );
            auth::atomic_json(&s.registry_path, &next)?;
            *registry = next;
        }
        let mut next = directory.clone();
        next.nodes.insert(c.node_id.clone(), c.public_key.clone());
        next.terms.insert(c.node_id.clone(), terms.clone());
        auth::atomic_json(&s.onboarding.path, &next)?;
        *directory = next;
    }
    let receipt = EnrollmentReceipt {
        protocol_version: PROTOCOL_VERSION,
        request_id: c.request_id.clone(),
        node_id: c.node_id.clone(),
        control_id: s.control.control_id.clone(),
        control_public_key: s.control.public_key.clone(),
        policy_revision: s.policy.revision,
        issued_at_ms: now,
    };
    Ok(Json(PublicJoinResponse {
        authority: Some(crate::authority::member_context(&s, &c.node_id).await?),
        signature: sign_value(&s, &receipt)?,
        receipt,
        membership: membership_for(&s, &c.node_id, now).await?,
    }))
}
