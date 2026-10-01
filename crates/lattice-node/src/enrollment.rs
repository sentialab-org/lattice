use crate::identity::{IdentityState, unix_time_ms};
use lattice_crypto::{fingerprint, sign, verify};
use lattice_protocol::{
    ApiError, ControlTrust, EnrollmentClaim, EnrollmentRequest, EnrollmentResponse,
    PROTOCOL_VERSION,
};
use reqwest::Client;
use std::time::Duration;
use uuid::Uuid;

pub async fn enroll(
    identity: &IdentityState,
    control_url: &str,
    enrollment_token: &str,
) -> Result<ControlTrust, String> {
    let control_url = normalize_control_url(control_url)?;
    let enrollment_token = enrollment_token.trim();

    if enrollment_token.is_empty() {
        return Err("enrollment token is required".to_string());
    }

    let node = identity.identity();
    let claim = EnrollmentClaim {
        protocol_version: PROTOCOL_VERSION,
        request_id: Uuid::new_v4().to_string(),
        node_id: node.node_id.clone(),
        node_name: node.node_name.clone(),
        platform: node.platform.clone(),
        architecture: node.architecture.clone(),
        public_key: node.public_key.clone(),
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        issued_at_ms: unix_time_ms(),
    };
    let signature = sign(identity.private_key(), &claim)?;
    let request = EnrollmentRequest {
        claim: claim.clone(),
        enrollment_token: enrollment_token.to_string(),
        signature,
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(format!("lattice-node/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| error.to_string())?;
    let response = client
        .post(format!("{control_url}/api/v1/enroll"))
        .json(&request)
        .send()
        .await
        .map_err(|error| format!("control server request failed: {error}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if let Ok(error) = serde_json::from_str::<ApiError>(&body) {
            return Err(format!("{}: {}", error.code, error.message));
        }
        return Err(format!("control server returned HTTP {status}"));
    }

    let enrollment: EnrollmentResponse =
        response.json().await.map_err(|error| error.to_string())?;
    let receipt = &enrollment.receipt;

    if receipt.protocol_version != PROTOCOL_VERSION {
        return Err("control server protocol version mismatch".to_string());
    }

    if receipt.request_id != claim.request_id {
        return Err("control server enrollment response request ID mismatch".to_string());
    }

    if receipt.node_id != node.node_id {
        return Err("control server enrollment response node ID mismatch".to_string());
    }

    verify(
        &receipt.control_public_key,
        &enrollment.signature,
        &enrollment.receipt,
    )
    .map_err(|error| format!("invalid control server enrollment signature: {error}"))?;

    let control_fingerprint = fingerprint(&receipt.control_public_key)?;

    Ok(ControlTrust {
        control_url,
        control_id: receipt.control_id.clone(),
        control_public_key: receipt.control_public_key.clone(),
        control_fingerprint,
        policy_revision: receipt.policy_revision,
        enrolled_at_ms: unix_time_ms(),
    })
}

pub fn normalize_control_url(value: &str) -> Result<String, String> {
    let value = value.trim().trim_end_matches('/');

    if value.is_empty() {
        return Err("control server URL is required".to_string());
    }

    if !value.starts_with("https://")
        && !value.starts_with("http://127.0.0.1")
        && !value.starts_with("http://localhost")
        && !value.starts_with("http://[::1]")
    {
        return Err("control server URL must use HTTPS outside localhost".to_string());
    }

    Ok(value.to_string())
}
