use crate::identity::{IdentityState, unix_time_ms};
use lattice_crypto::{fingerprint, sign, verify};
use lattice_protocol::{
    ApiError, BootstrapTrust, ControlTrust, EnrollmentClaim, EnrollmentRequest, EnrollmentResponse,
    PROTOCOL_VERSION,
};
use reqwest::Client;
use uuid::Uuid;

pub async fn enroll(
    client: &Client,
    identity: &IdentityState,
    control_url: &str,
    enrollment_token: &str,
) -> Result<ControlTrust, String> {
    let (control_url, receipt) =
        enroll_with(client, identity, control_url, enrollment_token).await?;
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

pub async fn enroll_bootstrap(
    client: &Client,
    identity: &IdentityState,
    bootstrap_url: &str,
    enrollment_token: &str,
) -> Result<BootstrapTrust, String> {
    let (url, receipt) = enroll_with(client, identity, bootstrap_url, enrollment_token).await?;
    let bootstrap_fingerprint = fingerprint(&receipt.control_public_key)?;

    Ok(BootstrapTrust {
        bootstrap_url: url,
        bootstrap_id: receipt.control_id.clone(),
        bootstrap_public_key: receipt.control_public_key.clone(),
        bootstrap_fingerprint,
        enrolled_at_ms: unix_time_ms(),
    })
}

struct VerifiedReceipt {
    control_public_key: String,
    control_id: String,
    policy_revision: u64,
}

async fn enroll_with(
    client: &Client,
    identity: &IdentityState,
    url: &str,
    enrollment_token: &str,
) -> Result<(String, VerifiedReceipt), String> {
    let control_url = normalize_control_url(url)?;
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

    Ok((
        control_url,
        VerifiedReceipt {
            control_public_key: receipt.control_public_key.clone(),
            control_id: receipt.control_id.clone(),
            policy_revision: receipt.policy_revision,
        },
    ))
}

pub fn normalize_control_url(value: &str) -> Result<String, String> {
    normalize_server_url(value, "control server")
}

pub fn normalize_bootstrap_url(value: &str) -> Result<String, String> {
    normalize_server_url(value, "bootstrapper")
}

fn insecure_http_allowed() -> bool {
    insecure_http_allowed_from(std::env::var("LATTICE_ALLOW_INSECURE_HTTP").ok().as_deref())
}

fn insecure_http_allowed_from(value: Option<&str>) -> bool {
    value
        .map(|value| {
            let normalized = value.trim().to_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes"
        })
        .unwrap_or(false)
}

fn normalize_server_url(value: &str, role: &str) -> Result<String, String> {
    let value = value.trim().trim_end_matches('/');

    if value.is_empty() {
        return Err(format!("{role} URL is required"));
    }

    if value.starts_with("https://")
        || value.starts_with("http://127.0.0.1")
        || value.starts_with("http://localhost")
        || value.starts_with("http://[::1]")
    {
        return Ok(value.to_string());
    }

    if value.starts_with("http://") && insecure_http_allowed() {
        return Ok(value.to_string());
    }

    Err(format!("{role} URL must use HTTPS outside localhost"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_url_rules_match_control_url() {
        unsafe {
            std::env::remove_var("LATTICE_ALLOW_INSECURE_HTTP");
        }
        assert!(normalize_bootstrap_url("http://14.241.111.182:7443").is_err());
        assert!(normalize_control_url("http://14.241.111.182:7443").is_err());
        assert!(normalize_bootstrap_url("https://boot.example.net").is_ok());
        assert!(normalize_bootstrap_url("http://127.0.0.1:7443").is_ok());
        assert!(normalize_bootstrap_url("").is_err());
    }

    #[test]
    fn insecure_http_exception_is_explicit() {
        assert!(!insecure_http_allowed_from(None));
        assert!(!insecure_http_allowed_from(Some("0")));
        assert!(!insecure_http_allowed_from(Some("false")));
        assert!(insecure_http_allowed_from(Some("1")));
        assert!(insecure_http_allowed_from(Some("true")));
        assert!(insecure_http_allowed_from(Some(" YES ")));
    }
}

pub async fn join_public(
    client: &Client,
    identity: &IdentityState,
    bootstrap_url: &str,
) -> Result<BootstrapTrust, String> {
    use lattice_protocol::{
        PRODUCT_SCHEMA_VERSION, PublicJoinClaim, PublicJoinRequest, PublicJoinResponse,
    };
    let url = normalize_bootstrap_url(bootstrap_url)?;
    let node = identity.identity();
    let claim = PublicJoinClaim {
        schema_version: PRODUCT_SCHEMA_VERSION,
        enrollment: EnrollmentClaim {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4().to_string(),
            node_id: node.node_id.clone(),
            node_name: node.node_name.clone(),
            platform: node.platform.clone(),
            architecture: node.architecture.clone(),
            public_key: node.public_key.clone(),
            client_version: env!("CARGO_PKG_VERSION").into(),
            issued_at_ms: unix_time_ms(),
        },
    };
    let response = client
        .post(format!("{url}/api/v1/bootstrap/join"))
        .json(&PublicJoinRequest {
            signature: sign(identity.private_key(), &claim)?,
            claim: claim.clone(),
        })
        .send()
        .await
        .map_err(|_| "public join request failed")?;
    if !response.status().is_success() {
        return Err(format!("public join rejected: HTTP {}", response.status()));
    }
    let r: PublicJoinResponse = response
        .json()
        .await
        .map_err(|_| "invalid public join response")?;
    if r.receipt.protocol_version != PROTOCOL_VERSION
        || r.receipt.node_id != node.node_id
        || r.receipt.request_id != claim.enrollment.request_id
        || r.receipt.issued_at_ms.abs_diff(unix_time_ms()) > 120_000
    {
        return Err("public join binding rejected".into());
    }
    verify(&r.receipt.control_public_key, &r.signature, &r.receipt)?;
    verify(
        &r.receipt.control_public_key,
        &r.membership.signature,
        &r.membership.membership,
    )?;
    let m = &r.membership.membership;
    if m.schema_version != PRODUCT_SCHEMA_VERSION
        || m.node_id != node.node_id
        || m.node_public_key != node.public_key
        || m.expires_at_ms <= unix_time_ms()
    {
        return Err("public membership binding rejected".into());
    }
    Ok(BootstrapTrust {
        bootstrap_url: url,
        bootstrap_id: r.receipt.control_id,
        bootstrap_fingerprint: fingerprint(&r.receipt.control_public_key)?,
        bootstrap_public_key: r.receipt.control_public_key,
        enrolled_at_ms: unix_time_ms(),
    })
}

pub async fn discover(
    client: &Client,
    identity: &IdentityState,
    trust: &BootstrapTrust,
) -> Result<lattice_protocol::DiscoveryResponse, String> {
    use lattice_protocol::*;
    let claim = DiscoveryClaim {
        schema_version: PRODUCT_SCHEMA_VERSION,
        request_id: Uuid::new_v4().to_string(),
        node_id: identity.identity().node_id.clone(),
        issued_at_ms: unix_time_ms(),
    };
    let response = client
        .post(format!(
            "{}/api/v1/bootstrap/discovery",
            trust.bootstrap_url
        ))
        .json(&DiscoveryRequest {
            signature: sign(identity.private_key(), &claim)?,
            claim,
        })
        .send()
        .await
        .map_err(|_| "discovery request failed")?;
    if !response.status().is_success() {
        return Err("discovery rejected".into());
    }
    let r: DiscoveryResponse = response
        .json()
        .await
        .map_err(|_| "invalid discovery response")?;
    validate_discovery(&r, identity, trust)?;
    Ok(r)
}
pub(crate) fn validate_discovery(
    r: &lattice_protocol::DiscoveryResponse,
    identity: &IdentityState,
    trust: &BootstrapTrust,
) -> Result<(), String> {
    use lattice_protocol::*;
    verify(
        &trust.bootstrap_public_key,
        &r.directory.signature,
        &r.directory.directory,
    )?;
    verify(
        &trust.bootstrap_public_key,
        &r.membership.signature,
        &r.membership.membership,
    )?;
    let now = unix_time_ms();
    let m = &r.membership.membership;
    let d = &r.directory.directory;
    if d.schema_version != PRODUCT_SCHEMA_VERSION
        || m.schema_version != PRODUCT_SCHEMA_VERSION
        || m.node_id != identity.identity().node_id
        || m.node_public_key != identity.identity().public_key
        || m.network_id != d.network_id
        || m.expires_at_ms <= now
        || d.issued_at_ms.abs_diff(now) > 120_000
    {
        return Err("discovery binding rejected".into());
    }
    for g in &d.masters {
        verify(&trust.bootstrap_public_key, &g.signature, &g.grant)?;
        if g.grant.network_id != d.network_id
            || g.grant.schema_version != PRODUCT_SCHEMA_VERSION
            || g.grant.overlay_ipv4.parse::<std::net::Ipv4Addr>().is_err()
        {
            return Err("master directory rejected".into());
        }
    }
    Ok(())
}
