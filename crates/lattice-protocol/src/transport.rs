//! Content transport exceptions are scoped to an authenticated master origin.
pub fn validate_content_url(value: &str, authorized_origin: Option<&str>) -> Result<(), String> {
    let url = url::Url::parse(value).map_err(|_| "invalid content URL")?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("invalid content URL".into());
    }
    if url.scheme() == "https" {
        return Ok(());
    }
    if url.scheme() == "http" {
        let loopback = match url.host() {
            Some(url::Host::Domain("localhost")) => true,
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        if loopback {
            return Ok(());
        }
        if let Some(origin) = authorized_origin.and_then(|s| url::Url::parse(s).ok()) {
            let object = url.path().strip_prefix("/api/v1/content/");
            if origin.scheme() == "http"
                && matches!(origin.host(), Some(url::Host::Ipv4(_)))
                && origin.port_or_known_default() == Some(7443)
                && origin.origin() == url.origin()
                && object.is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                && url.query().is_none()
            {
                return Ok(());
            }
        }
    }
    Err("content URL requires HTTPS, loopback, or the authenticated master content origin".into())
}
#[cfg(test)]
mod tests {
    #[test]
    fn overlay_content_accepts_only_the_authorized_origin() {
        let hash = "a".repeat(64);
        let url = format!("http://10.77.0.2:7443/api/v1/content/{hash}");
        assert!(super::validate_content_url(&url, None).is_err());
        assert!(super::validate_content_url(&url, Some("http://10.77.0.2:7443")).is_ok());
        assert!(super::validate_content_url(&url, Some("http://10.77.0.3:7443")).is_err());
        assert!(
            super::validate_content_url("http://localhost.attacker.test/payload", None).is_err()
        );
        assert!(
            super::validate_content_url(
                "http://10.77.0.2:7443/private",
                Some("http://10.77.0.2:7443")
            )
            .is_err()
        );
    }
}
