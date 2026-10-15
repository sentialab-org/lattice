use crate::AppState;
use axum::{
    Json,
    extract::State,
    http::{StatusCode, header},
    response::{Html, IntoResponse},
};
pub async fn auth_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../../web/control/auth.js"),
    )
}
pub async fn setup_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../../web/control/setup.js"),
    )
}
pub async fn install() -> Html<&'static str> {
    Html(include_str!("../../../web/installer/index.html"))
}
pub async fn linux() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        include_str!("../../../web/installer/linux.sh"),
    )
}
pub async fn macos() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        include_str!("../../../web/installer/macos.sh"),
    )
}
pub async fn windows() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        include_str!("../../../web/installer/windows.ps1"),
    )
}
pub fn release_root() -> std::path::PathBuf {
    std::env::var_os("LATTICE_RELEASE_ROOT")
        .map(Into::into)
        .unwrap_or_else(|| "./dist/releases".into())
}
pub async fn catalog(State(_s): State<AppState>) -> impl IntoResponse {
    let root = release_root();
    if let Ok(v) = tokio::fs::read_to_string(root.join("stable")).await {
        let v = v.trim();
        if semver::Version::parse(v).is_ok() && !v.contains('/') && !v.contains('\\') {
            if let Ok(bytes) = tokio::fs::read(root.join(v).join("catalog.json")).await {
                return (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, "application/json"),
                        (header::CACHE_CONTROL, "no-store"),
                    ],
                    bytes,
                )
                    .into_response();
            }
        }
    }
    Json(serde_json::json!({"version":null,"targets":[],"bundles":[]})).into_response()
}
