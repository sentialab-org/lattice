use super::*;
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Login {
    username: String,
    password: String,
}
pub async fn login(
    State(state): State<AppState>,
    h: HeaderMap,
    Json(input): Json<Login>,
) -> Result<Response, ApiResponseError> {
    state.auth.origin(&h)?;
    state.auth.throttle(state.clock.now_ms())?;
    if input.username.len() > 128 || input.password.len() > 1024 {
        return Err(AuthError::Credentials.into());
    }
    let permit = state
        .auth
        .verifier
        .clone()
        .try_acquire_owned()
        .map_err(|_| AuthError::Throttled)?;
    let path = state.auth.account_path.clone();
    let username = input.username.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        credentials::verify(&path, &input.username, input.password.as_bytes())
    })
    .await
    .map_err(|_| AuthError::Persistence)??;
    let (raw, session) = state.auth.create(username, state.clock.now_ms())?;
    let mut response = Json(session).into_response();
    response.headers_mut().insert(
        "set-cookie",
        state
            .auth
            .cookie(&raw)
            .parse()
            .map_err(|_| AuthError::Persistence)?,
    );
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    Ok(response)
}
pub async fn session(
    State(state): State<AppState>,
    h: HeaderMap,
) -> Result<Response, ApiResponseError> {
    let s = state.auth.session(&h, false, state.clock.now_ms())?;
    let mut r = Json(s).into_response();
    r.headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    Ok(r)
}
pub async fn logout(
    State(state): State<AppState>,
    h: HeaderMap,
) -> Result<Response, ApiResponseError> {
    state.auth.logout(&h, state.clock.now_ms())?;
    let mut r = Json(serde_json::json!({"ok":true})).into_response();
    r.headers_mut().insert(
        "set-cookie",
        format!(
            "lattice_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
            if state.auth.config.secure_cookie {
                "; Secure"
            } else {
                ""
            }
        )
        .parse()
        .unwrap(),
    );
    Ok(r)
}
