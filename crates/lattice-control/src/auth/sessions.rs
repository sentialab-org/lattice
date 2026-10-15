use super::*;
use lattice_protocol::DashboardSession;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Mutex,
};
const IDLE: u64 = 1_800_000;
const ABSOLUTE: u64 = 28_800_000;
#[derive(Clone)]
pub struct AuthConfig {
    pub origin: String,
    pub secure_cookie: bool,
}
impl AuthConfig {
    pub fn new(origin: &str) -> Result<Self, AuthError> {
        let u = url::Url::parse(origin).map_err(|_| AuthError::Credentials)?;
        if !matches!(u.scheme(), "https" | "http") || u.host_str().is_none() {
            return Err(AuthError::Credentials);
        }
        Ok(Self {
            origin: u.origin().ascii_serialization(),
            secure_cookie: true,
        })
    }
    pub fn loopback_test(origin: &str) -> Result<Self, AuthError> {
        let mut config = Self::new(origin)?;
        let u = url::Url::parse(origin).map_err(|_| AuthError::Credentials)?;
        if !matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")) {
            return Err(AuthError::Credentials);
        }
        config.secure_cookie = false;
        Ok(config)
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct Session {
    username: String,
    csrf_token: String,
    created: u64,
    last_seen: u64,
}
pub struct AuthState {
    pub config: AuthConfig,
    pub account_path: PathBuf,
    path: PathBuf,
    sessions: Mutex<BTreeMap<String, Session>>,
    attempts: Mutex<(u64, u32)>,
    pub verifier: std::sync::Arc<tokio::sync::Semaphore>,
}
impl AuthState {
    pub fn load(dir: &Path, config: AuthConfig) -> Result<Self, AuthError> {
        let path = dir.join("sessions.json");
        Ok(Self {
            config,
            account_path: dir.join("account.json"),
            sessions: Mutex::new(read_json(&path)?),
            path,
            attempts: Mutex::new((0, 0)),
            verifier: std::sync::Arc::new(tokio::sync::Semaphore::new(2)),
        })
    }
    pub fn origin(&self, h: &HeaderMap) -> Result<(), AuthError> {
        if h.get("origin").and_then(|v| v.to_str().ok()) != Some(self.config.origin.as_str()) {
            return Err(AuthError::Csrf);
        }
        Ok(())
    }
    pub fn throttle(&self, now: u64) -> Result<(), AuthError> {
        let mut a = self.attempts.lock().map_err(|_| AuthError::Persistence)?;
        if now.saturating_sub(a.0) >= 60_000 {
            *a = (now, 0);
        }
        if a.1 >= 10 {
            return Err(AuthError::Throttled);
        }
        a.1 += 1;
        Ok(())
    }
    pub fn create(
        &self,
        username: String,
        now: u64,
    ) -> Result<(String, DashboardSession), AuthError> {
        let raw = random_secret();
        let s = Session {
            username,
            csrf_token: random_secret(),
            created: now,
            last_seen: now,
        };
        let response = Self::view(&s);
        let mut records = self.sessions.lock().map_err(|_| AuthError::Persistence)?;
        let mut next = records.clone();
        next.retain(|_, s| {
            now.saturating_sub(s.last_seen) < IDLE && now.saturating_sub(s.created) < ABSOLUTE
        });
        next.insert(digest(raw.as_bytes()), s);
        atomic_json(&self.path, &next)?;
        *records = next;
        Ok((raw, response))
    }
    fn view(s: &Session) -> DashboardSession {
        DashboardSession {
            username: s.username.clone(),
            csrf_token: s.csrf_token.clone(),
            idle_expires_at_ms: s.last_seen.saturating_add(IDLE),
            absolute_expires_at_ms: s.created.saturating_add(ABSOLUTE),
        }
    }
    fn key(h: &HeaderMap) -> Result<String, AuthError> {
        let raw = h
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                v.split(';')
                    .filter_map(|c| c.trim().split_once('='))
                    .find(|(k, _)| *k == "lattice_session")
                    .map(|(_, v)| v)
            })
            .ok_or(AuthError::Credentials)?;
        if raw.len() != 64 {
            return Err(AuthError::Credentials);
        }
        Ok(digest(raw.as_bytes()))
    }
    pub fn session(
        &self,
        h: &HeaderMap,
        write: bool,
        now: u64,
    ) -> Result<DashboardSession, AuthError> {
        let key = Self::key(h)?;
        let mut records = self.sessions.lock().map_err(|_| AuthError::Persistence)?;
        let s = records.get(&key).ok_or(AuthError::Credentials)?;
        if now < s.created
            || now.saturating_sub(s.last_seen) >= IDLE
            || now.saturating_sub(s.created) >= ABSOLUTE
        {
            return Err(AuthError::Expired);
        }
        if write {
            self.origin(h)?;
            let csrf = h
                .get("x-lattice-csrf")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !crate::constant_time_token_match(csrf, &s.csrf_token) {
                return Err(AuthError::Csrf);
            }
        }
        let mut next = records.clone();
        let s = next.get_mut(&key).ok_or(AuthError::Credentials)?;
        s.last_seen = now;
        let view = Self::view(s);
        atomic_json(&self.path, &next)?;
        *records = next;
        Ok(view)
    }
    pub fn authenticate(
        &self,
        h: &HeaderMap,
        scope: OperatorScope,
        now: u64,
    ) -> Result<OperatorPrincipal, AuthError> {
        let s = self.session(h, scope.is_write(), now)?;
        Ok(OperatorPrincipal {
            username: s.username,
            scope: None,
        })
    }
    pub fn logout(&self, h: &HeaderMap, now: u64) -> Result<(), AuthError> {
        self.session(h, true, now)?;
        let mut records = self.sessions.lock().map_err(|_| AuthError::Persistence)?;
        let mut next = records.clone();
        next.remove(&Self::key(h)?);
        atomic_json(&self.path, &next)?;
        *records = next;
        Ok(())
    }
    pub fn cookie(&self, raw: &str) -> String {
        format!(
            "lattice_session={raw}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800{}",
            if self.config.secure_cookie {
                "; Secure"
            } else {
                ""
            }
        )
    }
}
