#![allow(dead_code)]
use lattice_control::{
    AppState,
    auth::{AuthConfig, AuthState, credentials},
    clock::Clock,
};
use serde_json::Value;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
pub struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
pub struct Fixture {
    pub state: AppState,
    pub client: reqwest::Client,
    pub url: String,
    pub dir: tempfile::TempDir,
    pub clock: Arc<TestClock>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    pub async fn new(role: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        credentials::provision(
            &dir.path().join("account.json"),
            "owner",
            b" password with spaces ",
        )
        .unwrap();
        let mut state = lattice_control::load_state(
            dir.path(),
            "legacy-enrollment".into(),
            None,
            "https://lattice.test".into(),
            role.into(),
        )
        .await
        .unwrap();
        state.auth = Arc::new(
            AuthState::load(dir.path(), AuthConfig::new("https://lattice.test").unwrap()).unwrap(),
        );
        let clock = Arc::new(TestClock(AtomicU64::new(1_800_000_000_000)));
        state.clock = clock.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = lattice_control::build_router(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            state,
            client: reqwest::Client::new(),
            url,
            dir,
            clock,
            task,
        }
    }
    pub fn advance_ms(&self, ms: u64) {
        self.clock.0.fetch_add(ms, Ordering::SeqCst);
    }
    pub async fn login(&self, user: &str, password: &str) -> (reqwest::StatusCode, String, Value) {
        let r = self
            .client
            .post(format!("{}/api/v1/auth/login", self.url))
            .header("origin", "https://lattice.test")
            .json(&serde_json::json!({"username":user,"password":password}))
            .send()
            .await
            .unwrap();
        let status = r.status();
        let cookie = r
            .headers()
            .get("set-cookie")
            .and_then(|s| s.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = r.json().await.unwrap();
        (status, cookie, body)
    }
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        json: Value,
        cookie: &str,
        csrf: &str,
    ) -> reqwest::Response {
        let mut r = self
            .client
            .request(method.parse().unwrap(), format!("{}{}", self.url, path))
            .header("origin", "https://lattice.test");
        if !cookie.is_empty() {
            r = r.header("cookie", cookie.split(';').next().unwrap());
        }
        if !csrf.is_empty() {
            r = r.header("x-lattice-csrf", csrf);
        }
        if method != "GET" {
            r = r.json(&json);
        }
        r.send().await.unwrap()
    }
}
pub struct Device {
    pub id: String,
    pub private: [u8; 32],
    pub public: String,
}
impl Device {
    pub fn new() -> Self {
        let private = lattice_crypto::generate_private_key();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            public: lattice_crypto::encode_key(&lattice_crypto::public_key(&private)),
            private,
        }
    }
    pub fn join(&self, now: u64) -> lattice_protocol::PublicJoinRequest {
        let claim = lattice_protocol::PublicJoinClaim {
            schema_version: 1,
            enrollment: lattice_protocol::EnrollmentClaim {
                protocol_version: lattice_protocol::PROTOCOL_VERSION,
                request_id: uuid::Uuid::new_v4().to_string(),
                node_id: self.id.clone(),
                node_name: "Fixture node".into(),
                platform: lattice_protocol::Platform::Linux,
                architecture: lattice_protocol::Architecture::X86_64,
                public_key: self.public.clone(),
                client_version: "0.1.0".into(),
                issued_at_ms: now,
            },
        };
        lattice_protocol::PublicJoinRequest {
            signature: lattice_crypto::sign(&self.private, &claim).unwrap(),
            claim,
        }
    }
}
