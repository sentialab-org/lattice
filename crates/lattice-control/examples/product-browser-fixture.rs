use lattice_control::{
    auth::{self, AuthConfig, AuthState},
    clock::Clock,
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
#[tokio::main]
async fn main() {
    let dir = std::path::PathBuf::from(
        std::env::var_os("LATTICE_FIXTURE_DIR").expect("fixture directory"),
    );
    let mut state = lattice_control::load_state(
        &dir,
        String::new(),
        None,
        "http://127.0.0.1:18743".into(),
        "bootstrapper".into(),
    )
    .await
    .unwrap();
    auth::credentials::provision(
        &dir.join("account.json"),
        "fixture",
        "fixture-password".as_bytes(),
    )
    .unwrap();
    state.auth = Arc::new(
        AuthState::load(
            &dir,
            AuthConfig::loopback_test("http://127.0.0.1:18743").unwrap(),
        )
        .unwrap(),
    );
    let clock = Arc::new(TestClock(AtomicU64::new(lattice_control::unix_time_ms())));
    state.clock = clock.clone();
    let app = lattice_control::build_router(state).route(
        "/__fixture/expire",
        axum::routing::post(move || {
            let clock = clock.clone();
            async move {
                clock.0.fetch_add(1_800_000, Ordering::SeqCst);
                "expired"
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:18743")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
