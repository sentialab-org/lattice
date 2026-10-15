pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        crate::unix_time_ms()
    }
}
