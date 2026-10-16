//! Validated network intent and the Base Node owned operating-system boundary.
mod intent;
mod owner;
mod system;
mod transaction;
pub use intent::{NetworkBinding, ValidatedGateway, validate_gateway_intent};
pub use owner::HostLock;
pub use system::SystemRunner;
pub use transaction::{
    AppliedNetwork, NetworkCommand, NetworkFuture, NetworkRunner, NetworkSnapshot, OwnedRoute,
    apply_gateway, recover_gateway_transaction, write_atomic_private,
};
