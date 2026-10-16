//! Validated network intent and the Base Node owned operating-system boundary.
mod base;
mod intent;
mod owner;
mod system;
mod transaction;
pub use intent::{
    NetworkBinding, ValidatedGateway, validate_gateway_intent, validate_local_transport,
};
pub use owner::HostLock;
pub use system::SystemRunner;
pub use transaction::{
    AppliedNetwork, NetworkCommand, NetworkFuture, NetworkRunner, NetworkSnapshot, OwnedRoute,
    apply_base, apply_gateway, disconnect_owned, recover_gateway_transaction, withdraw_forwarding,
    write_atomic_private,
};

pub use base::{
    ValidatedBase, valid_direct_peer, validate_base_configuration, validate_base_desired_config,
};
