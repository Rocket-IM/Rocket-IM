//! 固定双设备联网协调，网络和密码计算不占SQLite线程；所有持久状态沿用原事务库。
#[cfg(feature = "network")]
mod auth;
#[cfg(feature = "network")]
mod auth_types;
mod capacity;
mod reserve;
pub(in crate::persistent) use reserve::{install_receipt, project_known};
mod ledger;
pub(in crate::persistent) use capacity::capacity;
mod rejection;
pub(in crate::persistent) use rejection::{
    original as rejected_original, validate as validate_rejection,
};
pub use rejection::{RejectionCode, SendRejection};
mod queue;
mod recovery_types;
mod recovery_validation;
mod types;
pub(in crate::persistent) use recovery_types::{
    recovery_gate, recovery_managed, recovery_transport,
};
pub use recovery_types::{NetworkRecoveryCommand, NetworkRecoveryState};
#[cfg(feature = "network")]
mod recovery;
#[cfg(feature = "network")]
mod recovery_commands;
#[cfg(feature = "network")]
pub use auth_types::*;
pub(super) use ledger::{check_candidate, mark_received};
pub(super) use types::NetworkData;
pub use types::{
    Acceptance, NetworkOptions, NetworkState, SendingState, UnavailableMessage, UnavailableRecord,
};
#[cfg(feature = "network")]
mod deadline;
#[cfg(feature = "network")]
mod session;
#[cfg(feature = "network")]
mod socket;
#[cfg(feature = "network")]
mod sync;
#[cfg(feature = "network")]
pub use session::NetworkSession;
#[cfg(all(test, feature = "network"))]
mod budget_tests;
#[cfg(all(test, feature = "network"))]
mod recovery_tests;
#[cfg(all(test, feature = "network"))]
mod rejection_budget_tests;
#[cfg(all(test, feature = "network"))]
mod rejection_tests;
#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "network"))]
mod reserve_tests;
