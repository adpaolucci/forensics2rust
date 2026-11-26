#![deny(unsafe_code)]

//! Read-only Windows Updates, Defender, and SecurityCenter2 posture analysis crate
//! (`posture.updates`, `posture.full_updates`, `posture.defender_status`, `posture.security_center`).
//!
//! Strictly read-only per GUAP R4: zero legacy hotfix uninstall-key scanning, zero credential/secret
//! extraction, zero DLL injection/API hooking, and zero mutating OS/Registry calls.

pub mod cbs_log;
pub mod datastore_ese;
pub mod defender;
pub mod discovery;
pub mod providers;
pub mod security_center;
pub mod store_db;

#[cfg(windows)]
#[allow(unsafe_code)]
pub mod live;

#[cfg(not(windows))]
#[path = "live_stub.rs"]
pub mod live;

#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod tests;

use forensics2rust_core::{ToolCategory, ToolDescriptor, tools_by_category};

pub use providers::{
    PostureDefenderStatusProvider, PostureFullUpdatesProvider, PostureSecurityCenterProvider, PostureUpdatesProvider,
    all_providers, default_providers, provider_for_tool,
};

/// Returns the crate metadata descriptor tuple `(crate_name, version)`.
pub fn crate_info() -> (&'static str, &'static str) {
    (env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

/// Lists all registered `posture` tools from the canonical catalog.
pub fn domain_tools() -> Vec<&'static ToolDescriptor> {
    tools_by_category(ToolCategory::Posture).collect()
}
