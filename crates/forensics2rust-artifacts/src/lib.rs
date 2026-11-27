#![deny(unsafe_code)]
#![cfg_attr(not(windows), allow(unused_imports, unused_mut))]

//! Read-only Windows DFIR artifact parsers and 14 [`guap_table::TableProvider`]
//! views (`artifacts.prefetch`, `artifacts.recent`, `artifacts.jumplists`, `artifacts.shellbags`,
//! `artifacts.userassist`, `artifacts.muicache`, `artifacts.opensave`, `artifacts.executed`,
//! `artifacts.activity`, `artifacts.usb_devices`, `artifacts.usb_log`, `artifacts.vss`,
//! `artifacts.previous`, `artifacts.profiles`).

pub mod correlator;
#[cfg(windows)]
#[allow(unsafe_code)]
mod live;
#[cfg(not(windows))]
#[path = "live_stub.rs"]
mod live;
pub mod parsers;
pub mod providers;
pub mod vss;

#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod tests;

use forensics2rust_core::{ToolCategory, ToolDescriptor, tools_by_category};

pub use providers::all_providers;
pub use vss::{restore_previous_file, restore_previous_file_into_dir};

/// Returns the crate metadata descriptor tuple `(crate_name, version)`.
pub fn crate_info() -> (&'static str, &'static str) {
    (env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

/// Lists all registered `artifacts` tools from the canonical catalog.
pub fn domain_tools() -> Vec<&'static ToolDescriptor> {
    tools_by_category(ToolCategory::Artifacts).collect()
}
