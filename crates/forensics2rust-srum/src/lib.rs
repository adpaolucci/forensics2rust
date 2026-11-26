#[forbid(unsafe_code)]
pub mod ese;
#[forbid(unsafe_code)]
pub mod id_map;
pub mod live;
#[forbid(unsafe_code)]
pub mod providers;

#[cfg(test)]
#[forbid(unsafe_code)]
pub(crate) mod fixtures;
#[cfg(test)]
#[forbid(unsafe_code)]
mod tests;

use forensics2rust_core::{ToolCategory, ToolDescriptor, tools_by_category};

pub use providers::{SrumAppProvider, SrumDbProvider, SrumEnergyProvider, SrumNetProvider, all_providers};

/// Returns the crate metadata descriptor tuple `(crate_name, version)`.
pub fn crate_info() -> (&'static str, &'static str) {
    (env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

/// Lists all registered `srum` tools from the canonical catalog.
pub fn domain_tools() -> Vec<&'static ToolDescriptor> {
    tools_by_category(ToolCategory::Srum).collect()
}
