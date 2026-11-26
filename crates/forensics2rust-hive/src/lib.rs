use std::sync::Arc;

use forensics2rust_core::{ForensicSource, ToolCategory, ToolDescriptor, tools_by_category};
use guap_table::TableProvider;

pub mod etw;
pub mod live;
#[forbid(unsafe_code)]
pub mod providers;
#[forbid(unsafe_code)]
pub mod reg_format;
#[forbid(unsafe_code)]
pub mod regf;

#[cfg(test)]
mod tests;

pub use providers::{
    FindCriteria, OfflineFinderProvider, OfflineRegistryProvider, RegFileExportProvider, RegScannerProvider,
    RegWatchProvider, RegistryChangesProvider, RegistrySnapshotEntry, ScanOptions,
};

/// Returns the crate metadata descriptor tuple `(crate_name, version)`.
pub fn crate_info() -> (&'static str, &'static str) {
    (env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

/// Lists all registered `hive` tools from the canonical catalog.
pub fn domain_tools() -> Vec<&'static ToolDescriptor> {
    tools_by_category(ToolCategory::Hive).collect()
}

/// Constructs all 6 read-only Registry Hive [`TableProvider`] instances bound to `source`.
pub fn all_providers(source: &ForensicSource) -> Vec<Arc<dyn TableProvider>> {
    vec![
        Arc::new(RegScannerProvider::new(source.clone())),
        Arc::new(RegistryChangesProvider::new(source.clone())),
        Arc::new(OfflineRegistryProvider::new(source.clone())),
        Arc::new(OfflineFinderProvider::new(source.clone())),
        Arc::new(RegFileExportProvider::new(source.clone())),
        Arc::new(RegWatchProvider::new(source.clone())),
    ]
}
