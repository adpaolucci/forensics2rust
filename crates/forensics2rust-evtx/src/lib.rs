#![deny(unsafe_code)]

//! Pure-Rust `[MS-EVEN6]` Windows Event Log (EVTX) parser, live `wevtapi` + Registry
//! collector, and 14 read-only [`guap_table::TableProvider`] DFIR views.

mod binxml;
#[cfg(windows)]
#[allow(unsafe_code)]
mod live;
#[cfg(not(windows))]
#[path = "live_stub.rs"]
mod live;
pub mod model;
pub mod parser;
pub mod providers;
pub mod xml;

use forensics2rust_core::{ToolCategory, ToolDescriptor, tools_by_category};

pub use model::{
    ChannelMetadata, EvtxChunkInfo, EvtxFileHeader, EvtxParseOptions, EvtxRecord, LiveQueryOptions, SourceMetadata,
};
pub use parser::EvtxArchive;
pub use providers::{all_providers, all_providers_with_options};

/// Returns the crate metadata descriptor tuple `(crate_name, version)`.
pub fn crate_info() -> (&'static str, &'static str) {
    (env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

/// Lists all registered `evtx` tools from the canonical catalog.
pub fn domain_tools() -> Vec<&'static ToolDescriptor> {
    tools_by_category(ToolCategory::Evtx).collect()
}
