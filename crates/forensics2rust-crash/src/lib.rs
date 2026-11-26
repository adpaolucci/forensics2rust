#![forbid(unsafe_code)]

//! Pure-Rust, read-only Windows crash dump (`MDMP`) and Windows Error Reporting (`Report.wer`)
//! analysis crate (`crash.bsod`, `crash.wer`, `crash.report`).
//!
//! Zero DLL injection, zero credential dumping, and zero legacy WinXP crash log parsing.

pub mod bugcheck;
pub mod context;
pub mod discovery;
pub mod mdmp;
pub mod pe;
pub mod providers;
pub mod stack;
pub mod wer;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use forensics2rust_core::{ForensicSource, ToolCategory, ToolDescriptor, tools_by_category};
use guap_table::TableProvider;

pub use providers::{CrashBsodProvider, CrashReportProvider, CrashWerProvider};

/// Returns the crate metadata descriptor tuple `(crate_name, version)`.
pub fn crate_info() -> (&'static str, &'static str) {
    (env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

/// Lists all registered `crash` tools from the canonical catalog.
pub fn domain_tools() -> Vec<&'static ToolDescriptor> {
    tools_by_category(ToolCategory::Crash).collect()
}

/// Instantiates all 3 strictly read-only crash `TableProvider`s bound to `source`.
pub fn all_providers(source: &ForensicSource) -> Vec<Arc<dyn TableProvider>> {
    vec![
        Arc::new(CrashBsodProvider::new(source.clone())),
        Arc::new(CrashWerProvider::new(source.clone())),
        Arc::new(CrashReportProvider::new(source.clone())),
    ]
}

/// Instantiates all 3 crash providers using `ForensicSource::Live`.
pub fn default_providers() -> Vec<Arc<dyn TableProvider>> {
    all_providers(&ForensicSource::Live)
}

/// Looks up a single crash `TableProvider` by canonical `tool_id`.
pub fn provider_for_tool(tool_id: &str, source: &ForensicSource) -> Option<Arc<dyn TableProvider>> {
    match tool_id {
        "crash.bsod" => Some(Arc::new(CrashBsodProvider::new(source.clone()))),
        "crash.wer" => Some(Arc::new(CrashWerProvider::new(source.clone()))),
        "crash.report" => Some(Arc::new(CrashReportProvider::new(source.clone()))),
        _ => None,
    }
}
