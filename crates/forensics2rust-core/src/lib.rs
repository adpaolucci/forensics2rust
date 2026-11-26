#![forbid(unsafe_code)]

//! Core foundation crate for the `forensics2rust` read-only Windows DFIR suite.
//!
//! Provides:
//! - [`ForensicSource`] for switching between live Windows OS inspection and deterministic offline fixtures.
//! - [`ForensicError`] and [`DiagnosticWarning`] with graceful elevation/missing-artifact mapping into [`guap_table::TableError`].
//! - [`FORENSIC_TOOL_CATALOG`] registering all 45 read-only DFIR tools across 6 domain crates.
//! - Pure-Rust DFIR binary decoders (`FILETIME`, OLE Automation `DATE`, `[MS-DTYP]` SID/GUID, UTF-16LE, IEEE 802.3 CRC-32, hex, ROT13).
//! - [`QueryHelper`] delegating filtering, sorting, projection, and pagination to `guap_table`.
//! - [`init_logging`] configuring `tracing_subscriber` output to `stderr` / log file.

pub mod catalog;
pub mod decode;
pub mod error;
pub mod logging;
pub mod query;
pub mod source;

#[cfg(test)]
mod tests;

pub use catalog::{
    FORENSIC_TOOL_CATALOG, ToolCategory, ToolDescriptor, all_tool_ids, find_by_subcommand, find_tool, tools_by_category,
};
pub use decode::{
    WINDOWS_EPOCH_OFFSET_100NS, WINDOWS_EPOCH_OFFSET_SECS, bytes_to_hex_lower, crc32_ieee, filetime_to_utc,
    ole_automation_date_to_utc, parse_guid_le, parse_guid_le_braced, parse_sid, read_utf16_le, read_utf16_le_nul,
    rot13, try_read_utf16_le, utc_to_filetime,
};
pub use error::{DiagnosticWarning, ForensicError, WarningSeverity, is_elevation_error};
pub use logging::init_logging;
pub use query::QueryHelper;
pub use source::ForensicSource;
