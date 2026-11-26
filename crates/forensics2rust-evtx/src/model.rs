use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Options controlling `[MS-EVEN6]` EVTX binary archive parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EvtxParseOptions {
    /// When `true`, any CRC-32 checksum mismatch in the file header, chunk header,
    /// or event records region returns `Err(ForensicError::Parse)`.
    /// When `false` (default DFIR mode), mismatches emit a `DiagnosticWarning` and
    /// parsing continues across valid records.
    pub strict_checksums: bool,
}

/// Parsed `[MS-EVEN6]` 4096-byte EVTX file header metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvtxFileHeader {
    pub oldest_chunk: u64,
    pub current_chunk_number: u64,
    pub next_record_id: u64,
    pub header_size: u32,
    pub minor_version: u16,
    pub major_version: u16,
    pub header_block_size: u16,
    pub chunk_count: u16,
    pub file_flags: u32,
    pub checksum: u32,
    pub header_checksum_valid: bool,
}

impl EvtxFileHeader {
    /// Returns `true` if the EVTX `DIRTY` flag (`0x01`) is set in `file_flags`.
    pub fn is_dirty(&self) -> bool {
        (self.file_flags & 0x01) != 0
    }

    /// Returns `true` if the EVTX `FULL` flag (`0x02`) is set in `file_flags`.
    pub fn is_full(&self) -> bool {
        (self.file_flags & 0x02) != 0
    }
}

/// Parsed `[MS-EVEN6]` 65,536-byte EVTX chunk header metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvtxChunkInfo {
    pub chunk_index: usize,
    pub file_offset: u64,
    pub first_event_record_number: u64,
    pub last_event_record_number: u64,
    pub first_event_record_id: u64,
    pub last_event_record_id: u64,
    pub free_space_offset: u32,
    pub event_records_checksum: u32,
    pub header_checksum: u32,
    pub header_checksum_valid: bool,
    pub records_checksum_valid: bool,
    pub parsed_record_count: usize,
}

/// Unified Windows Event Log record produced by both the pure-Rust `[MS-EVEN6]`
/// binary/BinXML parser and live `wevtapi` XML rendering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvtxRecord {
    pub record_id: u64,
    pub event_time: DateTime<Utc>,
    pub event_id: u16,
    pub qualifiers: Option<u16>,
    pub version: Option<u8>,
    pub level: u8,
    pub channel: String,
    pub provider: String,
    pub provider_guid: Option<String>,
    pub opcode: u16,
    pub opcode_name: Option<String>,
    pub task: u16,
    pub task_name: Option<String>,
    pub keywords: u64,
    pub process_id: Option<u32>,
    pub thread_id: Option<u32>,
    pub user_sid: Option<String>,
    pub computer: String,
    pub activity_id: Option<String>,
    pub event_data: BTreeMap<String, String>,
    pub user_data: BTreeMap<String, String>,
    pub description: String,
    pub source_file: String,
    pub raw_xml: String,
    pub raw_bytes: Vec<u8>,
}

impl EvtxRecord {
    /// Parses a rendered `<Event>...</Event>` XML string into an [`EvtxRecord`].
    pub fn parse_xml(xml: &str) -> Result<Self, forensics2rust_core::ForensicError> {
        crate::xml::parse_event_xml(
            xml,
            xml.as_bytes().to_vec(),
            0,
            DateTime::<Utc>::UNIX_EPOCH,
            "<xml>".to_string(),
        )
    }

    /// Maps Windows Event Log numeric `level` to its standard display name.
    pub fn level_name(&self) -> &'static str {
        match self.level {
            0 => "LogAlways",
            1 => "Critical",
            2 => "Error",
            3 => "Warning",
            4 => "Information",
            5 => "Verbose",
            _ => "Unknown",
        }
    }

    /// Looks up a field in `user_data` or `event_data` by exact key, falling back to
    /// ASCII case-insensitive match.
    pub fn get_data(&self, key: &str) -> Option<&str> {
        if let Some(v) = self.user_data.get(key) {
            return Some(v.as_str());
        }
        if let Some(v) = self.event_data.get(key) {
            return Some(v.as_str());
        }
        for (k, v) in &self.user_data {
            if k.eq_ignore_ascii_case(key) {
                return Some(v.as_str());
            }
        }
        for (k, v) in &self.event_data {
            if k.eq_ignore_ascii_case(key) {
                return Some(v.as_str());
            }
        }
        None
    }
}

/// Live or offline Windows Event Log channel metadata (`evtx.channels`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelMetadata {
    pub channel_name: String,
    pub log_file_path: String,
    pub enabled: Option<bool>,
    pub channel_type: Option<String>,
    pub isolation: Option<String>,
    pub max_size_kb: Option<u64>,
    pub event_count: Option<u64>,
    pub file_size: Option<u64>,
    pub modified_time: Option<DateTime<Utc>>,
    pub owning_publisher: Option<String>,
    pub classic_eventlog: Option<bool>,
    pub raw_bytes: Vec<u8>,
}

/// Live or offline Windows Event Log publisher/source metadata (`evtx.sources`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceMetadata {
    pub source_name: String,
    pub channel: String,
    pub provider_guid: Option<String>,
    pub message_dll: Option<String>,
    pub parameter_dll: Option<String>,
    pub dll_exists: Option<bool>,
    pub registry_modified: Option<DateTime<Utc>>,
    pub observed_event_count: Option<u64>,
    pub raw_bytes: Vec<u8>,
}

/// Options bounding live Windows Event Log (`wevtapi`) queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveQueryOptions {
    /// Maximum number of records fetched across a query (`None` defaults to `10_000` in providers).
    pub max_records: Option<usize>,
    /// Optional XPath filter expression passed to `EvtQuery` (defaults to `"*"`).
    pub xpath_query: Option<String>,
    /// Whether to query newest-first (`EvtQueryReverseDirection`).
    pub reverse_direction: bool,
}

impl Default for LiveQueryOptions {
    fn default() -> Self {
        Self {
            max_records: Some(10_000),
            xpath_query: None,
            reverse_direction: true,
        }
    }
}
