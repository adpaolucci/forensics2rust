pub mod builder;
pub mod parser;

use std::borrow::Cow;
use std::path::Path;

use chrono::{DateTime, Utc};
use forensics2rust_core::{ForensicError, bytes_to_hex_lower, read_utf16_le, read_utf16_le_nul};
use serde::{Deserialize, Serialize};

pub use builder::RegfBuilder;
pub use parser::{MAX_KEY_DEPTH, MAX_LIST_DEPTH, compute_regf_checksum, decode_regf_name};

pub const KEY_VOLATILE: u16 = 0x0001;
pub const KEY_HIVE_EXIT: u16 = 0x0002;
pub const KEY_HIVE_ENTRY: u16 = 0x0004;
pub const KEY_NO_DELETE: u16 = 0x0008;
pub const KEY_SYM_LINK: u16 = 0x0010;
pub const KEY_COMP_NAME: u16 = 0x0020;
pub const KEY_PREDEF_HANDLE: u16 = 0x0040;

pub const VALUE_COMP_NAME: u16 = 0x0001;

pub const REG_NONE: u32 = 0;
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_DWORD_BIG_ENDIAN: u32 = 5;
pub const REG_LINK: u32 = 6;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_RESOURCE_LIST: u32 = 8;
pub const REG_FULL_RESOURCE_DESCRIPTOR: u32 = 9;
pub const REG_RESOURCE_REQUIREMENTS_LIST: u32 = 10;
pub const REG_QWORD: u32 = 11;

/// Parsed Windows Registry value payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegValueData {
    None,
    Sz(String),
    ExpandSz(String),
    Binary(Vec<u8>),
    Dword(u32),
    DwordBigEndian(u32),
    Link(String),
    MultiSz(Vec<String>),
    Qword(u64),
    Other { raw_type: u32, data: Vec<u8> },
}

impl RegValueData {
    /// Decodes raw value bytes according to Windows `REG_*` value type.
    pub fn from_raw(raw_type: u32, raw_bytes: &[u8]) -> Self {
        match raw_type {
            REG_NONE => Self::None,
            REG_SZ => Self::Sz(read_utf16_le_nul(raw_bytes)),
            REG_EXPAND_SZ => Self::ExpandSz(read_utf16_le_nul(raw_bytes)),
            REG_BINARY => Self::Binary(raw_bytes.to_vec()),
            REG_DWORD => {
                if raw_bytes.len() >= 4 {
                    Self::Dword(u32::from_le_bytes([
                        raw_bytes[0],
                        raw_bytes[1],
                        raw_bytes[2],
                        raw_bytes[3],
                    ]))
                } else {
                    Self::Other {
                        raw_type,
                        data: raw_bytes.to_vec(),
                    }
                }
            }
            REG_DWORD_BIG_ENDIAN => {
                if raw_bytes.len() >= 4 {
                    Self::DwordBigEndian(u32::from_be_bytes([
                        raw_bytes[0],
                        raw_bytes[1],
                        raw_bytes[2],
                        raw_bytes[3],
                    ]))
                } else {
                    Self::Other {
                        raw_type,
                        data: raw_bytes.to_vec(),
                    }
                }
            }
            REG_LINK => Self::Link(read_utf16_le_nul(raw_bytes)),
            REG_MULTI_SZ => Self::MultiSz(decode_multi_sz(raw_bytes)),
            REG_QWORD => {
                if raw_bytes.len() >= 8 {
                    Self::Qword(u64::from_le_bytes([
                        raw_bytes[0],
                        raw_bytes[1],
                        raw_bytes[2],
                        raw_bytes[3],
                        raw_bytes[4],
                        raw_bytes[5],
                        raw_bytes[6],
                        raw_bytes[7],
                    ]))
                } else {
                    Self::Other {
                        raw_type,
                        data: raw_bytes.to_vec(),
                    }
                }
            }
            _ => Self::Other {
                raw_type,
                data: raw_bytes.to_vec(),
            },
        }
    }

    pub fn raw_type(&self) -> u32 {
        match self {
            Self::None => REG_NONE,
            Self::Sz(_) => REG_SZ,
            Self::ExpandSz(_) => REG_EXPAND_SZ,
            Self::Binary(_) => REG_BINARY,
            Self::Dword(_) => REG_DWORD,
            Self::DwordBigEndian(_) => REG_DWORD_BIG_ENDIAN,
            Self::Link(_) => REG_LINK,
            Self::MultiSz(_) => REG_MULTI_SZ,
            Self::Qword(_) => REG_QWORD,
            Self::Other { raw_type, .. } => *raw_type,
        }
    }

    pub fn type_name(&self) -> Cow<'static, str> {
        reg_type_name(self.raw_type())
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Sz(s) | Self::ExpandSz(s) | Self::Link(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Self::Dword(v) | Self::DwordBigEndian(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Qword(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Binary(b) | Self::Other { data: b, .. } => Some(b.as_slice()),
            _ => None,
        }
    }

    pub fn as_multi_sz(&self) -> Option<&[String]> {
        match self {
            Self::MultiSz(items) => Some(items.as_slice()),
            _ => None,
        }
    }

    /// Returns the full human-readable decoded representation.
    pub fn decoded_string(&self) -> String {
        match self {
            Self::None => String::new(),
            Self::Sz(s) | Self::ExpandSz(s) | Self::Link(s) => s.clone(),
            Self::Binary(b) => {
                if b.is_empty() {
                    String::new()
                } else {
                    bytes_to_hex_lower(b)
                }
            }
            Self::Dword(v) => format!("{v} (0x{v:08x})"),
            Self::DwordBigEndian(v) => format!("{v} (0x{v:08x})"),
            Self::MultiSz(items) => items.join(" | "),
            Self::Qword(v) => format!("{v} (0x{v:016x})"),
            Self::Other { data, .. } => {
                if data.is_empty() {
                    String::new()
                } else {
                    bytes_to_hex_lower(data)
                }
            }
        }
    }

    /// Returns a concise preview string suitable for table cells.
    pub fn preview(&self) -> String {
        self.preview_truncated(160)
    }

    pub fn preview_truncated(&self, max_chars: usize) -> String {
        let full = match self {
            Self::None => "(none)".to_owned(),
            Self::Binary(b) if b.is_empty() => "(zero-length binary)".to_owned(),
            Self::Other { data, .. } if data.is_empty() => "(empty)".to_owned(),
            _ => self.decoded_string(),
        };
        truncate_chars(&full, max_chars)
    }
}

/// Returns the canonical Windows `REG_*` name for a numeric value type.
pub fn reg_type_name(raw_type: u32) -> Cow<'static, str> {
    match raw_type {
        REG_NONE => Cow::Borrowed("REG_NONE"),
        REG_SZ => Cow::Borrowed("REG_SZ"),
        REG_EXPAND_SZ => Cow::Borrowed("REG_EXPAND_SZ"),
        REG_BINARY => Cow::Borrowed("REG_BINARY"),
        REG_DWORD => Cow::Borrowed("REG_DWORD"),
        REG_DWORD_BIG_ENDIAN => Cow::Borrowed("REG_DWORD_BIG_ENDIAN"),
        REG_LINK => Cow::Borrowed("REG_LINK"),
        REG_MULTI_SZ => Cow::Borrowed("REG_MULTI_SZ"),
        REG_RESOURCE_LIST => Cow::Borrowed("REG_RESOURCE_LIST"),
        REG_FULL_RESOURCE_DESCRIPTOR => Cow::Borrowed("REG_FULL_RESOURCE_DESCRIPTOR"),
        REG_RESOURCE_REQUIREMENTS_LIST => Cow::Borrowed("REG_RESOURCE_REQUIREMENTS_LIST"),
        REG_QWORD => Cow::Borrowed("REG_QWORD"),
        other => Cow::Owned(format!("REG_UNKNOWN(0x{other:x})")),
    }
}

/// Decodes a UTF-16LE `REG_MULTI_SZ` buffer into individual strings.
pub fn decode_multi_sz(raw: &[u8]) -> Vec<String> {
    let mut items = Vec::new();
    let mut current: Vec<u16> = Vec::new();
    for &chunk in raw.as_chunks::<2>().0 {
        let unit = u16::from_le_bytes(chunk);
        if unit == 0 {
            if current.is_empty() {
                break;
            }
            items.push(String::from_utf16_lossy(&current));
            current.clear();
        } else {
            current.push(unit);
        }
    }
    if !current.is_empty() {
        items.push(String::from_utf16_lossy(&current));
    }
    items
}

/// Encodes a slice of strings into UTF-16LE `REG_MULTI_SZ` bytes.
pub fn encode_multi_sz(items: &[String]) -> Vec<u8> {
    if items.is_empty() {
        return vec![0, 0];
    }
    let mut out = Vec::new();
    for item in items {
        for unit in item.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out.extend_from_slice(&[0, 0]);
    }
    out.extend_from_slice(&[0, 0]);
    out
}

/// Encodes a string as NUL-terminated UTF-16LE bytes.
pub fn encode_utf16_le_nul(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity((s.len() + 1) * 2);
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    out
}

pub(crate) fn truncate_chars(s: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let mut chars = s.chars();
    let mut out = String::new();
    for _ in 0..max_chars {
        match chars.next() {
            Some(c) => out.push(c),
            None => return s.to_owned(),
        }
    }
    if chars.next().is_some() {
        out.push_str("...");
    }
    out
}

/// Decodes a single `vk` Registry value record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegValue {
    /// Empty string `""` denotes the `(Default)` unnamed value.
    pub name: String,
    pub raw_type: u32,
    pub data: RegValueData,
    pub raw_bytes: Vec<u8>,
    pub cell_offset: u32,
    pub is_deleted: bool,
}

impl RegValue {
    pub fn display_name(&self) -> &str {
        if self.name.is_empty() { "(Default)" } else { &self.name }
    }

    pub fn type_name(&self) -> Cow<'static, str> {
        reg_type_name(self.raw_type)
    }

    pub fn preview(&self) -> String {
        self.data.preview()
    }

    pub fn decoded_string(&self) -> String {
        self.data.decoded_string()
    }

    pub fn as_utf16_lossy(&self) -> String {
        read_utf16_le(&self.raw_bytes)
    }
}

/// Parsed 4096-byte `regf` base block metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegfHeader {
    pub primary_seq: u32,
    pub secondary_seq: u32,
    pub is_dirty: bool,
    pub last_written: Option<DateTime<Utc>>,
    pub major_version: u32,
    pub minor_version: u32,
    pub file_type: u32,
    pub file_format: u32,
    pub root_cell_offset: u32,
    pub hive_bins_data_size: u32,
    pub clustering_factor: u32,
    pub file_name: String,
    pub checksum_stored: u32,
    pub checksum_computed: u32,
    pub checksum_valid: bool,
}

/// A carved unallocated or orphaned key recovered from `hbin` cells.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredKey {
    pub name: String,
    pub path: String,
    pub cell_offset: u32,
    pub parent_offset: u32,
    pub last_write_time: Option<DateTime<Utc>>,
    pub values: Vec<RegValue>,
    pub reason: String,
    pub is_deleted: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct RegKeyNode {
    pub(crate) name: String,
    pub(crate) path: String,
    pub(crate) flags: u16,
    pub(crate) last_write_time: Option<DateTime<Utc>>,
    pub(crate) declared_subkey_count: u32,
    pub(crate) cell_offset: u32,
    pub(crate) is_deleted: bool,
    pub(crate) children: Vec<usize>,
    pub(crate) values: Vec<RegValue>,
}

/// In-memory representation of a parsed Windows Registry `regf` hive.
#[derive(Debug, Clone)]
pub struct RegfHive {
    pub(crate) header: RegfHeader,
    pub(crate) nodes: Vec<RegKeyNode>,
    pub(crate) root_idx: Option<usize>,
    pub(crate) recovered: Vec<RecoveredKey>,
    pub(crate) diagnostics: Vec<String>,
}

impl RegfHive {
    /// Parses a `regf` hive in strict mode from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ForensicError> {
        parser::parse_regf_bytes(bytes, false)
    }

    /// Parses a `regf` hive in tolerant mode, recovering partial keys and unallocated/orphaned cells.
    pub fn from_bytes_tolerant(bytes: &[u8]) -> Result<Self, ForensicError> {
        parser::parse_regf_bytes(bytes, true)
    }

    /// Opens and parses a `regf` hive file in strict mode.
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        let bytes = std::fs::read(path).map_err(|err| ForensicError::io_classified(path.display().to_string(), err))?;
        Self::from_bytes(&bytes)
    }

    /// Opens and parses a `regf` hive file in tolerant recovery mode.
    pub fn open_tolerant(path: &Path) -> Result<Self, ForensicError> {
        let bytes = std::fs::read(path).map_err(|err| ForensicError::io_classified(path.display().to_string(), err))?;
        Self::from_bytes_tolerant(&bytes)
    }

    pub fn header(&self) -> &RegfHeader {
        &self.header
    }

    pub fn root_key(&self) -> Option<RegKeyRef<'_>> {
        self.root_idx.map(|idx| RegKeyRef { hive: self, idx })
    }

    /// Looks up a key by case-insensitive `\`- or `/`-separated path relative to the root key.
    pub fn find_key(&self, path: &str) -> Option<RegKeyRef<'_>> {
        let mut current = self.root_key()?;
        let trimmed = path.trim_matches(|c| c == '\\' || c == '/');
        if trimmed.is_empty() {
            return Some(current);
        }
        for segment in trimmed.split(['\\', '/']).filter(|s| !s.is_empty()) {
            current = current.find_subkey(segment)?;
        }
        Some(current)
    }

    /// Iterates all active keys in pre-order depth-first traversal.
    pub fn walk_keys(&self) -> RegKeyWalk<'_> {
        let stack = self.root_idx.into_iter().collect();
        RegKeyWalk { hive: self, stack }
    }

    /// Returns carved unallocated and orphaned keys discovered in `hbin` chunks.
    pub fn carve_unallocated(&self) -> Vec<RecoveredKey> {
        self.recovered.clone()
    }

    pub fn recovered_keys(&self) -> &[RecoveredKey] {
        &self.recovered
    }

    pub fn diagnostics(&self) -> &[String] {
        &self.diagnostics
    }
}

/// Lightweight handle to a key inside a [`RegfHive`].
#[derive(Debug, Clone, Copy)]
pub struct RegKeyRef<'a> {
    hive: &'a RegfHive,
    idx: usize,
}

impl<'a> RegKeyRef<'a> {
    fn node(&self) -> &'a RegKeyNode {
        &self.hive.nodes[self.idx]
    }

    pub fn name(&self) -> &'a str {
        &self.node().name
    }

    /// Canonical `\`-separated path relative to the hive root (`""` for root itself).
    pub fn path(&self) -> &'a str {
        &self.node().path
    }

    pub fn flags(&self) -> u16 {
        self.node().flags
    }

    pub fn last_write_time(&self) -> Option<DateTime<Utc>> {
        self.node().last_write_time
    }

    pub fn subkey_count(&self) -> usize {
        self.node().children.len()
    }

    pub fn declared_subkey_count(&self) -> u32 {
        self.node().declared_subkey_count
    }

    pub fn subkeys(&self) -> impl Iterator<Item = RegKeyRef<'a>> + 'a {
        let hive = self.hive;
        self.node()
            .children
            .iter()
            .copied()
            .map(move |idx| RegKeyRef { hive, idx })
    }

    pub fn find_subkey(&self, name: &str) -> Option<RegKeyRef<'a>> {
        self.subkeys().find(|k| k.name().eq_ignore_ascii_case(name))
    }

    pub fn values(&self) -> &'a [RegValue] {
        &self.node().values
    }

    pub fn value(&self, name: &str) -> Option<&'a RegValue> {
        self.values().iter().find(|v| v.name.eq_ignore_ascii_case(name))
    }

    pub fn cell_offset(&self) -> u32 {
        self.node().cell_offset
    }

    pub fn is_deleted(&self) -> bool {
        self.node().is_deleted
    }
}

/// Pre-order depth-first iterator over active keys in a [`RegfHive`].
pub struct RegKeyWalk<'a> {
    hive: &'a RegfHive,
    stack: Vec<usize>,
}

impl<'a> Iterator for RegKeyWalk<'a> {
    type Item = RegKeyRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let idx = self.stack.pop()?;
        let node = &self.hive.nodes[idx];
        for &child_idx in node.children.iter().rev() {
            self.stack.push(child_idx);
        }
        Some(RegKeyRef { hive: self.hive, idx })
    }
}
