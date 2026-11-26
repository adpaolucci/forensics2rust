use std::collections::HashMap;

use chrono::{DateTime, Utc};
use forensics2rust_core::{ForensicError, bytes_to_hex_lower, filetime_to_utc};
use serde::{Deserialize, Serialize};

use crate::reg_format::{RegExportFormat, RegScriptOp, escape_reg_str, format_reg_value_line, parse_reg_script};
use crate::regf::RegValueData;

pub const KERNEL_REGISTRY_PROVIDER_GUID_STR: &str = "{70EB4F03-C1DE-4F73-A051-33D13D5413BD}";
pub const KERNEL_REGISTRY_PROVIDER_U128: u128 = 0x70eb4f03_c1de_4f73_a051_33d13d5413bd;
pub const F2RETW01_MAGIC: &[u8; 8] = b"F2RETW01";
pub const EVENT_HEADER_FLAG_64_BIT_HEADER_U16: u16 = 0x0040;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchOptions {
    pub duration_ms: u64,
    pub max_events: usize,
    pub target_pid: Option<u32>,
    pub process_filter: Option<String>,
    pub key_filter: Option<String>,
    pub mutations_only: bool,
}

impl Default for WatchOptions {
    fn default() -> Self {
        Self {
            duration_ms: 500,
            max_events: 1000,
            target_pid: None,
            process_filter: None,
            key_filter: None,
            mutations_only: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryWatchEvent {
    pub timestamp: DateTime<Utc>,
    pub pid: u32,
    pub tid: u32,
    pub process_name: String,
    pub event_id: u16,
    pub opcode: u8,
    pub operation: String,
    pub key_path: String,
    pub value_name: Option<String>,
    pub value_type: Option<u32>,
    pub data: Option<RegValueData>,
    pub raw_bytes: Vec<u8>,
    pub status: u32,
    pub reg_dotnet_line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEtwRegistryRecord {
    pub timestamp: Option<DateTime<Utc>>,
    pub pid: u32,
    #[serde(default)]
    pub tid: u32,
    #[serde(default)]
    pub process_name: Option<String>,
    pub event_id: u16,
    #[serde(default)]
    pub opcode: u8,
    #[serde(default = "default_ptr_size")]
    pub pointer_size: usize,
    #[serde(default)]
    pub user_data_hex: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub value_name: Option<String>,
    #[serde(default)]
    pub value_type: Option<u32>,
    #[serde(default)]
    pub data_hex: Option<String>,
    #[serde(default)]
    pub reg_dotnet_line: Option<String>,
}

fn default_ptr_size() -> usize {
    8
}

/// Normalizes NT kernel registry paths (`\REGISTRY\MACHINE\...`) to Win32 root names (`HKEY_LOCAL_MACHINE\...`).
pub fn normalize_nt_registry_path(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('\\');
    if trimmed.is_empty() {
        return String::new();
    }
    let upper = trimmed.to_ascii_uppercase();
    if upper == "\\REGISTRY\\MACHINE" {
        return "HKEY_LOCAL_MACHINE".to_owned();
    }
    if let Some(rest) = upper
        .strip_prefix("\\REGISTRY\\MACHINE\\")
        .map(|_| &trimmed["\\REGISTRY\\MACHINE\\".len()..])
    {
        return format!("HKEY_LOCAL_MACHINE\\{rest}");
    }
    if upper == "\\REGISTRY\\USER" {
        return "HKEY_USERS".to_owned();
    }
    if let Some(rest) = upper
        .strip_prefix("\\REGISTRY\\USER\\")
        .map(|_| &trimmed["\\REGISTRY\\USER\\".len()..])
    {
        return format!("HKEY_USERS\\{rest}");
    }
    if let Some(rest) = upper.strip_prefix("HKLM\\").map(|_| &trimmed["HKLM\\".len()..]) {
        return format!("HKEY_LOCAL_MACHINE\\{rest}");
    }
    if let Some(rest) = upper.strip_prefix("HKCU\\").map(|_| &trimmed["HKCU\\".len()..]) {
        return format!("HKEY_CURRENT_USER\\{rest}");
    }
    if let Some(rest) = upper.strip_prefix("HKU\\").map(|_| &trimmed["HKU\\".len()..]) {
        return format!("HKEY_USERS\\{rest}");
    }
    if let Some(rest) = upper.strip_prefix("HKCR\\").map(|_| &trimmed["HKCR\\".len()..]) {
        return format!("HKEY_CLASSES_ROOT\\{rest}");
    }
    if let Some(rest) = upper.strip_prefix("HKCC\\").map(|_| &trimmed["HKCC\\".len()..]) {
        return format!("HKEY_CURRENT_CONFIG\\{rest}");
    }
    trimmed.to_owned()
}

fn join_registry_paths(base: &str, rel: &str) -> String {
    let b = base.trim_end_matches('\\');
    let r = rel.trim_start_matches('\\');
    match (b.is_empty(), r.is_empty()) {
        (true, true) => String::new(),
        (false, true) => b.to_owned(),
        (true, false) => r.to_owned(),
        (false, false) => format!("{b}\\{r}"),
    }
}

pub fn event_id_operation_name(event_id: u16) -> &'static str {
    match event_id {
        1 => "CreateKey",
        2 => "OpenKey",
        3 => "DeleteKey",
        4 => "QueryKey",
        5 => "SetValue",
        6 => "DeleteValue",
        7 => "QueryValue",
        8 => "EnumerateKey",
        9 => "EnumerateValue",
        10 => "QueryMultipleValue",
        11 => "SetInformationKey",
        12 => "FlushKey",
        13 => "CloseKey",
        14 => "QuerySecurityKey",
        15 => "SetSecurityKey",
        _ => "Unknown",
    }
}

pub fn is_mutation_event_id(event_id: u16) -> bool {
    matches!(event_id, 1 | 3 | 5 | 6)
}

/// Stateful pure-Rust decoder for `Microsoft-Windows-Kernel-Registry` (`EID 1..15`) `UserData` payloads.
#[derive(Debug, Default)]
pub struct EtwRegistryDecoderState {
    key_objects: HashMap<u64, String>,
}

impl EtwRegistryDecoderState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cached_object_count(&self) -> usize {
        self.key_objects.len()
    }

    fn is_absolute_registry_path(path: &str) -> bool {
        let upper = path.to_ascii_uppercase();
        upper.starts_with("HKEY_") || upper.starts_with("\\REGISTRY\\")
    }

    fn resolve_key_path(&self, key_object: u64, raw_key_name: &str) -> String {
        let normalized = normalize_nt_registry_path(raw_key_name);
        if Self::is_absolute_registry_path(&normalized) {
            return normalized;
        }
        if key_object != 0
            && let Some(cached) = self.key_objects.get(&key_object)
        {
            if normalized.is_empty() || normalized.eq_ignore_ascii_case(cached) {
                return cached.clone();
            }
            let norm_lower = normalized.to_ascii_lowercase();
            let cached_lower = cached.to_ascii_lowercase();
            if let Some(rest) = norm_lower.strip_prefix(&cached_lower)
                && rest.starts_with('\\')
            {
                return normalized;
            }
            return join_registry_paths(cached, &normalized);
        }
        normalized
    }

    #[allow(clippy::too_many_arguments)]
    pub fn decode_record(
        &mut self,
        event_id: u16,
        opcode: u8,
        pointer_size: usize,
        pid: u32,
        tid: u32,
        timestamp: DateTime<Utc>,
        process_name: String,
        user_data: &[u8],
    ) -> Option<RegistryWatchEvent> {
        let ptr_sz = if pointer_size == 4 { 4 } else { 8 };
        let mut cur = 0usize;

        match event_id {
            // CreateKey (1) / OpenKey (2):
            // BaseObject(Ptr), KeyObject(Ptr), Status(u32), Disposition(u32), BaseName(UTF-16LE NUL), RelativeName(UTF-16LE NUL)
            1 | 2 => {
                let base_obj = read_ptr(user_data, &mut cur, ptr_sz)?;
                let key_obj = read_ptr(user_data, &mut cur, ptr_sz)?;
                let status = read_u32(user_data, &mut cur)?;
                let _disposition = read_u32(user_data, &mut cur)?;
                let base_name = read_utf16_nul(user_data, &mut cur).unwrap_or_default();
                let rel_name = read_utf16_nul(user_data, &mut cur).unwrap_or_default();

                let resolved_base = if base_name.is_empty() && base_obj != 0 {
                    self.key_objects.get(&base_obj).cloned().unwrap_or_default()
                } else {
                    normalize_nt_registry_path(&base_name)
                };
                let norm_rel = normalize_nt_registry_path(&rel_name);
                let full_path = if resolved_base.is_empty() || Self::is_absolute_registry_path(&norm_rel) {
                    norm_rel
                } else {
                    normalize_nt_registry_path(&join_registry_paths(&resolved_base, &rel_name))
                };
                if key_obj != 0 && !full_path.is_empty() {
                    self.key_objects.insert(key_obj, full_path.clone());
                }
                let reg_dotnet_line = if full_path.is_empty() {
                    String::new()
                } else {
                    format!("[{full_path}]")
                };

                Some(RegistryWatchEvent {
                    timestamp,
                    pid,
                    tid,
                    process_name,
                    event_id,
                    opcode,
                    operation: event_id_operation_name(event_id).to_owned(),
                    key_path: full_path,
                    value_name: None,
                    value_type: None,
                    data: None,
                    raw_bytes: Vec::new(),
                    status,
                    reg_dotnet_line,
                })
            }
            // DeleteKey (3): KeyObject(Ptr), Status(u32), KeyName(UTF-16LE NUL)
            3 => {
                let key_obj = read_ptr(user_data, &mut cur, ptr_sz)?;
                let status = read_u32(user_data, &mut cur)?;
                let key_name = read_utf16_nul(user_data, &mut cur).unwrap_or_default();
                let full_path = self.resolve_key_path(key_obj, &key_name);
                self.key_objects.remove(&key_obj);
                let reg_dotnet_line = if full_path.is_empty() {
                    String::new()
                } else {
                    format!("[-{full_path}]")
                };

                Some(RegistryWatchEvent {
                    timestamp,
                    pid,
                    tid,
                    process_name,
                    event_id,
                    opcode,
                    operation: "DeleteKey".to_owned(),
                    key_path: full_path,
                    value_name: None,
                    value_type: None,
                    data: None,
                    raw_bytes: Vec::new(),
                    status,
                    reg_dotnet_line,
                })
            }
            // SetValueKey (5):
            // KeyObject(Ptr), Status(u32), Type(u32), DataSize(u32), KeyName(UTF-16LE NUL), ValueName(UTF-16LE NUL),
            // CapturedDataSize(u16), CapturedData([u8; CapturedDataSize]), [optional PreviousData*]
            5 => {
                let key_obj = read_ptr(user_data, &mut cur, ptr_sz)?;
                let status = read_u32(user_data, &mut cur)?;
                let val_type = read_u32(user_data, &mut cur)?;
                let _data_size = read_u32(user_data, &mut cur)?;
                let key_name = read_utf16_nul(user_data, &mut cur).unwrap_or_default();
                let value_name = read_utf16_nul(user_data, &mut cur).unwrap_or_default();
                let captured_size = usize::from(read_u16(user_data, &mut cur).unwrap_or(0));
                let avail = user_data.len().saturating_sub(cur);
                let take = captured_size.min(avail);
                let raw_bytes = user_data[cur..cur + take].to_vec();

                let full_path = self.resolve_key_path(key_obj, &key_name);
                let data = RegValueData::from_raw(val_type, &raw_bytes);
                let reg_dotnet_line = format_reg_value_line(&value_name, &data, &raw_bytes, RegExportFormat::Regedit5);

                Some(RegistryWatchEvent {
                    timestamp,
                    pid,
                    tid,
                    process_name,
                    event_id,
                    opcode,
                    operation: "SetValue".to_owned(),
                    key_path: full_path,
                    value_name: Some(value_name),
                    value_type: Some(val_type),
                    data: Some(data),
                    raw_bytes,
                    status,
                    reg_dotnet_line,
                })
            }
            // DeleteValueKey (6): KeyObject(Ptr), Status(u32), KeyName(UTF-16LE NUL), ValueName(UTF-16LE NUL)
            6 => {
                let key_obj = read_ptr(user_data, &mut cur, ptr_sz)?;
                let status = read_u32(user_data, &mut cur)?;
                let key_name = read_utf16_nul(user_data, &mut cur).unwrap_or_default();
                let value_name = read_utf16_nul(user_data, &mut cur).unwrap_or_default();
                let full_path = self.resolve_key_path(key_obj, &key_name);
                let reg_dotnet_line = if value_name.is_empty() {
                    "@=-".to_owned()
                } else {
                    format!("\"{}\"=-", escape_reg_str(&value_name))
                };

                Some(RegistryWatchEvent {
                    timestamp,
                    pid,
                    tid,
                    process_name,
                    event_id,
                    opcode,
                    operation: "DeleteValue".to_owned(),
                    key_path: full_path,
                    value_name: Some(value_name),
                    value_type: None,
                    data: None,
                    raw_bytes: Vec::new(),
                    status,
                    reg_dotnet_line,
                })
            }
            // QueryValueKey (7):
            // KeyObject(Ptr), Status(u32), InfoClass(u32), DataSize(u32), KeyName, ValueName, CapturedDataSize(u16), CapturedData
            7 => {
                let key_obj = read_ptr(user_data, &mut cur, ptr_sz)?;
                let status = read_u32(user_data, &mut cur)?;
                let _info_class = read_u32(user_data, &mut cur)?;
                let _data_size = read_u32(user_data, &mut cur)?;
                let key_name = read_utf16_nul(user_data, &mut cur).unwrap_or_default();
                let value_name = read_utf16_nul(user_data, &mut cur).unwrap_or_default();
                let captured_size = usize::from(read_u16(user_data, &mut cur).unwrap_or(0));
                let avail = user_data.len().saturating_sub(cur);
                let raw_bytes = user_data[cur..cur + captured_size.min(avail)].to_vec();
                let full_path = self.resolve_key_path(key_obj, &key_name);
                let reg_dotnet_line = format!(
                    "; QueryValue \"{}\" ({} bytes)",
                    escape_reg_str(&value_name),
                    raw_bytes.len()
                );

                Some(RegistryWatchEvent {
                    timestamp,
                    pid,
                    tid,
                    process_name,
                    event_id,
                    opcode,
                    operation: "QueryValue".to_owned(),
                    key_path: full_path,
                    value_name: Some(value_name),
                    value_type: None,
                    data: None,
                    raw_bytes,
                    status,
                    reg_dotnet_line,
                })
            }
            // QueryKey (4) / SetInformationKey (11):
            // KeyObject(Ptr), Status(u32), InfoClass(u32), DataSize(u32), KeyName, CapturedDataSize(u16), CapturedData
            4 | 11 => {
                let key_obj = read_ptr(user_data, &mut cur, ptr_sz)?;
                let status = read_u32(user_data, &mut cur)?;
                let _info_class = read_u32(user_data, &mut cur)?;
                let _data_size = read_u32(user_data, &mut cur)?;
                let key_name = read_utf16_nul(user_data, &mut cur).unwrap_or_default();
                let captured_size = usize::from(read_u16(user_data, &mut cur).unwrap_or(0));
                let avail = user_data.len().saturating_sub(cur);
                let raw_bytes = user_data[cur..cur + captured_size.min(avail)].to_vec();
                let full_path = self.resolve_key_path(key_obj, &key_name);
                let op = event_id_operation_name(event_id);

                Some(RegistryWatchEvent {
                    timestamp,
                    pid,
                    tid,
                    process_name,
                    event_id,
                    opcode,
                    operation: op.to_owned(),
                    key_path: full_path.clone(),
                    value_name: None,
                    value_type: None,
                    data: None,
                    raw_bytes,
                    status,
                    reg_dotnet_line: format!("; {op} [{full_path}]"),
                })
            }
            // EnumerateKey (8) / EnumerateValueKey (9):
            // KeyObject(Ptr), Status(u32), Index(u32), InfoClass(u32), DataSize(u32), KeyName, CapturedDataSize(u16), CapturedData
            8 | 9 => {
                let key_obj = read_ptr(user_data, &mut cur, ptr_sz)?;
                let status = read_u32(user_data, &mut cur)?;
                let index = read_u32(user_data, &mut cur)?;
                let _info_class = read_u32(user_data, &mut cur)?;
                let _data_size = read_u32(user_data, &mut cur)?;
                let key_name = read_utf16_nul(user_data, &mut cur).unwrap_or_default();
                let captured_size = usize::from(read_u16(user_data, &mut cur).unwrap_or(0));
                let avail = user_data.len().saturating_sub(cur);
                let raw_bytes = user_data[cur..cur + captured_size.min(avail)].to_vec();
                let full_path = self.resolve_key_path(key_obj, &key_name);
                let op = event_id_operation_name(event_id);

                Some(RegistryWatchEvent {
                    timestamp,
                    pid,
                    tid,
                    process_name,
                    event_id,
                    opcode,
                    operation: op.to_owned(),
                    key_path: full_path.clone(),
                    value_name: None,
                    value_type: None,
                    data: None,
                    raw_bytes,
                    status,
                    reg_dotnet_line: format!("; {op} #{index} [{full_path}]"),
                })
            }
            // QueryMultipleValueKey (10): KeyObject(Ptr), Status(u32), EntryCount(u32), DataSize(u32), KeyName
            10 => {
                let key_obj = read_ptr(user_data, &mut cur, ptr_sz)?;
                let status = read_u32(user_data, &mut cur)?;
                let entry_count = read_u32(user_data, &mut cur)?;
                let _data_size = read_u32(user_data, &mut cur)?;
                let key_name = read_utf16_nul(user_data, &mut cur).unwrap_or_default();
                let full_path = self.resolve_key_path(key_obj, &key_name);

                Some(RegistryWatchEvent {
                    timestamp,
                    pid,
                    tid,
                    process_name,
                    event_id,
                    opcode,
                    operation: "QueryMultipleValue".to_owned(),
                    key_path: full_path.clone(),
                    value_name: None,
                    value_type: None,
                    data: None,
                    raw_bytes: Vec::new(),
                    status,
                    reg_dotnet_line: format!("; QueryMultipleValue ({entry_count} entries) [{full_path}]"),
                })
            }
            // FlushKey (12) / CloseKey (13) / QuerySecurityKey (14) / SetSecurityKey (15):
            // KeyObject(Ptr), Status(u32), KeyName
            12..=15 => {
                let key_obj = read_ptr(user_data, &mut cur, ptr_sz)?;
                let status = read_u32(user_data, &mut cur)?;
                let key_name = read_utf16_nul(user_data, &mut cur).unwrap_or_default();
                let full_path = self.resolve_key_path(key_obj, &key_name);
                if event_id == 13 {
                    self.key_objects.remove(&key_obj);
                }
                let op = event_id_operation_name(event_id);

                Some(RegistryWatchEvent {
                    timestamp,
                    pid,
                    tid,
                    process_name,
                    event_id,
                    opcode,
                    operation: op.to_owned(),
                    key_path: full_path.clone(),
                    value_name: None,
                    value_type: None,
                    data: None,
                    raw_bytes: Vec::new(),
                    status,
                    reg_dotnet_line: format!("; {op} [{full_path}]"),
                })
            }
            _ => None,
        }
    }
}

fn read_ptr(buf: &[u8], cur: &mut usize, ptr_sz: usize) -> Option<u64> {
    if ptr_sz == 4 {
        let val = read_u32(buf, cur)?;
        Some(u64::from(val))
    } else {
        let slice = buf.get(*cur..*cur + 8)?;
        *cur += 8;
        Some(u64::from_le_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ]))
    }
}

fn read_u32(buf: &[u8], cur: &mut usize) -> Option<u32> {
    let slice = buf.get(*cur..*cur + 4)?;
    *cur += 4;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u16(buf: &[u8], cur: &mut usize) -> Option<u16> {
    let slice = buf.get(*cur..*cur + 2)?;
    *cur += 2;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_utf16_nul(buf: &[u8], cur: &mut usize) -> Option<String> {
    if *cur >= buf.len() {
        return None;
    }
    let mut units = Vec::new();
    while *cur + 1 < buf.len() {
        let u = u16::from_le_bytes([buf[*cur], buf[*cur + 1]]);
        *cur += 2;
        if u == 0 {
            break;
        }
        units.push(u);
    }
    Some(String::from_utf16_lossy(&units))
}

/// Encodes synthetic ETW Kernel-Registry records into the `"F2RETW01"` binary fixture format.
/// Record layout: `[event_id: u16, flags: u16, pid: u32, filetime: u64, user_data_len: u32, user_data: [u8]]`.
pub fn encode_f2retw01_trace(records: &[(u16, u16, u32, u64, &[u8])]) -> Vec<u8> {
    let mut out = Vec::from(&F2RETW01_MAGIC[..]);
    for &(event_id, flags, pid, filetime, user_data) in records {
        out.extend_from_slice(&event_id.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&pid.to_le_bytes());
        out.extend_from_slice(&filetime.to_le_bytes());
        out.extend_from_slice(&(user_data.len() as u32).to_le_bytes());
        out.extend_from_slice(user_data);
    }
    out
}

/// Parses an `"F2RETW01"` binary ETW trace stream using [`EtwRegistryDecoderState`].
pub fn parse_f2retw01_trace(bytes: &[u8]) -> Result<Vec<RegistryWatchEvent>, ForensicError> {
    if !bytes.starts_with(F2RETW01_MAGIC) {
        return Err(ForensicError::parse("f2retw01", "missing F2RETW01 header magic"));
    }
    let mut cur = F2RETW01_MAGIC.len();
    let mut state = EtwRegistryDecoderState::new();
    let mut events = Vec::new();

    while cur < bytes.len() {
        if bytes.len() - cur < 20 {
            return Err(ForensicError::parse(
                "f2retw01",
                format!("truncated record header at byte offset {cur}"),
            ));
        }
        let event_id = u16::from_le_bytes([bytes[cur], bytes[cur + 1]]);
        let flags = u16::from_le_bytes([bytes[cur + 2], bytes[cur + 3]]);
        let pid = u32::from_le_bytes([bytes[cur + 4], bytes[cur + 5], bytes[cur + 6], bytes[cur + 7]]);
        let ft = u64::from_le_bytes([
            bytes[cur + 8],
            bytes[cur + 9],
            bytes[cur + 10],
            bytes[cur + 11],
            bytes[cur + 12],
            bytes[cur + 13],
            bytes[cur + 14],
            bytes[cur + 15],
        ]);
        let ud_len = u32::from_le_bytes([bytes[cur + 16], bytes[cur + 17], bytes[cur + 18], bytes[cur + 19]]) as usize;
        cur += 20;

        let end = cur.checked_add(ud_len).filter(|&e| e <= bytes.len()).ok_or_else(|| {
            ForensicError::parse(
                "f2retw01",
                format!("record user_data_len={ud_len} exceeds stream bounds at offset {cur}"),
            )
        })?;
        let user_data = &bytes[cur..end];
        cur = end;

        let pointer_size = if (flags & EVENT_HEADER_FLAG_64_BIT_HEADER_U16) != 0 {
            8
        } else {
            4
        };
        let timestamp = filetime_to_utc(ft).unwrap_or_else(Utc::now);
        let opcode = 31u8.saturating_add(event_id as u8);
        let proc_name = format!("PID:{pid}");

        if let Some(ev) = state.decode_record(event_id, opcode, pointer_size, pid, 0, timestamp, proc_name, user_data) {
            events.push(ev);
        }
    }

    Ok(events)
}

/// Parses an offline `hive.watch` fixture (`"F2RETW01"` binary trace, JSON array/NDJSON, or `.reg` script).
pub fn parse_offline_watch_bytes(bytes: &[u8]) -> Result<Vec<RegistryWatchEvent>, ForensicError> {
    if bytes.starts_with(F2RETW01_MAGIC) {
        return parse_f2retw01_trace(bytes);
    }

    let trimmed_utf8 = std::str::from_utf8(bytes)
        .map(|s| s.trim_start_matches('\u{FEFF}').trim())
        .ok();
    if let Some(text) = trimmed_utf8 {
        if text.starts_with('{') {
            return parse_json_watch_records(text);
        }
        if text.starts_with('[') {
            let first_line = text.lines().next().unwrap_or("").trim();
            let looks_like_reg_section = first_line.starts_with('[')
                && first_line.ends_with(']')
                && first_line.len() > 2
                && !first_line[1..].trim_start().starts_with('{')
                && !first_line[1..].trim_start().starts_with('"')
                && !first_line[1..].trim_start().starts_with(']');
            if !looks_like_reg_section {
                return parse_json_watch_records(text);
            }
            if let Ok(json_events) = parse_json_watch_records(text) {
                return Ok(json_events);
            }
        }
    }

    let entries = parse_reg_script(bytes)?;
    let now = Utc::now();
    let events = entries
        .into_iter()
        .map(|entry| {
            let event_id = match entry.operation {
                RegScriptOp::CreateKey => 1,
                RegScriptOp::DeleteKey => 3,
                RegScriptOp::SetValue => 5,
                RegScriptOp::DeleteValue => 6,
            };
            RegistryWatchEvent {
                timestamp: now,
                pid: 0,
                tid: 0,
                process_name: "reg-script".to_owned(),
                event_id,
                opcode: 31 + event_id as u8,
                operation: entry.operation.as_str().to_owned(),
                key_path: normalize_nt_registry_path(&entry.key_path),
                value_name: entry.value_name,
                value_type: entry.value_type,
                data: entry.data,
                raw_bytes: entry.raw_bytes,
                status: 0,
                reg_dotnet_line: entry.reg_dotnet_line,
            }
        })
        .collect();
    Ok(events)
}

fn parse_json_watch_records(text: &str) -> Result<Vec<RegistryWatchEvent>, ForensicError> {
    let raw_records: Vec<RawEtwRegistryRecord> = if text.starts_with('[') {
        serde_json::from_str(text).map_err(|e| ForensicError::parse("etw_json", e.to_string()))?
    } else {
        let mut list = Vec::new();
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let rec: RawEtwRegistryRecord =
                serde_json::from_str(line).map_err(|e| ForensicError::parse("etw_ndjson", e.to_string()))?;
            list.push(rec);
        }
        list
    };

    let mut state = EtwRegistryDecoderState::new();
    let mut out = Vec::with_capacity(raw_records.len());

    for rec in raw_records {
        let ts = rec.timestamp.unwrap_or_else(Utc::now);
        let proc_name = rec.process_name.unwrap_or_else(|| format!("PID:{}", rec.pid));

        if let Some(hex_ud) = rec.user_data_hex {
            let ud = hex::decode(hex_ud.trim())
                .map_err(|e| ForensicError::parse("etw_json", format!("invalid user_data_hex: {e}")))?;
            if let Some(ev) = state.decode_record(
                rec.event_id,
                rec.opcode,
                rec.pointer_size,
                rec.pid,
                rec.tid,
                ts,
                proc_name,
                &ud,
            ) {
                out.push(ev);
            }
        } else {
            let raw_bytes = match rec.data_hex {
                Some(ref h) if !h.trim().is_empty() => hex::decode(h.trim())
                    .map_err(|e| ForensicError::parse("etw_json", format!("invalid data_hex: {e}")))?,
                _ => Vec::new(),
            };
            let data = rec.value_type.map(|vt| RegValueData::from_raw(vt, &raw_bytes));
            let key_path = normalize_nt_registry_path(rec.key_path.as_deref().unwrap_or(""));
            let op = rec
                .operation
                .unwrap_or_else(|| event_id_operation_name(rec.event_id).to_owned());
            let reg_dotnet_line = rec.reg_dotnet_line.unwrap_or_else(|| match (rec.event_id, &data) {
                (5, Some(d)) => format_reg_value_line(
                    rec.value_name.as_deref().unwrap_or(""),
                    d,
                    &raw_bytes,
                    RegExportFormat::Regedit5,
                ),
                (6, _) => match rec.value_name.as_deref() {
                    Some("") | None => "@=-".to_owned(),
                    Some(vn) => format!("\"{}\"=-", escape_reg_str(vn)),
                },
                (3, _) => format!("[-{key_path}]"),
                _ => format!("[{key_path}]"),
            });

            out.push(RegistryWatchEvent {
                timestamp: ts,
                pid: rec.pid,
                tid: rec.tid,
                process_name: proc_name,
                event_id: rec.event_id,
                opcode: rec.opcode,
                operation: op,
                key_path,
                value_name: rec.value_name,
                value_type: rec.value_type,
                data,
                raw_bytes,
                status: 0,
                reg_dotnet_line,
            });
        }
    }

    Ok(out)
}

/// Renders a sequence of [`RegistryWatchEvent`]s into a valid `Windows Registry Editor Version 5.00` script.
pub fn export_watch_reg_script(events: &[RegistryWatchEvent]) -> String {
    let mut out = String::from("Windows Registry Editor Version 5.00\r\n\r\n");
    let mut current_key: Option<&str> = None;

    for ev in events {
        match ev.event_id {
            1 => {
                if !ev.key_path.is_empty() && current_key != Some(ev.key_path.as_str()) {
                    out.push('[');
                    out.push_str(&ev.key_path);
                    out.push_str("]\r\n");
                    current_key = Some(&ev.key_path);
                }
            }
            3 => {
                if !ev.key_path.is_empty() {
                    out.push_str("[-");
                    out.push_str(&ev.key_path);
                    out.push_str("]\r\n\r\n");
                    current_key = None;
                }
            }
            5 | 6 => {
                if !ev.key_path.is_empty() && current_key != Some(ev.key_path.as_str()) {
                    if current_key.is_some() {
                        out.push_str("\r\n");
                    }
                    out.push('[');
                    out.push_str(&ev.key_path);
                    out.push_str("]\r\n");
                    current_key = Some(&ev.key_path);
                }
                if !ev.reg_dotnet_line.is_empty() && !ev.reg_dotnet_line.starts_with('[') {
                    out.push_str(&ev.reg_dotnet_line);
                    out.push_str("\r\n");
                }
            }
            _ => {}
        }
    }

    let _ = bytes_to_hex_lower(&[]);
    out
}

#[cfg(windows)]
mod imp {
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use chrono::Utc;
    use forensics2rust_core::{ForensicError, filetime_to_utc};
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_PRIVILEGE_NOT_HELD, ERROR_SUCCESS, GetLastError,
        HANDLE, WIN32_ERROR,
    };
    use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
    use windows::Win32::System::Diagnostics::Etw::{
        CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, ENABLE_TRACE_PARAMETERS, ENABLE_TRACE_PARAMETERS_VERSION_2,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_HEADER_FLAG_64_BIT_HEADER, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP,
        EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW,
        PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE, ProcessTrace, StartTraceW,
        TRACE_LEVEL_VERBOSE, WNODE_FLAG_TRACED_GUID,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };
    use windows::core::{GUID, PCWSTR, PWSTR};

    use super::{
        EtwRegistryDecoderState, KERNEL_REGISTRY_PROVIDER_U128, RegistryWatchEvent, WatchOptions, is_mutation_event_id,
    };

    const INVALID_PROCESSTRACE_HANDLE_VAL: u64 = u64::MAX;

    struct SafeHandle(HANDLE);

    impl Drop for SafeHandle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    /// Checks whether the current process token is elevated (Administrator).
    pub fn is_process_elevated() -> bool {
        let mut token = HANDLE::default();
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if opened.is_err() {
            return false;
        }
        let _guard = SafeHandle(token);
        let mut elev = TOKEN_ELEVATION::default();
        let mut ret_len: u32 = 0;
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                Some((&raw mut elev).cast::<c_void>()),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            )
        };
        ok.is_ok() && elev.TokenIsElevated != 0
    }

    fn resolve_process_name(pid: u32, cache: &mut HashMap<u32, String>) -> String {
        if let Some(cached) = cache.get(&pid) {
            return cached.clone();
        }
        let resolved = if pid == 0 {
            "Idle".to_owned()
        } else if pid == 4 {
            "System".to_owned()
        } else if let Ok(proc_handle) = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
            let _guard = SafeHandle(proc_handle);
            let mut buf = vec![0u16; 512];
            let mut size = buf.len() as u32;
            let ok = unsafe {
                QueryFullProcessImageNameW(proc_handle, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut size)
            };
            if ok.is_ok() && size > 0 {
                let full = String::from_utf16_lossy(&buf[..size as usize]);
                full.rsplit('\\').next().unwrap_or(&full).to_owned()
            } else {
                format!("PID:{pid}")
            }
        } else {
            format!("PID:{pid}")
        };
        cache.insert(pid, resolved.clone());
        resolved
    }

    fn init_trace_properties(buf: &mut [u64], session_name_wide: &[u16]) {
        buf.fill(0);
        let total_bytes = std::mem::size_of_val(buf);
        let props_size = size_of::<EVENT_TRACE_PROPERTIES>();
        unsafe {
            let props = &mut *buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
            props.Wnode.BufferSize = total_bytes as u32;
            props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            // ClientContext = 2 => SystemTime (Windows FILETIME)
            props.Wnode.ClientContext = 2;
            props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            props.BufferSize = 64;
            props.MinimumBuffers = 4;
            props.MaximumBuffers = 64;
            props.FlushTimer = 1;
            props.LoggerNameOffset = props_size as u32;

            let dst = buf.as_mut_ptr().cast::<u8>().add(props_size).cast::<u16>();
            std::ptr::copy_nonoverlapping(session_name_wide.as_ptr(), dst, session_name_wide.len());
        }
    }

    struct EtwSessionGuard {
        session_name: Vec<u16>,
        props_buf: Vec<u64>,
        session_handle: CONTROLTRACE_HANDLE,
        trace_handle: PROCESSTRACE_HANDLE,
        stopped: Arc<AtomicBool>,
    }

    impl EtwSessionGuard {
        fn stop_session(&mut self) {
            if !self.stopped.swap(true, Ordering::AcqRel) && self.session_handle.Value != 0 {
                let props_ptr = self.props_buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
                unsafe {
                    let _ = ControlTraceW(
                        self.session_handle,
                        PCWSTR(self.session_name.as_ptr()),
                        props_ptr,
                        EVENT_TRACE_CONTROL_STOP,
                    );
                }
            }
            if self.trace_handle.Value != INVALID_PROCESSTRACE_HANDLE_VAL {
                unsafe {
                    let _ = CloseTrace(self.trace_handle);
                }
                self.trace_handle.Value = INVALID_PROCESSTRACE_HANDLE_VAL;
            }
        }
    }

    impl Drop for EtwSessionGuard {
        fn drop(&mut self) {
            self.stop_session();
        }
    }

    struct CallbackContext {
        options: WatchOptions,
        decoder: EtwRegistryDecoderState,
        proc_cache: HashMap<u32, String>,
        events: Mutex<Vec<RegistryWatchEvent>>,
        stop_flag: Arc<AtomicBool>,
        session_handle: CONTROLTRACE_HANDLE,
        session_name: Vec<u16>,
        stop_props_buf: Vec<u64>,
    }

    unsafe extern "system" fn on_event_record(event_record: *mut EVENT_RECORD) {
        if event_record.is_null() {
            return;
        }
        let rec = unsafe { &*event_record };
        if rec.UserContext.is_null() {
            return;
        }
        let ctx = unsafe { &mut *rec.UserContext.cast::<CallbackContext>() };
        if ctx.stop_flag.load(Ordering::Acquire) {
            return;
        }

        let target_guid = GUID::from_u128(KERNEL_REGISTRY_PROVIDER_U128);
        if rec.EventHeader.ProviderId != target_guid {
            return;
        }

        let event_id = rec.EventHeader.EventDescriptor.Id;
        let is_key_lifecycle = matches!(event_id, 1 | 2 | 3 | 13);
        if ctx.options.mutations_only && !is_mutation_event_id(event_id) && !is_key_lifecycle {
            return;
        }

        let pid = rec.EventHeader.ProcessId;
        let pid_matches = ctx.options.target_pid.is_none_or(|filter_pid| pid == filter_pid);
        if !pid_matches && !is_key_lifecycle {
            return;
        }

        let proc_name = if pid_matches {
            resolve_process_name(pid, &mut ctx.proc_cache)
        } else {
            String::new()
        };
        let proc_matches = pid_matches
            && ctx
                .options
                .process_filter
                .as_ref()
                .is_none_or(|pfilter| proc_name.to_ascii_lowercase().contains(&pfilter.to_ascii_lowercase()));
        if !proc_matches && !is_key_lifecycle {
            return;
        }

        let pointer_size = if (u32::from(rec.EventHeader.Flags) & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0 {
            8
        } else {
            4
        };
        let timestamp = u64::try_from(rec.EventHeader.TimeStamp)
            .ok()
            .and_then(filetime_to_utc)
            .unwrap_or_else(Utc::now);

        let user_data = if rec.UserData.is_null() || rec.UserDataLength == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(rec.UserData.cast::<u8>(), usize::from(rec.UserDataLength)) }
        };

        let Some(ev) = ctx.decoder.decode_record(
            event_id,
            rec.EventHeader.EventDescriptor.Opcode,
            pointer_size,
            pid,
            rec.EventHeader.ThreadId,
            timestamp,
            proc_name,
            user_data,
        ) else {
            return;
        };

        if ctx.options.mutations_only && !is_mutation_event_id(event_id) {
            return;
        }
        if !proc_matches {
            return;
        }

        if let Some(ref kfilter) = ctx.options.key_filter
            && !ev.key_path.to_ascii_lowercase().contains(&kfilter.to_ascii_lowercase())
        {
            return;
        }

        if let Ok(mut guard) = ctx.events.lock() {
            if guard.len() < ctx.options.max_events {
                guard.push(ev);
            }
            if guard.len() >= ctx.options.max_events && !ctx.stop_flag.swap(true, Ordering::AcqRel) {
                let props_ptr = ctx.stop_props_buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
                unsafe {
                    let _ = ControlTraceW(
                        ctx.session_handle,
                        PCWSTR(ctx.session_name.as_ptr()),
                        props_ptr,
                        EVENT_TRACE_CONTROL_STOP,
                    );
                }
            }
        }
    }

    pub fn watch_live_registry(options: &WatchOptions) -> Result<Vec<RegistryWatchEvent>, ForensicError> {
        let session_str = format!("forensics2rust-regwatch-{}", std::process::id());
        let mut session_name: Vec<u16> = session_str.encode_utf16().collect();
        session_name.push(0);

        let total_bytes = size_of::<EVENT_TRACE_PROPERTIES>() + session_name.len() * size_of::<u16>();
        let u64_len = total_bytes.div_ceil(size_of::<u64>());
        let mut props_buf = vec![0u64; u64_len];
        init_trace_properties(&mut props_buf, &session_name);

        let mut session_handle = CONTROLTRACE_HANDLE::default();
        let mut err = unsafe {
            StartTraceW(
                &mut session_handle,
                PCWSTR(session_name.as_ptr()),
                props_buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>(),
            )
        };

        if err == ERROR_ALREADY_EXISTS {
            let mut stop_buf = vec![0u64; u64_len];
            init_trace_properties(&mut stop_buf, &session_name);
            unsafe {
                let _ = ControlTraceW(
                    CONTROLTRACE_HANDLE::default(),
                    PCWSTR(session_name.as_ptr()),
                    stop_buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>(),
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            init_trace_properties(&mut props_buf, &session_name);
            err = unsafe {
                StartTraceW(
                    &mut session_handle,
                    PCWSTR(session_name.as_ptr()),
                    props_buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>(),
                )
            };
        }

        if err == ERROR_ACCESS_DENIED || err == ERROR_PRIVILEGE_NOT_HELD {
            let elevated = is_process_elevated();
            return Err(ForensicError::permission_denied(
                "ETW StartTraceW",
                format!(
                    "ETW Microsoft-Windows-Kernel-Registry session requires Administrator or Performance Log Users privilege (elevated={elevated}, Win32 error {})",
                    err.0
                ),
            ));
        }
        if err != ERROR_SUCCESS {
            return Err(ForensicError::io_classified(
                "ETW StartTraceW",
                std::io::Error::from_raw_os_error(err.0 as i32),
            ));
        }

        let stopped = Arc::new(AtomicBool::new(false));
        let mut guard = EtwSessionGuard {
            session_name: session_name.clone(),
            props_buf,
            session_handle,
            trace_handle: PROCESSTRACE_HANDLE {
                Value: INVALID_PROCESSTRACE_HANDLE_VAL,
            },
            stopped: Arc::clone(&stopped),
        };

        let provider_guid = GUID::from_u128(KERNEL_REGISTRY_PROVIDER_U128);
        let enable_params = ENABLE_TRACE_PARAMETERS {
            Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
            ..Default::default()
        };
        let match_any_keyword: u64 = if options.mutations_only {
            0x0000_0000_0000_7301
        } else {
            0x0000_0000_0000_FFFF
        };

        let enable_err = unsafe {
            EnableTraceEx2(
                guard.session_handle,
                &provider_guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                TRACE_LEVEL_VERBOSE as u8,
                match_any_keyword,
                0,
                0,
                Some(&enable_params),
            )
        };
        if enable_err == ERROR_ACCESS_DENIED || enable_err == ERROR_PRIVILEGE_NOT_HELD {
            return Err(ForensicError::permission_denied(
                "ETW EnableTraceEx2",
                format!(
                    "access denied enabling Kernel-Registry provider (Win32 error {})",
                    enable_err.0
                ),
            ));
        }
        if enable_err != ERROR_SUCCESS {
            return Err(ForensicError::io_classified(
                "ETW EnableTraceEx2",
                std::io::Error::from_raw_os_error(enable_err.0 as i32),
            ));
        }

        let mut stop_props_buf = vec![0u64; u64_len];
        init_trace_properties(&mut stop_props_buf, &session_name);

        let mut cb_ctx = CallbackContext {
            options: options.clone(),
            decoder: EtwRegistryDecoderState::new(),
            proc_cache: HashMap::new(),
            events: Mutex::new(Vec::new()),
            stop_flag: Arc::clone(&stopped),
            session_handle: guard.session_handle,
            session_name: session_name.clone(),
            stop_props_buf,
        };

        let mut logger_name_mut = session_name.clone();
        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR(logger_name_mut.as_mut_ptr()),
            ..Default::default()
        };
        logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(on_event_record);
        logfile.Context = (&raw mut cb_ctx).cast::<c_void>();

        let trace_handle = unsafe { OpenTraceW(&mut logfile) };
        if trace_handle.Value == INVALID_PROCESSTRACE_HANDLE_VAL {
            let last_err = unsafe { GetLastError() };
            return Err(ForensicError::io_classified(
                "ETW OpenTraceW",
                std::io::Error::from_raw_os_error(last_err.0 as i32),
            ));
        }
        guard.trace_handle = trace_handle;

        let watchdog_stop = Arc::clone(&stopped);
        let watchdog_session = guard.session_handle;
        let watchdog_name = session_name;
        let duration = Duration::from_millis(options.duration_ms.max(1));

        let process_result: WIN32_ERROR = std::thread::scope(|scope| {
            scope.spawn(move || {
                let deadline = Instant::now() + duration;
                while Instant::now() < deadline {
                    if watchdog_stop.load(Ordering::Acquire) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                if !watchdog_stop.swap(true, Ordering::AcqRel) {
                    let mut wd_buf = vec![0u64; u64_len];
                    init_trace_properties(&mut wd_buf, &watchdog_name);
                    unsafe {
                        let _ = ControlTraceW(
                            watchdog_session,
                            PCWSTR(watchdog_name.as_ptr()),
                            wd_buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>(),
                            EVENT_TRACE_CONTROL_STOP,
                        );
                    }
                }
            });

            let handles = [trace_handle];
            unsafe { ProcessTrace(&handles, None, None) }
        });

        guard.stop_session();
        let _ = process_result;

        let events = cb_ctx
            .events
            .into_inner()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(events)
    }
}

#[cfg(not(windows))]
mod imp {
    use forensics2rust_core::ForensicError;

    use super::{RegistryWatchEvent, WatchOptions};

    pub fn is_process_elevated() -> bool {
        false
    }

    pub fn watch_live_registry(_options: &WatchOptions) -> Result<Vec<RegistryWatchEvent>, ForensicError> {
        Err(ForensicError::unsupported_platform(
            "etw_kernel_registry",
            "live ETW Microsoft-Windows-Kernel-Registry capture requires Windows",
        ))
    }
}

pub use imp::{is_process_elevated, watch_live_registry};
