use std::collections::HashMap;

use chrono::{DateTime, Utc};
use forensics2rust_core::{
    bytes_to_hex_lower, filetime_to_utc, ole_automation_date_to_utc, parse_guid_le_braced, parse_sid, read_utf16_le_nul,
};
use guap_table::CellValue;

use crate::ese::compress::{DecompressOutcome, decompress_ese_value};
use crate::ese::{EseDatabase, EseRow, EseValue};

const OLE_EPOCH_UNIX_SECS: i64 = -2_209_161_600;
const MIN_FILETIME_THRESHOLD: u64 = 100_000_000_000_000_000;

#[derive(Debug, Clone)]
pub struct IdMapEntry {
    pub id_index: i64,
    pub id_type: i64,
    pub resolved: String,
    pub raw_blob: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct SruDbIdMap {
    entries: HashMap<i64, IdMapEntry>,
}

impl SruDbIdMap {
    pub fn from_ese(db: &EseDatabase) -> Self {
        let Some(table_name) = db
            .table_names()
            .into_iter()
            .find(|n| n.eq_ignore_ascii_case("SruDbIdMapTable"))
        else {
            tracing::warn!("SruDbIdMapTable not found in ESE database; IDs will fall back to IdIndex(N)");
            return Self::default();
        };

        let table = match db.read_table(&table_name) {
            Ok(t) => t,
            Err(err) => {
                tracing::warn!("failed to read SruDbIdMapTable: {err}");
                return Self::default();
            }
        };

        let mut entries = HashMap::with_capacity(table.rows.len());
        for row in &table.rows {
            if let Some(entry) = parse_id_map_row(row) {
                entries.insert(entry.id_index, entry);
            }
        }

        Self { entries }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, id_index: i64) -> Option<&IdMapEntry> {
        self.entries.get(&id_index)
    }

    pub fn resolve_id(&self, id_index: i64) -> String {
        self.entries
            .get(&id_index)
            .map_or_else(|| format!("IdIndex({id_index})"), |e| e.resolved.clone())
    }

    pub fn resolve_app(&self, val: Option<&EseValue>) -> Option<String> {
        match val {
            None | Some(EseValue::Null) => None,
            Some(EseValue::Text(s)) => Some(s.clone()),
            Some(EseValue::Binary(b)) => Some(decode_id_text_blob(b)),
            Some(other) => other.as_i64().map(|id| self.resolve_id(id)),
        }
    }

    pub fn resolve_user(&self, val: Option<&EseValue>) -> Option<String> {
        match val {
            None | Some(EseValue::Null) => None,
            Some(EseValue::Text(s)) => Some(s.clone()),
            Some(EseValue::Binary(b)) => Some(decode_sid_blob(b)),
            Some(other) => other.as_i64().map(|id| self.resolve_id(id)),
        }
    }
}

fn find_col_ci<'a>(row: &'a EseRow, candidates: &[&str]) -> Option<&'a EseValue> {
    for candidate in candidates {
        if let Some(v) = row.values.get(*candidate) {
            return Some(v);
        }
    }
    for candidate in candidates {
        if let Some((_, v)) = row.values.iter().find(|(k, _)| k.eq_ignore_ascii_case(candidate)) {
            return Some(v);
        }
    }
    None
}

fn parse_id_map_row(row: &EseRow) -> Option<IdMapEntry> {
    let id_index = find_col_ci(row, &["IdIndex", "Index"])?.as_i64()?;
    let id_type = find_col_ci(row, &["IdType", "Type"])
        .and_then(EseValue::as_i64)
        .unwrap_or(-1);

    let blob_val = find_col_ci(row, &["IdBlob", "Blob"]);
    let (resolved, raw_blob) = match blob_val {
        None | Some(EseValue::Null) => (format!("IdIndex({id_index})"), Vec::new()),
        Some(EseValue::Text(s)) => {
            let trimmed = s.trim_end_matches('\0').to_string();
            (trimmed.clone(), trimmed.into_bytes())
        }
        Some(EseValue::Binary(b)) => {
            let decoded = match id_type {
                0..=2 => decode_id_text_blob(b),
                3 => decode_sid_blob(b),
                _ => {
                    if b.len() >= 2 && b.len().is_multiple_of(2) {
                        let s = read_utf16_le_nul(b);
                        if !s.is_empty() && s.chars().all(|c| !c.is_control() || c.is_whitespace()) {
                            s
                        } else {
                            format!("0x{}", bytes_to_hex_lower(b))
                        }
                    } else {
                        format!("0x{}", bytes_to_hex_lower(b))
                    }
                }
            };
            (decoded, b.clone())
        }
        Some(other) => (other.display_compact(), Vec::new()),
    };

    Some(IdMapEntry {
        id_index,
        id_type,
        resolved,
        raw_blob,
    })
}

pub fn decode_id_text_blob(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    if matches!(bytes[0] & 0xF8, 0x08 | 0x10 | 0x18) && bytes.len() >= 2 {
        let mut warnings = Vec::new();
        if let Ok(DecompressOutcome::Decompressed {
            bytes: dec,
            is_utf16_expanded,
        }) = decompress_ese_value(bytes, &mut warnings)
        {
            let candidate =
                if is_utf16_expanded || (dec.len() >= 2 && dec.len().is_multiple_of(2) && dec.get(1) == Some(&0)) {
                    read_utf16_le_nul(&dec)
                } else {
                    String::from_utf8_lossy(&dec).trim_end_matches('\0').to_string()
                };
            if !candidate.is_empty() && candidate.chars().all(|c| !c.is_control() || c.is_whitespace()) {
                return candidate;
            }
        }
    }

    if bytes.len() >= 2 && bytes.len().is_multiple_of(2) && bytes.as_chunks::<2>().0.iter().any(|c| c[1] == 0) {
        let utf16 = read_utf16_le_nul(bytes);
        if !utf16.is_empty() && utf16.chars().all(|c| !c.is_control() || c.is_whitespace()) {
            return utf16;
        }
    }

    if let Ok(utf8) = std::str::from_utf8(bytes) {
        let trimmed = utf8.trim_end_matches('\0');
        if !trimmed.is_empty() && trimmed.chars().all(|c| !c.is_control() || c.is_whitespace()) {
            return trimmed.to_string();
        }
    }

    if bytes.len() >= 2 && bytes.len().is_multiple_of(2) {
        let utf16 = read_utf16_le_nul(bytes);
        if !utf16.is_empty() && utf16.chars().all(|c| !c.is_control() || c.is_whitespace()) {
            return utf16;
        }
    }

    format!("0x{}", bytes_to_hex_lower(bytes))
}

pub fn decode_sid_blob(bytes: &[u8]) -> String {
    if let Ok(sid) = parse_sid(bytes) {
        return sid;
    }
    if bytes.len() >= 8 && bytes.len().is_multiple_of(2) {
        let s = read_utf16_le_nul(bytes);
        if s.starts_with("S-1-") {
            return s;
        }
    }
    format!("0x{}", bytes_to_hex_lower(bytes))
}

pub fn format_interface_luid(val: Option<&EseValue>) -> CellValue {
    match val {
        None | Some(EseValue::Null) => CellValue::Null,
        Some(EseValue::Text(s)) => CellValue::Text(s.clone()),
        Some(EseValue::Guid(g)) => CellValue::Text(g.clone()),
        Some(EseValue::Binary(b)) => {
            if b.len() == 8 {
                let luid = u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]));
                CellValue::Text(format_luid_u64(luid))
            } else if b.len() >= 16 {
                parse_guid_le_braced(b)
                    .map(CellValue::Text)
                    .unwrap_or_else(|_| CellValue::Hex(b.clone()))
            } else {
                CellValue::Hex(b.clone())
            }
        }
        Some(other) => {
            if let Some(raw) = other.as_i64() {
                CellValue::Text(format_luid_u64(raw as u64))
            } else {
                CellValue::Text(other.display_compact())
            }
        }
    }
}

pub fn format_luid_u64(luid: u64) -> String {
    let if_type = ((luid >> 48) & 0xFFFF) as u16;
    let kind = match if_type {
        6 => Some("Ethernet"),
        23 => Some("PPP"),
        24 => Some("Loopback"),
        53 => Some("PropVirtual"),
        71 => Some("Wi-Fi"),
        131 => Some("Tunnel"),
        _ => None,
    };
    match kind {
        Some(label) => format!("0x{luid:016x} ({label})"),
        None => format!("0x{luid:016x}"),
    }
}

pub fn decode_srum_timestamp(val: Option<&EseValue>) -> Option<DateTime<Utc>> {
    match val? {
        EseValue::Null => None,
        EseValue::DateTime(dt) => {
            if dt.timestamp() == OLE_EPOCH_UNIX_SECS && dt.timestamp_subsec_nanos() == 0 {
                None
            } else {
                Some(*dt)
            }
        }
        EseValue::F64(days) => {
            if *days == 0.0 {
                None
            } else {
                ole_automation_date_to_utc(*days)
            }
        }
        EseValue::I64(v) => {
            if *v <= 0 {
                None
            } else {
                let raw = *v as u64;
                if raw >= MIN_FILETIME_THRESHOLD {
                    filetime_to_utc(raw)
                } else {
                    None
                }
            }
        }
        EseValue::Binary(b) if b.len() == 8 => {
            let raw_u64 = u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]));
            if raw_u64 == 0 {
                None
            } else if raw_u64 >= MIN_FILETIME_THRESHOLD {
                filetime_to_utc(raw_u64)
            } else {
                let days = f64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]));
                if days == 0.0 {
                    None
                } else {
                    ole_automation_date_to_utc(days)
                }
            }
        }
        _ => None,
    }
}
