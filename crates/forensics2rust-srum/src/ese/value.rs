use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use forensics2rust_core::{
    DiagnosticWarning, ForensicError, WarningSeverity, ole_automation_date_to_utc, parse_guid_le_braced, read_utf16_le,
};
use guap_table::CellValue;

use super::catalog::{EseColumnSchema, EseTableSchema, JetColType};
use super::compress::{DecompressOutcome, decompress_ese_value, is_known_ese_compression_header};
use super::lv::LongValueIndex;
use super::record::{ParsedRecord, TaggedField};

#[derive(Debug, Clone, PartialEq)]
pub enum EseValue {
    Null,
    Bool(bool),
    U8(u8),
    I16(i16),
    U16(u16),
    I32(i32),
    U32(u32),
    I64(i64),
    F32(f32),
    F64(f64),
    DateTime(DateTime<Utc>),
    Text(String),
    Binary(Vec<u8>),
    Guid(String),
}

impl EseValue {
    pub fn to_cell_value(&self) -> CellValue {
        match self {
            Self::Null => CellValue::Null,
            Self::Bool(b) => CellValue::Bool(*b),
            Self::U8(v) => CellValue::Uint(u64::from(*v)),
            Self::I16(v) => CellValue::Int(i64::from(*v)),
            Self::U16(v) => CellValue::Uint(u64::from(*v)),
            Self::I32(v) => CellValue::Int(i64::from(*v)),
            Self::U32(v) => CellValue::Uint(u64::from(*v)),
            Self::I64(v) => CellValue::Int(*v),
            Self::F32(v) => CellValue::Float(f64::from(*v)),
            Self::F64(v) => CellValue::Float(*v),
            Self::DateTime(dt) => CellValue::Timestamp(*dt),
            Self::Text(s) => CellValue::Text(s.clone()),
            Self::Binary(b) => CellValue::Hex(b.clone()),
            Self::Guid(g) => CellValue::Text(g.clone()),
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::U8(v) => Some(i64::from(*v)),
            Self::I16(v) => Some(i64::from(*v)),
            Self::U16(v) => Some(i64::from(*v)),
            Self::I32(v) => Some(i64::from(*v)),
            Self::U32(v) => Some(i64::from(*v)),
            Self::I64(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::U8(v) => Some(u64::from(*v)),
            Self::I16(v) => u64::try_from(*v).ok(),
            Self::U16(v) => Some(u64::from(*v)),
            Self::I32(v) => u64::try_from(*v).ok(),
            Self::U32(v) => Some(u64::from(*v)),
            Self::I64(v) => u64::try_from(*v).ok(),
            _ => None,
        }
    }

    pub fn to_json_value(&self) -> serde_json::Value {
        match self {
            Self::Null => serde_json::Value::Null,
            Self::Bool(b) => serde_json::Value::Bool(*b),
            Self::U8(v) => serde_json::Value::from(*v),
            Self::I16(v) => serde_json::Value::from(*v),
            Self::U16(v) => serde_json::Value::from(*v),
            Self::I32(v) => serde_json::Value::from(*v),
            Self::U32(v) => serde_json::Value::from(*v),
            Self::I64(v) => serde_json::Value::from(*v),
            Self::F32(v) => serde_json::json!(*v),
            Self::F64(v) => serde_json::json!(*v),
            Self::DateTime(dt) => serde_json::Value::String(dt.to_rfc3339()),
            Self::Text(s) => serde_json::Value::String(s.clone()),
            Self::Binary(b) => serde_json::Value::String(format!("0x{}", forensics2rust_core::bytes_to_hex_lower(b))),
            Self::Guid(g) => serde_json::Value::String(g.clone()),
        }
    }

    pub fn display_compact(&self) -> String {
        match self {
            Self::Null => String::new(),
            Self::Bool(b) => b.to_string(),
            Self::U8(v) => v.to_string(),
            Self::I16(v) => v.to_string(),
            Self::U16(v) => v.to_string(),
            Self::I32(v) => v.to_string(),
            Self::U32(v) => v.to_string(),
            Self::I64(v) => v.to_string(),
            Self::F32(v) => v.to_string(),
            Self::F64(v) => v.to_string(),
            Self::DateTime(dt) => dt.to_rfc3339(),
            Self::Text(s) => s.clone(),
            Self::Binary(b) => format!("0x{}", forensics2rust_core::bytes_to_hex_lower(b)),
            Self::Guid(g) => g.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EseRow {
    pub values: BTreeMap<String, EseValue>,
    pub raw_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EseTableData {
    pub schema: EseTableSchema,
    pub rows: Vec<EseRow>,
}

/// Pure-Rust Windows-1252 single-byte decoder (`0x80..=0x9F` mapped per CP1252).
pub fn decode_cp1252(bytes: &[u8]) -> String {
    const C1_MAP: [char; 32] = [
        '\u{20AC}', '\u{FFFD}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}', '\u{02C6}',
        '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{FFFD}', '\u{017D}', '\u{FFFD}', '\u{FFFD}', '\u{2018}',
        '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}', '\u{02DC}', '\u{2122}', '\u{0161}',
        '\u{203A}', '\u{0153}', '\u{FFFD}', '\u{017E}', '\u{0178}',
    ];

    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            0x00..=0x7F => out.push(b as char),
            0x80..=0x9F => out.push(C1_MAP[(b - 0x80) as usize]),
            0xA0..=0xFF => out.push(char::from(b)),
        }
    }
    out
}

pub fn decode_ese_text(bytes: &[u8], codepage: u32, force_utf16: bool) -> String {
    let raw = if force_utf16 || codepage == 1200 {
        read_utf16_le(bytes)
    } else {
        decode_cp1252(bytes)
    };
    raw.trim_end_matches('\0').to_string()
}

pub fn decode_column_value(
    col: &EseColumnSchema,
    rec: &ParsedRecord,
    lv_index: &LongValueIndex,
    warnings: &mut Vec<DiagnosticWarning>,
) -> Result<EseValue, ForensicError> {
    decode_column_value_with_collision(col, rec, lv_index, false, warnings)
}

pub fn decode_column_value_with_collision(
    col: &EseColumnSchema,
    rec: &ParsedRecord,
    lv_index: &LongValueIndex,
    has_fid_collision: bool,
    warnings: &mut Vec<DiagnosticWarning>,
) -> Result<EseValue, ForensicError> {
    if col.id <= 127 {
        let Some(bytes) = rec.get_fixed(col.id) else {
            return Ok(EseValue::Null);
        };
        return Ok(decode_scalar(col, bytes, false));
    }
    if col.id <= 255 {
        let Some(bytes) = rec.get_variable(col.id) else {
            return Ok(EseValue::Null);
        };
        return Ok(decode_scalar(col, bytes, false));
    }

    let Some(tagged) = rec.get_tagged_for_column(col.id, col.is_derived, has_fid_collision) else {
        return Ok(EseValue::Null);
    };
    decode_tagged_field(col, tagged, lv_index, warnings)
}

fn decode_tagged_field(
    col: &EseColumnSchema,
    tagged: &TaggedField,
    lv_index: &LongValueIndex,
    warnings: &mut Vec<DiagnosticWarning>,
) -> Result<EseValue, ForensicError> {
    if tagged.is_null {
        return Ok(EseValue::Null);
    }

    let col_compressed = (col.flags & 0x1000) != 0;

    if tagged.is_multi_value || tagged.is_two_values {
        let owned_lv: Vec<u8>;
        let mv_bytes: &[u8] = if tagged.is_separated {
            let Some(resolved) = lv_index.resolve_column(&tagged.data, false, false, warnings)? else {
                return Ok(EseValue::Binary(tagged.data.clone()));
            };
            owned_lv = resolved.bytes;
            &owned_lv
        } else {
            &tagged.data
        };

        return decode_multi_value_bytes(
            col,
            mv_bytes,
            tagged.is_two_values,
            tagged.is_compressed,
            lv_index,
            warnings,
        );
    }

    if tagged.is_separated {
        let Some(resolved) = lv_index.resolve_column(&tagged.data, tagged.is_compressed, col_compressed, warnings)?
        else {
            return Ok(EseValue::Binary(tagged.data.clone()));
        };
        if resolved.unsupported_compression {
            return Ok(EseValue::Binary(resolved.bytes));
        }
        return Ok(decode_scalar(col, &resolved.bytes, resolved.is_utf16_expanded));
    }

    if tagged.is_compressed && !tagged.data.is_empty() {
        match decompress_ese_value(&tagged.data, warnings) {
            Ok(DecompressOutcome::Decompressed {
                bytes,
                is_utf16_expanded,
            }) => Ok(decode_scalar(col, &bytes, is_utf16_expanded)),
            Ok(DecompressOutcome::Unsupported { .. }) => Ok(EseValue::Binary(tagged.data.clone())),
            Err(err) => {
                warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Warn,
                    tool_id: "srum.db".to_string(),
                    source: format!("ESE column {}", col.name),
                    message: format!("decompression failed ({err}); preserving raw binary"),
                });
                Ok(EseValue::Binary(tagged.data.clone()))
            }
        }
    } else {
        Ok(decode_scalar(col, &tagged.data, false))
    }
}

fn decode_multi_value_bytes(
    col: &EseColumnSchema,
    raw_data: &[u8],
    is_two_values: bool,
    tagged_compressed: bool,
    lv_index: &LongValueIndex,
    warnings: &mut Vec<DiagnosticWarning>,
) -> Result<EseValue, ForensicError> {
    let slices: Vec<(&[u8], bool)> = if is_two_values {
        if raw_data.is_empty() {
            warnings.push(DiagnosticWarning {
                severity: WarningSeverity::Warn,
                tool_id: "srum.db".to_string(),
                source: format!("ESE column {}", col.name),
                message: "empty fTwoValues tagged field; preserving raw binary".to_string(),
            });
            return Ok(EseValue::Binary(Vec::new()));
        }
        let len0 = raw_data[0] as usize;
        if 1 + len0 > raw_data.len() {
            warnings.push(DiagnosticWarning {
                severity: WarningSeverity::Warn,
                tool_id: "srum.db".to_string(),
                source: format!("ESE column {}", col.name),
                message: format!(
                    "malformed fTwoValues first length {len0} (len {}); preserving raw binary",
                    raw_data.len()
                ),
            });
            return Ok(EseValue::Binary(raw_data.to_vec()));
        }
        vec![(&raw_data[1..1 + len0], false), (&raw_data[1 + len0..], false)]
    } else {
        if raw_data.len() < 2 {
            warnings.push(DiagnosticWarning {
                severity: WarningSeverity::Warn,
                tool_id: "srum.db".to_string(),
                source: format!("ESE column {}", col.name),
                message: format!(
                    "truncated multi-value offset header ({} bytes); preserving raw binary",
                    raw_data.len()
                ),
            });
            return Ok(EseValue::Binary(raw_data.to_vec()));
        }
        let off0 = (u16::from_le_bytes([raw_data[0], raw_data[1]]) & 0x7FFF) as usize;
        if off0 < 2 || !off0.is_multiple_of(2) || off0 > raw_data.len() {
            warnings.push(DiagnosticWarning {
                severity: WarningSeverity::Warn,
                tool_id: "srum.db".to_string(),
                source: format!("ESE column {}", col.name),
                message: format!(
                    "invalid multi-value first offset {off0} (len {}); preserving raw binary",
                    raw_data.len()
                ),
            });
            return Ok(EseValue::Binary(raw_data.to_vec()));
        }
        let count = off0 / 2;
        let mut offsets: Vec<(usize, bool)> = Vec::with_capacity(count);
        let mut prev_off = off0;
        for i in 0..count {
            let raw_off = u16::from_le_bytes([raw_data[i * 2], raw_data[i * 2 + 1]]);
            let off = (raw_off & 0x7FFF) as usize;
            let is_elem_separated = (raw_off & 0x8000) != 0;
            if off < prev_off || off > raw_data.len() {
                warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Warn,
                    tool_id: "srum.db".to_string(),
                    source: format!("ESE column {}", col.name),
                    message: format!(
                        "malformed multi-value offset[{i}]={off} (prev={prev_off}, len={}); preserving raw binary",
                        raw_data.len()
                    ),
                });
                return Ok(EseValue::Binary(raw_data.to_vec()));
            }
            offsets.push((off, is_elem_separated));
            prev_off = off;
        }
        let mut elems = Vec::with_capacity(count);
        for i in 0..count {
            let (start, is_elem_separated) = offsets[i];
            let end = if i + 1 < count {
                offsets[i + 1].0
            } else {
                raw_data.len()
            };
            elems.push((&raw_data[start..end], is_elem_separated));
        }
        elems
    };

    let col_compressed = (col.flags & 0x1000) != 0;

    let mut decoded_values: Vec<EseValue> = Vec::with_capacity(slices.len());
    for (elem_index, (elem, elem_is_separated)) in slices.into_iter().enumerate() {
        if elem.is_empty() {
            continue;
        }
        if elem_is_separated {
            let Some(resolved) = lv_index.resolve_column(elem, false, col_compressed, warnings)? else {
                decoded_values.push(EseValue::Binary(elem.to_vec()));
                continue;
            };
            if resolved.unsupported_compression {
                decoded_values.push(EseValue::Binary(resolved.bytes));
                continue;
            }
            if resolved.bytes.is_empty() {
                continue;
            }
            let val = decode_scalar(col, &resolved.bytes, resolved.is_utf16_expanded);
            if !matches!(val, EseValue::Null) {
                decoded_values.push(val);
            }
            continue;
        }

        // In ESENT inline multi-value (`fMultiValues` / `fTwoValues`) fields:
        // - When `tagged.is_compressed == false`, NO inline element is compressed (stored raw without `0x01` wrappers).
        // - Even when `tagged.is_compressed == true`, ONLY `elem[0]` is compressed; `elem[1+]` are stored raw without `0x01` wrappers.
        let allow_inline_decompress = tagged_compressed && elem_index == 0;
        let mut decompressed_buf: Option<Vec<u8>> = None;
        let mut is_utf16_expanded = false;

        let is_raw_utf16_ctrl_header = col.codepage == 1200
            && elem.len() >= 2
            && elem.len().is_multiple_of(2)
            && elem[1] == 0x00
            && (elem[0] == 0x01 || matches!(elem[0] & 0xF8, 0x08 | 0x10));

        if allow_inline_decompress && is_known_ese_compression_header(elem[0]) && !is_raw_utf16_ctrl_header {
            match decompress_ese_value(elem, warnings) {
                Ok(DecompressOutcome::Decompressed {
                    bytes,
                    is_utf16_expanded: expanded,
                }) => {
                    decompressed_buf = Some(bytes);
                    is_utf16_expanded = expanded;
                }
                Ok(DecompressOutcome::Unsupported { .. }) => {}
                Err(err) => {
                    let looks_like_raw_utf16 =
                        col.codepage == 1200 && elem.len() >= 2 && elem.len().is_multiple_of(2) && elem[1] == 0x00;
                    if !looks_like_raw_utf16 {
                        warnings.push(DiagnosticWarning {
                            severity: WarningSeverity::Warn,
                            tool_id: "srum.db".to_string(),
                            source: format!("ESE column {}", col.name),
                            message: format!(
                                "multi-value element decompression failed ({err}); preserving raw element"
                            ),
                        });
                    }
                }
            }
        }

        let elem_bytes = decompressed_buf.as_deref().unwrap_or(elem);
        if elem_bytes.is_empty() {
            continue;
        }
        let val = decode_scalar(col, elem_bytes, is_utf16_expanded);
        if !matches!(val, EseValue::Null) {
            decoded_values.push(val);
        }
    }

    match decoded_values.len() {
        0 => Ok(EseValue::Null),
        1 => Ok(decoded_values.into_iter().next().unwrap_or(EseValue::Null)),
        _ => {
            let joined = decoded_values
                .iter()
                .map(EseValue::display_compact)
                .collect::<Vec<_>>()
                .join("; ");
            Ok(EseValue::Text(joined))
        }
    }
}

fn decode_scalar(col: &EseColumnSchema, bytes: &[u8], force_utf16: bool) -> EseValue {
    match col.col_type {
        JetColType::Nil => EseValue::Null,
        JetColType::Bit => bytes.first().map_or(EseValue::Null, |&b| EseValue::Bool(b != 0)),
        JetColType::UnsignedByte => bytes.first().map_or(EseValue::Null, |&b| EseValue::U8(b)),
        JetColType::Short => {
            if bytes.len() >= 2 {
                EseValue::I16(i16::from_le_bytes([bytes[0], bytes[1]]))
            } else {
                EseValue::Binary(bytes.to_vec())
            }
        }
        JetColType::UnsignedShort => {
            if bytes.len() >= 2 {
                EseValue::U16(u16::from_le_bytes([bytes[0], bytes[1]]))
            } else {
                EseValue::Binary(bytes.to_vec())
            }
        }
        JetColType::Long => {
            if bytes.len() >= 4 {
                EseValue::I32(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            } else {
                EseValue::Binary(bytes.to_vec())
            }
        }
        JetColType::UnsignedLong => {
            if bytes.len() >= 4 {
                EseValue::U32(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            } else {
                EseValue::Binary(bytes.to_vec())
            }
        }
        JetColType::Currency | JetColType::LongLong => {
            if bytes.len() >= 8 {
                EseValue::I64(i64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8])))
            } else {
                EseValue::Binary(bytes.to_vec())
            }
        }
        JetColType::Single => {
            if bytes.len() >= 4 {
                EseValue::F32(f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            } else {
                EseValue::Binary(bytes.to_vec())
            }
        }
        JetColType::Double => {
            if bytes.len() >= 8 {
                EseValue::F64(f64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8])))
            } else {
                EseValue::Binary(bytes.to_vec())
            }
        }
        JetColType::DateTime => {
            if bytes.len() >= 8 {
                let raw_f64 = f64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]));
                if raw_f64 == 0.0 {
                    EseValue::Null
                } else if let Some(dt) = ole_automation_date_to_utc(raw_f64) {
                    EseValue::DateTime(dt)
                } else {
                    EseValue::F64(raw_f64)
                }
            } else {
                EseValue::Binary(bytes.to_vec())
            }
        }
        JetColType::Text | JetColType::LongText => EseValue::Text(decode_ese_text(bytes, col.codepage, force_utf16)),
        JetColType::Binary | JetColType::LongBinary | JetColType::Slv | JetColType::Unknown(_) => {
            EseValue::Binary(bytes.to_vec())
        }
        JetColType::Guid => {
            parse_guid_le_braced(bytes).map_or_else(|_| EseValue::Binary(bytes.to_vec()), EseValue::Guid)
        }
    }
}
