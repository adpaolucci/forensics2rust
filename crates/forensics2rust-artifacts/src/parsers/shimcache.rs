#![forbid(unsafe_code)]

//! Pure-Rust Windows `AppCompatCache` (ShimCache) binary parser supporting
//! Windows 7 (`0xBADC0FEE` 32/64-bit), Windows 8/8.1 (`0x80` + `00ts`/`10ts`),
//! and Windows 10/11 (`0x30`/`0x34` + `10ts`, including AppX entries).

use chrono::{DateTime, Utc};
use forensics2rust_core::{ForensicError, filetime_to_utc, read_utf16_le, read_utf16_le_nul};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShimCacheEntry {
    pub path: String,
    pub last_modified: Option<DateTime<Utc>>,
    pub exec_flag: Option<bool>,
    pub order_index: usize,
    pub format: String,
}

fn read_u16_le(b: &[u8], off: usize) -> Result<u16, ForensicError> {
    let s = off
        .checked_add(2)
        .and_then(|end| b.get(off..end))
        .ok_or_else(|| ForensicError::parse("ShimCache", format!("truncated u16 at 0x{off:X}")))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32_le(b: &[u8], off: usize) -> Result<u32, ForensicError> {
    let s = off
        .checked_add(4)
        .and_then(|end| b.get(off..end))
        .ok_or_else(|| ForensicError::parse("ShimCache", format!("truncated u32 at 0x{off:X}")))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64_le(b: &[u8], off: usize) -> Result<u64, ForensicError> {
    let s = off
        .checked_add(8)
        .and_then(|end| b.get(off..end))
        .ok_or_else(|| ForensicError::parse("ShimCache", format!("truncated u64 at 0x{off:X}")))?;
    Ok(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

pub fn parse_shimcache(bytes: &[u8]) -> Result<Vec<ShimCacheEntry>, ForensicError> {
    if bytes.len() < 8 {
        return Err(ForensicError::parse(
            "ShimCache",
            format!("buffer too short ({} bytes)", bytes.len()),
        ));
    }

    let sig = read_u32_le(bytes, 0)?;
    match sig {
        0x0000_0030 | 0x0000_0034 => parse_win10_11(bytes, sig as usize),
        0x0000_0080 => parse_win8(bytes),
        0xBADC_0FEE => parse_win7(bytes),
        other => Err(ForensicError::parse(
            "ShimCache",
            format!("unrecognized AppCompatCache signature 0x{other:08X}"),
        )),
    }
}

fn clean_shim_path(raw: String) -> String {
    let trimmed = raw.trim_end_matches('\0').trim();
    if let Some(rest) = trimmed.strip_prefix("\\??\\") {
        rest.to_string()
    } else if let Some(rest) = trimmed.strip_prefix("SYSVOL\\") {
        format!("C:\\Windows\\{rest}")
    } else {
        trimmed.to_string()
    }
}

fn parse_win10_11(bytes: &[u8], header_size: usize) -> Result<Vec<ShimCacheEntry>, ForensicError> {
    if bytes.len() < header_size {
        return Err(ForensicError::parse("ShimCache", "truncated Win10/11 header"));
    }
    let mut entries = Vec::new();
    let mut pos = header_size;
    let mut idx = 0usize;

    while pos.checked_add(14).is_some_and(|end| end <= bytes.len()) {
        let tag = &bytes[pos..pos + 4];
        if tag != b"10ts" {
            break;
        }
        let entry_data_size = read_u32_le(bytes, pos + 8)? as usize;
        let Some(entry_end) = entry_data_size.checked_add(12).and_then(|t| pos.checked_add(t)) else {
            return Err(ForensicError::parse(
                "ShimCache",
                format!("invalid 10ts entry size {entry_data_size} at 0x{pos:X}"),
            ));
        };
        if entry_data_size < 14 || entry_end > bytes.len() {
            return Err(ForensicError::parse(
                "ShimCache",
                format!("invalid 10ts entry size {entry_data_size} at 0x{pos:X}"),
            ));
        }

        let path_len = read_u16_le(bytes, pos + 12)? as usize;
        let path_start = pos + 14;
        let Some(path_end) = path_start.checked_add(path_len) else {
            return Err(ForensicError::parse(
                "ShimCache",
                format!("10ts path length {path_len} exceeds entry bounds at 0x{pos:X}"),
            ));
        };
        if path_end.checked_add(8).is_none_or(|end| end > entry_end) {
            return Err(ForensicError::parse(
                "ShimCache",
                format!("10ts path length {path_len} exceeds entry bounds at 0x{pos:X}"),
            ));
        }
        let raw_path = read_utf16_le_nul(&bytes[path_start..path_end]);
        let last_modified = filetime_to_utc(read_u64_le(bytes, path_end)?);

        let clean = clean_shim_path(raw_path);
        if !clean.is_empty() {
            entries.push(ShimCacheEntry {
                path: clean,
                last_modified,
                exec_flag: None,
                order_index: idx,
                format: "Win10/11 (10ts)".to_string(),
            });
            idx += 1;
        }
        pos = entry_end;
    }

    Ok(entries)
}

fn parse_win8(bytes: &[u8]) -> Result<Vec<ShimCacheEntry>, ForensicError> {
    if bytes.len() < 0x80 {
        return Err(ForensicError::parse("ShimCache", "truncated Win8 header"));
    }
    let mut entries = Vec::new();
    let mut pos = 0x80usize;
    let mut idx = 0usize;

    while pos.checked_add(14).is_some_and(|end| end <= bytes.len()) {
        let tag = &bytes[pos..pos + 4];
        if tag != b"00ts" && tag != b"10ts" {
            break;
        }
        let entry_data_size = read_u32_le(bytes, pos + 8)? as usize;
        let Some(entry_end) = entry_data_size.checked_add(12).and_then(|t| pos.checked_add(t)) else {
            return Err(ForensicError::parse(
                "ShimCache",
                format!("invalid Win8 entry size {entry_data_size} at 0x{pos:X}"),
            ));
        };
        if entry_data_size < 14 || entry_end > bytes.len() {
            return Err(ForensicError::parse(
                "ShimCache",
                format!("invalid Win8 entry size {entry_data_size} at 0x{pos:X}"),
            ));
        }

        let path_len = read_u16_le(bytes, pos + 12)? as usize;
        let path_start = pos + 14;
        let Some(path_end) = path_start.checked_add(path_len) else {
            return Err(ForensicError::parse("ShimCache", "Win8 path exceeds entry bounds"));
        };
        if path_end > entry_end {
            return Err(ForensicError::parse("ShimCache", "Win8 path exceeds entry bounds"));
        }
        let raw_path = read_utf16_le_nul(&bytes[path_start..path_end]);

        let (last_modified, exec_flag) = if tag == b"10ts" {
            let lm = if path_end.checked_add(8).is_some_and(|end| end <= entry_end) {
                filetime_to_utc(read_u64_le(bytes, path_end)?)
            } else {
                None
            };
            (lm, None)
        } else {
            // 00ts: path, u16 pkg_len, pkg, u32 insert_flags, u32 shim_flags, u64 filetime
            let mut cursor = path_end;
            if cursor.checked_add(2).is_some_and(|end| end <= entry_end) {
                let pkg_len = read_u16_le(bytes, cursor)? as usize;
                cursor = cursor.saturating_add(2).saturating_add(pkg_len);
            }
            if cursor.checked_add(16).is_some_and(|end| end <= entry_end) {
                let insert_flags = read_u32_le(bytes, cursor)?;
                let ft = read_u64_le(bytes, cursor + 8)?;
                (filetime_to_utc(ft), Some((insert_flags & 0x02) != 0))
            } else {
                (None, None)
            }
        };

        let clean = clean_shim_path(raw_path);
        if !clean.is_empty() {
            entries.push(ShimCacheEntry {
                path: clean,
                last_modified,
                exec_flag,
                order_index: idx,
                format: format!("Win8 ({})", String::from_utf8_lossy(tag)),
            });
            idx += 1;
        }
        pos = entry_end;
    }

    Ok(entries)
}

fn parse_win7(bytes: &[u8]) -> Result<Vec<ShimCacheEntry>, ForensicError> {
    if bytes.len() < 0x80 {
        return Err(ForensicError::parse("ShimCache", "truncated Win7 header"));
    }
    let entry_count = (read_u32_le(bytes, 4)? as usize).min(4096);
    if entry_count == 0 {
        return Ok(Vec::new());
    }

    // Detect 64-bit (48-byte entries) vs 32-bit (32-byte entries) by checking path_off/len
    let is_64bit = if bytes.len() >= 0x80 + 48 {
        let len64 = read_u16_le(bytes, 0x80)? as usize;
        let max64 = read_u16_le(bytes, 0x82)? as usize;
        let pad64 = read_u32_le(bytes, 0x84)?;
        let off64_raw = read_u64_le(bytes, 0x88)?;
        pad64 == 0
            && len64 > 0
            && len64 <= max64
            && usize::try_from(off64_raw)
                .ok()
                .is_some_and(|off64| off64 >= 0x80 && off64.checked_add(len64).is_some_and(|end| end <= bytes.len()))
    } else {
        false
    };

    let entry_size = if is_64bit { 48usize } else { 32usize };
    let mut entries = Vec::with_capacity(entry_count);

    for i in 0..entry_count {
        let Some(off) = i.checked_mul(entry_size).and_then(|d| 0x80usize.checked_add(d)) else {
            break;
        };
        if off.checked_add(entry_size).is_none_or(|end| end > bytes.len()) {
            break;
        }
        let path_len = read_u16_le(bytes, off)? as usize;
        let (path_off_opt, ft, insert_flags) = if is_64bit {
            let p_off = usize::try_from(read_u64_le(bytes, off + 8)?).ok();
            let ft = read_u64_le(bytes, off + 16)?;
            let ins = read_u32_le(bytes, off + 24)?;
            (p_off, ft, ins)
        } else {
            let p_off = Some(read_u32_le(bytes, off + 4)? as usize);
            let ft = read_u64_le(bytes, off + 8)?;
            let ins = read_u32_le(bytes, off + 16)?;
            (p_off, ft, ins)
        };

        if path_len > 0
            && let Some(path_off) = path_off_opt
            && let Some(path_slice) = bytes.get(path_off..).and_then(|s| s.get(..path_len))
        {
            let raw_path = read_utf16_le(path_slice);
            let clean = clean_shim_path(raw_path);
            if !clean.is_empty() {
                entries.push(ShimCacheEntry {
                    path: clean,
                    last_modified: filetime_to_utc(ft),
                    exec_flag: Some((insert_flags & 0x02) != 0),
                    order_index: i,
                    format: if is_64bit {
                        "Win7x64 (0xBADC0FEE)".to_string()
                    } else {
                        "Win7x86 (0xBADC0FEE)".to_string()
                    },
                });
            }
        }
    }

    Ok(entries)
}
