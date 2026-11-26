use std::fmt::Write as _;

use chrono::{DateTime, Utc};

use crate::error::ForensicError;

/// Seconds between Windows epoch (`1601-01-01T00:00:00Z`) and Unix epoch (`1970-01-01T00:00:00Z`).
pub const WINDOWS_EPOCH_OFFSET_SECS: i64 = 11_644_473_600;

/// 100-nanosecond ticks between Windows epoch (`1601-01-01T00:00:00Z`) and Unix epoch (`1970-01-01T00:00:00Z`).
pub const WINDOWS_EPOCH_OFFSET_100NS: u64 = 116_444_736_000_000_000;

/// Seconds between OLE Automation epoch (`1899-12-30T00:00:00Z`) and Unix epoch (`1970-01-01T00:00:00Z`).
const OLE_EPOCH_UNIX_SECS: i128 = -2_209_161_600;

const fn build_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

const CRC32_TABLE: [u32; 256] = build_crc32_table();

/// Converts a Windows `FILETIME` (100ns ticks since `1601-01-01T00:00:00Z`) to `DateTime<Utc>`.
///
/// Supports pre-1970 timestamps down to `ft = 1` (`1601-01-01T00:00:00.000000100Z`).
/// Returns `None` for `ft == 0` (unset) or values above `i64::MAX as u64` (Windows sentinel/overflow).
pub fn filetime_to_utc(ft: u64) -> Option<DateTime<Utc>> {
    if ft == 0 || ft > i64::MAX as u64 {
        return None;
    }
    let delta_100ns = (ft as i128) - (WINDOWS_EPOCH_OFFSET_100NS as i128);
    let secs = i64::try_from(delta_100ns.div_euclid(10_000_000)).ok()?;
    let nanos = (delta_100ns.rem_euclid(10_000_000) * 100) as u32;
    DateTime::from_timestamp(secs, nanos)
}

/// Converts a `DateTime<Utc>` back to Windows `FILETIME` (100ns ticks since `1601-01-01T00:00:00Z`).
///
/// Returns `None` if the timestamp precedes `1601-01-01T00:00:00Z` or exceeds `i64::MAX` ticks.
pub fn utc_to_filetime(dt: DateTime<Utc>) -> Option<u64> {
    let secs = i128::from(dt.timestamp());
    let nanos = i128::from(dt.timestamp_subsec_nanos());
    let total_100ns = secs * 10_000_000 + (nanos / 100) + i128::from(WINDOWS_EPOCH_OFFSET_100NS);
    if total_100ns < 0 || total_100ns > i128::from(i64::MAX) {
        return None;
    }
    Some(total_100ns as u64)
}

/// Converts a Windows OLE Automation `DATE` (`f64` days since `1899-12-30T00:00:00Z`,
/// commonly used in ESE/SRUM tables) to `DateTime<Utc>`.
///
/// Follows `[MS-OAUT]` §2.2.25 semantics: the integral part is the signed day offset from
/// `1899-12-30`, while the fractional part (`days.fract().abs()`) is always a non-negative
/// time-of-day offset added forward from midnight of that day (e.g., `-0.5` decodes to
/// `1899-12-30T12:00:00Z`, and `-1.5` decodes to `1899-12-29T12:00:00Z`).
///
/// Returns `None` for non-finite values (`NaN`, `INFINITY`) or out-of-range day counts.
pub fn ole_automation_date_to_utc(days: f64) -> Option<DateTime<Utc>> {
    if !days.is_finite() || days.abs() > 3_652_059.0 {
        return None;
    }
    let whole_days = days.trunc() as i128;
    let frac_days = days.fract().abs();
    let frac_ns = (frac_days * 86_400_000_000_000.0).round() as i128;
    let total_ns = (OLE_EPOCH_UNIX_SECS + whole_days * 86_400) * 1_000_000_000 + frac_ns;
    let secs = i64::try_from(total_ns.div_euclid(1_000_000_000)).ok()?;
    let nanos = total_ns.rem_euclid(1_000_000_000) as u32;
    DateTime::from_timestamp(secs, nanos)
}

/// Parses a `[MS-DTYP]` §2.4.2 binary Windows SID into canonical `S-1-<auth>-<sub...>` text.
pub fn parse_sid(bytes: &[u8]) -> Result<String, ForensicError> {
    if bytes.len() < 8 {
        return Err(ForensicError::parse(
            "SID",
            format!("buffer too short ({} bytes, minimum 8)", bytes.len()),
        ));
    }
    let revision = bytes[0];
    if revision != 1 {
        return Err(ForensicError::parse(
            "SID",
            format!("unsupported SID revision {revision} (expected 1)"),
        ));
    }
    let sub_count = usize::from(bytes[1]);
    if sub_count > 15 {
        return Err(ForensicError::parse(
            "SID",
            format!("subauthority count {sub_count} exceeds maximum 15"),
        ));
    }
    let required_len = 8 + sub_count * 4;
    if bytes.len() < required_len {
        return Err(ForensicError::parse(
            "SID",
            format!(
                "truncated SID buffer ({} bytes, need {} for {sub_count} subauthorities)",
                bytes.len(),
                required_len
            ),
        ));
    }

    let mut authority: u64 = 0;
    for &b in &bytes[2..8] {
        authority = (authority << 8) | u64::from(b);
    }

    let mut out = String::with_capacity(16 + sub_count * 11);
    if authority <= u64::from(u32::MAX) {
        let _ = write!(out, "S-1-{authority}");
    } else {
        let _ = write!(out, "S-1-0x{authority:x}");
    }

    for chunk in bytes[8..required_len].as_chunks::<4>().0 {
        let sub = u32::from_le_bytes(*chunk);
        let _ = write!(out, "-{sub}");
    }
    Ok(out)
}

/// Parses a 16-byte mixed-endian Windows GUID (`[MS-DTYP]` §2.3.4) into lowercase
/// hyphenated RFC 4122 text (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`).
pub fn parse_guid_le(bytes: &[u8]) -> Result<String, ForensicError> {
    if bytes.len() < 16 {
        return Err(ForensicError::parse(
            "GUID",
            format!("buffer too short ({} bytes, need 16)", bytes.len()),
        ));
    }
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    Ok(format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    ))
}

/// Parses a 16-byte mixed-endian Windows GUID into braced `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` form.
pub fn parse_guid_le_braced(bytes: &[u8]) -> Result<String, ForensicError> {
    let inner = parse_guid_le(bytes)?;
    Ok(format!("{{{inner}}}"))
}

/// Tolerantly decodes a UTF-16LE byte slice (ignoring any trailing odd byte and
/// replacing unpaired surrogates with U+FFFD).
pub fn read_utf16_le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Tolerantly decodes a NUL-terminated UTF-16LE byte slice, stopping at the first `0x0000`
/// code unit (ignoring any trailing odd byte and replacing unpaired surrogates with U+FFFD).
pub fn read_utf16_le_nul(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Strictly decodes a UTF-16LE byte slice, returning `ForensicError::Parse` on odd
/// byte lengths or unpaired UTF-16 surrogates.
pub fn try_read_utf16_le(bytes: &[u8]) -> Result<String, ForensicError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(ForensicError::parse(
            "UTF-16LE",
            format!("odd byte length ({}) cannot be valid UTF-16LE", bytes.len()),
        ));
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16(&units).map_err(|err| ForensicError::parse("UTF-16LE", err.to_string()))
}

/// Computes the IEEE 802.3 CRC-32 checksum using a pure-Rust `const` 256-entry lookup table.
pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        let idx = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[idx];
    }
    !crc
}

/// Encodes a byte slice as lowercase hexadecimal (`000fabff`).
pub fn bytes_to_hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Applies ASCII ROT13 substitution (used by Windows `UserAssist` Registry keys),
/// leaving non-ASCII and non-alphabetic characters unchanged.
pub fn rot13(input: &str) -> String {
    input
        .chars()
        .map(|ch| match ch {
            'a'..='m' | 'A'..='M' => ((ch as u8) + 13) as char,
            'n'..='z' | 'N'..='Z' => ((ch as u8) - 13) as char,
            other => other,
        })
        .collect()
}
