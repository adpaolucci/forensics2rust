#![forbid(unsafe_code)]

//! Pure-Rust Windows `SHITEMID` / `ITEMIDLIST` (PIDL) binary decoder shared by
//! `ShellBagsView`, `OpenSaveFilesView`, and `[MS-SHLLINK]` `.lnk` parsing.

use chrono::{DateTime, NaiveDate, Utc};
use forensics2rust_core::{filetime_to_utc, parse_guid_le_braced, read_utf16_le_nul};
use serde::{Deserialize, Serialize};

const MAX_PIDL_ITEMS: usize = 256;
const MAX_DELEGATE_DEPTH: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShellItemKind {
    RootFolder,
    Volume,
    Directory,
    File,
    Network,
    Delegate,
    ControlPanel,
    Uri,
    PropertyStore,
    Unknown(u8),
}

impl ShellItemKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RootFolder => "RootFolder",
            Self::Volume => "Volume",
            Self::Directory => "Directory",
            Self::File => "File",
            Self::Network => "Network",
            Self::Delegate => "Delegate",
            Self::ControlPanel => "ControlPanel",
            Self::Uri => "Uri",
            Self::PropertyStore => "PropertyStore",
            Self::Unknown(_) => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedShellItem {
    pub type_byte: u8,
    pub kind: ShellItemKind,
    pub name: String,
    pub short_name: Option<String>,
    pub file_size: Option<u32>,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    pub mft_entry: Option<String>,
    pub guid: Option<String>,
    pub raw_len: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedPidl {
    pub items: Vec<DecodedShellItem>,
    pub diagnostics: Vec<String>,
}

/// Decodes an MS-DOS packed date + time pair (`dos_date`, `dos_time`) into UTC.
pub fn dos_datetime_to_utc(dos_date: u16, dos_time: u16) -> Option<DateTime<Utc>> {
    if dos_date == 0 && dos_time == 0 {
        return None;
    }
    let day = u32::from(dos_date & 0x1F);
    let month = u32::from((dos_date >> 5) & 0x0F);
    let year = i32::from((dos_date >> 9) & 0x7F) + 1980;
    let sec = u32::from((dos_time & 0x1F) * 2);
    let min = u32::from((dos_time >> 5) & 0x3F);
    let hour = u32::from((dos_time >> 11) & 0x1F);
    NaiveDate::from_ymd_opt(year, month, day)?
        .and_hms_opt(hour, min, sec)
        .map(|ndt| ndt.and_utc())
}

pub fn known_folder_guid_name(guid: &str) -> Option<&'static str> {
    match guid.to_ascii_uppercase().as_str() {
        "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" => Some("This PC"),
        "{59031A47-3F72-44A7-89C5-5595FE6B30EE}" => Some("User Files"),
        "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" => Some("Network"),
        "{645FF040-5081-101B-9F08-00AA002F954E}" => Some("Recycle Bin"),
        "{031E4825-7B94-4DC3-B131-E946B44C8DD5}" => Some("Libraries"),
        "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" => Some("Desktop"),
        "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}" => Some("Documents"),
        "{374DE290-123F-4565-9164-39C4925E467B}" => Some("Downloads"),
        "{018D5C66-4533-4307-9B53-224DE2ED1FE6}" => Some("OneDrive"),
        "{21EC2020-3AEA-1069-A2DD-08002B30309D}" => Some("Control Panel"),
        "{450D8FBA-AD25-11D0-98A8-0800361B1103}" => Some("My Documents"),
        "{208D2C60-3AEA-1069-A2D7-08002B30309D}" => Some("My Network Places"),
        "{871C5380-42A0-1069-A2EA-08002B30309D}" => Some("Internet Explorer"),
        _ => None,
    }
}

/// Decodes a `SHITEMID` / `ITEMIDLIST` buffer (one or more items, optionally terminated by `0x0000`).
pub fn parse_pidl(buf: &[u8]) -> DecodedPidl {
    parse_pidl_depth(buf, 0)
}

fn parse_pidl_depth(buf: &[u8], depth: usize) -> DecodedPidl {
    let mut items = Vec::new();
    let mut diagnostics = Vec::new();
    let mut off = 0usize;

    while off + 2 <= buf.len() && items.len() < MAX_PIDL_ITEMS {
        let cb = u16::from_le_bytes([buf[off], buf[off + 1]]) as usize;
        if cb == 0 {
            break;
        }
        if cb < 3 || off + cb > buf.len() {
            diagnostics.push(format!(
                "truncated or invalid SHITEMID length {cb} at offset {off} (buf len {})",
                buf.len()
            ));
            break;
        }
        let item = &buf[off..off + cb];
        let body = &item[2..];
        items.push(decode_single_shell_item(item, body, depth));
        off += cb;
    }

    DecodedPidl { items, diagnostics }
}

/// Decodes a single `SHITEMID` buffer (used for single `BagMRU` registry values that may or may not
/// include the trailing `0x0000` terminator).
pub fn parse_single_item(buf: &[u8]) -> Option<DecodedShellItem> {
    parse_pidl(buf).items.into_iter().next()
}

fn decode_ascii_nul(bytes: &[u8]) -> (String, usize) {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let text: String = bytes[..end]
        .iter()
        .map(|&b| if b >= 0x20 || b == b'\t' { b as char } else { '?' })
        .collect();
    let consumed = if end < bytes.len() { end + 1 } else { end };
    (text, consumed)
}

fn decode_utf16_nul_consumed(bytes: &[u8]) -> (String, usize) {
    let mut units = Vec::new();
    let mut i = 0usize;
    while i + 2 <= bytes.len() {
        let u = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        i += 2;
        if u == 0 {
            break;
        }
        units.push(u);
    }
    (String::from_utf16_lossy(&units), i)
}

fn extract_1sps_props(bytes: &[u8]) -> (Option<String>, Option<DateTime<Utc>>) {
    let mut best_name: Option<String> = None;
    let mut best_time: Option<DateTime<Utc>> = None;

    let mut pos = 0usize;
    while pos + 24 <= bytes.len() {
        if &bytes[pos + 4..pos + 8] == b"1SPS" {
            let block_size = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]) as usize;
            let block_end = if block_size >= 24 && pos + block_size <= bytes.len() {
                pos + block_size
            } else {
                bytes.len()
            };
            let mut p = pos + 24;
            while p + 9 <= block_end {
                let val_size = u32::from_le_bytes([bytes[p], bytes[p + 1], bytes[p + 2], bytes[p + 3]]) as usize;
                if val_size == 0 {
                    break;
                }
                if val_size < 13 || p + val_size > block_end {
                    break;
                }
                let pid = u32::from_le_bytes([bytes[p + 4], bytes[p + 5], bytes[p + 6], bytes[p + 7]]);
                let vt_type = u32::from_le_bytes([bytes[p + 9], bytes[p + 10], bytes[p + 11], bytes[p + 12]]);
                let val_data = &bytes[p + 13..p + val_size];
                if vt_type == 31 && val_data.len() >= 4 {
                    // VT_LPWSTR: u32 char count + UTF-16LE
                    let char_cnt = u32::from_le_bytes([val_data[0], val_data[1], val_data[2], val_data[3]]) as usize;
                    let str_bytes = &val_data[4..];
                    let take = char_cnt.saturating_mul(2).min(str_bytes.len());
                    let s = read_utf16_le_nul(&str_bytes[..take]);
                    if !s.is_empty() && (best_name.is_none() || pid == 10 || pid == 30) {
                        best_name = Some(s);
                    }
                } else if vt_type == 64 && val_data.len() >= 8 && best_time.is_none() {
                    let ft = u64::from_le_bytes([
                        val_data[0],
                        val_data[1],
                        val_data[2],
                        val_data[3],
                        val_data[4],
                        val_data[5],
                        val_data[6],
                        val_data[7],
                    ]);
                    best_time = filetime_to_utc(ft);
                }
                p += val_size;
            }
            pos = block_end;
        } else {
            pos += 1;
        }
    }

    (best_name, best_time)
}

fn find_readable_utf16_hint(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 6 {
        return None;
    }
    for start in (0..bytes.len().saturating_sub(4)).step_by(2) {
        let mut units = Vec::new();
        let mut i = start;
        while i + 2 <= bytes.len() {
            let u = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
            if u == 0 {
                break;
            }
            if !(0x0020..=0x007E).contains(&u) && !(0x00A0..=0xFFFD).contains(&u) {
                units.clear();
                break;
            }
            units.push(u);
            i += 2;
        }
        if units.len() >= 2 && i + 2 <= bytes.len() && u16::from_le_bytes([bytes[i], bytes[i + 1]]) == 0 {
            let s = String::from_utf16_lossy(&units);
            if s.chars().any(|c| c.is_alphanumeric()) {
                return Some(s);
            }
        }
    }
    None
}

fn decode_single_shell_item(raw_item: &[u8], body: &[u8], depth: usize) -> DecodedShellItem {
    let type_byte = body[0];
    let raw_len = raw_item.len();

    // Check CFSF Delegate wrapper (`0x74` or `0x00` with `b"CFSF"` at `body[4..8]`)
    if (type_byte == 0x74 || type_byte == 0x00) && body.len() >= 8 && &body[4..8] == b"CFSF" {
        let inner_size = u16::from_le_bytes([body[2], body[3]]) as usize;
        if inner_size >= 3 && 8 + inner_size <= body.len() && depth < MAX_DELEGATE_DEPTH {
            let inner = parse_pidl_depth(&body[8..8 + inner_size], depth + 1);
            if let Some(first) = inner.items.into_iter().next() {
                return DecodedShellItem {
                    type_byte,
                    kind: ShellItemKind::Delegate,
                    raw_len,
                    ..first
                };
            }
        }
        let (prop_name, prop_time) = extract_1sps_props(body);
        return DecodedShellItem {
            type_byte,
            kind: ShellItemKind::Delegate,
            name: prop_name.unwrap_or_else(|| format!("[Delegate 0x{type_byte:02x}]")),
            short_name: None,
            file_size: None,
            created: None,
            modified: prop_time,
            accessed: None,
            mft_entry: None,
            guid: None,
            raw_len,
        };
    }

    match type_byte {
        0x1F => {
            let guid = if body.len() >= 18 {
                parse_guid_le_braced(&body[2..18]).ok()
            } else {
                None
            };
            let (prop_name, prop_time) = extract_1sps_props(body);
            let name = prop_name
                .or_else(|| guid.as_deref().and_then(known_folder_guid_name).map(str::to_string))
                .or_else(|| guid.clone())
                .unwrap_or_else(|| "[RootFolder]".to_string());
            DecodedShellItem {
                type_byte,
                kind: ShellItemKind::RootFolder,
                name,
                short_name: None,
                file_size: None,
                created: None,
                modified: prop_time,
                accessed: None,
                mft_entry: None,
                guid,
                raw_len,
            }
        }
        0x20..=0x2F => {
            let mut guid = None;
            let name = if type_byte == 0x2F && body.len() > 1 {
                let (s, _) = decode_ascii_nul(&body[1..]);
                if s.is_empty() { "Drive".to_string() } else { s }
            } else if body.len() >= 18 {
                let (ascii, _) = decode_ascii_nul(&body[1..]);
                if ascii.starts_with("\\\\?\\Volume{") || ascii.starts_with("\\\\") {
                    ascii
                } else if let Ok(g) = parse_guid_le_braced(&body[2..18]) {
                    guid = Some(g.clone());
                    g
                } else {
                    ascii
                }
            } else if body.len() > 1 {
                let (s, _) = decode_ascii_nul(&body[1..]);
                s
            } else {
                format!("[Volume 0x{type_byte:02x}]")
            };
            DecodedShellItem {
                type_byte,
                kind: ShellItemKind::Volume,
                name,
                short_name: None,
                file_size: None,
                created: None,
                modified: None,
                accessed: None,
                mft_entry: None,
                guid,
                raw_len,
            }
        }
        0x30..=0x3F => {
            let kind = if (type_byte & 0x01) != 0 {
                ShellItemKind::Directory
            } else {
                ShellItemKind::File
            };
            if body.len() < 13 {
                return DecodedShellItem {
                    type_byte,
                    kind,
                    name: format!("[ShellItem 0x{type_byte:02x}]"),
                    short_name: None,
                    file_size: None,
                    created: None,
                    modified: None,
                    accessed: None,
                    mft_entry: None,
                    guid: None,
                    raw_len,
                };
            }

            let file_size = Some(u32::from_le_bytes([body[2], body[3], body[4], body[5]]));
            let mod_date = u16::from_le_bytes([body[6], body[7]]);
            let mod_time = u16::from_le_bytes([body[8], body[9]]);
            let modified = dos_datetime_to_utc(mod_date, mod_time);

            let name_slice = &body[12..];
            let (short_name_str, consumed) = if (type_byte & 0x04) != 0 {
                decode_utf16_nul_consumed(name_slice)
            } else {
                decode_ascii_nul(name_slice)
            };
            // Round up to 2-byte alignment after NUL
            let aligned_consumed = if !consumed.is_multiple_of(2) {
                consumed + 1
            } else {
                consumed
            };
            let ext = name_slice.get(aligned_consumed..).unwrap_or(&[]);

            let mut created = None;
            let mut accessed = None;
            let mut mft_entry = None;
            let mut long_name: Option<String> = None;

            if ext.len() >= 8 {
                let ext_size = u16::from_le_bytes([ext[0], ext[1]]) as usize;
                let ext_ver = u16::from_le_bytes([ext[2], ext[3]]);
                let ext_sig = u32::from_le_bytes([ext[4], ext[5], ext[6], ext[7]]);
                let ext_slice = if ext_size >= 8 && ext_size <= ext.len() {
                    &ext[..ext_size]
                } else {
                    ext
                };
                if ext_sig == 0xBEEF_0004 && ext_slice.len() >= 16 {
                    let c_date = u16::from_le_bytes([ext_slice[8], ext_slice[9]]);
                    let c_time = u16::from_le_bytes([ext_slice[10], ext_slice[11]]);
                    created = dos_datetime_to_utc(c_date, c_time);

                    let a_date = u16::from_le_bytes([ext_slice[12], ext_slice[13]]);
                    let a_time = u16::from_le_bytes([ext_slice[14], ext_slice[15]]);
                    accessed = dos_datetime_to_utc(a_date, a_time);

                    if ext_ver >= 0x0007 && ext_slice.len() >= 28 {
                        let raw_ref = u64::from_le_bytes([
                            ext_slice[20],
                            ext_slice[21],
                            ext_slice[22],
                            ext_slice[23],
                            ext_slice[24],
                            ext_slice[25],
                            ext_slice[26],
                            ext_slice[27],
                        ]);
                        if raw_ref != 0 {
                            let entry = raw_ref & 0x0000_FFFF_FFFF_FFFF;
                            let seq = (raw_ref >> 48) as u16;
                            mft_entry = Some(format!("{entry}-{seq}"));
                        }
                    }

                    let primary_name_off = match ext_ver {
                        0x0003 => 20usize,
                        0x0007 => 38usize,
                        0x0008 => 42usize,
                        _ => 46usize,
                    };
                    if primary_name_off + 2 <= ext_slice.len() {
                        let s = read_utf16_le_nul(&ext_slice[primary_name_off..]);
                        if !s.is_empty() {
                            long_name = Some(s);
                        }
                    }
                    if long_name.is_none() && ext_slice.len() > 22 {
                        long_name = find_readable_utf16_hint(&ext_slice[20..]);
                    }
                }
            }

            let short_opt = if short_name_str.is_empty() {
                None
            } else {
                Some(short_name_str.clone())
            };
            let display_name = long_name
                .or(short_opt.clone())
                .unwrap_or_else(|| format!("[File 0x{type_byte:02x}]"));

            DecodedShellItem {
                type_byte,
                kind,
                name: display_name,
                short_name: short_opt,
                file_size,
                created,
                modified,
                accessed,
                mft_entry,
                guid: None,
                raw_len,
            }
        }
        0x40..=0x4F => {
            let mut start = 2usize.min(body.len());
            while start < body.len() && start < 4 && (body[start] < 0x20 || body[start] == 0x80) {
                start += 1;
            }
            let (unc, _) = decode_ascii_nul(body.get(start..).unwrap_or(&[]));
            let name = if unc.is_empty() {
                format!("[Network 0x{type_byte:02x}]")
            } else {
                unc
            };
            DecodedShellItem {
                type_byte,
                kind: ShellItemKind::Network,
                name,
                short_name: None,
                file_size: None,
                created: None,
                modified: None,
                accessed: None,
                mft_entry: None,
                guid: None,
                raw_len,
            }
        }
        0x71 => {
            let guid = if body.len() >= 28 {
                parse_guid_le_braced(&body[12..28]).ok()
            } else {
                None
            };
            let (prop_name, prop_time) = extract_1sps_props(body);
            let name = prop_name
                .or_else(|| guid.as_deref().and_then(known_folder_guid_name).map(str::to_string))
                .or_else(|| guid.clone())
                .unwrap_or_else(|| "Control Panel".to_string());
            DecodedShellItem {
                type_byte,
                kind: ShellItemKind::ControlPanel,
                name,
                short_name: None,
                file_size: None,
                created: None,
                modified: prop_time,
                accessed: None,
                mft_entry: None,
                guid,
                raw_len,
            }
        }
        0x61 => {
            let uri = find_readable_utf16_hint(body).unwrap_or_else(|| {
                let (s, _) = decode_ascii_nul(&body[1..]);
                if s.is_empty() {
                    format!("[URI 0x{type_byte:02x}]")
                } else {
                    s
                }
            });
            DecodedShellItem {
                type_byte,
                kind: ShellItemKind::Uri,
                name: uri,
                short_name: None,
                file_size: None,
                created: None,
                modified: None,
                accessed: None,
                mft_entry: None,
                guid: None,
                raw_len,
            }
        }
        _ => {
            let (prop_name, prop_time) = extract_1sps_props(body);
            if let Some(pname) = prop_name {
                DecodedShellItem {
                    type_byte,
                    kind: ShellItemKind::PropertyStore,
                    name: pname,
                    short_name: None,
                    file_size: None,
                    created: None,
                    modified: prop_time,
                    accessed: None,
                    mft_entry: None,
                    guid: None,
                    raw_len,
                }
            } else if body.windows(4).any(|w| w == b"1SPS") {
                DecodedShellItem {
                    type_byte,
                    kind: ShellItemKind::PropertyStore,
                    name: find_readable_utf16_hint(body)
                        .unwrap_or_else(|| format!("[PropertyStore 0x{type_byte:02x}: {raw_len}B]")),
                    short_name: None,
                    file_size: None,
                    created: None,
                    modified: prop_time,
                    accessed: None,
                    mft_entry: None,
                    guid: None,
                    raw_len,
                }
            } else {
                DecodedShellItem {
                    type_byte,
                    kind: ShellItemKind::Unknown(type_byte),
                    name: format!("[Unknown 0x{type_byte:02x}: {raw_len}B]"),
                    short_name: None,
                    file_size: None,
                    created: None,
                    modified: None,
                    accessed: None,
                    mft_entry: None,
                    guid: None,
                    raw_len,
                }
            }
        }
    }
}

/// Joins decoded PIDL items into a clean Windows-style display path.
/// Skips leading `"This PC"` (`{20D04FE0-...}`) when immediately followed by a `Volume` item (`C:\`).
pub fn join_pidl_path(items: &[DecodedShellItem]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for (idx, item) in items.iter().enumerate() {
        if idx == 0
            && item.kind == ShellItemKind::RootFolder
            && item
                .guid
                .as_deref()
                .is_some_and(|g| g.eq_ignore_ascii_case("{20D04FE0-3AEA-1069-A2D8-08002B30309D}"))
            && items.get(1).is_some_and(|n| n.kind == ShellItemKind::Volume)
        {
            continue;
        }
        let seg = if item.kind == ShellItemKind::Volume {
            item.name.trim_end_matches('\\').to_string()
        } else {
            item.name.trim_matches('\\').to_string()
        };
        if !seg.is_empty() {
            parts.push(seg);
        }
    }
    if parts.len() == 1 && items.iter().any(|i| i.kind == ShellItemKind::Volume) && parts[0].ends_with(':') {
        format!("{}\\", parts[0])
    } else {
        parts.join("\\")
    }
}
