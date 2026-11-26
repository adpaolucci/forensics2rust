#![forbid(unsafe_code)]

//! Pure-Rust `[MS-SHLLINK]` Windows Shortcut (`.lnk`) binary parser.

use chrono::{DateTime, Utc};
use forensics2rust_core::{ForensicError, filetime_to_utc, parse_guid_le_braced, read_utf16_le, read_utf16_le_nul};
use serde::{Deserialize, Serialize};

use crate::parsers::pidl::{DecodedShellItem, join_pidl_path, parse_pidl};

pub const CLSID_SHELL_LINK: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

const FLAG_HAS_LINK_TARGET_ID_LIST: u32 = 0x0000_0001;
const FLAG_HAS_LINK_INFO: u32 = 0x0000_0002;
const FLAG_HAS_NAME: u32 = 0x0000_0004;
const FLAG_HAS_RELATIVE_PATH: u32 = 0x0000_0008;
const FLAG_HAS_WORKING_DIR: u32 = 0x0000_0010;
const FLAG_HAS_ARGUMENTS: u32 = 0x0000_0020;
const FLAG_HAS_ICON_LOCATION: u32 = 0x0000_0040;
const FLAG_IS_UNICODE: u32 = 0x0000_0080;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkTrackerData {
    pub machine_id: String,
    pub droid_volume_id: String,
    pub droid_file_id: String,
    pub birth_droid_volume_id: String,
    pub birth_droid_file_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkInfoData {
    pub drive_type: Option<u32>,
    pub drive_serial_number: Option<u32>,
    pub volume_label: Option<String>,
    pub local_base_path: Option<String>,
    pub net_name: Option<String>,
    pub common_path_suffix: Option<String>,
    pub resolved_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellLink {
    pub link_flags: u32,
    pub file_attributes: u32,
    pub file_attributes_text: String,
    pub creation_time: Option<DateTime<Utc>>,
    pub access_time: Option<DateTime<Utc>>,
    pub write_time: Option<DateTime<Utc>>,
    pub file_size: u32,
    pub icon_index: i32,
    pub show_command: u32,
    pub hot_key: u16,
    pub id_list_items: Vec<DecodedShellItem>,
    pub id_list_path: Option<String>,
    pub link_info: Option<LinkInfoData>,
    pub name: Option<String>,
    pub relative_path: Option<String>,
    pub working_dir: Option<String>,
    pub command_line_arguments: Option<String>,
    pub icon_location: Option<String>,
    pub tracker: Option<LinkTrackerData>,
    pub env_target: Option<String>,
    pub darwin_id: Option<String>,
    pub special_folder_id: Option<u32>,
    pub known_folder_id: Option<String>,
    pub target_path: Option<String>,
}

pub fn format_file_attributes(attrs: u32) -> String {
    const FLAGS: &[(u32, &str)] = &[
        (0x0001, "READONLY"),
        (0x0002, "HIDDEN"),
        (0x0004, "SYSTEM"),
        (0x0010, "DIRECTORY"),
        (0x0020, "ARCHIVE"),
        (0x0080, "NORMAL"),
        (0x0100, "TEMPORARY"),
        (0x0200, "SPARSE"),
        (0x0400, "REPARSE_POINT"),
        (0x0800, "COMPRESSED"),
        (0x1000, "OFFLINE"),
        (0x4000, "ENCRYPTED"),
    ];
    let mut parts = Vec::new();
    for &(bit, label) in FLAGS {
        if (attrs & bit) != 0 {
            parts.push(label);
        }
    }
    if parts.is_empty() {
        format!("0x{attrs:08X}")
    } else {
        parts.join(" | ")
    }
}

fn read_u16_le(b: &[u8], off: usize) -> Result<u16, ForensicError> {
    let s = b
        .get(off..off + 2)
        .ok_or_else(|| ForensicError::parse("SHLLINK", format!("truncated u16 at 0x{off:X}")))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32_le(b: &[u8], off: usize) -> Result<u32, ForensicError> {
    let s = b
        .get(off..off + 4)
        .ok_or_else(|| ForensicError::parse("SHLLINK", format!("truncated u32 at 0x{off:X}")))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64_le(b: &[u8], off: usize) -> Result<u64, ForensicError> {
    let s = b
        .get(off..off + 8)
        .ok_or_else(|| ForensicError::parse("SHLLINK", format!("truncated u64 at 0x{off:X}")))?;
    Ok(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

fn read_ansi_nul(slice: &[u8]) -> String {
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    slice[..end]
        .iter()
        .map(|&b| if b >= 0x20 || b == b'\t' { b as char } else { '?' })
        .collect()
}

/// Parses an `[MS-SHLLINK]` stream starting at `bytes[0]`, returning `(ShellLink, bytes_consumed)`.
pub fn parse_lnk(bytes: &[u8]) -> Result<(ShellLink, usize), ForensicError> {
    if bytes.len() < 76 {
        return Err(ForensicError::parse(
            "SHLLINK",
            format!("buffer too short ({} bytes; expected >= 76)", bytes.len()),
        ));
    }

    let header_size = read_u32_le(bytes, 0x00)?;
    if header_size != 0x0000_004C {
        return Err(ForensicError::parse(
            "SHLLINK",
            format!("invalid ShellLinkHeader size 0x{header_size:08X} (expected 0x0000004C)"),
        ));
    }
    if bytes[0x04..0x14] != CLSID_SHELL_LINK {
        return Err(ForensicError::parse("SHLLINK", "invalid LinkCLSID"));
    }

    let link_flags = read_u32_le(bytes, 0x14)?;
    let file_attributes = read_u32_le(bytes, 0x18)?;
    let creation_time = filetime_to_utc(read_u64_le(bytes, 0x1C)?);
    let access_time = filetime_to_utc(read_u64_le(bytes, 0x24)?);
    let write_time = filetime_to_utc(read_u64_le(bytes, 0x2C)?);
    let file_size = read_u32_le(bytes, 0x34)?;
    let icon_index = read_u32_le(bytes, 0x38)? as i32;
    let show_command = read_u32_le(bytes, 0x3C)?;
    let hot_key = read_u16_le(bytes, 0x40)?;

    let mut pos = 76usize;

    // 1. LinkTargetIDList
    let mut id_list_items = Vec::new();
    let mut id_list_path = None;
    if (link_flags & FLAG_HAS_LINK_TARGET_ID_LIST) != 0 {
        let id_list_size = read_u16_le(bytes, pos)? as usize;
        pos += 2;
        if pos + id_list_size > bytes.len() {
            return Err(ForensicError::parse(
                "SHLLINK",
                format!("LinkTargetIDList size {id_list_size} exceeds buffer"),
            ));
        }
        let decoded = parse_pidl(&bytes[pos..pos + id_list_size]);
        let joined = join_pidl_path(&decoded.items);
        if !joined.is_empty() {
            id_list_path = Some(joined);
        }
        id_list_items = decoded.items;
        pos += id_list_size;
    }

    // 2. LinkInfo
    let mut link_info = None;
    if (link_flags & FLAG_HAS_LINK_INFO) != 0 {
        let li_size = read_u32_le(bytes, pos)? as usize;
        if li_size == 0 {
            pos += 4;
        } else {
            if li_size < 28 || pos + li_size > bytes.len() {
                return Err(ForensicError::parse(
                    "SHLLINK",
                    format!("invalid or truncated LinkInfo size {li_size}"),
                ));
            }
            let li = &bytes[pos..pos + li_size];
            let li_hdr_size = read_u32_le(li, 4)? as usize;
            let li_flags = read_u32_le(li, 8)?;
            let vol_off = read_u32_le(li, 12)? as usize;
            let local_off = read_u32_le(li, 16)? as usize;
            let net_off = read_u32_le(li, 20)? as usize;
            let suffix_off = read_u32_le(li, 24)? as usize;

            let mut drive_type = None;
            let mut drive_serial_number = None;
            let mut volume_label = None;
            let mut local_base_path = None;
            let mut net_name = None;

            if (li_flags & 0x01) != 0 {
                if vol_off > 0 && vol_off + 16 <= li.len() {
                    let v = &li[vol_off..];
                    let v_size = read_u32_le(v, 0)? as usize;
                    let v_end = v_size.min(v.len());
                    if v_end >= 16 {
                        drive_type = Some(read_u32_le(v, 4)?);
                        drive_serial_number = Some(read_u32_le(v, 8)?);
                        let lbl_off = read_u32_le(v, 12)? as usize;
                        if lbl_off == 0x14 && v_end >= 20 {
                            let u_off = read_u32_le(v, 16)? as usize;
                            if u_off < v_end {
                                let lbl = read_utf16_le_nul(&v[u_off..v_end]);
                                if !lbl.is_empty() {
                                    volume_label = Some(lbl);
                                }
                            }
                        } else if lbl_off > 0 && lbl_off < v_end {
                            let lbl = read_ansi_nul(&v[lbl_off..v_end]);
                            if !lbl.is_empty() {
                                volume_label = Some(lbl);
                            }
                        }
                    }
                }
                if li_hdr_size >= 0x24 && li.len() >= 32 {
                    let local_u_off = read_u32_le(li, 28)? as usize;
                    if local_u_off > 0 && local_u_off < li.len() {
                        let s = read_utf16_le_nul(&li[local_u_off..]);
                        if !s.is_empty() {
                            local_base_path = Some(s);
                        }
                    }
                }
                if local_base_path.is_none() && local_off > 0 && local_off < li.len() {
                    let s = read_ansi_nul(&li[local_off..]);
                    if !s.is_empty() {
                        local_base_path = Some(s);
                    }
                }
            }

            if (li_flags & 0x02) != 0 && net_off > 0 && net_off + 20 <= li.len() {
                let n = &li[net_off..];
                let n_size = read_u32_le(n, 0)? as usize;
                let n_end = n_size.min(n.len());
                let nn_off = read_u32_le(n, 8)? as usize;
                if nn_off > 0x14 && n_end >= 24 {
                    let nn_u_off = read_u32_le(n, 20)? as usize;
                    if nn_u_off > 0 && nn_u_off < n_end {
                        let s = read_utf16_le_nul(&n[nn_u_off..n_end]);
                        if !s.is_empty() {
                            net_name = Some(s);
                        }
                    }
                }
                if net_name.is_none() && nn_off > 0 && nn_off < n_end {
                    let s = read_ansi_nul(&n[nn_off..n_end]);
                    if !s.is_empty() {
                        net_name = Some(s);
                    }
                }
            }

            let mut common_path_suffix = None;
            if li_hdr_size >= 0x24 && li.len() >= 36 {
                let suf_u_off = read_u32_le(li, 32)? as usize;
                if suf_u_off > 0 && suf_u_off < li.len() {
                    let s = read_utf16_le_nul(&li[suf_u_off..]);
                    if !s.is_empty() {
                        common_path_suffix = Some(s);
                    }
                }
            }
            if common_path_suffix.is_none() && suffix_off > 0 && suffix_off < li.len() {
                let s = read_ansi_nul(&li[suffix_off..]);
                if !s.is_empty() {
                    common_path_suffix = Some(s);
                }
            }

            let resolved_path = match (&local_base_path, &net_name, &common_path_suffix) {
                (Some(base), _, Some(suf)) if !suf.is_empty() => {
                    if base.ends_with('\\') {
                        Some(format!("{base}{suf}"))
                    } else {
                        Some(format!("{base}\\{suf}"))
                    }
                }
                (Some(base), _, _) => Some(base.clone()),
                (None, Some(net), Some(suf)) if !suf.is_empty() => {
                    if net.ends_with('\\') {
                        Some(format!("{net}{suf}"))
                    } else {
                        Some(format!("{net}\\{suf}"))
                    }
                }
                (None, Some(net), _) => Some(net.clone()),
                _ => None,
            };

            link_info = Some(LinkInfoData {
                drive_type,
                drive_serial_number,
                volume_label,
                local_base_path,
                net_name,
                common_path_suffix,
                resolved_path,
            });
            pos += li_size;
        }
    }

    // 3. StringData in exact flag order
    let is_unicode = (link_flags & FLAG_IS_UNICODE) != 0;
    let mut read_string_data = |flag: u32| -> Result<Option<String>, ForensicError> {
        if (link_flags & flag) == 0 {
            return Ok(None);
        }
        let char_count = read_u16_le(bytes, pos)? as usize;
        pos += 2;
        let byte_len = if is_unicode {
            char_count.saturating_mul(2)
        } else {
            char_count
        };
        let slice = bytes
            .get(pos..pos + byte_len)
            .ok_or_else(|| ForensicError::parse("SHLLINK", "truncated StringData"))?;
        pos += byte_len;
        let val = if is_unicode {
            read_utf16_le(slice)
        } else {
            read_ansi_nul(slice)
        };
        Ok(Some(val))
    };

    let name = read_string_data(FLAG_HAS_NAME)?;
    let relative_path = read_string_data(FLAG_HAS_RELATIVE_PATH)?;
    let working_dir = read_string_data(FLAG_HAS_WORKING_DIR)?;
    let command_line_arguments = read_string_data(FLAG_HAS_ARGUMENTS)?;
    let icon_location = read_string_data(FLAG_HAS_ICON_LOCATION)?;

    // 4. ExtraData
    let mut tracker = None;
    let mut env_target = None;
    let mut darwin_id = None;
    let mut special_folder_id = None;
    let mut known_folder_id = None;

    while pos + 4 <= bytes.len() {
        let block_size = read_u32_le(bytes, pos)? as usize;
        if block_size < 4 {
            pos += 4;
            break;
        }
        if pos + block_size > bytes.len() {
            return Err(ForensicError::parse(
                "SHLLINK",
                format!("truncated ExtraData block of size {block_size} at 0x{pos:X}"),
            ));
        }
        let blk = &bytes[pos..pos + block_size];
        if blk.len() >= 8 {
            let sig = read_u32_le(blk, 4)?;
            match sig {
                0xA000_0003 if blk.len() >= 96 => {
                    let machine_id = read_ansi_nul(&blk[16..32]);
                    let droid_volume_id = parse_guid_le_braced(&blk[32..48]).unwrap_or_default();
                    let droid_file_id = parse_guid_le_braced(&blk[48..64]).unwrap_or_default();
                    let birth_droid_volume_id = parse_guid_le_braced(&blk[64..80]).unwrap_or_default();
                    let birth_droid_file_id = parse_guid_le_braced(&blk[80..96]).unwrap_or_default();
                    tracker = Some(LinkTrackerData {
                        machine_id,
                        droid_volume_id,
                        droid_file_id,
                        birth_droid_volume_id,
                        birth_droid_file_id,
                    });
                }
                0xA000_0001 if blk.len() >= 788 => {
                    let u = read_utf16_le_nul(&blk[268..788]);
                    let a = read_ansi_nul(&blk[8..268]);
                    let chosen = if !u.is_empty() { u } else { a };
                    if !chosen.is_empty() {
                        env_target = Some(chosen);
                    }
                }
                0xA000_0006 if blk.len() >= 788 => {
                    let u = read_utf16_le_nul(&blk[268..788]);
                    let a = read_ansi_nul(&blk[8..268]);
                    let chosen = if !u.is_empty() { u } else { a };
                    if !chosen.is_empty() {
                        darwin_id = Some(chosen);
                    }
                }
                0xA000_0005 if blk.len() >= 16 => {
                    special_folder_id = Some(read_u32_le(blk, 8)?);
                }
                0xA000_000B if blk.len() >= 28 => {
                    if let Ok(g) = parse_guid_le_braced(&blk[8..24]) {
                        known_folder_id = Some(g);
                    }
                }
                _ => {}
            }
        }
        pos += block_size;
    }

    let target_path = link_info
        .as_ref()
        .and_then(|li| li.resolved_path.clone())
        .or_else(|| id_list_path.clone())
        .or_else(|| env_target.clone())
        .or_else(|| relative_path.clone());

    Ok((
        ShellLink {
            link_flags,
            file_attributes,
            file_attributes_text: format_file_attributes(file_attributes),
            creation_time,
            access_time,
            write_time,
            file_size,
            icon_index,
            show_command,
            hot_key,
            id_list_items,
            id_list_path,
            link_info,
            name,
            relative_path,
            working_dir,
            command_line_arguments,
            icon_location,
            tracker,
            env_target,
            darwin_id,
            special_folder_id,
            known_folder_id,
            target_path,
        },
        pos,
    ))
}
