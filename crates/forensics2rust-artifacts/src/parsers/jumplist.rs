#![forbid(unsafe_code)]

//! Pure-Rust Windows JumpLists parser supporting `.automaticDestinations-ms`
//! (OLE2/CFBF + `DestList` v1/v3/v4/v6 + LNK streams) and `.customDestinations-ms`.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use forensics2rust_core::{
    DiagnosticWarning, ForensicError, WarningSeverity, filetime_to_utc, parse_guid_le_braced, read_utf16_le,
};
use serde::{Deserialize, Serialize};

use crate::parsers::cfbf::CfbfFile;
use crate::parsers::lnk::{CLSID_SHELL_LINK, ShellLink, parse_lnk};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestListEntry {
    pub entry_id: u64,
    pub path: String,
    pub access_score: f32,
    pub access_count: u32,
    pub last_recorded_time: Option<DateTime<Utc>>,
    pub pin_status: i32,
    pub netbios_name: String,
    pub volume_droid: String,
    pub object_droid: String,
    pub birth_volume_droid: String,
    pub birth_object_droid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumpListRecord {
    pub app_id: String,
    pub app_name: String,
    pub entry_id: String,
    pub file_name: String,
    pub full_path: String,
    pub record_time: Option<DateTime<Utc>>,
    pub access_count: Option<u32>,
    pub pin_status: String,
    pub arguments: Option<String>,
    pub volume_serial: Option<String>,
    pub lnk: Option<ShellLink>,
    pub dest_entry: Option<DestListEntry>,
    pub raw_bytes: Vec<u8>,
}

/// Resolves well-known Windows JumpList 16-hex AppIDs to friendly application names.
pub fn lookup_app_name(app_id: &str) -> String {
    match app_id.to_ascii_lowercase().as_str() {
        "1b4dd67f29cb1962" => "Windows Explorer (Taskbar)".to_string(),
        "f01b4d95cf55d32a" => "Windows Explorer".to_string(),
        "5d696d521de238c3" => "Google Chrome".to_string(),
        "28c8b86deab549a1" => "Internet Explorer".to_string(),
        "9b9cdc69c1c24e2b" => "Notepad".to_string(),
        "918e0ecb43d17e23" => "Notepad (Win11)".to_string(),
        "adecfb853d77462a" => "Microsoft Word".to_string(),
        "9839aec31243a928" => "Microsoft Excel".to_string(),
        "9c7cc110ff56d1bd" => "Microsoft PowerPoint".to_string(),
        "5f7b5f1e01b83767" => "Quick Access / Recent Folders".to_string(),
        "7e4dca80246863e3" => "Control Panel".to_string(),
        "bc03160ee1a59fc1" => "Windows Terminal".to_string(),
        "d00655d2aa12ff6d" => "Microsoft Edge".to_string(),
        "fb3b0dbfee58fac8" => "Microsoft Word (Office 365)".to_string(),
        "b8ab77100df80ab2" => "Microsoft Excel (Office 365)".to_string(),
        "1f8e7e98b4475a69" => "Visual Studio Code".to_string(),
        "aa2632b8d57e166a" => "Command Prompt (cmd.exe)".to_string(),
        "c4a466b757f7f4f4" => "Windows PowerShell".to_string(),
        _ => format!("Unknown ({app_id})"),
    }
}

fn read_u16_le(b: &[u8], off: usize) -> Result<u16, ForensicError> {
    let s = b
        .get(off..off + 2)
        .ok_or_else(|| ForensicError::parse("JumpList", format!("truncated u16 at 0x{off:X}")))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32_le(b: &[u8], off: usize) -> Result<u32, ForensicError> {
    let s = b
        .get(off..off + 4)
        .ok_or_else(|| ForensicError::parse("JumpList", format!("truncated u32 at 0x{off:X}")))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64_le(b: &[u8], off: usize) -> Result<u64, ForensicError> {
    let s = b
        .get(off..off + 8)
        .ok_or_else(|| ForensicError::parse("JumpList", format!("truncated u64 at 0x{off:X}")))?;
    Ok(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

fn read_ascii_nul(slice: &[u8]) -> String {
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    slice[..end]
        .iter()
        .map(|&b| if b >= 0x20 { b as char } else { '?' })
        .collect()
}

pub fn parse_destlist(bytes: &[u8]) -> Result<Vec<DestListEntry>, ForensicError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() < 32 {
        return Err(ForensicError::parse(
            "DestList",
            format!("DestList stream too short ({} bytes; expected >= 32)", bytes.len()),
        ));
    }

    let version = read_u32_le(bytes, 0)?;
    let entry_count = read_u32_le(bytes, 4)? as usize;

    let mut pos = 32usize;
    let mut entries = Vec::with_capacity(entry_count.min(4096));

    for _ in 0..entry_count {
        if pos + 114 > bytes.len() {
            return Err(ForensicError::parse(
                "DestList",
                format!("truncated DestList entry header at 0x{pos:X}"),
            ));
        }
        let volume_droid = parse_guid_le_braced(&bytes[pos + 0x08..pos + 0x18]).unwrap_or_default();
        let object_droid = parse_guid_le_braced(&bytes[pos + 0x18..pos + 0x28]).unwrap_or_default();
        let birth_volume_droid = parse_guid_le_braced(&bytes[pos + 0x28..pos + 0x38]).unwrap_or_default();
        let birth_object_droid = parse_guid_le_braced(&bytes[pos + 0x38..pos + 0x48]).unwrap_or_default();
        let netbios_name = read_ascii_nul(&bytes[pos + 0x48..pos + 0x58]);
        let entry_id = read_u64_le(bytes, pos + 0x58)?;
        let access_score = f32::from_bits(read_u32_le(bytes, pos + 0x60)?);
        let last_recorded_time = filetime_to_utc(read_u64_le(bytes, pos + 0x64)?);
        let pin_status = read_u32_le(bytes, pos + 0x6C)? as i32;

        let (access_count, path, next_pos) = if version <= 1 {
            let path_chars = read_u16_le(bytes, pos + 0x70)? as usize;
            let str_start = pos + 0x72;
            let str_end = str_start + path_chars * 2;
            if str_end > bytes.len() {
                return Err(ForensicError::parse("DestList", "truncated v1 DestList path"));
            }
            let path = read_utf16_le(&bytes[str_start..str_end]);
            let count = if access_score.is_finite() {
                access_score.round().max(0.0) as u32
            } else {
                0
            };
            (count, path, str_end)
        } else {
            if pos + 130 > bytes.len() {
                return Err(ForensicError::parse("DestList", "truncated v3/v4/v6 DestList entry"));
            }
            let access_count = read_u32_le(bytes, pos + 0x74)?;
            let path_chars = read_u16_le(bytes, pos + 0x80)? as usize;
            let str_start = pos + 0x82;
            let str_end = str_start + path_chars * 2;
            if str_end > bytes.len() {
                return Err(ForensicError::parse("DestList", "truncated v3/v4/v6 DestList path"));
            }
            let path = read_utf16_le(&bytes[str_start..str_end]);
            let next = (str_end + 4).min(bytes.len());
            (access_count, path, next)
        };

        entries.push(DestListEntry {
            entry_id,
            path,
            access_score,
            access_count,
            last_recorded_time,
            pin_status,
            netbios_name,
            volume_droid,
            object_droid,
            birth_volume_droid,
            birth_object_droid,
        });
        pos = next_pos;
    }

    Ok(entries)
}

fn basename_of(path: &str) -> String {
    let trimmed = path.trim_end_matches(['\\', '/']);
    trimmed
        .rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(path)
        .to_string()
}

pub fn parse_automatic_destinations(
    bytes: &[u8],
    app_id: &str,
) -> Result<(Vec<JumpListRecord>, Vec<DiagnosticWarning>), ForensicError> {
    let cfbf = CfbfFile::parse(bytes)?;
    let app_name = lookup_app_name(app_id);
    let mut warnings = Vec::new();
    let mut records = Vec::new();
    let mut matched_streams = HashSet::new();

    if let Some(dest_entry) = cfbf.find_stream("DestList") {
        matched_streams.insert("destlist".to_string());
        let dest_bytes = cfbf.read_stream(dest_entry)?;
        let dest_entries = parse_destlist(&dest_bytes)?;
        for de in dest_entries {
            let stream_name = format!("{:x}", de.entry_id);
            matched_streams.insert(stream_name.clone());

            let mut lnk_opt = None;
            let mut raw_bytes = Vec::new();
            if let Some(stream_dir) = cfbf.find_stream(&stream_name) {
                match cfbf.read_stream(stream_dir) {
                    Ok(sb) => {
                        raw_bytes = sb.iter().copied().take(4096).collect();
                        match parse_lnk(&sb) {
                            Ok((lnk, _)) => lnk_opt = Some(lnk),
                            Err(err) => warnings.push(DiagnosticWarning {
                                severity: WarningSeverity::Warn,
                                tool_id: "artifacts.jumplists".to_string(),
                                source: format!("{app_id}:{stream_name}"),
                                message: format!("LNK stream parse warning: {err}"),
                            }),
                        }
                    }
                    Err(err) => warnings.push(DiagnosticWarning {
                        severity: WarningSeverity::Warn,
                        tool_id: "artifacts.jumplists".to_string(),
                        source: format!("{app_id}:{stream_name}"),
                        message: format!("CFBF stream read warning: {err}"),
                    }),
                }
            }

            let full_path = if !de.path.is_empty() {
                de.path.clone()
            } else {
                lnk_opt.as_ref().and_then(|l| l.target_path.clone()).unwrap_or_default()
            };
            let file_name = basename_of(&full_path);
            let record_time = de
                .last_recorded_time
                .or_else(|| lnk_opt.as_ref().and_then(|l| l.write_time));
            let pin_status = if de.pin_status >= 0 {
                format!("Pinned (#{})", de.pin_status)
            } else {
                "Unpinned".to_string()
            };
            let arguments = lnk_opt
                .as_ref()
                .and_then(|l| l.command_line_arguments.clone())
                .filter(|s| !s.is_empty());
            let volume_serial = lnk_opt
                .as_ref()
                .and_then(|l| l.link_info.as_ref())
                .and_then(|li| li.drive_serial_number)
                .map(|s| format!("{s:08X}"));

            records.push(JumpListRecord {
                app_id: app_id.to_string(),
                app_name: app_name.clone(),
                entry_id: stream_name,
                file_name,
                full_path,
                record_time,
                access_count: Some(de.access_count),
                pin_status,
                arguments,
                volume_serial,
                lnk: lnk_opt,
                dest_entry: Some(de),
                raw_bytes,
            });
        }
    }

    // Also include any orphan hex-named LNK streams not referenced by DestList
    for entry in cfbf.entries() {
        if entry.object_type != 2 {
            continue;
        }
        let lower = entry.name.to_ascii_lowercase();
        if matched_streams.contains(&lower) || !lower.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        if let Ok(sb) = cfbf.read_stream(entry)
            && let Ok((lnk, _)) = parse_lnk(&sb)
        {
            let full_path = lnk.target_path.clone().unwrap_or_else(|| entry.name.clone());
            let file_name = basename_of(&full_path);
            let record_time = lnk.write_time.or(lnk.creation_time);
            let arguments = lnk.command_line_arguments.clone().filter(|s| !s.is_empty());
            let volume_serial = lnk
                .link_info
                .as_ref()
                .and_then(|li| li.drive_serial_number)
                .map(|s| format!("{s:08X}"));
            records.push(JumpListRecord {
                app_id: app_id.to_string(),
                app_name: app_name.clone(),
                entry_id: entry.name.clone(),
                file_name,
                full_path,
                record_time,
                access_count: None,
                pin_status: "OrphanStream".to_string(),
                arguments,
                volume_serial,
                lnk: Some(lnk),
                dest_entry: None,
                raw_bytes: sb.into_iter().take(4096).collect(),
            });
        }
    }

    Ok((records, warnings))
}

pub fn parse_custom_destinations(
    bytes: &[u8],
    app_id: &str,
) -> Result<(Vec<JumpListRecord>, Vec<DiagnosticWarning>), ForensicError> {
    if bytes.len() < 12 {
        return Err(ForensicError::parse(
            "CustomDestinations",
            format!("buffer too short ({} bytes; expected >= 12)", bytes.len()),
        ));
    }

    let app_name = lookup_app_name(app_id);
    let mut warnings = Vec::new();
    let category_count = read_u32_le(bytes, 4)? as usize;

    if bytes.len() == 12 && category_count == 0 {
        return Ok((Vec::new(), warnings));
    }

    match parse_custom_destinations_strict(bytes, app_id, &app_name, category_count) {
        Ok(recs) => Ok((recs, warnings)),
        Err(strict_err) => {
            // Fallback recovery scan for inline CLSID_ShellLink + ShellLinkHeader
            let mut recovered = Vec::new();
            let mut idx = 0usize;
            let mut search_pos = 0usize;
            while search_pos + 20 <= bytes.len() {
                if bytes[search_pos..].starts_with(&CLSID_SHELL_LINK)
                    && bytes.get(search_pos + 16..search_pos + 20) == Some(&[0x4C, 0x00, 0x00, 0x00])
                    && let Ok((lnk, consumed)) = parse_lnk(&bytes[search_pos + 16..])
                {
                    let full_path = lnk.target_path.clone().unwrap_or_default();
                    let file_name = basename_of(&full_path);
                    let record_time = lnk.write_time.or(lnk.creation_time);
                    let arguments = lnk.command_line_arguments.clone().filter(|s| !s.is_empty());
                    let volume_serial = lnk
                        .link_info
                        .as_ref()
                        .and_then(|li| li.drive_serial_number)
                        .map(|s| format!("{s:08X}"));
                    recovered.push(JumpListRecord {
                        app_id: app_id.to_string(),
                        app_name: app_name.clone(),
                        entry_id: format!("recovered:{idx}"),
                        file_name,
                        full_path,
                        record_time,
                        access_count: None,
                        pin_status: "Recovered".to_string(),
                        arguments,
                        volume_serial,
                        lnk: Some(lnk),
                        dest_entry: None,
                        raw_bytes: bytes[search_pos + 16..].iter().copied().take(4096).collect(),
                    });
                    idx += 1;
                    search_pos += 16 + consumed.max(1);
                    continue;
                }
                search_pos += 1;
            }
            if recovered.is_empty() {
                Err(strict_err)
            } else {
                warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Warn,
                    tool_id: "artifacts.jumplists".to_string(),
                    source: app_id.to_string(),
                    message: format!(
                        "recovered {} LNK entries after framing error: {strict_err}",
                        recovered.len()
                    ),
                });
                Ok((recovered, warnings))
            }
        }
    }
}

fn parse_custom_destinations_strict(
    bytes: &[u8],
    app_id: &str,
    app_name: &str,
    category_count: usize,
) -> Result<Vec<JumpListRecord>, ForensicError> {
    let mut records = Vec::new();
    let mut pos = 12usize;

    for cat_idx in 0..category_count.min(256) {
        let cat_type = read_u32_le(bytes, pos)?;
        pos += 4;
        let (pin_label, item_count) = match cat_type {
            0 => {
                // Custom category: u16 char count + UTF-16LE title + u32 item_count
                let title_chars = read_u16_le(bytes, pos)? as usize;
                pos += 2;
                let title_end = pos + title_chars * 2;
                if title_end > bytes.len() {
                    return Err(ForensicError::parse("CustomDestinations", "truncated category title"));
                }
                let title = read_utf16_le(&bytes[pos..title_end]);
                pos = title_end;
                let cnt = read_u32_le(bytes, pos)? as usize;
                pos += 4;
                (format!("Custom:{title}"), cnt)
            }
            1 => {
                // Known category: u32 known_id, 0 inline items
                let _known_id = read_u32_le(bytes, pos)?;
                pos += 4;
                ("Known".to_string(), 0usize)
            }
            2 => {
                // Tasks category: u32 item_count
                let cnt = read_u32_le(bytes, pos)? as usize;
                pos += 4;
                ("Task".to_string(), cnt)
            }
            other => {
                return Err(ForensicError::parse(
                    "CustomDestinations",
                    format!("unknown category type {other} at offset 0x{pos:X}"),
                ));
            }
        };

        for item_idx in 0..item_count.min(1024) {
            let clsid = bytes
                .get(pos..pos + 16)
                .ok_or_else(|| ForensicError::parse("CustomDestinations", "truncated CLSID_ShellLink"))?;
            if clsid != CLSID_SHELL_LINK {
                return Err(ForensicError::parse(
                    "CustomDestinations",
                    format!("expected CLSID_ShellLink at offset 0x{pos:X}"),
                ));
            }
            pos += 16;
            let (lnk, consumed) = parse_lnk(&bytes[pos..])?;
            let raw_bytes = bytes[pos..pos + consumed].iter().copied().take(4096).collect();
            pos += consumed;

            let full_path = lnk.target_path.clone().or_else(|| lnk.name.clone()).unwrap_or_default();
            let file_name = basename_of(&full_path);
            let record_time = lnk.write_time.or(lnk.creation_time);
            let arguments = lnk.command_line_arguments.clone().filter(|s| !s.is_empty());
            let volume_serial = lnk
                .link_info
                .as_ref()
                .and_then(|li| li.drive_serial_number)
                .map(|s| format!("{s:08X}"));

            records.push(JumpListRecord {
                app_id: app_id.to_string(),
                app_name: app_name.to_string(),
                entry_id: format!("cat[{cat_idx}]:item[{item_idx}]"),
                file_name,
                full_path,
                record_time,
                access_count: None,
                pin_status: pin_label.clone(),
                arguments,
                volume_serial,
                lnk: Some(lnk),
                dest_entry: None,
                raw_bytes,
            });
        }

        let footer = read_u32_le(bytes, pos)?;
        if footer != 0xBABF_FBAB {
            return Err(ForensicError::parse(
                "CustomDestinations",
                format!("invalid category footer 0x{footer:08X} (expected 0xBABFFBAB)"),
            ));
        }
        pos += 4;
    }

    Ok(records)
}
