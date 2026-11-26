use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use forensics2rust_core::{ForensicError, filetime_to_utc, read_utf16_le, read_utf16_le_nul};

use super::{KEY_COMP_NAME, RecoveredKey, RegKeyNode, RegValue, RegValueData, RegfHeader, RegfHive, VALUE_COMP_NAME};

pub const HBIN_START: usize = 0x1000;
pub const MAX_KEY_DEPTH: usize = 512;
pub const MAX_LIST_DEPTH: usize = 32;
pub const MAX_BIG_DATA_CHUNK: usize = 16_344;

/// Computes the Windows `regf` base-block XOR-32 checksum over `0x00..0x1FC`.
pub fn compute_regf_checksum(base_block: &[u8]) -> u32 {
    if base_block.len() < 0x1FC {
        return 0;
    }
    let mut sum = 0u32;
    for &chunk in base_block[..0x1FC].as_chunks::<4>().0 {
        sum ^= u32::from_le_bytes(chunk);
    }
    match sum {
        0x0000_0000 => 0x0000_0001,
        0xFFFF_FFFF => 0xFFFF_FFFE,
        other => other,
    }
}

/// Decodes a compressed Latin-1 or uncompressed UTF-16LE `regf` key/value name.
pub fn decode_regf_name(bytes: &[u8], compressed: bool) -> String {
    if compressed {
        bytes.iter().map(|&b| char::from(b)).collect()
    } else {
        read_utf16_le(bytes)
    }
}

#[derive(Debug, Clone, Copy)]
struct CellSlice<'a> {
    allocated: bool,
    payload: &'a [u8],
}

#[derive(Debug, Clone)]
struct ParsedNk {
    flags: u16,
    last_write_time: Option<DateTime<Utc>>,
    parent_offset: u32,
    subkey_count: u32,
    subkeys_list_offset: u32,
    value_count: u32,
    value_list_offset: u32,
    name: String,
}

fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    let slice = buf.get(off..off + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let slice = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_i32_le(buf: &[u8], off: usize) -> Option<i32> {
    let slice = buf.get(off..off + 4)?;
    Some(i32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64_le(buf: &[u8], off: usize) -> Option<u64> {
    let slice = buf.get(off..off + 8)?;
    Some(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn read_cell_at<'a>(
    bytes: &'a [u8],
    rel_offset: u32,
    tolerant: bool,
    diagnostics: &mut Vec<String>,
) -> Option<CellSlice<'a>> {
    if rel_offset == u32::MAX {
        return None;
    }
    if !rel_offset.is_multiple_of(8) {
        diagnostics.push(format!("unaligned cell offset 0x{rel_offset:08x}"));
        return None;
    }
    let abs = HBIN_START.checked_add(rel_offset as usize)?;
    if abs.saturating_add(8) > bytes.len() {
        diagnostics.push(format!("cell offset 0x{rel_offset:08x} beyond EOF"));
        return None;
    }
    let raw_size = read_i32_le(bytes, abs)?;
    if raw_size == 0 {
        diagnostics.push(format!("zero-size cell at offset 0x{rel_offset:08x}"));
        return None;
    }
    let allocated = raw_size < 0;
    let cell_len = raw_size.unsigned_abs() as usize;
    if cell_len < 8 {
        diagnostics.push(format!("undersized cell ({cell_len}B) at offset 0x{rel_offset:08x}"));
        return None;
    }
    let end = match abs.checked_add(cell_len) {
        Some(end) if end <= bytes.len() => end,
        _ => {
            if tolerant {
                diagnostics.push(format!("truncated cell at offset 0x{rel_offset:08x}; clamped to EOF"));
                bytes.len()
            } else {
                diagnostics.push(format!("cell at offset 0x{rel_offset:08x} overflows EOF"));
                return None;
            }
        }
    };
    Some(CellSlice {
        allocated,
        payload: &bytes[abs + 4..end],
    })
}

fn parse_header(bytes: &[u8], tolerant: bool, diagnostics: &mut Vec<String>) -> Result<RegfHeader, ForensicError> {
    if bytes.len() < HBIN_START {
        if !tolerant {
            return Err(ForensicError::parse(
                "regf",
                format!("hive truncated: {} bytes (< 4096-byte base block)", bytes.len()),
            ));
        }
        let has_hbin = bytes.windows(4).any(|w| w == b"hbin");
        if !has_hbin {
            return Err(ForensicError::parse(
                "regf",
                format!("hive truncated ({} bytes) and no hbin chunks found", bytes.len()),
            ));
        }
        diagnostics.push(format!(
            "base block shorter than 4096 bytes ({}B); proceeding in tolerant recovery mode",
            bytes.len()
        ));
        return Ok(RegfHeader {
            primary_seq: 0,
            secondary_seq: 0,
            is_dirty: false,
            last_written: None,
            major_version: 1,
            minor_version: 5,
            file_type: 0,
            file_format: 1,
            root_cell_offset: 0x20,
            hive_bins_data_size: 0,
            clustering_factor: 1,
            file_name: String::new(),
            checksum_stored: 0,
            checksum_computed: 0,
            checksum_valid: false,
        });
    }

    let sig_valid = &bytes[0..4] == b"regf";
    if !sig_valid {
        if !tolerant {
            return Err(ForensicError::parse(
                "regf",
                format!(
                    "invalid regf signature: {:02x} {:02x} {:02x} {:02x}",
                    bytes[0], bytes[1], bytes[2], bytes[3]
                ),
            ));
        }
        let has_hbin = bytes[HBIN_START..].windows(4).any(|w| w == b"hbin");
        if !has_hbin {
            return Err(ForensicError::parse(
                "regf",
                "invalid regf signature and no hbin chunks found",
            ));
        }
        diagnostics.push("invalid regf base block signature; continuing tolerant hbin scan".to_owned());
    }

    let primary_seq = read_u32_le(bytes, 0x04).unwrap_or(0);
    let secondary_seq = read_u32_le(bytes, 0x08).unwrap_or(0);
    let is_dirty = primary_seq != secondary_seq;
    if is_dirty {
        diagnostics.push(format!(
            "dirty hive detected: primary_seq ({primary_seq}) != secondary_seq ({secondary_seq})"
        ));
    }
    let timestamp_raw = read_u64_le(bytes, 0x0C).unwrap_or(0);
    let last_written = filetime_to_utc(timestamp_raw);
    let major_version = read_u32_le(bytes, 0x14).unwrap_or(0);
    let minor_version = read_u32_le(bytes, 0x18).unwrap_or(0);
    let file_type = read_u32_le(bytes, 0x1C).unwrap_or(0);
    let file_format = read_u32_le(bytes, 0x20).unwrap_or(0);
    let root_cell_offset = read_u32_le(bytes, 0x24).unwrap_or(u32::MAX);
    let hive_bins_data_size = read_u32_le(bytes, 0x28).unwrap_or(0);
    let clustering_factor = read_u32_le(bytes, 0x2C).unwrap_or(0);
    let file_name = read_utf16_le_nul(&bytes[0x30..0x70]);
    let checksum_stored = read_u32_le(bytes, 0x1FC).unwrap_or(0);
    let checksum_computed = compute_regf_checksum(&bytes[..HBIN_START]);
    let checksum_valid = sig_valid && checksum_stored == checksum_computed;
    if sig_valid && !checksum_valid {
        diagnostics.push(format!(
            "regf checksum mismatch: stored 0x{checksum_stored:08x} != computed 0x{checksum_computed:08x}"
        ));
    }

    Ok(RegfHeader {
        primary_seq,
        secondary_seq,
        is_dirty,
        last_written,
        major_version,
        minor_version,
        file_type,
        file_format,
        root_cell_offset,
        hive_bins_data_size,
        clustering_factor,
        file_name,
        checksum_stored,
        checksum_computed,
        checksum_valid,
    })
}

fn parse_nk_payload(
    payload: &[u8],
    rel_offset: u32,
    tolerant: bool,
    diagnostics: &mut Vec<String>,
) -> Option<ParsedNk> {
    if payload.len() < 0x4C || &payload[0..2] != b"nk" {
        return None;
    }
    let flags = read_u16_le(payload, 0x02)?;
    let ft_raw = read_u64_le(payload, 0x04)?;
    let last_write_time = filetime_to_utc(ft_raw);
    let parent_offset = read_u32_le(payload, 0x10)?;
    let subkey_count = read_u32_le(payload, 0x14)?;
    let subkeys_list_offset = read_u32_le(payload, 0x1C)?;
    let value_count = read_u32_le(payload, 0x24)?;
    let value_list_offset = read_u32_le(payload, 0x28)?;
    let name_len = usize::from(read_u16_le(payload, 0x48)?);

    let name_end = match 0x4Cusize.checked_add(name_len) {
        Some(end) if end <= payload.len() => end,
        _ => {
            if tolerant {
                diagnostics.push(format!("clamped truncated nk name at cell 0x{rel_offset:08x}"));
                payload.len()
            } else {
                diagnostics.push(format!("nk name exceeds cell payload at 0x{rel_offset:08x}"));
                return None;
            }
        }
    };
    let compressed = (flags & KEY_COMP_NAME) != 0;
    let name = decode_regf_name(&payload[0x4C..name_end], compressed);

    Some(ParsedNk {
        flags,
        last_write_time,
        parent_offset,
        subkey_count,
        subkeys_list_offset,
        value_count,
        value_list_offset,
        name,
    })
}

fn read_big_data(
    bytes: &[u8],
    db_payload: &[u8],
    data_len: usize,
    tolerant: bool,
    diagnostics: &mut Vec<String>,
) -> Vec<u8> {
    if db_payload.len() < 8 || &db_payload[0..2] != b"db" {
        return Vec::new();
    }
    let seg_count = usize::from(read_u16_le(db_payload, 0x02).unwrap_or(0));
    let seg_list_off = read_u32_le(db_payload, 0x04).unwrap_or(u32::MAX);
    let Some(list_cell) = read_cell_at(bytes, seg_list_off, tolerant, diagnostics) else {
        return Vec::new();
    };
    let max_entries = list_cell.payload.len() / 4;
    let count = seg_count.min(max_entries);
    if seg_count > max_entries {
        diagnostics.push(format!(
            "db segment list truncated: declared {seg_count}, available {max_entries}"
        ));
    }

    let capped_len = data_len.min(bytes.len());
    let mut out = Vec::with_capacity(capped_len.min(MAX_BIG_DATA_CHUNK * count.max(1)));
    for idx in 0..count {
        if out.len() >= capped_len {
            break;
        }
        let Some(seg_off) = read_u32_le(list_cell.payload, idx * 4) else {
            break;
        };
        let Some(seg_cell) = read_cell_at(bytes, seg_off, tolerant, diagnostics) else {
            break;
        };
        let remaining = capped_len - out.len();
        let take = remaining.min(seg_cell.payload.len()).min(MAX_BIG_DATA_CHUNK);
        out.extend_from_slice(&seg_cell.payload[..take]);
    }
    out
}

fn parse_vk_cell(
    bytes: &[u8],
    vk_offset: u32,
    is_deleted: bool,
    tolerant: bool,
    diagnostics: &mut Vec<String>,
) -> Option<RegValue> {
    let cell = read_cell_at(bytes, vk_offset, tolerant, diagnostics)?;
    let payload = cell.payload;
    if payload.len() < 0x14 || &payload[0..2] != b"vk" {
        diagnostics.push(format!("invalid vk signature/length at 0x{vk_offset:08x}"));
        return None;
    }

    let name_len = usize::from(read_u16_le(payload, 0x02)?);
    let raw_data_length = read_u32_le(payload, 0x04)?;
    let data_offset = read_u32_le(payload, 0x08)?;
    let raw_type = read_u32_le(payload, 0x0C)?;
    let flags = read_u16_le(payload, 0x10)?;

    let name_end = match 0x14usize.checked_add(name_len) {
        Some(end) if end <= payload.len() => end,
        _ => {
            if tolerant {
                diagnostics.push(format!("clamped truncated vk name at 0x{vk_offset:08x}"));
                payload.len()
            } else {
                diagnostics.push(format!("vk name exceeds cell payload at 0x{vk_offset:08x}"));
                return None;
            }
        }
    };
    let name = if name_len == 0 {
        String::new()
    } else {
        decode_regf_name(&payload[0x14..name_end], (flags & VALUE_COMP_NAME) != 0)
    };

    let is_inline = (raw_data_length & 0x8000_0000) != 0;
    let data_len = (raw_data_length & 0x7FFF_FFFF) as usize;

    let raw_bytes = if is_inline {
        if data_len > 4 {
            diagnostics.push(format!(
                "inline vk at 0x{vk_offset:08x} claims data_len={data_len} (>4); clamping to 4"
            ));
        }
        let len = data_len.min(4);
        payload[0x08..0x08 + len].to_vec()
    } else if data_len == 0 {
        Vec::new()
    } else if data_len > bytes.len() {
        diagnostics.push(format!(
            "vk at 0x{vk_offset:08x} claims data_len={data_len} > hive size ({}); skipping payload",
            bytes.len()
        ));
        Vec::new()
    } else if let Some(data_cell) = read_cell_at(bytes, data_offset, tolerant, diagnostics) {
        if data_len > MAX_BIG_DATA_CHUNK && data_cell.payload.len() >= 8 && data_cell.payload.starts_with(b"db") {
            read_big_data(bytes, data_cell.payload, data_len, tolerant, diagnostics)
        } else {
            if data_cell.payload.len() < data_len {
                diagnostics.push(format!(
                    "vk data cell at 0x{data_offset:08x} truncated ({} < {data_len})",
                    data_cell.payload.len()
                ));
            }
            let take = data_len.min(data_cell.payload.len());
            data_cell.payload[..take].to_vec()
        }
    } else {
        Vec::new()
    };

    let data = RegValueData::from_raw(raw_type, &raw_bytes);
    Some(RegValue {
        name,
        raw_type,
        data,
        raw_bytes,
        cell_offset: vk_offset,
        is_deleted,
    })
}

fn read_value_list(
    bytes: &[u8],
    nk: &ParsedNk,
    is_deleted: bool,
    tolerant: bool,
    diagnostics: &mut Vec<String>,
) -> Vec<RegValue> {
    if nk.value_count == 0 || nk.value_list_offset == u32::MAX {
        return Vec::new();
    }
    let Some(list_cell) = read_cell_at(bytes, nk.value_list_offset, tolerant, diagnostics) else {
        return Vec::new();
    };
    let max_entries = list_cell.payload.len() / 4;
    let count = (nk.value_count as usize).min(max_entries);
    if (nk.value_count as usize) > max_entries {
        diagnostics.push(format!(
            "value list at 0x{:08x} truncated: declared {}, available {}",
            nk.value_list_offset, nk.value_count, max_entries
        ));
    }

    let mut values = Vec::with_capacity(count);
    for idx in 0..count {
        if let Some(vk_off) = read_u32_le(list_cell.payload, idx * 4)
            && let Some(val) = parse_vk_cell(bytes, vk_off, is_deleted, tolerant, diagnostics)
        {
            values.push(val);
        }
    }
    values
}

fn collect_subkey_offsets(
    bytes: &[u8],
    list_offset: u32,
    depth: usize,
    visited_lists: &mut HashSet<u32>,
    tolerant: bool,
    diagnostics: &mut Vec<String>,
    out: &mut Vec<u32>,
) {
    if list_offset == u32::MAX {
        return;
    }
    if depth > MAX_LIST_DEPTH {
        diagnostics.push(format!(
            "subkey list depth exceeded {MAX_LIST_DEPTH} at 0x{list_offset:08x}"
        ));
        return;
    }
    if !visited_lists.insert(list_offset) {
        diagnostics.push(format!("cycle detected in subkey list at 0x{list_offset:08x}"));
        return;
    }
    let Some(cell) = read_cell_at(bytes, list_offset, tolerant, diagnostics) else {
        return;
    };
    let payload = cell.payload;
    if payload.len() < 4 {
        diagnostics.push(format!("undersized subkey list at 0x{list_offset:08x}"));
        return;
    }
    let sig = &payload[0..2];
    let declared_count = usize::from(read_u16_le(payload, 2).unwrap_or(0));
    match sig {
        b"lf" | b"lh" => {
            let max_entries = (payload.len() - 4) / 8;
            let count = declared_count.min(max_entries);
            if declared_count > max_entries {
                diagnostics.push(format!(
                    "subkey list {:?} at 0x{list_offset:08x} truncated ({declared_count} > {max_entries})",
                    String::from_utf8_lossy(sig)
                ));
            }
            for i in 0..count {
                if let Some(nk_off) = read_u32_le(payload, 4 + i * 8) {
                    out.push(nk_off);
                }
            }
        }
        b"li" => {
            let max_entries = (payload.len() - 4) / 4;
            let count = declared_count.min(max_entries);
            if declared_count > max_entries {
                diagnostics.push(format!(
                    "subkey list li at 0x{list_offset:08x} truncated ({declared_count} > {max_entries})"
                ));
            }
            for i in 0..count {
                if let Some(nk_off) = read_u32_le(payload, 4 + i * 4) {
                    out.push(nk_off);
                }
            }
        }
        b"ri" => {
            let max_entries = (payload.len() - 4) / 4;
            let count = declared_count.min(max_entries);
            if declared_count > max_entries {
                diagnostics.push(format!(
                    "subkey list ri at 0x{list_offset:08x} truncated ({declared_count} > {max_entries})"
                ));
            }
            for i in 0..count {
                if let Some(sub_off) = read_u32_le(payload, 4 + i * 4) {
                    collect_subkey_offsets(bytes, sub_off, depth + 1, visited_lists, tolerant, diagnostics, out);
                }
            }
        }
        _ => {
            diagnostics.push(format!(
                "unknown subkey list signature {:02x} {:02x} at 0x{list_offset:08x}",
                sig[0], sig[1]
            ));
        }
    }
}

struct TraverseCtx<'a> {
    bytes: &'a [u8],
    tolerant: bool,
    nodes: Vec<RegKeyNode>,
    visited_keys: HashSet<u32>,
    visited_lists: HashSet<u32>,
    active_paths: HashMap<u32, String>,
    diagnostics: Vec<String>,
}

impl<'a> TraverseCtx<'a> {
    fn visit_nk(&mut self, rel_offset: u32, parent_path: Option<&str>, depth: usize) -> Option<usize> {
        if depth > MAX_KEY_DEPTH {
            self.diagnostics
                .push(format!("max key depth {MAX_KEY_DEPTH} exceeded at 0x{rel_offset:08x}"));
            return None;
        }
        if !self.visited_keys.insert(rel_offset) {
            self.diagnostics
                .push(format!("cycle or duplicate nk offset 0x{rel_offset:08x}"));
            return None;
        }
        let cell = read_cell_at(self.bytes, rel_offset, self.tolerant, &mut self.diagnostics)?;
        let nk = parse_nk_payload(cell.payload, rel_offset, self.tolerant, &mut self.diagnostics)?;

        let path = match parent_path {
            None => String::new(),
            Some("") => nk.name.clone(),
            Some(p) => format!("{p}\\{}", nk.name),
        };
        self.active_paths.insert(rel_offset, path.clone());

        let values = read_value_list(self.bytes, &nk, false, self.tolerant, &mut self.diagnostics);

        let mut child_offsets = Vec::new();
        if nk.subkey_count > 0 && nk.subkeys_list_offset != u32::MAX {
            collect_subkey_offsets(
                self.bytes,
                nk.subkeys_list_offset,
                0,
                &mut self.visited_lists,
                self.tolerant,
                &mut self.diagnostics,
                &mut child_offsets,
            );
        }

        let node_idx = self.nodes.len();
        self.nodes.push(RegKeyNode {
            name: nk.name,
            path: path.clone(),
            flags: nk.flags,
            last_write_time: nk.last_write_time,
            declared_subkey_count: nk.subkey_count,
            cell_offset: rel_offset,
            is_deleted: !cell.allocated,
            children: Vec::new(),
            values,
        });

        let mut child_indices = Vec::with_capacity(child_offsets.len());
        for child_off in child_offsets {
            if let Some(child_idx) = self.visit_nk(child_off, Some(&path), depth + 1) {
                child_indices.push(child_idx);
            }
        }
        self.nodes[node_idx].children = child_indices;
        Some(node_idx)
    }
}

fn looks_like_carved_nk_name(name: &str) -> bool {
    !name.is_empty() && !name.chars().any(|c| c.is_control())
}

fn try_carve_nk(
    bytes: &[u8],
    payload: &[u8],
    rel_offset: u32,
    reason: &str,
    diagnostics: &mut Vec<String>,
) -> Option<(ParsedNk, Vec<RegValue>, String)> {
    if payload.len() < 0x4C || &payload[0..2] != b"nk" {
        return None;
    }
    let name_len = usize::from(read_u16_le(payload, 0x48)?);
    if name_len == 0 || name_len > 512 || 0x4C + name_len > payload.len() {
        return None;
    }
    let subkey_count = read_u32_le(payload, 0x14)?;
    let value_count = read_u32_le(payload, 0x24)?;
    if subkey_count > 1_000_000 || value_count > 100_000 {
        return None;
    }
    let ft_raw = read_u64_le(payload, 0x04)?;
    if ft_raw != 0 && filetime_to_utc(ft_raw).is_none() {
        return None;
    }

    let mut scratch_diag = Vec::new();
    let nk = parse_nk_payload(payload, rel_offset, true, &mut scratch_diag)?;
    if !looks_like_carved_nk_name(&nk.name) {
        return None;
    }

    let values = if nk.value_count > 0 && nk.value_list_offset != u32::MAX {
        let mut val_diag = Vec::new();
        let vals = read_value_list(bytes, &nk, true, true, &mut val_diag);
        diagnostics.extend(val_diag);
        vals
    } else {
        Vec::new()
    };

    Some((nk, values, reason.to_owned()))
}

fn carve_hbin_cells(
    bytes: &[u8],
    header: &RegfHeader,
    reachable_nk_offsets: &HashSet<u32>,
    active_paths: &HashMap<u32, String>,
    tolerant: bool,
    diagnostics: &mut Vec<String>,
) -> Vec<RecoveredKey> {
    struct RawRecovered {
        nk: ParsedNk,
        rel_offset: u32,
        values: Vec<RegValue>,
        reason: String,
    }

    let mut raw_found: Vec<RawRecovered> = Vec::new();
    let mut seen_offsets: HashSet<u32> = HashSet::new();

    let scan_limit = if tolerant || header.hive_bins_data_size == 0 {
        bytes.len()
    } else {
        bytes
            .len()
            .min(HBIN_START.saturating_add(header.hive_bins_data_size as usize))
    };

    let mut pos = HBIN_START;
    while pos + 0x20 <= scan_limit {
        if &bytes[pos..pos + 4] != b"hbin" {
            if tolerant {
                diagnostics.push(format!("missing hbin signature at 0x{pos:x}; scanning forward"));
                pos = pos.saturating_add(0x1000);
                continue;
            } else {
                diagnostics.push(format!("unexpected non-hbin block at 0x{pos:x}"));
                break;
            }
        }

        let bin_size = read_u32_le(bytes, pos + 0x08).unwrap_or(0) as usize;
        let bin_end = if bin_size < 0x20 || !bin_size.is_multiple_of(4096) {
            diagnostics.push(format!("invalid hbin size {bin_size} at 0x{pos:x}"));
            if tolerant {
                (pos + 0x1000).min(scan_limit)
            } else {
                break;
            }
        } else {
            let expected = pos.saturating_add(bin_size);
            if expected > scan_limit {
                diagnostics.push(format!(
                    "truncated hbin at 0x{pos:x} (expected end 0x{expected:x}, EOF 0x{scan_limit:x})"
                ));
            }
            expected.min(scan_limit)
        };

        let mut cell_pos = pos + 0x20;
        while cell_pos + 8 <= bin_end {
            let raw_size = read_i32_le(bytes, cell_pos).unwrap_or(0);
            if raw_size == 0 {
                break;
            }
            let allocated = raw_size < 0;
            let cell_len = raw_size.unsigned_abs() as usize;
            if cell_len < 8 {
                diagnostics.push(format!("invalid cell length {cell_len} at 0x{cell_pos:x}"));
                break;
            }
            let cell_end = if cell_pos.saturating_add(cell_len) <= bin_end {
                cell_pos + cell_len
            } else if tolerant {
                diagnostics.push(format!("clamped cell at 0x{cell_pos:x} to hbin end 0x{bin_end:x}"));
                bin_end
            } else {
                break;
            };

            let rel_offset = (cell_pos - HBIN_START) as u32;
            let payload = &bytes[cell_pos + 4..cell_end];

            if !allocated {
                // Scan start of free cell and 8-byte aligned sub-offsets inside coalesced free blocks.
                let mut inner = 0usize;
                while inner + 0x4C <= payload.len() {
                    if &payload[inner..inner + 2] == b"nk" {
                        let sub_rel = rel_offset.saturating_add(inner as u32);
                        if !reachable_nk_offsets.contains(&sub_rel)
                            && seen_offsets.insert(sub_rel)
                            && let Some((nk, values, reason)) =
                                try_carve_nk(bytes, &payload[inner..], sub_rel, "unallocated_nk", diagnostics)
                        {
                            let raw_name_len = usize::from(read_u16_le(&payload[inner..], 0x48).unwrap_or(0));
                            let advance = (0x4C + raw_name_len + 7) & !7;
                            raw_found.push(RawRecovered {
                                nk,
                                rel_offset: sub_rel,
                                values,
                                reason,
                            });
                            inner = inner.saturating_add(advance.max(8));
                            continue;
                        }
                    }
                    inner = inner.saturating_add(8);
                }
            } else if payload.starts_with(b"nk")
                && !reachable_nk_offsets.contains(&rel_offset)
                && seen_offsets.insert(rel_offset)
                && let Some((nk, values, reason)) =
                    try_carve_nk(bytes, payload, rel_offset, "orphaned_allocated_nk", diagnostics)
            {
                raw_found.push(RawRecovered {
                    nk,
                    rel_offset,
                    values,
                    reason,
                });
            }

            if cell_end == bin_end && cell_pos + cell_len > bin_end {
                break;
            }
            cell_pos = cell_end;
        }

        pos = if bin_size >= 0x20 && bin_size.is_multiple_of(4096) {
            pos.saturating_add(bin_size)
        } else {
            pos.saturating_add(0x1000)
        };
    }

    let recovered_by_offset: HashMap<u32, (String, u32)> = raw_found
        .iter()
        .map(|r| (r.rel_offset, (r.nk.name.clone(), r.nk.parent_offset)))
        .collect();

    raw_found
        .into_iter()
        .map(|item| {
            let mut segments = vec![item.nk.name.clone()];
            let mut cur_parent = item.nk.parent_offset;
            let mut visited = HashSet::new();
            visited.insert(item.rel_offset);
            let mut reached_active = None;
            for _ in 0..MAX_KEY_DEPTH {
                if cur_parent == u32::MAX || !visited.insert(cur_parent) {
                    break;
                }
                if let Some(active) = active_paths.get(&cur_parent) {
                    reached_active = Some(active.clone());
                    break;
                }
                if let Some((pname, next_parent)) = recovered_by_offset.get(&cur_parent) {
                    segments.push(pname.clone());
                    cur_parent = *next_parent;
                } else {
                    break;
                }
            }
            segments.reverse();
            let joined = segments.join("\\");
            let path = match reached_active {
                Some(prefix) if prefix.is_empty() => joined,
                Some(prefix) => format!("{prefix}\\{joined}"),
                None => format!("[Recovered]\\{joined}"),
            };

            RecoveredKey {
                name: item.nk.name,
                path,
                cell_offset: item.rel_offset,
                parent_offset: item.nk.parent_offset,
                last_write_time: item.nk.last_write_time,
                values: item.values,
                reason: item.reason,
                is_deleted: true,
            }
        })
        .collect()
}

pub(crate) fn parse_regf_bytes(bytes: &[u8], tolerant: bool) -> Result<RegfHive, ForensicError> {
    let mut diagnostics = Vec::new();
    let header = parse_header(bytes, tolerant, &mut diagnostics)?;

    let mut ctx = TraverseCtx {
        bytes,
        tolerant,
        nodes: Vec::new(),
        visited_keys: HashSet::new(),
        visited_lists: HashSet::new(),
        active_paths: HashMap::new(),
        diagnostics,
    };

    let root_idx = if header.root_cell_offset != u32::MAX {
        ctx.visit_nk(header.root_cell_offset, None, 0)
    } else {
        None
    };

    if root_idx.is_none() {
        if !tolerant {
            return Err(ForensicError::parse(
                "regf",
                format!(
                    "unable to parse root nk cell at offset 0x{:08x}",
                    header.root_cell_offset
                ),
            ));
        }
        ctx.diagnostics.push(format!(
            "root nk cell at 0x{:08x} unreadable; relying on carved hbin recovery",
            header.root_cell_offset
        ));
    }

    let recovered = carve_hbin_cells(
        bytes,
        &header,
        &ctx.visited_keys,
        &ctx.active_paths,
        tolerant,
        &mut ctx.diagnostics,
    );

    Ok(RegfHive {
        header,
        nodes: ctx.nodes,
        root_idx,
        recovered,
        diagnostics: ctx.diagnostics,
    })
}
