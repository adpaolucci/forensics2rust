#![forbid(unsafe_code)]

//! Pure-Rust Windows Prefetch (`SCCA` v17/v23/v26/v30/v31) parser,
//! transparently decompressing `MAM\x04` / `MAM\x84` Win10/11 files.

use std::borrow::Cow;

use chrono::{DateTime, Utc};
use forensics2rust_core::{ForensicError, filetime_to_utc, read_utf16_le, read_utf16_le_nul};
use serde::{Deserialize, Serialize};

use crate::parsers::xca;

const MAX_METRICS_COUNT: usize = 65_536;
const MAX_VOLUMES_COUNT: usize = 1_024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefetchMetric {
    pub start_time_ms: u32,
    pub duration_ms: u32,
    pub avg_duration_ms: Option<u32>,
    pub filename: Option<String>,
    pub flags: u32,
    pub mft_file_ref: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefetchVolume {
    pub device_path: String,
    pub creation_time: Option<DateTime<Utc>>,
    pub serial_number: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefetchFile {
    pub version: u32,
    pub compressed: bool,
    pub file_size: u32,
    pub executable_name: String,
    pub prefetch_hash: u32,
    pub flags: u32,
    pub run_count: u32,
    pub last_run_times: Vec<DateTime<Utc>>,
    pub loaded_files: Vec<String>,
    pub metrics: Vec<PrefetchMetric>,
    pub volumes: Vec<PrefetchVolume>,
    pub process_path: String,
}

fn read_u32_le(data: &[u8], off: usize) -> Result<u32, ForensicError> {
    let slice = data
        .get(off..off + 4)
        .ok_or_else(|| ForensicError::parse("SCCA", format!("truncated u32 at offset 0x{off:X}")))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64_le(data: &[u8], off: usize) -> Result<u64, ForensicError> {
    let slice = data
        .get(off..off + 8)
        .ok_or_else(|| ForensicError::parse("SCCA", format!("truncated u64 at offset 0x{off:X}")))?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

/// Parses a Windows `.pf` Prefetch file (either compressed `MAM\x04`/`MAM\x84` or raw `SCCA`).
pub fn parse_prefetch(raw: &[u8]) -> Result<PrefetchFile, ForensicError> {
    let (data, compressed): (Cow<'_, [u8]>, bool) = if raw.starts_with(b"MAM") {
        (Cow::Owned(xca::decompress_mam(raw)?), true)
    } else {
        (Cow::Borrowed(raw), false)
    };

    if data.len() < 84 {
        return Err(ForensicError::parse(
            "SCCA",
            format!("Prefetch data too short ({} bytes; expected >= 84)", data.len()),
        ));
    }
    if &data[4..8] != b"SCCA" {
        return Err(ForensicError::parse("SCCA", "invalid SCCA signature at offset 0x04"));
    }

    let version = read_u32_le(&data, 0x00)?;
    let file_size = read_u32_le(&data, 0x0C)?;
    let executable_name = read_utf16_le_nul(&data[0x10..0x4C]);
    let prefetch_hash = read_u32_le(&data, 0x4C)?;
    let flags = read_u32_le(&data, 0x50)?;

    if data.len() < 0x94 {
        return Err(ForensicError::parse(
            "SCCA",
            format!("Prefetch file info truncated ({} bytes)", data.len()),
        ));
    }

    let metrics_offset = read_u32_le(&data, 0x54)? as usize;
    let metrics_count = (read_u32_le(&data, 0x58)? as usize).min(MAX_METRICS_COUNT);
    let filename_strings_offset = read_u32_le(&data, 0x64)? as usize;
    let filename_strings_size = read_u32_le(&data, 0x68)? as usize;
    let volumes_info_offset = read_u32_le(&data, 0x6C)? as usize;
    let volumes_count = (read_u32_le(&data, 0x70)? as usize).min(MAX_VOLUMES_COUNT);
    let _volumes_info_size = read_u32_le(&data, 0x74)? as usize;

    let (last_run_times, run_count, metric_entry_size, volume_entry_size) = match version {
        17 => {
            let ft = read_u64_le(&data, 0x78)?;
            let rc = read_u32_le(&data, 0x90)?;
            let runs = filetime_to_utc(ft).into_iter().collect();
            (runs, rc, 20usize, 40usize)
        }
        23 => {
            if data.len() < 0x9C {
                return Err(ForensicError::parse("SCCA", "truncated v23 FileInfo"));
            }
            let ft = read_u64_le(&data, 0x80)?;
            let rc = read_u32_le(&data, 0x98)?;
            let runs = filetime_to_utc(ft).into_iter().collect();
            (runs, rc, 32usize, 104usize)
        }
        26 => {
            if data.len() < 0xD4 {
                return Err(ForensicError::parse("SCCA", "truncated v26 FileInfo"));
            }
            let mut runs = Vec::new();
            for i in 0..8 {
                let ft = read_u64_le(&data, 0x80 + i * 8)?;
                if let Some(dt) = filetime_to_utc(ft) {
                    runs.push(dt);
                }
            }
            let rc = read_u32_le(&data, 0xD0)?;
            (runs, rc, 32usize, 104usize)
        }
        30 | 31 => {
            if data.len() < 0xCC {
                return Err(ForensicError::parse("SCCA", "truncated v30/v31 FileInfo"));
            }
            let mut runs = Vec::new();
            for i in 0..8 {
                let ft = read_u64_le(&data, 0x80 + i * 8)?;
                if let Some(dt) = filetime_to_utc(ft) {
                    runs.push(dt);
                }
            }
            let rc = if metrics_offset == 0x130 {
                if data.len() < 0xD4 {
                    return Err(ForensicError::parse("SCCA", "truncated v30 (0x130) run_count"));
                }
                read_u32_le(&data, 0xD0)?
            } else {
                read_u32_le(&data, 0xC8)?
            };
            (runs, rc, 32usize, 96usize)
        }
        other => {
            return Err(ForensicError::parse(
                "SCCA",
                format!("unsupported SCCA version {other}"),
            ));
        }
    };

    // Filename strings section
    let mut loaded_files = Vec::new();
    let fn_end = filename_strings_offset.saturating_add(filename_strings_size);
    if filename_strings_size > 0 && fn_end <= data.len() {
        let fn_slice = &data[filename_strings_offset..fn_end];
        let mut start = 0usize;
        for (idx, chunk) in fn_slice.as_chunks::<2>().0.iter().enumerate() {
            if u16::from_le_bytes(*chunk) == 0 {
                let byte_end = idx * 2;
                if byte_end > start {
                    let s = read_utf16_le(&fn_slice[start..byte_end]);
                    if !s.is_empty() {
                        loaded_files.push(s);
                    }
                }
                start = (idx + 1) * 2;
            }
        }
        if start < fn_slice.len() {
            let s = read_utf16_le(&fn_slice[start..]);
            if !s.is_empty() {
                loaded_files.push(s);
            }
        }
    }

    // Metrics section
    let mut metrics = Vec::new();
    if metrics_count > 0 && metrics_offset < data.len() {
        for i in 0..metrics_count {
            let entry_off = metrics_offset.saturating_add(i * metric_entry_size);
            if entry_off + metric_entry_size > data.len() {
                break;
            }
            let (start_time_ms, duration_ms, avg_duration_ms, fn_off, fn_len, m_flags, mft_file_ref) = if version == 17
            {
                (
                    read_u32_le(&data, entry_off)?,
                    read_u32_le(&data, entry_off + 4)?,
                    None,
                    read_u32_le(&data, entry_off + 8)? as usize,
                    read_u32_le(&data, entry_off + 12)? as usize,
                    read_u32_le(&data, entry_off + 16)?,
                    None,
                )
            } else {
                (
                    read_u32_le(&data, entry_off)?,
                    read_u32_le(&data, entry_off + 4)?,
                    Some(read_u32_le(&data, entry_off + 8)?),
                    read_u32_le(&data, entry_off + 12)? as usize,
                    read_u32_le(&data, entry_off + 16)? as usize,
                    read_u32_le(&data, entry_off + 20)?,
                    Some(read_u64_le(&data, entry_off + 24)?),
                )
            };

            let abs_fn_off = filename_strings_offset.saturating_add(fn_off);
            let abs_fn_end = abs_fn_off.saturating_add(fn_len.saturating_mul(2));
            let filename = if fn_len > 0 && abs_fn_end <= data.len() {
                Some(read_utf16_le_nul(&data[abs_fn_off..abs_fn_end]))
            } else {
                None
            };
            metrics.push(PrefetchMetric {
                start_time_ms,
                duration_ms,
                avg_duration_ms,
                filename,
                flags: m_flags,
                mft_file_ref,
            });
        }
    }

    // Volumes section
    let mut volumes = Vec::new();
    if volumes_count > 0 && volumes_info_offset < data.len() {
        for i in 0..volumes_count {
            let vol_off = volumes_info_offset.saturating_add(i * volume_entry_size);
            if vol_off + 20 > data.len() {
                break;
            }
            let dev_rel_off = read_u32_le(&data, vol_off)? as usize;
            let dev_len_chars = read_u32_le(&data, vol_off + 4)? as usize;
            let creation_ft = read_u64_le(&data, vol_off + 8)?;
            let serial_number = read_u32_le(&data, vol_off + 16)?;
            let abs_dev_off = volumes_info_offset.saturating_add(dev_rel_off);
            let abs_dev_end = abs_dev_off.saturating_add(dev_len_chars.saturating_mul(2));
            let device_path = if dev_len_chars > 0 && abs_dev_end <= data.len() {
                read_utf16_le_nul(&data[abs_dev_off..abs_dev_end])
            } else {
                String::new()
            };
            volumes.push(PrefetchVolume {
                device_path,
                creation_time: filetime_to_utc(creation_ft),
                serial_number,
            });
        }
    }

    let process_path = loaded_files
        .iter()
        .find(|p| {
            let base = p.rsplit(['\\', '/']).next().unwrap_or(p);
            base.eq_ignore_ascii_case(&executable_name)
        })
        .cloned()
        .unwrap_or_else(|| executable_name.clone());

    Ok(PrefetchFile {
        version,
        compressed,
        file_size,
        executable_name,
        prefetch_hash,
        flags,
        run_count,
        last_run_times,
        loaded_files,
        metrics,
        volumes,
        process_path,
    })
}
