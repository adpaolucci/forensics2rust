#![forbid(unsafe_code)]

//! Pure-Rust `[MS-CFB]` Compound File Binary Format (OLE2/CFBF) container reader
//! with strict cycle detection and bounds checking.

use std::collections::HashSet;

use forensics2rust_core::{ForensicError, read_utf16_le};
use serde::{Deserialize, Serialize};

pub const CFBF_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

const FREESECT: u32 = 0xFFFF_FFFF;
const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
const FATSECT: u32 = 0xFFFF_FFFD;
const DIFSECT: u32 = 0xFFFF_FFFC;
const MAXREGSECT: u32 = 0xFFFF_FFFA;

const MAX_SECTORS_CAP: usize = 262_144;
const MAX_STREAM_CAP: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfbfDirectoryEntry {
    pub name: String,
    pub object_type: u8,
    pub start_sector: u32,
    pub stream_size: u64,
}

#[derive(Debug, Clone)]
pub struct CfbfFile {
    data: Vec<u8>,
    sector_size: usize,
    mini_sector_size: usize,
    mini_stream_cutoff: u64,
    fat: Vec<u32>,
    minifat: Vec<u32>,
    ministream: Vec<u8>,
    entries: Vec<CfbfDirectoryEntry>,
}

fn read_u16_le(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn read_u32_le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn read_u64_le(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ])
}

impl CfbfFile {
    pub fn parse(bytes: &[u8]) -> Result<Self, ForensicError> {
        if bytes.len() < 512 {
            return Err(ForensicError::parse(
                "CFBF",
                format!("buffer too short ({} bytes; expected >= 512)", bytes.len()),
            ));
        }
        if bytes[0..8] != CFBF_MAGIC {
            return Err(ForensicError::parse("CFBF", "invalid CFBF magic signature"));
        }

        let byte_order = read_u16_le(bytes, 0x1C);
        if byte_order != 0xFFFE {
            return Err(ForensicError::parse(
                "CFBF",
                format!("unexpected byte order 0x{byte_order:04X}"),
            ));
        }

        let sector_shift = read_u16_le(bytes, 0x1E);
        if sector_shift != 9 && sector_shift != 12 {
            return Err(ForensicError::parse(
                "CFBF",
                format!("unsupported sector shift {sector_shift} (expected 9 or 12)"),
            ));
        }
        let sector_size = 1usize << sector_shift;

        let mini_sector_shift = read_u16_le(bytes, 0x20);
        if mini_sector_shift > sector_shift || mini_sector_shift == 0 {
            return Err(ForensicError::parse(
                "CFBF",
                format!("invalid mini sector shift {mini_sector_shift}"),
            ));
        }
        let mini_sector_size = 1usize << mini_sector_shift;

        let num_fat_sectors = read_u32_le(bytes, 0x2C) as usize;
        let first_dir_sector = read_u32_le(bytes, 0x30);
        let mini_stream_cutoff = u64::from(read_u32_le(bytes, 0x38));
        let first_minifat_sector = read_u32_le(bytes, 0x3C);
        let num_minifat_sectors = read_u32_le(bytes, 0x40) as usize;
        let first_difat_sector = read_u32_le(bytes, 0x44);
        let num_difat_sectors = read_u32_le(bytes, 0x48) as usize;

        if num_fat_sectors > MAX_SECTORS_CAP || num_difat_sectors > MAX_SECTORS_CAP {
            return Err(ForensicError::parse(
                "CFBF",
                "FAT/DIFAT sector count exceeds safety cap",
            ));
        }

        // Collect DIFAT sector IDs pointing to FAT sectors
        let mut fat_sids = Vec::with_capacity(num_fat_sectors.min(4096));
        for i in 0..109 {
            let sid = read_u32_le(bytes, 0x4C + i * 4);
            if sid != FREESECT && sid <= MAXREGSECT {
                fat_sids.push(sid);
            }
        }

        if num_difat_sectors > 0 && first_difat_sector <= MAXREGSECT {
            let mut cur_difat = first_difat_sector;
            let mut seen_difat = HashSet::new();
            let entries_per_difat = (sector_size / 4).saturating_sub(1);
            for _ in 0..num_difat_sectors {
                if cur_difat == ENDOFCHAIN || cur_difat == FREESECT || cur_difat > MAXREGSECT {
                    break;
                }
                if !seen_difat.insert(cur_difat) {
                    return Err(ForensicError::parse("CFBF", "DIFAT sector cycle detected"));
                }
                let sec = sector_slice(bytes, sector_size, cur_difat)?;
                for j in 0..entries_per_difat {
                    let sid = read_u32_le(sec, j * 4);
                    if sid != FREESECT && sid <= MAXREGSECT {
                        fat_sids.push(sid);
                    }
                }
                cur_difat = read_u32_le(sec, entries_per_difat * 4);
            }
        }

        // Build FAT
        let mut fat = Vec::with_capacity(fat_sids.len().min(4096) * (sector_size / 4));
        for &fat_sid in fat_sids.iter().take(num_fat_sectors.max(fat_sids.len())) {
            let sec = sector_slice(bytes, sector_size, fat_sid)?;
            for chunk in sec.as_chunks::<4>().0 {
                fat.push(u32::from_le_bytes(*chunk));
            }
        }

        // Read Directory chain
        let dir_bytes = read_fat_chain(bytes, sector_size, &fat, first_dir_sector, MAX_STREAM_CAP)?;
        let mut entries = Vec::new();
        for chunk in dir_bytes.as_chunks::<128>().0 {
            let object_type = chunk[0x42];
            if object_type == 0 {
                continue;
            }
            let name_byte_len = (read_u16_le(chunk, 0x40) as usize).min(64);
            let raw_name = if name_byte_len >= 2 {
                read_utf16_le(&chunk[..name_byte_len])
            } else {
                String::new()
            };
            let name = raw_name.trim_end_matches('\0').to_string();
            let start_sector = read_u32_le(chunk, 0x74);
            let raw_size = read_u64_le(chunk, 0x78);
            let stream_size = if sector_shift == 9 {
                raw_size & 0xFFFF_FFFF
            } else {
                raw_size
            };
            entries.push(CfbfDirectoryEntry {
                name,
                object_type,
                start_sector,
                stream_size,
            });
        }

        // Read MiniFAT & MiniStream
        let mut minifat = Vec::new();
        if num_minifat_sectors > 0 && first_minifat_sector <= MAXREGSECT {
            let minifat_bytes = read_fat_chain(bytes, sector_size, &fat, first_minifat_sector, MAX_STREAM_CAP)?;
            for chunk in minifat_bytes.as_chunks::<4>().0 {
                minifat.push(u32::from_le_bytes(*chunk));
            }
        }

        let ministream = if let Some(root) = entries.iter().find(|e| e.object_type == 5) {
            if root.start_sector <= MAXREGSECT && root.stream_size > 0 {
                let cap = usize::try_from(root.stream_size)
                    .unwrap_or(MAX_STREAM_CAP)
                    .min(MAX_STREAM_CAP);
                let mut raw_ms = read_fat_chain(bytes, sector_size, &fat, root.start_sector, cap)?;
                raw_ms.truncate(cap);
                raw_ms
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Ok(Self {
            data: bytes.to_vec(),
            sector_size,
            mini_sector_size,
            mini_stream_cutoff,
            fat,
            minifat,
            ministream,
            entries,
        })
    }

    pub fn entries(&self) -> &[CfbfDirectoryEntry] {
        &self.entries
    }

    pub fn find_stream(&self, name: &str) -> Option<&CfbfDirectoryEntry> {
        self.entries
            .iter()
            .find(|e| e.object_type == 2 && e.name.eq_ignore_ascii_case(name))
    }

    pub fn read_stream(&self, entry: &CfbfDirectoryEntry) -> Result<Vec<u8>, ForensicError> {
        if entry.stream_size == 0 || entry.start_sector == ENDOFCHAIN || entry.start_sector == FREESECT {
            return Ok(Vec::new());
        }
        let target_len = usize::try_from(entry.stream_size)
            .map_err(|_| ForensicError::parse("CFBF", "stream size exceeds usize"))?;
        if target_len > MAX_STREAM_CAP {
            return Err(ForensicError::parse(
                "CFBF",
                format!("stream '{}' size {target_len} exceeds safety cap", entry.name),
            ));
        }

        let mut out = if entry.object_type == 2 && entry.stream_size < self.mini_stream_cutoff {
            read_minifat_chain(
                &self.ministream,
                self.mini_sector_size,
                &self.minifat,
                entry.start_sector,
                target_len,
            )?
        } else {
            read_fat_chain(&self.data, self.sector_size, &self.fat, entry.start_sector, target_len)?
        };
        out.truncate(target_len);
        Ok(out)
    }
}

fn sector_slice(data: &[u8], sector_size: usize, sid: u32) -> Result<&[u8], ForensicError> {
    let offset = (sid as usize)
        .checked_add(1)
        .and_then(|s| s.checked_mul(sector_size))
        .ok_or_else(|| ForensicError::parse("CFBF", format!("sector ID {sid} offset overflow")))?;
    let end = offset
        .checked_add(sector_size)
        .ok_or_else(|| ForensicError::parse("CFBF", "sector end overflow"))?;
    data.get(offset..end).ok_or_else(|| {
        ForensicError::parse(
            "CFBF",
            format!(
                "sector {sid} (bytes {offset}..{end}) out of bounds (len {})",
                data.len()
            ),
        )
    })
}

fn read_fat_chain(
    data: &[u8],
    sector_size: usize,
    fat: &[u32],
    start_sid: u32,
    max_bytes: usize,
) -> Result<Vec<u8>, ForensicError> {
    if start_sid == ENDOFCHAIN || start_sid == FREESECT {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut cur = start_sid;
    let max_iters = fat.len().clamp(1, MAX_SECTORS_CAP);

    for _ in 0..max_iters {
        if cur == ENDOFCHAIN || cur == FREESECT {
            return Ok(out);
        }
        if cur == FATSECT || cur == DIFSECT || cur > MAXREGSECT {
            return Err(ForensicError::parse(
                "CFBF",
                format!("unexpected special sector ID 0x{cur:08X} in FAT chain"),
            ));
        }
        if !seen.insert(cur) {
            return Err(ForensicError::parse(
                "CFBF",
                format!("FAT chain cycle detected at sector {cur}"),
            ));
        }
        let sec = sector_slice(data, sector_size, cur)?;
        out.extend_from_slice(sec);
        if out.len() >= max_bytes {
            return Ok(out);
        }
        cur = *fat
            .get(cur as usize)
            .ok_or_else(|| ForensicError::parse("CFBF", format!("FAT chain sector {cur} out of FAT bounds")))?;
    }

    Err(ForensicError::parse("CFBF", "FAT chain exceeded maximum sector count"))
}

fn read_minifat_chain(
    ministream: &[u8],
    mini_sector_size: usize,
    minifat: &[u32],
    start_sid: u32,
    max_bytes: usize,
) -> Result<Vec<u8>, ForensicError> {
    if start_sid == ENDOFCHAIN || start_sid == FREESECT {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut cur = start_sid;
    let max_iters = minifat.len().clamp(1, MAX_SECTORS_CAP);

    for _ in 0..max_iters {
        if cur == ENDOFCHAIN || cur == FREESECT {
            return Ok(out);
        }
        if cur > MAXREGSECT {
            return Err(ForensicError::parse(
                "CFBF",
                format!("invalid MiniFAT sector ID 0x{cur:08X}"),
            ));
        }
        if !seen.insert(cur) {
            return Err(ForensicError::parse(
                "CFBF",
                format!("MiniFAT chain cycle detected at mini-sector {cur}"),
            ));
        }
        let off = (cur as usize).saturating_mul(mini_sector_size);
        let end = off.saturating_add(mini_sector_size);
        let sec = ministream.get(off..end).ok_or_else(|| {
            ForensicError::parse(
                "CFBF",
                format!(
                    "mini-sector {cur} ({off}..{end}) exceeds MiniStream len {}",
                    ministream.len()
                ),
            )
        })?;
        out.extend_from_slice(sec);
        if out.len() >= max_bytes {
            return Ok(out);
        }
        cur = *minifat
            .get(cur as usize)
            .ok_or_else(|| ForensicError::parse("CFBF", format!("MiniFAT sector {cur} out of bounds")))?;
    }

    Err(ForensicError::parse(
        "CFBF",
        "MiniFAT chain exceeded maximum sector count",
    ))
}
