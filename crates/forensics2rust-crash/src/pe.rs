use std::collections::HashMap;
use std::path::Path;

use forensics2rust_core::ForensicError;
use serde::{Deserialize, Serialize};

/// An exported symbol entry parsed from a PE32 / PE32+ `IMAGE_EXPORT_DIRECTORY`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeExport {
    pub ordinal: u32,
    pub rva: u32,
    pub name: String,
    pub forwarder: Option<String>,
}

/// Resolved export match for a target RVA inside a PE module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportMatch {
    pub name: String,
    pub ordinal: u32,
    pub export_rva: u32,
    pub displacement: u32,
}

impl ExportMatch {
    pub fn format_symbol(&self, module_name: &str) -> String {
        if self.displacement == 0 {
            format!("{module_name}!{}", self.name)
        } else {
            format!("{module_name}!{}+0x{:x}", self.name, self.displacement)
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PeSection {
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
}

/// Pure-Rust PE32 / PE32+ export table parser (zero DLL injection, read-only).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeImageExports {
    pub is_pe64: bool,
    pub exports: Vec<PeExport>,
}

fn read_u16(data: &[u8], off: usize) -> Result<u16, ForensicError> {
    let s = off
        .checked_add(2)
        .and_then(|end| data.get(off..end))
        .ok_or_else(|| ForensicError::parse("PE", format!("truncated u16 at 0x{off:x}")))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32(data: &[u8], off: usize) -> Result<u32, ForensicError> {
    let s = off
        .checked_add(4)
        .and_then(|end| data.get(off..end))
        .ok_or_else(|| ForensicError::parse("PE", format!("truncated u32 at 0x{off:x}")))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_i32(data: &[u8], off: usize) -> Result<i32, ForensicError> {
    let s = off
        .checked_add(4)
        .and_then(|end| data.get(off..end))
        .ok_or_else(|| ForensicError::parse("PE", format!("truncated i32 at 0x{off:x}")))?;
    Ok(i32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_cstr(data: &[u8], off: usize) -> Option<String> {
    let tail = data.get(off..)?;
    let nul = tail.iter().position(|&b| b == 0).unwrap_or(tail.len().min(512));
    Some(String::from_utf8_lossy(&tail[..nul]).into_owned())
}

fn rva_to_offset(rva: u32, size_of_headers: u32, sections: &[PeSection]) -> Option<usize> {
    if rva < size_of_headers {
        return Some(rva as usize);
    }
    for sec in sections {
        let span = sec.virtual_size.max(sec.size_of_raw_data);
        let end = sec.virtual_address.saturating_add(span);
        if rva >= sec.virtual_address && rva < end {
            let delta = rva - sec.virtual_address;
            if delta < sec.size_of_raw_data {
                return sec.pointer_to_raw_data.checked_add(delta).map(|v| v as usize);
            }
        }
    }
    None
}

impl PeImageExports {
    /// Parses PE32 (`0x010B`) or PE32+ (`0x020B`) `IMAGE_EXPORT_DIRECTORY` from raw image bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ForensicError> {
        if data.len() < 64 {
            return Err(ForensicError::parse("PE", "file too small for IMAGE_DOS_HEADER"));
        }
        if read_u16(data, 0)? != 0x5A4D {
            return Err(ForensicError::parse("PE", "missing MZ signature"));
        }
        let e_lfanew_raw = read_i32(data, 0x3C)?;
        if e_lfanew_raw < 64 {
            return Err(ForensicError::parse("PE", format!("invalid e_lfanew {e_lfanew_raw}")));
        }
        let pe_off = e_lfanew_raw as usize;
        if pe_off.checked_add(24).is_none_or(|end| end > data.len()) {
            return Err(ForensicError::parse("PE", "e_lfanew points past EOF"));
        }
        if &data[pe_off..pe_off + 4] != b"PE\0\0" {
            return Err(ForensicError::parse("PE", "missing PE\\0\\0 signature"));
        }

        let file_hdr = pe_off + 4;
        let num_sections = usize::from(read_u16(data, file_hdr + 2)?);
        let size_of_optional_header = usize::from(read_u16(data, file_hdr + 16)?);

        let opt_off = file_hdr + 20;
        let opt_end = opt_off
            .checked_add(size_of_optional_header)
            .ok_or_else(|| ForensicError::parse("PE", "optional header size overflow"))?;
        if opt_end > data.len() || size_of_optional_header < 2 {
            return Err(ForensicError::parse("PE", "truncated IMAGE_OPTIONAL_HEADER"));
        }

        let magic = read_u16(data, opt_off)?;
        let (is_pe64, rva_count_off, data_dir0_off) = match magic {
            0x010B => (false, opt_off.checked_add(0x5C), opt_off.checked_add(0x60)),
            0x020B => (true, opt_off.checked_add(0x6C), opt_off.checked_add(0x70)),
            other => {
                return Err(ForensicError::parse(
                    "PE",
                    format!("unsupported optional header magic 0x{other:04x}"),
                ));
            }
        };

        let size_of_headers = if size_of_optional_header >= 0x40 {
            let hdr_off = opt_off
                .checked_add(0x3C)
                .ok_or_else(|| ForensicError::parse("PE", "SizeOfHeaders offset overflow"))?;
            read_u32(data, hdr_off)?
        } else {
            0
        };

        let (Some(rva_count_off), Some(data_dir0_off)) = (rva_count_off, data_dir0_off) else {
            return Ok(Self {
                is_pe64,
                exports: Vec::new(),
            });
        };

        let num_rva_and_sizes = if data_dir0_off <= opt_end {
            read_u32(data, rva_count_off)?
        } else {
            0
        };

        if num_rva_and_sizes == 0 || data_dir0_off.checked_add(8).is_none_or(|end| end > opt_end) {
            return Ok(Self {
                is_pe64,
                exports: Vec::new(),
            });
        }

        let export_rva = read_u32(data, data_dir0_off)?;
        let export_size = read_u32(data, data_dir0_off + 4)?;
        if export_rva == 0 || export_size == 0 {
            return Ok(Self {
                is_pe64,
                exports: Vec::new(),
            });
        }

        let sec_table_size = num_sections
            .checked_mul(40)
            .ok_or_else(|| ForensicError::parse("PE", "section table overflow"))?;
        let sec_table_end = opt_end
            .checked_add(sec_table_size)
            .ok_or_else(|| ForensicError::parse("PE", "section table end overflow"))?;
        if sec_table_end > data.len() {
            return Err(ForensicError::parse("PE", "truncated IMAGE_SECTION_HEADER table"));
        }

        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let s = opt_end + i * 40;
            sections.push(PeSection {
                virtual_size: read_u32(data, s + 0x08)?,
                virtual_address: read_u32(data, s + 0x0C)?,
                size_of_raw_data: read_u32(data, s + 0x10)?,
                pointer_to_raw_data: read_u32(data, s + 0x14)?,
            });
        }

        let Some(export_off) = rva_to_offset(export_rva, size_of_headers, &sections) else {
            return Ok(Self {
                is_pe64,
                exports: Vec::new(),
            });
        };
        if export_off.checked_add(40).is_none_or(|end| end > data.len()) {
            return Err(ForensicError::parse("PE", "truncated IMAGE_EXPORT_DIRECTORY"));
        }

        let ordinal_base = read_u32(data, export_off + 0x10)?;
        let num_functions = read_u32(data, export_off + 0x14)? as usize;
        let num_names = read_u32(data, export_off + 0x18)? as usize;
        let addr_of_functions_rva = read_u32(data, export_off + 0x1C)?;
        let addr_of_names_rva = read_u32(data, export_off + 0x20)?;
        let addr_of_ordinals_rva = read_u32(data, export_off + 0x24)?;

        let Some(funcs_off) = rva_to_offset(addr_of_functions_rva, size_of_headers, &sections) else {
            return Ok(Self {
                is_pe64,
                exports: Vec::new(),
            });
        };
        let Some(names_off) = rva_to_offset(addr_of_names_rva, size_of_headers, &sections) else {
            return Ok(Self {
                is_pe64,
                exports: Vec::new(),
            });
        };
        let Some(ords_off) = rva_to_offset(addr_of_ordinals_rva, size_of_headers, &sections) else {
            return Ok(Self {
                is_pe64,
                exports: Vec::new(),
            });
        };

        let safe_names = num_names.min(65_536);
        let export_end_rva = export_rva.saturating_add(export_size);
        let mut exports = Vec::with_capacity(safe_names);

        for i in 0..safe_names {
            let Some(name_rva_pos) = i.checked_mul(4).and_then(|d| names_off.checked_add(d)) else {
                break;
            };
            let Some(ord_pos) = i.checked_mul(2).and_then(|d| ords_off.checked_add(d)) else {
                break;
            };
            if name_rva_pos.checked_add(4).is_none_or(|end| end > data.len())
                || ord_pos.checked_add(2).is_none_or(|end| end > data.len())
            {
                break;
            }
            let name_rva = read_u32(data, name_rva_pos)?;
            let ord_idx = usize::from(read_u16(data, ord_pos)?);
            if ord_idx >= num_functions {
                continue;
            }
            let Some(func_pos) = ord_idx.checked_mul(4).and_then(|d| funcs_off.checked_add(d)) else {
                continue;
            };
            if func_pos.checked_add(4).is_none_or(|end| end > data.len()) {
                continue;
            }
            let func_rva = read_u32(data, func_pos)?;
            if func_rva == 0 {
                continue;
            }
            let Some(name_off) = rva_to_offset(name_rva, size_of_headers, &sections) else {
                continue;
            };
            let Some(name) = read_cstr(data, name_off) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }

            let forwarder = if func_rva >= export_rva && func_rva < export_end_rva {
                rva_to_offset(func_rva, size_of_headers, &sections).and_then(|off| read_cstr(data, off))
            } else {
                None
            };

            exports.push(PeExport {
                ordinal: ordinal_base.saturating_add(ord_idx as u32),
                rva: func_rva,
                name,
                forwarder,
            });
        }

        exports.sort_by_key(|e| e.rva);
        Ok(Self { is_pe64, exports })
    }

    /// Reads and parses a PE binary directly from disk (read-only).
    pub fn from_path(path: &Path) -> Result<Self, ForensicError> {
        let bytes = std::fs::read(path).map_err(|err| ForensicError::io_classified(path.display().to_string(), err))?;
        Self::from_bytes(&bytes)
    }

    /// Resolves `target_rva` to the closest preceding non-forwarded exported symbol within 64 KiB.
    pub fn resolve_rva(&self, target_rva: u32) -> Option<ExportMatch> {
        let mut best: Option<&PeExport> = None;
        for exp in &self.exports {
            if exp.forwarder.is_some() {
                continue;
            }
            if exp.rva <= target_rva {
                match best {
                    Some(prev) if prev.rva >= exp.rva => {}
                    _ => best = Some(exp),
                }
            } else {
                break;
            }
        }
        let exp = best?;
        let disp = target_rva - exp.rva;
        if disp > 0x10_000 {
            return None;
        }
        Some(ExportMatch {
            name: exp.name.clone(),
            ordinal: exp.ordinal,
            export_rva: exp.rva,
            displacement: disp,
        })
    }
}

/// Attempts offline read-only PE export resolution using a per-dump module export cache so each
/// unique on-disk binary is read and parsed at most once.
pub fn resolve_va_with_cache(
    cache: &mut HashMap<String, Option<PeImageExports>>,
    module_path: &str,
    base_of_image: u64,
    target_va: u64,
) -> Option<String> {
    if target_va < base_of_image {
        return None;
    }
    let delta = target_va - base_of_image;
    let rva = u32::try_from(delta).ok()?;
    let exports = if let Some(cached) = cache.get(module_path) {
        cached.as_ref()?
    } else {
        let path = Path::new(module_path);
        let parsed = if path.is_file() {
            PeImageExports::from_path(path).ok()
        } else {
            None
        };
        cache.entry(module_path.to_string()).or_insert(parsed).as_ref()?
    };
    let matched = exports.resolve_rva(rva)?;
    let short_name = module_path.rsplit(['\\', '/']).next().unwrap_or(module_path);
    Some(matched.format_symbol(short_name))
}

/// Attempts offline read-only PE export resolution for a target virtual address given a module path on disk.
pub fn resolve_va_with_disk_pe(module_path: &str, base_of_image: u64, target_va: u64) -> Option<String> {
    let mut cache = HashMap::new();
    resolve_va_with_cache(&mut cache, module_path, base_of_image, target_va)
}
