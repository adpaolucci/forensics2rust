use chrono::{DateTime, Utc};
use forensics2rust_core::{DiagnosticWarning, ForensicError, WarningSeverity, read_utf16_le_nul};
use serde::{Deserialize, Serialize};

use crate::context::{CpuContext, ProcessorArch};

/// `MDMP` magic (`0x504D444D`, little-endian ASCII `"MDMP"`).
pub const MDMP_SIGNATURE: u32 = 0x504D_444D;
/// Expected low 16 bits of `MINIDUMP_HEADER.Version` (`0xA793` = 42899).
pub const MINIDUMP_VERSION: u32 = 0x0000_A793;
/// `VS_FIXEDFILEINFO.dwSignature`.
pub const VS_FFI_SIGNATURE: u32 = 0xFEEF_04BD;

/// `MINIDUMP_STREAM_TYPE` numeric IDs verified against `windows-0.62.2`.
pub mod stream_type {
    pub const UNUSED: u32 = 0;
    pub const THREAD_LIST: u32 = 3;
    pub const MODULE_LIST: u32 = 4;
    pub const MEMORY_LIST: u32 = 5;
    pub const EXCEPTION: u32 = 6;
    pub const SYSTEM_INFO: u32 = 7;
    pub const MEMORY64_LIST: u32 = 9;
    pub const COMMENT_A: u32 = 10;
    pub const COMMENT_W: u32 = 11;
    pub const UNLOADED_MODULE_LIST: u32 = 14;
    pub const MISC_INFO: u32 = 15;
}

/// Parsed 32-byte `MINIDUMP_HEADER`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinidumpHeader {
    pub signature: u32,
    pub version: u32,
    pub number_of_streams: u32,
    pub stream_directory_rva: u32,
    pub checksum: u32,
    pub time_date_stamp: u32,
    pub timestamp_utc: Option<DateTime<Utc>>,
    pub flags: u64,
}

/// Parsed 12-byte `MINIDUMP_DIRECTORY` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinidumpDirectoryEntry {
    pub stream_type: u32,
    pub data_size: u32,
    pub rva: u32,
}

/// Parsed `SystemInfoStream` (`StreamType = 7`, `56` bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinidumpSystemInfo {
    pub processor_architecture: ProcessorArch,
    pub processor_level: u16,
    pub processor_revision: u16,
    pub number_of_processors: u8,
    pub product_type: u8,
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    pub platform_id: u32,
    pub csd_version: String,
    pub suite_mask: u16,
}

impl MinidumpSystemInfo {
    pub fn os_build_string(&self) -> String {
        if self.csd_version.is_empty() {
            format!("{}.{}.{}", self.major_version, self.minor_version, self.build_number)
        } else {
            format!(
                "{}.{}.{} ({})",
                self.major_version, self.minor_version, self.build_number, self.csd_version
            )
        }
    }
}

/// Parsed `ExceptionStream` (`StreamType = 6`, `168` bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinidumpException {
    pub thread_id: u32,
    pub exception_code: u32,
    pub exception_flags: u32,
    pub exception_record: u64,
    pub exception_address: u64,
    pub number_parameters: u32,
    pub exception_information: Vec<u64>,
    pub thread_context: Option<CpuContext>,
}

/// Parsed CodeView `RSDS` record attached to a `MINIDUMP_MODULE.CvRecord` when present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeViewInfo {
    pub signature: String,
    pub guid: Option<String>,
    pub age: Option<u32>,
    pub pdb_name: String,
}

/// Parsed `MINIDUMP_MODULE` (`108` bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinidumpModule {
    pub base_of_image: u64,
    pub size_of_image: u32,
    pub checksum: u32,
    pub time_date_stamp: u32,
    pub full_path: String,
    pub module_name: String,
    pub file_version: Option<String>,
    pub product_version: Option<String>,
    pub codeview: Option<CodeViewInfo>,
}

impl MinidumpModule {
    pub fn contains_va(&self, va: u64) -> bool {
        let end = self.base_of_image.saturating_add(u64::from(self.size_of_image));
        va >= self.base_of_image && va < end
    }
}

/// Parsed `MINIDUMP_UNLOADED_MODULE` (`StreamType = 14`, `24` bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinidumpUnloadedModule {
    pub base_of_image: u64,
    pub size_of_image: u32,
    pub checksum: u32,
    pub time_date_stamp: u32,
    pub full_path: String,
    pub module_name: String,
}

impl MinidumpUnloadedModule {
    pub fn contains_va(&self, va: u64) -> bool {
        let end = self.base_of_image.saturating_add(u64::from(self.size_of_image));
        va >= self.base_of_image && va < end
    }
}

/// Virtual memory range backed by a slice inside the minidump file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRange {
    pub start_va: u64,
    pub data_size: u64,
    pub file_offset: u64,
}

/// Parsed `MINIDUMP_THREAD` (`48` bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinidumpThread {
    pub thread_id: u32,
    pub suspend_count: u32,
    pub priority_class: u32,
    pub priority: u32,
    pub teb: u64,
    pub stack: Option<MemoryRange>,
    pub context: Option<CpuContext>,
}

/// Parsed `MiscInfoStream` (`StreamType = 15`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinidumpMiscInfo {
    pub size_of_info: u32,
    pub flags1: u32,
    pub process_id: Option<u32>,
    pub process_create_time: Option<DateTime<Utc>>,
    pub process_user_time: Option<u32>,
    pub process_kernel_time: Option<u32>,
    pub build_string: Option<String>,
    pub dbg_build_string: Option<String>,
}

/// Resolved module containment for a virtual address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAddress {
    pub module_name: String,
    pub module_path: String,
    pub base_of_image: u64,
    pub offset: u64,
    pub file_version: Option<String>,
    pub unloaded: bool,
}

impl ResolvedAddress {
    pub fn format_symbolic(&self) -> String {
        if self.unloaded {
            format!("<unloaded> {}+0x{:x}", self.module_name, self.offset)
        } else {
            format!("{}+0x{:x}", self.module_name, self.offset)
        }
    }
}

/// Fully parsed pure-Rust Windows `MDMP` minidump representation.
#[derive(Debug, Clone)]
pub struct MinidumpFile {
    pub header: MinidumpHeader,
    pub directory: Vec<MinidumpDirectoryEntry>,
    pub system_info: Option<MinidumpSystemInfo>,
    pub exception: Option<MinidumpException>,
    pub modules: Vec<MinidumpModule>,
    pub unloaded_modules: Vec<MinidumpUnloadedModule>,
    pub threads: Vec<MinidumpThread>,
    pub memory_ranges: Vec<MemoryRange>,
    pub misc_info: Option<MinidumpMiscInfo>,
    pub comments: Vec<String>,
    pub warnings: Vec<DiagnosticWarning>,
    raw_data: Vec<u8>,
}

fn short_module_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

fn read_u16_at(data: &[u8], off: usize, ctx: &str) -> Result<u16, ForensicError> {
    let s = off
        .checked_add(2)
        .and_then(|end| data.get(off..end))
        .ok_or_else(|| ForensicError::parse(ctx, format!("truncated u16 at offset 0x{off:x}")))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32_at(data: &[u8], off: usize, ctx: &str) -> Result<u32, ForensicError> {
    let s = off
        .checked_add(4)
        .and_then(|end| data.get(off..end))
        .ok_or_else(|| ForensicError::parse(ctx, format!("truncated u32 at offset 0x{off:x}")))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64_at(data: &[u8], off: usize, ctx: &str) -> Result<u64, ForensicError> {
    let s = off
        .checked_add(8)
        .and_then(|end| data.get(off..end))
        .ok_or_else(|| ForensicError::parse(ctx, format!("truncated u64 at offset 0x{off:x}")))?;
    Ok(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

/// Reads a `MINIDUMP_STRING` (`u32` byte length + UTF-16LE bytes) with overflow checks.
fn read_minidump_string(data: &[u8], rva: u32) -> Result<String, ForensicError> {
    let start = rva as usize;
    let len_bytes = read_u32_at(data, start, "MINIDUMP_STRING")? as usize;
    let str_start = start
        .checked_add(4)
        .ok_or_else(|| ForensicError::parse("MINIDUMP_STRING", "offset overflow"))?;
    let str_end = str_start
        .checked_add(len_bytes)
        .ok_or_else(|| ForensicError::parse("MINIDUMP_STRING", "string length overflow"))?;
    if str_end > data.len() {
        return Err(ForensicError::parse(
            "MINIDUMP_STRING",
            format!(
                "string at RVA 0x{rva:x} (len {len_bytes}) exceeds dump size {}",
                data.len()
            ),
        ));
    }
    Ok(read_utf16_le_nul(&data[str_start..str_end]))
}

fn parse_codeview(data: &[u8], rva: u32, size: u32) -> Option<CodeViewInfo> {
    if size < 4 || rva == 0 {
        return None;
    }
    let start = rva as usize;
    let end = start.checked_add(size as usize)?;
    let slice = data.get(start..end)?;
    if slice.starts_with(b"RSDS") && slice.len() >= 24 {
        let guid = forensics2rust_core::parse_guid_le(&slice[4..20]).ok();
        let age = Some(u32::from_le_bytes([slice[20], slice[21], slice[22], slice[23]]));
        let pdb_tail = &slice[24..];
        let nul = pdb_tail.iter().position(|&b| b == 0).unwrap_or(pdb_tail.len());
        let pdb_name = String::from_utf8_lossy(&pdb_tail[..nul]).into_owned();
        return Some(CodeViewInfo {
            signature: "RSDS".to_string(),
            guid,
            age,
            pdb_name,
        });
    }
    None
}

fn format_vs_version(ms: u32, ls: u32) -> String {
    format!("{}.{}.{}.{}", ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)
}

impl MinidumpFile {
    /// Parses an `MDMP` minidump from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ForensicError> {
        Self::parse(bytes.to_vec())
    }

    /// Parses an `MDMP` minidump taking ownership of the buffer for zero-copy VA reads.
    pub fn parse(data: Vec<u8>) -> Result<Self, ForensicError> {
        if data.len() >= 8 && (&data[..8] == b"PAGEDUMP" || &data[..8] == b"PAGEDU64") {
            return Err(ForensicError::unsupported_platform(
                "MDMP",
                "full kernel MEMORY.DMP (PAGEDUMP/PAGEDU64) is not an MDMP minidump; supply C:\\Windows\\Minidump\\*.dmp",
            ));
        }
        if data.len() < 32 {
            return Err(ForensicError::parse(
                "MINIDUMP_HEADER",
                format!("buffer too short ({} bytes, minimum 32)", data.len()),
            ));
        }

        let signature = read_u32_at(&data, 0x00, "MINIDUMP_HEADER")?;
        if signature != MDMP_SIGNATURE {
            return Err(ForensicError::parse(
                "MINIDUMP_HEADER",
                format!("invalid MDMP signature 0x{signature:08x} (expected 0x{MDMP_SIGNATURE:08x})"),
            ));
        }
        let version = read_u32_at(&data, 0x04, "MINIDUMP_HEADER")?;
        if (version & 0xFFFF) != MINIDUMP_VERSION {
            return Err(ForensicError::parse(
                "MINIDUMP_HEADER",
                format!(
                    "unsupported MINIDUMP_VERSION 0x{:04x} (expected 0x{MINIDUMP_VERSION:04x})",
                    version & 0xFFFF
                ),
            ));
        }

        let number_of_streams = read_u32_at(&data, 0x08, "MINIDUMP_HEADER")?;
        if number_of_streams > 4096 {
            return Err(ForensicError::parse(
                "MINIDUMP_HEADER",
                format!("stream count {number_of_streams} exceeds safety limit 4096"),
            ));
        }
        let stream_directory_rva = read_u32_at(&data, 0x0C, "MINIDUMP_HEADER")?;
        let checksum = read_u32_at(&data, 0x10, "MINIDUMP_HEADER")?;
        let time_date_stamp = read_u32_at(&data, 0x14, "MINIDUMP_HEADER")?;
        let flags = read_u64_at(&data, 0x18, "MINIDUMP_HEADER")?;

        let dir_start = stream_directory_rva as usize;
        let dir_bytes = (number_of_streams as usize)
            .checked_mul(12)
            .ok_or_else(|| ForensicError::parse("MINIDUMP_DIRECTORY", "directory size overflow"))?;
        let dir_end = dir_start
            .checked_add(dir_bytes)
            .ok_or_else(|| ForensicError::parse("MINIDUMP_DIRECTORY", "directory offset overflow"))?;
        if dir_end > data.len() {
            return Err(ForensicError::parse(
                "MINIDUMP_DIRECTORY",
                format!(
                    "directory range 0x{dir_start:x}..0x{dir_end:x} exceeds dump size {}",
                    data.len()
                ),
            ));
        }

        let mut directory = Vec::with_capacity(number_of_streams as usize);
        for i in 0..(number_of_streams as usize) {
            let off = dir_start + i * 12;
            let entry = MinidumpDirectoryEntry {
                stream_type: read_u32_at(&data, off, "MINIDUMP_DIRECTORY")?,
                data_size: read_u32_at(&data, off + 4, "MINIDUMP_DIRECTORY")?,
                rva: read_u32_at(&data, off + 8, "MINIDUMP_DIRECTORY")?,
            };
            if entry.stream_type != stream_type::UNUSED && entry.data_size > 0 {
                if entry.rva < 32 {
                    return Err(ForensicError::parse(
                        "MINIDUMP_DIRECTORY",
                        format!(
                            "stream {} has invalid RVA 0x{:x} inside MINIDUMP_HEADER (< 32)",
                            entry.stream_type, entry.rva
                        ),
                    ));
                }
                let end = (entry.rva as usize)
                    .checked_add(entry.data_size as usize)
                    .ok_or_else(|| ForensicError::parse("MINIDUMP_DIRECTORY", "stream range overflow"))?;
                if end > data.len() {
                    return Err(ForensicError::parse(
                        "MINIDUMP_DIRECTORY",
                        format!(
                            "stream {} (0x{:x}..0x{end:x}) exceeds dump size {}",
                            entry.stream_type,
                            entry.rva,
                            data.len()
                        ),
                    ));
                }
            }
            directory.push(entry);
        }

        let header = MinidumpHeader {
            signature,
            version,
            number_of_streams,
            stream_directory_rva,
            checksum,
            time_date_stamp,
            timestamp_utc: DateTime::from_timestamp(i64::from(time_date_stamp), 0),
            flags,
        };

        let mut warnings = Vec::new();
        let mut system_info: Option<MinidumpSystemInfo> = None;

        // First pass: parse SystemInfoStream (7) so CPU architecture is known for CONTEXT decoding.
        for entry in &directory {
            if entry.stream_type == stream_type::SYSTEM_INFO && entry.data_size > 0 {
                let s = entry.rva as usize;
                let e = s + entry.data_size as usize;
                if entry.data_size < 56 {
                    return Err(ForensicError::parse(
                        "SystemInfoStream",
                        format!("SystemInfoStream too short ({} bytes, expected >= 56)", entry.data_size),
                    ));
                }
                let slice = &data[s..e];
                let arch = ProcessorArch::from_raw(u16::from_le_bytes([slice[0], slice[1]]));
                let csd_rva = read_u32_at(slice, 0x18, "SystemInfoStream")?;
                let csd_version = if csd_rva != 0 {
                    read_minidump_string(&data, csd_rva)?
                } else {
                    String::new()
                };
                system_info = Some(MinidumpSystemInfo {
                    processor_architecture: arch,
                    processor_level: read_u16_at(slice, 0x02, "SystemInfoStream")?,
                    processor_revision: read_u16_at(slice, 0x04, "SystemInfoStream")?,
                    number_of_processors: slice[0x06],
                    product_type: slice[0x07],
                    major_version: read_u32_at(slice, 0x08, "SystemInfoStream")?,
                    minor_version: read_u32_at(slice, 0x0C, "SystemInfoStream")?,
                    build_number: read_u32_at(slice, 0x10, "SystemInfoStream")?,
                    platform_id: read_u32_at(slice, 0x14, "SystemInfoStream")?,
                    csd_version,
                    suite_mask: read_u16_at(slice, 0x1C, "SystemInfoStream")?,
                });
                break;
            }
        }

        let arch = system_info
            .as_ref()
            .map(|si| si.processor_architecture)
            .unwrap_or(ProcessorArch::Unknown(0xFFFF));

        let mut exception: Option<MinidumpException> = None;
        let mut modules: Vec<MinidumpModule> = Vec::new();
        let mut unloaded_modules: Vec<MinidumpUnloadedModule> = Vec::new();
        let mut threads: Vec<MinidumpThread> = Vec::new();
        let mut memory_ranges: Vec<MemoryRange> = Vec::new();
        let mut misc_info: Option<MinidumpMiscInfo> = None;
        let mut comments: Vec<String> = Vec::new();

        for entry in &directory {
            if entry.stream_type == stream_type::UNUSED || entry.data_size == 0 {
                continue;
            }
            let s = entry.rva as usize;
            let e = s + entry.data_size as usize;
            let slice = &data[s..e];

            match entry.stream_type {
                stream_type::SYSTEM_INFO => {}
                stream_type::EXCEPTION => {
                    if slice.len() < 168 {
                        return Err(ForensicError::parse(
                            "ExceptionStream",
                            format!("ExceptionStream too short ({} bytes, expected 168)", slice.len()),
                        ));
                    }
                    let thread_id = read_u32_at(slice, 0x00, "ExceptionStream")?;
                    let exception_code = read_u32_at(slice, 0x08, "ExceptionStream")?;
                    let exception_flags = read_u32_at(slice, 0x0C, "ExceptionStream")?;
                    let exception_record = read_u64_at(slice, 0x10, "ExceptionStream")?;
                    let exception_address = read_u64_at(slice, 0x18, "ExceptionStream")?;
                    let raw_param_count = read_u32_at(slice, 0x20, "ExceptionStream")?;
                    let param_count = (raw_param_count as usize).min(15);
                    let mut exception_information = Vec::with_capacity(param_count);
                    for idx in 0..param_count {
                        exception_information.push(read_u64_at(slice, 0x28 + idx * 8, "ExceptionStream")?);
                    }
                    let ctx_size = read_u32_at(slice, 0xA0, "ExceptionStream")? as usize;
                    let ctx_rva = read_u32_at(slice, 0xA4, "ExceptionStream")? as usize;
                    let thread_context = if ctx_size > 0 && ctx_rva > 0 {
                        match ctx_rva.checked_add(ctx_size).and_then(|end| data.get(ctx_rva..end)) {
                            Some(ctx_bytes) => match CpuContext::parse(arch, ctx_bytes) {
                                Ok(ctx) => Some(ctx),
                                Err(err) => {
                                    warnings.push(DiagnosticWarning {
                                        severity: WarningSeverity::Warn,
                                        tool_id: "crash.mdmp".to_string(),
                                        source: "ExceptionStream.ThreadContext".to_string(),
                                        message: err.to_string(),
                                    });
                                    None
                                }
                            },
                            None => {
                                return Err(ForensicError::parse(
                                    "ExceptionStream",
                                    "ThreadContext range exceeds dump bounds",
                                ));
                            }
                        }
                    } else {
                        None
                    };
                    exception = Some(MinidumpException {
                        thread_id,
                        exception_code,
                        exception_flags,
                        exception_record,
                        exception_address,
                        number_parameters: raw_param_count,
                        exception_information,
                        thread_context,
                    });
                }
                stream_type::MODULE_LIST => {
                    if slice.len() < 4 {
                        return Err(ForensicError::parse("ModuleListStream", "missing NumberOfModules"));
                    }
                    let count = read_u32_at(slice, 0, "ModuleListStream")? as usize;
                    let required = count
                        .checked_mul(108)
                        .and_then(|n| n.checked_add(4))
                        .ok_or_else(|| ForensicError::parse("ModuleListStream", "module count overflow"))?;
                    if required > slice.len() {
                        return Err(ForensicError::parse(
                            "ModuleListStream",
                            format!(
                                "ModuleListStream truncated (need {required} bytes, got {})",
                                slice.len()
                            ),
                        ));
                    }
                    for i in 0..count {
                        let m = &slice[4 + i * 108..4 + (i + 1) * 108];
                        let base_of_image = read_u64_at(m, 0x00, "MINIDUMP_MODULE")?;
                        let size_of_image = read_u32_at(m, 0x08, "MINIDUMP_MODULE")?;
                        let checksum = read_u32_at(m, 0x0C, "MINIDUMP_MODULE")?;
                        let time_date_stamp = read_u32_at(m, 0x10, "MINIDUMP_MODULE")?;
                        let module_name_rva = read_u32_at(m, 0x14, "MINIDUMP_MODULE")?;
                        let full_path = if module_name_rva != 0 {
                            read_minidump_string(&data, module_name_rva)?
                        } else {
                            String::new()
                        };
                        let module_name = short_module_name(&full_path);

                        let vs_sig = read_u32_at(m, 0x18, "VS_FIXEDFILEINFO")?;
                        let (file_version, product_version) = if vs_sig == VS_FFI_SIGNATURE {
                            let fv_ms = read_u32_at(m, 0x20, "VS_FIXEDFILEINFO")?;
                            let fv_ls = read_u32_at(m, 0x24, "VS_FIXEDFILEINFO")?;
                            let pv_ms = read_u32_at(m, 0x28, "VS_FIXEDFILEINFO")?;
                            let pv_ls = read_u32_at(m, 0x2C, "VS_FIXEDFILEINFO")?;
                            (
                                Some(format_vs_version(fv_ms, fv_ls)),
                                Some(format_vs_version(pv_ms, pv_ls)),
                            )
                        } else {
                            (None, None)
                        };

                        let cv_size = read_u32_at(m, 0x4C, "MINIDUMP_MODULE")?;
                        let cv_rva = read_u32_at(m, 0x50, "MINIDUMP_MODULE")?;
                        let codeview = parse_codeview(&data, cv_rva, cv_size);

                        modules.push(MinidumpModule {
                            base_of_image,
                            size_of_image,
                            checksum,
                            time_date_stamp,
                            full_path,
                            module_name,
                            file_version,
                            product_version,
                            codeview,
                        });
                    }
                }
                stream_type::THREAD_LIST => {
                    if slice.len() < 4 {
                        return Err(ForensicError::parse("ThreadListStream", "missing NumberOfThreads"));
                    }
                    let count = read_u32_at(slice, 0, "ThreadListStream")? as usize;
                    let required = count
                        .checked_mul(48)
                        .and_then(|n| n.checked_add(4))
                        .ok_or_else(|| ForensicError::parse("ThreadListStream", "thread count overflow"))?;
                    if required > slice.len() {
                        return Err(ForensicError::parse(
                            "ThreadListStream",
                            format!(
                                "ThreadListStream truncated (need {required} bytes, got {})",
                                slice.len()
                            ),
                        ));
                    }
                    for i in 0..count {
                        let t = &slice[4 + i * 48..4 + (i + 1) * 48];
                        let thread_id = read_u32_at(t, 0x00, "MINIDUMP_THREAD")?;
                        let suspend_count = read_u32_at(t, 0x04, "MINIDUMP_THREAD")?;
                        let priority_class = read_u32_at(t, 0x08, "MINIDUMP_THREAD")?;
                        let priority = read_u32_at(t, 0x0C, "MINIDUMP_THREAD")?;
                        let teb = read_u64_at(t, 0x10, "MINIDUMP_THREAD")?;

                        let stack_start = read_u64_at(t, 0x18, "MINIDUMP_THREAD")?;
                        let stack_size = read_u32_at(t, 0x20, "MINIDUMP_THREAD")?;
                        let stack_rva = read_u32_at(t, 0x24, "MINIDUMP_THREAD")?;
                        let stack = if stack_size > 0 && stack_rva > 0 {
                            let end = (stack_rva as usize)
                                .checked_add(stack_size as usize)
                                .ok_or_else(|| ForensicError::parse("MINIDUMP_THREAD", "stack range overflow"))?;
                            if end <= data.len() {
                                Some(MemoryRange {
                                    start_va: stack_start,
                                    data_size: u64::from(stack_size),
                                    file_offset: u64::from(stack_rva),
                                })
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        let ctx_size = read_u32_at(t, 0x28, "MINIDUMP_THREAD")? as usize;
                        let ctx_rva = read_u32_at(t, 0x2C, "MINIDUMP_THREAD")? as usize;
                        let context = if ctx_size > 0 && ctx_rva > 0 {
                            ctx_rva
                                .checked_add(ctx_size)
                                .and_then(|end| data.get(ctx_rva..end))
                                .and_then(|ctx_bytes| CpuContext::parse(arch, ctx_bytes).ok())
                        } else {
                            None
                        };

                        threads.push(MinidumpThread {
                            thread_id,
                            suspend_count,
                            priority_class,
                            priority,
                            teb,
                            stack,
                            context,
                        });
                    }
                }
                stream_type::MEMORY_LIST => {
                    if slice.len() < 4 {
                        return Err(ForensicError::parse("MemoryListStream", "missing NumberOfMemoryRanges"));
                    }
                    let count = read_u32_at(slice, 0, "MemoryListStream")? as usize;
                    let required = count
                        .checked_mul(16)
                        .and_then(|n| n.checked_add(4))
                        .ok_or_else(|| ForensicError::parse("MemoryListStream", "range count overflow"))?;
                    if required > slice.len() {
                        return Err(ForensicError::parse(
                            "MemoryListStream",
                            format!(
                                "MemoryListStream truncated (need {required} bytes, got {})",
                                slice.len()
                            ),
                        ));
                    }
                    for i in 0..count {
                        let r = &slice[4 + i * 16..4 + (i + 1) * 16];
                        let start_va = read_u64_at(r, 0x00, "MINIDUMP_MEMORY_DESCRIPTOR")?;
                        let data_size = read_u32_at(r, 0x08, "MINIDUMP_MEMORY_DESCRIPTOR")?;
                        let rva = read_u32_at(r, 0x0C, "MINIDUMP_MEMORY_DESCRIPTOR")?;
                        if data_size > 0
                            && let Some(end) = (rva as usize).checked_add(data_size as usize)
                            && end <= data.len()
                        {
                            memory_ranges.push(MemoryRange {
                                start_va,
                                data_size: u64::from(data_size),
                                file_offset: u64::from(rva),
                            });
                        }
                    }
                }
                stream_type::MEMORY64_LIST => {
                    if slice.len() < 16 {
                        return Err(ForensicError::parse("Memory64ListStream", "header too short"));
                    }
                    let count_u64 = read_u64_at(slice, 0x00, "Memory64ListStream")?;
                    let mut cur_rva = read_u64_at(slice, 0x08, "Memory64ListStream")?;
                    let count = usize::try_from(count_u64)
                        .map_err(|_| ForensicError::parse("Memory64ListStream", "range count overflow"))?;
                    let required = count
                        .checked_mul(16)
                        .and_then(|n| n.checked_add(16))
                        .ok_or_else(|| ForensicError::parse("Memory64ListStream", "table size overflow"))?;
                    if required > slice.len() {
                        return Err(ForensicError::parse(
                            "Memory64ListStream",
                            "Memory64ListStream truncated",
                        ));
                    }
                    for i in 0..count {
                        let r = &slice[16 + i * 16..16 + (i + 1) * 16];
                        let start_va = read_u64_at(r, 0x00, "MINIDUMP_MEMORY_DESCRIPTOR64")?;
                        let data_size = read_u64_at(r, 0x08, "MINIDUMP_MEMORY_DESCRIPTOR64")?;
                        if data_size > 0
                            && let Some(end) = cur_rva.checked_add(data_size)
                            && end <= data.len() as u64
                        {
                            memory_ranges.push(MemoryRange {
                                start_va,
                                data_size,
                                file_offset: cur_rva,
                            });
                        }
                        cur_rva = cur_rva.saturating_add(data_size);
                    }
                }
                stream_type::UNLOADED_MODULE_LIST => {
                    if slice.len() < 12 {
                        return Err(ForensicError::parse("UnloadedModuleListStream", "header too short"));
                    }
                    let size_of_header = read_u32_at(slice, 0x00, "UnloadedModuleListStream")? as usize;
                    let size_of_entry = read_u32_at(slice, 0x04, "UnloadedModuleListStream")? as usize;
                    let num_entries = read_u32_at(slice, 0x08, "UnloadedModuleListStream")? as usize;
                    if size_of_header < 12 || size_of_entry < 24 {
                        return Err(ForensicError::parse(
                            "UnloadedModuleListStream",
                            "invalid header/entry sizes",
                        ));
                    }
                    let required = num_entries
                        .checked_mul(size_of_entry)
                        .and_then(|n| n.checked_add(size_of_header))
                        .ok_or_else(|| ForensicError::parse("UnloadedModuleListStream", "entry table overflow"))?;
                    if required > slice.len() {
                        return Err(ForensicError::parse(
                            "UnloadedModuleListStream",
                            "UnloadedModuleListStream truncated",
                        ));
                    }
                    for i in 0..num_entries {
                        let off = size_of_header + i * size_of_entry;
                        let u = &slice[off..off + 24];
                        let base_of_image = read_u64_at(u, 0x00, "MINIDUMP_UNLOADED_MODULE")?;
                        let size_of_image = read_u32_at(u, 0x08, "MINIDUMP_UNLOADED_MODULE")?;
                        let checksum = read_u32_at(u, 0x0C, "MINIDUMP_UNLOADED_MODULE")?;
                        let time_date_stamp = read_u32_at(u, 0x10, "MINIDUMP_UNLOADED_MODULE")?;
                        let name_rva = read_u32_at(u, 0x14, "MINIDUMP_UNLOADED_MODULE")?;
                        let full_path = if name_rva != 0 {
                            read_minidump_string(&data, name_rva)?
                        } else {
                            String::new()
                        };
                        let module_name = short_module_name(&full_path);
                        unloaded_modules.push(MinidumpUnloadedModule {
                            base_of_image,
                            size_of_image,
                            checksum,
                            time_date_stamp,
                            full_path,
                            module_name,
                        });
                    }
                }
                stream_type::MISC_INFO => {
                    if slice.len() >= 24 {
                        let size_of_info = read_u32_at(slice, 0x00, "MiscInfoStream")?;
                        let flags1 = read_u32_at(slice, 0x04, "MiscInfoStream")?;
                        let process_id = if flags1 & 0x01 != 0 {
                            Some(read_u32_at(slice, 0x08, "MiscInfoStream")?)
                        } else {
                            None
                        };
                        let (process_create_time, process_user_time, process_kernel_time) = if flags1 & 0x02 != 0 {
                            let create_ts = read_u32_at(slice, 0x0C, "MiscInfoStream")?;
                            let user_t = read_u32_at(slice, 0x10, "MiscInfoStream")?;
                            let kernel_t = read_u32_at(slice, 0x14, "MiscInfoStream")?;
                            (
                                DateTime::from_timestamp(i64::from(create_ts), 0),
                                Some(user_t),
                                Some(kernel_t),
                            )
                        } else {
                            (None, None, None)
                        };
                        let (build_string, dbg_build_string) =
                            if size_of_info >= 832 && slice.len() >= 832 && (flags1 & 0x100 != 0) {
                                let b = read_utf16_le_nul(&slice[0xE8..0xE8 + 520]);
                                let d = read_utf16_le_nul(&slice[0x2F0..0x2F0 + 80]);
                                (
                                    if b.is_empty() { None } else { Some(b) },
                                    if d.is_empty() { None } else { Some(d) },
                                )
                            } else {
                                (None, None)
                            };
                        misc_info = Some(MinidumpMiscInfo {
                            size_of_info,
                            flags1,
                            process_id,
                            process_create_time,
                            process_user_time,
                            process_kernel_time,
                            build_string,
                            dbg_build_string,
                        });
                    }
                }
                stream_type::COMMENT_A => {
                    let nul = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
                    let s = String::from_utf8_lossy(&slice[..nul]).into_owned();
                    if !s.is_empty() {
                        comments.push(s);
                    }
                }
                stream_type::COMMENT_W => {
                    let s = read_utf16_le_nul(slice);
                    if !s.is_empty() {
                        comments.push(s);
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            header,
            directory,
            system_info,
            exception,
            modules,
            unloaded_modules,
            threads,
            memory_ranges,
            misc_info,
            comments,
            warnings,
            raw_data: data,
        })
    }

    /// Reads `len` bytes starting at virtual address `va` from `MemoryListStream`,
    /// `Memory64ListStream`, or any thread's captured `Stack` descriptor.
    pub fn read_va(&self, va: u64, len: usize) -> Option<&[u8]> {
        let len_u64 = u64::try_from(len).ok()?;
        let req_end = va.checked_add(len_u64)?;

        let all_ranges = self
            .memory_ranges
            .iter()
            .copied()
            .chain(self.threads.iter().filter_map(|t| t.stack));

        for range in all_ranges {
            let range_end = range.start_va.saturating_add(range.data_size);
            if va >= range.start_va && req_end <= range_end {
                let delta = va - range.start_va;
                let file_off = usize::try_from(range.file_offset.checked_add(delta)?).ok()?;
                let file_end = file_off.checked_add(len)?;
                return self.raw_data.get(file_off..file_end);
            }
        }
        None
    }

    /// Reads a little-endian `u64` from virtual address `va`.
    pub fn read_va_u64(&self, va: u64) -> Option<u64> {
        let b = self.read_va(va, 8)?;
        Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    /// Reads a little-endian `u32` from virtual address `va`.
    pub fn read_va_u32(&self, va: u64) -> Option<u32> {
        let b = self.read_va(va, 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Finds the loaded module containing `va`.
    pub fn resolve_loaded_address(&self, va: u64) -> Option<ResolvedAddress> {
        for m in &self.modules {
            if m.contains_va(va) {
                return Some(ResolvedAddress {
                    module_name: m.module_name.clone(),
                    module_path: m.full_path.clone(),
                    base_of_image: m.base_of_image,
                    offset: va - m.base_of_image,
                    file_version: m.file_version.clone(),
                    unloaded: false,
                });
            }
        }
        None
    }

    /// Finds either a loaded module or an unloaded module containing `va`.
    pub fn resolve_address(&self, va: u64) -> Option<ResolvedAddress> {
        if let Some(hit) = self.resolve_loaded_address(va) {
            return Some(hit);
        }
        for u in &self.unloaded_modules {
            if u.contains_va(va) {
                return Some(ResolvedAddress {
                    module_name: u.module_name.clone(),
                    module_path: u.full_path.clone(),
                    base_of_image: u.base_of_image,
                    offset: va - u.base_of_image,
                    file_version: None,
                    unloaded: true,
                });
            }
        }
        None
    }

    /// Returns the active faulting `CpuContext` (from `ExceptionStream` first, else matching thread).
    pub fn faulting_context(&self) -> Option<&CpuContext> {
        if let Some(exc) = &self.exception {
            if let Some(ctx) = &exc.thread_context {
                return Some(ctx);
            }
            if let Some(thread) = self.threads.iter().find(|t| t.thread_id == exc.thread_id)
                && let Some(ctx) = &thread.context
            {
                return Some(ctx);
            }
        }
        self.threads.iter().find_map(|t| t.context.as_ref())
    }

    /// Returns the memory range covering `sp` (preferring the faulting thread's stack).
    pub fn stack_window_for(&self, sp: u64) -> Option<MemoryRange> {
        if let Some(exc) = &self.exception
            && let Some(thread) = self.threads.iter().find(|t| t.thread_id == exc.thread_id)
            && let Some(stack) = thread.stack
        {
            let end = stack.start_va.saturating_add(stack.data_size);
            if sp >= stack.start_va && sp < end {
                return Some(stack);
            }
        }
        for thread in &self.threads {
            if let Some(stack) = thread.stack {
                let end = stack.start_va.saturating_add(stack.data_size);
                if sp >= stack.start_va && sp < end {
                    return Some(stack);
                }
            }
        }
        for &range in &self.memory_ranges {
            let end = range.start_va.saturating_add(range.data_size);
            if sp >= range.start_va && sp < end {
                return Some(range);
            }
        }
        None
    }

    /// Returns a bounded prefix (`<= 65_536` bytes) of the dump for GUI hex inspection.
    pub fn bounded_raw_bytes(&self) -> Vec<u8> {
        let cap = self.raw_data.len().min(65_536);
        self.raw_data[..cap].to_vec()
    }

    pub fn raw_len(&self) -> usize {
        self.raw_data.len()
    }
}
