use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use crc32fast::Hasher;
use forensics2rust_core::{DiagnosticWarning, ForensicError, ForensicSource, WarningSeverity, filetime_to_utc};
use walkdir::WalkDir;

use crate::binxml::{ChunkCache, decode_binxml_to_xml};
use crate::live;
use crate::model::{ChannelMetadata, LiveQueryOptions, SourceMetadata};
pub use crate::model::{EvtxChunkInfo, EvtxFileHeader, EvtxParseOptions, EvtxRecord};
use crate::xml::parse_event_xml;

const FILE_MAGIC: &[u8; 8] = b"ElfFile\0";
const CHUNK_MAGIC: &[u8; 8] = b"ElfChnk\0";
const RECORD_MAGIC: [u8; 4] = [0x2A, 0x2A, 0x00, 0x00];
const CHUNK_SIZE: usize = 65_536;
const CHUNK_HEADER_DATA_OFFSET: usize = 0x200;

/// Pure-Rust `[MS-EVEN6]` EVTX archive parser.
#[derive(Debug, Clone)]
pub struct EvtxArchive {
    header: EvtxFileHeader,
    chunks: Vec<EvtxChunkInfo>,
    records: Vec<EvtxRecord>,
    warnings: Vec<DiagnosticWarning>,
}

impl EvtxArchive {
    /// Parses an in-memory EVTX buffer using default tolerant DFIR checksum handling.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ForensicError> {
        Self::from_bytes_with_options(bytes, EvtxParseOptions::default())
    }

    /// Parses an in-memory EVTX buffer with explicit [`EvtxParseOptions`].
    pub fn from_bytes_with_options(bytes: &[u8], options: EvtxParseOptions) -> Result<Self, ForensicError> {
        Self::parse_slice(bytes, "<memory>", options)
    }

    /// Opens and parses an `.evtx` file from disk using default tolerant DFIR checksum handling.
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        Self::open_with_options(path, EvtxParseOptions::default())
    }

    /// Opens and parses an `.evtx` file from disk with explicit [`EvtxParseOptions`].
    pub fn open_with_options(path: &Path, options: EvtxParseOptions) -> Result<Self, ForensicError> {
        let bytes = fs::read(path).map_err(|err| ForensicError::io_classified(path.display().to_string(), err))?;
        let label = path.display().to_string();
        Self::parse_slice(&bytes, &label, options)
    }

    pub fn records(&self) -> &[EvtxRecord] {
        &self.records
    }

    pub fn into_records(self) -> Vec<EvtxRecord> {
        self.records
    }

    pub fn chunks_info(&self) -> &[EvtxChunkInfo] {
        &self.chunks
    }

    pub fn header(&self) -> &EvtxFileHeader {
        &self.header
    }

    pub fn warnings(&self) -> &[DiagnosticWarning] {
        &self.warnings
    }

    fn parse_slice(bytes: &[u8], source_label: &str, options: EvtxParseOptions) -> Result<Self, ForensicError> {
        if bytes.len() < 4096 {
            return Err(ForensicError::parse(
                source_label,
                format!("EVTX file too short ({} bytes; expected >= 4096)", bytes.len()),
            ));
        }

        if &bytes[0..8] != FILE_MAGIC {
            return Err(ForensicError::parse(
                source_label,
                "invalid EVTX file magic (expected ElfFile\\0)",
            ));
        }

        let oldest_chunk = read_u64_le(bytes, 0x08);
        let current_chunk_number = read_u64_le(bytes, 0x10);
        let next_record_id = read_u64_le(bytes, 0x18);
        let header_size = read_u32_le(bytes, 0x20);
        let minor_version = read_u16_le(bytes, 0x24);
        let major_version = read_u16_le(bytes, 0x26);
        let header_block_size = read_u16_le(bytes, 0x28);
        let chunk_count = read_u16_le(bytes, 0x2A);
        let file_flags = read_u32_le(bytes, 0x78);
        let checksum = read_u32_le(bytes, 0x7C);

        if usize::from(header_block_size) < 128 || bytes.len() < usize::from(header_block_size) {
            return Err(ForensicError::parse(
                source_label,
                format!("invalid header_block_size {header_block_size}"),
            ));
        }
        if header_size < 128 || header_size > u32::from(header_block_size) {
            return Err(ForensicError::parse(
                source_label,
                format!("invalid header_size {header_size}"),
            ));
        }

        let computed_header_crc = crc32fast::hash(&bytes[0..120]);
        let header_checksum_valid = computed_header_crc == checksum;

        let mut warnings = Vec::new();
        if !header_checksum_valid {
            let msg = format!(
                "EVTX file header CRC-32 mismatch: expected 0x{checksum:08x}, got 0x{computed_header_crc:08x} (flags=0x{file_flags:x})"
            );
            if options.strict_checksums {
                return Err(ForensicError::parse(source_label, msg));
            }
            warnings.push(DiagnosticWarning {
                severity: WarningSeverity::Warn,
                tool_id: "evtx.parser".to_string(),
                source: source_label.to_string(),
                message: msg,
            });
        }

        let header = EvtxFileHeader {
            oldest_chunk,
            current_chunk_number,
            next_record_id,
            header_size,
            minor_version,
            major_version,
            header_block_size,
            chunk_count,
            file_flags,
            checksum,
            header_checksum_valid,
        };

        let mut chunks = Vec::new();
        let mut records = Vec::new();

        let mut offset = usize::from(header_block_size);
        let mut chunk_index = 0usize;

        while offset + CHUNK_SIZE <= bytes.len() {
            let chunk = &bytes[offset..offset + CHUNK_SIZE];
            if chunk[0..8] == [0u8; 8] {
                warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Info,
                    tool_id: "evtx.parser".to_string(),
                    source: source_label.to_string(),
                    message: format!("skipping zero-filled preallocated chunk {chunk_index} at 0x{offset:x}"),
                });
                offset += CHUNK_SIZE;
                chunk_index += 1;
                continue;
            }

            if &chunk[0..8] != CHUNK_MAGIC {
                return Err(ForensicError::parse(
                    source_label,
                    format!("invalid EVTX chunk magic at offset 0x{offset:x}"),
                ));
            }

            let first_event_record_number = read_u64_le(chunk, 0x08);
            let last_event_record_number = read_u64_le(chunk, 0x10);
            let first_event_record_id = read_u64_le(chunk, 0x18);
            let last_event_record_id = read_u64_le(chunk, 0x20);
            let chunk_header_size = read_u32_le(chunk, 0x28);
            if chunk_header_size < 128 {
                return Err(ForensicError::parse(
                    source_label,
                    format!("invalid chunk header size {chunk_header_size} in chunk {chunk_index}"),
                ));
            }

            let raw_free_space = read_u32_le(chunk, 0x30);
            let event_records_checksum = read_u32_le(chunk, 0x34);
            let chunk_header_checksum = read_u32_le(chunk, 0x7C);

            let mut hdr_hasher = Hasher::new();
            hdr_hasher.update(&chunk[0..120]);
            hdr_hasher.update(&chunk[128..512]);
            let computed_chunk_hdr_crc = hdr_hasher.finalize();
            let chunk_header_valid = computed_chunk_hdr_crc == chunk_header_checksum;

            if !chunk_header_valid {
                let msg = format!(
                    "chunk {chunk_index} header CRC-32 mismatch: expected 0x{chunk_header_checksum:08x}, got 0x{computed_chunk_hdr_crc:08x}"
                );
                if options.strict_checksums {
                    return Err(ForensicError::parse(source_label, msg));
                }
                warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Warn,
                    tool_id: "evtx.parser".to_string(),
                    source: source_label.to_string(),
                    message: msg,
                });
            }

            let free_space_clamped = usize::try_from(raw_free_space).unwrap_or(CHUNK_SIZE);
            let scan_end = if !(CHUNK_HEADER_DATA_OFFSET..=CHUNK_SIZE).contains(&free_space_clamped) {
                let msg = format!("chunk {chunk_index} has out-of-range free_space_offset {raw_free_space}");
                if options.strict_checksums {
                    return Err(ForensicError::parse(source_label, msg));
                }
                warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Warn,
                    tool_id: "evtx.parser".to_string(),
                    source: source_label.to_string(),
                    message: msg,
                });
                CHUNK_SIZE
            } else {
                free_space_clamped
            };

            let computed_records_crc = crc32fast::hash(&chunk[CHUNK_HEADER_DATA_OFFSET..scan_end]);
            let records_checksum_valid = computed_records_crc == event_records_checksum;
            if !records_checksum_valid {
                let msg = format!(
                    "chunk {chunk_index} event records CRC-32 mismatch: expected 0x{event_records_checksum:08x}, got 0x{computed_records_crc:08x}"
                );
                if options.strict_checksums {
                    return Err(ForensicError::parse(source_label, msg));
                }
                warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Warn,
                    tool_id: "evtx.parser".to_string(),
                    source: source_label.to_string(),
                    message: msg,
                });
            }

            let mut cache = ChunkCache::default();
            let mut rec_off = CHUNK_HEADER_DATA_OFFSET;
            let mut chunk_rec_count = 0usize;

            while rec_off + 28 <= scan_end {
                if chunk[rec_off..rec_off + 4] == [0, 0, 0, 0] && free_space_clamped != scan_end {
                    // End of dirty/uncommitted records when scanning clamped chunk
                    break;
                }
                if chunk[rec_off..rec_off + 4] != RECORD_MAGIC {
                    return Err(ForensicError::parse(
                        source_label,
                        format!(
                            "invalid event record magic at chunk {chunk_index} offset 0x{rec_off:x}: {:02x?}",
                            &chunk[rec_off..rec_off + 4]
                        ),
                    ));
                }
                let rec_size = read_u32_le(chunk, rec_off + 4) as usize;
                if rec_size < 28 || rec_off + rec_size > scan_end {
                    return Err(ForensicError::parse(
                        source_label,
                        format!(
                            "invalid event record size {rec_size} at chunk {chunk_index} offset 0x{rec_off:x} (scan_end={scan_end})"
                        ),
                    ));
                }
                let trailing_size = read_u32_le(chunk, rec_off + rec_size - 4) as usize;
                if trailing_size != rec_size {
                    return Err(ForensicError::parse(
                        source_label,
                        format!(
                            "event record trailing size mismatch ({trailing_size} != {rec_size}) at chunk {chunk_index} offset 0x{rec_off:x}"
                        ),
                    ));
                }

                let rec_id = read_u64_le(chunk, rec_off + 8);
                let written_ft = read_u64_le(chunk, rec_off + 16);
                let written_dt = filetime_to_utc(written_ft).unwrap_or(DateTime::<Utc>::UNIX_EPOCH);

                let binxml_start = rec_off + 24;
                let binxml_end = rec_off + rec_size - 4;
                let xml = decode_binxml_to_xml(chunk, binxml_start, binxml_end, &mut cache)?;
                let raw_bytes = chunk[rec_off..rec_off + rec_size].to_vec();

                let mut record = parse_event_xml(&xml, raw_bytes, rec_id, written_dt, source_label.to_string())?;
                if record.record_id == 0 {
                    record.record_id = rec_id;
                }
                records.push(record);
                chunk_rec_count += 1;
                rec_off += rec_size;
            }

            if rec_off != scan_end && free_space_clamped == scan_end {
                return Err(ForensicError::parse(
                    source_label,
                    format!(
                        "truncated trailing event record bytes at chunk {chunk_index} offset 0x{rec_off:x} (free_space_offset={scan_end})"
                    ),
                ));
            }

            chunks.push(EvtxChunkInfo {
                chunk_index,
                file_offset: offset as u64,
                first_event_record_number,
                last_event_record_number,
                first_event_record_id,
                last_event_record_id,
                free_space_offset: raw_free_space,
                event_records_checksum,
                header_checksum: chunk_header_checksum,
                header_checksum_valid: chunk_header_valid,
                records_checksum_valid,
                parsed_record_count: chunk_rec_count,
            });

            offset += CHUNK_SIZE;
            chunk_index += 1;
        }

        if usize::from(chunk_count) != chunks.len() {
            warnings.push(DiagnosticWarning {
                severity: WarningSeverity::Info,
                tool_id: "evtx.parser".to_string(),
                source: source_label.to_string(),
                message: format!(
                    "header chunk_count={} differs from parsed chunk count {}",
                    chunk_count,
                    chunks.len()
                ),
            });
        }

        Ok(Self {
            header,
            chunks,
            records,
            warnings,
        })
    }
}

/// Result of loading EVTX records from a [`ForensicSource`].
#[derive(Debug, Default)]
pub(crate) struct LoadedRecords {
    pub records: Vec<EvtxRecord>,
    pub warnings: Vec<DiagnosticWarning>,
}

/// Loads EVTX records from `OfflineBytes`, `OfflinePath` (file or directory walk), or `Live`.
pub(crate) fn load_records(
    source: &ForensicSource,
    tool_id: &str,
    live_channels: &[&str],
    live_opts: &LiveQueryOptions,
) -> Result<LoadedRecords, ForensicError> {
    match source {
        ForensicSource::OfflineBytes(bytes) => {
            let archive = EvtxArchive::from_bytes(bytes)?;
            Ok(LoadedRecords {
                warnings: archive.warnings().to_vec(),
                records: archive.into_records(),
            })
        }
        ForensicSource::OfflinePath(path) => load_records_from_path(path, tool_id),
        ForensicSource::Live => {
            let (records, warnings) = live::query_channels(tool_id, live_channels, live_opts)?;
            Ok(LoadedRecords { records, warnings })
        }
    }
}

fn load_records_from_path(path: &Path, tool_id: &str) -> Result<LoadedRecords, ForensicError> {
    if !path.exists() {
        return Err(ForensicError::NotFound(path.display().to_string()));
    }
    if path.is_file() {
        let archive = EvtxArchive::open(path)?;
        return Ok(LoadedRecords {
            warnings: archive.warnings().to_vec(),
            records: archive.into_records(),
        });
    }
    if path.is_dir() {
        let evtx_files = collect_evtx_files(path)?;
        if evtx_files.is_empty() {
            return Ok(LoadedRecords {
                records: Vec::new(),
                warnings: vec![DiagnosticWarning {
                    severity: WarningSeverity::Warn,
                    tool_id: tool_id.to_string(),
                    source: path.display().to_string(),
                    message: format!("no .evtx files found under directory {}", path.display()),
                }],
            });
        }

        let mut all_records = Vec::new();
        let mut warnings = Vec::new();
        let mut first_err: Option<ForensicError> = None;
        let mut succeeded_files = 0usize;

        for file_path in evtx_files {
            match EvtxArchive::open(&file_path) {
                Ok(archive) => {
                    succeeded_files += 1;
                    warnings.extend(archive.warnings().iter().cloned());
                    all_records.extend(archive.into_records());
                }
                Err(err) => {
                    warnings.push(DiagnosticWarning {
                        severity: WarningSeverity::Warn,
                        tool_id: tool_id.to_string(),
                        source: file_path.display().to_string(),
                        message: err.to_string(),
                    });
                    if first_err.is_none() {
                        first_err = Some(err);
                    }
                }
            }
        }

        if succeeded_files == 0
            && let Some(err) = first_err
        {
            return Err(err);
        }

        return Ok(LoadedRecords {
            records: all_records,
            warnings,
        });
    }

    Err(ForensicError::InvalidArgument(format!(
        "path {} is neither a regular file nor a directory",
        path.display()
    )))
}

pub(crate) fn collect_evtx_files(dir: &Path) -> Result<Vec<PathBuf>, ForensicError> {
    let mut files = Vec::new();
    for entry in WalkDir::new(dir).follow_links(false) {
        let entry = entry.map_err(|err| {
            let p = err
                .path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| dir.display().to_string());
            if let Some(io_err) = err.into_io_error() {
                ForensicError::io_classified(p, io_err)
            } else {
                ForensicError::InvalidArgument(format!("failed walking directory {p}"))
            }
        })?;
        if entry.file_type().is_file()
            && entry
                .path()
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("evtx"))
        {
            files.push(entry.into_path());
        }
    }
    files.sort();
    Ok(files)
}

/// Loads EVTX channel metadata for `evtx.channels` (`Live` via `wevtapi` + Registry,
/// or offline from `.evtx` files/bytes).
pub(crate) fn load_channels(
    source: &ForensicSource,
) -> Result<(Vec<ChannelMetadata>, Vec<DiagnosticWarning>), ForensicError> {
    match source {
        ForensicSource::Live => live::enumerate_channels(),
        ForensicSource::OfflineBytes(bytes) => {
            let archive = EvtxArchive::from_bytes(bytes)?;
            let warnings = archive.warnings().to_vec();
            let raw_header = bytes[..bytes.len().min(128)].to_vec();
            let mut counts: BTreeMap<String, u64> = BTreeMap::new();
            for rec in archive.records() {
                let ch = if rec.channel.is_empty() {
                    "(unknown)".to_string()
                } else {
                    rec.channel.clone()
                };
                *counts.entry(ch).or_insert(0) += 1;
            }
            if counts.is_empty() {
                counts.insert("(empty)".to_string(), 0);
            }
            let channels = counts
                .into_iter()
                .map(|(channel_name, event_count)| ChannelMetadata {
                    channel_name,
                    log_file_path: "<memory>".to_string(),
                    enabled: None,
                    channel_type: Some("Offline".to_string()),
                    isolation: None,
                    max_size_kb: None,
                    event_count: Some(event_count),
                    file_size: Some(bytes.len() as u64),
                    modified_time: None,
                    owning_publisher: None,
                    classic_eventlog: None,
                    raw_bytes: raw_header.clone(),
                })
                .collect();
            Ok((channels, warnings))
        }
        ForensicSource::OfflinePath(path) => {
            if !path.exists() {
                return Err(ForensicError::NotFound(path.display().to_string()));
            }
            let files = if path.is_file() {
                vec![path.to_path_buf()]
            } else if path.is_dir() {
                collect_evtx_files(path)?
            } else {
                return Err(ForensicError::InvalidArgument(format!(
                    "path {} is neither a file nor a directory",
                    path.display()
                )));
            };

            let mut out = Vec::new();
            let mut warnings = Vec::new();
            let mut first_err: Option<ForensicError> = None;
            for file in files {
                let meta = fs::metadata(&file).ok();
                let file_size = meta.as_ref().map(|m| m.len());
                let modified_time = meta.as_ref().and_then(|m| m.modified().ok()).map(DateTime::<Utc>::from);
                let bytes =
                    fs::read(&file).map_err(|err| ForensicError::io_classified(file.display().to_string(), err))?;
                let raw_header = bytes[..bytes.len().min(128)].to_vec();
                match EvtxArchive::from_bytes(&bytes) {
                    Ok(archive) => {
                        warnings.extend(archive.warnings().iter().cloned());
                        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
                        for rec in archive.records() {
                            let ch = if rec.channel.is_empty() {
                                file_stem_or_unknown(&file)
                            } else {
                                rec.channel.clone()
                            };
                            *counts.entry(ch).or_insert(0) += 1;
                        }
                        if counts.is_empty() {
                            counts.insert(file_stem_or_unknown(&file), 0);
                        }
                        for (channel_name, event_count) in counts {
                            out.push(ChannelMetadata {
                                channel_name,
                                log_file_path: file.display().to_string(),
                                enabled: None,
                                channel_type: Some("Offline".to_string()),
                                isolation: None,
                                max_size_kb: None,
                                event_count: Some(event_count),
                                file_size,
                                modified_time,
                                owning_publisher: None,
                                classic_eventlog: None,
                                raw_bytes: raw_header.clone(),
                            });
                        }
                    }
                    Err(err) => {
                        if path.is_file() {
                            return Err(err);
                        }
                        warnings.push(DiagnosticWarning {
                            severity: WarningSeverity::Warn,
                            tool_id: "evtx.channels".to_string(),
                            source: file.display().to_string(),
                            message: err.to_string(),
                        });
                        if first_err.is_none() {
                            first_err = Some(err);
                        }
                    }
                }
            }
            if out.is_empty()
                && let Some(err) = first_err
            {
                return Err(err);
            }
            Ok((out, warnings))
        }
    }
}

/// Loads EVTX publisher/source metadata for `evtx.sources` (`Live` via `wevtapi` + Registry,
/// or offline from unique `(provider, channel, provider_guid)` tuples observed in `.evtx` records).
pub(crate) fn load_sources(
    source: &ForensicSource,
) -> Result<(Vec<SourceMetadata>, Vec<DiagnosticWarning>), ForensicError> {
    if source.is_live() {
        return live::enumerate_sources();
    }

    let loaded = load_records(source, "evtx.sources", &[], &LiveQueryOptions::default())?;
    let mut grouped: BTreeMap<(String, String), (Option<String>, u64)> = BTreeMap::new();
    let mut seen_guids: HashSet<(String, String)> = HashSet::new();

    for rec in &loaded.records {
        let source_name = if rec.provider.is_empty() {
            "(unknown)".to_string()
        } else {
            rec.provider.clone()
        };
        let channel = if rec.channel.is_empty() {
            "(unknown)".to_string()
        } else {
            rec.channel.clone()
        };
        let key = (source_name.clone(), channel.clone());
        let entry = grouped
            .entry(key.clone())
            .or_insert_with(|| (rec.provider_guid.clone(), 0));
        if entry.0.is_none() && rec.provider_guid.is_some() && seen_guids.insert(key) {
            entry.0 = rec.provider_guid.clone();
        }
        entry.1 += 1;
    }

    let sources = grouped
        .into_iter()
        .map(|((source_name, channel), (provider_guid, count))| {
            let meta_json = serde_json::json!({
                "source_mode": "offline",
                "source_name": source_name,
                "channel": channel,
                "provider_guid": provider_guid,
                "observed_event_count": count,
            });
            let raw_bytes = serde_json::to_vec_pretty(&meta_json).unwrap_or_default();
            SourceMetadata {
                source_name,
                channel,
                provider_guid,
                message_dll: None,
                parameter_dll: None,
                dll_exists: None,
                registry_modified: None,
                observed_event_count: Some(count),
                raw_bytes,
            }
        })
        .collect();

    Ok((sources, loaded.warnings))
}

fn file_stem_or_unknown(path: &Path) -> String {
    path.file_stem()
        .and_then(|s| s.to_str())
        .map(str::to_string)
        .unwrap_or_else(|| "(unknown)".to_string())
}

fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}
