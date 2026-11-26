use std::collections::BTreeMap;

use forensics2rust_core::{DiagnosticWarning, ForensicError, WarningSeverity};

use super::btree::{WalkOptions, walk_btree};
use super::compress::{DecompressOutcome, decompress_ese_value, is_known_ese_compression_header};
use super::header::EseHeader;

#[derive(Debug, Clone)]
pub struct ResolvedLongValue {
    pub bytes: Vec<u8>,
    pub is_utf16_expanded: bool,
    pub unsupported_compression: bool,
}

#[derive(Debug, Clone)]
pub struct LongValueIndex {
    chunks_4: BTreeMap<u32, Vec<(u32, Vec<u8>)>>,
    chunks_8: BTreeMap<u64, Vec<(u32, Vec<u8>)>>,
    sizes_4: BTreeMap<u32, u32>,
    sizes_8: BTreeMap<u64, u32>,
}

impl LongValueIndex {
    pub fn empty() -> Self {
        Self {
            chunks_4: BTreeMap::new(),
            chunks_8: BTreeMap::new(),
            sizes_4: BTreeMap::new(),
            sizes_8: BTreeMap::new(),
        }
    }

    pub fn build(
        data: &[u8],
        header: &EseHeader,
        lv_pgno_fdp: u32,
        warnings: &mut Vec<DiagnosticWarning>,
    ) -> Result<Self, ForensicError> {
        let entries = match walk_btree(data, header, lv_pgno_fdp, WalkOptions::forensic_default(), warnings) {
            Ok(e) => e,
            Err(err) => {
                warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Warn,
                    tool_id: "srum.db".to_string(),
                    source: format!("ESE LV tree {lv_pgno_fdp}"),
                    message: format!("failed to read LongValue tree: {err}"),
                });
                return Ok(Self::empty());
            }
        };

        let mut chunks_4: BTreeMap<u32, Vec<(u32, Vec<u8>)>> = BTreeMap::new();
        let mut chunks_8: BTreeMap<u64, Vec<(u32, Vec<u8>)>> = BTreeMap::new();
        let mut sizes_4: BTreeMap<u32, u32> = BTreeMap::new();
        let mut sizes_8: BTreeMap<u64, u32> = BTreeMap::new();
        let mut pending_8: Vec<([u8; 8], Vec<u8>)> = Vec::new();
        for entry in entries {
            if entry.tag_flags.is_versioned() && entry.data == [0x00] {
                continue;
            }
            match entry.key.len() {
                4 => {
                    if entry.data.len() >= 8 {
                        let lid = u32::from_be_bytes([entry.key[0], entry.key[1], entry.key[2], entry.key[3]]);
                        let ul_size = u32::from_le_bytes([entry.data[4], entry.data[5], entry.data[6], entry.data[7]]);
                        sizes_4.insert(lid, ul_size);
                    }
                }
                8 => {
                    if let Ok(key8) = <[u8; 8]>::try_from(entry.key.as_slice()) {
                        pending_8.push((key8, entry.data));
                    }
                }
                12 => {
                    let lid = u64::from_be_bytes(entry.key[0..8].try_into().unwrap_or([0; 8]));
                    let offset = u32::from_be_bytes([entry.key[8], entry.key[9], entry.key[10], entry.key[11]]);
                    chunks_8.entry(lid).or_default().push((offset, entry.data));
                }
                _ => {}
            }
        }

        for (key8, entry_data) in pending_8 {
            let lid8 = u64::from_be_bytes(key8);
            let lid4 = u32::from_be_bytes([key8[0], key8[1], key8[2], key8[3]]);
            let offset = u32::from_be_bytes([key8[4], key8[5], key8[6], key8[7]]);
            let is_lid8_root = entry_data.len() == 8 && (chunks_8.contains_key(&lid8) || !sizes_4.contains_key(&lid4));
            if is_lid8_root {
                let ul_size = u32::from_le_bytes([entry_data[4], entry_data[5], entry_data[6], entry_data[7]]);
                sizes_8.insert(lid8, ul_size);
            } else {
                chunks_4.entry(lid4).or_default().push((offset, entry_data));
            }
        }

        for chunks in chunks_4.values_mut() {
            chunks.sort_by_key(|(offset, _)| *offset);
        }
        for chunks in chunks_8.values_mut() {
            chunks.sort_by_key(|(offset, _)| *offset);
        }

        Ok(Self {
            chunks_4,
            chunks_8,
            sizes_4,
            sizes_8,
        })
    }

    pub fn resolve(
        &self,
        lid_bytes: &[u8],
        compressed: bool,
        warnings: &mut Vec<DiagnosticWarning>,
    ) -> Result<Option<ResolvedLongValue>, ForensicError> {
        self.resolve_column(lid_bytes, compressed, false, warnings)
    }

    pub fn resolve_column(
        &self,
        lid_bytes: &[u8],
        tagged_compressed: bool,
        col_compressed: bool,
        warnings: &mut Vec<DiagnosticWarning>,
    ) -> Result<Option<ResolvedLongValue>, ForensicError> {
        let (lid, ul_size, chunks) = match lid_bytes.len() {
            4 => {
                let lid32 = u32::from_le_bytes([lid_bytes[0], lid_bytes[1], lid_bytes[2], lid_bytes[3]]);
                (
                    u64::from(lid32),
                    self.sizes_4.get(&lid32).copied(),
                    self.chunks_4.get(&lid32),
                )
            }
            8 => {
                let lid64 = u64::from_le_bytes(lid_bytes.try_into().unwrap_or([0; 8]));
                (lid64, self.sizes_8.get(&lid64).copied(), self.chunks_8.get(&lid64))
            }
            _ => {
                warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Warn,
                    tool_id: "srum.db".to_string(),
                    source: "ESE LV".to_string(),
                    message: format!("unexpected LongValue ID length {} bytes", lid_bytes.len()),
                });
                return Ok(None);
            }
        };

        let Some(chunks) = chunks else {
            warnings.push(DiagnosticWarning {
                severity: WarningSeverity::Warn,
                tool_id: "srum.db".to_string(),
                source: "ESE LV".to_string(),
                message: format!("missing LongValue ID {lid}"),
            });
            return Ok(None);
        };

        let should_decompress = tagged_compressed || col_compressed;
        if !should_decompress {
            let total_len: usize = chunks.iter().map(|(_, c)| c.len()).sum();
            let mut combined = Vec::with_capacity(total_len);
            for (_, chunk) in chunks {
                combined.extend_from_slice(chunk);
            }
            return Ok(Some(ResolvedLongValue {
                bytes: combined,
                is_utf16_expanded: false,
                unsupported_compression: false,
            }));
        }

        // If `tagged_compressed` is explicitly set across multiple chunks where a single
        // compressed stream was split across chunks (rather than compressed per-chunk),
        // fall back to whole-stream decompression when continuation chunks lack headers.
        if tagged_compressed
            && chunks.len() > 1
            && !chunks
                .iter()
                .filter(|(_, c)| !c.is_empty())
                .all(|(_, c)| is_known_ese_compression_header(c[0]))
        {
            let total_len: usize = chunks.iter().map(|(_, c)| c.len()).sum();
            let mut combined = Vec::with_capacity(total_len);
            for (_, chunk) in chunks {
                combined.extend_from_slice(chunk);
            }
            if combined.is_empty() {
                return Ok(Some(ResolvedLongValue {
                    bytes: combined,
                    is_utf16_expanded: false,
                    unsupported_compression: false,
                }));
            }
            return match decompress_ese_value(&combined, warnings) {
                Ok(DecompressOutcome::Decompressed {
                    bytes,
                    is_utf16_expanded,
                }) => Ok(Some(ResolvedLongValue {
                    bytes,
                    is_utf16_expanded,
                    unsupported_compression: false,
                })),
                Ok(DecompressOutcome::Unsupported { .. }) => Ok(Some(ResolvedLongValue {
                    bytes: combined,
                    is_utf16_expanded: false,
                    unsupported_compression: true,
                })),
                Err(err) => {
                    warnings.push(DiagnosticWarning {
                        severity: WarningSeverity::Warn,
                        tool_id: "srum.db".to_string(),
                        source: format!("ESE LV {lid}"),
                        message: format!("LongValue decompression failed ({err}); preserving raw binary"),
                    });
                    Ok(Some(ResolvedLongValue {
                        bytes: combined,
                        is_utf16_expanded: false,
                        unsupported_compression: true,
                    }))
                }
            };
        }

        let mut out = Vec::new();
        let mut any_utf16_expanded = false;
        let mut any_unsupported_or_error = false;
        for (idx, (offset, chunk)) in chunks.iter().enumerate() {
            if chunk.is_empty() {
                continue;
            }
            let expected_span: Option<u32> = if idx + 1 < chunks.len() {
                chunks[idx + 1].0.checked_sub(*offset)
            } else {
                ul_size.and_then(|s| s.checked_sub(*offset))
            };
            let is_exact_uncompressed_span =
                !tagged_compressed && expected_span.is_some_and(|span| usize::try_from(span).ok() == Some(chunk.len()));
            let attempt =
                tagged_compressed || (!is_exact_uncompressed_span && is_known_ese_compression_header(chunk[0]));
            if !attempt {
                out.extend_from_slice(chunk);
                continue;
            }
            match decompress_ese_value(chunk, warnings) {
                Ok(DecompressOutcome::Decompressed {
                    bytes,
                    is_utf16_expanded,
                }) => {
                    any_utf16_expanded |= is_utf16_expanded;
                    out.extend_from_slice(&bytes);
                }
                Ok(DecompressOutcome::Unsupported { .. }) => {
                    if tagged_compressed {
                        any_unsupported_or_error = true;
                    }
                    out.extend_from_slice(chunk);
                }
                Err(err) => {
                    warnings.push(DiagnosticWarning {
                        severity: WarningSeverity::Warn,
                        tool_id: "srum.db".to_string(),
                        source: format!("ESE LV {lid}"),
                        message: format!("LongValue chunk decompression failed ({err}); preserving raw binary"),
                    });
                    any_unsupported_or_error = true;
                    out.extend_from_slice(chunk);
                }
            }
        }

        Ok(Some(ResolvedLongValue {
            bytes: out,
            is_utf16_expanded: any_utf16_expanded,
            unsupported_compression: any_unsupported_or_error,
        }))
    }
}
