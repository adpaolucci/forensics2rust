use std::collections::HashSet;

use forensics2rust_core::{DiagnosticWarning, ForensicError, WarningSeverity};

use super::header::{EseHeader, PageFormat};
use super::page::{PageFlags, PageTag, TagFlags, parse_page};

pub const MAX_BTREE_DEPTH: usize = 64;

#[derive(Debug, Clone)]
pub struct BTreeLeafEntry {
    pub key: Vec<u8>,
    pub data: Vec<u8>,
    pub page_flags: PageFlags,
    pub tag_flags: TagFlags,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct WalkOptions {
    pub include_versioned: bool,
}

impl WalkOptions {
    pub fn forensic_default() -> Self {
        Self {
            include_versioned: true,
        }
    }
}

struct DecodedEntry<'a> {
    key: Vec<u8>,
    payload: &'a [u8],
}

fn decode_btree_entry<'a>(
    format: PageFormat,
    tag: &PageTag,
    entry: &'a [u8],
    common_prefix: &[u8],
) -> Option<DecodedEntry<'a>> {
    if entry.len() < 2 {
        return None;
    }

    let (cb_common, cb_local, cursor) = match format {
        PageFormat::Small => {
            if tag.flags.has(TagFlags::COMMON) {
                if entry.len() < 4 {
                    return None;
                }
                let common = u16::from_le_bytes([entry[0], entry[1]]) as usize;
                let local = u16::from_le_bytes([entry[2], entry[3]]) as usize;
                (common, local, 4usize)
            } else {
                let local = u16::from_le_bytes([entry[0], entry[1]]) as usize;
                (0usize, local, 2usize)
            }
        }
        PageFormat::Large => {
            let first_u16 = u16::from_le_bytes([entry[0], entry[1]]);
            let entry_flags = TagFlags(((first_u16 >> 13) & 0x07) as u8);
            let val_13 = (first_u16 & 0x1FFF) as usize;
            if entry_flags.has(TagFlags::COMMON) {
                if entry.len() < 4 {
                    return None;
                }
                let local = (u16::from_le_bytes([entry[2], entry[3]]) & 0x1FFF) as usize;
                (val_13, local, 4usize)
            } else {
                (0usize, val_13, 2usize)
            }
        }
    };

    if cursor + cb_local > entry.len() {
        return None;
    }

    let prefix_len = cb_common.min(common_prefix.len());
    let mut key = Vec::with_capacity(prefix_len + cb_local);
    key.extend_from_slice(&common_prefix[..prefix_len]);
    key.extend_from_slice(&entry[cursor..cursor + cb_local]);
    let payload = &entry[cursor + cb_local..];

    Some(DecodedEntry { key, payload })
}

pub fn walk_btree(
    data: &[u8],
    header: &EseHeader,
    root_pgno: u32,
    options: WalkOptions,
    warnings: &mut Vec<DiagnosticWarning>,
) -> Result<Vec<BTreeLeafEntry>, ForensicError> {
    let mut visited = HashSet::new();
    let mut out = Vec::new();
    walk_recursive(
        data,
        header,
        root_pgno,
        0,
        options,
        &mut visited,
        &mut out,
        warnings,
        true,
    )?;
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn walk_recursive(
    data: &[u8],
    header: &EseHeader,
    pgno: u32,
    depth: usize,
    options: WalkOptions,
    visited: &mut HashSet<u32>,
    out: &mut Vec<BTreeLeafEntry>,
    warnings: &mut Vec<DiagnosticWarning>,
    is_root_call: bool,
) -> Result<(), ForensicError> {
    if depth > MAX_BTREE_DEPTH {
        return Err(ForensicError::parse(
            "ESE B-tree",
            format!("maximum depth {MAX_BTREE_DEPTH} exceeded at page {pgno}"),
        ));
    }

    if !visited.insert(pgno) {
        warnings.push(DiagnosticWarning {
            severity: WarningSeverity::Warn,
            tool_id: "srum.db".to_string(),
            source: "ESE B-tree".to_string(),
            message: format!("cycle detected at ESE page {pgno}; stopping branch traversal"),
        });
        return Ok(());
    }

    let page = match parse_page(data, header.page_size, header.page_format, pgno, warnings) {
        Ok(p) => p,
        Err(err) => {
            if is_root_call {
                return Err(err);
            }
            warnings.push(DiagnosticWarning {
                severity: WarningSeverity::Warn,
                tool_id: "srum.db".to_string(),
                source: "ESE B-tree".to_string(),
                message: format!("skipping unreadable child page {pgno}: {err}"),
            });
            return Ok(());
        }
    };

    let flags = page.header.flags;
    if flags.has(PageFlags::EMPTY) || flags.has(PageFlags::SCRUBBED) || flags.has(PageFlags::SPACE_TREE) {
        return Ok(());
    }

    let common_prefix: &[u8] = if !flags.has(PageFlags::ROOT) {
        page.tag_slice(0).unwrap_or(&[])
    } else {
        &[]
    };

    if flags.has(PageFlags::LEAF) {
        for itag in 1..page.tags.len() {
            let tag = page.tags[itag];
            if !tag.valid || tag.size == 0 {
                continue;
            }
            if !options.include_versioned && tag.flags.has(TagFlags::VERSION) {
                continue;
            }
            let Some(raw_entry) = page.tag_slice(itag) else {
                continue;
            };
            let Some(decoded) = decode_btree_entry(header.page_format, &tag, raw_entry, common_prefix) else {
                warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Warn,
                    tool_id: "srum.db".to_string(),
                    source: format!("ESE page {pgno}"),
                    message: format!("malformed leaf B-tree entry at tag {itag}; skipping"),
                });
                continue;
            };
            out.push(BTreeLeafEntry {
                key: decoded.key,
                data: decoded.payload.to_vec(),
                page_flags: flags,
                tag_flags: tag.flags,
            });
        }
    } else {
        let mut child_pages = Vec::new();
        for itag in 1..page.tags.len() {
            let tag = page.tags[itag];
            if !tag.valid || tag.size == 0 {
                continue;
            }
            let Some(raw_entry) = page.tag_slice(itag) else {
                continue;
            };
            let Some(decoded) = decode_btree_entry(header.page_format, &tag, raw_entry, common_prefix) else {
                continue;
            };
            if decoded.payload.len() < 4 {
                continue;
            }
            let tail = &decoded.payload[decoded.payload.len() - 4..];
            let child_pgno = u32::from_le_bytes([tail[0], tail[1], tail[2], tail[3]]);
            if child_pgno != 0 {
                child_pages.push(child_pgno);
            }
        }
        for child_pgno in child_pages {
            walk_recursive(
                data,
                header,
                child_pgno,
                depth + 1,
                options,
                visited,
                out,
                warnings,
                false,
            )?;
        }
    }

    Ok(())
}
