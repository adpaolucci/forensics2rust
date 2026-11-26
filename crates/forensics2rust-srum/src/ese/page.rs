use forensics2rust_core::{DiagnosticWarning, ForensicError, WarningSeverity};

use super::header::PageFormat;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageFlags(pub u32);

impl PageFlags {
    pub const ROOT: u32 = 0x0001;
    pub const LEAF: u32 = 0x0002;
    pub const PARENT: u32 = 0x0004;
    pub const EMPTY: u32 = 0x0008;
    pub const REPAIR: u32 = 0x0010;
    pub const SPACE_TREE: u32 = 0x0020;
    pub const INDEX: u32 = 0x0040;
    pub const LONG_VALUE: u32 = 0x0080;
    pub const PRIMARY: u32 = 0x0400;
    pub const PRE_INIT: u32 = 0x1000;
    pub const NEW_RECORD_FORMAT: u32 = 0x2000;
    pub const SCRUBBED: u32 = 0x4000;
    pub const NEW_CHECKSUM: u32 = 0x8000;

    pub fn has(self, mask: u32) -> bool {
        (self.0 & mask) != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagFlags(pub u8);

impl TagFlags {
    pub const VERSION: u8 = 0x01;
    pub const DERIVED: u8 = 0x02;
    pub const COMMON: u8 = 0x04;

    pub fn has(self, mask: u8) -> bool {
        (self.0 & mask) != 0
    }

    pub fn is_versioned(self) -> bool {
        self.has(Self::VERSION)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageHeader {
    pub checksum: u64,
    pub dbtime_dirtied: u64,
    pub pgno_prev: u32,
    pub pgno_next: u32,
    pub objid_fdp: u32,
    pub cb_free: u16,
    pub cb_uncommitted_free: u16,
    pub ib_mic_free: u16,
    pub itag_state: u16,
    pub tag_count: usize,
    pub flags: PageFlags,
    pub pgno_this: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageTag {
    pub itag: usize,
    pub abs_offset: usize,
    pub size: usize,
    pub flags: TagFlags,
    pub valid: bool,
}

pub struct ParsedPage<'a> {
    pub pgno: u32,
    pub format: PageFormat,
    pub header: PageHeader,
    pub tags: Vec<PageTag>,
    pub raw: &'a [u8],
}

impl<'a> ParsedPage<'a> {
    pub fn tag_slice(&self, itag: usize) -> Option<&'a [u8]> {
        let tag = self.tags.get(itag)?;
        if !tag.valid || tag.size == 0 {
            return None;
        }
        self.raw.get(tag.abs_offset..tag.abs_offset + tag.size)
    }
}

pub fn page_slice(data: &[u8], page_size: u32, pgno: u32) -> Result<&[u8], ForensicError> {
    if pgno == 0 {
        return Err(ForensicError::parse("ESE page", "logical page number 0 is invalid"));
    }
    let ps = page_size as usize;
    let start = (pgno as usize)
        .checked_add(1)
        .and_then(|n| n.checked_mul(ps))
        .ok_or_else(|| ForensicError::parse("ESE page", format!("page {pgno} offset overflow")))?;
    let end = start
        .checked_add(ps)
        .ok_or_else(|| ForensicError::parse("ESE page", format!("page {pgno} end overflow")))?;
    data.get(start..end).ok_or_else(|| {
        ForensicError::parse(
            "ESE page",
            format!(
                "page {pgno} out of bounds (offset {start}..{end}, file len {})",
                data.len()
            ),
        )
    })
}

pub fn parse_page<'a>(
    data: &'a [u8],
    page_size: u32,
    format: PageFormat,
    pgno: u32,
    warnings: &mut Vec<DiagnosticWarning>,
) -> Result<ParsedPage<'a>, ForensicError> {
    let raw = page_slice(data, page_size, pgno)?;
    let header_len = format.header_len();
    if raw.len() < header_len {
        return Err(ForensicError::parse(
            "ESE page",
            format!("page {pgno} shorter than header ({} < {header_len})", raw.len()),
        ));
    }

    let checksum = u64::from_le_bytes(raw[0..8].try_into().unwrap_or([0; 8]));
    let dbtime_dirtied = u64::from_le_bytes(raw[8..16].try_into().unwrap_or([0; 8]));
    let pgno_prev = u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]);
    let pgno_next = u32::from_le_bytes([raw[20], raw[21], raw[22], raw[23]]);
    let objid_fdp = u32::from_le_bytes([raw[24], raw[25], raw[26], raw[27]]);
    let cb_free = u16::from_le_bytes([raw[28], raw[29]]);
    let cb_uncommitted_free = u16::from_le_bytes([raw[30], raw[31]]);
    let ib_mic_free = u16::from_le_bytes([raw[32], raw[33]]);
    let itag_state = u16::from_le_bytes([raw[34], raw[35]]);
    let tag_count = (itag_state & 0x0FFF) as usize;
    let flags = PageFlags(u32::from_le_bytes([raw[36], raw[37], raw[38], raw[39]]));
    let pgno_this = if format == PageFormat::Large {
        Some(u64::from_le_bytes(raw[64..72].try_into().unwrap_or([0; 8])) as u32)
    } else {
        None
    };

    let max_tag_bytes = raw.len().saturating_sub(header_len);
    if tag_count * 4 > max_tag_bytes {
        return Err(ForensicError::parse(
            "ESE page",
            format!("page {pgno} tag_count {tag_count} exceeds page capacity"),
        ));
    }

    let tag_array_start = raw.len() - tag_count * 4;
    let mut tags = Vec::with_capacity(tag_count);
    for itag in 0..tag_count {
        let tag_pos = raw.len() - 4 * (itag + 1);
        let size_word = u16::from_le_bytes([raw[tag_pos], raw[tag_pos + 1]]);
        let offset_word = u16::from_le_bytes([raw[tag_pos + 2], raw[tag_pos + 3]]);

        let (size, rel_offset, tag_flags) = match format {
            PageFormat::Small => (
                (size_word & 0x1FFF) as usize,
                (offset_word & 0x1FFF) as usize,
                TagFlags(((offset_word >> 13) & 0x07) as u8),
            ),
            PageFormat::Large => {
                let sz = (size_word & 0x7FFF) as usize;
                let off = (offset_word & 0x7FFF) as usize;
                let abs = header_len + off;
                let fl = if sz >= 2 && abs + 2 <= tag_array_start {
                    let first_u16 = u16::from_le_bytes([raw[abs], raw[abs + 1]]);
                    TagFlags(((first_u16 >> 13) & 0x07) as u8)
                } else {
                    TagFlags(0)
                };
                (sz, off, fl)
            }
        };

        let abs_offset = header_len + rel_offset;
        let end_ok = abs_offset.checked_add(size).is_some_and(|end| end <= tag_array_start);
        if size > 0 && !end_ok {
            warnings.push(DiagnosticWarning {
                severity: WarningSeverity::Warn,
                tool_id: "srum.db".to_string(),
                source: format!("ESE page {pgno}"),
                message: format!(
                    "tag {itag} out of bounds (offset {abs_offset} + size {size} > {tag_array_start}); skipping"
                ),
            });
        }

        tags.push(PageTag {
            itag,
            abs_offset,
            size,
            flags: tag_flags,
            valid: size == 0 || end_ok,
        });
    }

    Ok(ParsedPage {
        pgno,
        format,
        header: PageHeader {
            checksum,
            dbtime_dirtied,
            pgno_prev,
            pgno_next,
            objid_fdp,
            cb_free,
            cb_uncommitted_free,
            ib_mic_free,
            itag_state,
            tag_count,
            flags,
            pgno_this,
        },
        tags,
        raw,
    })
}
