use forensics2rust_core::{DiagnosticWarning, ForensicError, WarningSeverity};

pub const ESE_SIGNATURE: u32 = 0x89AB_CDEF;
pub const ESE_MIN_HEADER_LEN: usize = 668;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseState {
    JustCreated,
    DirtyShutdown,
    CleanShutdown,
    BeingConverted,
    ForceDetach,
    Unknown(u32),
}

impl DatabaseState {
    pub fn from_u32(val: u32) -> Self {
        match val {
            1 => Self::JustCreated,
            2 => Self::DirtyShutdown,
            3 => Self::CleanShutdown,
            4 => Self::BeingConverted,
            5 => Self::ForceDetach,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageFormat {
    /// Page size <= 8192 bytes (40-byte PGHDR, 13-bit tags, `fExtendedInfo` `0x4000` in TAGFLD).
    Small,
    /// Page size >= 16384 bytes (80-byte PGHDR+PGHDR2, 15-bit tags, entry-prefix tag flags, unconditional TAGFLD_HEADER).
    Large,
}

impl PageFormat {
    pub fn from_page_size(page_size: u32) -> Self {
        if page_size <= 8192 { Self::Small } else { Self::Large }
    }

    pub fn header_len(self) -> usize {
        match self {
            Self::Small => 40,
            Self::Large => 80,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EseHeader {
    pub checksum: u32,
    pub checksum_valid: bool,
    pub signature: u32,
    pub format_version: u32,
    pub format_revision: u32,
    pub file_type: u32,
    pub database_state: DatabaseState,
    pub page_size: u32,
    pub page_format: PageFormat,
    pub repair_count: u32,
    pub total_logical_pages: u32,
    pub recovered_from_backup_header: bool,
}

pub fn compute_header_xor32_checksum(header_page: &[u8]) -> u32 {
    let end = header_page.len().min(ESE_MIN_HEADER_LEN);
    let mut xor: u32 = ESE_SIGNATURE;
    if end > 4 {
        for chunk in header_page[4..end].as_chunks::<4>().0 {
            xor ^= u32::from_le_bytes(*chunk);
        }
    }
    xor
}

fn is_valid_page_size(ps: u32) -> bool {
    matches!(ps, 2048 | 4096 | 8192 | 16384 | 32768)
}

fn try_parse_header_at(slice: &[u8]) -> Result<EseHeader, ForensicError> {
    if slice.len() < ESE_MIN_HEADER_LEN {
        return Err(ForensicError::parse(
            "ESE header",
            format!(
                "header too short ({} bytes, need at least {ESE_MIN_HEADER_LEN})",
                slice.len()
            ),
        ));
    }

    let checksum = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
    let signature = u32::from_le_bytes([slice[4], slice[5], slice[6], slice[7]]);
    if signature != ESE_SIGNATURE {
        return Err(ForensicError::parse(
            "ESE header",
            format!("invalid ESE magic 0x{signature:08X} (expected 0x{ESE_SIGNATURE:08X})"),
        ));
    }

    let format_version = u32::from_le_bytes([slice[8], slice[9], slice[10], slice[11]]);
    let file_type = u32::from_le_bytes([slice[12], slice[13], slice[14], slice[15]]);
    let database_state =
        DatabaseState::from_u32(u32::from_le_bytes([slice[0x34], slice[0x35], slice[0x36], slice[0x37]]));
    let format_revision = u32::from_le_bytes([slice[0xE8], slice[0xE9], slice[0xEA], slice[0xEB]]);
    let raw_page_size = u32::from_le_bytes([slice[0xEC], slice[0xED], slice[0xEE], slice[0xEF]]);
    let page_size = if raw_page_size == 0 { 4096 } else { raw_page_size };

    if !is_valid_page_size(page_size) {
        return Err(ForensicError::parse(
            "ESE header",
            format!("invalid ESE page size {raw_page_size}"),
        ));
    }

    let repair_count = u32::from_le_bytes([slice[0xF0], slice[0xF1], slice[0xF2], slice[0xF3]]);
    let computed_xor = compute_header_xor32_checksum(&slice[..ESE_MIN_HEADER_LEN]);
    let checksum_valid = computed_xor == checksum;

    Ok(EseHeader {
        checksum,
        checksum_valid,
        signature,
        format_version,
        format_revision,
        file_type,
        database_state,
        page_size,
        page_format: PageFormat::from_page_size(page_size),
        repair_count,
        total_logical_pages: 0,
        recovered_from_backup_header: false,
    })
}

pub fn parse_database_header(data: &[u8]) -> Result<(EseHeader, Vec<DiagnosticWarning>), ForensicError> {
    if data.len() < 2048 {
        return Err(ForensicError::parse(
            "ESE header",
            format!("ESE database too small ({} bytes, minimum 2048)", data.len()),
        ));
    }

    let mut warnings = Vec::new();
    let mut header = match try_parse_header_at(data) {
        Ok(hdr) if data.len() >= hdr.page_size as usize => hdr,
        primary_err => {
            let mut recovered = None;
            for &probe_offset in &[4096usize, 8192, 16384, 32768, 2048] {
                if data.len() >= probe_offset + ESE_MIN_HEADER_LEN
                    && let Ok(mut backup_hdr) = try_parse_header_at(&data[probe_offset..])
                    && backup_hdr.page_size as usize == probe_offset
                {
                    backup_hdr.recovered_from_backup_header = true;
                    warnings.push(DiagnosticWarning {
                        severity: WarningSeverity::Warn,
                        tool_id: "srum.db".to_string(),
                        source: "ESE header".to_string(),
                        message: format!(
                            "Primary page 0 header invalid; recovered from backup page 1 at offset {probe_offset}"
                        ),
                    });
                    recovered = Some(backup_hdr);
                    break;
                }
            }
            match recovered {
                Some(hdr) => hdr,
                None => {
                    return Err(match primary_err {
                        Ok(hdr) => ForensicError::parse(
                            "ESE header",
                            format!(
                                "file truncated ({} bytes) for declared page size {}",
                                data.len(),
                                hdr.page_size
                            ),
                        ),
                        Err(e) => e,
                    });
                }
            }
        }
    };

    header.total_logical_pages = (data.len() / header.page_size as usize).saturating_sub(2) as u32;

    if !header.checksum_valid {
        warnings.push(DiagnosticWarning {
            severity: WarningSeverity::Warn,
            tool_id: "srum.db".to_string(),
            source: "ESE header".to_string(),
            message: format!("ESE header XOR32 checksum mismatch (stored 0x{:08X})", header.checksum),
        });
    }

    if header.database_state == DatabaseState::DirtyShutdown {
        warnings.push(DiagnosticWarning {
            severity: WarningSeverity::Warn,
            tool_id: "srum.db".to_string(),
            source: "ESE header".to_string(),
            message: "ESE database state is DirtyShutdown (2); continuing read-only forensic parse".to_string(),
        });
    }

    Ok((header, warnings))
}
