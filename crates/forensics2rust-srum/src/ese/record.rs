use std::collections::BTreeMap;

use forensics2rust_core::ForensicError;

use super::header::PageFormat;
use super::page::PageFlags;

#[derive(Debug, Clone, Copy)]
pub struct FixedColumnLayout {
    pub id: u16,
    pub size: usize,
    pub record_offset: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct TaggedField {
    pub fid: u16,
    pub data: Vec<u8>,
    pub is_compressed: bool,
    pub is_separated: bool,
    pub is_multi_value: bool,
    pub is_two_values: bool,
    pub is_null: bool,
    pub is_derived: bool,
}

#[derive(Debug, Clone)]
pub struct ParsedRecord {
    pub fixed: BTreeMap<u16, Option<Vec<u8>>>,
    pub variable: BTreeMap<u16, Option<Vec<u8>>>,
    pub tagged: Vec<TaggedField>,
}

impl ParsedRecord {
    pub fn get_fixed(&self, fid: u16) -> Option<&[u8]> {
        self.fixed.get(&fid).and_then(|v| v.as_deref())
    }

    pub fn get_variable(&self, fid: u16) -> Option<&[u8]> {
        self.variable.get(&fid).and_then(|v| v.as_deref())
    }

    pub fn get_tagged(&self, fid: u16) -> Option<&TaggedField> {
        self.tagged.iter().find(|t| t.fid == fid)
    }

    pub fn get_tagged_for_column(&self, fid: u16, is_derived: bool, strict_derived: bool) -> Option<&TaggedField> {
        self.tagged
            .iter()
            .find(|t| t.fid == fid && t.is_derived == is_derived)
            .or_else(|| {
                if !strict_derived && is_derived {
                    self.tagged.iter().find(|t| t.fid == fid)
                } else {
                    None
                }
            })
    }
}

pub fn parse_record(
    payload: &[u8],
    page_flags: PageFlags,
    page_format: PageFormat,
    fixed_cols: &[FixedColumnLayout],
) -> Result<ParsedRecord, ForensicError> {
    if payload.len() < 4 {
        return Err(ForensicError::parse(
            "ESE record",
            format!("record shorter than 4-byte RECHDR ({} bytes)", payload.len()),
        ));
    }

    let fid_fixed_last = payload[0];
    let fid_var_last = payload[1];
    let cb_var_data_offset = u16::from_le_bytes([payload[2], payload[3]]) as usize;

    if cb_var_data_offset < 4 || cb_var_data_offset > payload.len() {
        return Err(ForensicError::parse(
            "ESE record",
            format!(
                "invalid cb_var_data_offset {cb_var_data_offset} (record len {})",
                payload.len()
            ),
        ));
    }

    let mut fixed = BTreeMap::new();
    if fid_fixed_last > 0 {
        let bitmap_len = (fid_fixed_last as usize).div_ceil(8);
        if cb_var_data_offset < 4 + bitmap_len {
            return Err(ForensicError::parse(
                "ESE record",
                format!("cb_var_data_offset {cb_var_data_offset} too small for fixed null bitmap ({bitmap_len} bytes)"),
            ));
        }
        let fixed_bitmap_start = cb_var_data_offset - bitmap_len;
        let bitmap = &payload[fixed_bitmap_start..cb_var_data_offset];

        let mut sorted_fixed: Vec<FixedColumnLayout> = fixed_cols
            .iter()
            .copied()
            .filter(|c| c.id >= 1 && c.id <= u16::from(fid_fixed_last))
            .collect();
        sorted_fixed.sort_by_key(|c| c.id);

        let use_explicit_offsets = !sorted_fixed.is_empty()
            && sorted_fixed.iter().all(|c| {
                c.record_offset
                    .is_some_and(|off| off >= 4 && off.saturating_add(c.size) <= fixed_bitmap_start)
            });

        let mut cursor = 4usize;
        for col in sorted_fixed {
            let idx = (col.id - 1) as usize;
            let is_null = (bitmap[idx / 8] & (1 << (idx % 8))) != 0;
            let start = if use_explicit_offsets {
                col.record_offset.unwrap_or(cursor)
            } else {
                let s = cursor;
                cursor = cursor.saturating_add(col.size);
                s
            };
            if is_null {
                fixed.insert(col.id, None);
            } else if let Some(end) = start.checked_add(col.size)
                && end <= fixed_bitmap_start
                && let Some(slice) = payload.get(start..end)
            {
                fixed.insert(col.id, Some(slice.to_vec()));
            } else {
                fixed.insert(col.id, None);
            }
        }
    }

    let mut variable = BTreeMap::new();
    let tagged_area_start = if fid_var_last >= 128 {
        let var_count = (fid_var_last - 127) as usize;
        let var_table_end = cb_var_data_offset
            .checked_add(var_count * 2)
            .ok_or_else(|| ForensicError::parse("ESE record", "variable table offset overflow"))?;
        if var_table_end > payload.len() {
            return Err(ForensicError::parse(
                "ESE record",
                format!(
                    "variable offset table ({var_table_end}) exceeds record length ({})",
                    payload.len()
                ),
            ));
        }
        let mut prev_end = 0usize;
        for i in 0..var_count {
            let fid = 128 + i as u16;
            let pos = cb_var_data_offset + i * 2;
            let raw = u16::from_le_bytes([payload[pos], payload[pos + 1]]);
            let is_null = (raw & 0x8000) != 0;
            let end = (raw & 0x7FFF) as usize;
            if is_null {
                variable.insert(fid, None);
            } else {
                if end < prev_end || var_table_end + end > payload.len() {
                    return Err(ForensicError::parse(
                        "ESE record",
                        format!("invalid variable column {fid} end offset {end} (prev {prev_end})"),
                    ));
                }
                variable.insert(
                    fid,
                    Some(payload[var_table_end + prev_end..var_table_end + end].to_vec()),
                );
                prev_end = end;
            }
        }
        var_table_end + prev_end
    } else {
        cb_var_data_offset
    };

    let mut tagged = Vec::new();
    if tagged_area_start < payload.len() {
        if page_flags.has(PageFlags::NEW_RECORD_FORMAT) {
            if tagged_area_start + 4 > payload.len() {
                return Err(ForensicError::parse(
                    "ESE record",
                    "truncated NewRecordFormat TAGFLD directory",
                ));
            }
            let offset_mask = match page_format {
                PageFormat::Small => 0x3FFF,
                PageFormat::Large => 0x7FFF,
            };
            let first_ib = u16::from_le_bytes([payload[tagged_area_start + 2], payload[tagged_area_start + 3]]);
            let first_offset = (first_ib & offset_mask) as usize;
            if first_offset < 4 || !first_offset.is_multiple_of(4) || tagged_area_start + first_offset > payload.len() {
                return Err(ForensicError::parse(
                    "ESE record",
                    format!("invalid first TAGFLD offset {first_offset}"),
                ));
            }
            let tag_count = first_offset / 4;
            for idx in 0..tag_count {
                let p = tagged_area_start + idx * 4;
                let fid = u16::from_le_bytes([payload[p], payload[p + 1]]);
                let ib_word = u16::from_le_bytes([payload[p + 2], payload[p + 3]]);
                let val_start = tagged_area_start + (ib_word & offset_mask) as usize;
                let val_end = if idx + 1 < tag_count {
                    let np = tagged_area_start + (idx + 1) * 4;
                    let next_ib = u16::from_le_bytes([payload[np + 2], payload[np + 3]]);
                    tagged_area_start + (next_ib & offset_mask) as usize
                } else {
                    payload.len()
                };
                if val_start > val_end || val_end > payload.len() {
                    return Err(ForensicError::parse(
                        "ESE record",
                        format!("invalid TAGFLD value bounds {val_start}..{val_end}"),
                    ));
                }
                let is_derived = (ib_word & 0x8000) != 0;
                let has_ext_header = match page_format {
                    PageFormat::Large => true,
                    PageFormat::Small => (ib_word & 0x4000) != 0,
                };
                let raw_slice = &payload[val_start..val_end];
                let (data, is_compressed, is_separated, is_multi_value, is_two_values, is_null) =
                    if has_ext_header && !raw_slice.is_empty() {
                        let hdr = raw_slice[0];
                        (
                            raw_slice[1..].to_vec(),
                            (hdr & 0x02) != 0,
                            (hdr & 0x04) != 0,
                            (hdr & 0x08) != 0,
                            (hdr & 0x10) != 0,
                            (hdr & 0x20) != 0,
                        )
                    } else {
                        (raw_slice.to_vec(), false, false, false, false, false)
                    };
                tagged.push(TaggedField {
                    fid,
                    data,
                    is_compressed,
                    is_separated,
                    is_multi_value,
                    is_two_values,
                    is_null,
                    is_derived,
                });
            }
        } else {
            let mut pos = tagged_area_start;
            while pos + 4 <= payload.len() {
                let fid = u16::from_le_bytes([payload[pos], payload[pos + 1]]);
                let cb = u16::from_le_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
                pos += 4;
                let end = pos.saturating_add(cb).min(payload.len());
                let slice = &payload[pos..end];
                let (data, is_separated) = if !slice.is_empty() {
                    (slice[1..].to_vec(), (slice[0] & 0x01) != 0)
                } else {
                    (Vec::new(), false)
                };
                tagged.push(TaggedField {
                    fid,
                    data,
                    is_compressed: false,
                    is_separated,
                    is_multi_value: false,
                    is_two_values: false,
                    is_null: false,
                    is_derived: false,
                });
                pos = end;
            }
        }
    }

    Ok(ParsedRecord {
        fixed,
        variable,
        tagged,
    })
}
