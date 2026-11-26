use crate::ese::header::compute_header_xor32_checksum;
use crate::ese::page::PageFlags;

pub fn encode_7bit_ascii(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut bit_buf: u32 = 0;
    let mut bit_len: u8 = 0;
    for &b in input {
        bit_buf |= u32::from(b & 0x7F) << bit_len;
        bit_len += 7;
        while bit_len >= 8 {
            out.push((bit_buf & 0xFF) as u8);
            bit_buf >>= 8;
            bit_len -= 8;
        }
    }
    if bit_len > 0 {
        out.push((bit_buf & 0xFF) as u8);
    }
    out
}

pub fn encode_ese_7bit_ascii(input: &[u8]) -> Vec<u8> {
    let mut out = vec![0x08u8];
    out.extend_from_slice(&encode_7bit_ascii(input));
    out
}

pub fn encode_ese_7bit_unicode(input: &[u8]) -> Vec<u8> {
    let mut out = vec![0x10u8];
    out.extend_from_slice(&encode_7bit_ascii(input));
    out
}

/// Pure-Rust ESENT `0x38` LZ4 block compressor for test fixtures (`[0x38][u16 LE uncompressed_len][lz4_block]`).
pub fn encode_ese_lz4(input: &[u8]) -> Vec<u8> {
    assert!(input.len() <= u16::MAX as usize);
    let mut out = Vec::new();
    out.push(0x38);
    out.extend_from_slice(&(input.len() as u16).to_le_bytes());

    if input.is_empty() {
        return out;
    }

    let mut pos = 0usize;
    let mut anchor = 0usize;
    while pos + 4 <= input.len() && input.len() - pos > 5 {
        let mut best_len = 0usize;
        let mut best_off = 0usize;
        let search_start = pos.saturating_sub(65535);
        for cand in search_start..pos {
            let mut mlen = 0usize;
            while pos + mlen < input.len().saturating_sub(5) && input[cand + mlen] == input[pos + mlen] {
                mlen += 1;
            }
            if mlen >= 4 && mlen > best_len {
                best_len = mlen;
                best_off = pos - cand;
            }
        }

        if best_len >= 4 {
            let lit_len = pos - anchor;
            let enc_match = best_len - 4;
            let token = ((lit_len.min(15) as u8) << 4) | (enc_match.min(15) as u8);
            out.push(token);
            if lit_len >= 15 {
                let mut rem = lit_len - 15;
                while rem >= 255 {
                    out.push(255);
                    rem -= 255;
                }
                out.push(rem as u8);
            }
            out.extend_from_slice(&input[anchor..pos]);
            out.extend_from_slice(&(best_off as u16).to_le_bytes());
            if enc_match >= 15 {
                let mut rem = enc_match - 15;
                while rem >= 255 {
                    out.push(255);
                    rem -= 255;
                }
                out.push(rem as u8);
            }
            pos += best_len;
            anchor = pos;
        } else {
            pos += 1;
        }
    }

    let last_lit_len = input.len() - anchor;
    let token = (last_lit_len.min(15) as u8) << 4;
    out.push(token);
    if last_lit_len >= 15 {
        let mut rem = last_lit_len - 15;
        while rem >= 255 {
            out.push(255);
            rem -= 255;
        }
        out.push(rem as u8);
    }
    out.extend_from_slice(&input[anchor..]);
    out
}

/// Simple pure-Rust `[MS-XCA]` §2.3 Plain LZ77 XPRESS compressor for test fixtures (`0x18` header).
pub fn encode_ese_xpress_lz77(input: &[u8]) -> Vec<u8> {
    assert!(input.len() <= u16::MAX as usize);
    let mut out = Vec::new();
    out.push(0x18);
    out.extend_from_slice(&(input.len() as u16).to_le_bytes());

    let mut body = Vec::new();
    let mut pos = 0usize;
    while pos < input.len() {
        let flag_pos = body.len();
        body.extend_from_slice(&0u32.to_le_bytes());
        let mut flags: u32 = 0;
        let mut nibble_idx: Option<usize> = None;

        for bit in 0..32 {
            if pos >= input.len() {
                break;
            }

            let mut best_len = 0usize;
            let mut best_off = 0usize;
            let search_start = pos.saturating_sub(8192);
            for cand in search_start..pos {
                let mut mlen = 0usize;
                while pos + mlen < input.len() && input[cand + mlen] == input[pos + mlen] {
                    mlen += 1;
                    if mlen >= 65530 {
                        break;
                    }
                }
                if mlen >= 3 && mlen > best_len {
                    best_len = mlen;
                    best_off = pos - cand;
                }
            }

            if best_len >= 3 {
                flags |= 1u32 << (31 - bit);
                let len_minus_3 = best_len - 3;
                let low3 = len_minus_3.min(7) as u16;
                let tok = (((best_off - 1) as u16) << 3) | low3;
                body.extend_from_slice(&tok.to_le_bytes());

                if len_minus_3 >= 7 {
                    let rem = len_minus_3 - 7;
                    let nib = rem.min(15) as u8;
                    if let Some(npos) = nibble_idx.take() {
                        body[npos] |= nib << 4;
                    } else {
                        nibble_idx = Some(body.len());
                        body.push(nib);
                    }
                    if rem >= 15 {
                        let rem2 = rem - 15;
                        if rem2 < 255 {
                            body.push(rem2 as u8);
                        } else {
                            body.push(255);
                            body.extend_from_slice(&(len_minus_3 as u16).to_le_bytes());
                        }
                    }
                }
                pos += best_len;
            } else {
                body.push(input[pos]);
                pos += 1;
            }
        }

        body[flag_pos..flag_pos + 4].copy_from_slice(&flags.to_le_bytes());
    }

    out.extend_from_slice(&body);
    out
}

pub fn encode_utf16le_nul(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity((s.len() + 1) * 2);
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

pub fn encode_sid_bytes(auth: u64, subs: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + subs.len() * 4);
    out.push(1);
    out.push(subs.len() as u8);
    out.extend_from_slice(&auth.to_be_bytes()[2..8]);
    for &sub in subs {
        out.extend_from_slice(&sub.to_le_bytes());
    }
    out
}

pub fn build_record(
    fixed_cols: &[(u16, Option<&[u8]>)],
    var_cols: &[(u16, Option<&[u8]>)],
    tagged_cols: &[(u16, u8, &[u8])],
    large_page: bool,
    new_record_format: bool,
) -> Vec<u8> {
    let fid_fixed_last = fixed_cols.iter().map(|(id, _)| *id).max().unwrap_or(0) as u8;
    let fid_var_last = var_cols.iter().map(|(id, _)| *id).max().unwrap_or(127) as u8;

    let mut out = vec![0u8; 4];
    for (_, val) in fixed_cols {
        if let Some(bytes) = val {
            out.extend_from_slice(bytes);
        }
    }

    if fid_fixed_last > 0 {
        let bitmap_len = (fid_fixed_last as usize).div_ceil(8);
        let mut bitmap = vec![0u8; bitmap_len];
        for (id, val) in fixed_cols {
            if val.is_none() {
                let idx = (*id - 1) as usize;
                bitmap[idx / 8] |= 1 << (idx % 8);
            }
        }
        out.extend_from_slice(&bitmap);
    }

    let cb_var_data_offset = out.len() as u16;
    out[0] = fid_fixed_last;
    out[1] = fid_var_last;
    out[2..4].copy_from_slice(&cb_var_data_offset.to_le_bytes());

    if fid_var_last >= 128 {
        let var_count = (fid_var_last - 127) as usize;
        let var_table_start = out.len();
        out.resize(var_table_start + var_count * 2, 0);
        let mut var_data = Vec::new();
        for i in 0..var_count {
            let fid = 128 + i as u16;
            let entry = var_cols.iter().find(|(id, _)| *id == fid).and_then(|(_, v)| *v);
            let word = if let Some(bytes) = entry {
                var_data.extend_from_slice(bytes);
                (var_data.len() as u16) & 0x7FFF
            } else {
                0x8000 | ((var_data.len() as u16) & 0x7FFF)
            };
            out[var_table_start + i * 2..var_table_start + i * 2 + 2].copy_from_slice(&word.to_le_bytes());
        }
        out.extend_from_slice(&var_data);
    }

    if !tagged_cols.is_empty() {
        if new_record_format {
            let dir_len = tagged_cols.len() * 4;
            let mut val_offset = dir_len;
            let mut dir = Vec::with_capacity(dir_len);
            let mut vals = Vec::new();
            for &(fid, hdr_flags, data) in tagged_cols {
                let has_ext = large_page || hdr_flags != 0;
                let mut ib_word = val_offset as u16;
                if !large_page && has_ext {
                    ib_word |= 0x4000;
                }
                dir.extend_from_slice(&fid.to_le_bytes());
                dir.extend_from_slice(&ib_word.to_le_bytes());
                if has_ext {
                    vals.push(hdr_flags);
                    val_offset += 1;
                }
                vals.extend_from_slice(data);
                val_offset += data.len();
            }
            out.extend_from_slice(&dir);
            out.extend_from_slice(&vals);
        } else {
            for &(fid, hdr_flags, data) in tagged_cols {
                let cb = (1 + data.len()) as u16;
                out.extend_from_slice(&fid.to_le_bytes());
                out.extend_from_slice(&cb.to_le_bytes());
                out.push(if (hdr_flags & 0x04) != 0 { 0x01 } else { 0x00 });
                out.extend_from_slice(data);
            }
        }
    }

    out
}

pub struct SyntheticEseBuilder {
    page_size: u32,
    large_page: bool,
    buf: Vec<u8>,
}

impl SyntheticEseBuilder {
    pub fn new(page_size: u32) -> Self {
        Self {
            page_size,
            large_page: page_size >= 16384,
            buf: vec![0u8; page_size as usize * 2],
        }
    }

    pub fn ensure_logical_pages(&mut self, max_pgno: u32) {
        let needed = (max_pgno as usize + 2) * self.page_size as usize;
        if self.buf.len() < needed {
            self.buf.resize(needed, 0);
        }
    }

    pub fn write_headers(&mut self, database_state: u32, format_revision: u32) {
        let ps = self.page_size as usize;
        let hdr = &mut self.buf[0..ps];
        hdr[4..8].copy_from_slice(&0x89AB_CDEFu32.to_le_bytes());
        hdr[8..12].copy_from_slice(&0x0000_0620u32.to_le_bytes());
        hdr[12..16].copy_from_slice(&0u32.to_le_bytes());
        hdr[0x34..0x38].copy_from_slice(&database_state.to_le_bytes());
        hdr[0xE8..0xEC].copy_from_slice(&format_revision.to_le_bytes());
        hdr[0xEC..0xF0].copy_from_slice(&self.page_size.to_le_bytes());
        let cksum = compute_header_xor32_checksum(&self.buf[0..ps]);
        self.buf[0..4].copy_from_slice(&cksum.to_le_bytes());

        let (h0, h1) = self.buf.split_at_mut(ps);
        h1[0..ps].copy_from_slice(&h0[0..ps]);
    }

    pub fn page_mut(&mut self, pgno: u32) -> &mut [u8] {
        self.ensure_logical_pages(pgno);
        let ps = self.page_size as usize;
        let start = (pgno as usize + 1) * ps;
        &mut self.buf[start..start + ps]
    }

    fn write_raw_page(
        &mut self,
        pgno: u32,
        objid_fdp: u32,
        flags: u32,
        prev: u32,
        next: u32,
        tag_entries: &[(u8, Vec<u8>)],
    ) {
        let ps = self.page_size as usize;
        let large = self.large_page;
        let header_len = if large { 80 } else { 40 };
        let page = self.page_mut(pgno);
        page.fill(0);

        page[16..20].copy_from_slice(&prev.to_le_bytes());
        page[20..24].copy_from_slice(&next.to_le_bytes());
        page[24..28].copy_from_slice(&objid_fdp.to_le_bytes());
        page[34..36].copy_from_slice(&(tag_entries.len() as u16).to_le_bytes());
        page[36..40].copy_from_slice(&flags.to_le_bytes());
        if large {
            page[64..72].copy_from_slice(&u64::from(pgno).to_le_bytes());
        }

        let mut data_cursor = header_len;
        for (itag, (tag_flags, bytes)) in tag_entries.iter().enumerate() {
            let rel_off = data_cursor - header_len;
            page[data_cursor..data_cursor + bytes.len()].copy_from_slice(bytes);
            data_cursor += bytes.len();

            let tag_pos = ps - 4 * (itag + 1);
            let size_word = bytes.len() as u16;
            let offset_word = if large {
                rel_off as u16
            } else {
                (rel_off as u16) | (u16::from(*tag_flags & 0x07) << 13)
            };
            page[tag_pos..tag_pos + 2].copy_from_slice(&size_word.to_le_bytes());
            page[tag_pos + 2..tag_pos + 4].copy_from_slice(&offset_word.to_le_bytes());
        }

        let ib_mic_free = (data_cursor - header_len) as u16;
        let cb_free = (ps - tag_entries.len() * 4 - data_cursor) as u16;
        page[28..30].copy_from_slice(&cb_free.to_le_bytes());
        page[32..34].copy_from_slice(&ib_mic_free.to_le_bytes());
    }

    fn encode_entry(&self, tag_flags: u8, cb_common: usize, local_key: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        if self.large_page {
            let fl = u16::from(tag_flags & 0x07) << 13;
            if (tag_flags & 0x04) != 0 {
                out.extend_from_slice(&(fl | (cb_common as u16 & 0x1FFF)).to_le_bytes());
                out.extend_from_slice(&(local_key.len() as u16 & 0x1FFF).to_le_bytes());
            } else {
                out.extend_from_slice(&(fl | (local_key.len() as u16 & 0x1FFF)).to_le_bytes());
            }
        } else {
            if (tag_flags & 0x04) != 0 {
                out.extend_from_slice(&(cb_common as u16).to_le_bytes());
            }
            out.extend_from_slice(&(local_key.len() as u16).to_le_bytes());
        }
        out.extend_from_slice(local_key);
        out.extend_from_slice(payload);
        out
    }

    pub fn write_branch_page(&mut self, pgno: u32, objid_fdp: u32, flags: u32, children: &[(&[u8], u32)]) {
        let mut tags = Vec::with_capacity(children.len() + 1);
        tags.push((0u8, vec![0u8; 16])); // tag 0 FDP header
        for &(key, child_pgno) in children {
            let entry = self.encode_entry(0, 0, key, &child_pgno.to_le_bytes());
            tags.push((0u8, entry));
        }
        self.write_raw_page(pgno, objid_fdp, flags, 0, 0, &tags);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn write_leaf_page(
        &mut self,
        pgno: u32,
        objid_fdp: u32,
        flags: u32,
        prev: u32,
        next: u32,
        common_prefix: &[u8],
        records: &[(u8, usize, &[u8], &[u8])],
    ) {
        let mut tags = Vec::with_capacity(records.len() + 1);
        let tag0 = if (flags & PageFlags::ROOT) != 0 {
            vec![0u8; 16]
        } else {
            common_prefix.to_vec()
        };
        tags.push((0u8, tag0));
        for &(tflags, cb_common, local_key, payload) in records {
            let entry = self.encode_entry(tflags, cb_common, local_key, payload);
            tags.push((tflags, entry));
        }
        self.write_raw_page(pgno, objid_fdp, flags, prev, next, &tags);
    }

    pub fn write_lv_page(&mut self, pgno: u32, objid_fdp: u32, chunks: &[(u32, u32, &[u8])]) {
        let flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::LONG_VALUE | PageFlags::NEW_RECORD_FORMAT;
        let mut tags = Vec::with_capacity(chunks.len() + 1);
        tags.push((0u8, vec![0u8; 16]));
        for &(lv_id, offset, data) in chunks {
            let mut key = Vec::with_capacity(8);
            key.extend_from_slice(&lv_id.to_be_bytes());
            key.extend_from_slice(&offset.to_be_bytes());
            let entry = self.encode_entry(0, 0, &key, data);
            tags.push((0u8, entry));
        }
        self.write_raw_page(pgno, objid_fdp, flags, 0, 0, &tags);
    }

    pub fn write_raw_lv_page(&mut self, pgno: u32, objid_fdp: u32, entries: &[(&[u8], &[u8])]) {
        let flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::LONG_VALUE | PageFlags::NEW_RECORD_FORMAT;
        let mut tags = Vec::with_capacity(entries.len() + 1);
        tags.push((0u8, vec![0u8; 16]));
        for &(key, data) in entries {
            let entry = self.encode_entry(0, 0, key, data);
            tags.push((0u8, entry));
        }
        self.write_raw_page(pgno, objid_fdp, flags, 0, 0, &tags);
    }

    pub fn build(self) -> Vec<u8> {
        self.buf
    }
}

#[allow(clippy::too_many_arguments)]
fn msys_row(
    objid_table: i32,
    obj_type: i16,
    id: i32,
    coltyp_or_pgno: i32,
    space_usage: i32,
    flags: i32,
    locale: i32,
    record_offset: i16,
    name: &str,
    template_table: Option<&str>,
    large_page: bool,
) -> Vec<u8> {
    let o_bytes = objid_table.to_le_bytes();
    let t_bytes = obj_type.to_le_bytes();
    let i_bytes = id.to_le_bytes();
    let c_bytes = coltyp_or_pgno.to_le_bytes();
    let s_bytes = space_usage.to_le_bytes();
    let f_bytes = flags.to_le_bytes();
    let l_bytes = locale.to_le_bytes();
    let r_bytes = [0u8];
    let ro_bytes = record_offset.to_le_bytes();
    let lc_bytes = 0i32.to_le_bytes();
    let km_bytes = 0u16.to_le_bytes();

    let fixed = [
        (1, Some(o_bytes.as_slice())),
        (2, Some(t_bytes.as_slice())),
        (3, Some(i_bytes.as_slice())),
        (4, Some(c_bytes.as_slice())),
        (5, Some(s_bytes.as_slice())),
        (6, Some(f_bytes.as_slice())),
        (7, Some(l_bytes.as_slice())),
        (8, Some(r_bytes.as_slice())),
        (9, Some(ro_bytes.as_slice())),
        (10, Some(lc_bytes.as_slice())),
        (11, Some(km_bytes.as_slice())),
    ];
    let var = [(128, Some(name.as_bytes()))];
    let mut tagged = Vec::new();
    if let Some(tmpl) = template_table {
        tagged.push((257u16, 0u8, tmpl.as_bytes()));
    }
    build_record(&fixed, &var, &tagged, large_page, true)
}

fn col_row(table_objid: i32, col_id: i32, coltyp: i32, size: i32, locale: i32, name: &str, large: bool) -> Vec<u8> {
    msys_row(table_objid, 2, col_id, coltyp, size, 0, locale, 0, name, None, large)
}

fn tbl_row(table_objid: i32, pgno_fdp: i32, name: &str, template: Option<&str>, large: bool) -> Vec<u8> {
    msys_row(1, 1, table_objid, pgno_fdp, 0, 0, 0, 0, name, template, large)
}

fn lv_row(table_objid: i32, lv_pgno_fdp: i32, large: bool) -> Vec<u8> {
    msys_row(table_objid, 4, 4, lv_pgno_fdp, 0, 0, 0, 0, "LV", None, large)
}

/// Builds a genuine multi-page 4 KiB `SRUDB.dat` synthetic ESE database exercising:
/// - Multi-page `MSysObjects` (`pgno=4` -> `pgno=5` + `pgno=6` with `fCommon` prefix compression)
/// - `SruDbIdMapTable` (`pgno=7`) with `LV` (`pgno=8`), UTF-16LE, 7-bit ASCII compressed text, SIDs
/// - `{973F5D5C-...}` (`pgno=9` -> `pgno=10` + `pgno=11`) including orphan `AppId=999`
/// - `{D10CA2FE-...}` (`pgno=12`)
/// - `{FEE4E14F-...}` (`pgno=13`)
/// - `{DD6636C4-...}` (`pgno=14`)
pub fn build_synthetic_srudb_bytes() -> Vec<u8> {
    let mut b = SyntheticEseBuilder::new(4096);
    b.write_headers(3, 0x17); // CleanShutdown, Win10+

    // Space trees on pgno 2, 3
    let space_flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::SPACE_TREE;
    b.write_leaf_page(2, 1, space_flags, 0, 0, &[], &[]);
    b.write_leaf_page(3, 1, space_flags, 0, 0, &[], &[]);

    // MSysObjects records split across pgno 5 and pgno 6
    let mut msys_part1 = vec![
        // SruDbIdMapTable (objid=10, pgno=7, LV pgno=8)
        tbl_row(10, 7, "SruDbIdMapTable", None, false),
        lv_row(10, 8, false),
        col_row(10, 1, 2, 1, 0, "IdType", false),    // UnsignedByte
        col_row(10, 2, 4, 4, 0, "IdIndex", false),   // Long
        col_row(10, 256, 11, 0, 0, "IdBlob", false), // LongBinary (tagged)
        // {973F5D5C-1D90-4944-BE8E-24B94231A174} (objid=20, pgno=9)
        tbl_row(20, 9, "{973F5D5C-1D90-4944-BE8E-24B94231A174}", None, false),
        col_row(20, 1, 4, 4, 0, "AutoIncId", false),
        col_row(20, 2, 8, 8, 0, "TimeStamp", false), // DateTime (OLE f64)
        col_row(20, 3, 4, 4, 0, "AppId", false),     // Long
        col_row(20, 4, 4, 4, 0, "UserId", false),    // Long
        col_row(20, 5, 15, 8, 0, "InterfaceLuid", false), // LongLong
        col_row(20, 6, 15, 8, 0, "L2ProfileId", false), // LongLong
        col_row(20, 7, 4, 4, 0, "L2ProfileFlags", false), // Long
        col_row(20, 8, 15, 8, 0, "BytesSent", false), // LongLong
        col_row(20, 9, 15, 8, 0, "BytesRecvd", false), // LongLong
        col_row(20, 10, 15, 8, 0, "ConnectStartTime", false), // FILETIME in LongLong
        // {D10CA2FE-6FCF-4F6D-848E-B2E99266FA89} (objid=30, pgno=12)
        tbl_row(30, 12, "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}", None, false),
        col_row(30, 1, 8, 8, 0, "TimeStamp", false),
        col_row(30, 2, 4, 4, 0, "AppId", false),
        col_row(30, 3, 4, 4, 0, "UserId", false),
        col_row(30, 4, 15, 8, 0, "ForegroundCycleTime", false),
        col_row(30, 5, 15, 8, 0, "BackgroundCycleTime", false),
        col_row(30, 6, 4, 4, 0, "FaceTime", false),
        col_row(30, 7, 15, 8, 0, "ForegroundBytesRead", false),
        col_row(30, 8, 15, 8, 0, "BackgroundBytesRead", false),
        col_row(30, 9, 15, 8, 0, "ForegroundBytesWritten", false),
        col_row(30, 10, 15, 8, 0, "BackgroundBytesWritten", false),
        col_row(30, 11, 4, 4, 0, "ForegroundContextSwitches", false),
        col_row(30, 12, 4, 4, 0, "BackgroundContextSwitches", false),
    ];

    let msys_part2 = vec![
        // {FEE4E14F-02A9-4550-B5CE-5FA2DA202E37} (objid=40, pgno=13)
        tbl_row(40, 13, "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}", None, false),
        col_row(40, 1, 8, 8, 0, "TimeStamp", false),
        col_row(40, 2, 4, 4, 0, "AppId", false),
        col_row(40, 3, 4, 4, 0, "UserId", false),
        col_row(40, 4, 15, 8, 0, "TotalEnergyConsumption", false),
        col_row(40, 5, 15, 8, 0, "CPUEnergyConsumption", false),
        col_row(40, 6, 15, 8, 0, "NetworkTailEnergyConsumption", false),
        col_row(40, 7, 4, 4, 0, "DisplayRequiredTime", false),
        // {DD6636C4-8929-4683-974E-22C046A43763} (objid=50, pgno=14)
        tbl_row(50, 14, "{DD6636C4-8929-4683-974E-22C046A43763}", None, false),
        col_row(50, 1, 8, 8, 0, "TimeStamp", false),
        col_row(50, 2, 4, 4, 0, "AppId", false),
        col_row(50, 3, 4, 4, 0, "UserId", false),
        col_row(50, 4, 15, 8, 0, "InterfaceLuid", false),
        col_row(50, 5, 15, 8, 0, "L2ProfileId", false),
        col_row(50, 6, 4, 4, 0, "ConnectedTime", false),
        col_row(50, 7, 15, 8, 0, "ConnectStartTime", false),
    ];

    b.write_branch_page(
        4,
        2,
        PageFlags::ROOT | PageFlags::PARENT | PageFlags::NEW_RECORD_FORMAT,
        &[(b"M1", 5), (b"", 6)],
    );

    let leaf_flags = PageFlags::LEAF | PageFlags::NEW_RECORD_FORMAT;
    let p1_recs: Vec<(u8, usize, &[u8], &[u8])> = msys_part1
        .drain(..)
        .enumerate()
        .map(|(i, r)| {
            let k = Box::leak(format!("k{i:02}").into_bytes().into_boxed_slice());
            let v = Box::leak(r.into_boxed_slice());
            (0u8, 0usize, &*k, &*v)
        })
        .collect();
    b.write_leaf_page(5, 2, leaf_flags, 0, 6, &[], &p1_recs);

    // Exercise fCommon prefix compression on pgno 6!
    let p2_recs: Vec<(u8, usize, &[u8], &[u8])> = msys_part2
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            let k = Box::leak(format!("{i:02}").into_bytes().into_boxed_slice());
            let v = Box::leak(r.into_boxed_slice());
            (0x04u8, 5usize, &*k, &*v)
        })
        .collect();
    b.write_leaf_page(6, 2, leaf_flags, 5, 0, b"MSYS2", &p2_recs);

    // SruDbIdMapTable (pgno=7) + LV (pgno=8)
    let long_path = format!(
        "C:\\Program Files\\Vendor\\{}\\{}\\worker.exe",
        "ComponentA_".repeat(12),
        "SubModuleB_".repeat(12)
    );
    let long_path_utf16 = encode_utf16le_nul(&long_path);
    let split = long_path_utf16.len() / 2;
    b.write_lv_page(
        8,
        10,
        &[
            (1, 0, &long_path_utf16[..split]),
            (1, split as u32, &long_path_utf16[split..]),
        ],
    );

    let svchost_blob = encode_utf16le_nul(r"C:\Windows\System32\svchost.exe");
    let compressed_pkg = encode_ese_7bit_ascii(b"Microsoft.Windows.Search_cw5n1h2txyewy");
    let terminal_blob = encode_utf16le_nul("Microsoft.WindowsTerminal_8wekyb3d8bbwe!App");
    let sid_system = encode_sid_bytes(5, &[18]);
    let sid_user = encode_sid_bytes(5, &[21, 123_456_789, 987_654_321, 111_111_111, 1001]);

    let id_rows = vec![
        build_record(
            &[(1, Some(&[0u8])), (2, Some(&1i32.to_le_bytes()))],
            &[],
            &[(256, 0x00, &svchost_blob)],
            false,
            true,
        ),
        build_record(
            &[(1, Some(&[0u8])), (2, Some(&2i32.to_le_bytes()))],
            &[],
            &[(256, 0x04, &1u32.to_le_bytes())], // Separated LV ID=1
            false,
            true,
        ),
        build_record(
            &[(1, Some(&[1u8])), (2, Some(&3i32.to_le_bytes()))],
            &[],
            &[(256, 0x02, &compressed_pkg)], // Compressed 7-bit ASCII
            false,
            true,
        ),
        build_record(
            &[(1, Some(&[2u8])), (2, Some(&4i32.to_le_bytes()))],
            &[],
            &[(256, 0x00, &terminal_blob)],
            false,
            true,
        ),
        build_record(
            &[(1, Some(&[3u8])), (2, Some(&5i32.to_le_bytes()))],
            &[],
            &[(256, 0x00, &sid_system)],
            false,
            true,
        ),
        build_record(
            &[(1, Some(&[3u8])), (2, Some(&6i32.to_le_bytes()))],
            &[],
            &[(256, 0x00, &sid_user)],
            false,
            true,
        ),
    ];
    let id_tags: Vec<(u8, usize, &[u8], &[u8])> = id_rows
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            let k = Box::leak((i as u32).to_be_bytes().to_vec().into_boxed_slice());
            let v = Box::leak(r.into_boxed_slice());
            (0u8, 0usize, &*k, &*v)
        })
        .collect();
    b.write_leaf_page(7, 10, PageFlags::ROOT | leaf_flags, 0, 0, &[], &id_tags);

    // {973F5D5C-...} multi-page B-tree: pgno=9 -> pgno=10 & pgno=11
    // OLE dates: 45600.5 = 2024-11-04T12:00:00Z, 45601.25 = 2024-11-05T06:00:00Z
    let ft_valid: i64 = 133_751_856_000_000_000;
    let luid_eth: i64 = (6i64 << 48) | 0x0000_0000_0000_0001;
    let luid_wifi: i64 = (71i64 << 48) | 0x0000_0000_0000_0002;

    let net_row_1 = build_record(
        &[
            (1, Some(&1i32.to_le_bytes())),
            (2, Some(&45600.5f64.to_le_bytes())),
            (3, Some(&1i32.to_le_bytes())),
            (4, Some(&5i32.to_le_bytes())),
            (5, Some(&luid_eth.to_le_bytes())),
            (6, Some(&101i64.to_le_bytes())),
            (7, Some(&0i32.to_le_bytes())),
            (8, Some(&1_048_576i64.to_le_bytes())),
            (9, Some(&2_097_152i64.to_le_bytes())),
            (10, Some(&ft_valid.to_le_bytes())),
        ],
        &[],
        &[],
        false,
        true,
    );
    let net_row_2 = build_record(
        &[
            (1, Some(&2i32.to_le_bytes())),
            (2, Some(&45601.25f64.to_le_bytes())),
            (3, Some(&2i32.to_le_bytes())),
            (4, Some(&6i32.to_le_bytes())),
            (5, Some(&luid_wifi.to_le_bytes())),
            (6, Some(&202i64.to_le_bytes())),
            (7, Some(&1i32.to_le_bytes())),
            (8, Some(&65_536i64.to_le_bytes())),
            (9, Some(&131_072i64.to_le_bytes())),
            (10, Some(&0i64.to_le_bytes())), // 0 -> None
        ],
        &[],
        &[],
        false,
        true,
    );
    let net_row_3_orphan = build_record(
        &[
            (1, Some(&3i32.to_le_bytes())),
            (2, Some(&0.0f64.to_le_bytes())), // 0.0 -> None
            (3, Some(&999i32.to_le_bytes())), // orphan IdIndex(999)
            (4, Some(&998i32.to_le_bytes())), // orphan IdIndex(998)
            (5, Some(&luid_wifi.to_le_bytes())),
            (6, Some(&0i64.to_le_bytes())),
            (7, Some(&0i32.to_le_bytes())),
            (8, Some(&512i64.to_le_bytes())),
            (9, Some(&1024i64.to_le_bytes())),
            (10, Some(&ft_valid.to_le_bytes())),
        ],
        &[],
        &[],
        false,
        true,
    );

    b.write_branch_page(
        9,
        20,
        PageFlags::ROOT | PageFlags::PARENT | PageFlags::NEW_RECORD_FORMAT,
        &[(b"n1", 10), (b"", 11)],
    );
    b.write_leaf_page(
        10,
        20,
        leaf_flags,
        0,
        11,
        &[],
        &[(0, 0, b"n0", &net_row_1), (0, 0, b"n1", &net_row_2)],
    );
    b.write_leaf_page(11, 20, leaf_flags, 10, 0, &[], &[(0, 0, b"n2", &net_row_3_orphan)]);

    // {D10CA2FE-...} on pgno=12
    let app_row_1 = build_record(
        &[
            (1, Some(&45601.5f64.to_le_bytes())),
            (2, Some(&3i32.to_le_bytes())),
            (3, Some(&6i32.to_le_bytes())),
            (4, Some(&500_000i64.to_le_bytes())),
            (5, Some(&250_000i64.to_le_bytes())),
            (6, Some(&120i32.to_le_bytes())),
            (7, Some(&4096i64.to_le_bytes())),
            (8, Some(&1024i64.to_le_bytes())),
            (9, Some(&2048i64.to_le_bytes())),
            (10, Some(&512i64.to_le_bytes())),
            (11, Some(&300i32.to_le_bytes())),
            (12, Some(&50i32.to_le_bytes())),
        ],
        &[],
        &[],
        false,
        true,
    );
    b.write_leaf_page(
        12,
        30,
        PageFlags::ROOT | leaf_flags,
        0,
        0,
        &[],
        &[(0, 0, b"a0", &app_row_1)],
    );

    // {FEE4E14F-...} on pgno=13
    let energy_row_1 = build_record(
        &[
            (1, Some(&45601.75f64.to_le_bytes())),
            (2, Some(&4i32.to_le_bytes())),
            (3, Some(&6i32.to_le_bytes())),
            (4, Some(&9000i64.to_le_bytes())),
            (5, Some(&6000i64.to_le_bytes())),
            (6, Some(&1500i64.to_le_bytes())),
            (7, Some(&45i32.to_le_bytes())),
        ],
        &[],
        &[],
        false,
        true,
    );
    b.write_leaf_page(
        13,
        40,
        PageFlags::ROOT | leaf_flags,
        0,
        0,
        &[],
        &[(0, 0, b"e0", &energy_row_1)],
    );

    // {DD6636C4-...} on pgno=14
    let conn_row_1 = build_record(
        &[
            (1, Some(&45601.875f64.to_le_bytes())),
            (2, Some(&1i32.to_le_bytes())),
            (3, Some(&5i32.to_le_bytes())),
            (4, Some(&luid_eth.to_le_bytes())),
            (5, Some(&101i64.to_le_bytes())),
            (6, Some(&3600i32.to_le_bytes())),
            (7, Some(&ft_valid.to_le_bytes())),
        ],
        &[],
        &[],
        false,
        true,
    );
    b.write_leaf_page(
        14,
        50,
        PageFlags::ROOT | leaf_flags,
        0,
        0,
        &[],
        &[(0, 0, b"c0", &conn_row_1)],
    );

    b.build()
}

/// Builds a genuine 16 KiB `PageFormat::Large` `DataStore.edb` synthetic fixture for
/// `forensics2rust-posture` compatibility verification.
pub fn build_synthetic_datastore_edb_bytes() -> Vec<u8> {
    let mut b = SyntheticEseBuilder::new(16384);
    b.write_headers(2, 0x66BC); // DirtyShutdown tolerated!

    let space_flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::SPACE_TREE;
    b.write_leaf_page(2, 1, space_flags, 0, 0, &[], &[]);
    b.write_leaf_page(3, 1, space_flags, 0, 0, &[], &[]);

    let msys_rows = vec![
        tbl_row(10, 5, "tbHistory", None, true),
        col_row(10, 1, 16, 16, 0, "UpdateId", true),                  // GUID
        col_row(10, 2, 4, 4, 0, "ResultCode", true),                  // Long
        col_row(10, 3, 8, 8, 0, "Date", true),                        // DateTime
        col_row(10, 128, 10, 255, 1200, "ClientApplicationId", true), // Text UTF-16LE
        col_row(10, 256, 12, 0, 1200, "Title", true),                 // LongText XPRESS compressed
        col_row(10, 257, 12, 0, 1200, "Description", true),           // LongText 7-bit Unicode compressed
    ];
    let msys_tags: Vec<(u8, usize, &[u8], &[u8])> = msys_rows
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            let k = Box::leak(format!("m{i:02}").into_bytes().into_boxed_slice());
            let v = Box::leak(r.into_boxed_slice());
            (0u8, 0usize, &*k, &*v)
        })
        .collect();
    b.write_leaf_page(
        4,
        2,
        PageFlags::ROOT | PageFlags::LEAF | PageFlags::NEW_RECORD_FORMAT,
        0,
        0,
        &[],
        &msys_tags,
    );

    let guid_bytes: [u8; 16] = [
        0x78, 0x56, 0x34, 0x12, 0xAB, 0xCD, 0xEF, 0x01, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    ];
    let client_app = encode_utf16le_nul("MoUsoCoreWorker");
    let title_plain = encode_utf16le_nul("2024-11 Cumulative Update for Windows 11 (KB5046633) - Cumulative Update");
    let title_xpress = encode_ese_xpress_lz77(&title_plain);
    let desc_7bit_unicode = encode_ese_7bit_unicode(b"Installs security and reliability improvements.");

    let hist_row = build_record(
        &[
            (1, Some(&guid_bytes)),
            (2, Some(&0i32.to_le_bytes())),
            (3, Some(&45602.5f64.to_le_bytes())),
        ],
        &[(128, Some(&client_app))],
        &[(256, 0x02, &title_xpress), (257, 0x02, &desc_7bit_unicode)],
        true,
        true,
    );

    b.write_leaf_page(
        5,
        10,
        PageFlags::ROOT | PageFlags::LEAF | PageFlags::NEW_RECORD_FORMAT,
        0,
        0,
        &[],
        &[(0, 0, b"h0", &hist_row)],
    );

    b.build()
}
