#![forbid(unsafe_code)]

//! Deterministic synthetic binary & JSON fixtures for 100% offline testing of all 4
//! `forensics2rust-posture` tools (`posture.updates`, `posture.full_updates`,
//! `posture.defender_status`, `posture.security_center`).

use std::io::Write;
use std::path::Path;

use chrono::{TimeZone, Utc};
use flate2::Compression;
use flate2::write::GzEncoder;
use forensics2rust_core::utc_to_filetime;
use forensics2rust_hive::regf::RegfBuilder;
use forensics2rust_srum::ese::header::compute_header_xor32_checksum;
use forensics2rust_srum::ese::page::PageFlags;
use rusqlite::Connection;

pub fn encode_utf16le_nul(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity((s.len() + 1) * 2);
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

pub fn encode_utf16le_raw(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

fn build_record(
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

    if !tagged_cols.is_empty() && new_record_format {
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
    }

    out
}

struct SyntheticEseBuilder {
    page_size: u32,
    large_page: bool,
    buf: Vec<u8>,
}

impl SyntheticEseBuilder {
    fn new(page_size: u32) -> Self {
        Self {
            page_size,
            large_page: page_size >= 16384,
            buf: vec![0u8; page_size as usize * 2],
        }
    }

    fn ensure_logical_pages(&mut self, max_pgno: u32) {
        let needed = (max_pgno as usize + 2) * self.page_size as usize;
        if self.buf.len() < needed {
            self.buf.resize(needed, 0);
        }
    }

    fn write_headers(&mut self, database_state: u32, format_revision: u32) {
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

    fn page_mut(&mut self, pgno: u32) -> &mut [u8] {
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

    #[allow(clippy::too_many_arguments)]
    fn write_leaf_page(
        &mut self,
        pgno: u32,
        objid_fdp: u32,
        flags: u32,
        prev: u32,
        next: u32,
        common_prefix: &[u8],
        records: &[(&[u8], &[u8])],
    ) {
        let mut tags = Vec::with_capacity(records.len() + 1);
        let tag0 = if (flags & PageFlags::ROOT) != 0 {
            vec![0u8; 16]
        } else {
            common_prefix.to_vec()
        };
        tags.push((0u8, tag0));
        for &(local_key, payload) in records {
            let entry = self.encode_entry(0, 0, local_key, payload);
            tags.push((0u8, entry));
        }
        self.write_raw_page(pgno, objid_fdp, flags, prev, next, &tags);
    }

    fn build(self) -> Vec<u8> {
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
    name: &str,
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
    let ro_bytes = 0i16.to_le_bytes();
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
    build_record(&fixed, &var, &[], large_page, true)
}

fn tbl_row(table_objid: i32, pgno_fdp: i32, name: &str, large: bool) -> Vec<u8> {
    msys_row(1, 1, table_objid, pgno_fdp, 0, 0, 0, name, large)
}

fn col_row(table_objid: i32, col_id: i32, coltyp: i32, size: i32, locale: i32, name: &str, large: bool) -> Vec<u8> {
    msys_row(table_objid, 2, col_id, coltyp, size, 0, locale, name, large)
}

/// Builds a synthetic 16 KiB `DataStore.edb` containing `tbHistory`, `tbUpdates`,
/// `tbUpdateLocalizedProps`, and `tbFiles` exercising:
/// 1. 16-byte `JetColType::Binary` `UpdateId` join to `tbUpdates.KBArticleIds` (`KB5044285`)
/// 2. Failed update row (`Status = 4`, `MappedResult = 0x80070643`) with empty `tbHistory.Title`
///    resolved via `tbUpdateLocalizedProps` (`en-US`)
/// 3. Aborted Uninstallation row (`Flags = 2`, `Status = 5`)
pub fn build_synthetic_datastore_edb_bytes() -> Vec<u8> {
    let mut b = SyntheticEseBuilder::new(16384);
    b.write_headers(3, 0x17);

    let space_flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::SPACE_TREE;
    b.write_leaf_page(2, 1, space_flags, 0, 0, &[], &[]);
    b.write_leaf_page(3, 1, space_flags, 0, 0, &[], &[]);

    let msys_rows = vec![
        // tbHistory (objid=10, pgno=5)
        tbl_row(10, 5, "tbHistory", true),
        col_row(10, 1, 4, 4, 0, "IdEvent", true),
        col_row(10, 2, 4, 4, 0, "Status", true),
        col_row(10, 3, 4, 4, 0, "MappedResult", true),
        col_row(10, 4, 4, 4, 0, "UnmappedResult", true),
        col_row(10, 5, 9, 16, 0, "UpdateId", true),
        col_row(10, 6, 8, 8, 0, "Date", true),
        col_row(10, 7, 4, 4, 0, "Flags", true),
        col_row(10, 256, 12, 0, 1200, "ClientId", true),
        col_row(10, 257, 12, 0, 1200, "Title", true),
        col_row(10, 258, 12, 0, 1200, "Description", true),
        col_row(10, 259, 12, 0, 1200, "SupportUrl", true),
        col_row(10, 260, 12, 0, 1200, "Categories", true),
        // tbUpdates (objid=20, pgno=6)
        tbl_row(20, 6, "tbUpdates", true),
        col_row(20, 1, 4, 4, 0, "IdLocal", true),
        col_row(20, 2, 9, 16, 0, "UpdateId", true),
        col_row(20, 3, 4, 4, 0, "RevisionNumber", true),
        col_row(20, 4, 4, 4, 0, "FlightBuildNumber", true),
        col_row(20, 256, 12, 0, 1200, "SupportUrl", true),
        col_row(20, 257, 12, 0, 1200, "KBArticleIds", true),
        col_row(20, 258, 12, 0, 1200, "ProductName", true),
        // tbUpdateLocalizedProps (objid=30, pgno=7)
        tbl_row(30, 7, "tbUpdateLocalizedProps", true),
        col_row(30, 1, 4, 4, 0, "IdLocal", true),
        col_row(30, 128, 10, 32, 1252, "Language", true),
        col_row(30, 256, 12, 0, 1200, "Title", true),
        col_row(30, 257, 12, 0, 1200, "Description", true),
        col_row(30, 258, 12, 0, 1200, "SupportUrl", true),
        // tbFiles (objid=40, pgno=8)
        tbl_row(40, 8, "tbFiles", true),
        col_row(40, 1, 4, 4, 0, "IdFileLocal", true),
        col_row(40, 2, 5, 8, 0, "Size", true),
        col_row(40, 256, 12, 0, 1200, "Name", true),
    ];

    let msys_keys: Vec<Vec<u8>> = (0..msys_rows.len()).map(|i| format!("m{i:02}").into_bytes()).collect();
    let msys_tags: Vec<(&[u8], &[u8])> = msys_keys
        .iter()
        .zip(msys_rows.iter())
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect();
    let root_leaf_flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::NEW_RECORD_FORMAT;
    b.write_leaf_page(4, 2, root_leaf_flags, 0, 0, &[], &msys_tags);

    let guid_1: [u8; 16] = [
        0x78, 0x56, 0x34, 0x12, 0xAB, 0xCD, 0xEF, 0x01, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    ];
    let guid_2: [u8; 16] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
    ];
    let guid_3: [u8; 16] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22,
    ];

    // tbHistory rows
    let h1 = build_record(
        &[
            (1, Some(&1i32.to_le_bytes())),
            (2, Some(&2i32.to_le_bytes())), // Succeeded
            (3, Some(&0i32.to_le_bytes())),
            (4, Some(&0i32.to_le_bytes())),
            (5, Some(&guid_1)),
            (6, Some(&45602.5f64.to_le_bytes())),
            (7, Some(&1i32.to_le_bytes())), // Installation
        ],
        &[],
        &[
            (256, 0, &encode_utf16le_nul("MoUsoCoreWorker")),
            (257, 0, &encode_utf16le_nul("2024-11 Cumulative Update for Windows 11")),
            (
                258,
                0,
                &encode_utf16le_nul("Security improvements for Windows 11 24H2."),
            ),
            (260, 0, &encode_utf16le_nul("Security Updates")),
        ],
        true,
        true,
    );

    // Failed row with empty tbHistory.Title -> resolved from tbUpdateLocalizedProps via IdLocal=202!
    let h2 = build_record(
        &[
            (1, Some(&2i32.to_le_bytes())),
            (2, Some(&4i32.to_le_bytes())),             // Failed
            (3, Some(&(-2147023293i32).to_le_bytes())), // 0x80070643
            (4, Some(&0x643i32.to_le_bytes())),
            (5, Some(&guid_2)),
            (6, Some(&45601.25f64.to_le_bytes())),
            (7, Some(&1i32.to_le_bytes())),
        ],
        &[],
        &[(256, 0, &encode_utf16le_nul("UpdateOrchestrator"))],
        true,
        true,
    );

    // Aborted Uninstallation row
    let h3 = build_record(
        &[
            (1, Some(&3i32.to_le_bytes())),
            (2, Some(&5i32.to_le_bytes())), // Aborted
            (3, Some(&(-2145124341i32).to_le_bytes())),
            (4, Some(&0i32.to_le_bytes())),
            (5, Some(&guid_3)),
            (6, Some(&45600.75f64.to_le_bytes())),
            (7, Some(&2i32.to_le_bytes())), // Uninstallation
        ],
        &[],
        &[
            (256, 0, &encode_utf16le_nul("wuauclt")),
            (257, 0, &encode_utf16le_nul("Feature Preview Removal (KB5049999)")),
        ],
        true,
        true,
    );

    b.write_leaf_page(
        5,
        10,
        root_leaf_flags,
        0,
        0,
        &[],
        &[(b"h0", &h1), (b"h1", &h2), (b"h2", &h3)],
    );

    // tbUpdates rows
    let u1 = build_record(
        &[
            (1, Some(&101i32.to_le_bytes())),
            (2, Some(&guid_1)),
            (3, Some(&200i32.to_le_bytes())),
            (4, Some(&26100i32.to_le_bytes())),
        ],
        &[],
        &[
            (256, 0, &encode_utf16le_nul("https://support.microsoft.com/kb/5044285")),
            (257, 0, &encode_utf16le_nul("5044285")),
            (258, 0, &encode_utf16le_nul("Windows 11")),
        ],
        true,
        true,
    );
    let u2 = build_record(
        &[
            (1, Some(&202i32.to_le_bytes())),
            (2, Some(&guid_2)),
            (3, Some(&1i32.to_le_bytes())),
            (4, Some(&0i32.to_le_bytes())),
        ],
        &[],
        &[
            (256, 0, &encode_utf16le_nul("https://support.microsoft.com/kb/5045594")),
            (257, 0, &encode_utf16le_nul("KB5045594")),
            (258, 0, &encode_utf16le_nul(".NET Framework")),
        ],
        true,
        true,
    );
    b.write_leaf_page(6, 20, root_leaf_flags, 0, 0, &[], &[(b"u0", &u1), (b"u1", &u2)]);

    // tbUpdateLocalizedProps rows (de-DE and en-US for IdLocal=202 to verify en-US preference)
    let l_de = build_record(
        &[(1, Some(&202i32.to_le_bytes()))],
        &[(128, Some(b"de-DE"))],
        &[
            (256, 0, &encode_utf16le_nul("Kumulatives Update fuer .NET (KB5045594)")),
            (257, 0, &encode_utf16le_nul("Deutsche Beschreibung")),
        ],
        true,
        true,
    );
    let l_en = build_record(
        &[(1, Some(&202i32.to_le_bytes()))],
        &[(128, Some(b"en-US"))],
        &[
            (256, 0, &encode_utf16le_nul("2024-11 .NET Framework Cumulative Update")),
            (257, 0, &encode_utf16le_nul("Localized English fallback description.")),
            (
                258,
                0,
                &encode_utf16le_nul("https://support.microsoft.com/en-us/kb/5045594"),
            ),
        ],
        true,
        true,
    );
    b.write_leaf_page(7, 30, root_leaf_flags, 0, 0, &[], &[(b"l0", &l_de), (b"l1", &l_en)]);

    // tbFiles row
    let f1 = build_record(
        &[(1, Some(&1i32.to_le_bytes())), (2, Some(&12_345_678i64.to_le_bytes()))],
        &[],
        &[(256, 0, &encode_utf16le_nul("windows11.0-kb5044285-x64.msu"))],
        true,
        true,
    );
    b.write_leaf_page(8, 40, root_leaf_flags, 0, 0, &[], &[(b"f0", &f1)]);

    b.build()
}

/// Builds a synthetic SQLite `USOPrivate\UpdateStore\store.db` on disk and returns its raw bytes.
pub fn build_synthetic_store_db_bytes(path: &Path) -> Vec<u8> {
    let conn = Connection::open(path).expect("create synthetic store.db");
    conn.execute_batch(
        r#"
        CREATE TABLE COMPLETEDUPDATES (
            PROVIDERID TEXT,
            UPDATEID TEXT,
            TIME TEXT,
            TITLE TEXT,
            DESCRIPTION TEXT,
            MOREINFOURL TEXT,
            HISTORYCATEGORY TEXT,
            UNINSTALL INTEGER,
            WASREBOOTREQUIRED INTEGER,
            FOROS INTEGER,
            METADATA TEXT
        );
        CREATE TABLE UPDATEEVENTHISTORYDIAGNOSTICS (
            PROVIDERID TEXT,
            UPDATEID TEXT,
            STARTTIME TEXT,
            ENDTIME TEXT,
            EVENT TEXT,
            CATEGORY TEXT,
            TITLE TEXT,
            RESULT TEXT,
            REASON TEXT,
            UPDATEMETADATA TEXT
        );
        INSERT INTO COMPLETEDUPDATES VALUES (
            'WuProvider',
            '{11111111-2222-3333-4444-555555555555}',
            '1731094054357',
            '2024-11 Cumulative Update for Windows 11 Version 24H2 (KB5046617) 26100.2314',
            'Resolves security vulnerabilities in Windows.',
            'https://support.microsoft.com/help/5046617',
            'Quality',
            1,
            1,
            1,
            'build=10.0.26100.2314'
        );
        INSERT INTO COMPLETEDUPDATES VALUES (
            'WuProvider',
            '{66666666-7777-8888-9999-AAAAAAAAAAAA}',
            '2024-11-12T10:15:30Z',
            'Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.463.436.0)',
            'Updates Defender signatures.',
            NULL,
            'Definition',
            0,
            0,
            0,
            NULL
        );
        INSERT INTO UPDATEEVENTHISTORYDIAGNOSTICS VALUES (
            'WuProvider',
            '{BBBBBBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF}',
            '1731100000',
            '1731100600',
            'Install',
            'Driver',
            'Intel - Net - 23.80.0.1',
            '0x80240017',
            'Installation failed in sandbox',
            NULL
        );
        "#,
    )
    .expect("populate synthetic store.db");
    drop(conn);
    std::fs::read(path).expect("read synthetic store.db bytes")
}

/// Builds a synthetic UTF-8 BOM-prefixed `CBS.log` fixture exercising noise filtering,
/// `wcp.dll` build tracking, `Package_for_RollupFix`, `KB5044285`, and `HRESULT` error extraction.
pub fn build_synthetic_cbs_log_bytes() -> Vec<u8> {
    let text = concat!(
        "\u{FEFF}",
        "2024-11-12 08:00:01, Info                  CBS    WcpInitialize: wcp.dll version 10.0.26100.10068\n",
        "2024-11-12 08:00:02, Info                  CBS    Perf: LRU Cache populated in 12ms\n",
        "2024-11-12 08:00:03, Info                  CBS    Read out cached applicability for package Package_for_Dummy, ApplicableState: 0\n",
        "2024-11-12 08:00:04, Info                  CBS    InternalOpenPackage failed for dummy [HRESULT = 0x800f0805 - CBS_E_INVALID_PACKAGE]\n",
        "2024-11-12 08:00:05, Info                  CBS    Finalized package Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.10075.1.25 (KB5044285)\n",
        "2024-11-12 08:00:06, Error                 CBS    Failed to stage package Package_for_KB5045594~31bf3856ad364e35~amd64~~26100.1.1.0 [HRESULT = 0x800f081f - CBS_E_SOURCE_MISSING]\n",
    );
    text.as_bytes().to_vec()
}

/// Builds a UTF-16LE BOM-prefixed `CBS.log` byte slice.
pub fn build_synthetic_cbs_log_utf16le_bytes() -> Vec<u8> {
    let text = "2024-11-12 09:00:00, Info                  CBS    WcpInitialize: wcp.dll version 10.0.26100.10068\r\n\
                2024-11-12 09:00:02, Info                  CBS    Committed Package_for_KB5046633~31bf3856ad364e35~amd64~~26100.2314.1.0\r\n";
    let mut out = vec![0xFFu8, 0xFE];
    out.extend_from_slice(&encode_utf16le_raw(text));
    out
}

/// Builds a gzipped `CBS.persist.log.gz` byte slice.
pub fn build_synthetic_cbs_log_gz_bytes() -> Vec<u8> {
    let raw = build_synthetic_cbs_log_bytes();
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(&raw).expect("gzip write");
    enc.finish().expect("gzip finish")
}

/// Builds a synthetic `SOFTWARE` `regf` hive with Defender local keys and optional GPO `Policies`.
pub fn build_synthetic_defender_regf_bytes(include_gpo_override: bool) -> Vec<u8> {
    let mut b = RegfBuilder::new("SOFTWARE").with_file_name("SOFTWARE");

    let sig_dt = Utc.with_ymd_and_hms(2026, 11, 23, 8, 0, 36).unwrap();
    let sig_ft = utc_to_filetime(sig_dt).expect("valid filetime");

    b.add_key("Microsoft\\Windows Defender")
        .add_dword("Microsoft\\Windows Defender", "PassiveMode", 0)
        .add_dword("Microsoft\\Windows Defender", "DisableAntiSpyware", 0)
        .add_dword("Microsoft\\Windows Defender", "DisableAntiVirus", 0)
        .add_dword("Microsoft\\Windows Defender", "PUAProtection", 1)
        .add_dword("Microsoft\\Windows Defender", "IsServiceRunning", 1)
        .add_sz(
            "Microsoft\\Windows Defender",
            "InstallLocation",
            "C:\\Program Files\\Windows Defender\\",
        )
        .add_key("Microsoft\\Windows Defender\\Real-Time Protection")
        .add_dword(
            "Microsoft\\Windows Defender\\Real-Time Protection",
            "DisableRealtimeMonitoring",
            0,
        )
        .add_dword(
            "Microsoft\\Windows Defender\\Real-Time Protection",
            "DisableBehaviorMonitoring",
            0,
        )
        .add_dword(
            "Microsoft\\Windows Defender\\Real-Time Protection",
            "DisableOnAccessProtection",
            0,
        )
        .add_dword(
            "Microsoft\\Windows Defender\\Real-Time Protection",
            "DisableIOAVProtection",
            0,
        )
        .add_key("Microsoft\\Windows Defender\\Signature Updates")
        .add_sz(
            "Microsoft\\Windows Defender\\Signature Updates",
            "EngineVersion",
            "1.1.26100.4",
        )
        .add_sz(
            "Microsoft\\Windows Defender\\Signature Updates",
            "AVSignatureVersion",
            "1.463.436.0",
        )
        .add_binary(
            "Microsoft\\Windows Defender\\Signature Updates",
            "SignaturesLastUpdated",
            sig_ft.to_le_bytes().to_vec(),
        )
        .add_key("Microsoft\\Windows Defender\\Features")
        .add_dword("Microsoft\\Windows Defender\\Features", "TamperProtection", 5)
        .add_dword("Microsoft\\Windows Defender\\Features", "TamperProtectionSource", 2)
        .add_key("Microsoft\\Windows Defender\\Spynet")
        .add_dword("Microsoft\\Windows Defender\\Spynet", "SpyNetReporting", 2)
        .add_dword("Microsoft\\Windows Defender\\Spynet", "SubmitSamplesConsent", 1)
        .add_key("Microsoft\\Windows Defender\\Scan")
        .add_dword("Microsoft\\Windows Defender\\Scan", "QuickScanAge", 2)
        .add_dword("Microsoft\\Windows Defender\\Scan", "FullScanAge", u32::MAX)
        .add_key("Microsoft\\Windows Defender\\Exclusions\\Paths")
        .add_dword("Microsoft\\Windows Defender\\Exclusions\\Paths", "C:\\BuildCache", 0)
        .add_key("Microsoft\\Windows Defender\\Exclusions\\Processes")
        .add_dword("Microsoft\\Windows Defender\\Exclusions\\Processes", "cargo.exe", 0)
        .add_key("Microsoft\\Windows Defender\\Exclusions\\Extensions")
        .add_dword("Microsoft\\Windows Defender\\Exclusions\\Extensions", ".pdb", 0);

    if include_gpo_override {
        b.add_key("Policies\\Microsoft\\Windows Defender")
            .add_dword("Policies\\Microsoft\\Windows Defender", "PUAProtection", 2)
            .add_key("Policies\\Microsoft\\Windows Defender\\Real-Time Protection")
            .add_dword(
                "Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
                "DisableRealtimeMonitoring",
                1,
            )
            .add_key("Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths")
            .add_dword(
                "Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths",
                "D:\\GpoExcluded",
                0,
            );
    }

    b.build()
}

pub fn build_synthetic_defender_wmi_json_bytes() -> Vec<u8> {
    serde_json::to_vec_pretty(&serde_json::json!({
        "computer_status": {
            "AMServiceEnabled": true,
            "AntivirusEnabled": true,
            "RealTimeProtectionEnabled": true,
            "BehaviorMonitorEnabled": true,
            "IoavProtectionEnabled": true,
            "OnAccessProtectionEnabled": true,
            "IsTamperProtected": true,
            "TamperProtectionSource": "UI",
            "AMRunningMode": "Normal",
            "AMProductVersion": "4.18.26100.4",
            "AMEngineVersion": "1.1.26100.4",
            "AntivirusSignatureVersion": "1.463.436.0",
            "AntivirusSignatureLastUpdated": "20261123080036.000000+000",
            "AntivirusSignatureAge": 0,
            "QuickScanAge": 3,
            "FullScanAge": 4294967295u32,
            "QuickScanEndTime": "20261120094902.000000+000"
        },
        "preferences": {
            "DisableRealtimeMonitoring": false,
            "PUAProtection": 1,
            "MAPSReporting": 2,
            "SubmitSamplesConsent": 1,
            "HideExclusionsFromLocalUsers": true,
            "ExclusionPath": ["N/A: Must be an administrator to view exclusions"],
            "ExclusionProcess": ["N/A: Must be an administrator to view exclusions"],
            "ExclusionExtension": [".tmp"],
            "ExclusionIpAddress": []
        }
    }))
    .expect("serialize defender json")
}

pub fn build_synthetic_security_center_json_bytes() -> Vec<u8> {
    serde_json::to_vec_pretty(&serde_json::json!({
        "AntiVirusProduct": [
            {
                "displayName": "Windows Defender",
                "instanceGuid": "{D68DDC3A-831F-4fae-9E44-DA132C1ACF46}",
                "pathToSignedProductExe": "windowsdefender://",
                "pathToSignedReportingExe": "%ProgramFiles%\\Windows Defender\\MsMpeng.exe",
                "productState": 397568,
                "timestamp": "Thu, 19 Nov 2026 18:50:00 GMT"
            }
        ],
        "FirewallProduct": [
            {
                "displayName": "Contoso Endpoint Firewall",
                "instanceGuid": "{11111111-2222-3333-4444-555555555555}",
                "pathToSignedProductExe": "C:\\Program Files\\Contoso\\fw.exe",
                "pathToSignedReportingExe": "C:\\Program Files\\Contoso\\fwrpt.exe",
                "productState": "0x041010",
                "timestamp": "Thu, 19 Nov 2026 18:50:00 GMT"
            }
        ],
        "AntiSpywareProduct": []
    }))
    .expect("serialize security center json")
}
