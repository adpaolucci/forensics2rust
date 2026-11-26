use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use forensics2rust_core::crc32_ieee;
use forensics2rust_hive::regf::RegfBuilder;
use forensics2rust_srum::ese::header::compute_header_xor32_checksum;
use forensics2rust_srum::ese::page::PageFlags;
use tempfile::TempDir;

pub struct SyntheticSuiteDir {
    dir: TempDir,
}

impl SyntheticSuiteDir {
    pub fn create() -> Self {
        let dir = tempfile::tempdir().expect("create temp suite dir");
        let root = dir.path();

        // 1. EVTX archive
        fs::write(root.join("Security.evtx"), build_minimal_evtx()).unwrap();

        // 2. Hive files (NTUSER.DAT + watch.reg)
        let ntuser = RegfBuilder::new("ROOT")
            .add_sz("Software\\Demo", "AppName", "forensics2rust-test")
            .add_dword("Software\\Demo", "RunCount", 7)
            .build();
        fs::write(root.join("NTUSER.DAT"), ntuser).unwrap();
        fs::write(
            root.join("watch.reg"),
            "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\Demo]\r\n\"WatchKey\"=\"enabled\"\r\n",
        )
        .unwrap();

        // 3. SRUM ESE database
        fs::write(root.join("SRUDB.dat"), build_minimal_srudb()).unwrap();

        // 4. Crash WER
        fs::write(
            root.join("Report.wer"),
            "Version=1\r\nEventType=APPCRASH\r\nAppName=notepad.exe\r\nAppPath=C:\\Windows\\System32\\notepad.exe\r\n",
        )
        .unwrap();

        // 5. Artifacts: uncompressed SCCA v30 .pf + setupapi.dev.log + vss_catalog.json
        fs::write(root.join("NOTEPAD.EXE-12345678.pf"), build_minimal_scca_v30()).unwrap();
        fs::write(
            root.join("setupapi.dev.log"),
            ">>>  [Device Install (Hardware initiated) - USB\\VID_1234&PID_5678\\SER001]\r\n>>>  Section start 2025/01/15 10:00:00.000\r\n<<<  Section end 2025/01/15 10:00:01.000\r\n<<<  [Exit status: SUCCESS]\r\n",
        )
        .unwrap();
        fs::write(
            root.join("vss_catalog.json"),
            r#"[{"shadow_id":"{11111111-2222-3333-4444-555555555555}","volume_name":"C:\\","device_object":"\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1","created_time":"2025-01-15T10:00:00Z","originating_machine":"DFIR-HOST01","service_machine":"DFIR-HOST01","state":"Complete"}]"#,
        )
        .unwrap();

        // 6. Posture JSON + CBS.log
        fs::write(
            root.join("wua_updates.json"),
            r#"[{"title":"2025-01 Cumulative Update (KB5050001)","kb_article":"KB5050001","installed_on":"2025-01-15T12:00:00Z","result":"Succeeded","operation":"Installation","category":"Security Updates"}]"#,
        )
        .unwrap();
        fs::write(
            root.join("CBS.log"),
            "2025-01-15 12:00:00, Info                  CBS    Package Package_for_RollupFix~31bf3856ad364e35~amd64~~22621.4751.1.1 is Installed\r\n",
        )
        .unwrap();

        Self { dir }
    }

    pub fn root(&self) -> &Path {
        self.dir.path()
    }

    pub fn evtx_file(&self) -> PathBuf {
        self.dir.path().join("Security.evtx")
    }

    pub fn ntuser_path(&self) -> PathBuf {
        self.dir.path().join("NTUSER.DAT")
    }

    pub fn watch_path(&self) -> PathBuf {
        self.dir.path().join("watch.reg")
    }

    pub fn srum_path(&self) -> PathBuf {
        self.dir.path().join("SRUDB.dat")
    }
}

fn push_utf16_nul(buf: &mut Vec<u8>, s: &str) {
    for u in s.encode_utf16() {
        buf.extend_from_slice(&u.to_le_bytes());
    }
    buf.extend_from_slice(&0u16.to_le_bytes());
}

fn build_minimal_evtx() -> Vec<u8> {
    const CHUNK_SIZE: usize = 65_536;
    const FILETIME_2025: u64 = 133_814_000_000_000_000;
    let mut chunk = vec![0u8; 0x200];

    let mut name_cache: HashMap<String, u32> = HashMap::new();
    let write_name_ref = |buf: &mut Vec<u8>, cache: &mut HashMap<String, u32>, name: &str| {
        let slot = buf.len();
        buf.extend_from_slice(&0u32.to_le_bytes());
        if let Some(&off) = cache.get(name) {
            buf[slot..slot + 4].copy_from_slice(&off.to_le_bytes());
            return;
        }
        let off = buf.len() as u32;
        buf[slot..slot + 4].copy_from_slice(&off.to_le_bytes());
        cache.insert(name.to_string(), off);
        let units: Vec<u16> = name.encode_utf16().collect();
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&(units.len() as u16).to_le_bytes());
        for u in units {
            buf.extend_from_slice(&u.to_le_bytes());
        }
        buf.extend_from_slice(&0u16.to_le_bytes());
    };
    let write_inline_utf16 = |buf: &mut Vec<u8>, s: &str| {
        buf.push(0x05);
        buf.push(0x01);
        let units: Vec<u16> = s.encode_utf16().collect();
        buf.extend_from_slice(&(units.len() as u16).to_le_bytes());
        for u in units {
            buf.extend_from_slice(&u.to_le_bytes());
        }
    };
    let open_elem = |buf: &mut Vec<u8>, cache: &mut HashMap<String, u32>, name: &str, attrs: &[(&str, &str)]| {
        buf.push(if attrs.is_empty() { 0x01 } else { 0x41 });
        buf.extend_from_slice(&0xFFFFu16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        write_name_ref(buf, cache, name);
        if !attrs.is_empty() {
            let size_slot = buf.len();
            buf.extend_from_slice(&0u32.to_le_bytes());
            let list_start = buf.len();
            for (i, (k, v)) in attrs.iter().enumerate() {
                buf.push(if i + 1 < attrs.len() { 0x46 } else { 0x06 });
                write_name_ref(buf, cache, k);
                write_inline_utf16(buf, v);
            }
            let list_size = (buf.len() - list_start) as u32;
            buf[size_slot..size_slot + 4].copy_from_slice(&list_size.to_le_bytes());
        }
        buf.push(0x02);
    };
    let empty_elem = |buf: &mut Vec<u8>, cache: &mut HashMap<String, u32>, name: &str, attrs: &[(&str, &str)]| {
        buf.push(if attrs.is_empty() { 0x01 } else { 0x41 });
        buf.extend_from_slice(&0xFFFFu16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        write_name_ref(buf, cache, name);
        if !attrs.is_empty() {
            let size_slot = buf.len();
            buf.extend_from_slice(&0u32.to_le_bytes());
            let list_start = buf.len();
            for (i, (k, v)) in attrs.iter().enumerate() {
                buf.push(if i + 1 < attrs.len() { 0x46 } else { 0x06 });
                write_name_ref(buf, cache, k);
                write_inline_utf16(buf, v);
            }
            let list_size = (buf.len() - list_start) as u32;
            buf[size_slot..size_slot + 4].copy_from_slice(&list_size.to_le_bytes());
        }
        buf.push(0x03);
    };
    let text_elem = |buf: &mut Vec<u8>, cache: &mut HashMap<String, u32>, name: &str, val: &str| {
        open_elem(buf, cache, name, &[]);
        write_inline_utf16(buf, val);
        buf.push(0x04);
    };

    let rec_start = chunk.len();
    chunk.extend_from_slice(&[0x2A, 0x2A, 0x00, 0x00]);
    chunk.extend_from_slice(&0u32.to_le_bytes());
    chunk.extend_from_slice(&1u64.to_le_bytes());
    chunk.extend_from_slice(&FILETIME_2025.to_le_bytes());
    chunk.extend_from_slice(&[0x0F, 0x01, 0x01, 0x00]);

    open_elem(&mut chunk, &mut name_cache, "Event", &[]);
    open_elem(&mut chunk, &mut name_cache, "System", &[]);
    empty_elem(
        &mut chunk,
        &mut name_cache,
        "Provider",
        &[("Name", "Microsoft-Windows-Security-Auditing")],
    );
    text_elem(&mut chunk, &mut name_cache, "EventID", "4688");
    text_elem(&mut chunk, &mut name_cache, "Level", "0");
    empty_elem(
        &mut chunk,
        &mut name_cache,
        "TimeCreated",
        &[("SystemTime", "2025-01-15T10:00:00Z")],
    );
    text_elem(&mut chunk, &mut name_cache, "EventRecordID", "1");
    text_elem(&mut chunk, &mut name_cache, "Channel", "Security");
    text_elem(&mut chunk, &mut name_cache, "Computer", "DFIR-HOST01");
    chunk.push(0x04);

    open_elem(&mut chunk, &mut name_cache, "EventData", &[]);
    open_elem(&mut chunk, &mut name_cache, "Data", &[("Name", "NewProcessName")]);
    write_inline_utf16(&mut chunk, r"C:\Windows\System32\notepad.exe");
    chunk.push(0x04);
    open_elem(&mut chunk, &mut name_cache, "Data", &[("Name", "SubjectUserName")]);
    write_inline_utf16(&mut chunk, "Analyst");
    chunk.push(0x04);
    chunk.push(0x04);
    chunk.push(0x04);
    chunk.push(0x00);

    chunk.extend_from_slice(&0u32.to_le_bytes());
    let rec_size = (chunk.len() - rec_start) as u32;
    chunk[rec_start + 4..rec_start + 8].copy_from_slice(&rec_size.to_le_bytes());
    let tail = chunk.len() - 4;
    chunk[tail..].copy_from_slice(&rec_size.to_le_bytes());

    let free_space = chunk.len() as u32;
    chunk.resize(CHUNK_SIZE, 0);
    chunk[0..8].copy_from_slice(b"ElfChnk\0");
    chunk[0x08..0x10].copy_from_slice(&1u64.to_le_bytes());
    chunk[0x10..0x18].copy_from_slice(&1u64.to_le_bytes());
    chunk[0x18..0x20].copy_from_slice(&1u64.to_le_bytes());
    chunk[0x20..0x28].copy_from_slice(&1u64.to_le_bytes());
    chunk[0x28..0x2C].copy_from_slice(&128u32.to_le_bytes());
    chunk[0x2C..0x30].copy_from_slice(&(rec_start as u32).to_le_bytes());
    chunk[0x30..0x34].copy_from_slice(&free_space.to_le_bytes());
    let rec_crc = crc32_ieee(&chunk[0x200..free_space as usize]);
    chunk[0x34..0x38].copy_from_slice(&rec_crc.to_le_bytes());
    let mut hdr_crc_buf = Vec::with_capacity(120 + (512 - 128));
    hdr_crc_buf.extend_from_slice(&chunk[0..120]);
    hdr_crc_buf.extend_from_slice(&chunk[128..512]);
    chunk[0x7C..0x80].copy_from_slice(&crc32_ieee(&hdr_crc_buf).to_le_bytes());

    let mut hdr = vec![0u8; 4096];
    hdr[0..8].copy_from_slice(b"ElfFile\0");
    hdr[0x18..0x20].copy_from_slice(&2u64.to_le_bytes());
    hdr[0x20..0x24].copy_from_slice(&128u32.to_le_bytes());
    hdr[0x24..0x26].copy_from_slice(&1u16.to_le_bytes());
    hdr[0x26..0x28].copy_from_slice(&3u16.to_le_bytes());
    hdr[0x28..0x2A].copy_from_slice(&4096u16.to_le_bytes());
    hdr[0x2A..0x2C].copy_from_slice(&1u16.to_le_bytes());
    let hcrc = crc32_ieee(&hdr[0..120]);
    hdr[0x7C..0x80].copy_from_slice(&hcrc.to_le_bytes());

    let mut evtx = Vec::with_capacity(4096 + CHUNK_SIZE);
    evtx.extend_from_slice(&hdr);
    evtx.extend_from_slice(&chunk);
    evtx
}

fn build_minimal_scca_v30() -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&30u32.to_le_bytes());
    data.extend_from_slice(b"SCCA");
    data.extend_from_slice(&17u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());

    let mut exe_buf = [0u8; 60];
    let mut exe_u16 = Vec::new();
    push_utf16_nul(&mut exe_u16, "NOTEPAD.EXE");
    let copy_len = exe_u16.len().min(60);
    exe_buf[..copy_len].copy_from_slice(&exe_u16[..copy_len]);
    data.extend_from_slice(&exe_buf);
    data.extend_from_slice(&0x1234_5678u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());

    let metrics_offset = 0x128usize;
    data.resize(metrics_offset, 0);
    data[0x80..0x88].copy_from_slice(&133_814_000_000_000_000u64.to_le_bytes());
    data[0xC8..0xCC].copy_from_slice(&3u32.to_le_bytes());

    let mut fn_strings = Vec::new();
    let target = r"\VOLUME{01}\WINDOWS\SYSTEM32\NOTEPAD.EXE";
    let char_len = target.encode_utf16().count() as u32;
    push_utf16_nul(&mut fn_strings, target);

    // 1 metric entry (32B)
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&char_len.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&100u64.to_le_bytes());

    let trace_chains_offset = data.len() as u32;
    let filename_strings_offset = data.len() as u32;
    let filename_strings_size = fn_strings.len() as u32;
    data.extend_from_slice(&fn_strings);

    let volumes_info_offset = data.len() as u32;
    data[0x54..0x58].copy_from_slice(&(metrics_offset as u32).to_le_bytes());
    data[0x58..0x5C].copy_from_slice(&1u32.to_le_bytes());
    data[0x5C..0x60].copy_from_slice(&trace_chains_offset.to_le_bytes());
    data[0x60..0x64].copy_from_slice(&0u32.to_le_bytes());
    data[0x64..0x68].copy_from_slice(&filename_strings_offset.to_le_bytes());
    data[0x68..0x6C].copy_from_slice(&filename_strings_size.to_le_bytes());
    data[0x6C..0x70].copy_from_slice(&volumes_info_offset.to_le_bytes());
    data[0x70..0x74].copy_from_slice(&0u32.to_le_bytes());
    data[0x74..0x78].copy_from_slice(&0u32.to_le_bytes());

    let total_len = data.len() as u32;
    data[0x0C..0x10].copy_from_slice(&total_len.to_le_bytes());
    data
}

fn build_ese_record(
    fixed_cols: &[(u16, Option<&[u8]>)],
    var_cols: &[(u16, Option<&[u8]>)],
    tagged_cols: &[(u16, u8, &[u8])],
) -> Vec<u8> {
    let last_fixed_id = fixed_cols.iter().map(|(id, _)| *id).max().unwrap_or(0);
    let last_var_id = var_cols.iter().map(|(id, _)| *id).max().unwrap_or(127);

    let mut fixed_data = Vec::new();
    let mut fixed_nulls = Vec::new();
    for (idx, (_, opt)) in fixed_cols.iter().enumerate() {
        if let Some(bytes) = opt {
            fixed_data.extend_from_slice(bytes);
        } else {
            fixed_nulls.push(idx);
        }
    }

    let fixed_end = 4 + fixed_data.len();
    let var_count = if last_var_id >= 128 {
        (last_var_id - 127) as usize
    } else {
        0
    };
    let bitmap_bytes = (last_fixed_id as usize + var_count).div_ceil(8);
    let ib_var_off = fixed_end + bitmap_bytes;

    let mut out = Vec::new();
    out.push(last_fixed_id as u8);
    out.push(last_var_id as u8);
    out.extend_from_slice(&(ib_var_off as u16).to_le_bytes());
    out.extend_from_slice(&fixed_data);

    let mut bitmap = vec![0u8; bitmap_bytes];
    for idx in fixed_nulls {
        bitmap[idx / 8] |= 1 << (idx % 8);
    }
    for i in 0..var_count {
        let fid = 128 + i as u16;
        let is_null = !var_cols.iter().any(|(id, val)| *id == fid && val.is_some());
        if is_null {
            let b_idx = last_fixed_id as usize + i;
            bitmap[b_idx / 8] |= 1 << (b_idx % 8);
        }
    }
    out.extend_from_slice(&bitmap);

    if var_count > 0 {
        let var_table_start = out.len();
        out.resize(var_table_start + var_count * 2, 0);
        let mut var_data = Vec::new();
        for i in 0..var_count {
            let fid = 128 + i as u16;
            let word = if let Some((_, Some(bytes))) = var_cols.iter().find(|(id, _)| *id == fid) {
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
        let dir_len = tagged_cols.len() * 4;
        let mut val_offset = dir_len;
        let mut dir = Vec::with_capacity(dir_len);
        let mut vals = Vec::new();
        for &(fid, hdr_flags, data) in tagged_cols {
            let mut ib_word = val_offset as u16;
            if hdr_flags != 0 {
                ib_word |= 0x4000;
            }
            dir.extend_from_slice(&fid.to_le_bytes());
            dir.extend_from_slice(&ib_word.to_le_bytes());
            if hdr_flags != 0 {
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

fn msys_obj_row(objid_table: i32, obj_type: i16, id: i32, coltyp_or_pgno: i32, space: i32, name: &str) -> Vec<u8> {
    let o = objid_table.to_le_bytes();
    let t = obj_type.to_le_bytes();
    let i = id.to_le_bytes();
    let c = coltyp_or_pgno.to_le_bytes();
    let s = space.to_le_bytes();
    let z4 = 0i32.to_le_bytes();
    let z2 = 0i16.to_le_bytes();
    let z1 = [0u8];
    build_ese_record(
        &[
            (1, Some(&o)),
            (2, Some(&t)),
            (3, Some(&i)),
            (4, Some(&c)),
            (5, Some(&s)),
            (6, Some(&z4)),
            (7, Some(&z4)),
            (8, Some(&z1)),
            (9, Some(&z2)),
            (10, Some(&z4)),
            (11, Some(&z2)),
        ],
        &[(128, Some(name.as_bytes()))],
        &[],
    )
}

fn write_ese_leaf_page(
    buf: &mut Vec<u8>,
    page_size: usize,
    pgno: u32,
    objid_fdp: u32,
    flags: u32,
    records: &[(&[u8], &[u8])],
) {
    let needed = (pgno as usize + 2) * page_size;
    if buf.len() < needed {
        buf.resize(needed, 0);
    }
    let start = (pgno as usize + 1) * page_size;
    let page = &mut buf[start..start + page_size];
    page.fill(0);
    page[24..28].copy_from_slice(&objid_fdp.to_le_bytes());
    page[34..36].copy_from_slice(&((records.len() + 1) as u16).to_le_bytes());
    page[36..40].copy_from_slice(&flags.to_le_bytes());

    let mut entries: Vec<Vec<u8>> = Vec::with_capacity(records.len() + 1);
    entries.push(vec![0u8; 16]);
    for &(key, payload) in records {
        let mut e = Vec::with_capacity(2 + key.len() + payload.len());
        e.extend_from_slice(&(key.len() as u16).to_le_bytes());
        e.extend_from_slice(key);
        e.extend_from_slice(payload);
        entries.push(e);
    }

    let mut cur = 40usize;
    for (itag, bytes) in entries.iter().enumerate() {
        let rel = (cur - 40) as u16;
        page[cur..cur + bytes.len()].copy_from_slice(bytes);
        cur += bytes.len();
        let tag_pos = page_size - 4 * (itag + 1);
        page[tag_pos..tag_pos + 2].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
        page[tag_pos + 2..tag_pos + 4].copy_from_slice(&rel.to_le_bytes());
    }
    let ib_mic_free = (cur - 40) as u16;
    let cb_free = (page_size - entries.len() * 4 - cur) as u16;
    page[28..30].copy_from_slice(&cb_free.to_le_bytes());
    page[32..34].copy_from_slice(&ib_mic_free.to_le_bytes());
}

fn build_minimal_srudb() -> Vec<u8> {
    let ps = 4096usize;
    let mut buf = vec![0u8; ps * 2];
    buf[4..8].copy_from_slice(&0x89AB_CDEFu32.to_le_bytes());
    buf[8..12].copy_from_slice(&0x0000_0620u32.to_le_bytes());
    buf[0x34..0x38].copy_from_slice(&3u32.to_le_bytes());
    buf[0xE8..0xEC].copy_from_slice(&0x17u32.to_le_bytes());
    buf[0xEC..0xF0].copy_from_slice(&(ps as u32).to_le_bytes());
    let cksum = compute_header_xor32_checksum(&buf[0..ps]);
    buf[0..4].copy_from_slice(&cksum.to_le_bytes());
    let (h0, h1) = buf.split_at_mut(ps);
    h1.copy_from_slice(h0);

    let space_flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::SPACE_TREE;
    write_ese_leaf_page(&mut buf, ps, 2, 1, space_flags, &[]);
    write_ese_leaf_page(&mut buf, ps, 3, 1, space_flags, &[]);

    let msys_recs = vec![
        msys_obj_row(1, 1, 10, 5, 0, "SruDbIdMapTable"),
        msys_obj_row(10, 2, 1, 2, 1, "IdType"),
        msys_obj_row(10, 2, 2, 4, 4, "IdIndex"),
        msys_obj_row(10, 2, 256, 11, 0, "IdBlob"),
        msys_obj_row(1, 1, 20, 6, 0, "{973F5D5C-1D90-4944-BE8E-24B94231A174}"),
        msys_obj_row(20, 2, 1, 4, 4, "AutoIncId"),
        msys_obj_row(20, 2, 2, 8, 8, "TimeStamp"),
        msys_obj_row(20, 2, 3, 4, 4, "AppId"),
        msys_obj_row(20, 2, 4, 4, 4, "UserId"),
        msys_obj_row(20, 2, 5, 15, 8, "InterfaceLuid"),
        msys_obj_row(20, 2, 6, 15, 8, "L2ProfileId"),
        msys_obj_row(20, 2, 7, 4, 4, "L2ProfileFlags"),
        msys_obj_row(20, 2, 8, 15, 8, "BytesSent"),
        msys_obj_row(20, 2, 9, 15, 8, "BytesRecvd"),
        msys_obj_row(20, 2, 10, 15, 8, "ConnectStartTime"),
    ];
    let msys_keys: Vec<(Vec<u8>, &[u8])> = msys_recs
        .iter()
        .enumerate()
        .map(|(i, r)| (format!("k{i:02}").into_bytes(), r.as_slice()))
        .collect();
    let msys_pairs: Vec<(&[u8], &[u8])> = msys_keys.iter().map(|(k, v)| (k.as_slice(), *v)).collect();

    let leaf_root = PageFlags::ROOT | PageFlags::LEAF | PageFlags::NEW_RECORD_FORMAT;
    write_ese_leaf_page(&mut buf, ps, 4, 2, leaf_root, &msys_pairs);

    let mut app_blob = Vec::new();
    push_utf16_nul(&mut app_blob, r"C:\Windows\System32\svchost.exe");
    let id_row = build_ese_record(
        &[(1, Some(&[0u8])), (2, Some(&1i32.to_le_bytes()))],
        &[],
        &[(256, 0x00, &app_blob)],
    );
    write_ese_leaf_page(&mut buf, ps, 5, 10, leaf_root, &[(b"i0", &id_row)]);

    let net_row = build_ese_record(
        &[
            (1, Some(&1i32.to_le_bytes())),
            (2, Some(&45601.5f64.to_le_bytes())),
            (3, Some(&1i32.to_le_bytes())),
            (4, Some(&1i32.to_le_bytes())),
            (5, Some(&0x0006_0000_0000_0001u64.to_le_bytes())),
            (6, Some(&0i64.to_le_bytes())),
            (7, Some(&0i32.to_le_bytes())),
            (8, Some(&4096i64.to_le_bytes())),
            (9, Some(&8192i64.to_le_bytes())),
            (10, Some(&133_814_000_000_000_000u64.to_le_bytes())),
        ],
        &[],
        &[],
    );
    write_ese_leaf_page(&mut buf, ps, 6, 20, leaf_root, &[(b"n0", &net_row)]);

    buf
}
