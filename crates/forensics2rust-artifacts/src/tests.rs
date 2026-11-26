#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use forensics2rust_core::{FORENSIC_TOOL_CATALOG, ForensicError, ForensicSource, QueryHelper, ToolCategory};
use guap_table::{CellValue, TableError, TableProvider, TableQuery};
use tempfile::TempDir;

use crate::fixtures::{
    SyntheticSccaSpec, build_amcache_hive, build_destlist, build_minimal_evtx, build_ntuser_hive, build_pidl_bytes,
    build_pidl_item_drive, build_pidl_item_fs_beef0004, build_pidl_item_root_this_pc, build_setupapi_dev_log,
    build_shimcache_win7, build_shimcache_win8, build_shimcache_win10, build_software_hive, build_synthetic_cfbf,
    build_synthetic_custom_destinations, build_synthetic_lnk, build_synthetic_scca, build_system_hive,
    build_usrclass_hive, ft, ts,
};
use crate::parsers::jumplist::{parse_automatic_destinations, parse_custom_destinations};
use crate::parsers::lnk::parse_lnk;
use crate::parsers::pidl::{ShellItemKind, dos_datetime_to_utc, join_pidl_path, parse_pidl};
use crate::parsers::prefetch::parse_prefetch;
use crate::parsers::setupapi_log::parse_setupapi_dev_log;
use crate::parsers::shimcache::parse_shimcache;
use crate::parsers::xca::{decompress_mam, test_encoder::compress_mam_xca};
use crate::providers::{
    ExecutedProgramsProvider, JumpListsProvider, LastActivityProvider, MuiCacheProvider, OpenSaveProvider,
    PreviousFilesProvider, RecentFilesProvider, ShadowCopyProvider, ShellBagsProvider, UsbDevicesProvider,
    UsbLogProvider, UserAssistProvider, UserProfilesProvider, WinPrefetchProvider, all_providers,
};
use crate::vss::{PreviousFilesOptions, parse_cim_datetime, parse_vss_json, parse_vssadmin_text};
use crate::{crate_info, domain_tools, restore_previous_file, restore_previous_file_into_dir};

#[test]
fn catalog_and_all_providers_match_14_readonly_tools() {
    assert_eq!(crate_info().0, "forensics2rust-artifacts");
    let catalog_tools: Vec<_> = FORENSIC_TOOL_CATALOG
        .iter()
        .filter(|t| t.category == ToolCategory::Artifacts)
        .collect();
    assert_eq!(domain_tools().len(), 14);
    assert_eq!(catalog_tools.len(), 14);

    let providers = all_providers(&ForensicSource::Live);
    assert_eq!(providers.len(), 14);
    for (p, cat) in providers.iter().zip(catalog_tools.iter()) {
        assert_eq!(p.tool_id(), cat.tool_id);
        assert!(p.is_read_only(), "{} must be read-only", p.tool_id());
        let schema = p.schema();
        assert_eq!(schema.tool_id, cat.tool_id);
        assert!(!schema.columns.is_empty());
    }
}

#[test]
fn xca_decompress_mam_x04_and_x84_roundtrip_literals_and_lz77_matches() {
    let when = ts(2025, 5, 10, 12, 0, 0);
    let scca = build_synthetic_scca(&SyntheticSccaSpec {
        version: 30,
        exe_name: "PROCMON.EXE",
        hash: 0xDEAD_BEEF,
        run_count: 11,
        last_runs: &[ft(when)],
        loaded_files: &[
            "\\VOLUME{1}\\TOOLS\\PROCMON.EXE",
            "\\VOLUME{1}\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
        ],
        volumes: &[("\\VOLUME{1}", 0x1234_5678, ft(when))],
        v30_variant2_0x128: true,
    });

    // 1. Literal-only MAM\x04
    let mam_lit = compress_mam_xca(&scca, false, false);
    assert_eq!(decompress_mam(&mam_lit).unwrap(), scca);

    // 2. LZ77 RLE + CRC variant MAM\x84
    let mam_crc = compress_mam_xca(&scca, true, true);
    assert_eq!(decompress_mam(&mam_crc).unwrap(), scca);

    // 3. Multi-chunk (> 65,536 bytes) with long RLE exercise (ml16 and ml8 paths)
    let mut big = Vec::new();
    big.extend(std::iter::repeat_n(b'A', 70_000));
    big.extend_from_slice(&scca);
    big.extend(std::iter::repeat_n(b'B', 400));
    let big_comp = compress_mam_xca(&big, false, true);
    assert_eq!(decompress_mam(&big_comp).unwrap(), big);
}

#[test]
fn xca_exercises_ml16_zero_to_ml32_and_rejects_corrupt_inputs() {
    // Craft a minimal valid MAM\x04 stream using uniform 9-bit Huffman tree:
    // literal 'Z' (0x5A) followed by match sym=271 (match_len=15, dist_bits=0 => offset=1),
    // ml=255, ml16=0, ml32=100 => total output = 1 + (100 + 3) = 104 bytes of 'Z'.
    let mut stream = Vec::new();
    stream.extend_from_slice(b"MAM\x04");
    stream.extend_from_slice(&104u32.to_le_bytes());
    stream.extend(std::iter::repeat_n(0x99u8, 256)); // uniform 9-bit table
    // Two 9-bit codes: 0x05A (9 bits) + 271=0x10F (9 bits) = 18 bits packed MSB-first:
    // bits: 001011010 | 100001111 | 00000000000000
    // word0 = 0b001011010_1000011 = 0x2D43
    // word1 = 0b11_00000000000000 = 0xC000
    stream.extend_from_slice(&0x2D43u16.to_le_bytes());
    stream.extend_from_slice(&0xC000u16.to_le_bytes());
    // Consumed 9 + 9 = 18 bits => bits_avail=14 < 16 => decoder refills 1 word (2 bytes) BEFORE ml!
    stream.extend_from_slice(&0u16.to_le_bytes());
    stream.push(255); // ml = 255
    stream.extend_from_slice(&0u16.to_le_bytes()); // ml16 = 0
    stream.extend_from_slice(&100u32.to_le_bytes()); // ml32 = 100
    let decoded = decompress_mam(&stream).unwrap();
    assert_eq!(decoded, vec![b'Z'; 104]);

    assert!(matches!(
        decompress_mam(b"BAD\x04\x64\x00\x00\x00"),
        Err(ForensicError::Parse { .. })
    ));
    assert!(matches!(
        decompress_mam(b"MAM\x05\x64\x00\x00\x00"),
        Err(ForensicError::Parse { .. })
    ));
    // Huge uncompressed size OOM guard (256 MiB > 64 MiB cap)
    let mut oom = Vec::from(*b"MAM\x04");
    oom.extend_from_slice(&(256u32 * 1024 * 1024).to_le_bytes());
    assert!(matches!(decompress_mam(&oom), Err(ForensicError::Parse { .. })));
    // Bad Huffman table (Kraft sum > 32768)
    let mut bad_huff = Vec::from(*b"MAM\x04");
    bad_huff.extend_from_slice(&200u32.to_le_bytes());
    bad_huff.extend(std::iter::repeat_n(0x11u8, 256));
    bad_huff.extend_from_slice(&[0u8; 8]);
    assert!(matches!(decompress_mam(&bad_huff), Err(ForensicError::Parse { .. })));
}

#[test]
fn prefetch_scca_versions_v17_v23_v26_v30_and_provider() {
    let t1 = ts(2025, 5, 10, 14, 0, 0);
    let t2 = ts(2025, 5, 10, 15, 0, 0);
    for &(ver, v2) in &[
        (17, false),
        (23, false),
        (26, false),
        (30, false),
        (30, true),
        (31, true),
    ] {
        let raw = build_synthetic_scca(&SyntheticSccaSpec {
            version: ver,
            exe_name: "CMD.EXE",
            hash: 0xABCD_1234,
            run_count: 5,
            last_runs: &[ft(t2), ft(t1)],
            loaded_files: &["\\VOLUME{1}\\WINDOWS\\SYSTEM32\\CMD.EXE"],
            volumes: &[("\\VOLUME{1}", 0xCAFE_BABE, ft(t1))],
            v30_variant2_0x128: v2,
        });
        let parsed = parse_prefetch(&raw).unwrap();
        assert_eq!(parsed.version, ver);
        assert_eq!(parsed.executable_name, "CMD.EXE");
        assert_eq!(parsed.run_count, 5);
        assert_eq!(parsed.prefetch_hash, 0xABCD_1234);
        assert!(!parsed.last_run_times.is_empty());
        assert_eq!(parsed.process_path, "\\VOLUME{1}\\WINDOWS\\SYSTEM32\\CMD.EXE");
    }

    // Compressed v30 via WinPrefetchProvider + GuapQuery projection/filtering
    let scca = build_synthetic_scca(&SyntheticSccaSpec {
        version: 30,
        exe_name: "NOTEPAD.EXE",
        hash: 0x1122_3344,
        run_count: 9,
        last_runs: &[ft(t2)],
        loaded_files: &["\\DEVICE\\HARDDISKVOLUME3\\WINDOWS\\NOTEPAD.EXE"],
        volumes: &[("\\DEVICE\\HARDDISKVOLUME3", 0x9988_7766, ft(t1))],
        v30_variant2_0x128: true,
    });
    let mam = compress_mam_xca(&scca, false, true);
    let dir = TempDir::new().unwrap();
    let pf_path = dir.path().join("NOTEPAD.EXE-11223344.pf");
    fs::write(&pf_path, &mam).unwrap();

    let prov = WinPrefetchProvider::new(ForensicSource::OfflinePath(dir.path().to_path_buf()));
    let table = prov.query(&TableQuery::default()).unwrap();
    assert_eq!(table.total_rows, 1);
    let row = &table.rows[0];
    assert_eq!(row.cells[0], CellValue::Text("NOTEPAD.EXE-11223344.pf".to_string()));
    assert_eq!(row.cells[3], CellValue::Uint(9));
    assert_eq!(row.cells[6], CellValue::Text("11223344".to_string()));
    assert!(row.detail_json.is_some());
    assert!(row.raw_bytes.is_some());

    let missing = WinPrefetchProvider::new(ForensicSource::OfflinePath(dir.path().join("missing.pf")));
    assert!(matches!(
        missing.query(&TableQuery::default()),
        Err(TableError::Provider(_))
    ));
}

#[test]
fn lnk_parser_and_recent_files_provider() {
    let created = ts(2025, 5, 1, 9, 0, 0);
    let modified = ts(2025, 5, 10, 16, 30, 0);
    let lnk_bytes = build_synthetic_lnk(
        "C:\\Users\\Alice\\Documents\\evidence.docx",
        Some("Evidence Doc"),
        Some("..\\Documents\\evidence.docx"),
        Some("C:\\Users\\Alice\\Documents"),
        Some("--readonly"),
        Some("C:\\Program Files\\Word\\winword.exe"),
        0xA1B2_C3D4,
        12_345,
        ft(created),
        ft(modified),
        Some("WORKSTATION01"),
    );

    let (parsed, consumed) = parse_lnk(&lnk_bytes).unwrap();
    assert_eq!(consumed, lnk_bytes.len());
    assert_eq!(
        parsed.target_path.as_deref(),
        Some("C:\\Users\\Alice\\Documents\\evidence.docx")
    );
    assert_eq!(parsed.command_line_arguments.as_deref(), Some("--readonly"));
    assert_eq!(parsed.tracker.as_ref().unwrap().machine_id, "WORKSTATION01");

    // Negative test: truncated LNK
    assert!(parse_lnk(&lnk_bytes[..40]).is_err());

    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("evidence.docx.lnk"), &lnk_bytes).unwrap();
    let prov = RecentFilesProvider::new(ForensicSource::OfflinePath(dir.path().to_path_buf()));
    let table = prov.query(&TableQuery::default()).unwrap();
    assert_eq!(table.total_rows, 1);
    assert_eq!(table.rows[0].cells[0], CellValue::Text("evidence.docx".to_string()));
    assert_eq!(table.rows[0].cells[2], CellValue::Text("docx".to_string()));
    assert_eq!(table.rows[0].cells[6], CellValue::Bytes(12_345));
}

#[test]
fn jumplists_cfbf_destlist_v1_v4_v6_and_custom_destinations_plus_cycle_guard() {
    let when = ts(2025, 5, 10, 18, 0, 0);
    let lnk1 = build_synthetic_lnk(
        "C:\\Cases\\case01.pdf",
        None,
        None,
        None,
        Some("--page 2"),
        None,
        0xDEAD_0001,
        8192,
        ft(when),
        ft(when),
        Some("DFIR-PC"),
    );

    // 1. DestList v6 + CFBF MiniStream (<4096B) + large FAT stream (>=4096B)
    let mut padded_lnk = lnk1.clone();
    padded_lnk.resize(4200, 0);
    let dl_v6 = build_destlist(
        6,
        &[
            (0x1a, "C:\\Cases\\case01.pdf", 4, 0, ft(when), "DFIR-PC"),
            (0x1b, "C:\\Cases\\case02.pdf", 2, -1, ft(when), "DFIR-PC"),
        ],
    );
    let cfbf_bytes = build_synthetic_cfbf(&[("DestList", &dl_v6), ("1a", &lnk1), ("1b", &padded_lnk)]);
    let (auto_recs, warnings) = parse_automatic_destinations(&cfbf_bytes, "1b4dd67f29cb1962").unwrap();
    assert!(warnings.is_empty());
    assert_eq!(auto_recs.len(), 2);
    assert_eq!(auto_recs[0].pin_status, "Pinned (#0)");
    assert_eq!(auto_recs[0].access_count, Some(4));
    assert_eq!(auto_recs[0].volume_serial.as_deref(), Some("DEAD0001"));
    assert_eq!(auto_recs[1].pin_status, "Unpinned");

    // 2. DestList v1
    let dl_v1 = build_destlist(1, &[(0x1, "C:\\Legacy\\doc.txt", 3, -1, ft(when), "XP-HOST")]);
    let cfbf_v1 = build_synthetic_cfbf(&[("DestList", &dl_v1), ("1", &lnk1)]);
    let (v1_recs, _) = parse_automatic_destinations(&cfbf_v1, "f01b4d95cf55d32a").unwrap();
    assert_eq!(v1_recs.len(), 1);
    assert_eq!(v1_recs[0].access_count, Some(3));

    // 3. CustomDestinations
    let custom_bytes = build_synthetic_custom_destinations("Pinned Cases", &lnk1, &lnk1);
    let (cust_recs, _) = parse_custom_destinations(&custom_bytes, "5d696d521de238c3").unwrap();
    assert_eq!(cust_recs.len(), 2);
    assert_eq!(cust_recs[0].pin_status, "Custom:Pinned Cases");
    assert_eq!(cust_recs[1].pin_status, "Task");

    // 4. JumpListsProvider over directory
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("1b4dd67f29cb1962.automaticDestinations-ms"),
        &cfbf_bytes,
    )
    .unwrap();
    fs::write(dir.path().join("5d696d521de238c3.customDestinations-ms"), &custom_bytes).unwrap();
    let prov = JumpListsProvider::new(ForensicSource::OfflinePath(dir.path().to_path_buf()));
    let table = prov.query(&TableQuery::default()).unwrap();
    assert_eq!(table.total_rows, 4);

    // 5. FAT cycle guard negative test
    let mut bad_cfbf = cfbf_bytes.clone();
    let num_fat = u32::from_le_bytes(bad_cfbf[0x2C..0x30].try_into().unwrap()) as usize;
    for i in 0..num_fat {
        let sid = u32::from_le_bytes(bad_cfbf[0x4C + i * 4..0x50 + i * 4].try_into().unwrap()) as usize;
        let sec_off = (sid + 1) * 512;
        if sec_off + 512 <= bad_cfbf.len() {
            for j in 0..128 {
                let entry_val = u32::from_le_bytes(bad_cfbf[sec_off + j * 4..sec_off + j * 4 + 4].try_into().unwrap());
                if entry_val == 0xFFFF_FFFE || entry_val < 100 {
                    bad_cfbf[sec_off + j * 4..sec_off + j * 4 + 4].copy_from_slice(&(j as u32).to_le_bytes());
                }
            }
        }
    }
    assert!(matches!(
        parse_automatic_destinations(&bad_cfbf, "cycle"),
        Err(ForensicError::Parse { .. })
    ));
}

#[test]
fn pidl_decoder_covers_fs_network_delegate_1sps_and_unknown_items() {
    let dt = dos_datetime_to_utc(0x58A1, 0x7100).unwrap();
    assert_eq!(dt, ts(2024, 5, 1, 14, 8, 0));
    assert!(dos_datetime_to_utc(0, 0).is_none());

    // Network UNC item (0x47)
    let mut net_item = Vec::new();
    let mut net_body = vec![0x47u8, 0x00, 0x00];
    net_body.extend_from_slice(b"\\\\FILESRV\\Cases\0");
    net_item.extend_from_slice(&((net_body.len() + 2) as u16).to_le_bytes());
    net_item.extend_from_slice(&net_body);

    // Delegate item (0x74 + "CFSF") wrapping a File item
    let inner_file =
        build_pidl_item_fs_beef0004(false, "INNER~1.TXT", "inner_file.txt", 128, (0x58A1, 0x7100), (88, 1));
    let mut del_body = vec![0x74u8, 0x00];
    del_body.extend_from_slice(&(inner_file.len() as u16).to_le_bytes());
    del_body.extend_from_slice(b"CFSF");
    del_body.extend_from_slice(&inner_file);
    let mut del_item = ((del_body.len() + 2) as u16).to_le_bytes().to_vec();
    del_item.extend_from_slice(&del_body);

    let pidl_bytes = build_pidl_bytes(&[
        build_pidl_item_root_this_pc(),
        build_pidl_item_drive("C:\\"),
        build_pidl_item_fs_beef0004(true, "DOCUME~1", "Documents", 0, (0x58A1, 0x7100), (1234, 5)),
        del_item,
    ]);
    let decoded = parse_pidl(&pidl_bytes);
    assert_eq!(decoded.items.len(), 4);
    assert_eq!(decoded.items[0].kind, ShellItemKind::RootFolder);
    assert_eq!(decoded.items[2].mft_entry.as_deref(), Some("1234-5"));
    assert_eq!(decoded.items[3].kind, ShellItemKind::Delegate);
    assert_eq!(decoded.items[3].name, "inner_file.txt");
    assert_eq!(join_pidl_path(&decoded.items), "C:\\Documents\\inner_file.txt");

    let net_dec = parse_pidl(&[net_item, vec![0, 0]].concat());
    assert_eq!(net_dec.items[0].kind, ShellItemKind::Network);
    assert_eq!(net_dec.items[0].name, "\\\\FILESRV\\Cases");

    // Unknown type fallback
    let unk = [5u8, 0, 0xEE, 0x01, 0x02, 0, 0];
    let dec_unk = parse_pidl(&unk);
    assert_eq!(dec_unk.items.len(), 1);
    assert_eq!(dec_unk.items[0].kind, ShellItemKind::Unknown(0xEE));
}

#[test]
fn registry_providers_shellbags_userassist_muicache_opensave_profiles() {
    let when = ts(2025, 5, 10, 10, 0, 0);
    let usrclass = build_usrclass_hive(when);
    let ntuser = build_ntuser_hive(when);
    let software = build_software_hive(when);

    // 1. ShellBags
    let sb = ShellBagsProvider::new(ForensicSource::OfflineBytes(usrclass.clone()));
    let sb_table = sb.query(&TableQuery::default()).unwrap();
    assert!(sb_table.total_rows >= 3);
    assert!(
        sb_table
            .rows
            .iter()
            .any(|r| r.cells[0] == CellValue::Text("C:\\Documents".to_string())
                && r.cells[8] == CellValue::Text("Details (4)".to_string()))
    );

    // 2. MUICache (offline FileExists MUST be Null)
    let mui = MuiCacheProvider::new(ForensicSource::OfflineBytes(usrclass));
    let mui_table = mui.query(&TableQuery::default()).unwrap();
    assert_eq!(mui_table.total_rows, 1);
    assert_eq!(
        mui_table.rows[0].cells[0],
        CellValue::Text("C:\\Tools\\procmon.exe".to_string())
    );
    assert_eq!(
        mui_table.rows[0].cells[1],
        CellValue::Text("Process Monitor".to_string())
    );
    assert_eq!(mui_table.rows[0].cells[4], CellValue::Null);

    // 3. UserAssist (Win10 72B + WinXP 16B, skipping UEME_CTLSESSION)
    let ua = UserAssistProvider::new(ForensicSource::OfflineBytes(ntuser.clone()));
    let ua_table = ua.query(&TableQuery::default()).unwrap();
    assert_eq!(ua_table.total_rows, 2);
    assert!(
        ua_table
            .rows
            .iter()
            .any(|r| r.cells[0] == CellValue::Text("C:\\Tools\\procmon.exe".to_string())
                && r.cells[2] == CellValue::Uint(7)
                && r.cells[4] == CellValue::Uint(45_000))
    );
    assert!(ua_table.rows.iter().any(|r| r.cells[0]
        == CellValue::Text("UEME_RUNPATH:C:\\Windows\\notepad.exe".to_string())
        && r.cells[2] == CellValue::Uint(3)
        && r.cells[3] == CellValue::Null));

    // 4. OpenSave
    let os = OpenSaveProvider::new(ForensicSource::OfflineBytes(ntuser));
    let os_table = os.query(&TableQuery::default()).unwrap();
    assert_eq!(os_table.total_rows, 2);
    assert!(
        os_table
            .rows
            .iter()
            .any(|r| r.cells[0] == CellValue::Text("case_report.pdf".to_string())
                && r.cells[2] == CellValue::Text("C:\\case_report.pdf".to_string())
                && r.cells[5] == CellValue::Text("OpenSavePidlMRU".to_string()))
    );
    assert!(
        os_table
            .rows
            .iter()
            .any(|r| r.cells[0] == CellValue::Text("AcroRd32.exe".to_string())
                && r.cells[5] == CellValue::Text("LastVisitedPidlMRU".to_string()))
    );

    // 5. UserProfiles (offline Loaded MUST be Null)
    let prof = UserProfilesProvider::new(ForensicSource::OfflineBytes(software));
    let prof_table = prof.query(&TableQuery::default()).unwrap();
    assert_eq!(prof_table.total_rows, 2);
    assert!(
        prof_table
            .rows
            .iter()
            .any(|r| r.cells[0] == CellValue::Text("Alice".to_string()) && r.cells[7] == CellValue::Null)
    );
    assert!(
        prof_table
            .rows
            .iter()
            .any(|r| r.cells[0] == CellValue::Text("SYSTEM".to_string()) && r.cells[7] == CellValue::Null)
    );
}

#[test]
fn shimcache_win10_win8_win7_and_usb_parsers_and_providers() {
    let when = ts(2025, 5, 10, 14, 30, 0);

    let s10 = build_shimcache_win10(&[("C:\\Tools\\evil.exe", when)]);
    let p10 = parse_shimcache(&s10).unwrap();
    assert_eq!(p10.len(), 1);
    assert_eq!(p10[0].path, "C:\\Tools\\evil.exe");

    let s8 = build_shimcache_win8(&[("C:\\Tools\\win8.exe", when)]);
    let p8 = parse_shimcache(&s8).unwrap();
    assert_eq!(p8.len(), 1);
    assert_eq!(p8[0].exec_flag, Some(true));

    let s7_64 = build_shimcache_win7(&[("C:\\Tools\\win7x64.exe", when)], true);
    let p7_64 = parse_shimcache(&s7_64).unwrap();
    assert_eq!(p7_64.len(), 1);
    assert_eq!(p7_64[0].path, "C:\\Tools\\win7x64.exe");

    let s7_32 = build_shimcache_win7(&[("C:\\Tools\\win7x86.exe", when)], false);
    let p7_32 = parse_shimcache(&s7_32).unwrap();
    assert_eq!(p7_32.len(), 1);
    assert_eq!(p7_32[0].path, "C:\\Tools\\win7x86.exe");

    // Offline USB devices SYSTEM hive
    let sys = build_system_hive(when);
    let usb_dev = UsbDevicesProvider::new(ForensicSource::OfflineBytes(sys));
    let dev_table = usb_dev.query(&TableQuery::default()).unwrap();
    assert_eq!(dev_table.total_rows, 2);
    assert!(
        dev_table
            .rows
            .iter()
            .any(|r| r.cells[5] == CellValue::Text("0781".to_string())
                && r.cells[6] == CellValue::Text("5583".to_string())
                && r.cells[8] == CellValue::Text("E:".to_string())
                && r.cells[3] == CellValue::Null)
    );

    // USB Log UTF-8 and UTF-16LE BOM
    let log_str = build_setupapi_dev_log();
    let mut utf16_log = vec![0xFFu8, 0xFEu8];
    for u in log_str.encode_utf16() {
        utf16_log.extend_from_slice(&u.to_le_bytes());
    }
    assert_eq!(parse_setupapi_dev_log(&utf16_log).len(), 2);

    let usb_log = UsbLogProvider::new(ForensicSource::OfflineBytes(log_str.into_bytes()));
    let log_table = usb_log.query(&TableQuery::default()).unwrap();
    assert_eq!(log_table.total_rows, 2);
    assert!(
        log_table
            .rows
            .iter()
            .any(|r| r.cells[1] == CellValue::Text("Plug".to_string()))
    );
    assert!(
        log_table
            .rows
            .iter()
            .any(|r| r.cells[1] == CellValue::Text("Unplug".to_string()))
    );
}

#[test]
fn aggregators_executed_programs_and_last_activity_offline_directory() {
    let when = ts(2025, 5, 10, 15, 0, 0);
    let dir = TempDir::new().unwrap();

    fs::write(dir.path().join("UsrClass.dat"), build_usrclass_hive(when)).unwrap();
    fs::write(dir.path().join("NTUSER.DAT"), build_ntuser_hive(when)).unwrap();
    fs::write(dir.path().join("SYSTEM"), build_system_hive(when)).unwrap();
    fs::write(dir.path().join("Amcache.hve"), build_amcache_hive(when)).unwrap();
    let scca = build_synthetic_scca(&SyntheticSccaSpec {
        version: 30,
        exe_name: "PROCMON.EXE",
        hash: 0xCAFE_1111,
        run_count: 12,
        last_runs: &[ft(when)],
        loaded_files: &["C:\\Tools\\procmon.exe"],
        volumes: &[("\\VOLUME{1}", 0x1111_2222, ft(when))],
        v30_variant2_0x128: true,
    });
    fs::write(
        dir.path().join("PROCMON.EXE-CAFE1111.pf"),
        compress_mam_xca(&scca, false, true),
    )
    .unwrap();
    fs::write(
        dir.path().join("Security.evtx"),
        build_minimal_evtx(when, "C:\\Tools\\procmon.exe"),
    )
    .unwrap();
    let lnk = build_synthetic_lnk(
        "C:\\Cases\\evidence.txt",
        None,
        None,
        None,
        None,
        None,
        0x1122,
        512,
        ft(when),
        ft(when),
        None,
    );
    fs::write(dir.path().join("evidence.lnk"), &lnk).unwrap();
    let dl = build_destlist(4, &[(1, "C:\\Cases\\evidence.txt", 3, -1, ft(when), "HOST")]);
    fs::write(
        dir.path().join("1b4dd67f29cb1962.automaticDestinations-ms"),
        build_synthetic_cfbf(&[("DestList", &dl), ("1", &lnk)]),
    )
    .unwrap();
    // Corrupt .pf to verify graceful partial degradation emits warning instead of aborting
    fs::write(dir.path().join("CORRUPT.EXE-00000000.pf"), b"BAD_PREFETCH").unwrap();

    let exec_prov = ExecutedProgramsProvider::new(ForensicSource::OfflinePath(dir.path().to_path_buf()));
    let (exec_table, exec_warnings) = exec_prov.query_with_warnings(&TableQuery::default()).unwrap();
    assert!(!exec_warnings.is_empty());
    let procmon_row = exec_table
        .rows
        .iter()
        .find(|r| matches!(&r.cells[0], CellValue::Text(s) if s.eq_ignore_ascii_case("C:\\Tools\\procmon.exe")))
        .expect("procmon aggregated row");
    assert_eq!(procmon_row.cells[2], CellValue::Uint(12));
    assert_eq!(procmon_row.cells[4], CellValue::Text("3.96.0.0".to_string()));
    assert_eq!(
        procmon_row.cells[5],
        CellValue::Text("Sysinternals - Microsoft".to_string())
    );
    if let CellValue::Text(ref sources) = procmon_row.cells[3] {
        assert!(sources.contains("Amcache"));
        assert!(sources.contains("Prefetch"));
        assert!(sources.contains("ShimCache"));
        assert!(sources.contains("UserAssist"));
        assert!(sources.contains("MUICache"));
    } else {
        panic!("expected Text source_artifact");
    }

    let act_prov = LastActivityProvider::new(ForensicSource::OfflinePath(dir.path().to_path_buf()));
    let (act_table, act_warnings) = act_prov.query_with_warnings(&TableQuery::default()).unwrap();
    assert!(!act_warnings.is_empty());
    assert!(act_table.total_rows >= 6);
    assert!(
        act_table
            .rows
            .iter()
            .any(|r| matches!(&r.cells[5], CellValue::Text(s) if s.starts_with("EVTX:")))
    );
    assert!(
        act_table
            .rows
            .iter()
            .any(|r| r.cells[5] == CellValue::Text("Prefetch".to_string()))
    );
    assert!(
        act_table
            .rows
            .iter()
            .any(|r| r.cells[5] == CellValue::Text("RecentLnk".to_string()))
    );
    assert!(
        act_table
            .rows
            .iter()
            .any(|r| r.cells[5] == CellValue::Text("JumpLists".to_string()))
    );
    assert!(
        act_table
            .rows
            .iter()
            .any(|r| r.cells[5] == CellValue::Text("Registry:RunMRU".to_string()))
    );

    // GuapQuery filter test on Cross-Artifact Activity Timeline
    let filtered = QueryHelper::apply_query(
        &act_table.schema,
        &act_table.rows,
        None,
        Some("source == \"Prefetch\""),
        None,
        0,
        None,
    )
    .unwrap();
    assert_eq!(filtered.total_rows, 1);
}

#[test]
fn vss_cim_datetime_vssadmin_json_catalog_and_safe_restore_helpers() {
    let dt = parse_cim_datetime("20250510142211.123456-240").unwrap();
    assert_eq!(
        dt,
        ts(2025, 5, 10, 18, 22, 11) + chrono::Duration::microseconds(123_456)
    );

    let vss_text = "\
Contents of shadow copy set ID: {aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}
   Contained 1 shadow copies at creation time: 2025-05-10 14:22:11
      Shadow Copy ID: {11111111-2222-3333-4444-555555555555}
         Original Volume: (C:)\\\\?\\Volume{99999999-0000-0000-0000-000000000001}\\
         Shadow Copy Volume: \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy7
         Originating Machine: HOST01
         Service Machine: HOST01
         Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
         Attributes: Persistent, ClientAccessible
";
    let parsed_vss = parse_vssadmin_text(vss_text);
    assert_eq!(parsed_vss.len(), 1);
    assert_eq!(parsed_vss[0].shadow_copy_name, "HarddiskVolumeShadowCopy7");

    // JSON catalog via OfflineBytes
    let json_bytes = serde_json::to_vec(&parsed_vss).unwrap();
    let vss_json_prov = ShadowCopyProvider::new(ForensicSource::OfflineBytes(json_bytes));
    let vss_json_table = vss_json_prov.query(&TableQuery::default()).unwrap();
    assert_eq!(vss_json_table.total_rows, 1);

    // Offline directory tree with HarddiskVolumeShadowCopy1
    let dir = TempDir::new().unwrap();
    let snap_dir = dir.path().join("HarddiskVolumeShadowCopy1");
    let user_docs = snap_dir.join("Users").join("Alice");
    fs::create_dir_all(&user_docs).unwrap();
    let sample_file = user_docs.join("secret_notes.txt");
    fs::write(&sample_file, b"restored shadow content").unwrap();

    let vss_prov = ShadowCopyProvider::new(ForensicSource::OfflinePath(dir.path().to_path_buf()));
    let vss_table = vss_prov.query(&TableQuery::default()).unwrap();
    assert_eq!(vss_table.total_rows, 1);
    assert_eq!(
        vss_table.rows[0].cells[0],
        CellValue::Text("HarddiskVolumeShadowCopy1".to_string())
    );

    let prev_prov = PreviousFilesProvider::new(ForensicSource::OfflinePath(dir.path().to_path_buf()));
    let prev_table = prev_prov.query(&TableQuery::default()).unwrap();
    assert_eq!(prev_table.total_rows, 1);
    assert_eq!(
        prev_table.rows[0].cells[0],
        CellValue::Text("secret_notes.txt".to_string())
    );

    // Safe restore
    let out_dir = TempDir::new().unwrap();
    let restored =
        restore_previous_file_into_dir(&snap_dir, Path::new("Users\\Alice\\secret_notes.txt"), out_dir.path()).unwrap();
    assert_eq!(fs::read(&restored).unwrap(), b"restored shadow content");

    let direct_dest = out_dir.path().join("direct_copy.txt");
    let copied = restore_previous_file(&sample_file, &direct_dest).unwrap();
    assert_eq!(copied, 23);

    // Traversal rejection
    assert!(matches!(
        restore_previous_file(&sample_file, Path::new("..\\escape.txt")),
        Err(ForensicError::InvalidArgument(_))
    ));
    assert!(matches!(
        restore_previous_file_into_dir(&snap_dir, Path::new("..\\..\\escape.txt"), out_dir.path()),
        Err(ForensicError::InvalidArgument(_))
    ));
}

#[cfg(windows)]
#[test]
fn live_non_elevated_smoke_tests_and_graceful_degradation() {
    let q = TableQuery {
        limit: Some(5),
        ..Default::default()
    };

    let profiles = UserProfilesProvider::new(ForensicSource::Live).query(&q);
    assert!(profiles.is_ok(), "User Profiles live failed: {profiles:?}");

    let usb_dev = UsbDevicesProvider::new(ForensicSource::Live).query(&q);
    assert!(usb_dev.is_ok(), "USB Devices live failed: {usb_dev:?}");

    let usb_log = UsbLogProvider::new(ForensicSource::Live).query(&q);
    assert!(usb_log.is_ok(), "USB Log live failed: {usb_log:?}");

    let recent = RecentFilesProvider::new(ForensicSource::Live).query(&q);
    assert!(recent.is_ok(), "Recent Files live failed: {recent:?}");

    let jumplists = JumpListsProvider::new(ForensicSource::Live).query(&q);
    assert!(jumplists.is_ok(), "Windows Jump Lists live failed: {jumplists:?}");

    let pnp = UsbLogProvider::watch_pnp_events(std::time::Duration::from_millis(50));
    assert!(pnp.is_ok(), "watch_pnp_events failed: {pnp:?}");

    let executed = ExecutedProgramsProvider::new(ForensicSource::Live).query_with_warnings(&q);
    assert!(executed.is_ok(), "Executed Programs live failed: {executed:?}");

    let pf_res = WinPrefetchProvider::new(ForensicSource::Live).query(&q);
    assert!(pf_res.is_ok() || matches!(pf_res, Err(TableError::Provider(_))));

    let vss_res = ShadowCopyProvider::new(ForensicSource::Live).query(&q);
    assert!(vss_res.is_ok() || matches!(vss_res, Err(TableError::Provider(_))));
}

#[test]
fn r4_compliance_and_unsafe_isolation_audit() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let unsafe_re = regex::Regex::new(r"\bunsafe\s*(\{|fn\b|impl\b|trait\b|extern\b|mod\b)").unwrap();
    let prohibited = [
        "CryptUnprotectData",
        "CredEnumerate",
        "VaultEnumerateItems",
        "VaultGetItem",
        "LsaRetrievePrivateData",
        "CreateRemoteThread",
        "NtCreateThreadEx",
        "QueueUserAPC",
        "SetWindowsHookEx",
        "WriteProcessMemory",
        "WLAN_PROFILE_GET_PLAINTEXT_KEY",
        "cred2rust",
        "RunAsDate",
        "SocketSniff",
        "IECacheView",
        "IndexDatView",
    ];

    for entry in walkdir::WalkDir::new(&src_dir).into_iter().flatten() {
        let p = entry.path();
        if !p.is_file() || p.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "tests.rs" {
            continue;
        }
        let content = fs::read_to_string(p).unwrap();
        for pat in prohibited {
            assert!(
                !content.contains(pat),
                "prohibited R4 symbol '{pat}' found in {}",
                p.display()
            );
        }
        if name != "live.rs" && name != "lib.rs" {
            assert!(
                !unsafe_re.is_match(&content),
                "unsafe block/item found outside live.rs in {}",
                p.display()
            );
        }
    }
}

#[test]
fn shimcache_win7_u64_max_offsets_do_not_panic() {
    // 1. 176-byte buffer (entry 0 with path_off = u64::MAX and u64::MAX - 4)
    for bad_off in [u64::MAX, u64::MAX - 4] {
        let mut buf = vec![0u8; 176];
        buf[0..4].copy_from_slice(&0xBADC_0FEEu32.to_le_bytes());
        buf[4..8].copy_from_slice(&1u32.to_le_bytes());
        buf[0x80..0x82].copy_from_slice(&10u16.to_le_bytes());
        buf[0x82..0x84].copy_from_slice(&10u16.to_le_bytes());
        buf[0x84..0x88].copy_from_slice(&0u32.to_le_bytes());
        buf[0x88..0x90].copy_from_slice(&bad_off.to_le_bytes());
        let res = parse_shimcache(&buf);
        assert!(res.is_ok(), "unexpected error on 176B Win7 buffer: {res:?}");
    }

    // 2. 234-byte and 256-byte 2-entry Win7 x64 buffers (entry 0 valid at 0xE0, entry 1 path_off = u64::MAX / u64::MAX - 4)
    let path_units: Vec<u16> = "C:\\Tools\\ok.exe".encode_utf16().collect();
    let path_bytes_len = (path_units.len() * 2) as u16;
    for &(buf_len, bad_off) in &[
        (234usize, u64::MAX),
        (234usize, u64::MAX - 4),
        (256usize, u64::MAX),
        (256usize, u64::MAX - 4),
    ] {
        let mut buf = vec![0u8; buf_len];
        buf[0..4].copy_from_slice(&0xBADC_0FEEu32.to_le_bytes());
        buf[4..8].copy_from_slice(&2u32.to_le_bytes());
        // Entry 0 at 0x80 (48 bytes) -> path at 0xE0
        let entry0_len = path_bytes_len.min((buf_len - 0xE0) as u16);
        buf[0x80..0x82].copy_from_slice(&entry0_len.to_le_bytes());
        buf[0x82..0x84].copy_from_slice(&entry0_len.to_le_bytes());
        buf[0x84..0x88].copy_from_slice(&0u32.to_le_bytes());
        buf[0x88..0x90].copy_from_slice(&0xE0u64.to_le_bytes());
        // Entry 1 at 0xB0 (48 bytes) -> malformed u64 offset
        buf[0xB0..0xB2].copy_from_slice(&10u16.to_le_bytes());
        buf[0xB2..0xB4].copy_from_slice(&10u16.to_le_bytes());
        buf[0xB4..0xB8].copy_from_slice(&0u32.to_le_bytes());
        buf[0xB8..0xC0].copy_from_slice(&bad_off.to_le_bytes());
        // Write entry 0 UTF-16LE path at 0xE0
        for (i, u) in path_units.iter().take((entry0_len / 2) as usize).enumerate() {
            let off = 0xE0 + i * 2;
            buf[off..off + 2].copy_from_slice(&u.to_le_bytes());
        }
        let parsed = parse_shimcache(&buf).unwrap();
        assert_eq!(parsed.len(), 1);
    }
}

#[test]
fn vss_restore_prevents_same_file_truncation_hardlink_and_junctions() {
    let dir = TempDir::new().unwrap();
    let src_dir = dir.path().join("src");
    let out_dir = dir.path().join("out");
    fs::create_dir_all(&src_dir).unwrap();
    fs::create_dir_all(&out_dir).unwrap();

    let src = src_dir.join("secret.txt");
    let payload = b"DO_NOT_DESTROY_ME";
    fs::write(&src, payload).unwrap();

    // Same path destination MUST error and preserve source contents
    assert!(matches!(
        restore_previous_file(&src, &src),
        Err(ForensicError::InvalidArgument(_))
    ));
    assert_eq!(fs::read(&src).unwrap(), payload);

    // Hardlink alias MUST also be rejected without truncating source
    let hardlink = out_dir.join("hardlink_alias.txt");
    fs::hard_link(&src, &hardlink).unwrap();
    assert!(matches!(
        restore_previous_file(&src, &hardlink),
        Err(ForensicError::InvalidArgument(_))
    ));
    assert_eq!(fs::read(&src).unwrap(), payload);

    // NTFS directory junction check on Windows
    #[cfg(windows)]
    {
        let junction = dir.path().join("junction_link");
        let status = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &junction.to_string_lossy(),
                &src_dir.to_string_lossy(),
            ])
            .output()
            .expect("invoke mklink /J");
        assert!(
            status.status.success(),
            "mklink /J failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );
        assert!(matches!(
            restore_previous_file(&junction.join("secret.txt"), &out_dir.join("j_leak.txt")),
            Err(ForensicError::InvalidArgument(_))
        ));
        assert!(matches!(
            restore_previous_file(&src, &junction.join("secret.txt")),
            Err(ForensicError::InvalidArgument(_))
        ));
        assert_eq!(fs::read(&src).unwrap(), payload);
    }
}

#[test]
fn setupapi_odd_length_bomless_utf16le_and_usbstor_volume_delete_sections() {
    let log_text = concat!(
        ">>>  [Device Install (Hardware initiated) - USB\\VID_0781&PID_5583\\ABC12345]\r\n",
        ">>>  Section start 2025/05/10 14:22:11.123\r\n",
        "     dvi: Friendly Name: SanDisk Ultra\r\n",
        "<<<  Section end 2025/05/10 14:22:12.000\r\n",
        "<<<  [Exit status: SUCCESS]\r\n",
    );
    let mut bomless_odd = Vec::new();
    for u in log_text.encode_utf16() {
        bomless_odd.extend_from_slice(&u.to_le_bytes());
    }
    bomless_odd.push(0x41); // trailing odd byte without BOM
    let events = parse_setupapi_dev_log(&bomless_odd);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "Plug");
    assert_eq!(events[0].vendor_id.as_deref(), Some("0781"));

    let vol_delete = concat!(
        ">>>  [Delete Device - STORAGE\\VOLUME\\_??_USBSTOR#DISK&VEN_SANDISK&PROD_CRUZER&REV_1.00#1234567890&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}]\r\n",
        ">>>  Section start 2025/05/11 09:00:00.000\r\n",
        "<<<  Section end 2025/05/11 09:00:01.000\r\n",
        "<<<  [Exit status: SUCCESS]\r\n",
    );
    let vol_events = parse_setupapi_dev_log(vol_delete.as_bytes());
    assert_eq!(vol_events.len(), 1);
    assert_eq!(vol_events[0].event_type, "Unplug");
    assert_eq!(vol_events[0].device_type, "Mass Storage");
    assert_eq!(vol_events[0].serial_number.as_deref(), Some("1234567890"));
}

#[test]
fn vss_parse_json_accepts_empty_wrapper_and_single_record() {
    let empty = parse_vss_json(br#"{"shadow_copies":[]}"#).unwrap();
    assert!(empty.is_empty());

    let single_json = br#"{
        "shadow_copy_name": "HarddiskVolumeShadowCopy1",
        "device_object": "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1",
        "volume_name": "\\\\?\\Volume{00000000-0000-0000-0000-000000000001}\\",
        "created_time": null,
        "snapshot_id": "{11111111-2222-3333-4444-555555555555}",
        "originating_machine": "HOST",
        "service_machine": "HOST",
        "provider_id": "{b5946137-7b9f-4925-af80-51abd60b20d5}",
        "set_id": null,
        "attributes": null
    }"#;
    let single = parse_vss_json(single_json).unwrap();
    assert_eq!(single.len(), 1);
    assert_eq!(single[0].shadow_copy_name, "HarddiskVolumeShadowCopy1");

    assert!(matches!(parse_vss_json(b"{}"), Err(ForensicError::Parse { .. })));
}

#[test]
fn previous_files_provider_multi_shadow_strictly_enforces_max_entries() {
    let dir = TempDir::new().unwrap();
    for snap in ["HarddiskVolumeShadowCopy1", "HarddiskVolumeShadowCopy2"] {
        let snap_dir = dir.path().join(snap);
        fs::create_dir_all(&snap_dir).unwrap();
        for i in 0..3 {
            fs::write(snap_dir.join(format!("file_{i}.txt")), b"data").unwrap();
        }
    }

    let prov = PreviousFilesProvider::with_options(
        ForensicSource::OfflinePath(dir.path().to_path_buf()),
        PreviousFilesOptions {
            target_subpath: None,
            max_depth: 4,
            max_entries: 4,
        },
    );
    let table = prov.query(&TableQuery::default()).unwrap();
    assert_eq!(table.total_rows, 4);
}
