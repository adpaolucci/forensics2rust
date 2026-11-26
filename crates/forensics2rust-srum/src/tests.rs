use std::io::Write;

use forensics2rust_core::{ForensicError, ForensicSource, QueryHelper};
use guap_table::{CellValue, TableError, TableProvider, TableQuery};

use crate::ese::compress::{DecompressOutcome, decompress_ese_value};
use crate::ese::page::PageFlags;
use crate::ese::{DatabaseState, EseDatabase, EseValue, JetColType, PageFormat};
use crate::fixtures::{
    SyntheticEseBuilder, build_record, build_synthetic_datastore_edb_bytes, build_synthetic_srudb_bytes,
    encode_ese_7bit_ascii, encode_ese_7bit_unicode, encode_ese_lz4, encode_ese_xpress_lz77, encode_utf16le_nul,
};
use crate::live::{classify_srum_io_error, default_live_srudb_path};
use crate::{
    SrumAppProvider, SrumDbProvider, SrumEnergyProvider, SrumNetProvider, all_providers, crate_info, domain_tools,
};

#[test]
fn srum_crate_skeleton_has_4_catalog_tools() {
    assert_eq!(crate_info().0, "forensics2rust-srum");
    assert_eq!(domain_tools().len(), 4);
}

#[test]
fn all_providers_returns_4_readonly_tools() {
    let src = ForensicSource::OfflineBytes(build_synthetic_srudb_bytes());
    let providers = all_providers(&src);
    assert_eq!(providers.len(), 4);
    let ids: Vec<&str> = providers.iter().map(|p| p.tool_id()).collect();
    assert_eq!(ids, vec!["srum.db", "srum.net", "srum.app", "srum.energy"]);
    for p in providers {
        assert!(p.is_read_only());
        assert!(!p.description().is_empty());
        assert!(!p.schema().columns.is_empty());
    }
}

#[test]
fn parses_synthetic_srudb_multipage_ese_and_id_map() {
    let bytes = build_synthetic_srudb_bytes();
    let db = EseDatabase::from_bytes(&bytes).expect("synthetic SRUDB.dat should parse");

    assert_eq!(db.header().page_size, 4096);
    assert_eq!(db.header().page_format, PageFormat::Small);
    assert!(db.header().checksum_valid);
    assert_eq!(db.header().database_state, DatabaseState::CleanShutdown);

    let names = db.table_names();
    assert!(names.iter().any(|n| n == "SruDbIdMapTable"));
    assert!(names.iter().any(|n| n == "{973F5D5C-1D90-4944-BE8E-24B94231A174}"));
    assert!(names.iter().any(|n| n == "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"));
    assert!(names.iter().any(|n| n == "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}"));
    assert!(names.iter().any(|n| n == "{DD6636C4-8929-4683-974E-22C046A43763}"));

    // Multi-page net table (pgno 9 -> 10, 11) must return all 3 rows
    let net_tbl = db
        .read_table("{973F5D5C-1D90-4944-BE8E-24B94231A174}")
        .expect("net table");
    assert_eq!(net_tbl.rows.len(), 3);

    let id_map = crate::id_map::SruDbIdMap::from_ese(&db);
    assert_eq!(id_map.resolve_id(1), r"C:\Windows\System32\svchost.exe");
    assert!(
        id_map.resolve_id(2).ends_with(r"\worker.exe") && id_map.resolve_id(2).len() > 250,
        "LV path failed: {}",
        id_map.resolve_id(2)
    );
    assert_eq!(id_map.resolve_id(3), "Microsoft.Windows.Search_cw5n1h2txyewy");
    assert_eq!(id_map.resolve_id(4), "Microsoft.WindowsTerminal_8wekyb3d8bbwe!App");
    assert_eq!(id_map.resolve_id(5), "S-1-5-18");
    assert_eq!(id_map.resolve_id(6), "S-1-5-21-123456789-987654321-111111111-1001");
    assert_eq!(id_map.resolve_id(999), "IdIndex(999)");
}

#[test]
fn all_4_providers_support_getnir_queries_and_detail_payloads() {
    let src = ForensicSource::OfflineBytes(build_synthetic_srudb_bytes());

    // 1. srum.db (default + for_table)
    let db_prov = SrumDbProvider::new(src.clone());
    let db_res = QueryHelper::query_provider(
        &db_prov,
        None,
        Some("TableName=SruDbIdMapTable"),
        Some("RecordIndex:asc"),
        0,
        Some(10),
    )
    .expect("srum.db GetNir");
    assert_eq!(db_res.total_rows, 6);
    assert!(db_res.rows[0].detail_json.is_some());
    assert!(db_res.rows[0].raw_bytes.is_some());

    let db_specific = SrumDbProvider::for_table(src.clone(), "SruDbIdMapTable");
    assert!(db_specific.schema().columns.iter().any(|c| c.label == "IdBlob"));
    let spec_res = db_specific.query(&TableQuery::default()).expect("for_table query");
    assert_eq!(spec_res.total_rows, 6);

    // 2. srum.net
    let net_prov = SrumNetProvider::new(src.clone());
    let net_all = net_prov.query(&TableQuery::default()).expect("srum.net all");
    assert_eq!(net_all.total_rows, 3);
    assert!(
        net_all
            .rows
            .iter()
            .any(|r| r.cells[1] == CellValue::Text("IdIndex(999)".to_string()))
    );
    assert!(
        net_all
            .rows
            .iter()
            .any(|r| matches!(&r.cells[3], CellValue::Text(s) if s.contains("(Ethernet)")))
    );
    assert!(
        net_all
            .rows
            .iter()
            .any(|r| r.cells[0] == CellValue::Null && r.cells[1] == CellValue::Text("IdIndex(999)".to_string()))
    );

    let net_filtered = QueryHelper::query_provider(
        &net_prov,
        Some(vec!["AppId".to_string(), "BytesSent".to_string()]),
        Some("AppId icontains svchost"),
        Some("BytesSent:desc"),
        0,
        Some(1),
    )
    .expect("srum.net GetNir");
    assert_eq!(net_filtered.total_rows, 1);
    assert_eq!(net_filtered.rows[0].cells[1], CellValue::Bytes(1_048_576));

    // 3. srum.app
    let app_prov = SrumAppProvider::new(src.clone());
    let app_res = QueryHelper::query_provider(
        &app_prov,
        None,
        Some("CycleTime > 100000"),
        Some("CycleTime:desc"),
        0,
        Some(10),
    )
    .expect("srum.app GetNir");
    assert_eq!(app_res.total_rows, 1);
    assert_eq!(app_res.rows[0].cells[3], CellValue::Uint(750_000));
    assert_eq!(app_res.rows[0].cells[7], CellValue::Bytes(2560));
    assert_eq!(app_res.rows[0].cells[8], CellValue::Uint(350));

    // 4. srum.energy (both FEE4E14F and DD6636C4)
    let energy_prov = SrumEnergyProvider::new(src);
    let energy_all = QueryHelper::query_provider(&energy_prov, None, None, Some("Timestamp:desc"), 0, Some(10))
        .expect("srum.energy GetNir");
    assert_eq!(energy_all.total_rows, 2);
    assert!(energy_all.rows.iter().any(|r| r.cells[3] == CellValue::Uint(9000)));
    assert!(energy_all.rows.iter().any(|r| r.cells[7] == CellValue::Uint(3600)));
}

#[test]
fn parses_large_16k_datastore_edb_with_xpress_and_7bit_unicode() {
    let bytes = build_synthetic_datastore_edb_bytes();
    let db = EseDatabase::from_bytes(&bytes).expect("16KiB DataStore.edb should parse");

    assert_eq!(db.header().page_size, 16384);
    assert_eq!(db.header().page_format, PageFormat::Large);
    assert_eq!(db.header().database_state, DatabaseState::DirtyShutdown);
    assert!(
        db.warnings().iter().any(|w| w.message.contains("DirtyShutdown")),
        "expected DirtyShutdown warning"
    );

    let tbl = db.read_table("tbHistory").expect("tbHistory table");
    assert_eq!(tbl.rows.len(), 1);
    let row = &tbl.rows[0];
    assert_eq!(
        row.values.get("UpdateId"),
        Some(&EseValue::Guid("{12345678-cdab-01ef-2233-445566778899}".to_string()))
    );
    assert_eq!(
        row.values.get("ClientApplicationId"),
        Some(&EseValue::Text("MoUsoCoreWorker".to_string()))
    );
    assert_eq!(
        row.values.get("Title"),
        Some(&EseValue::Text(
            "2024-11 Cumulative Update for Windows 11 (KB5046633) - Cumulative Update".to_string()
        ))
    );
    assert_eq!(
        row.values.get("Description"),
        Some(&EseValue::Text(
            "Installs security and reliability improvements.".to_string()
        ))
    );

    let prov = SrumDbProvider::for_table(ForensicSource::OfflineBytes(bytes), "tbHistory");
    let data = prov.query(&TableQuery::default()).expect("srum.db on DataStore.edb");
    assert_eq!(data.total_rows, 1);
}

#[test]
fn compression_roundtrips_and_unknown_flag_fallback() {
    // 7-bit ASCII (lengths 1, 7, 8, 15)
    for text in [b"a".as_slice(), b"abcdefg", b"abcdefgh", b"0123456789abcde"] {
        let comp = encode_ese_7bit_ascii(text);
        let mut w = Vec::new();
        let res = decompress_ese_value(&comp, &mut w).expect("7-bit ASCII");
        assert_eq!(
            res,
            DecompressOutcome::Decompressed {
                bytes: text.to_vec(),
                is_utf16_expanded: false
            }
        );
    }

    // 7-bit Unicode (including low3=7 preserving 8th-char NUL terminator vs low3=0 stripping 7-bit padding)
    let u_comp = encode_ese_7bit_unicode(b"Hello");
    let mut w = Vec::new();
    let u_res = decompress_ese_value(&u_comp, &mut w).expect("7-bit Unicode");
    assert_eq!(
        u_res,
        DecompressOutcome::Decompressed {
            bytes: b"H\0e\0l\0l\0o\0".to_vec(),
            is_utf16_expanded: true
        }
    );
    let mut u8_nul = encode_ese_7bit_unicode(b"1234567\0");
    u8_nul[0] = 0x17;
    let u8_res = decompress_ese_value(&u8_nul, &mut w).expect("7-bit Unicode 0x17");
    assert_eq!(
        u8_res,
        DecompressOutcome::Decompressed {
            bytes: encode_utf16le_nul("1234567"),
            is_utf16_expanded: true
        }
    );
    let mut a8_nul = encode_ese_7bit_ascii(b"1234567\0");
    a8_nul[0] = 0x0F;
    let a8_res = decompress_ese_value(&a8_nul, &mut w).expect("7-bit ASCII 0x0F");
    assert_eq!(
        a8_res,
        DecompressOutcome::Decompressed {
            bytes: b"1234567\0".to_vec(),
            is_utf16_expanded: false
        }
    );

    // XPRESS LZ77 with literals, overlapping RLE, nibble lengths, and extended lengths
    let mut payload = Vec::new();
    payload.extend_from_slice(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); // 40 'A's -> RLE + nibble length
    payload.extend_from_slice(b"Prefix-12345-Middle-");
    payload.extend_from_slice(&[b'Z'; 300]); // extended match length > 279!
    payload.extend_from_slice(b"-End-Prefix-12345-Middle-");
    let x_comp = encode_ese_xpress_lz77(&payload);
    let x_res = decompress_ese_value(&x_comp, &mut w).expect("XPRESS LZ77");
    assert_eq!(
        x_res,
        DecompressOutcome::Decompressed {
            bytes: payload,
            is_utf16_expanded: false
        }
    );

    // Unknown compression flag 0x30 -> Unsupported + warning
    let unk = vec![0x30, 0x01, 0x02, 0x03];
    let mut uw = Vec::new();
    let unk_res = decompress_ese_value(&unk, &mut uw).expect("unknown compression flag");
    assert_eq!(unk_res, DecompressOutcome::Unsupported { flag: 0x30 });
    assert_eq!(uw.len(), 1);
}

#[test]
fn recovers_from_backup_page_1_and_tolerates_bad_checksum() {
    let mut bytes = build_synthetic_srudb_bytes();
    // Corrupt page 0 signature + checksum while keeping page 1 backup intact
    bytes[0..8].fill(0xFF);
    let db = EseDatabase::from_bytes(&bytes).expect("backup page 1 should recover");
    assert!(db.header().recovered_from_backup_header);
    assert!(
        db.warnings().iter().any(|w| w.message.contains("backup page 1")),
        "expected backup recovery warning"
    );
    assert!(!db.table_names().is_empty());

    // Corrupt only checksum on page 0
    let mut bytes2 = build_synthetic_srudb_bytes();
    bytes2[0] ^= 0x5A;
    let db2 = EseDatabase::from_bytes(&bytes2).expect("checksum mismatch should warn, not fail");
    assert!(!db2.header().checksum_valid);
    assert!(db2.warnings().iter().any(|w| w.message.contains("checksum mismatch")));
}

#[test]
fn handles_template_table_legacy_record_and_all_jet_coltypes() {
    let mut b = SyntheticEseBuilder::new(4096);
    b.write_headers(3, 0x11);
    let space_flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::SPACE_TREE;
    b.write_leaf_page(2, 1, space_flags, 0, 0, &[], &[]);
    b.write_leaf_page(3, 1, space_flags, 0, 0, &[], &[]);

    // Build MSysObjects with TemplateTable inheritance + legacy record table
    let mut rows = vec![
        // Template table (objid=10, pgno=5)
        build_record(
            &[
                (1, Some(&1i32.to_le_bytes())),
                (2, Some(&1i16.to_le_bytes())),
                (3, Some(&10i32.to_le_bytes())),
                (4, Some(&5i32.to_le_bytes())),
                (5, Some(&0i32.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(b"BaseTmpl"))],
            &[],
            false,
            true,
        ),
        // Template column: Bit (1)
        build_record(
            &[
                (1, Some(&10i32.to_le_bytes())),
                (2, Some(&2i16.to_le_bytes())),
                (3, Some(&1i32.to_le_bytes())),
                (4, Some(&1i32.to_le_bytes())),
                (5, Some(&1i32.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(b"FlagBit"))],
            &[],
            false,
            true,
        ),
        // Derived table (objid=20, pgno=6, TemplateTable="BaseTmpl")
        build_record(
            &[
                (1, Some(&1i32.to_le_bytes())),
                (2, Some(&1i16.to_le_bytes())),
                (3, Some(&20i32.to_le_bytes())),
                (4, Some(&6i32.to_le_bytes())),
                (5, Some(&0i32.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(b"DerivedTbl"))],
            &[(257, 0x00, b"BaseTmpl")],
            false,
            true,
        ),
    ];

    let extra_cols: Vec<(i32, i32, i32, i32, &str)> = vec![
        (2, 2, 1, 0, "ColU8"),
        (3, 3, 2, 0, "ColI16"),
        (4, 17, 2, 0, "ColU16"),
        (5, 14, 4, 0, "ColU32"),
        (6, 5, 8, 0, "ColCurrency"),
        (7, 6, 4, 0, "ColF32"),
        (8, 7, 8, 0, "ColF64"),
        (9, 13, 8, 0, "ColSlv"),
        (128, 10, 255, 1252, "ColCp1252"),
        (256, 9, 0, 0, "ColLegacyTag"),
    ];
    for (cid, ctyp, sz, cp, cname) in extra_cols {
        rows.push(build_record(
            &[
                (1, Some(&20i32.to_le_bytes())),
                (2, Some(&2i16.to_le_bytes())),
                (3, Some(&cid.to_le_bytes())),
                (4, Some(&ctyp.to_le_bytes())),
                (5, Some(&sz.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&cp.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(cname.as_bytes()))],
            &[],
            false,
            true,
        ));
    }

    let msys_tags: Vec<(u8, usize, &[u8], &[u8])> = rows
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            let k = Box::leak(format!("r{i:02}").into_bytes().into_boxed_slice());
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

    b.write_leaf_page(
        5,
        10,
        PageFlags::ROOT | PageFlags::LEAF | PageFlags::NEW_RECORD_FORMAT,
        0,
        0,
        &[],
        &[],
    );

    // Legacy !NEW_RECORD_FORMAT data row on pgno 6
    let cp1252_bytes = [0x80u8, b' ', 0x93, b'H', b'i', 0x94]; // "€ “Hi”"
    let data_rec = build_record(
        &[
            (1, Some(&[1u8])), // inherited Bit
            (2, Some(&[42u8])),
            (3, Some(&(-123i16).to_le_bytes())),
            (4, Some(&500u16.to_le_bytes())),
            (5, Some(&99_999u32.to_le_bytes())),
            (6, Some(&(-777i64).to_le_bytes())),
            (7, Some(&1.5f32.to_le_bytes())),
            (8, Some(&2.25f64.to_le_bytes())),
            (9, None), // NULL fixed Slv
        ],
        &[(128, Some(&cp1252_bytes))],
        &[(256, 0x00, &[0xDE, 0xAD, 0xBE, 0xEF])],
        false,
        false, // legacy tagged format!
    );
    b.write_leaf_page(
        6,
        20,
        PageFlags::ROOT | PageFlags::LEAF, // no NEW_RECORD_FORMAT
        0,
        0,
        &[],
        &[(0, 0, b"k", &data_rec)],
    );

    let db = EseDatabase::from_bytes(&b.build()).expect("template + legacy db");
    let tbl = db.read_table("DerivedTbl").expect("DerivedTbl");
    assert_eq!(tbl.rows.len(), 1);
    let r = &tbl.rows[0].values;
    assert_eq!(r.get("FlagBit"), Some(&EseValue::Bool(true)));
    assert_eq!(r.get("ColU8"), Some(&EseValue::U8(42)));
    assert_eq!(r.get("ColI16"), Some(&EseValue::I16(-123)));
    assert_eq!(r.get("ColU16"), Some(&EseValue::U16(500)));
    assert_eq!(r.get("ColU32"), Some(&EseValue::U32(99_999)));
    assert_eq!(r.get("ColCurrency"), Some(&EseValue::I64(-777)));
    assert_eq!(r.get("ColF32"), Some(&EseValue::F32(1.5)));
    assert_eq!(r.get("ColF64"), Some(&EseValue::F64(2.25)));
    assert_eq!(r.get("ColSlv"), Some(&EseValue::Null));
    assert_eq!(r.get("ColCp1252"), Some(&EseValue::Text("€ “Hi”".to_string())));
    assert_eq!(
        r.get("ColLegacyTag"),
        Some(&EseValue::Binary(vec![0xDE, 0xAD, 0xBE, 0xEF]))
    );
    assert_eq!(JetColType::from_u16(99), JetColType::Unknown(99));
}

#[test]
fn corrupted_truncated_and_cyclic_btree_fail_gracefully() {
    // 1. Empty / truncated
    assert!(EseDatabase::from_bytes(&[]).is_err());
    assert!(EseDatabase::from_bytes(&[0u8; 512]).is_err());

    // 2. Bad magic
    let mut bad_magic = vec![0u8; 4096 * 4];
    bad_magic[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    assert!(EseDatabase::from_bytes(&bad_magic).is_err());

    // 3. Invalid page size (1234)
    let mut bad_ps = build_synthetic_srudb_bytes();
    bad_ps[0xEC..0xF0].copy_from_slice(&1234u32.to_le_bytes());
    bad_ps[4096 + 0xEC..4096 + 0xF0].copy_from_slice(&1234u32.to_le_bytes());
    assert!(EseDatabase::from_bytes(&bad_ps).is_err());

    // 4. B-tree cycle (pgno 4 branch points to pgno 5, pgno 5 branch points back to pgno 4)
    let mut b = SyntheticEseBuilder::new(4096);
    b.write_headers(3, 0x17);
    b.write_branch_page(
        4,
        2,
        PageFlags::ROOT | PageFlags::PARENT | PageFlags::NEW_RECORD_FORMAT,
        &[(b"a", 5)],
    );
    b.write_branch_page(5, 2, PageFlags::PARENT | PageFlags::NEW_RECORD_FORMAT, &[(b"b", 4)]);
    let cycle_db = EseDatabase::from_bytes(&b.build()).expect("cycle guard must terminate cleanly");
    assert!(
        cycle_db.warnings().iter().any(|w| w.message.contains("cycle detected")),
        "expected cycle detection warning"
    );

    // 5. B-tree depth > MAX_BTREE_DEPTH (64) returns Err
    let mut deep = SyntheticEseBuilder::new(4096);
    deep.write_headers(3, 0x17);
    for pg in 4..=70u32 {
        let flags = if pg == 4 {
            PageFlags::ROOT | PageFlags::PARENT | PageFlags::NEW_RECORD_FORMAT
        } else {
            PageFlags::PARENT | PageFlags::NEW_RECORD_FORMAT
        };
        deep.write_branch_page(pg, 2, flags, &[(b"k", pg + 1)]);
    }
    let err = EseDatabase::from_bytes(&deep.build())
        .err()
        .expect("depth > 64 must error");
    assert!(matches!(err, ForensicError::Parse { .. }));

    // 6. Truncated SID blob in SruDbIdMapTable does not panic
    let decoded = crate::id_map::decode_sid_blob(&[1, 2, 0, 0]);
    assert!(decoded.starts_with("0x"));
}

#[test]
fn open_from_temp_file_and_error_classification() {
    let bytes = build_synthetic_srudb_bytes();
    let mut tmp = tempfile::NamedTempFile::new().expect("temp file");
    tmp.write_all(&bytes).expect("write");

    let db = EseDatabase::open(tmp.path()).expect("open temp SRUDB.dat");
    assert_eq!(db.header().page_size, 4096);

    let prov = SrumNetProvider::new(ForensicSource::OfflinePath(tmp.path().to_path_buf()));
    let res = prov.query(&TableQuery::default()).expect("query from path");
    assert_eq!(res.total_rows, 3);

    // Error classification checks for Win32 error codes 2, 3, 5, 1314, 32, 33
    assert!(matches!(
        classify_srum_io_error("SRUDB.dat", std::io::Error::from_raw_os_error(2)),
        ForensicError::NotFound(_)
    ));
    assert!(matches!(
        classify_srum_io_error("SRUDB.dat", std::io::Error::from_raw_os_error(3)),
        ForensicError::NotFound(_)
    ));
    assert!(matches!(
        classify_srum_io_error("SRUDB.dat", std::io::Error::from_raw_os_error(5)),
        ForensicError::PermissionDenied { .. }
    ));
    assert!(matches!(
        classify_srum_io_error("SRUDB.dat", std::io::Error::from_raw_os_error(1314)),
        ForensicError::PermissionDenied { .. }
    ));

    let err32 = classify_srum_io_error("SRUDB.dat", std::io::Error::from_raw_os_error(32));
    assert!(err32.to_string().contains("Diagnostic Policy Service (DPS)"));
    let err33 = classify_srum_io_error("SRUDB.dat", std::io::Error::from_raw_os_error(33));
    assert!(err33.to_string().contains("VSS"));

    // Live source check (never panics; either reads elevated or returns clean TableError::Provider)
    assert!(default_live_srudb_path().ends_with("SRUDB.dat"));
    let live_prov = SrumNetProvider::new(ForensicSource::Live);
    match live_prov.query(&TableQuery::default()) {
        Ok(_) => {}
        Err(TableError::Provider(msg)) => assert!(!msg.is_empty()),
        Err(other) => panic!("unexpected error variant for Live SRUM query: {other}"),
    }
}

#[test]
fn lz4_0x38_and_0x01_wrapper_roundtrip_and_bounds_errors() {
    // 1. 0x01 uncompressed wrapper
    let raw_incompressible = vec![0x01u8, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x42];
    let mut w = Vec::new();
    let res = decompress_ese_value(&raw_incompressible, &mut w).expect("0x01 wrapper");
    assert_eq!(
        res,
        DecompressOutcome::Decompressed {
            bytes: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x42],
            is_utf16_expanded: false,
        }
    );
    assert!(w.is_empty());

    // 2. 0x38 LZ4 with literals, overlapping RLE (offset=1, offset=3), extended lit & match lengths
    let mut payload = Vec::new();
    payload.extend_from_slice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789_"); // lit_len > 15
    payload.extend_from_slice(&[b'R'; 300]); // overlapping RLE offset=1, match_len > 270
    payload.extend_from_slice(b"XYZXYZXYZXYZXYZXYZXYZ"); // overlapping RLE offset=3
    payload.extend_from_slice(b"-TailLiterals12345");
    let lz4 = encode_ese_lz4(&payload);
    assert_eq!(lz4[0], 0x38);
    let out = decompress_ese_value(&lz4, &mut w).expect("0x38 LZ4 roundtrip");
    assert_eq!(
        out,
        DecompressOutcome::Decompressed {
            bytes: payload.clone(),
            is_utf16_expanded: false,
        }
    );
    assert!(w.is_empty());

    // Also test non-zero lower 3 bits on 0x38..=0x3F (e.g., 0x3A)
    let mut lz4_3a = lz4;
    lz4_3a[0] = 0x3A;
    let out_3a = decompress_ese_value(&lz4_3a, &mut w).expect("0x3A LZ4 roundtrip");
    assert_eq!(
        out_3a,
        DecompressOutcome::Decompressed {
            bytes: payload,
            is_utf16_expanded: false,
        }
    );

    // 3. Adversarial malformed 0x38 LZ4 payloads must return Err, never panic
    // Too short for header
    assert!(decompress_ese_value(&[0x38, 0x05], &mut w).is_err());
    // Zero offset
    assert!(decompress_ese_value(&[0x38, 0x08, 0x00, 0x40, b'A', b'B', b'C', b'D', 0x00, 0x00], &mut w).is_err());
    // Offset > out.len()
    assert!(decompress_ese_value(&[0x38, 0x08, 0x00, 0x20, b'A', b'B', 0x05, 0x00], &mut w).is_err());
    // Truncated literals
    assert!(decompress_ese_value(&[0x38, 0x08, 0x00, 0x80, b'A', b'B'], &mut w).is_err());
    // Uncompressed length mismatch (truncated stream)
    assert!(decompress_ese_value(&[0x38, 0x20, 0x00, 0x30, b'A', b'B', b'C'], &mut w).is_err());
    // Match exceeds declared uncompressed length
    assert!(decompress_ese_value(&[0x38, 0x04, 0x00, 0x11, b'A', 0x01, 0x00], &mut w).is_err());
}

#[test]
fn separated_lv_per_chunk_compression_flags_0x1000_and_corrupt_fallback() {
    let mut b = SyntheticEseBuilder::new(4096);
    b.write_headers(3, 0x17);
    let space_flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::SPACE_TREE;
    b.write_leaf_page(2, 1, space_flags, 0, 0, &[], &[]);
    b.write_leaf_page(3, 1, space_flags, 0, 0, &[], &[]);

    // Helper for MSysObjects column row with explicit Flags
    let make_col = |tid: i32, cid: i32, ctyp: i32, sz: i32, flags: i32, cp: i32, name: &str| {
        build_record(
            &[
                (1, Some(&tid.to_le_bytes())),
                (2, Some(&2i16.to_le_bytes())),
                (3, Some(&cid.to_le_bytes())),
                (4, Some(&ctyp.to_le_bytes())),
                (5, Some(&sz.to_le_bytes())),
                (6, Some(&flags.to_le_bytes())),
                (7, Some(&cp.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(name.as_bytes()))],
            &[],
            false,
            true,
        )
    };

    let msys_rows = [
        build_record(
            &[
                (1, Some(&1i32.to_le_bytes())),
                (2, Some(&1i16.to_le_bytes())),
                (3, Some(&10i32.to_le_bytes())),
                (4, Some(&5i32.to_le_bytes())),
                (5, Some(&0i32.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(b"LvTest"))],
            &[],
            false,
            true,
        ),
        build_record(
            &[
                (1, Some(&10i32.to_le_bytes())),
                (2, Some(&4i16.to_le_bytes())),
                (3, Some(&4i32.to_le_bytes())),
                (4, Some(&6i32.to_le_bytes())),
                (5, Some(&0i32.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(b"LV"))],
            &[],
            false,
            true,
        ),
        make_col(10, 1, 4, 4, 0, 0, "RowId"),
        make_col(10, 256, 11, 0, 0x1000, 0, "MultiLz4Bin"),
        make_col(10, 257, 12, 0, 0x1000, 1200, "Multi7BitUniText"),
        make_col(10, 258, 12, 0, 0x1000, 1200, "UncompressedWithFlag"),
        make_col(10, 259, 11, 0, 0x1000, 0, "CorruptLvBin"),
    ];
    let msys_tags: Vec<(u8, usize, &[u8], &[u8])> = msys_rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let k = Box::leak(format!("m{i:02}").into_bytes().into_boxed_slice());
            (0u8, 0usize, &*k, r.as_slice())
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

    // Build LV chunks on pgno=6:
    // lid=1: 2 chunks compressed individually (chunk 0: 0x38 LZ4, chunk 1: 0x01 wrapper)
    let part_a = b"AAAAAAAAAAAA_Chunk0_LZ4_Data_".repeat(4);
    let part_b = b"_Chunk1_Raw_0x01_Data";
    let chunk1_a = encode_ese_lz4(&part_a);
    let mut chunk1_b = vec![0x01u8];
    chunk1_b.extend_from_slice(part_b);
    let mut expected_bin = part_a.clone();
    expected_bin.extend_from_slice(part_b);

    // lid=2: 2 chunks of 7-bit Unicode with 0x13 and 0x16 header bytes
    let mut chunk2_a = encode_ese_7bit_unicode(b"FirstChunk ");
    chunk2_a[0] = 0x13;
    let mut chunk2_b = encode_ese_7bit_unicode(b"SecondChunk");
    chunk2_b[0] = 0x16;

    // lid=3: legitimately uncompressed UTF-16LE text inside a col with 0x1000 flag (starts with '0'=0x30)
    let raw_utf16 = encode_utf16le_nul("0-Uncompressed-Text");

    // lid=4: corrupted XPRESS inside separated LV (must warn and preserve raw binary without aborting)
    let corrupt_xpress = vec![0x18u8, 0x80, 0x00, 0x00, 0x00];

    b.write_lv_page(
        6,
        10,
        &[
            (1, 0, &chunk1_a),
            (1, part_a.len() as u32, &chunk1_b),
            (2, 0, &chunk2_a),
            (2, 22, &chunk2_b),
            (3, 0, &raw_utf16),
            (4, 0, &corrupt_xpress),
        ],
    );

    // Record has TAGFLD_HEADER 0x04 (fSeparated ONLY, fCompressed=0x02 NOT set!)
    let rec = build_record(
        &[(1, Some(&1i32.to_le_bytes()))],
        &[],
        &[
            (256, 0x04, &1u32.to_le_bytes()),
            (257, 0x04, &2u32.to_le_bytes()),
            (258, 0x04, &3u32.to_le_bytes()),
            (259, 0x04, &4u32.to_le_bytes()),
        ],
        false,
        true,
    );
    b.write_leaf_page(
        5,
        10,
        PageFlags::ROOT | PageFlags::LEAF | PageFlags::NEW_RECORD_FORMAT,
        0,
        0,
        &[],
        &[(0, 0, b"r0", &rec)],
    );

    let db = EseDatabase::from_bytes(&b.build()).expect("LV db");
    let tbl = db
        .read_table("LvTest")
        .expect("read_table must not abort on corrupt LV");
    assert_eq!(tbl.rows.len(), 1);
    let r = &tbl.rows[0].values;
    assert_eq!(r.get("MultiLz4Bin"), Some(&EseValue::Binary(expected_bin)));
    assert_eq!(
        r.get("Multi7BitUniText"),
        Some(&EseValue::Text("FirstChunk SecondChunk".to_string()))
    );
    assert_eq!(
        r.get("UncompressedWithFlag"),
        Some(&EseValue::Text("0-Uncompressed-Text".to_string()))
    );
    assert_eq!(r.get("CorruptLvBin"), Some(&EseValue::Binary(corrupt_xpress)));
}

#[test]
fn msysobjects_template_table_fid_130_and_fderived_tag_collision() {
    let mut b = SyntheticEseBuilder::new(4096);
    b.write_headers(3, 0x17);
    let space_flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::SPACE_TREE;
    b.write_leaf_page(2, 1, space_flags, 0, 0, &[], &[]);
    b.write_leaf_page(3, 1, space_flags, 0, 0, &[], &[]);

    let make_col = |tid: i32, cid: i32, ctyp: i32, sz: i32, off: i16, cp: i32, name: &str| {
        build_record(
            &[
                (1, Some(&tid.to_le_bytes())),
                (2, Some(&2i16.to_le_bytes())),
                (3, Some(&cid.to_le_bytes())),
                (4, Some(&ctyp.to_le_bytes())),
                (5, Some(&sz.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&cp.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&off.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(name.as_bytes()))],
            &[],
            false,
            true,
        )
    };

    let msys_rows = [
        // BaseTemplate (objid=10, pgno=5)
        build_record(
            &[
                (1, Some(&1i32.to_le_bytes())),
                (2, Some(&1i16.to_le_bytes())),
                (3, Some(&10i32.to_le_bytes())),
                (4, Some(&5i32.to_le_bytes())),
                (5, Some(&0i32.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(b"BaseTemplate"))],
            &[],
            false,
            true,
        ),
        make_col(10, 1, 4, 4, 4, 0, "AutoId"),
        make_col(10, 2, 15, 8, 8, 0, "CreatedAt"),
        make_col(10, 256, 12, 0, 0, 1252, "TmplTag"),
        // DerivedTable (objid=20, pgno=6) with TemplateTable in variable col id=130!
        // Also has CallbackDependencies in tagged col id=257 (must NOT be misread as TemplateTable!)
        build_record(
            &[
                (1, Some(&1i32.to_le_bytes())),
                (2, Some(&1i16.to_le_bytes())),
                (3, Some(&20i32.to_le_bytes())),
                (4, Some(&6i32.to_le_bytes())),
                (5, Some(&0i32.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(b"DerivedTable")), (129, None), (130, Some(b"BaseTemplate"))],
            &[(257, 0x00, b"CallbackDepBinary")],
            false,
            true,
        ),
        make_col(20, 3, 1, 1, 16, 0, "FlagBit"),
        make_col(20, 256, 12, 0, 0, 1252, "OwnTag"), // Same fid=256 as TmplTag!
    ];
    let msys_tags: Vec<(u8, usize, &[u8], &[u8])> = msys_rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let k = Box::leak(format!("t{i:02}").into_bytes().into_boxed_slice());
            (0u8, 0usize, &*k, r.as_slice())
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
    b.write_leaf_page(
        5,
        10,
        PageFlags::ROOT | PageFlags::LEAF | PageFlags::NEW_RECORD_FORMAT,
        0,
        0,
        &[],
        &[],
    );

    // Build data record manually with fDerived (0x8000) on TmplTag (fid=256) and !fDerived on OwnTag (fid=256)
    let mut data_rec = build_record(
        &[
            (1, Some(&77i32.to_le_bytes())),
            (2, Some(&999_999i64.to_le_bytes())),
            (3, Some(&[1u8])),
        ],
        &[],
        &[],
        false,
        true,
    );
    // Append NewRecordFormat TAGFLD directory with 2 entries: OwnTag (fid=256, off=8) & TmplTag (fid=256, off=14 | 0x8000)
    data_rec.extend_from_slice(&256u16.to_le_bytes());
    data_rec.extend_from_slice(&8u16.to_le_bytes());
    data_rec.extend_from_slice(&256u16.to_le_bytes());
    data_rec.extend_from_slice(&(14u16 | 0x8000).to_le_bytes());
    data_rec.extend_from_slice(b"OwnVal"); // 6 bytes (8..14)
    data_rec.extend_from_slice(b"TmplVal"); // 7 bytes (14..21)

    b.write_leaf_page(
        6,
        20,
        PageFlags::ROOT | PageFlags::LEAF | PageFlags::NEW_RECORD_FORMAT,
        0,
        0,
        &[],
        &[(0, 0, b"d0", &data_rec)],
    );

    let db = EseDatabase::from_bytes(&b.build()).expect("template fid 130 db");
    let schema = db.table_schema("DerivedTable").expect("DerivedTable schema");
    assert_eq!(schema.template_table.as_deref(), Some("BaseTemplate"));

    let tbl = db.read_table("DerivedTable").expect("read DerivedTable");
    assert_eq!(tbl.rows.len(), 1);
    let r = &tbl.rows[0].values;
    assert_eq!(r.get("AutoId"), Some(&EseValue::I32(77)));
    assert_eq!(r.get("CreatedAt"), Some(&EseValue::I64(999_999)));
    assert_eq!(r.get("FlagBit"), Some(&EseValue::Bool(true)));
    assert_eq!(r.get("OwnTag"), Some(&EseValue::Text("OwnVal".to_string())));
    assert_eq!(r.get("TmplTag"), Some(&EseValue::Text("TmplVal".to_string())));
}

#[test]
fn tagfld_fnull_0x20_and_find_col_ci_skips_null() {
    // Build a DB with {DD6636C4-...} where TimeStamp is tagged with fNull (0x20)
    // and ConnectStartTime has a valid FILETIME; SrumEnergyProvider must fall back to ConnectStartTime.
    let mut b = SyntheticEseBuilder::new(4096);
    b.write_headers(3, 0x17);
    let space_flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::SPACE_TREE;
    b.write_leaf_page(2, 1, space_flags, 0, 0, &[], &[]);
    b.write_leaf_page(3, 1, space_flags, 0, 0, &[], &[]);

    let make_col = |tid: i32, cid: i32, ctyp: i32, sz: i32, name: &str| {
        build_record(
            &[
                (1, Some(&tid.to_le_bytes())),
                (2, Some(&2i16.to_le_bytes())),
                (3, Some(&cid.to_le_bytes())),
                (4, Some(&ctyp.to_le_bytes())),
                (5, Some(&sz.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(name.as_bytes()))],
            &[],
            false,
            true,
        )
    };

    let msys_rows = [
        build_record(
            &[
                (1, Some(&1i32.to_le_bytes())),
                (2, Some(&1i16.to_le_bytes())),
                (3, Some(&50i32.to_le_bytes())),
                (4, Some(&5i32.to_le_bytes())),
                (5, Some(&0i32.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(b"{DD6636C4-8929-4683-974E-22C046A43763}"))],
            &[],
            false,
            true,
        ),
        make_col(50, 1, 15, 8, "ConnectStartTime"),
        make_col(50, 2, 4, 4, "ConnectedTime"),
        make_col(50, 256, 8, 8, "TimeStamp"),
        make_col(50, 257, 10, 255, "TaggedNullText"),
    ];
    let msys_tags: Vec<(u8, usize, &[u8], &[u8])> = msys_rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let k = Box::leak(format!("e{i:02}").into_bytes().into_boxed_slice());
            (0u8, 0usize, &*k, r.as_slice())
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

    let ft_valid: i64 = 133_751_856_000_000_000;
    let conn_rec = build_record(
        &[(1, Some(&ft_valid.to_le_bytes())), (2, Some(&4200i32.to_le_bytes()))],
        &[],
        &[(256, 0x20, &[]), (257, 0x20, &[])], // TAGFLD_HEADER fNull (0x20)
        false,
        true,
    );
    b.write_leaf_page(
        5,
        50,
        PageFlags::ROOT | PageFlags::LEAF | PageFlags::NEW_RECORD_FORMAT,
        0,
        0,
        &[],
        &[(0, 0, b"c0", &conn_rec)],
    );

    let db_bytes = b.build();
    let db = EseDatabase::from_bytes(&db_bytes).expect("fNull db");
    let tbl = db
        .read_table("{DD6636C4-8929-4683-974E-22C046A43763}")
        .expect("read DD6636C4");
    assert_eq!(tbl.rows[0].values.get("TimeStamp"), Some(&EseValue::Null));
    assert_eq!(tbl.rows[0].values.get("TaggedNullText"), Some(&EseValue::Null));

    // SrumEnergyProvider must skip TimeStamp=Null and fall back to ConnectStartTime!
    let prov = SrumEnergyProvider::new(ForensicSource::OfflineBytes(db_bytes));
    let res = prov.query(&TableQuery::default()).expect("srum.energy query");
    assert_eq!(res.total_rows, 1);
    assert!(
        matches!(res.rows[0].cells[0], CellValue::Timestamp(_)),
        "expected Timestamp fallback from ConnectStartTime, got {:?}",
        res.rows[0].cells[0]
    );
    assert_eq!(res.rows[0].cells[7], CellValue::Uint(4200));
}

fn encode_multi_value_payload(elements: &[&[u8]]) -> Vec<u8> {
    let header_len = elements.len() * 2;
    let mut out = Vec::new();
    let mut cur = header_len;
    for elem in elements {
        out.extend_from_slice(&(cur as u16).to_le_bytes());
        cur += elem.len();
    }
    for elem in elements {
        out.extend_from_slice(elem);
    }
    out
}

#[test]
fn multi_value_longtext_mixed_7bit_unicode_and_raw_utf16_and_twovalues() {
    let mut b = SyntheticEseBuilder::new(16384);
    b.write_headers(3, 0x66BC);
    let space_flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::SPACE_TREE;
    b.write_leaf_page(2, 1, space_flags, 0, 0, &[], &[]);
    b.write_leaf_page(3, 1, space_flags, 0, 0, &[], &[]);

    let make_col = |tid: i32, cid: i32, ctyp: i32, sz: i32, flags: i32, cp: i32, name: &str| {
        build_record(
            &[
                (1, Some(&tid.to_le_bytes())),
                (2, Some(&2i16.to_le_bytes())),
                (3, Some(&cid.to_le_bytes())),
                (4, Some(&ctyp.to_le_bytes())),
                (5, Some(&sz.to_le_bytes())),
                (6, Some(&flags.to_le_bytes())),
                (7, Some(&cp.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(name.as_bytes()))],
            &[],
            true,
            true,
        )
    };

    let msys_rows = [
        build_record(
            &[
                (1, Some(&1i32.to_le_bytes())),
                (2, Some(&1i16.to_le_bytes())),
                (3, Some(&10i32.to_le_bytes())),
                (4, Some(&5i32.to_le_bytes())),
                (5, Some(&0i32.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(b"tbHistory"))],
            &[],
            true,
            true,
        ),
        make_col(10, 1, 4, 4, 0, 0, "RowId"),
        // fid=262 LongText cp=1200 flags=0x1008 (Compressed | MultiValued)
        make_col(10, 262, 12, 0, 0x1008, 1200, "Categories"),
        // fid=263 LongText cp=1200 flags=0x1008 (fTwoValues test)
        make_col(10, 263, 12, 0, 0x1008, 1200, "TwoCategories"),
    ];
    let msys_tags: Vec<(u8, usize, &[u8], &[u8])> = msys_rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let k = Box::leak(format!("m{i:02}").into_bytes().into_boxed_slice());
            (0u8, 0usize, &*k, r.as_slice())
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

    // Element 0: 7-bit Unicode (0x14 header) "Windows 10\0"
    let mut e0 = encode_ese_7bit_unicode(b"Windows 10\0");
    e0[0] = 0x14;
    // Element 1: uncompressed UTF-16LE "Windows 10 LTSB"
    let e1 = encode_utf16le_nul("Windows 10 LTSB");
    // Element 2: uncompressed UTF-16LE starting with '<' (0x3C, collides with 0x38 LZ4 header!)
    let e2 = encode_utf16le_nul("<Security>");
    // Element 3: uncompressed UTF-16LE starting with \u{0001} (0x01, collides with 0x01 wrapper!)
    let e3 = encode_utf16le_nul("\u{0001}Tag");
    let mv_categories = encode_multi_value_payload(&[&e0, &e1, &e2, &e3]);

    // fTwoValues (0x18 = fMultiValues | fTwoValues, + 0x02 fCompressed = 0x1A)
    let tv0 = encode_ese_7bit_unicode(b"Alpha");
    let tv1 = encode_utf16le_nul("Beta");
    let mut tv_payload = Vec::new();
    tv_payload.push(tv0.len() as u8);
    tv_payload.extend_from_slice(&tv0);
    tv_payload.extend_from_slice(&tv1);

    let rec = build_record(
        &[(1, Some(&1i32.to_le_bytes()))],
        &[],
        &[(262, 0x0A, &mv_categories), (263, 0x1A, &tv_payload)],
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
        &[(0, 0, b"r0", &rec)],
    );

    let db = EseDatabase::from_bytes(&b.build()).expect("multi-value db");
    let tbl = db.read_table("tbHistory").expect("tbHistory");
    assert_eq!(tbl.rows.len(), 1);
    assert_eq!(
        tbl.rows[0].values.get("Categories"),
        Some(&EseValue::Text(
            "Windows 10; Windows 10 LTSB; <Security>; \u{0001}Tag".to_string()
        ))
    );
    assert_eq!(
        tbl.rows[0].values.get("TwoCategories"),
        Some(&EseValue::Text("Alpha; Beta".to_string()))
    );
}

#[test]
fn multi_value_guid_server_ref_format() {
    let mut b = SyntheticEseBuilder::new(16384);
    b.write_headers(3, 0x66BC);
    let space_flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::SPACE_TREE;
    b.write_leaf_page(2, 1, space_flags, 0, 0, &[], &[]);
    b.write_leaf_page(3, 1, space_flags, 0, 0, &[], &[]);

    let make_col = |tid: i32, cid: i32, ctyp: i32, sz: i32, flags: i32, name: &str| {
        build_record(
            &[
                (1, Some(&tid.to_le_bytes())),
                (2, Some(&2i16.to_le_bytes())),
                (3, Some(&cid.to_le_bytes())),
                (4, Some(&ctyp.to_le_bytes())),
                (5, Some(&sz.to_le_bytes())),
                (6, Some(&flags.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(name.as_bytes()))],
            &[],
            true,
            true,
        )
    };

    let msys_rows = [
        build_record(
            &[
                (1, Some(&1i32.to_le_bytes())),
                (2, Some(&1i16.to_le_bytes())),
                (3, Some(&20i32.to_le_bytes())),
                (4, Some(&5i32.to_le_bytes())),
                (5, Some(&0i32.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(b"tbUpdates"))],
            &[],
            true,
            true,
        ),
        make_col(20, 1, 4, 4, 0, "RowId"),
        make_col(20, 273, 16, 16, 0x08, "ServerRef"),
    ];
    let msys_tags: Vec<(u8, usize, &[u8], &[u8])> = msys_rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let k = Box::leak(format!("u{i:02}").into_bytes().into_boxed_slice());
            (0u8, 0usize, &*k, r.as_slice())
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

    let g1: [u8; 16] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
    ];
    let g2: [u8; 16] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22,
    ];
    let mv_guids = encode_multi_value_payload(&[&g1, &g2]);
    assert_eq!(mv_guids.len(), 36);
    assert_eq!(&mv_guids[0..4], &[0x04, 0x00, 0x14, 0x00]);

    let single_guid = encode_multi_value_payload(&[&g1]);

    let r0 = build_record(
        &[(1, Some(&1i32.to_le_bytes()))],
        &[],
        &[(273, 0x08, &mv_guids)],
        true,
        true,
    );
    let r1 = build_record(
        &[(1, Some(&2i32.to_le_bytes()))],
        &[],
        &[(273, 0x08, &single_guid)],
        true,
        true,
    );
    b.write_leaf_page(
        5,
        20,
        PageFlags::ROOT | PageFlags::LEAF | PageFlags::NEW_RECORD_FORMAT,
        0,
        0,
        &[],
        &[(0, 0, b"r0", &r0), (0, 0, b"r1", &r1)],
    );

    let db = EseDatabase::from_bytes(&b.build()).expect("multi-value guid db");
    let tbl = db.read_table("tbUpdates").expect("tbUpdates");
    assert_eq!(tbl.rows.len(), 2);
    assert_eq!(
        tbl.rows[0].values.get("ServerRef"),
        Some(&EseValue::Text(
            "{44332211-6655-8877-99aa-bbccddeeff00}; {ddccbbaa-2211-4433-5566-778899001122}".to_string()
        ))
    );
    assert_eq!(
        tbl.rows[1].values.get("ServerRef"),
        Some(&EseValue::Guid("{44332211-6655-8877-99aa-bbccddeeff00}".to_string()))
    );
}

#[test]
fn separated_lv_combined_with_multi_value_decodes_cleanly() {
    let mut b = SyntheticEseBuilder::new(4096);
    b.write_headers(3, 0x17);
    let space_flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::SPACE_TREE;
    b.write_leaf_page(2, 1, space_flags, 0, 0, &[], &[]);
    b.write_leaf_page(3, 1, space_flags, 0, 0, &[], &[]);

    let make_col = |tid: i32, cid: i32, ctyp: i32, sz: i32, flags: i32, cp: i32, name: &str| {
        build_record(
            &[
                (1, Some(&tid.to_le_bytes())),
                (2, Some(&2i16.to_le_bytes())),
                (3, Some(&cid.to_le_bytes())),
                (4, Some(&ctyp.to_le_bytes())),
                (5, Some(&sz.to_le_bytes())),
                (6, Some(&flags.to_le_bytes())),
                (7, Some(&cp.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(name.as_bytes()))],
            &[],
            false,
            true,
        )
    };

    let msys_rows = [
        build_record(
            &[
                (1, Some(&1i32.to_le_bytes())),
                (2, Some(&1i16.to_le_bytes())),
                (3, Some(&30i32.to_le_bytes())),
                (4, Some(&5i32.to_le_bytes())),
                (5, Some(&0i32.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(b"SepMvTable"))],
            &[],
            false,
            true,
        ),
        build_record(
            &[
                (1, Some(&30i32.to_le_bytes())),
                (2, Some(&4i16.to_le_bytes())),
                (3, Some(&4i32.to_le_bytes())),
                (4, Some(&6i32.to_le_bytes())),
                (5, Some(&0i32.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(b"LV"))],
            &[],
            false,
            true,
        ),
        make_col(30, 1, 4, 4, 0, 0, "RowId"),
        make_col(30, 256, 12, 0, 0x1008, 1200, "SepCategories"),
    ];
    let msys_tags: Vec<(u8, usize, &[u8], &[u8])> = msys_rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let k = Box::leak(format!("s{i:02}").into_bytes().into_boxed_slice());
            (0u8, 0usize, &*k, r.as_slice())
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

    // Build separated multi-value buffer starting with off0=0x08 (4 elements!) so we also prove
    // LV resolution does NOT misinterpret off0=0x08 as a 7-bit ASCII compression header!
    // Per authentic ESENT semantics, only elem[0] may be compressed inline; elem[1+] are raw.
    let e0 = encode_ese_lz4(&encode_utf16le_nul("First-Long-LZ4-Element-Repeated-Repeated"));
    let e1 = encode_utf16le_nul("Second");
    let e2 = encode_utf16le_nul("Third");
    let e3 = encode_utf16le_nul("Fourth");
    let mv_buf = encode_multi_value_payload(&[&e0, &e1, &e2, &e3]);
    let split = mv_buf.len() / 2;

    b.write_lv_page(6, 30, &[(1, 0, &mv_buf[..split]), (1, split as u32, &mv_buf[split..])]);

    // TAGFLD_HEADER: 0x04 (is_separated) | 0x08 (is_multi_value) | 0x02 (is_compressed) = 0x0E
    let rec = build_record(
        &[(1, Some(&1i32.to_le_bytes()))],
        &[],
        &[(256, 0x0E, &1u32.to_le_bytes())],
        false,
        true,
    );
    b.write_leaf_page(
        5,
        30,
        PageFlags::ROOT | PageFlags::LEAF | PageFlags::NEW_RECORD_FORMAT,
        0,
        0,
        &[],
        &[(0, 0, b"r0", &rec)],
    );

    let db = EseDatabase::from_bytes(&b.build()).expect("sep+mv db");
    let tbl = db.read_table("SepMvTable").expect("SepMvTable");
    assert_eq!(tbl.rows.len(), 1);
    assert_eq!(
        tbl.rows[0].values.get("SepCategories"),
        Some(&EseValue::Text(
            "First-Long-LZ4-Element-Repeated-Repeated; Second; Third; Fourth".to_string()
        ))
    );
}

#[test]
fn malformed_multi_value_offset_arrays_warn_and_recover_without_panic() {
    use std::collections::BTreeMap;

    use crate::ese::catalog::EseColumnSchema;
    use crate::ese::lv::LongValueIndex;
    use crate::ese::record::{ParsedRecord, TaggedField};
    use crate::ese::value::decode_column_value;

    let col = EseColumnSchema {
        id: 262,
        name: "Categories".to_string(),
        col_type: JetColType::LongText,
        max_size: 0,
        flags: 0x1008,
        codepage: 1200,
        record_offset: None,
        is_derived: false,
    };
    let lv_index = LongValueIndex::empty();

    let malformed_cases: Vec<Vec<u8>> = vec![
        vec![],                                   // empty (< 2 bytes)
        vec![0x02],                               // 1 byte (< 2 bytes)
        vec![0x00, 0x00, 0x41, 0x00],             // off_0 < 2
        vec![0x03, 0x00, 0x41, 0x00],             // odd off_0
        vec![0x08, 0x00, 0x08, 0x00],             // off_0 > len
        vec![0x04, 0x00, 0x02, 0x00, 0x41, 0x00], // non-monotonic (off_1=2 < off_0=4)
        vec![0x04, 0x00, 0x20, 0x00, 0x41, 0x00], // off_1 > len
    ];

    for payload in malformed_cases {
        let rec = ParsedRecord {
            fixed: BTreeMap::new(),
            variable: BTreeMap::new(),
            tagged: vec![TaggedField {
                fid: 262,
                data: payload.clone(),
                is_compressed: true,
                is_separated: false,
                is_multi_value: true,
                is_two_values: false,
                is_null: false,
                is_derived: false,
            }],
        };
        let mut warnings = Vec::new();
        let val =
            decode_column_value(&col, &rec, &lv_index, &mut warnings).expect("malformed multi-value must not abort");
        assert_eq!(val, EseValue::Binary(payload));
        assert_eq!(
            warnings.len(),
            1,
            "expected DiagnosticWarning for malformed offset array"
        );
    }

    // Malformed fTwoValues (len0 out of bounds) must also warn and preserve raw binary
    let two_rec = ParsedRecord {
        fixed: BTreeMap::new(),
        variable: BTreeMap::new(),
        tagged: vec![TaggedField {
            fid: 262,
            data: vec![0x50, 0x41, 0x00],
            is_compressed: false,
            is_separated: false,
            is_multi_value: true,
            is_two_values: true,
            is_null: false,
            is_derived: false,
        }],
    };
    let mut tw_warnings = Vec::new();
    let tw_val =
        decode_column_value(&col, &two_rec, &lv_index, &mut tw_warnings).expect("malformed fTwoValues must not abort");
    assert_eq!(tw_val, EseValue::Binary(vec![0x50, 0x41, 0x00]));
    assert_eq!(tw_warnings.len(), 1);
}

fn encode_multi_value_payload_with_sep(elements: &[(&[u8], bool)]) -> Vec<u8> {
    let header_len = elements.len() * 2;
    let mut out = Vec::new();
    let mut cur = header_len;
    for &(elem, is_sep) in elements {
        let word = (cur as u16) | if is_sep { 0x8000 } else { 0 };
        out.extend_from_slice(&word.to_le_bytes());
        cur += elem.len();
    }
    for &(elem, _) in elements {
        out.extend_from_slice(elem);
    }
    out
}

fn make_lv_root_value(ref_count: u32, ul_size: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&ref_count.to_le_bytes());
    out[4..8].copy_from_slice(&ul_size.to_le_bytes());
    out
}

fn make_lv_chunk_key_8(lid64: u64, offset: u32) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0..8].copy_from_slice(&lid64.to_be_bytes());
    out[8..12].copy_from_slice(&offset.to_be_bytes());
    out
}

fn make_lv_chunk_key_4(lid32: u32, offset: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&lid32.to_be_bytes());
    out[4..8].copy_from_slice(&offset.to_be_bytes());
    out
}

#[test]
fn multi_value_per_element_0x8000_separated_and_mixed_inline() {
    let mut b = SyntheticEseBuilder::new(16384);
    b.write_headers(3, 0x66BC);
    let space_flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::SPACE_TREE;
    b.write_leaf_page(2, 1, space_flags, 0, 0, &[], &[]);
    b.write_leaf_page(3, 1, space_flags, 0, 0, &[], &[]);

    let make_col = |tid: i32, cid: i32, ctyp: i32, sz: i32, flags: i32, cp: i32, name: &str| {
        build_record(
            &[
                (1, Some(&tid.to_le_bytes())),
                (2, Some(&2i16.to_le_bytes())),
                (3, Some(&cid.to_le_bytes())),
                (4, Some(&ctyp.to_le_bytes())),
                (5, Some(&sz.to_le_bytes())),
                (6, Some(&flags.to_le_bytes())),
                (7, Some(&cp.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(name.as_bytes()))],
            &[],
            true,
            true,
        )
    };

    let msys_rows = [
        build_record(
            &[
                (1, Some(&1i32.to_le_bytes())),
                (2, Some(&1i16.to_le_bytes())),
                (3, Some(&40i32.to_le_bytes())),
                (4, Some(&5i32.to_le_bytes())),
                (5, Some(&0i32.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(b"MvSepTable"))],
            &[],
            true,
            true,
        ),
        build_record(
            &[
                (1, Some(&40i32.to_le_bytes())),
                (2, Some(&4i16.to_le_bytes())),
                (3, Some(&4i32.to_le_bytes())),
                (4, Some(&6i32.to_le_bytes())),
                (5, Some(&0i32.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(b"LV"))],
            &[],
            true,
            true,
        ),
        make_col(40, 1, 4, 4, 0, 0, "RowId"),
        make_col(40, 262, 12, 0, 0x1008, 1200, "MvSeparatedText"),
    ];
    let msys_tags: Vec<(u8, usize, &[u8], &[u8])> = msys_rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let k = Box::leak(format!("m{i:02}").into_bytes().into_boxed_slice());
            (0u8, 0usize, &*k, r.as_slice())
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

    // 8-byte LIDs matching real esent.dll (`[03, 00, 00, 80, 00, 00, 00, 80]` etc.)
    let lid1: u64 = 0x8000_0000_8000_0003;
    let lid2: u64 = 0x8000_0000_8000_0004;
    let lid3: u64 = 0x8000_0000_8000_0005;
    let lid_mix: u64 = 0x8000_0000_8000_000C;

    // LID 1: multi-chunk compressed LV (chunk 0: 0x38 LZ4, chunk 1: 0x14 7-bit Unicode)
    let lv1_p0: Vec<u8> = "SepMV0-Repeated-"
        .repeat(20)
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let lv1_c0 = encode_ese_lz4(&lv1_p0);
    let mut lv1_c1 = encode_ese_7bit_unicode(b"-Tail0\0");
    lv1_c1[0] = 0x14;
    let lv1_ul_size = (lv1_p0.len() + 14) as u32;

    // LID 2: uncompressed UTF-16LE starting with '<' (0x3C) with exact ulSize == chunk.len()
    let lv2_raw = encode_utf16le_nul("<SepMV1-RawUtf16>");
    let lv2_ul_size = lv2_raw.len() as u32;

    // LID 3: 0x01-wrapped uncompressed UTF-16LE (`chunk.len() == ulSize + 1`)
    let lv3_raw = encode_utf16le_nul("SepMV2-Wrapped01");
    let mut lv3_wrapped = vec![0x01u8];
    lv3_wrapped.extend_from_slice(&lv3_raw);
    let lv3_ul_size = lv3_raw.len() as u32;

    // LID mix: multi-chunk compressed LV for mixed inline+sep+inline row
    let mix_p0: Vec<u8> = "SepMiddle-5-"
        .repeat(16)
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let mix_c0 = encode_ese_lz4(&mix_p0);
    let mut mix_c1 = encode_ese_7bit_unicode(b"-End\0");
    mix_c1[0] = 0x12;
    let mix_ul_size = (mix_p0.len() + 10) as u32;

    let lv_entries: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (lid1.to_be_bytes().to_vec(), make_lv_root_value(1, lv1_ul_size).to_vec()),
        (make_lv_chunk_key_8(lid1, 0).to_vec(), lv1_c0),
        (make_lv_chunk_key_8(lid1, lv1_p0.len() as u32).to_vec(), lv1_c1),
        (lid2.to_be_bytes().to_vec(), make_lv_root_value(1, lv2_ul_size).to_vec()),
        (make_lv_chunk_key_8(lid2, 0).to_vec(), lv2_raw),
        (lid3.to_be_bytes().to_vec(), make_lv_root_value(1, lv3_ul_size).to_vec()),
        (make_lv_chunk_key_8(lid3, 0).to_vec(), lv3_wrapped),
        (
            lid_mix.to_be_bytes().to_vec(),
            make_lv_root_value(1, mix_ul_size).to_vec(),
        ),
        (make_lv_chunk_key_8(lid_mix, 0).to_vec(), mix_c0),
        (make_lv_chunk_key_8(lid_mix, mix_p0.len() as u32).to_vec(), mix_c1),
    ];
    let lv_refs: Vec<(&[u8], &[u8])> = lv_entries.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect();
    b.write_raw_lv_page(6, 40, &lv_refs);

    // Row 0: all-separated [06, 80, 0e, 80, 16, 80, ...] with outer TAGFLD_HEADER = 0x08 (fMultiValues only)
    let mv_all_sep = encode_multi_value_payload_with_sep(&[
        (&lid1.to_le_bytes(), true),
        (&lid2.to_le_bytes(), true),
        (&lid3.to_le_bytes(), true),
    ]);
    assert_eq!(&mv_all_sep[0..6], &[0x06, 0x80, 0x0E, 0x80, 0x16, 0x80]);

    // Row 1: mixed inline (7-bit Unicode) + 0x8000-separated (LID) + inline (raw UTF-16LE starting with '<')
    let mut inline_first = encode_ese_7bit_unicode(b"InlineFirst-5");
    inline_first[0] = 0x12;
    let inline_last = encode_utf16le_nul("<InlineLast-5>");
    let mv_mixed = encode_multi_value_payload_with_sep(&[
        (&inline_first, false),
        (&lid_mix.to_le_bytes(), true),
        (&inline_last, false),
    ]);
    assert_eq!(mv_mixed[0..2], [0x06, 0x00]);
    assert_eq!(mv_mixed[3], 0x80);
    assert_eq!(mv_mixed[5], 0x00);

    let r0 = build_record(
        &[(1, Some(&0i32.to_le_bytes()))],
        &[],
        &[(262, 0x08, &mv_all_sep)],
        true,
        true,
    );
    let r1 = build_record(
        &[(1, Some(&5i32.to_le_bytes()))],
        &[],
        &[(262, 0x0A, &mv_mixed)],
        true,
        true,
    );
    b.write_leaf_page(
        5,
        40,
        PageFlags::ROOT | PageFlags::LEAF | PageFlags::NEW_RECORD_FORMAT,
        0,
        0,
        &[],
        &[(0, 0, b"r0", &r0), (0, 0, b"r1", &r1)],
    );

    let db = EseDatabase::from_bytes(&b.build()).expect("mv sep db");
    let tbl = db.read_table("MvSepTable").expect("MvSepTable");
    assert_eq!(tbl.rows.len(), 2);

    let expected_r0 = format!(
        "{}-Tail0; <SepMV1-RawUtf16>; SepMV2-Wrapped01",
        "SepMV0-Repeated-".repeat(20)
    );
    assert_eq!(
        tbl.rows[0].values.get("MvSeparatedText"),
        Some(&EseValue::Text(expected_r0))
    );

    let expected_r1 = format!("InlineFirst-5; {}-End; <InlineLast-5>", "SepMiddle-5-".repeat(16));
    assert_eq!(
        tbl.rows[1].values.get("MvSeparatedText"),
        Some(&EseValue::Text(expected_r1))
    );
}

#[test]
fn uncompressed_lv_chunks_with_compression_magic_first_bytes_preserve_exact_bytes() {
    let mut b = SyntheticEseBuilder::new(16384);
    b.write_headers(3, 0x66BC);
    let space_flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::SPACE_TREE;
    b.write_leaf_page(2, 1, space_flags, 0, 0, &[], &[]);
    b.write_leaf_page(3, 1, space_flags, 0, 0, &[], &[]);

    let make_col = |tid: i32, cid: i32, ctyp: i32, sz: i32, flags: i32, name: &str| {
        build_record(
            &[
                (1, Some(&tid.to_le_bytes())),
                (2, Some(&2i16.to_le_bytes())),
                (3, Some(&cid.to_le_bytes())),
                (4, Some(&ctyp.to_le_bytes())),
                (5, Some(&sz.to_le_bytes())),
                (6, Some(&flags.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(name.as_bytes()))],
            &[],
            true,
            true,
        )
    };

    let msys_rows = [
        build_record(
            &[
                (1, Some(&1i32.to_le_bytes())),
                (2, Some(&1i16.to_le_bytes())),
                (3, Some(&50i32.to_le_bytes())),
                (4, Some(&5i32.to_le_bytes())),
                (5, Some(&0i32.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(b"LvSpanTable"))],
            &[],
            true,
            true,
        ),
        build_record(
            &[
                (1, Some(&50i32.to_le_bytes())),
                (2, Some(&4i16.to_le_bytes())),
                (3, Some(&4i32.to_le_bytes())),
                (4, Some(&6i32.to_le_bytes())),
                (5, Some(&0i32.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(b"LV"))],
            &[],
            true,
            true,
        ),
        make_col(50, 1, 4, 4, 0, "RowId"),
        // col.flags & 0x1000 (compressed), separated with tagged_compressed = false
        make_col(50, 256, 11, 0, 0x1000, "Blob"),
    ];
    let msys_tags: Vec<(u8, usize, &[u8], &[u8])> = msys_rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let k = Box::leak(format!("m{i:02}").into_bytes().into_boxed_slice());
            (0u8, 0usize, &*k, r.as_slice())
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

    // Build uncompressed single-chunk 8-byte LIDs starting with 0x01, 0x0A, 0x15, 0x38
    let make_blob = |lead: u8, len: usize| -> Vec<u8> {
        let mut v = vec![lead];
        for i in 1..len {
            v.push(((i * 37 + usize::from(lead)) & 0xFF) as u8);
        }
        v
    };
    let single_01 = make_blob(0x01, 300);
    let single_0a = make_blob(0x0A, 300);
    let single_15 = make_blob(0x15, 300);
    let single_38 = make_blob(0x38, 300);

    // Multi-chunk 8-byte LID: chunk 0 = 0x38-compressed (4050 bytes logical), chunk 1 = uncompressed 0x0A (358 bytes)
    let mc_p0 = vec![0x42u8; 4050];
    let mc_c0 = encode_ese_lz4(&mc_p0);
    assert!(mc_c0.len() < 4050);
    let mc_p1 = make_blob(0x0A, 358);
    let mut mc_expected = mc_p0.clone();
    mc_expected.extend_from_slice(&mc_p1);
    let mc_ul_size = mc_expected.len() as u32;

    // 0x01-wrapped chunk (`chunk.len() == ulSize + 1`)
    let wrapped_payload = make_blob(0x99, 250);
    let mut wrapped_chunk = vec![0x01u8];
    wrapped_chunk.extend_from_slice(&wrapped_payload);

    // 4-byte LID with 8-byte chunk data (key.len()==8, data.len()==8) to verify sizes_4 vs sizes_8 isolation
    let lid4: u32 = 100;
    let lid4_chunk = [0x15, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11];

    let lid_01: u64 = 1;
    let lid_0a: u64 = 2;
    let lid_15: u64 = 3;
    let lid_38: u64 = 4;
    let lid_mc: u64 = 5;
    let lid_wrap: u64 = 6;

    let lv_entries: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (lid_01.to_be_bytes().to_vec(), make_lv_root_value(1, 300).to_vec()),
        (make_lv_chunk_key_8(lid_01, 0).to_vec(), single_01.clone()),
        (lid_0a.to_be_bytes().to_vec(), make_lv_root_value(1, 300).to_vec()),
        (make_lv_chunk_key_8(lid_0a, 0).to_vec(), single_0a.clone()),
        (lid_15.to_be_bytes().to_vec(), make_lv_root_value(1, 300).to_vec()),
        (make_lv_chunk_key_8(lid_15, 0).to_vec(), single_15.clone()),
        (lid_38.to_be_bytes().to_vec(), make_lv_root_value(1, 300).to_vec()),
        (make_lv_chunk_key_8(lid_38, 0).to_vec(), single_38.clone()),
        (
            lid_mc.to_be_bytes().to_vec(),
            make_lv_root_value(1, mc_ul_size).to_vec(),
        ),
        (make_lv_chunk_key_8(lid_mc, 0).to_vec(), mc_c0),
        (make_lv_chunk_key_8(lid_mc, 4050).to_vec(), mc_p1),
        (lid_wrap.to_be_bytes().to_vec(), make_lv_root_value(1, 250).to_vec()),
        (make_lv_chunk_key_8(lid_wrap, 0).to_vec(), wrapped_chunk),
        // 4-byte LID root (ulSize = 8) + 8-byte chunk
        (lid4.to_be_bytes().to_vec(), make_lv_root_value(1, 8).to_vec()),
        (make_lv_chunk_key_4(lid4, 0).to_vec(), lid4_chunk.to_vec()),
    ];
    let lv_refs: Vec<(&[u8], &[u8])> = lv_entries.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect();
    b.write_raw_lv_page(6, 50, &lv_refs);

    let recs: Vec<Vec<u8>> = [
        (0i32, lid_01.to_le_bytes().as_slice()),
        (1, &lid_0a.to_le_bytes()),
        (2, &lid_15.to_le_bytes()),
        (3, &lid_38.to_le_bytes()),
        (4, &lid_mc.to_le_bytes()),
        (5, &lid_wrap.to_le_bytes()),
        (6, &lid4.to_le_bytes()),
    ]
    .iter()
    .map(|(rid, lid_b)| build_record(&[(1, Some(&rid.to_le_bytes()))], &[], &[(256, 0x04, lid_b)], true, true))
    .collect();
    let rec_tags: Vec<(u8, usize, &[u8], &[u8])> = recs
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let k = Box::leak(format!("r{i:02}").into_bytes().into_boxed_slice());
            (0u8, 0usize, &*k, r.as_slice())
        })
        .collect();
    b.write_leaf_page(
        5,
        50,
        PageFlags::ROOT | PageFlags::LEAF | PageFlags::NEW_RECORD_FORMAT,
        0,
        0,
        &[],
        &rec_tags,
    );

    let db = EseDatabase::from_bytes(&b.build()).expect("lv span db");
    let tbl = db.read_table("LvSpanTable").expect("LvSpanTable");
    assert_eq!(tbl.rows.len(), 7);
    assert_eq!(tbl.rows[0].values.get("Blob"), Some(&EseValue::Binary(single_01)));
    assert_eq!(tbl.rows[1].values.get("Blob"), Some(&EseValue::Binary(single_0a)));
    assert_eq!(tbl.rows[2].values.get("Blob"), Some(&EseValue::Binary(single_15)));
    assert_eq!(tbl.rows[3].values.get("Blob"), Some(&EseValue::Binary(single_38)));
    assert_eq!(tbl.rows[4].values.get("Blob"), Some(&EseValue::Binary(mc_expected)));
    assert_eq!(tbl.rows[5].values.get("Blob"), Some(&EseValue::Binary(wrapped_payload)));
    assert_eq!(
        tbl.rows[6].values.get("Blob"),
        Some(&EseValue::Binary(lid4_chunk.to_vec()))
    );
}

#[test]
fn malformed_0x8000_multi_value_and_missing_lid_warn_gracefully() {
    use std::collections::BTreeMap;

    use crate::ese::catalog::EseColumnSchema;
    use crate::ese::lv::LongValueIndex;
    use crate::ese::record::{ParsedRecord, TaggedField};
    use crate::ese::value::decode_column_value;

    let col = EseColumnSchema {
        id: 262,
        name: "MvSep".to_string(),
        col_type: JetColType::LongText,
        max_size: 0,
        flags: 0x1008,
        codepage: 1200,
        record_offset: None,
        is_derived: false,
    };
    let lv_index = LongValueIndex::empty();

    let bad_arrays: Vec<Vec<u8>> = vec![
        // Non-monotonic masked offsets: off0=4|0x8000, off1=2|0x8000
        vec![0x04, 0x80, 0x02, 0x80, 0x01, 0x00, 0x00, 0x00],
        // Out-of-bounds masked off1=0x0020|0x8000 > len=8
        vec![0x04, 0x80, 0x20, 0x80, 0x01, 0x00, 0x00, 0x00],
        // Out-of-bounds masked off0=0x0010|0x8000 > len=4
        vec![0x10, 0x80, 0x01, 0x00],
    ];
    for payload in bad_arrays {
        let rec = ParsedRecord {
            fixed: BTreeMap::new(),
            variable: BTreeMap::new(),
            tagged: vec![TaggedField {
                fid: 262,
                data: payload.clone(),
                is_compressed: false,
                is_separated: false,
                is_multi_value: true,
                is_two_values: false,
                is_null: false,
                is_derived: false,
            }],
        };
        let mut w = Vec::new();
        let val = decode_column_value(&col, &rec, &lv_index, &mut w).expect("bad 0x8000 array must not abort");
        assert_eq!(val, EseValue::Binary(payload));
        assert_eq!(w.len(), 1);
    }

    // Missing LID in a single 0x8000-separated element warns and preserves LID bytes
    let missing_lid = [0x99u8, 0x00, 0x00, 0x00];
    let single_sep_missing = encode_multi_value_payload_with_sep(&[(&missing_lid, true)]);
    let rec_missing = ParsedRecord {
        fixed: BTreeMap::new(),
        variable: BTreeMap::new(),
        tagged: vec![TaggedField {
            fid: 262,
            data: single_sep_missing,
            is_compressed: false,
            is_separated: false,
            is_multi_value: true,
            is_two_values: false,
            is_null: false,
            is_derived: false,
        }],
    };
    let mut mw = Vec::new();
    let mval = decode_column_value(&col, &rec_missing, &lv_index, &mut mw).expect("missing LID must not abort");
    assert_eq!(mval, EseValue::Binary(missing_lid.to_vec()));
    assert_eq!(mw.len(), 1);

    // Invalid LID length (2 bytes) in mixed inline + 0x8000-separated warns without losing inline element
    let inline_ok = encode_utf16le_nul("Ok");
    let bad_lid = [0xAAu8, 0xBB];
    let mixed_bad = encode_multi_value_payload_with_sep(&[(&inline_ok, false), (&bad_lid, true)]);
    let rec_mixed_bad = ParsedRecord {
        fixed: BTreeMap::new(),
        variable: BTreeMap::new(),
        tagged: vec![TaggedField {
            fid: 262,
            data: mixed_bad,
            is_compressed: false,
            is_separated: false,
            is_multi_value: true,
            is_two_values: false,
            is_null: false,
            is_derived: false,
        }],
    };
    let mut bw = Vec::new();
    let bval = decode_column_value(&col, &rec_mixed_bad, &lv_index, &mut bw).expect("bad LID len must not abort");
    assert_eq!(bval, EseValue::Text("Ok; 0xaabb".to_string()));
    assert_eq!(bw.len(), 1);

    // Single-char UTF-16LE "<\0" ([0x3C, 0x00, 0x00, 0x00]) in cp=1200 compressed MV must not be dropped
    let lt_nul = [0x3Cu8, 0x00, 0x00, 0x00];
    let a_nul = [0x41u8, 0x00, 0x00, 0x00];
    let mv_lt = encode_multi_value_payload(&[&lt_nul, &a_nul]);
    let rec_lt = ParsedRecord {
        fixed: BTreeMap::new(),
        variable: BTreeMap::new(),
        tagged: vec![TaggedField {
            fid: 262,
            data: mv_lt,
            is_compressed: true,
            is_separated: false,
            is_multi_value: true,
            is_two_values: false,
            is_null: false,
            is_derived: false,
        }],
    };
    let mut ltw = Vec::new();
    let lt_val = decode_column_value(&col, &rec_lt, &lv_index, &mut ltw).expect("lt_nul must not abort");
    assert_eq!(lt_val, EseValue::Text("<; A".to_string()));
    assert!(ltw.is_empty());
}

#[test]
fn large_32k_8byte_lid_high_word_does_not_collide_with_4byte_chunk_keys() {
    let mut b = SyntheticEseBuilder::new(32768);
    b.write_headers(3, 0x66BC);
    let space_flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::SPACE_TREE;
    b.write_leaf_page(2, 1, space_flags, 0, 0, &[], &[]);
    b.write_leaf_page(3, 1, space_flags, 0, 0, &[], &[]);

    let make_col = |tid: i32, cid: i32, ctyp: i32, sz: i32, flags: i32, name: &str| {
        build_record(
            &[
                (1, Some(&tid.to_le_bytes())),
                (2, Some(&2i16.to_le_bytes())),
                (3, Some(&cid.to_le_bytes())),
                (4, Some(&ctyp.to_le_bytes())),
                (5, Some(&sz.to_le_bytes())),
                (6, Some(&flags.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(name.as_bytes()))],
            &[],
            true,
            true,
        )
    };

    let msys_rows = [
        build_record(
            &[
                (1, Some(&1i32.to_le_bytes())),
                (2, Some(&1i16.to_le_bytes())),
                (3, Some(&60i32.to_le_bytes())),
                (4, Some(&5i32.to_le_bytes())),
                (5, Some(&0i32.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(b"Lv8CollisionTable"))],
            &[],
            true,
            true,
        ),
        build_record(
            &[
                (1, Some(&60i32.to_le_bytes())),
                (2, Some(&4i16.to_le_bytes())),
                (3, Some(&4i32.to_le_bytes())),
                (4, Some(&6i32.to_le_bytes())),
                (5, Some(&0i32.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(b"LV"))],
            &[],
            true,
            true,
        ),
        make_col(60, 1, 4, 4, 0, "RowId"),
        make_col(60, 256, 11, 0, 0, "Payload"),
    ];
    let msys_tags: Vec<(u8, usize, &[u8], &[u8])> = msys_rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let k = Box::leak(format!("m{i:02}").into_bytes().into_boxed_slice());
            (0u8, 0usize, &*k, r.as_slice())
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

    let lid_a: u64 = 1;
    let lid_b: u64 = 0x0000_0001_0000_0002;
    let payload_a = b"HELLO_LID_ONE_PAYLOAD_123456".to_vec();
    let payload_b = b"HIGH_WORD_LID_TWO_PAYLOAD_7890".to_vec();

    let lv_entries: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (
            lid_a.to_be_bytes().to_vec(),
            make_lv_root_value(1, payload_a.len() as u32).to_vec(),
        ),
        (make_lv_chunk_key_8(lid_a, 0).to_vec(), payload_a.clone()),
        (
            lid_b.to_be_bytes().to_vec(),
            make_lv_root_value(1, payload_b.len() as u32).to_vec(),
        ),
        (make_lv_chunk_key_8(lid_b, 0).to_vec(), payload_b.clone()),
    ];
    let lv_refs: Vec<(&[u8], &[u8])> = lv_entries.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect();
    b.write_raw_lv_page(6, 60, &lv_refs);

    let r0 = build_record(
        &[(1, Some(&0i32.to_le_bytes()))],
        &[],
        &[(256, 0x04, &lid_a.to_le_bytes())],
        true,
        true,
    );
    let r1 = build_record(
        &[(1, Some(&1i32.to_le_bytes()))],
        &[],
        &[(256, 0x04, &lid_b.to_le_bytes())],
        true,
        true,
    );
    b.write_leaf_page(
        5,
        60,
        PageFlags::ROOT | PageFlags::LEAF | PageFlags::NEW_RECORD_FORMAT,
        0,
        0,
        &[],
        &[(0, 0, b"r0", &r0), (0, 0, b"r1", &r1)],
    );

    let db = EseDatabase::from_bytes(&b.build()).expect("32KiB LV collision db");
    assert_eq!(db.header().page_size, 32768);
    assert_eq!(db.header().page_format, PageFormat::Large);

    let tbl = db.read_table("Lv8CollisionTable").expect("Lv8CollisionTable");
    assert_eq!(tbl.rows.len(), 2);
    assert_eq!(tbl.rows[0].values.get("Payload"), Some(&EseValue::Binary(payload_a)));
    assert_eq!(tbl.rows[1].values.get("Payload"), Some(&EseValue::Binary(payload_b)));
}

fn capture_tracing_warnings<R>(f: impl FnOnce() -> R) -> (R, Vec<String>) {
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Level, Metadata, Subscriber};

    struct MsgVisitor(String);
    impl Visit for MsgVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{value:?}");
            }
        }
        fn record_str(&mut self, field: &Field, value: &str) {
            if field.name() == "message" {
                self.0 = value.to_string();
            }
        }
    }

    struct WarnCollector(Arc<Mutex<Vec<String>>>);
    impl Subscriber for WarnCollector {
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            metadata.level() <= &Level::WARN
        }
        fn new_span(&self, _span: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _span: &Id, _values: &Record<'_>) {}
        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
        fn event(&self, event: &Event<'_>) {
            if event.metadata().level() == &Level::WARN {
                let mut v = MsgVisitor(String::new());
                event.record(&mut v);
                self.0.lock().expect("lock").push(v.0);
            }
        }
        fn enter(&self, _span: &Id) {}
        fn exit(&self, _span: &Id) {}
    }

    let msgs = Arc::new(Mutex::new(Vec::new()));
    let subscriber = WarnCollector(Arc::clone(&msgs));
    let res = tracing::subscriber::with_default(subscriber, f);
    let captured = msgs.lock().expect("lock").clone();
    (res, captured)
}

#[test]
fn inline_multivalue_longbinary_decompression_gating() {
    let mut b = SyntheticEseBuilder::new(16384);
    b.write_headers(3, 0x66BC);
    let space_flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::SPACE_TREE;
    b.write_leaf_page(2, 1, space_flags, 0, 0, &[], &[]);
    b.write_leaf_page(3, 1, space_flags, 0, 0, &[], &[]);

    let make_col = |tid: i32, cid: i32, ctyp: i32, sz: i32, flags: i32, cp: i32, name: &str| {
        build_record(
            &[
                (1, Some(&tid.to_le_bytes())),
                (2, Some(&2i16.to_le_bytes())),
                (3, Some(&cid.to_le_bytes())),
                (4, Some(&ctyp.to_le_bytes())),
                (5, Some(&sz.to_le_bytes())),
                (6, Some(&flags.to_le_bytes())),
                (7, Some(&cp.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(name.as_bytes()))],
            &[],
            true,
            true,
        )
    };

    let msys_rows = [
        build_record(
            &[
                (1, Some(&1i32.to_le_bytes())),
                (2, Some(&1i16.to_le_bytes())),
                (3, Some(&70i32.to_le_bytes())),
                (4, Some(&5i32.to_le_bytes())),
                (5, Some(&0i32.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(b"tbFiles"))],
            &[],
            true,
            true,
        ),
        make_col(70, 1, 4, 4, 0, 0, "RowId"),
        // fid=260 LongBinary flags=0x1008 (Compressed | MultiValued)
        make_col(70, 260, 11, 0, 0x1008, 0, "Urls"),
    ];
    let msys_tags: Vec<(u8, usize, &[u8], &[u8])> = msys_rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let k = Box::leak(format!("f{i:02}").into_bytes().into_boxed_slice());
            (0u8, 0usize, &*k, r.as_slice())
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

    // Row 0: tagged.is_compressed == false (TAGFLD 0x08) with elements starting with 0x18 (XPRESS-like) and 0x01
    let r0_e0 = [0xB4u8, 0xF4, 0x82, 0x11, 0x22];
    let r0_e1 = [0x18u8, 0xF9, 0x71, 0x79, 0xAA, 0xBB, 0xCC];
    let r0_e2 = [0x01u8, 0xAA, 0xBB, 0xCC, 0xDD];
    let r0_e3 = [0x0Fu8, 0xC1, 0x60, 0x30, 0x18];
    let r0_mv = encode_multi_value_payload(&[&r0_e0, &r0_e1, &r0_e2, &r0_e3]);
    let rec0 = build_record(
        &[(1, Some(&0i32.to_le_bytes()))],
        &[],
        &[(260, 0x08, &r0_mv)],
        true,
        true,
    );

    // Row 1: tagged.is_compressed == true (TAGFLD 0x0A), elem[0] compressed (7-bit ASCII), elem[1+] start with 0x01 and 0x0F
    let r1_plain0 = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let r1_e0 = encode_ese_7bit_ascii(r1_plain0);
    let r1_e1 = [0x01u8, 0xAA, 0xBB, 0xCC, 0xDD];
    let r1_e2 = [0x0Fu8, 0xC1, 0x60, 0x30, 0x18, 0x0C, 0x06, 0x83];
    let r1_e3 = [0x18u8, 0x80, 0x00, 0x00, 0x00];
    let r1_mv = encode_multi_value_payload(&[&r1_e0, &r1_e1, &r1_e2, &r1_e3]);
    let rec1 = build_record(
        &[(1, Some(&1i32.to_le_bytes()))],
        &[],
        &[(260, 0x0A, &r1_mv)],
        true,
        true,
    );

    // Row 2: tagged.is_compressed == true (TAGFLD 0x0A), elem[0] LZ4 (0x38), elem[1] starts with 0x38
    let r2_plain0 = b"RepeatedPayload_RepeatedPayload_RepeatedPayload";
    let r2_e0 = encode_ese_lz4(r2_plain0);
    let r2_e1 = [0x38u8, 0x05, 0x00, 0x10, 0xFF];
    let r2_mv = encode_multi_value_payload(&[&r2_e0, &r2_e1]);
    let rec2 = build_record(
        &[(1, Some(&2i32.to_le_bytes()))],
        &[],
        &[(260, 0x0A, &r2_mv)],
        true,
        true,
    );

    b.write_leaf_page(
        5,
        70,
        PageFlags::ROOT | PageFlags::LEAF | PageFlags::NEW_RECORD_FORMAT,
        0,
        0,
        &[],
        &[(0, 0, b"r0", &rec0), (0, 0, b"r1", &rec1), (0, 0, b"r2", &rec2)],
    );

    let db = EseDatabase::from_bytes(&b.build()).expect("tbFiles db");
    let (tbl_res, warns) = capture_tracing_warnings(|| db.read_table("tbFiles"));
    let tbl = tbl_res.expect("read tbFiles");
    assert!(warns.is_empty(), "expected 0 warnings, got: {warns:?}");
    assert_eq!(tbl.rows.len(), 3);

    let expected_r0 = format!(
        "{}; {}; {}; {}",
        EseValue::Binary(r0_e0.to_vec()).display_compact(),
        EseValue::Binary(r0_e1.to_vec()).display_compact(),
        EseValue::Binary(r0_e2.to_vec()).display_compact(),
        EseValue::Binary(r0_e3.to_vec()).display_compact(),
    );
    assert_eq!(tbl.rows[0].values.get("Urls"), Some(&EseValue::Text(expected_r0)));

    let expected_r1 = format!(
        "{}; {}; {}; {}",
        EseValue::Binary(r1_plain0.to_vec()).display_compact(),
        EseValue::Binary(r1_e1.to_vec()).display_compact(),
        EseValue::Binary(r1_e2.to_vec()).display_compact(),
        EseValue::Binary(r1_e3.to_vec()).display_compact(),
    );
    assert_eq!(tbl.rows[1].values.get("Urls"), Some(&EseValue::Text(expected_r1)));

    let expected_r2 = format!(
        "{}; {}",
        EseValue::Binary(r2_plain0.to_vec()).display_compact(),
        EseValue::Binary(r2_e1.to_vec()).display_compact(),
    );
    assert_eq!(tbl.rows[2].values.get("Urls"), Some(&EseValue::Text(expected_r2)));
}

#[test]
fn twovalues_0x10_decompression_gating_matches_esent() {
    let mut b = SyntheticEseBuilder::new(16384);
    b.write_headers(3, 0x66BC);
    let space_flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::SPACE_TREE;
    b.write_leaf_page(2, 1, space_flags, 0, 0, &[], &[]);
    b.write_leaf_page(3, 1, space_flags, 0, 0, &[], &[]);

    let make_col = |tid: i32, cid: i32, ctyp: i32, sz: i32, flags: i32, cp: i32, name: &str| {
        build_record(
            &[
                (1, Some(&tid.to_le_bytes())),
                (2, Some(&2i16.to_le_bytes())),
                (3, Some(&cid.to_le_bytes())),
                (4, Some(&ctyp.to_le_bytes())),
                (5, Some(&sz.to_le_bytes())),
                (6, Some(&flags.to_le_bytes())),
                (7, Some(&cp.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(name.as_bytes()))],
            &[],
            true,
            true,
        )
    };

    let msys_rows = [
        build_record(
            &[
                (1, Some(&1i32.to_le_bytes())),
                (2, Some(&1i16.to_le_bytes())),
                (3, Some(&80i32.to_le_bytes())),
                (4, Some(&5i32.to_le_bytes())),
                (5, Some(&0i32.to_le_bytes())),
                (6, Some(&0i32.to_le_bytes())),
                (7, Some(&0i32.to_le_bytes())),
                (8, Some(&[0u8])),
                (9, Some(&0i16.to_le_bytes())),
                (10, Some(&0i32.to_le_bytes())),
                (11, Some(&0u16.to_le_bytes())),
            ],
            &[(128, Some(b"TwoValTbl"))],
            &[],
            true,
            true,
        ),
        make_col(80, 1, 4, 4, 0, 0, "RowId"),
        make_col(80, 256, 9, 255, 0x08, 0, "TwoBin"),
        make_col(80, 257, 10, 255, 0x08, 1200, "TwoTxt"),
        make_col(80, 258, 11, 0, 0x1008, 0, "TwoCompBin"),
    ];
    let msys_tags: Vec<(u8, usize, &[u8], &[u8])> = msys_rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let k = Box::leak(format!("v{i:02}").into_bytes().into_boxed_slice());
            (0u8, 0usize, &*k, r.as_slice())
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

    let encode_two = |a: &[u8], b_val: &[u8]| -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + a.len() + b_val.len());
        out.push(a.len() as u8);
        out.extend_from_slice(a);
        out.extend_from_slice(b_val);
        out
    };

    let bin_a = [0x01u8, 0xAA, 0xBB];
    let bin_b = [0x18u8, 0xF9, 0x71, 0x79];
    let tv_bin = encode_two(&bin_a, &bin_b);

    let txt_a = [0x41u8, 0x00]; // "A"
    let txt_b = [0x01u8, 0x00, 0x42, 0x00]; // "\u{0001}B"
    let tv_txt = encode_two(&txt_a, &txt_b);

    let comp_plain = b"HelloTwoValues";
    let comp_a = encode_ese_7bit_ascii(comp_plain);
    let comp_b = [0x01u8, 0xDE, 0xAD, 0xBE, 0xEF];
    let tv_comp = encode_two(&comp_a, &comp_b);

    let rec = build_record(
        &[(1, Some(&1i32.to_le_bytes()))],
        &[],
        &[(256, 0x18, &tv_bin), (257, 0x18, &tv_txt), (258, 0x1A, &tv_comp)],
        true,
        true,
    );
    b.write_leaf_page(
        5,
        80,
        PageFlags::ROOT | PageFlags::LEAF | PageFlags::NEW_RECORD_FORMAT,
        0,
        0,
        &[],
        &[(0, 0, b"r0", &rec)],
    );

    let db = EseDatabase::from_bytes(&b.build()).expect("TwoValTbl db");
    let (tbl_res, warns) = capture_tracing_warnings(|| db.read_table("TwoValTbl"));
    let tbl = tbl_res.expect("read TwoValTbl");
    assert!(warns.is_empty(), "expected 0 warnings, got: {warns:?}");
    assert_eq!(tbl.rows.len(), 1);

    let r = &tbl.rows[0].values;
    assert_eq!(
        r.get("TwoBin"),
        Some(&EseValue::Text(format!(
            "{}; {}",
            EseValue::Binary(bin_a.to_vec()).display_compact(),
            EseValue::Binary(bin_b.to_vec()).display_compact(),
        )))
    );
    assert_eq!(r.get("TwoTxt"), Some(&EseValue::Text("A; \u{0001}B".to_string())));
    assert_eq!(
        r.get("TwoCompBin"),
        Some(&EseValue::Text(format!(
            "{}; {}",
            EseValue::Binary(comp_plain.to_vec()).display_compact(),
            EseValue::Binary(comp_b.to_vec()).display_compact(),
        )))
    );
}

#[test]
fn versioned_single_zero_byte_tombstone_skipped_cleanly_while_corrupt_warns() {
    use crate::ese::page::TagFlags;

    for page_size in [4096u32, 16384u32] {
        let large = page_size >= 16384;
        let mut b = SyntheticEseBuilder::new(page_size);
        b.write_headers(3, if large { 0x66BC } else { 0x17 });
        let space_flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::SPACE_TREE;
        b.write_leaf_page(2, 1, space_flags, 0, 0, &[], &[]);
        b.write_leaf_page(3, 1, space_flags, 0, 0, &[], &[]);

        let msys_rows = [
            build_record(
                &[
                    (1, Some(&1i32.to_le_bytes())),
                    (2, Some(&1i16.to_le_bytes())),
                    (3, Some(&90i32.to_le_bytes())),
                    (4, Some(&5i32.to_le_bytes())),
                    (5, Some(&0i32.to_le_bytes())),
                    (6, Some(&0i32.to_le_bytes())),
                    (7, Some(&0i32.to_le_bytes())),
                    (8, Some(&[0u8])),
                    (9, Some(&0i16.to_le_bytes())),
                    (10, Some(&0i32.to_le_bytes())),
                    (11, Some(&0u16.to_le_bytes())),
                ],
                &[(128, Some(b"TombstoneTbl"))],
                &[],
                large,
                true,
            ),
            build_record(
                &[
                    (1, Some(&90i32.to_le_bytes())),
                    (2, Some(&2i16.to_le_bytes())),
                    (3, Some(&1i32.to_le_bytes())),
                    (4, Some(&4i32.to_le_bytes())),
                    (5, Some(&4i32.to_le_bytes())),
                    (6, Some(&0i32.to_le_bytes())),
                    (7, Some(&0i32.to_le_bytes())),
                    (8, Some(&[0u8])),
                    (9, Some(&0i16.to_le_bytes())),
                    (10, Some(&0i32.to_le_bytes())),
                    (11, Some(&0u16.to_le_bytes())),
                ],
                &[(128, Some(b"RowId"))],
                &[],
                large,
                true,
            ),
            // Second table with ONLY valid row + versioned [0x00] tombstone -> 0 warnings
            build_record(
                &[
                    (1, Some(&1i32.to_le_bytes())),
                    (2, Some(&1i16.to_le_bytes())),
                    (3, Some(&91i32.to_le_bytes())),
                    (4, Some(&6i32.to_le_bytes())),
                    (5, Some(&0i32.to_le_bytes())),
                    (6, Some(&0i32.to_le_bytes())),
                    (7, Some(&0i32.to_le_bytes())),
                    (8, Some(&[0u8])),
                    (9, Some(&0i16.to_le_bytes())),
                    (10, Some(&0i32.to_le_bytes())),
                    (11, Some(&0u16.to_le_bytes())),
                ],
                &[(128, Some(b"CleanTombstoneTbl"))],
                &[],
                large,
                true,
            ),
            build_record(
                &[
                    (1, Some(&91i32.to_le_bytes())),
                    (2, Some(&2i16.to_le_bytes())),
                    (3, Some(&1i32.to_le_bytes())),
                    (4, Some(&4i32.to_le_bytes())),
                    (5, Some(&4i32.to_le_bytes())),
                    (6, Some(&0i32.to_le_bytes())),
                    (7, Some(&0i32.to_le_bytes())),
                    (8, Some(&[0u8])),
                    (9, Some(&0i16.to_le_bytes())),
                    (10, Some(&0i32.to_le_bytes())),
                    (11, Some(&0u16.to_le_bytes())),
                ],
                &[(128, Some(b"RowId"))],
                &[],
                large,
                true,
            ),
        ];
        let msys_tags: Vec<(u8, usize, &[u8], &[u8])> = msys_rows
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let k = Box::leak(format!("t{i:02}").into_bytes().into_boxed_slice());
                (0u8, 0usize, &*k, r.as_slice())
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

        let valid_rec = build_record(&[(1, Some(&42i32.to_le_bytes()))], &[], &[], large, true);
        let ver_flags = TagFlags::VERSION | TagFlags::DERIVED;
        b.write_leaf_page(
            5,
            90,
            PageFlags::ROOT | PageFlags::LEAF | PageFlags::NEW_RECORD_FORMAT,
            0,
            0,
            &[],
            &[
                (ver_flags, 0, b"del0", &[0x00]),
                (0, 0, b"bad1", &[0xDE, 0xAD]),
                (0, 0, b"ok2", &valid_rec),
            ],
        );
        b.write_leaf_page(
            6,
            91,
            PageFlags::ROOT | PageFlags::LEAF | PageFlags::NEW_RECORD_FORMAT,
            0,
            0,
            &[],
            &[(ver_flags, 0, b"del0", &[0x00]), (0, 0, b"ok1", &valid_rec)],
        );

        let db = EseDatabase::from_bytes(&b.build()).expect("tombstone db");

        let (tbl_res, warns) = capture_tracing_warnings(|| db.read_table("TombstoneTbl"));
        let tbl = tbl_res.expect("read TombstoneTbl");
        assert_eq!(tbl.rows.len(), 1);
        assert_eq!(tbl.rows[0].values.get("RowId"), Some(&EseValue::I32(42)));
        assert_eq!(
            warns.len(),
            1,
            "expected exactly 1 warning for non-versioned corrupt record at page_size={page_size}, got: {warns:?}"
        );
        assert!(warns[0].contains("skipping malformed record"));

        let (clean_res, clean_warns) = capture_tracing_warnings(|| db.read_table("CleanTombstoneTbl"));
        let clean_tbl = clean_res.expect("read CleanTombstoneTbl");
        assert_eq!(clean_tbl.rows.len(), 1);
        assert_eq!(clean_tbl.rows[0].values.get("RowId"), Some(&EseValue::I32(42)));
        assert!(
            clean_warns.is_empty(),
            "expected 0 warnings on CleanTombstoneTbl at page_size={page_size}, got: {clean_warns:?}"
        );
    }
}

#[test]
fn mixed_4byte_and_8byte_lid_with_8byte_chunk_and_collision_resolves_exact() {
    for page_size in [4096u32, 8192u32, 32768u32] {
        let large = page_size >= 16384;
        let mut b = SyntheticEseBuilder::new(page_size);
        b.write_headers(3, if large { 0x66BC } else { 0x17 });
        let space_flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::SPACE_TREE;
        b.write_leaf_page(2, 1, space_flags, 0, 0, &[], &[]);
        b.write_leaf_page(3, 1, space_flags, 0, 0, &[], &[]);

        let make_col = |tid: i32, cid: i32, ctyp: i32, sz: i32, flags: i32, name: &str| {
            build_record(
                &[
                    (1, Some(&tid.to_le_bytes())),
                    (2, Some(&2i16.to_le_bytes())),
                    (3, Some(&cid.to_le_bytes())),
                    (4, Some(&ctyp.to_le_bytes())),
                    (5, Some(&sz.to_le_bytes())),
                    (6, Some(&flags.to_le_bytes())),
                    (7, Some(&0i32.to_le_bytes())),
                    (8, Some(&[0u8])),
                    (9, Some(&0i16.to_le_bytes())),
                    (10, Some(&0i32.to_le_bytes())),
                    (11, Some(&0u16.to_le_bytes())),
                ],
                &[(128, Some(name.as_bytes()))],
                &[],
                large,
                true,
            )
        };

        let msys_rows = [
            build_record(
                &[
                    (1, Some(&1i32.to_le_bytes())),
                    (2, Some(&1i16.to_le_bytes())),
                    (3, Some(&61i32.to_le_bytes())),
                    (4, Some(&5i32.to_le_bytes())),
                    (5, Some(&0i32.to_le_bytes())),
                    (6, Some(&0i32.to_le_bytes())),
                    (7, Some(&0i32.to_le_bytes())),
                    (8, Some(&[0u8])),
                    (9, Some(&0i16.to_le_bytes())),
                    (10, Some(&0i32.to_le_bytes())),
                    (11, Some(&0u16.to_le_bytes())),
                ],
                &[(128, Some(b"MixedLvTbl"))],
                &[],
                large,
                true,
            ),
            build_record(
                &[
                    (1, Some(&61i32.to_le_bytes())),
                    (2, Some(&4i16.to_le_bytes())),
                    (3, Some(&4i32.to_le_bytes())),
                    (4, Some(&6i32.to_le_bytes())),
                    (5, Some(&0i32.to_le_bytes())),
                    (6, Some(&0i32.to_le_bytes())),
                    (7, Some(&0i32.to_le_bytes())),
                    (8, Some(&[0u8])),
                    (9, Some(&0i16.to_le_bytes())),
                    (10, Some(&0i32.to_le_bytes())),
                    (11, Some(&0u16.to_le_bytes())),
                ],
                &[(128, Some(b"LV"))],
                &[],
                large,
                true,
            ),
            make_col(61, 1, 4, 4, 0, "RowId"),
            // flags = 0x1000 (Compressed) to verify ul_size is preserved for both 4B and 8B LIDs
            make_col(61, 256, 11, 0, 0x1000, "Payload"),
        ];
        let msys_tags: Vec<(u8, usize, &[u8], &[u8])> = msys_rows
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let k = Box::leak(format!("m{i:02}").into_bytes().into_boxed_slice());
                (0u8, 0usize, &*k, r.as_slice())
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

        let lid4_a: u32 = 1;
        let payload_4a = b"FOUR_BYTE_LID_ONE_PAYLOAD_EXACT_LEN".to_vec();

        // High 32 bits of lid8 collide with lid4_a = 1
        let lid8: u64 = 0x0000_0001_0000_0002;
        let payload_8 = b"HIGH_WORD_LID_EIGHT_PAYLOAD_EXACT_38".to_vec();

        // 4-byte LID whose chunk payload is exactly 8 bytes long (must stay in chunks_4, not sizes_8)
        let lid4_b: u32 = 2;
        let payload_4b = vec![0x18u8, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x42];

        let lv_entries: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (
                lid4_a.to_be_bytes().to_vec(),
                make_lv_root_value(1, payload_4a.len() as u32).to_vec(),
            ),
            (make_lv_chunk_key_4(lid4_a, 0).to_vec(), payload_4a.clone()),
            (
                lid8.to_be_bytes().to_vec(),
                make_lv_root_value(1, payload_8.len() as u32).to_vec(),
            ),
            (make_lv_chunk_key_8(lid8, 0).to_vec(), payload_8.clone()),
            (
                lid4_b.to_be_bytes().to_vec(),
                make_lv_root_value(1, payload_4b.len() as u32).to_vec(),
            ),
            (make_lv_chunk_key_4(lid4_b, 0).to_vec(), payload_4b.clone()),
        ];
        let lv_refs: Vec<(&[u8], &[u8])> = lv_entries.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect();
        b.write_raw_lv_page(6, 61, &lv_refs);

        let r0 = build_record(
            &[(1, Some(&0i32.to_le_bytes()))],
            &[],
            &[(256, 0x04, &lid4_a.to_le_bytes())],
            large,
            true,
        );
        let r1 = build_record(
            &[(1, Some(&1i32.to_le_bytes()))],
            &[],
            &[(256, 0x04, &lid8.to_le_bytes())],
            large,
            true,
        );
        let r2 = build_record(
            &[(1, Some(&2i32.to_le_bytes()))],
            &[],
            &[(256, 0x04, &lid4_b.to_le_bytes())],
            large,
            true,
        );
        b.write_leaf_page(
            5,
            61,
            PageFlags::ROOT | PageFlags::LEAF | PageFlags::NEW_RECORD_FORMAT,
            0,
            0,
            &[],
            &[(0, 0, b"r0", &r0), (0, 0, b"r1", &r1), (0, 0, b"r2", &r2)],
        );

        let db = EseDatabase::from_bytes(&b.build()).expect("mixed LV db");
        let (tbl_res, warns) = capture_tracing_warnings(|| db.read_table("MixedLvTbl"));
        let tbl = tbl_res.expect("MixedLvTbl");
        assert!(
            warns.is_empty(),
            "expected 0 warnings on MixedLvTbl at page_size={page_size}, got: {warns:?}"
        );
        assert_eq!(tbl.rows.len(), 3);
        assert_eq!(tbl.rows[0].values.get("Payload"), Some(&EseValue::Binary(payload_4a)));
        assert_eq!(tbl.rows[1].values.get("Payload"), Some(&EseValue::Binary(payload_8)));
        assert_eq!(tbl.rows[2].values.get("Payload"), Some(&EseValue::Binary(payload_4b)));
    }
}

#[test]
fn lv_versioned_single_zero_byte_tombstone_skipped_cleanly() {
    use crate::ese::page::TagFlags;

    for page_size in [4096u32, 32768u32] {
        let large = page_size >= 16384;
        let mut b = SyntheticEseBuilder::new(page_size);
        b.write_headers(3, if large { 0x66BC } else { 0x17 });
        let space_flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::SPACE_TREE;
        b.write_leaf_page(2, 1, space_flags, 0, 0, &[], &[]);
        b.write_leaf_page(3, 1, space_flags, 0, 0, &[], &[]);

        let make_col = |tid: i32, cid: i32, ctyp: i32, sz: i32, flags: i32, name: &str| {
            build_record(
                &[
                    (1, Some(&tid.to_le_bytes())),
                    (2, Some(&2i16.to_le_bytes())),
                    (3, Some(&cid.to_le_bytes())),
                    (4, Some(&ctyp.to_le_bytes())),
                    (5, Some(&sz.to_le_bytes())),
                    (6, Some(&flags.to_le_bytes())),
                    (7, Some(&0i32.to_le_bytes())),
                    (8, Some(&[0u8])),
                    (9, Some(&0i16.to_le_bytes())),
                    (10, Some(&0i32.to_le_bytes())),
                    (11, Some(&0u16.to_le_bytes())),
                ],
                &[(128, Some(name.as_bytes()))],
                &[],
                large,
                true,
            )
        };

        let msys_rows = [
            build_record(
                &[
                    (1, Some(&1i32.to_le_bytes())),
                    (2, Some(&1i16.to_le_bytes())),
                    (3, Some(&62i32.to_le_bytes())),
                    (4, Some(&5i32.to_le_bytes())),
                    (5, Some(&0i32.to_le_bytes())),
                    (6, Some(&0i32.to_le_bytes())),
                    (7, Some(&0i32.to_le_bytes())),
                    (8, Some(&[0u8])),
                    (9, Some(&0i16.to_le_bytes())),
                    (10, Some(&0i32.to_le_bytes())),
                    (11, Some(&0u16.to_le_bytes())),
                ],
                &[(128, Some(b"LvTombstoneTbl"))],
                &[],
                large,
                true,
            ),
            build_record(
                &[
                    (1, Some(&62i32.to_le_bytes())),
                    (2, Some(&4i16.to_le_bytes())),
                    (3, Some(&4i32.to_le_bytes())),
                    (4, Some(&6i32.to_le_bytes())),
                    (5, Some(&0i32.to_le_bytes())),
                    (6, Some(&0i32.to_le_bytes())),
                    (7, Some(&0i32.to_le_bytes())),
                    (8, Some(&[0u8])),
                    (9, Some(&0i16.to_le_bytes())),
                    (10, Some(&0i32.to_le_bytes())),
                    (11, Some(&0u16.to_le_bytes())),
                ],
                &[(128, Some(b"LV"))],
                &[],
                large,
                true,
            ),
            make_col(62, 1, 4, 4, 0, "RowId"),
            make_col(62, 256, 11, 0, 0, "Payload"),
        ];
        let msys_tags: Vec<(u8, usize, &[u8], &[u8])> = msys_rows
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let k = Box::leak(format!("t{i:02}").into_bytes().into_boxed_slice());
                (0u8, 0usize, &*k, r.as_slice())
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

        let lid4: u32 = 1;
        let payload_4 = b"LV_TOMBSTONE_4B_EXACT".to_vec();
        let lid8: u64 = 0x0000_0002_0000_0003;
        let payload_8 = b"LV_TOMBSTONE_8B_EXACT".to_vec();
        let lid4_zero: u32 = 3;
        let payload_zero = vec![0x00u8];

        let k_r4 = lid4.to_be_bytes().to_vec();
        let v_r4 = make_lv_root_value(1, payload_4.len() as u32).to_vec();
        let k_c4 = make_lv_chunk_key_4(lid4, 0).to_vec();
        let k_t4 = make_lv_chunk_key_4(lid4, 100).to_vec();

        let k_r8 = lid8.to_be_bytes().to_vec();
        let v_r8 = make_lv_root_value(1, payload_8.len() as u32).to_vec();
        let k_c8 = make_lv_chunk_key_8(lid8, 0).to_vec();
        let k_t8 = make_lv_chunk_key_8(lid8, 200).to_vec();

        let k_rz = lid4_zero.to_be_bytes().to_vec();
        let v_rz = make_lv_root_value(1, 1).to_vec();
        let k_cz = make_lv_chunk_key_4(lid4_zero, 0).to_vec();

        let ver_flags = TagFlags::VERSION | TagFlags::DERIVED;
        let tombstone = [0x00u8];
        let lv_records: Vec<(u8, usize, &[u8], &[u8])> = vec![
            (0, 0, &k_r4, &v_r4),
            (0, 0, &k_c4, &payload_4),
            (ver_flags, 0, &k_t4, &tombstone),
            (0, 0, &k_r8, &v_r8),
            (0, 0, &k_c8, &payload_8),
            (TagFlags::VERSION, 0, &k_t8, &tombstone),
            (0, 0, &k_rz, &v_rz),
            (0, 0, &k_cz, &payload_zero),
        ];
        b.write_leaf_page(
            6,
            62,
            PageFlags::ROOT | PageFlags::LEAF | PageFlags::LONG_VALUE | PageFlags::NEW_RECORD_FORMAT,
            0,
            0,
            &[],
            &lv_records,
        );

        let r0 = build_record(
            &[(1, Some(&0i32.to_le_bytes()))],
            &[],
            &[(256, 0x04, &lid4.to_le_bytes())],
            large,
            true,
        );
        let r1 = build_record(
            &[(1, Some(&1i32.to_le_bytes()))],
            &[],
            &[(256, 0x04, &lid8.to_le_bytes())],
            large,
            true,
        );
        let r2 = build_record(
            &[(1, Some(&2i32.to_le_bytes()))],
            &[],
            &[(256, 0x04, &lid4_zero.to_le_bytes())],
            large,
            true,
        );
        b.write_leaf_page(
            5,
            62,
            PageFlags::ROOT | PageFlags::LEAF | PageFlags::NEW_RECORD_FORMAT,
            0,
            0,
            &[],
            &[(0, 0, b"r0", &r0), (0, 0, b"r1", &r1), (0, 0, b"r2", &r2)],
        );

        let db = EseDatabase::from_bytes(&b.build()).expect("LV tombstone db");
        let (tbl_res, warns) = capture_tracing_warnings(|| db.read_table("LvTombstoneTbl"));
        let tbl = tbl_res.expect("LvTombstoneTbl");
        assert!(
            warns.is_empty(),
            "expected 0 warnings on LvTombstoneTbl at page_size={page_size}, got: {warns:?}"
        );
        assert_eq!(tbl.rows.len(), 3);
        assert_eq!(tbl.rows[0].values.get("Payload"), Some(&EseValue::Binary(payload_4)));
        assert_eq!(tbl.rows[1].values.get("Payload"), Some(&EseValue::Binary(payload_8)));
        assert_eq!(tbl.rows[2].values.get("Payload"), Some(&EseValue::Binary(payload_zero)));
    }
}
