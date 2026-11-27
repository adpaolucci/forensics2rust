use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{TimeZone, Utc};
use guap_table::{
    CellValue, ColumnDef, ColumnType, InMemoryTableProvider, Row, SortDirection, TableError, TableProvider, TableSchema,
};

use crate::{
    DiagnosticWarning, FORENSIC_TOOL_CATALOG, ForensicError, ForensicSource, QueryHelper, ToolCategory,
    WarningSeverity, all_tool_ids, bytes_to_hex_lower, crc32_ieee, filetime_to_utc, find_by_subcommand, find_tool,
    init_logging, is_elevation_error, ole_automation_date_to_utc, parse_guid_le, parse_guid_le_braced, parse_sid,
    read_utf16_le, read_utf16_le_nul, rot13, tools_by_category, try_read_utf16_le, utc_to_filetime,
};

// --- FILETIME & OLE Automation Date Tests ---

#[test]
fn filetime_zero_is_none() {
    assert_eq!(filetime_to_utc(0), None);
}

#[test]
fn filetime_unix_epoch() {
    let dt = filetime_to_utc(116_444_736_000_000_000).expect("unix epoch must decode");
    assert_eq!(dt, Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap());
}

#[test]
fn filetime_pre_1970_and_1601_min() {
    let min_dt = filetime_to_utc(1).expect("ft=1 must decode to 1601-01-01 + 100ns");
    assert_eq!(min_dt.format("%Y-%m-%dT%H:%M:%S").to_string(), "1601-01-01T00:00:00");
    assert_eq!(min_dt.timestamp_subsec_nanos(), 100);

    let almost_epoch = filetime_to_utc(116_444_735_999_999_999).expect("pre-1970 100ns tick must decode");
    assert_eq!(
        almost_epoch.format("%Y-%m-%dT%H:%M:%S").to_string(),
        "1969-12-31T23:59:59"
    );
    assert_eq!(almost_epoch.timestamp_subsec_nanos(), 999_999_900);

    let sec_before = filetime_to_utc(116_444_735_990_000_000).expect("1969-12-31T23:59:59Z must decode");
    assert_eq!(sec_before, Utc.with_ymd_and_hms(1969, 12, 31, 23, 59, 59).unwrap());
}

#[test]
fn filetime_modern_and_roundtrip() {
    let raw = 134_391_767_387_395_160u64;
    let dt = filetime_to_utc(raw).expect("modern FILETIME must decode");
    assert_eq!(
        dt.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string(),
        "2026-11-15T00:38:58.739516Z"
    );
    assert_eq!(utc_to_filetime(dt), Some(raw));

    let before_1601 = Utc.with_ymd_and_hms(1600, 12, 31, 23, 59, 59).unwrap();
    assert_eq!(utc_to_filetime(before_1601), None);
}

#[test]
fn filetime_overflow_and_sentinels() {
    assert_eq!(filetime_to_utc(u64::MAX), None);
    assert_eq!(filetime_to_utc(0x8000_0000_0000_0000), None);
    let max_valid = filetime_to_utc(0x7FFF_FFFF_FFFF_FFFF);
    assert!(max_valid.is_some());
}

#[test]
fn ole_automation_date_cases() {
    let epoch = ole_automation_date_to_utc(0.0).expect("OLE 0.0 must decode");
    assert_eq!(epoch, Utc.with_ymd_and_hms(1899, 12, 30, 0, 0, 0).unwrap());

    let neg_zero = ole_automation_date_to_utc(-0.0).expect("OLE -0.0 must decode");
    assert_eq!(neg_zero, Utc.with_ymd_and_hms(1899, 12, 30, 0, 0, 0).unwrap());

    let prev_day = ole_automation_date_to_utc(-1.0).expect("OLE -1.0 must decode");
    assert_eq!(prev_day, Utc.with_ymd_and_hms(1899, 12, 29, 0, 0, 0).unwrap());

    // [MS-OAUT] §2.2.25: negative fractional OLE DATE adds positive time-of-day to whole_days
    assert_eq!(
        ole_automation_date_to_utc(-0.5),
        Some(Utc.with_ymd_and_hms(1899, 12, 30, 12, 0, 0).unwrap())
    );
    assert_eq!(
        ole_automation_date_to_utc(-1.25),
        Some(Utc.with_ymd_and_hms(1899, 12, 29, 6, 0, 0).unwrap())
    );
    assert_eq!(
        ole_automation_date_to_utc(-1.5),
        Some(Utc.with_ymd_and_hms(1899, 12, 29, 12, 0, 0).unwrap())
    );
    assert_eq!(
        ole_automation_date_to_utc(-1.75),
        Some(Utc.with_ymd_and_hms(1899, 12, 29, 18, 0, 0).unwrap())
    );
    assert_eq!(
        ole_automation_date_to_utc(0.999_999_999_999_999_9),
        Some(Utc.with_ymd_and_hms(1899, 12, 31, 0, 0, 0).unwrap())
    );

    let modern = ole_automation_date_to_utc(45000.5).expect("OLE 45000.5 must decode");
    assert_eq!(modern, Utc.with_ymd_and_hms(2023, 3, 15, 12, 0, 0).unwrap());

    assert_eq!(ole_automation_date_to_utc(f64::NAN), None);
    assert_eq!(ole_automation_date_to_utc(f64::INFINITY), None);
    assert_eq!(ole_automation_date_to_utc(f64::NEG_INFINITY), None);
    assert_eq!(ole_automation_date_to_utc(10_000_000.0), None);
}

// --- SID Tests ---

#[test]
fn sid_system_and_zero_subauth() {
    let local_system = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    assert_eq!(parse_sid(&local_system).unwrap(), "S-1-5-18");

    let null_sid = [1, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(parse_sid(&null_sid).unwrap(), "S-1-0");
}

#[test]
fn sid_multi_subauthority_domain_user() {
    let mut bytes = vec![1, 5, 0, 0, 0, 0, 0, 5];
    for sub in [21u32, 123_456_789, 987_654_321, 111_111_111, 1001] {
        bytes.extend_from_slice(&sub.to_le_bytes());
    }
    assert_eq!(
        parse_sid(&bytes).unwrap(),
        "S-1-5-21-123456789-987654321-111111111-1001"
    );
}

#[test]
fn sid_large_hex_authority() {
    let bytes = [1, 1, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 42, 0, 0, 0];
    assert_eq!(parse_sid(&bytes).unwrap(), "S-1-0x100000002-42");
}

#[test]
fn sid_invalid_inputs() {
    assert!(matches!(
        parse_sid(&[1, 0, 0, 0, 0, 0, 0]),
        Err(ForensicError::Parse { .. })
    ));
    assert!(matches!(
        parse_sid(&[2, 0, 0, 0, 0, 0, 0, 5]),
        Err(ForensicError::Parse { .. })
    ));
    assert!(matches!(
        parse_sid(&[1, 16, 0, 0, 0, 0, 0, 5]),
        Err(ForensicError::Parse { .. })
    ));
    assert!(matches!(
        parse_sid(&[1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0]),
        Err(ForensicError::Parse { .. })
    ));
}

// --- GUID Tests ---

#[test]
fn guid_le_mixed_endian_order() {
    let raw = [
        0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    assert_eq!(parse_guid_le(&raw).unwrap(), "00112233-4455-6677-8899-aabbccddeeff");
    assert_eq!(
        parse_guid_le_braced(&raw).unwrap(),
        "{00112233-4455-6677-8899-aabbccddeeff}"
    );
}

#[test]
fn guid_le_short_buffer_err() {
    for len in 0..16 {
        let buf = vec![0u8; len];
        assert!(matches!(parse_guid_le(&buf), Err(ForensicError::Parse { .. })));
    }
}

// --- UTF-16LE Tests ---

#[test]
fn utf16_ascii_and_surrogate_pair() {
    assert_eq!(read_utf16_le(b"A\x00B\x00"), "AB");
    assert_eq!(try_read_utf16_le(b"A\x00B\x00").unwrap(), "AB");

    let grin = [0x3D, 0xD8, 0x00, 0xDE];
    assert_eq!(read_utf16_le(&grin), "😀");
    assert_eq!(try_read_utf16_le(&grin).unwrap(), "😀");
}

#[test]
fn utf16_odd_length_and_lone_surrogate() {
    assert_eq!(read_utf16_le(&[0x41, 0x00, 0x42]), "A");
    assert_eq!(read_utf16_le(&[0x00, 0xD8]), "\u{FFFD}");

    assert!(matches!(
        try_read_utf16_le(&[0x41, 0x00, 0x42]),
        Err(ForensicError::Parse { .. })
    ));
    assert!(matches!(
        try_read_utf16_le(&[0x00, 0xD8]),
        Err(ForensicError::Parse { .. })
    ));
}

#[test]
fn utf16_nul_termination() {
    assert_eq!(read_utf16_le_nul(b"H\x00i\x00\x00\x00X\x00"), "Hi");
    assert_eq!(read_utf16_le_nul(&[0x41, 0x00, 0x00]), "A");
    assert_eq!(read_utf16_le_nul(&[]), "");
}

// --- CRC32, Hex & ROT13 Tests ---

#[test]
fn crc32_ieee_standard_vector() {
    assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32_ieee(b""), 0x0000_0000);
    assert_eq!(crc32_ieee(b"\x00\x00\x00\x00"), 0x2144_DF1C);
}

#[test]
fn bytes_to_hex_lower_cases() {
    assert_eq!(bytes_to_hex_lower(&[]), "");
    assert_eq!(bytes_to_hex_lower(&[0x00, 0x0f, 0xab, 0xff]), "000fabff");
}

#[test]
fn rot13_preserves_non_alpha_and_inverts_itself() {
    let original = r"C:\Windows\System32\notepad.exe -v1.0 (Ü)";
    let encoded = rot13(original);
    assert_ne!(encoded, original);
    assert_eq!(rot13(&encoded), original);
    assert_eq!(rot13("HRZR_PGYFRFFVBA"), "UEME_CTLSESSION");
}

// --- ForensicSource, ForensicError & Diagnostics Tests ---

#[test]
fn forensic_source_and_error_mapping() {
    let live = ForensicSource::from_optional_path(None);
    assert!(live.is_live());
    assert!(!live.is_offline());
    assert_eq!(live.path(), None);
    assert_eq!(live.label(), "live");
    assert!(matches!(live.read_bytes(), Err(ForensicError::InvalidArgument(_))));

    let mem = ForensicSource::OfflineBytes(vec![1, 2, 3]);
    assert!(mem.is_offline());
    assert_eq!(mem.path(), None);
    assert_eq!(mem.label(), "<memory:3 bytes>");
    assert_eq!(mem.read_bytes().unwrap(), vec![1, 2, 3]);

    let missing_path = PathBuf::from("nonexistent_forensic_artifact_999999.evtx");
    let offline = ForensicSource::from_optional_path(Some(missing_path.clone()));
    assert!(offline.is_offline());
    assert_eq!(offline.path(), Some(missing_path.as_path()));
    assert!(matches!(offline.read_bytes(), Err(ForensicError::NotFound(_))));

    let temp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp.path(), b"EVTX_TEST").unwrap();
    let file_src = ForensicSource::OfflinePath(temp.path().to_path_buf());
    assert_eq!(file_src.read_bytes().unwrap(), b"EVTX_TEST");

    // Error conversions & classification
    let perm_io = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    assert!(is_elevation_error(&perm_io));
    let classified_perm = ForensicError::io_classified("Security.evtx", perm_io);
    assert!(matches!(classified_perm, ForensicError::PermissionDenied { .. }));
    match classified_perm.to_table_error() {
        TableError::Provider(msg) => assert!(msg.contains("run elevated or supply an offline artifact path")),
        other => panic!("unexpected TableError variant: {other:?}"),
    }

    let raw_5 = std::io::Error::from_raw_os_error(5);
    assert!(is_elevation_error(&raw_5));
    let raw_1314 = std::io::Error::from_raw_os_error(1314);
    assert!(is_elevation_error(&raw_1314));

    assert!(matches!(
        ForensicError::NotFound("hive".into()).to_table_error(),
        TableError::Provider(_)
    ));
    assert!(matches!(
        ForensicError::unsupported_platform("etw", "windows only").to_table_error(),
        TableError::Provider(_)
    ));
    assert!(matches!(
        ForensicError::parse("regf", "bad header").to_table_error(),
        TableError::Provider(_)
    ));
    assert!(matches!(
        ForensicError::io("x", std::io::Error::other("disk")).to_table_error(),
        TableError::Provider(_)
    ));
    assert!(matches!(
        ForensicError::InvalidArgument("bad".into()).to_table_error(),
        TableError::QueryParse(_)
    ));

    // InvalidRegex: QueryParse via &self, InvalidRegex via From
    let invalid_pattern = String::from("[");
    let bad_regex = regex::Regex::new(&invalid_pattern).unwrap_err();
    let wrapped_ref = ForensicError::Table(TableError::InvalidRegex(bad_regex.clone()));
    assert!(matches!(wrapped_ref.to_table_error(), TableError::QueryParse(_)));

    let wrapped_owned = ForensicError::Table(TableError::InvalidRegex(bad_regex));
    assert!(matches!(TableError::from(wrapped_owned), TableError::InvalidRegex(_)));

    let col_err = ForensicError::Table(TableError::InvalidColumn("missing".into()));
    assert!(matches!(col_err.to_table_error(), TableError::InvalidColumn(_)));

    let warn = DiagnosticWarning {
        severity: WarningSeverity::Warn,
        tool_id: "evtx.logon".to_string(),
        source: "live".to_string(),
        message: "Security channel requires elevation".to_string(),
    };
    let json = serde_json::to_string(&warn).unwrap();
    assert!(json.contains("\"severity\":\"warn\""));
}

// --- QueryHelper Integration Tests ---

#[test]
fn query_helper_guap_table_integration() {
    let schema = TableSchema::new(
        "evtx.test",
        "Test Events",
        vec![
            ColumnDef::new("event_id", "Event ID", ColumnType::Uint),
            ColumnDef::new("channel", "Channel", ColumnType::Text),
            ColumnDef::new("provider", "Provider", ColumnType::Text),
        ],
    )
    .with_default_sort(0, SortDirection::Asc);

    let rows = vec![
        Row::new(
            1,
            vec![
                CellValue::Uint(4624),
                CellValue::Text("Security".into()),
                CellValue::Text("Microsoft-Windows-Security-Auditing".into()),
            ],
        ),
        Row::new(
            2,
            vec![
                CellValue::Uint(4625),
                CellValue::Text("Security".into()),
                CellValue::Text("Microsoft-Windows-Security-Auditing".into()),
            ],
        ),
        Row::new(
            3,
            vec![
                CellValue::Uint(6005),
                CellValue::Text("System".into()),
                CellValue::Text("EventLog".into()),
            ],
        ),
        Row::new(
            4,
            vec![
                CellValue::Uint(4688),
                CellValue::Text("Security".into()),
                CellValue::Text("Microsoft-Windows-Security-Auditing".into()),
            ],
        ),
    ];

    let filtered = QueryHelper::apply_query(
        &schema,
        &rows,
        Some(vec!["event_id".into(), "channel".into()]),
        Some("channel=Security AND event_id>=4625"),
        Some("-event_id"),
        0,
        Some(1),
    )
    .unwrap();

    assert_eq!(filtered.total_rows, 2);
    assert_eq!(filtered.rows.len(), 1);
    assert_eq!(filtered.schema.columns.len(), 2);
    assert_eq!(filtered.rows[0].cells[0], CellValue::Uint(4688));

    let provider: Arc<dyn TableProvider> = Arc::new(InMemoryTableProvider::new(
        "evtx.test",
        "Test provider",
        schema.clone(),
        rows.clone(),
    ));
    let from_provider =
        QueryHelper::query_provider(provider.as_ref(), None, Some("provider~EventLog"), None, 0, None).unwrap();
    assert_eq!(from_provider.total_rows, 1);
    assert_eq!(from_provider.rows[0].cells[0], CellValue::Uint(6005));

    let bad_col = QueryHelper::apply_query(&schema, &rows, None, Some("nonexistent=1"), None, 0, None);
    assert!(matches!(bad_col, Err(ForensicError::Table(_))));

    let empty = QueryHelper::empty(schema);
    assert_eq!(empty.total_rows, 0);
    assert!(empty.rows.is_empty());
}

// --- 45-Tool Catalog & R4 Exclusion Tests ---

#[test]
fn catalog_45_tools_invariants_and_r4() {
    assert_eq!(FORENSIC_TOOL_CATALOG.len(), 45);
    assert_eq!(tools_by_category(ToolCategory::Evtx).count(), 14);
    assert_eq!(tools_by_category(ToolCategory::Hive).count(), 6);
    assert_eq!(tools_by_category(ToolCategory::Srum).count(), 4);
    assert_eq!(tools_by_category(ToolCategory::Artifacts).count(), 14);
    assert_eq!(tools_by_category(ToolCategory::Crash).count(), 3);
    assert_eq!(tools_by_category(ToolCategory::Posture).count(), 4);

    let mut seen_ids = HashSet::new();
    let mut seen_cmds = HashSet::new();

    let r4_forbidden = [
        "cred2rust",
        "drwatson",
        "winupdateslist",
        "runasdate",
        "socketsniff",
        "wirelesskeyview",
        "sniffpass",
        "lsasecrets",
        "webbrowserpassview",
        "password",
    ];

    for desc in FORENSIC_TOOL_CATALOG {
        assert!(seen_ids.insert(desc.tool_id), "duplicate tool_id: {}", desc.tool_id);
        assert!(
            seen_cmds.insert(desc.cli_subcommand),
            "duplicate cli_subcommand: {}",
            desc.cli_subcommand
        );
        assert!(desc.read_only, "tool {} must be read_only", desc.tool_id);
        assert!(desc.supports_offline, "tool {} must support offline mode", desc.tool_id);
        assert!(desc.tool_id.starts_with(desc.category.as_str()));
        assert!(desc.cli_subcommand.starts_with(desc.category.as_str()));
        assert!(desc.category.crate_name().starts_with("forensics2rust-"));
        assert_eq!(find_tool(desc.tool_id), Some(desc));
        assert_eq!(find_by_subcommand(desc.cli_subcommand), Some(desc));

        assert!(
            !desc.display_name.trim().is_empty(),
            "empty display_name for {}",
            desc.tool_id
        );
        let haystacks = [
            desc.tool_id.to_ascii_lowercase(),
            desc.cli_subcommand.to_ascii_lowercase(),
            desc.display_name.to_ascii_lowercase(),
            desc.description.to_ascii_lowercase(),
        ];
        for banned in r4_forbidden {
            for hay in &haystacks {
                assert!(
                    !hay.contains(banned),
                    "R4 exclusion '{banned}' matched in tool {}: {hay}",
                    desc.tool_id
                );
            }
        }
    }

    assert_eq!(all_tool_ids().count(), 45);
    assert_eq!(find_tool("nonexistent.tool"), None);
    assert_eq!(find_by_subcommand("nonexistent cmd"), None);
}

#[test]
fn logging_initialization_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("nested").join("forensics2rust.log");
    init_logging("warn", Some(&log_path)).unwrap();
    assert!(log_path.exists());
    init_logging("info", None).unwrap();
}
