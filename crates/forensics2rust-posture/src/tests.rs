#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use forensics2rust_core::{
    FORENSIC_TOOL_CATALOG, ForensicError, ForensicSource, QueryHelper, ToolCategory, WarningSeverity,
};
use guap_table::{CellValue, TableProvider, TableQuery};
use tempfile::TempDir;

use crate::cbs_log::{parse_cbs_log_bytes, parse_cbs_log_path};
use crate::datastore_ese::parse_datastore_ese_bytes;
use crate::defender::parse_defender_json;
use crate::discovery::parse_flexible_timestamp;
use crate::fixtures::{
    build_synthetic_cbs_log_bytes, build_synthetic_cbs_log_gz_bytes, build_synthetic_cbs_log_utf16le_bytes,
    build_synthetic_datastore_edb_bytes, build_synthetic_defender_regf_bytes, build_synthetic_defender_wmi_json_bytes,
    build_synthetic_security_center_json_bytes, build_synthetic_store_db_bytes,
};
use crate::providers::{
    PostureDefenderStatusProvider, PostureFullUpdatesProvider, PostureSecurityCenterProvider, PostureUpdatesProvider,
    all_providers, provider_for_tool,
};
use crate::security_center::{
    SecurityCenterRecord, classify_security_center_hresult, decode_product_state, merge_security_center_records,
    parse_security_center_json,
};
use crate::store_db::{parse_store_db_bytes, parse_store_db_path};
use crate::{crate_info, domain_tools};

#[test]
fn posture_catalog_and_providers_are_registered_and_read_only() {
    assert_eq!(crate_info().0, "forensics2rust-posture");
    let tools = domain_tools();
    assert_eq!(tools.len(), 4);

    let catalog_ids: Vec<&str> = FORENSIC_TOOL_CATALOG
        .iter()
        .filter(|t| t.category == ToolCategory::Posture)
        .map(|t| t.tool_id)
        .collect();
    assert_eq!(
        catalog_ids,
        vec![
            "posture.updates",
            "posture.full_updates",
            "posture.defender_status",
            "posture.security_center",
        ]
    );

    let providers = all_providers(&ForensicSource::Live);
    assert_eq!(providers.len(), 4);
    for (p, expected_id) in providers.iter().zip(catalog_ids.iter()) {
        assert_eq!(p.tool_id(), *expected_id);
        assert!(p.is_read_only(), "provider {} must be read-only", p.tool_id());
        assert!(provider_for_tool(expected_id, &ForensicSource::Live).is_some());
    }
    assert!(provider_for_tool("posture.unknown", &ForensicSource::Live).is_none());
}

#[test]
fn datastore_edb_parses_joins_updates_and_localized_fallback() {
    let edb_bytes = build_synthetic_datastore_edb_bytes();
    let (records, warnings) = parse_datastore_ese_bytes(&edb_bytes, "synthetic.edb").expect("parse DataStore.edb");
    assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    assert_eq!(records.len(), 3);

    // Row 1: joined KB5044285 from tbUpdates via 16B Binary UpdateId GUID
    let r0 = &records[0];
    assert_eq!(r0.title, "2024-11 Cumulative Update for Windows 11");
    assert_eq!(r0.result_code, "Succeeded");
    assert_eq!(r0.operation, "Installation");
    assert_eq!(r0.kb_article.as_deref(), Some("KB5044285"));
    assert_eq!(r0.update_id.as_deref(), Some("12345678-cdab-01ef-2233-445566778899"));
    assert_eq!(
        r0.support_url.as_deref(),
        Some("https://support.microsoft.com/kb/5044285")
    );
    assert_eq!(r0.client_app_id.as_deref(), Some("MoUsoCoreWorker"));
    assert!(r0.install_date.is_some());

    // Row 2: Failed row whose empty Title/Description fell back to en-US tbUpdateLocalizedProps
    let r1 = &records[1];
    assert_eq!(r1.result_code, "Failed");
    assert_eq!(r1.title, "2024-11 .NET Framework Cumulative Update");
    assert_eq!(r1.description, "Localized English fallback description.");
    assert_eq!(r1.kb_article.as_deref(), Some("KB5045594"));
    assert_eq!(r1.hresult, Some(-2147023293i32));

    // Row 3: Aborted Uninstallation row
    let r2 = &records[2];
    assert_eq!(r2.operation, "Uninstallation");
    assert_eq!(r2.result_code, "Aborted");
    assert_eq!(r2.kb_article.as_deref(), Some("KB5049999"));

    // Provider OfflineBytes + OfflinePath + GuapQuery filtering/sorting
    let provider = PostureUpdatesProvider::new(ForensicSource::OfflineBytes(edb_bytes.clone()));
    let table = provider.query(&TableQuery::default()).expect("provider query");
    assert_eq!(table.total_rows, 3);
    assert_eq!(
        table.rows[0].cells[0],
        CellValue::Text("2024-11 Cumulative Update for Windows 11".to_string())
    );

    let filtered = QueryHelper::query_provider(
        &provider,
        Some(vec![
            "Title".to_string(),
            "ResultCode".to_string(),
            "KBArticle".to_string(),
        ]),
        Some("ResultCode == 'Failed'"),
        None,
        0,
        None,
    )
    .expect("GuapQuery filter");
    assert_eq!(filtered.total_rows, 1);
    assert_eq!(filtered.rows[0].cells[2], CellValue::Text("KB5045594".to_string()));
}

#[test]
fn store_db_sqlite_and_ese_fallback_roundtrip() {
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("store.db");
    let bytes = build_synthetic_store_db_bytes(&db_path);

    let (path_recs, path_warn) = parse_store_db_path(&db_path).expect("parse SQLite store.db path");
    assert!(path_warn.is_empty());
    assert_eq!(path_recs.len(), 3);
    assert_eq!(path_recs[0].kb_number.as_deref(), Some("KB5046617"));
    assert_eq!(path_recs[0].build_version.as_deref(), Some("26100.2314"));
    assert_eq!(path_recs[0].category, "Quality");
    assert!(path_recs[0].install_date.is_some());
    assert_eq!(path_recs[1].kb_number.as_deref(), Some("KB2267602"));
    assert_eq!(path_recs[2].result.as_deref(), Some("0x80240017"));

    // OfflineBytes round-trip via RAII TempDbFile
    let (mem_recs, mem_warn) = parse_store_db_bytes(&bytes, "OfflineBytes(store.db)").expect("parse store.db bytes");
    assert!(mem_warn.is_empty());
    assert_eq!(mem_recs.len(), 3);

    // ESE fallback when store.db uses ESE 0x89ABCDEF format
    let ese_bytes = build_synthetic_datastore_edb_bytes();
    let (ese_recs, _) = parse_store_db_bytes(&ese_bytes, "OfflineBytes(store_ese.db)").expect("ESE store.db fallback");
    assert_eq!(ese_recs.len(), 3);
    assert_eq!(ese_recs[0].source_db, "store.db (ESE)");
}

#[test]
fn cbs_log_parses_bom_filters_noise_and_extracts_kb_build_hresult() {
    let utf8_bytes = build_synthetic_cbs_log_bytes();
    let (records, warnings) = parse_cbs_log_bytes(&utf8_bytes, "CBS.log").expect("parse UTF-8 BOM CBS.log");
    assert!(warnings.is_empty());

    // Noise lines (Perf: LRU Cache, ApplicableState: 0, CBS_E_INVALID_PACKAGE) must be filtered!
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].category, "ServicingStack");
    assert_eq!(records[0].build_version.as_deref(), Some("10.0.26100.10068"));

    assert_eq!(records[1].kb_number.as_deref(), Some("KB5044285"));
    assert_eq!(records[1].category, "RollupFix");
    assert_eq!(records[1].build_version.as_deref(), Some("26100.10075.1.25"));
    assert_eq!(records[1].result.as_deref(), Some("Completed"));

    assert_eq!(records[2].kb_number.as_deref(), Some("KB5045594"));
    assert_eq!(records[2].category, "ServicingError");
    assert_eq!(records[2].result.as_deref(), Some("0x800f081f"));

    // UTF-16LE BOM CBS.log (including >16 KiB multi-chunk streaming without trailing newline)
    let u16_bytes = build_synthetic_cbs_log_utf16le_bytes();
    let (u16_recs, _) = parse_cbs_log_bytes(&u16_bytes, "CBS_utf16.log").expect("parse UTF-16LE CBS.log");
    assert_eq!(u16_recs.len(), 2);
    assert_eq!(u16_recs[1].kb_number.as_deref(), Some("KB5046633"));

    let mut large_u16 = vec![0xFFu8, 0xFE];
    let noise_line = "2024-11-12 09:00:01, Info                  CBS    Perf: LRU Cache populated in 1ms\r\n";
    for _ in 0..120 {
        for unit in noise_line.encode_utf16() {
            large_u16.extend_from_slice(&unit.to_le_bytes());
        }
    }
    let tail_line = "2024-11-12 09:05:00, Info                  CBS    Committed Package_for_KB5049111~31bf3856ad364e35~amd64~~26100.2400.1.0";
    for unit in tail_line.encode_utf16() {
        large_u16.extend_from_slice(&unit.to_le_bytes());
    }
    assert!(large_u16.len() > 16_384);
    let (large_u16_recs, _) =
        parse_cbs_log_bytes(&large_u16, "CBS_large_utf16.log").expect("parse large UTF-16LE CBS.log");
    assert_eq!(large_u16_recs.len(), 1);
    assert_eq!(large_u16_recs[0].kb_number.as_deref(), Some("KB5049111"));

    // Gzipped CBS.persist.log.gz via path
    let dir = TempDir::new().expect("tempdir");
    let gz_path = dir.path().join("CBS.persist.log.gz");
    fs::write(&gz_path, build_synthetic_cbs_log_gz_bytes()).expect("write gz");
    let (gz_recs, _) = parse_cbs_log_path(&gz_path).expect("parse CBS.persist.log.gz");
    assert_eq!(gz_recs.len(), 3);
}

#[test]
fn full_updates_aggregates_offline_directory_and_bytes() {
    let dir = TempDir::new().expect("tempdir");
    let uso_dir = dir.path().join("ProgramData/Microsoft/Windows/USOPrivate/UpdateStore");
    let cbs_dir = dir.path().join("Windows/Logs/CBS");
    let ds_dir = dir.path().join("Windows/SoftwareDistribution/DataStore");
    fs::create_dir_all(&uso_dir).unwrap();
    fs::create_dir_all(&cbs_dir).unwrap();
    fs::create_dir_all(&ds_dir).unwrap();

    build_synthetic_store_db_bytes(&uso_dir.join("store.db"));
    fs::write(cbs_dir.join("CBS.log"), build_synthetic_cbs_log_bytes()).unwrap();
    fs::write(ds_dir.join("DataStore.edb"), build_synthetic_datastore_edb_bytes()).unwrap();

    let provider = PostureFullUpdatesProvider::new(ForensicSource::OfflinePath(dir.path().to_path_buf()));
    let (table, warnings) = provider
        .query_with_warnings(&TableQuery::default())
        .expect("aggregate offline dir");
    assert!(warnings.is_empty(), "warnings: {warnings:?}");
    // 3 from store.db + 3 from CBS.log + 3 from DataStore.edb = 9
    assert_eq!(table.total_rows, 9);

    // OfflineBytes dispatch for CBS.log and store.db
    let cbs_provider = PostureFullUpdatesProvider::new(ForensicSource::OfflineBytes(build_synthetic_cbs_log_bytes()));
    assert_eq!(cbs_provider.query(&TableQuery::default()).unwrap().total_rows, 3);

    // QueryHelper filter + sort on full_updates
    let filtered = QueryHelper::query_provider(
        &provider,
        Some(vec![
            "Title".to_string(),
            "KBNumber".to_string(),
            "SourceDB".to_string(),
        ]),
        Some("KBNumber == 'KB5044285'"),
        Some("Title:desc"),
        0,
        None,
    )
    .expect("QueryHelper on full_updates");
    assert_eq!(filtered.total_rows, 2); // DataStore.edb + CBS.log both have KB5044285
}

#[test]
fn kb_extractor_handles_cbs_underscores_and_adjacent_matches() {
    let kbs = crate::discovery::extract_kb_articles(&[
        "Package_for_KB5045594~31bf3856ad364e35~amd64~~26100.1.1.0",
        "KB5044285,KB5046633_kb2267602",
        "Ignore KB12345678 and XKB5044285",
    ]);
    assert_eq!(
        kbs,
        vec![
            "KB5045594".to_string(),
            "KB5044285".to_string(),
            "KB5046633".to_string(),
            "KB2267602".to_string(),
        ]
    );
}

#[test]
fn defender_regf_hive_and_gpo_override_precedence() {
    // 1. Local only
    let local_bytes = build_synthetic_defender_regf_bytes(false);
    let provider_local = PostureDefenderStatusProvider::new(ForensicSource::OfflineBytes(local_bytes));
    let (tbl_local, warn_local) = provider_local
        .query_with_warnings(&TableQuery::default())
        .expect("local hive");
    assert_eq!(tbl_local.total_rows, 1);
    let row = &tbl_local.rows[0];
    assert_eq!(row.cells[0], CellValue::Bool(true)); // AMServiceEnabled
    assert_eq!(row.cells[1], CellValue::Bool(true)); // AntivirusEnabled
    assert_eq!(row.cells[2], CellValue::Bool(true)); // RealTimeProtection
    assert_eq!(row.cells[6], CellValue::Bool(true)); // TamperProtected
    assert_eq!(row.cells[7], CellValue::Text("UI".to_string()));
    assert_eq!(row.cells[11], CellValue::Text("1.463.436.0".to_string()));
    assert!(matches!(row.cells[12], CellValue::Timestamp(_))); // SignatureUpdated
    assert_eq!(row.cells[14], CellValue::Uint(2)); // QuickScanAge
    assert_eq!(row.cells[15], CellValue::Null); // FullScanAge == u32::MAX -> Null!
    assert_eq!(row.cells[16], CellValue::Text("Enabled".to_string())); // PUAProtection = 1
    assert_eq!(row.cells[20], CellValue::Uint(0)); // GpoOverrides = 0
    assert_eq!(row.cells[21], CellValue::Text("C:\\BuildCache".to_string()));
    assert_eq!(row.cells[22], CellValue::Text("cargo.exe".to_string()));
    assert_eq!(row.cells[23], CellValue::Text(".pdb".to_string()));
    assert!(warn_local.is_empty());

    // 2. With GPO overrides under Policies\Microsoft\Windows Defender
    let gpo_bytes = build_synthetic_defender_regf_bytes(true);
    let dir = TempDir::new().unwrap();
    let hive_path = dir.path().join("SOFTWARE");
    fs::write(&hive_path, &gpo_bytes).unwrap();

    let provider_gpo = PostureDefenderStatusProvider::new(ForensicSource::OfflinePath(hive_path));
    let tbl_gpo = provider_gpo.query(&TableQuery::default()).expect("GPO hive");
    let gpo_row = &tbl_gpo.rows[0];
    assert_eq!(gpo_row.cells[2], CellValue::Bool(false)); // DisableRealtimeMonitoring=1 via GPO!
    assert_eq!(gpo_row.cells[16], CellValue::Text("AuditMode".to_string())); // PUAProtection=2 via GPO!
    assert_eq!(gpo_row.cells[20], CellValue::Uint(3)); // 3 GPO overrides
    assert_eq!(
        gpo_row.cells[21],
        CellValue::Text("C:\\BuildCache; D:\\GpoExcluded".to_string())
    );

    // 3. OfflinePath directory containing both Windows\System32\config\SOFTWARE and defender_status.json
    let ev_dir = TempDir::new().unwrap();
    let cfg_dir = ev_dir.path().join("Windows\\System32\\config");
    fs::create_dir_all(&cfg_dir).unwrap();
    fs::write(cfg_dir.join("SOFTWARE"), &gpo_bytes).unwrap();
    fs::write(
        ev_dir.path().join("defender_status.json"),
        build_synthetic_defender_wmi_json_bytes(),
    )
    .unwrap();

    let dir_provider = PostureDefenderStatusProvider::new(ForensicSource::OfflinePath(ev_dir.path().to_path_buf()));
    let (dir_tbl, dir_warnings) = dir_provider
        .query_with_warnings(&TableQuery::default())
        .expect("dir hive+json");
    assert_eq!(dir_tbl.total_rows, 1);
    let dir_row = &dir_tbl.rows[0];
    // GPO DisableRealtimeMonitoring=1 must override JSON RealTimeProtectionEnabled=true
    assert_eq!(dir_row.cells[2], CellValue::Bool(false));
    assert_eq!(dir_row.cells[16], CellValue::Text("AuditMode".to_string()));
    // JSON sentinel is stripped, hive exclusions remain, and JSON MSFT_MpPreference ExclusionExtension (.tmp) is preserved
    assert_eq!(
        dir_row.cells[21],
        CellValue::Text("C:\\BuildCache; D:\\GpoExcluded".to_string())
    );
    assert_eq!(dir_row.cells[23], CellValue::Text(".tmp; .pdb".to_string()));
    assert_eq!(dir_row.cells[24], CellValue::Text("OfflineHive+Json".to_string()));
    assert_eq!(
        dir_warnings
            .iter()
            .filter(|w| w.severity == WarningSeverity::Warn && w.message.contains("HideExclusionsFromLocalUsers"))
            .count(),
        1
    );

    // 4. Verify GPO overrides for BehaviorMonitoring, IOAV, OnAccess, AntiVirus, and PassiveMode over WMI
    let mut reg_override = crate::defender::DefenderRegistrySnapshot {
        disable_anti_virus: Some(true),
        disable_behavior_monitoring: Some(true),
        disable_ioav_protection: Some(true),
        disable_on_access_protection: Some(true),
        passive_mode: Some(true),
        ..Default::default()
    };
    reg_override
        .gpo_overrides
        .insert("DisableAntiVirus".to_string(), serde_json::json!(1));
    reg_override.gpo_overrides.insert(
        "Real-Time Protection\\DisableBehaviorMonitoring".to_string(),
        serde_json::json!(1),
    );
    reg_override.gpo_overrides.insert(
        "Real-Time Protection\\DisableIOAVProtection".to_string(),
        serde_json::json!(1),
    );
    reg_override.gpo_overrides.insert(
        "Real-Time Protection\\DisableOnAccessProtection".to_string(),
        serde_json::json!(1),
    );
    reg_override
        .gpo_overrides
        .insert("PassiveMode".to_string(), serde_json::json!(1));

    let wmi_all_on = crate::defender::DefenderWmiSnapshot {
        antivirus_enabled: Some(true),
        behavior_monitor_enabled: Some(true),
        ioav_protection_enabled: Some(true),
        on_access_protection_enabled: Some(true),
        am_running_mode: Some("Normal".to_string()),
        ..Default::default()
    };
    let mut corr_warn = Vec::new();
    let correlated = crate::defender::correlate_defender_snapshots(
        Some(wmi_all_on),
        Some(reg_override),
        "WMI+Registry",
        "posture.defender_status",
        &mut corr_warn,
    );
    assert_eq!(correlated.antivirus_enabled, Some(false));
    assert_eq!(correlated.behavior_monitor_enabled, Some(false));
    assert_eq!(correlated.ioav_protection_enabled, Some(false));
    assert_eq!(correlated.on_access_protection, Some(false));
    assert_eq!(correlated.passive_mode, Some(true));
    assert_eq!(correlated.am_running_mode.as_deref(), Some("Passive"));
}

#[test]
fn defender_wmi_json_filters_hidden_exclusions_sentinel_and_max_scan_age() {
    let json_bytes = build_synthetic_defender_wmi_json_bytes();
    let provider = PostureDefenderStatusProvider::new(ForensicSource::OfflineBytes(json_bytes));
    let (tbl, warnings) = provider
        .query_with_warnings(&TableQuery::default())
        .expect("defender json");
    assert_eq!(tbl.total_rows, 1);

    let row = &tbl.rows[0];
    // FullScanAge == u32::MAX must map to Null
    assert_eq!(row.cells[15], CellValue::Null);
    // Sentinel string must NEVER appear in ExclusionPaths or ExclusionProcesses!
    assert_eq!(row.cells[21], CellValue::Null);
    assert_eq!(row.cells[22], CellValue::Null);
    assert_eq!(row.cells[23], CellValue::Text(".tmp".to_string()));
    assert!(
        warnings
            .iter()
            .any(|w| w.severity == WarningSeverity::Warn && w.message.contains("HideExclusionsFromLocalUsers"))
    );
}

#[test]
fn security_center_product_state_bitmask_matrix() {
    let cases = [
        (
            0x061100u32,
            "0x061100",
            0x06u8,
            "On",
            Some(true),
            "UpToDate",
            Some(true),
        ),
        (
            0x061110u32,
            "0x061110",
            0x06u8,
            "On",
            Some(true),
            "OutOfDate",
            Some(false),
        ),
        (
            0x060100u32,
            "0x060100",
            0x06u8,
            "Off",
            Some(false),
            "UpToDate",
            Some(true),
        ),
        (
            0x041000u32,
            "0x041000",
            0x04u8,
            "On",
            Some(true),
            "UpToDate",
            Some(true),
        ),
        (
            0x041010u32,
            "0x041010",
            0x04u8,
            "On",
            Some(true),
            "OutOfDate",
            Some(false),
        ),
        (
            0x042000u32,
            "0x042000",
            0x04u8,
            "Snoozed",
            Some(false),
            "UpToDate",
            Some(true),
        ),
        (
            0x043000u32,
            "0x043000",
            0x04u8,
            "Expired",
            Some(false),
            "UpToDate",
            Some(true),
        ),
        (
            0x049020u32,
            "0x049020",
            0x04u8,
            "Unknown(0x9)",
            None,
            "Unknown(0x2)",
            None,
        ),
    ];

    for (raw, hex, pflags, prot, enabled, sig, uptodate) in cases {
        let d = decode_product_state(raw);
        assert_eq!(d.state_hex, hex);
        assert_eq!(d.provider_flags, pflags);
        assert_eq!(d.protection_state, prot);
        assert_eq!(d.enabled, enabled);
        assert_eq!(d.signature_status, sig);
        assert_eq!(d.up_to_date, uptodate);
    }
}

#[test]
fn security_center_hresult_classifier_and_merge_dedup() {
    let server_warn = classify_security_center_hresult(0x8004_100E_u32 as i32, "root\\SecurityCenter2");
    assert_eq!(server_warn.severity, WarningSeverity::Info);
    assert!(server_warn.message.contains("WBEM_E_INVALID_NAMESPACE"));

    let class_warn = classify_security_center_hresult(0x8004_0154_u32 as i32, "WSCProductList");
    assert_eq!(class_warn.severity, WarningSeverity::Info);
    assert!(class_warn.message.contains("REGDB_E_CLASSNOTREG"));

    let denied_warn = classify_security_center_hresult(0x8007_0005_u32 as i32, "SecurityCenter2");
    assert_eq!(denied_warn.severity, WarningSeverity::Warn);

    let json_bytes = build_synthetic_security_center_json_bytes();
    let provider = PostureSecurityCenterProvider::new(ForensicSource::OfflineBytes(json_bytes));
    let tbl = provider.query(&TableQuery::default()).expect("security center json");
    assert_eq!(tbl.total_rows, 2);
    assert_eq!(tbl.rows[0].cells[0], CellValue::Text("Windows Defender".to_string()));
    assert_eq!(tbl.rows[0].cells[3], CellValue::Text("0x061100".to_string()));
    assert_eq!(tbl.rows[0].cells[4], CellValue::Bool(true));
    assert_eq!(tbl.rows[0].cells[6], CellValue::Bool(true));
    assert_eq!(tbl.rows[1].cells[1], CellValue::Text("FW".to_string()));
    assert_eq!(tbl.rows[1].cells[6], CellValue::Bool(false)); // 0x041010 -> OutOfDate

    // Verify merge deduplicates WSC duplicate sharing GUID while keeping distinct Firewall product
    let wmi = vec![SecurityCenterRecord {
        display_name: "Windows Defender".to_string(),
        product_type: "AV".to_string(),
        instance_guid: Some("d68ddc3a-831f-4fae-9e44-da132c1acf46".to_string()),
        product_state_hex: Some("0x061100".to_string()),
        decoded_state: Some(decode_product_state(0x061100)),
        enabled: Some(true),
        protection_state: "On".to_string(),
        up_to_date: Some(true),
        signature_status: "UpToDate".to_string(),
        provider_flags_hex: Some("0x06".to_string()),
        signed_executable: Some("windowsdefender://".to_string()),
        reporting_executable: None,
        timestamp: parse_flexible_timestamp("Thu, 19 Nov 2026 18:50:00 GMT"),
        source: "WMI:SecurityCenter2".to_string(),
        is_default: None,
    }];
    let wsc = vec![
        SecurityCenterRecord {
            display_name: "Microsoft Defender Antivirus".to_string(),
            product_type: "AV".to_string(),
            instance_guid: Some("D68DDC3A-831F-4FAE-9E44-DA132C1ACF46".to_string()),
            product_state_hex: None,
            decoded_state: None,
            enabled: Some(true),
            protection_state: "On".to_string(),
            up_to_date: Some(true),
            signature_status: "UpToDate".to_string(),
            provider_flags_hex: None,
            signed_executable: Some("windowsdefender://".to_string()),
            reporting_executable: None,
            timestamp: None,
            source: "WSC:IWSCProductList".to_string(),
            is_default: Some(false),
        },
        SecurityCenterRecord {
            display_name: "Windows Firewall".to_string(),
            product_type: "FW".to_string(),
            instance_guid: None,
            product_state_hex: None,
            decoded_state: None,
            enabled: Some(true),
            protection_state: "On".to_string(),
            up_to_date: Some(true),
            signature_status: "UpToDate".to_string(),
            provider_flags_hex: None,
            signed_executable: Some("%windir%\\system32\\firewall.cpl".to_string()),
            reporting_executable: None,
            timestamp: None,
            source: "WSC:IWSCProductList".to_string(),
            is_default: Some(false),
        },
    ];
    let merged = merge_security_center_records(wmi, wsc);
    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0].source, "WMI:SecurityCenter2");
    assert_eq!(merged[1].display_name, "Windows Firewall");
}

#[test]
fn flexible_timestamps_and_malformed_inputs_return_classified_errors() {
    assert!(parse_flexible_timestamp("1731094054357").is_some());
    assert!(parse_flexible_timestamp("1731100000").is_some());
    assert!(parse_flexible_timestamp("133700000000000000").is_some());
    assert!(parse_flexible_timestamp("20261123080036.000000+000").is_some());
    assert!(parse_flexible_timestamp("Thu, 19 Nov 2026 18:50:00 GMT").is_some());
    assert!(parse_flexible_timestamp("NULL").is_none());

    let missing = Path::new("Z:\\definitely_missing_posture_dir_99999");
    for p in all_providers(&ForensicSource::OfflinePath(missing.to_path_buf())) {
        assert!(p.query(&TableQuery::default()).is_err());
    }

    for p in all_providers(&ForensicSource::OfflineBytes(b"not a valid artifact".to_vec())) {
        assert!(p.query(&TableQuery::default()).is_err());
    }

    // Verify missing sqlite table fails cleanly
    let dir = TempDir::new().unwrap();
    let bad_db = dir.path().join("empty.db");
    let conn = rusqlite::Connection::open(&bad_db).unwrap();
    conn.execute("CREATE TABLE OTHER (id INT)", []).unwrap();
    drop(conn);
    let err = parse_store_db_path(&bad_db).unwrap_err();
    assert!(matches!(err, ForensicError::Parse { .. }));
}

#[test]
fn defender_json_arrays_1_and_2_elements_preserve_distinct_rows() {
    let one = br#"[{"AMServiceEnabled":true,"AMProductVersion":"4.18.1"}]"#;
    let (one_recs, _) = parse_defender_json(one, "one.json").expect("1-element Defender JSON array");
    assert_eq!(one_recs.len(), 1);
    assert_eq!(one_recs[0].am_service_enabled, Some(true));
    assert_eq!(one_recs[0].am_product_version.as_deref(), Some("4.18.1"));
    assert_eq!(one_recs[0].pua_protection, None);

    let two = br#"[{"AMServiceEnabled":true,"AMProductVersion":"4.18.1"},{"AMServiceEnabled":false,"AMProductVersion":"4.18.2","PUAProtection":2}]"#;
    let (recs, _) = parse_defender_json(two, "two.json").expect("2-element Defender JSON array");
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0].am_service_enabled, Some(true));
    assert_eq!(recs[0].am_product_version.as_deref(), Some("4.18.1"));
    assert_eq!(recs[0].pua_protection, None);
    assert_eq!(recs[1].am_service_enabled, Some(false));
    assert_eq!(recs[1].am_product_version.as_deref(), Some("4.18.2"));
    assert_eq!(recs[1].pua_protection.as_deref(), Some("AuditMode"));

    // Provider OfflineBytes + OfflineHive+Json directory mode preserve both snapshots cleanly
    let bytes_provider = PostureDefenderStatusProvider::new(ForensicSource::OfflineBytes(two.to_vec()));
    let bytes_tbl = bytes_provider
        .query(&TableQuery::default())
        .expect("provider 2-element JSON");
    assert_eq!(bytes_tbl.total_rows, 2);

    let ev_dir = TempDir::new().unwrap();
    fs::write(
        ev_dir.path().join("SOFTWARE"),
        build_synthetic_defender_regf_bytes(false),
    )
    .unwrap();
    fs::write(ev_dir.path().join("defender_status.json"), two).unwrap();
    let dir_provider = PostureDefenderStatusProvider::new(ForensicSource::OfflinePath(ev_dir.path().to_path_buf()));
    let dir_tbl = dir_provider
        .query(&TableQuery::default())
        .expect("dir OfflineHive+Json with 2-element array");
    assert_eq!(dir_tbl.total_rows, 2);
    assert_eq!(dir_tbl.rows[0].cells[9], CellValue::Text("4.18.1".to_string()));
    assert_eq!(dir_tbl.rows[1].cells[9], CellValue::Text("4.18.2".to_string()));
    assert_eq!(dir_tbl.rows[1].cells[16], CellValue::Text("AuditMode".to_string()));
}

#[test]
fn cbs_log_bom_only_via_offline_path_returns_zero_rows_cleanly() {
    let dir = TempDir::new().unwrap();
    let utf8_bom_cbs = dir.path().join("CBS.log");
    fs::write(&utf8_bom_cbs, [0xEF, 0xBB, 0xBF]).unwrap();

    let utf8_file_provider = PostureFullUpdatesProvider::new(ForensicSource::OfflinePath(utf8_bom_cbs));
    let utf8_tbl = utf8_file_provider
        .query(&TableQuery::default())
        .expect("UTF-8 BOM-only CBS.log file");
    assert_eq!(utf8_tbl.total_rows, 0);

    let utf16_bom_cbs = dir.path().join("CBS.persist.log");
    fs::write(&utf16_bom_cbs, [0xFF, 0xFE]).unwrap();

    let utf16_file_provider = PostureFullUpdatesProvider::new(ForensicSource::OfflinePath(utf16_bom_cbs));
    let utf16_tbl = utf16_file_provider
        .query(&TableQuery::default())
        .expect("UTF-16LE BOM-only CBS.persist.log file");
    assert_eq!(utf16_tbl.total_rows, 0);

    // Directory discovery containing both BOM-only CBS logs must also succeed with 0 rows
    let dir_provider = PostureFullUpdatesProvider::new(ForensicSource::OfflinePath(dir.path().to_path_buf()));
    let dir_tbl = dir_provider
        .query(&TableQuery::default())
        .expect("directory with BOM-only CBS logs");
    assert_eq!(dir_tbl.total_rows, 0);
}

#[test]
fn security_center_json_rejects_unrelated_objects() {
    let unrelated = br#"{"computer_status": {"AMServiceEnabled": true}}"#;
    let err = parse_security_center_json(unrelated, "unrelated.json").unwrap_err();
    assert!(matches!(err, ForensicError::Parse { .. }));

    let provider = PostureSecurityCenterProvider::new(ForensicSource::OfflineBytes(unrelated.to_vec()));
    assert!(provider.query(&TableQuery::default()).is_err());

    // Explicitly empty object/array and single-product object remain accepted
    let (empty_obj, _) = parse_security_center_json(b"{}", "empty.json").expect("empty {}");
    assert!(empty_obj.is_empty());

    let single = br#"{"displayName": "Windows Defender", "productState": 397568}"#;
    let (single_recs, _) = parse_security_center_json(single, "single.json").expect("single product object");
    assert_eq!(single_recs.len(), 1);
    assert_eq!(single_recs[0].display_name, "Windows Defender");
    assert_eq!(single_recs[0].enabled, Some(true));
}

#[cfg(windows)]
#[test]
fn windows_live_non_elevated_smoke_tests() {
    for provider in all_providers(&ForensicSource::Live) {
        let res = provider.query(&TableQuery {
            limit: Some(10),
            ..Default::default()
        });
        assert!(
            res.is_ok(),
            "live non-elevated query failed for {}: {:?}",
            provider.tool_id(),
            res.err()
        );
    }
}

#[test]
fn r4_compliance_zero_prohibited_apis_in_posture_crate() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    // Construct forbidden tokens via concat! so this test file doesn't match its own literals.
    let forbidden = [
        concat!("NtUninstall", "KB"),
        concat!("WinUpdates", "List"),
        concat!("CryptUnprotect", "Data"),
        concat!("CredEnumerate", "W"),
        concat!("CreateRemote", "Thread"),
        concat!("SetWindowsHook", "Ex"),
        concat!("Set-Mp", "Preference"),
        concat!("SetDefault", "Product("),
    ];

    for entry in fs::read_dir(&src_dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) == Some("rs")
            && path.file_name().and_then(|n| n.to_str()) != Some("tests.rs")
        {
            let content = fs::read_to_string(&path).expect("read rs");
            for token in &forbidden {
                assert!(
                    !content.contains(token),
                    "R4 violation: found prohibited token '{token}' in {}",
                    path.display()
                );
            }
        }
    }
}
