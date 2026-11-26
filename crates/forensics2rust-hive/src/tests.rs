use std::collections::HashSet;
use std::io::Write;

use chrono::{TimeZone, Utc};
use forensics2rust_core::{ForensicError, ForensicSource, QueryHelper, utc_to_filetime};
use guap_table::{TableProvider, TableQuery};
use tempfile::NamedTempFile;

use crate::etw::{
    EVENT_HEADER_FLAG_64_BIT_HEADER_U16, EtwRegistryDecoderState, WatchOptions, encode_f2retw01_trace,
    export_watch_reg_script, normalize_nt_registry_path, parse_offline_watch_bytes,
};
use crate::providers::{
    FindCriteria, OfflineFinderProvider, OfflineRegistryProvider, RegWatchProvider, RegistryChangesProvider,
    RegistryFileExportProvider, RegistryScannerProvider, RegistrySnapshotEntry, ScanOptions,
};
use crate::reg_format::{RegExportFormat, RegExportOptions, export_hive, parse_reg_script};
use crate::regf::builder::{BuilderValue, RegfBuilder, SubkeyListKind};
use crate::regf::{
    REG_DWORD, REG_NONE, REG_QWORD, REG_SZ, RegValueData, RegfHive, compute_regf_checksum, encode_utf16_le_nul,
};
use crate::{all_providers, crate_info, domain_tools};

fn ts(year: i32, month: u32, day: u32, hour: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, hour, 0, 0).unwrap()
}

fn build_base_fixture_bytes() -> Vec<u8> {
    let t1 = ts(2026, 2, 1, 10);
    let t2 = ts(2026, 3, 15, 14);
    let mut b = RegfBuilder::new("ROOT").with_header_timestamp(t1);
    b.set_root_list_kind(SubkeyListKind::Lh);

    b.set_key_timestamp("Software\\GuapTest", t1)
        .add_sz("Software\\GuapTest", "", "DefaultValueText")
        .add_sz(
            "Software\\GuapTest",
            "AppPath",
            "C:\\Program Files\\Guap \"Tool\"\\app.exe",
        )
        .add_expand_sz("Software\\GuapTest", "EnvPath", "%SystemRoot%\\System32")
        .add_link(
            "Software\\GuapTest",
            "LinkTarget",
            "\\Registry\\Machine\\Software\\Target",
        )
        .add_dword("Software\\GuapTest", "BuildNum", 42)
        .add_dword_be("Software\\GuapTest", "BigEndian", 0x1234_5678)
        .add_qword("Software\\GuapTest", "TotalBytes", 0x0102_0304_0506_0708)
        .add_binary(
            "Software\\GuapTest",
            "RawBlob",
            vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
        )
        .add_multi_sz(
            "Software\\GuapTest",
            "SearchOrder",
            &["Alpha".to_owned(), "Beta".to_owned(), "Gamma".to_owned()],
        )
        .add_none("Software\\GuapTest", "EmptyType", vec![])
        .add_raw_value("Software\\GuapTest", "CustomType", 0x42, vec![0xAA, 0xBB, 0xCC]);

    // UTF-16LE non-Latin-1 key & value names + lf subkey list
    b.set_key_list_kind("Software", SubkeyListKind::Lf);
    b.set_key_timestamp("Software\\Unicode\\Ключ", t2)
        .add_sz("Software\\Unicode\\Ключ", "Привет", "Мир");

    // Deleted unallocated key + value
    b.add_deleted_key(
        "Software",
        "DeletedKey",
        t2,
        vec![BuilderValue {
            name: "DeletedVal".to_owned(),
            raw_type: REG_SZ,
            raw_bytes: encode_utf16_le_nul("SecretTrail"),
        }],
    );

    b.build()
}

fn build_modified_fixture_bytes() -> Vec<u8> {
    let t1 = ts(2026, 2, 1, 10);
    let t3 = ts(2026, 4, 20, 18);
    let mut b = RegfBuilder::new("ROOT").with_header_timestamp(t1);

    // Same AppPath, modified BuildNum, removed EmptyType, added NewKey/NewVal
    b.set_key_timestamp("Software\\GuapTest", t3)
        .add_sz("Software\\GuapTest", "", "DefaultValueText")
        .add_sz(
            "Software\\GuapTest",
            "AppPath",
            "C:\\Program Files\\Guap \"Tool\"\\app.exe",
        )
        .add_dword("Software\\GuapTest", "BuildNum", 99)
        .add_sz("Software\\AddedKey", "NewVal", "FreshEntry");

    b.build()
}

#[test]
fn catalog_and_all_providers_match_6_read_only_tools() {
    assert_eq!(crate_info().0, "forensics2rust-hive");
    let catalog = domain_tools();
    assert_eq!(catalog.len(), 6);

    let providers = all_providers(&ForensicSource::OfflineBytes(build_base_fixture_bytes()));
    assert_eq!(providers.len(), 6);

    for (desc, prov) in catalog.iter().zip(providers.iter()) {
        assert_eq!(prov.tool_id(), desc.tool_id);
        assert_eq!(prov.description(), desc.description);
        assert!(prov.is_read_only());
        assert_eq!(prov.schema().tool_id, desc.tool_id);
    }
}

#[test]
fn regf_checksum_edge_cases_and_dirty_hive_detection() {
    let mut zero_xor_block = vec![0u8; 4096];
    assert_eq!(compute_regf_checksum(&zero_xor_block), 1);

    zero_xor_block[0..4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    assert_eq!(compute_regf_checksum(&zero_xor_block), 0xFFFF_FFFE);

    let bytes = RegfBuilder::new("ROOT").with_sequences(15, 14).build();
    assert!(bytes.len() >= 8192);

    let hive = RegfHive::from_bytes(&bytes).expect("dirty hive should parse");
    assert!(hive.header().is_dirty);
    assert!(hive.header().checksum_valid);
    assert!(hive.diagnostics().iter().any(|d| d.contains("dirty hive")));
}

#[test]
fn regf_parses_all_value_types_subkey_lists_and_big_data_db() {
    let bytes = build_base_fixture_bytes();
    let hive = RegfHive::from_bytes(&bytes).expect("base fixture should parse");

    let root = hive.root_key().expect("root key present");
    assert_eq!(root.name(), "ROOT");
    assert_eq!(root.path(), "");

    // Case-insensitive + slash normalization
    let guap = hive.find_key("/software//guaptest/").expect("find_key GuapTest");
    assert_eq!(guap.path(), "Software\\GuapTest");

    assert_eq!(guap.value("").and_then(|v| v.data.as_str()), Some("DefaultValueText"));
    assert_eq!(
        guap.value("apppath").and_then(|v| v.data.as_str()),
        Some("C:\\Program Files\\Guap \"Tool\"\\app.exe")
    );
    assert_eq!(
        guap.value("EnvPath").map(|v| &v.data),
        Some(&RegValueData::ExpandSz("%SystemRoot%\\System32".to_owned()))
    );
    assert_eq!(
        guap.value("LinkTarget").map(|v| &v.data),
        Some(&RegValueData::Link("\\Registry\\Machine\\Software\\Target".to_owned()))
    );
    assert_eq!(guap.value("BuildNum").and_then(|v| v.data.as_u32()), Some(42));
    assert_eq!(
        guap.value("BigEndian").map(|v| &v.data),
        Some(&RegValueData::DwordBigEndian(0x1234_5678))
    );
    assert_eq!(
        guap.value("TotalBytes").and_then(|v| v.data.as_u64()),
        Some(0x0102_0304_0506_0708)
    );
    assert_eq!(
        guap.value("RawBlob").and_then(|v| v.data.as_bytes()),
        Some(&[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06][..])
    );
    assert_eq!(
        guap.value("SearchOrder").and_then(|v| v.data.as_multi_sz()),
        Some(&["Alpha".to_owned(), "Beta".to_owned(), "Gamma".to_owned()][..])
    );
    assert_eq!(guap.value("EmptyType").map(|v| &v.data), Some(&RegValueData::None));
    assert!(matches!(
        guap.value("CustomType").map(|v| &v.data),
        Some(RegValueData::Other { raw_type: 0x42, .. })
    ));

    // Unicode UTF-16LE subkey
    let uni = hive.find_key("Software\\Unicode\\Ключ").expect("Unicode key");
    assert_eq!(uni.value("Привет").and_then(|v| v.data.as_str()), Some("Мир"));

    // Multi-hbin + db big data (> 16344 bytes) + ri -> li subkey list
    let big_blob: Vec<u8> = (0..20_000usize).map(|i| (i % 251) as u8).collect();
    let mut multi = RegfBuilder::new("BIGROOT");
    multi.set_root_list_kind(SubkeyListKind::Ri);
    for i in 0..8 {
        multi.add_dword(&format!("SubKey{i}"), "Idx", i);
    }
    multi.add_binary("SubKey0", "HugeBlob", big_blob.clone());
    let multi_bytes = multi.build();
    assert!(multi_bytes.len() >= 24_576, "expected >= 24 KiB multi-hbin hive");

    let multi_hive = RegfHive::from_bytes(&multi_bytes).expect("multi-hbin hive should parse");
    let sub0 = multi_hive.find_key("SubKey0").expect("ri->li SubKey0");
    assert_eq!(
        sub0.value("HugeBlob").and_then(|v| v.data.as_bytes()),
        Some(big_blob.as_slice())
    );

    // Verify open() and open_tolerant() from disk via NamedTempFile
    let mut tmp = NamedTempFile::new().expect("temp file");
    tmp.write_all(&multi_bytes).expect("write temp hive");
    let from_disk = RegfHive::open(tmp.path()).expect("open from disk");
    assert!(from_disk.find_key("SubKey7").is_some());
    let from_disk_tol = RegfHive::open_tolerant(tmp.path()).expect("open_tolerant from disk");
    assert!(from_disk_tol.find_key("SubKey7").is_some());

    // Direct `li` subkey list
    let mut li_b = RegfBuilder::new("LIROOT");
    li_b.set_root_list_kind(SubkeyListKind::Li);
    li_b.add_dword("Alpha", "One", 1).add_dword("Beta", "Two", 2);
    let li_hive = RegfHive::from_bytes(&li_b.build()).expect("li hive");
    assert_eq!(
        li_hive.find_key("Beta").unwrap().value("Two").unwrap().data.as_u32(),
        Some(2)
    );
}

#[test]
fn regf_handles_corrupt_cyclic_and_oversized_inputs_without_panic() {
    // 1. Truncated < 4096 bytes rejected in strict mode
    assert!(RegfHive::from_bytes(b"regfshort").is_err());

    // 2. Cyclic nk subkey list pointing back to root nk offset + oversized raw_data_length
    let mut bytes = build_base_fixture_bytes();
    let root_off = u32::from_le_bytes(bytes[0x24..0x28].try_into().unwrap());
    let root_abs = 0x1000 + root_off as usize;
    let sub_list_off = u32::from_le_bytes(bytes[root_abs + 4 + 0x1C..root_abs + 4 + 0x20].try_into().unwrap());
    let list_abs = 0x1000 + sub_list_off as usize;
    // Patch first child offset in root's lh list to point back to root_off (cycle!)
    bytes[list_abs + 4 + 4..list_abs + 4 + 8].copy_from_slice(&root_off.to_le_bytes());

    let cyclic_hive = RegfHive::from_bytes(&bytes).expect("cycle guard prevents infinite loop");
    assert!(cyclic_hive.diagnostics().iter().any(|d| d.contains("cycle")));

    // 3. Corrupt ri self-cycle + truncated EOF + huge raw_data_length
    let mut ri_hive = RegfBuilder::new("R");
    ri_hive.set_root_list_kind(SubkeyListKind::Ri);
    ri_hive.add_binary("A", "HugeClaim", vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let mut ri_bytes = ri_hive.build();
    let r_root_off = u32::from_le_bytes(ri_bytes[0x24..0x28].try_into().unwrap()) as usize;
    let ri_off = u32::from_le_bytes(
        ri_bytes[0x1000 + r_root_off + 4 + 0x1C..0x1000 + r_root_off + 4 + 0x20]
            .try_into()
            .unwrap(),
    );
    let ri_abs = 0x1000 + ri_off as usize;
    // Point first entry of ri back to ri_off itself
    ri_bytes[ri_abs + 4 + 4..ri_abs + 4 + 8].copy_from_slice(&ri_off.to_le_bytes());
    // Also find first vk signature and overwrite raw_data_length to 0x7FFF_FFFF (OOM guard)
    if let Some(pos) = ri_bytes[0x1000..].windows(2).position(|w| w == b"vk") {
        let vk_abs = 0x1000 + pos;
        ri_bytes[vk_abs + 0x04..vk_abs + 0x08].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
    }
    // Truncate tail slightly
    ri_bytes.truncate(ri_bytes.len() - 500);

    let tolerant = RegfHive::from_bytes_tolerant(&ri_bytes).expect("tolerant recovery survives truncation and cycle");
    assert!(!tolerant.diagnostics().is_empty());
}

#[test]
fn carve_unallocated_and_reg_file_export_recover_deleted_cells() {
    let bytes = build_base_fixture_bytes();
    let hive = RegfHive::from_bytes_tolerant(&bytes).expect("tolerant parse");
    let recovered = hive.carve_unallocated();
    assert!(!recovered.is_empty(), "expected deleted key carved");
    let del = recovered
        .iter()
        .find(|k| k.name == "DeletedKey")
        .expect("DeletedKey recovered");
    assert!(del.is_deleted);
    assert!(del.path.contains("Software\\DeletedKey"));
    assert_eq!(
        del.values
            .iter()
            .find(|v| v.name == "DeletedVal")
            .and_then(|v| v.data.as_str()),
        Some("SecretTrail")
    );

    let exporter = RegistryFileExportProvider::new(ForensicSource::OfflineBytes(bytes))
        .with_format(RegExportFormat::Regedit5)
        .with_root_name("HKEY_LOCAL_MACHINE\\TESTHIVE");
    let res = exporter.export_to_result().expect("export result");
    assert!(res.recovered_cells >= 2);
    assert!(res.bytes.starts_with(&[0xFF, 0xFE])); // UTF-16LE BOM
    assert!(res.text.starts_with("Windows Registry Editor Version 5.00"));
    assert!(res.text.contains("@=\"DefaultValueText\""));
    assert!(
        res.text
            .contains("\"AppPath\"=\"C:\\\\Program Files\\\\Guap \\\"Tool\\\"\\\\app.exe\"")
    );
    assert!(res.text.contains("dword:0000002a"));
    assert!(res.text.contains("hex(b):08,07,06,05,04,03,02,01"));
    assert!(res.text.contains("SecretTrail"));

    // Verify 80-col wrapping on large hex value
    let mut long_b = RegfBuilder::new("WRAP");
    long_b.add_binary("Long", "Blob", (0u8..80u8).collect());
    let long_exp = RegistryFileExportProvider::new(ForensicSource::OfflineBytes(long_b.build()))
        .export_to_string()
        .expect("long export");
    assert!(long_exp.contains("\\\r\n  "));

    // Verify REGEDIT4 export
    let v4 = RegistryFileExportProvider::new(ForensicSource::OfflineBytes(build_base_fixture_bytes()))
        .with_format(RegExportFormat::Regedit4)
        .export_to_result()
        .expect("v4 export");
    assert!(v4.text.starts_with("REGEDIT4"));
    assert!(!v4.bytes.starts_with(&[0xFF, 0xFE]));

    // Provider table rows
    let table = exporter.query(&TableQuery::default()).expect("export table query");
    assert!(table.total_rows >= 4);
}

#[test]
fn reg_format_roundtrip_and_reg_watch_offline_reg_parsing() {
    let bytes = build_base_fixture_bytes();
    let exporter = RegistryFileExportProvider::new(ForensicSource::OfflineBytes(bytes))
        .with_include_deleted(false)
        .with_root_name("HKEY_LOCAL_MACHINE\\SOFTWARE\\RoundTrip");
    let exported = exporter.export_to_result().expect("export");

    // Parse exported UTF-16LE BOM .reg bytes back via RegWatchProvider
    let watch = RegWatchProvider::new(ForensicSource::OfflineBytes(exported.bytes.clone()));
    let events = watch.collect_events().expect("parse exported .reg");
    assert!(
        events
            .iter()
            .any(|e| e.operation == "CreateKey" && e.key_path.contains("GuapTest"))
    );
    assert!(events.iter().any(|e| {
        e.operation == "SetValue"
            && e.value_name.as_deref() == Some("BuildNum")
            && e.data == Some(RegValueData::Dword(42))
    }));
    assert!(events.iter().any(|e| {
        e.operation == "SetValue"
            && e.value_name.as_deref() == Some("")
            && e.data == Some(RegValueData::Sz("DefaultValueText".to_owned()))
    }));

    // Also verify [-HKEY_...] and "Val"=- deletions in .reg script
    let script = "Windows Registry Editor Version 5.00\r\n\r\n\
        [HKEY_CURRENT_USER\\Software\\Demo]\r\n\
        \"Keep\"=dword:00000001\r\n\
        \"Drop\"=-\r\n\r\n\
        [-HKEY_CURRENT_USER\\Software\\Obsolete]\r\n";
    let parsed = parse_reg_script(script.as_bytes()).expect("parse delete script");
    assert_eq!(parsed.len(), 4);
    assert_eq!(parsed[2].operation.as_str(), "DeleteValue");
    assert_eq!(parsed[3].operation.as_str(), "DeleteKey");
}

#[test]
fn registry_changes_diff_detects_added_modified_and_deleted() {
    let left = ForensicSource::OfflineBytes(build_base_fixture_bytes());
    let right = ForensicSource::OfflineBytes(build_modified_fixture_bytes());

    let diff = RegistryChangesProvider::between(left, right);
    let data = diff.query(&TableQuery::default()).expect("diff query");

    let change_idx = data.schema.column_index("ChangeType").unwrap();
    let key_idx = data.schema.column_index("KeyPath").unwrap();
    let val_idx = data.schema.column_index("ValueName").unwrap();
    let old_idx = data.schema.column_index("OldData").unwrap();
    let new_idx = data.schema.column_index("NewData").unwrap();

    let mut saw_added = false;
    let mut saw_modified = false;
    let mut saw_deleted = false;

    for row in &data.rows {
        let kind = row.cells[change_idx].to_string();
        let kp = row.cells[key_idx].to_string();
        let vn = row.cells[val_idx].to_string();
        if kind == "Added" && kp == "Software\\AddedKey" && vn == "NewVal" {
            saw_added = true;
            assert_eq!(row.cells[new_idx].to_string(), "FreshEntry");
        }
        if kind == "Modified" && kp == "Software\\GuapTest" && vn == "BuildNum" {
            saw_modified = true;
            assert!(row.cells[old_idx].to_string().starts_with("42"));
            assert!(row.cells[new_idx].to_string().starts_with("99"));
        }
        if kind == "Deleted" && kp == "Software\\GuapTest" && vn == "EmptyType" {
            saw_deleted = true;
        }
    }

    assert!(saw_added, "expected Added Software\\AddedKey\\NewVal");
    assert!(saw_modified, "expected Modified BuildNum");
    assert!(saw_deleted, "expected Deleted EmptyType");

    // JSON snapshot diff test
    let snap_pair = serde_json::json!({
        "left": [
            RegistrySnapshotEntry {
                key_path: "HKCU\\Run".to_owned(),
                value_name: "Updater".to_owned(),
                value_type: "REG_SZ".to_owned(),
                data_decoded: "old.exe".to_owned(),
                timestamp: None,
            }
        ],
        "right": [
            RegistrySnapshotEntry {
                key_path: "HKCU\\Run".to_owned(),
                value_name: "Updater".to_owned(),
                value_type: "REG_SZ".to_owned(),
                data_decoded: "new.exe".to_owned(),
                timestamp: None,
            }
        ]
    });
    let json_diff = RegistryChangesProvider::new(ForensicSource::OfflineBytes(serde_json::to_vec(&snap_pair).unwrap()));
    let jdata = json_diff.query(&TableQuery::default()).expect("json diff");
    assert_eq!(jdata.total_rows, 1);
}

#[test]
fn offline_finder_searches_string_hex_type_and_date() {
    let src = ForensicSource::OfflineBytes(build_base_fixture_bytes());

    // 1. Hex search
    let hex_finder = OfflineFinderProvider::new(src.clone())
        .with_criteria(FindCriteria::default().with_hex(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    let hex_res = hex_finder.query(&TableQuery::default()).expect("hex find");
    assert_eq!(hex_res.total_rows, 1);
    assert_eq!(hex_res.rows[0].cells[2].to_string(), "RawBlob");

    // 2. String search (case-insensitive)
    let str_finder = OfflineFinderProvider::new(src.clone()).with_criteria(FindCriteria::default().with_text("guap"));
    let str_res = str_finder.query(&TableQuery::default()).expect("str find");
    assert!(str_res.total_rows >= 2);

    // 3. Value type + date window search
    let qword_finder = OfflineFinderProvider::new(src).with_criteria(FindCriteria {
        value_types: vec![REG_QWORD],
        modified_after: Some(ts(2026, 1, 1, 0)),
        modified_before: Some(ts(2026, 3, 1, 0)),
        ..Default::default()
    });
    let q_res = qword_finder.query(&TableQuery::default()).expect("qword date find");
    assert_eq!(q_res.total_rows, 1);
    assert_eq!(q_res.rows[0].cells[2].to_string(), "TotalBytes");
}

fn push_utf16_nul(out: &mut Vec<u8>, s: &str) {
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out.extend_from_slice(&[0, 0]);
}

#[test]
fn etw_f2retw01_decodes_all_15_events_and_caches_key_objects() {
    assert_eq!(
        normalize_nt_registry_path("\\REGISTRY\\MACHINE\\Software\\Test"),
        "HKEY_LOCAL_MACHINE\\Software\\Test"
    );
    assert_eq!(
        normalize_nt_registry_path("\\REGISTRY\\USER\\S-1-5-21\\Software"),
        "HKEY_USERS\\S-1-5-21\\Software"
    );

    let ft = utc_to_filetime(ts(2026, 5, 1, 12)).unwrap();
    let flags = EVENT_HEADER_FLAG_64_BIT_HEADER_U16;
    let key_obj: u64 = 0xFFFF_8000_1234_5678;

    // EID 1: CreateKey
    let mut ud1 = Vec::new();
    ud1.extend_from_slice(&0u64.to_le_bytes());
    ud1.extend_from_slice(&key_obj.to_le_bytes());
    ud1.extend_from_slice(&0u32.to_le_bytes());
    ud1.extend_from_slice(&1u32.to_le_bytes());
    push_utf16_nul(&mut ud1, "\\REGISTRY\\MACHINE\\Software");
    push_utf16_nul(&mut ud1, "GuapEtw");

    // EID 2: OpenKey
    let mut ud2 = ud1.clone();
    ud2[8..16].copy_from_slice(&(key_obj + 8).to_le_bytes());

    // EID 5: SetValueKey with empty KeyName -> resolved via cached key_obj!
    let mut ud5 = Vec::new();
    ud5.extend_from_slice(&key_obj.to_le_bytes());
    ud5.extend_from_slice(&0u32.to_le_bytes()); // Status
    ud5.extend_from_slice(&REG_DWORD.to_le_bytes());
    ud5.extend_from_slice(&4u32.to_le_bytes()); // DataSize
    push_utf16_nul(&mut ud5, ""); // empty KeyName -> resolved via key_obj!
    push_utf16_nul(&mut ud5, "Enabled");
    ud5.extend_from_slice(&4u16.to_le_bytes()); // CapturedDataSize
    ud5.extend_from_slice(&1u32.to_le_bytes()); // CapturedData
    // Optional trailing Win10/11 PreviousData*
    ud5.extend_from_slice(&REG_DWORD.to_le_bytes());
    ud5.extend_from_slice(&4u32.to_le_bytes());
    ud5.extend_from_slice(&4u16.to_le_bytes());
    ud5.extend_from_slice(&0u32.to_le_bytes());

    // EID 6: DeleteValueKey
    let mut ud6 = Vec::new();
    ud6.extend_from_slice(&key_obj.to_le_bytes());
    ud6.extend_from_slice(&0u32.to_le_bytes());
    push_utf16_nul(&mut ud6, "");
    push_utf16_nul(&mut ud6, "OldFlag");

    // EID 4 & 11: QueryKey / SetInformationKey
    let mut ud4 = Vec::new();
    ud4.extend_from_slice(&key_obj.to_le_bytes());
    ud4.extend_from_slice(&0u32.to_le_bytes());
    ud4.extend_from_slice(&1u32.to_le_bytes());
    ud4.extend_from_slice(&0u32.to_le_bytes());
    push_utf16_nul(&mut ud4, "");
    ud4.extend_from_slice(&0u16.to_le_bytes());

    // EID 7: QueryValueKey
    let mut ud7 = Vec::new();
    ud7.extend_from_slice(&key_obj.to_le_bytes());
    ud7.extend_from_slice(&0u32.to_le_bytes());
    ud7.extend_from_slice(&2u32.to_le_bytes());
    ud7.extend_from_slice(&4u32.to_le_bytes());
    push_utf16_nul(&mut ud7, "");
    push_utf16_nul(&mut ud7, "Enabled");
    ud7.extend_from_slice(&4u16.to_le_bytes());
    ud7.extend_from_slice(&1u32.to_le_bytes());

    // EID 8 & 9: EnumerateKey / EnumerateValueKey
    let mut ud8 = Vec::new();
    ud8.extend_from_slice(&key_obj.to_le_bytes());
    ud8.extend_from_slice(&0u32.to_le_bytes());
    ud8.extend_from_slice(&0u32.to_le_bytes());
    ud8.extend_from_slice(&1u32.to_le_bytes());
    ud8.extend_from_slice(&0u32.to_le_bytes());
    push_utf16_nul(&mut ud8, "");
    ud8.extend_from_slice(&0u16.to_le_bytes());

    // EID 10: QueryMultipleValueKey
    let mut ud10 = Vec::new();
    ud10.extend_from_slice(&key_obj.to_le_bytes());
    ud10.extend_from_slice(&0u32.to_le_bytes());
    ud10.extend_from_slice(&2u32.to_le_bytes());
    ud10.extend_from_slice(&8u32.to_le_bytes());
    push_utf16_nul(&mut ud10, "");

    // EID 12, 14, 15, 3, 13 (KeyObject + Status + KeyName)
    let mut ud_simple = Vec::new();
    ud_simple.extend_from_slice(&key_obj.to_le_bytes());
    ud_simple.extend_from_slice(&0u32.to_le_bytes());
    push_utf16_nul(&mut ud_simple, "");

    let mut ud13 = Vec::new();
    ud13.extend_from_slice(&(key_obj + 8).to_le_bytes());
    ud13.extend_from_slice(&0u32.to_le_bytes());
    push_utf16_nul(&mut ud13, "");

    let trace = encode_f2retw01_trace(&[
        (1, flags, 1234, ft, &ud1),
        (2, flags, 1234, ft, &ud2),
        (4, flags, 1234, ft, &ud4),
        (5, flags, 1234, ft, &ud5),
        (6, flags, 1234, ft, &ud6),
        (7, flags, 1234, ft, &ud7),
        (8, flags, 1234, ft, &ud8),
        (9, flags, 1234, ft, &ud8),
        (10, flags, 1234, ft, &ud10),
        (11, flags, 1234, ft, &ud4),
        (12, flags, 1234, ft, &ud_simple),
        (14, flags, 1234, ft, &ud_simple),
        (15, flags, 1234, ft, &ud_simple),
        (3, flags, 1234, ft, &ud_simple),
        (13, flags, 1234, ft, &ud13),
    ]);

    let watch = RegWatchProvider::new(ForensicSource::OfflineBytes(trace)).with_options(WatchOptions {
        mutations_only: false,
        ..Default::default()
    });
    let events = watch.collect_events().expect("F2RETW01 trace should decode");
    assert_eq!(events.len(), 15);

    let seen_ids: HashSet<u16> = events.iter().map(|e| e.event_id).collect();
    for id in 1..=15u16 {
        assert!(seen_ids.contains(&id), "missing decoded EID {id}");
    }

    let set_ev = events.iter().find(|e| e.event_id == 5).unwrap();
    assert_eq!(set_ev.key_path, "HKEY_LOCAL_MACHINE\\Software\\GuapEtw");
    assert_eq!(set_ev.value_name.as_deref(), Some("Enabled"));
    assert_eq!(set_ev.reg_dotnet_line, "\"Enabled\"=dword:00000001");

    let script = export_watch_reg_script(&events);
    assert!(script.contains("[HKEY_LOCAL_MACHINE\\Software\\GuapEtw]"));
    assert!(script.contains("\"Enabled\"=dword:00000001"));
    assert!(script.contains("\"OldFlag\"=-"));
    assert!(script.contains("[-HKEY_LOCAL_MACHINE\\Software\\GuapEtw]"));

    // Verify 32-bit pointer SetValue without trailing PreviousData*
    let mut decoder = EtwRegistryDecoderState::new();
    let mut ud5_32 = Vec::new();
    ud5_32.extend_from_slice(&0x1020_3040u32.to_le_bytes());
    ud5_32.extend_from_slice(&0u32.to_le_bytes());
    ud5_32.extend_from_slice(&REG_SZ.to_le_bytes());
    ud5_32.extend_from_slice(&6u32.to_le_bytes());
    push_utf16_nul(&mut ud5_32, "\\REGISTRY\\MACHINE\\Software\\Legacy");
    push_utf16_nul(&mut ud5_32, "Ver");
    ud5_32.extend_from_slice(&6u16.to_le_bytes());
    push_utf16_nul(&mut ud5_32, "v1");
    let ev32 = decoder
        .decode_record(5, 36, 4, 42, 1, ts(2026, 5, 1, 12), "app.exe".to_owned(), &ud5_32)
        .expect("32-bit SetValue");
    assert_eq!(ev32.key_path, "HKEY_LOCAL_MACHINE\\Software\\Legacy");
    assert_eq!(ev32.reg_dotnet_line, "\"Ver\"=\"v1\"");

    // Verify JSON ETW fixture
    let json_bytes = serde_json::to_vec(&vec![serde_json::json!({
        "pid": 888,
        "process_name": "regedit.exe",
        "event_id": 5,
        "key_path": "HKCU\\Software\\JsonTest",
        "value_name": "Count",
        "value_type": 4,
        "data_hex": "07000000"
    })])
    .unwrap();
    let json_watch = RegWatchProvider::new(ForensicSource::OfflineBytes(json_bytes));
    let jtable = json_watch.query(&TableQuery::default()).expect("json watch query");
    assert_eq!(jtable.total_rows, 1);
    assert_eq!(jtable.rows[0].cells[6].to_string(), "\"Count\"=dword:00000007");
}

#[test]
fn guap_query_works_by_both_column_id_and_label() {
    let src = ForensicSource::OfflineBytes(build_base_fixture_bytes());
    let offline = OfflineRegistryProvider::new(src.clone());

    let schema = offline.schema();
    // Filter using PascalCase label, sort using snake_case id, project mixed id+label
    let q = QueryHelper::build_query(
        &schema,
        Some(vec![
            "key_path".to_owned(),
            "ValueName".to_owned(),
            "value_type".to_owned(),
            "DataDecoded".to_owned(),
        ]),
        Some("ValueType = \"REG_DWORD\""),
        Some("-ValueName"),
        0,
        Some(10),
    )
    .expect("GuapQuery should parse mixed id/label");

    let res = offline.query(&q).expect("execute GuapQuery");
    assert_eq!(res.total_rows, 1);
    assert_eq!(res.schema.columns.len(), 4);
    assert_eq!(res.rows[0].cells[1].to_string(), "BuildNum");

    // Scan provider GuapQuery on offline hive using BytesSize numeric filter
    let scan = RegistryScannerProvider::new(src);
    let scan_q = QueryHelper::build_query(
        &scan.schema(),
        None,
        Some("DataLen >= 8 && ValueType != \"REG_BINARY\""),
        Some("ValueName"),
        0,
        None,
    )
    .expect("scan GuapQuery");
    let scan_res = scan.query(&scan_q).expect("scan query");
    assert!(scan_res.total_rows >= 3);
}

#[test]
fn live_registry_and_etw_error_handling_graceful() {
    // Live offline-only tools reject Live cleanly
    let offline_live = OfflineRegistryProvider::new(ForensicSource::Live);
    assert!(offline_live.query(&TableQuery::default()).is_err());

    let find_live = OfflineFinderProvider::new(ForensicSource::Live);
    assert!(find_live.query(&TableQuery::default()).is_err());

    let export_live = RegistryFileExportProvider::new(ForensicSource::Live);
    assert!(export_live.query(&TableQuery::default()).is_err());

    // Live ETW: non-elevated => PermissionDenied (or succeeds if elevated on Windows; UnsupportedPlatform elsewhere)
    let watch_live = RegWatchProvider::new(ForensicSource::Live).with_options(crate::etw::WatchOptions {
        duration_ms: 50,
        max_events: 10,
        ..Default::default()
    });
    let watch_res = watch_live.collect_events();
    #[cfg(windows)]
    match watch_res {
        Ok(_) => {}
        Err(ForensicError::PermissionDenied { .. }) => {}
        Err(other) => panic!("unexpected live ETW error: {other}"),
    }
    #[cfg(not(windows))]
    assert!(matches!(watch_res, Err(ForensicError::UnsupportedPlatform { .. })));

    // Live Registry scan on HKCU\Software (bounded depth=1, max_keys=10)
    let scan_live = RegistryScannerProvider::new(ForensicSource::Live).with_options(ScanOptions {
        roots: vec!["HKCU\\Software".to_owned()],
        max_depth: Some(1),
        max_keys: Some(10),
        include_keys_without_values: true,
        ..Default::default()
    });
    let scan_res = scan_live.collect_rows();
    #[cfg(windows)]
    assert!(
        scan_res.is_ok(),
        "HKCU\\Software live scan should succeed: {scan_res:?}"
    );
    #[cfg(not(windows))]
    assert!(matches!(scan_res, Err(ForensicError::UnsupportedPlatform { .. })));

    // Live Registry non-existent root -> NotFound (on Windows), protected root HKLM\SECURITY -> PermissionDenied or Ok (if elevated),
    // and HKLM top-level descent skips protected child keys with DiagnosticWarning without aborting.
    #[cfg(windows)]
    {
        let missing_live = RegistryScannerProvider::new(ForensicSource::Live).with_options(ScanOptions {
            roots: vec!["HKCU\\Software\\GUAP_NONEXISTENT_KEY_99999".to_owned()],
            ..Default::default()
        });
        assert!(matches!(missing_live.collect_rows(), Err(ForensicError::NotFound(_))));

        let sec_live = RegistryScannerProvider::new(ForensicSource::Live).with_options(ScanOptions {
            roots: vec!["HKLM\\SECURITY".to_owned()],
            max_depth: Some(0),
            max_keys: Some(1),
            ..Default::default()
        });
        match sec_live.collect_rows() {
            Ok(_) | Err(ForensicError::PermissionDenied { .. }) => {}
            Err(other) => panic!("unexpected error on HKLM\\SECURITY: {other}"),
        }

        let hklm_top = RegistryScannerProvider::new(ForensicSource::Live).with_options(ScanOptions {
            roots: vec!["HKLM".to_owned()],
            max_depth: Some(1),
            max_keys: Some(8),
            include_keys_without_values: true,
            ..Default::default()
        });
        assert!(hklm_top.collect_rows().is_ok());
    }
}

#[test]
fn etw_mutations_only_retains_key_object_cache_and_filters_non_mutations() {
    let ft = utc_to_filetime(ts(2026, 6, 1, 9)).unwrap();
    let flags = EVENT_HEADER_FLAG_64_BIT_HEADER_U16;
    let opened_obj: u64 = 0xFFFF_9000_0000_2222;

    // EID 2: OpenKey populates key_objects for opened_obj
    let mut ud2 = Vec::new();
    ud2.extend_from_slice(&0u64.to_le_bytes());
    ud2.extend_from_slice(&opened_obj.to_le_bytes());
    ud2.extend_from_slice(&0u32.to_le_bytes());
    ud2.extend_from_slice(&2u32.to_le_bytes());
    push_utf16_nul(&mut ud2, "\\REGISTRY\\MACHINE\\Software");
    push_utf16_nul(&mut ud2, "GuapOpen");

    // EID 4: QueryKey (non-mutation)
    let mut ud4 = Vec::new();
    ud4.extend_from_slice(&opened_obj.to_le_bytes());
    ud4.extend_from_slice(&0u32.to_le_bytes());
    ud4.extend_from_slice(&1u32.to_le_bytes());
    ud4.extend_from_slice(&0u32.to_le_bytes());
    push_utf16_nul(&mut ud4, "");
    ud4.extend_from_slice(&0u16.to_le_bytes());

    // EID 5: SetValueKey with empty KeyName -> must resolve via EID 2 OpenKey!
    let mut ud5 = Vec::new();
    ud5.extend_from_slice(&opened_obj.to_le_bytes());
    ud5.extend_from_slice(&0u32.to_le_bytes());
    ud5.extend_from_slice(&REG_DWORD.to_le_bytes());
    ud5.extend_from_slice(&4u32.to_le_bytes());
    push_utf16_nul(&mut ud5, "");
    push_utf16_nul(&mut ud5, "OpenedFlag");
    ud5.extend_from_slice(&4u16.to_le_bytes());
    ud5.extend_from_slice(&1u32.to_le_bytes());

    // EID 13: CloseKey (non-mutation, evicts cache)
    let mut ud13 = Vec::new();
    ud13.extend_from_slice(&opened_obj.to_le_bytes());
    ud13.extend_from_slice(&0u32.to_le_bytes());
    push_utf16_nul(&mut ud13, "");

    let trace = encode_f2retw01_trace(&[
        (2, flags, 500, ft, &ud2),
        (4, flags, 500, ft, &ud4),
        (5, flags, 500, ft, &ud5),
        (13, flags, 500, ft, &ud13),
    ]);

    let watch = RegWatchProvider::new(ForensicSource::OfflineBytes(trace)).with_options(WatchOptions {
        mutations_only: true,
        ..Default::default()
    });
    let events = watch.collect_events().expect("mutations_only offline watch");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_id, 5);
    assert_eq!(events[0].key_path, "HKEY_LOCAL_MACHINE\\Software\\GuapOpen");
    assert_eq!(events[0].value_name.as_deref(), Some("OpenedFlag"));
}

#[test]
fn etw_resolve_key_path_respects_segment_boundaries() {
    let mut decoder = EtwRegistryDecoderState::new();
    let t = ts(2026, 6, 2, 12);
    let key_obj: u64 = 0x1000_2000;

    let mut ud1 = Vec::new();
    ud1.extend_from_slice(&0u64.to_le_bytes());
    ud1.extend_from_slice(&key_obj.to_le_bytes());
    ud1.extend_from_slice(&0u32.to_le_bytes());
    ud1.extend_from_slice(&1u32.to_le_bytes());
    push_utf16_nul(&mut ud1, "\\REGISTRY\\MACHINE\\Software");
    push_utf16_nul(&mut ud1, "GuapEtw");

    let create_ev = decoder
        .decode_record(1, 32, 8, 100, 1, t, "app.exe".to_owned(), &ud1)
        .expect("CreateKey");
    assert_eq!(create_ev.key_path, "HKEY_LOCAL_MACHINE\\Software\\GuapEtw");

    // Relative subkey "Etw" is a string suffix of "GuapEtw", but NOT a full segment match
    let mut ud5 = Vec::new();
    ud5.extend_from_slice(&key_obj.to_le_bytes());
    ud5.extend_from_slice(&0u32.to_le_bytes());
    ud5.extend_from_slice(&REG_DWORD.to_le_bytes());
    ud5.extend_from_slice(&4u32.to_le_bytes());
    push_utf16_nul(&mut ud5, "Etw");
    push_utf16_nul(&mut ud5, "Val");
    ud5.extend_from_slice(&4u16.to_le_bytes());
    ud5.extend_from_slice(&7u32.to_le_bytes());

    let set_ev = decoder
        .decode_record(5, 36, 8, 100, 1, t, "app.exe".to_owned(), &ud5)
        .expect("SetValueKey");
    assert_eq!(set_ev.key_path, "HKEY_LOCAL_MACHINE\\Software\\GuapEtw\\Etw");
}

#[test]
fn offline_watch_parses_headerless_reg_and_rejects_binary_or_garbage() {
    let headerless = b"[HKEY_LOCAL_MACHINE\\Software\\Headerless]\r\n\"X\"=dword:00000001\r\n";
    let events = parse_offline_watch_bytes(headerless).expect("headerless .reg should parse");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].operation, "CreateKey");
    assert_eq!(events[0].key_path, "HKEY_LOCAL_MACHINE\\Software\\Headerless");
    assert_eq!(events[1].operation, "SetValue");
    assert_eq!(events[1].value_name.as_deref(), Some("X"));

    let headerless_del = b"[-HKEY_LOCAL_MACHINE\\Software\\Obsolete]\r\n";
    let del_events = parse_offline_watch_bytes(headerless_del).expect("headerless delete .reg");
    assert_eq!(del_events.len(), 1);
    assert_eq!(del_events[0].operation, "DeleteKey");

    // Valid empty .reg with recognized header
    let empty_v5 =
        parse_reg_script(b"Windows Registry Editor Version 5.00\r\n\r\n; empty\r\n").expect("valid empty v5 .reg");
    assert!(empty_v5.is_empty());

    // Raw regf binary hive and arbitrary garbage text must return Err
    let regf_bytes = build_base_fixture_bytes();
    assert!(parse_reg_script(&regf_bytes).is_err());
    assert!(
        RegWatchProvider::new(ForensicSource::OfflineBytes(regf_bytes))
            .query(&TableQuery::default())
            .is_err()
    );

    let garbage = b"NOT A REG SCRIPT AT ALL\n12345\n";
    assert!(parse_reg_script(garbage).is_err());
    assert!(parse_offline_watch_bytes(garbage).is_err());
}

#[test]
fn regedit4_roundtrip_preserves_latin1_and_expand_link_multi_sz() {
    let mut b = RegfBuilder::new("ROOT");
    b.add_sz("Software\\V4Test", "Café", "résumé")
        .add_expand_sz("Software\\V4Test", "EnvPath", "%SystemRoot%\\System32")
        .add_link("Software\\V4Test", "SymTarget", "\\Registry\\Machine\\Software\\Dest")
        .add_multi_sz("Software\\V4Test", "Items", &["First".to_owned(), "Café".to_owned()]);

    let hive = RegfHive::from_bytes(&b.build()).expect("build hive");
    let opts = RegExportOptions {
        format: RegExportFormat::Regedit4,
        root_prefix: "HKEY_LOCAL_MACHINE\\OFFLINE".to_owned(),
        include_deleted: false,
        utf8_output: false,
    };
    let exported = export_hive(&hive, &opts);
    assert!(exported.text.starts_with("REGEDIT4"));

    let parsed = parse_reg_script(&exported.bytes).expect("parse REGEDIT4 export");
    let cafe = parsed
        .iter()
        .find(|e| e.value_name.as_deref() == Some("Café"))
        .expect("Café value preserved");
    assert_eq!(cafe.data, Some(RegValueData::Sz("résumé".to_owned())));

    let env = parsed
        .iter()
        .find(|e| e.value_name.as_deref() == Some("EnvPath"))
        .expect("EnvPath value");
    assert_eq!(
        env.data,
        Some(RegValueData::ExpandSz("%SystemRoot%\\System32".to_owned()))
    );

    let link = parsed
        .iter()
        .find(|e| e.value_name.as_deref() == Some("SymTarget"))
        .expect("SymTarget value");
    assert_eq!(
        link.data,
        Some(RegValueData::Link("\\Registry\\Machine\\Software\\Dest".to_owned()))
    );

    let multi = parsed
        .iter()
        .find(|e| e.value_name.as_deref() == Some("Items"))
        .expect("Items value");
    assert_eq!(
        multi.data,
        Some(RegValueData::MultiSz(vec!["First".to_owned(), "Café".to_owned()]))
    );
}

#[test]
fn diff_suppresses_spurious_key_rows_and_unifies_reg_none() {
    // 1. Empty key gaining (Default) value must NOT emit Deleted KEY row
    let mut left_b = RegfBuilder::new("ROOT");
    left_b.add_key("Software\\DefKey");
    left_b.add_key("Software\\RemovedEmpty");

    let mut right_b = RegfBuilder::new("ROOT");
    right_b.add_sz("Software\\DefKey", "", "DefaultData");
    right_b.add_key("Software\\AddedEmpty");

    let diff = RegistryChangesProvider::between(
        ForensicSource::OfflineBytes(left_b.build()),
        ForensicSource::OfflineBytes(right_b.build()),
    );
    let data = diff.query(&TableQuery::default()).expect("diff empty vs populated");
    let change_idx = data.schema.column_index("ChangeType").unwrap();
    let key_idx = data.schema.column_index("KeyPath").unwrap();
    let val_idx = data.schema.column_index("ValueName").unwrap();
    let new_type_idx = data.schema.column_index("NewType").unwrap();
    let old_type_idx = data.schema.column_index("OldType").unwrap();

    assert!(!data.rows.iter().any(|r| {
        r.cells[change_idx].to_string() == "Deleted"
            && r.cells[key_idx].to_string() == "Software\\DefKey"
            && r.cells[old_type_idx].to_string() == "KEY"
    }));
    assert!(data.rows.iter().any(|r| {
        r.cells[change_idx].to_string() == "Added"
            && r.cells[key_idx].to_string() == "Software\\DefKey"
            && r.cells[val_idx].to_string() == "(Default)"
    }));
    assert!(data.rows.iter().any(|r| {
        r.cells[change_idx].to_string() == "Deleted"
            && r.cells[key_idx].to_string() == "Software\\RemovedEmpty"
            && r.cells[old_type_idx].to_string() == "KEY"
    }));
    assert!(data.rows.iter().any(|r| {
        r.cells[change_idx].to_string() == "Added"
            && r.cells[key_idx].to_string() == "Software\\AddedEmpty"
            && r.cells[new_type_idx].to_string() == "KEY"
    }));

    // 2. Offline regf REG_NONE vs live-equivalent snapshot using RegValueData::None.decoded_string()
    let mut none_b = RegfBuilder::new("ROOT");
    none_b.add_none("Software\\NoneKey", "N", vec![]);
    let live_equiv = serde_json::to_vec(&vec![
        RegistrySnapshotEntry {
            key_path: String::new(),
            value_name: String::new(),
            value_type: "KEY".to_owned(),
            data_decoded: String::new(),
            timestamp: None,
        },
        RegistrySnapshotEntry {
            key_path: "Software".to_owned(),
            value_name: String::new(),
            value_type: "KEY".to_owned(),
            data_decoded: String::new(),
            timestamp: None,
        },
        RegistrySnapshotEntry {
            key_path: "Software\\NoneKey".to_owned(),
            value_name: "N".to_owned(),
            value_type: "REG_NONE".to_owned(),
            data_decoded: RegValueData::None.decoded_string(),
            timestamp: None,
        },
    ])
    .unwrap();

    let none_diff = RegistryChangesProvider::between(
        ForensicSource::OfflineBytes(none_b.build()),
        ForensicSource::OfflineBytes(live_equiv),
    );
    let none_res = none_diff.query(&TableQuery::default()).expect("REG_NONE diff");
    assert_eq!(none_res.total_rows, 0);
}

#[test]
fn offline_finder_matches_reg_binary_case_insensitively() {
    let mut b = RegfBuilder::new("ROOT");
    b.add_binary("Software\\Secrets", "AsciiBlob", b"\x00\x01MySecretToken\xFF".to_vec());
    let mut u16_blob = vec![0xAA]; // odd alignment!
    for u in "MyUtf16Token".encode_utf16() {
        u16_blob.extend_from_slice(&u.to_le_bytes());
    }
    b.add_binary("Software\\Secrets", "Utf16Blob", u16_blob);

    let src = ForensicSource::OfflineBytes(b.build());

    let ascii_res = OfflineFinderProvider::new(src.clone())
        .with_criteria(FindCriteria::default().with_text("mysecrettoken"))
        .query(&TableQuery::default())
        .expect("ascii binary find");
    assert_eq!(ascii_res.total_rows, 1);
    assert_eq!(ascii_res.rows[0].cells[2].to_string(), "AsciiBlob");

    let utf16_res = OfflineFinderProvider::new(src)
        .with_criteria(FindCriteria::default().with_text("myutf16token"))
        .query(&TableQuery::default())
        .expect("utf16 binary find");
    assert_eq!(utf16_res.total_rows, 1);
    assert_eq!(utf16_res.rows[0].cells[2].to_string(), "Utf16Blob");
}

#[test]
fn scan_options_default_and_offline_key_prefix_boundary() {
    assert!(ScanOptions::default().wow64_64);

    let mut b = RegfBuilder::new("ROOT");
    b.add_sz("Software\\Keep", "A", "1")
        .add_sz("SoftwareBackup\\Skip", "B", "2");
    let offline = OfflineRegistryProvider::new(ForensicSource::OfflineBytes(b.build()))
        .with_key_prefix(Some("Software".to_owned()));
    let data = offline.query(&TableQuery::default()).expect("offline query");
    assert!(
        data.rows
            .iter()
            .all(|r| !r.cells[0].to_string().contains("SoftwareBackup"))
    );
    assert!(data.rows.iter().any(|r| r.cells[0].to_string() == "Software\\Keep"));

    // Verify REG_NONE type constant used smoothly
    let _ = REG_NONE;
}
