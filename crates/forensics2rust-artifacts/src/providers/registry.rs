#![forbid(unsafe_code)]

//! Providers 4, 5, 6, 7, and 14 (Registry-backed user & profile artifacts):
//! - ShellBags View (`artifacts.shellbags`)
//! - UserAssist View (`artifacts.userassist`)
//! - MUICache View (`artifacts.muicache`)
//! - OpenSave Files View (`artifacts.opensave`)
//! - User Profiles View (`artifacts.profiles`)

use std::collections::HashSet;
use std::path::Path;

use forensics2rust_core::{DiagnosticWarning, ForensicError, ForensicSource};
use guap_table::{
    CellValue, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};

use crate::parsers::reg_reader::{RegTree, find_hive_key, load_offline_hives, scan_live_trees};
use crate::parsers::registry_artifacts::{
    MuiCacheRecord, OpenSaveRecord, ShellBagRecord, UserAssistRecord, UserProfileRecord, decode_lastvisited_pidl_mru,
    decode_muicache_tree, decode_opensave_pidl_mru, decode_profile_list_tree, decode_shellbags_tree,
    decode_userassist_tree,
};
use crate::providers::{apply_rows, col, non_empty_text, opt_text, opt_timestamp};

// ---------------------------------------------------------------------------
// 4. artifacts.shellbags — ShellBags View
// ---------------------------------------------------------------------------

pub struct ShellBagsProvider {
    source: ForensicSource,
}

impl ShellBagsProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }

    pub fn query_with_warnings(&self, req: &TableQuery) -> Result<(TableData, Vec<DiagnosticWarning>), TableError> {
        let (records, warnings) = load_shellbags(&self.source).map_err(|e| e.to_table_error())?;
        let rows: Vec<Row> = records
            .iter()
            .enumerate()
            .map(|(idx, r)| {
                let detail = serde_json::to_value(r).unwrap_or(serde_json::Value::Null);
                Row::new(
                    idx as u64 + 1,
                    vec![
                        non_empty_text(&r.folder_path),
                        CellValue::Text(r.item_type.clone()),
                        r.shell_slot.map(CellValue::Uint).unwrap_or(CellValue::Null),
                        CellValue::Text(r.registry_key.clone()),
                        opt_timestamp(r.last_modified),
                        opt_timestamp(r.created),
                        opt_timestamp(r.accessed),
                        opt_text(r.mft_entry.as_deref()),
                        opt_text(r.view_mode.as_deref()),
                    ],
                )
                .with_detail_json(detail)
                .with_raw_bytes(r.raw_bytes.clone())
            })
            .collect();

        let table = apply_rows(&self.schema(), &rows, req)?;
        Ok((table, warnings))
    }
}

fn load_shellbags(source: &ForensicSource) -> Result<(Vec<ShellBagRecord>, Vec<DiagnosticWarning>), ForensicError> {
    let mut records = Vec::new();
    let mut warnings = Vec::new();

    if source.is_live() {
        #[cfg(not(windows))]
        return Err(ForensicError::unsupported_platform(
            "artifacts.shellbags",
            "live artifacts.shellbags requires Windows",
        ));

        #[cfg(windows)]
        {
            let roots = [
                (
                    "HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
                    "HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags",
                ),
                (
                    "HKCU\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
                    "HKCU\\Software\\Microsoft\\Windows\\Shell\\Bags",
                ),
                (
                    "HKCU\\Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU",
                    "HKCU\\Software\\Microsoft\\Windows\\ShellNoRoam\\Bags",
                ),
            ];
            for (mru_root, bags_root) in roots {
                let (mru_trees, w1) = scan_live_trees(&[mru_root], Some(32), Some(8_000), "artifacts.shellbags")?;
                warnings.extend(w1);
                if let Some(mru_tree) = mru_trees.first() {
                    let (bags_trees, w2) = scan_live_trees(&[bags_root], Some(4), Some(4_000), "artifacts.shellbags")?;
                    warnings.extend(w2);
                    records.extend(decode_shellbags_tree(mru_tree, bags_trees.first()));
                }
            }
        }
    } else {
        let hives = load_offline_hives(
            source,
            &[
                "UsrClass.dat",
                "AppData\\Local\\Microsoft\\Windows\\UsrClass.dat",
                "NTUSER.DAT",
            ],
        )?;
        for (label, hive) in hives {
            for (mru_rel, bags_rel) in [
                (
                    "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
                    "Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags",
                ),
                (
                    "Software\\Microsoft\\Windows\\Shell\\BagMRU",
                    "Software\\Microsoft\\Windows\\Shell\\Bags",
                ),
                (
                    "Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU",
                    "Software\\Microsoft\\Windows\\ShellNoRoam\\Bags",
                ),
                ("BagMRU", "Bags"),
            ] {
                if let Some(mru_key) = hive.find_key(mru_rel) {
                    let mru_tree = RegTree::from_hive_subkey(&hive, mru_key, &format!("{label}\\{mru_rel}"));
                    let bags_tree = hive
                        .find_key(bags_rel)
                        .map(|bk| RegTree::from_hive_subkey(&hive, bk, &format!("{label}\\{bags_rel}")));
                    records.extend(decode_shellbags_tree(&mru_tree, bags_tree.as_ref()));
                }
            }
        }
    }

    Ok((records, warnings))
}

impl TableProvider for ShellBagsProvider {
    fn tool_id(&self) -> &'static str {
        "artifacts.shellbags"
    }

    fn description(&self) -> &'static str {
        "UsrClass.dat/NTUSER.DAT BagMRU SHITEMID PIDL folder access parser"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "ShellBags View",
            vec![
                col("folder_path", "FolderPath", ColumnType::Text, 320),
                col("item_type", "ItemType", ColumnType::Text, 110),
                col("shell_slot", "ShellSlot", ColumnType::Uint, 90),
                col("registry_key", "RegistryKey", ColumnType::Text, 320),
                col("last_modified", "LastModified", ColumnType::Timestamp, 180),
                col("created", "Created", ColumnType::Timestamp, 180),
                col("accessed", "Accessed", ColumnType::Timestamp, 180),
                col("mft_entry", "MFTEntry", ColumnType::Text, 120),
                col("view_mode", "ViewMode", ColumnType::Text, 130),
            ],
        )
        .with_default_sort(4, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        self.query_with_warnings(req).map(|(t, _)| t)
    }
}

// ---------------------------------------------------------------------------
// 5. artifacts.userassist — UserAssist View
// ---------------------------------------------------------------------------

pub struct UserAssistProvider {
    source: ForensicSource,
}

impl UserAssistProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }

    pub fn query_with_warnings(&self, req: &TableQuery) -> Result<(TableData, Vec<DiagnosticWarning>), TableError> {
        let (records, warnings) = load_userassist(&self.source).map_err(|e| e.to_table_error())?;
        let rows: Vec<Row> = records
            .iter()
            .enumerate()
            .map(|(idx, r)| {
                let detail = serde_json::json!({
                    "item_path": r.item_path,
                    "guid": r.guid,
                    "guid_name": r.guid_description,
                    "run_count": r.run_count,
                    "focus_count": r.focus_count,
                    "focus_time_ms": r.focus_time_ms,
                    "last_executed": r.last_executed,
                    "session_id": r.session_id,
                });
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(r.item_path.clone()),
                        CellValue::Text(r.guid.clone()),
                        CellValue::Uint(r.run_count),
                        r.focus_count.map(CellValue::Uint).unwrap_or(CellValue::Null),
                        r.focus_time_ms.map(CellValue::Uint).unwrap_or(CellValue::Null),
                        opt_timestamp(r.last_executed),
                        CellValue::Uint(idx as u64 + 1),
                    ],
                )
                .with_detail_json(detail)
                .with_raw_bytes(r.raw_bytes.clone())
            })
            .collect();

        let table = apply_rows(&self.schema(), &rows, req)?;
        Ok((table, warnings))
    }
}

fn load_userassist(source: &ForensicSource) -> Result<(Vec<UserAssistRecord>, Vec<DiagnosticWarning>), ForensicError> {
    let mut records = Vec::new();
    let mut warnings = Vec::new();

    if source.is_live() {
        #[cfg(not(windows))]
        return Err(ForensicError::unsupported_platform(
            "artifacts.userassist",
            "live artifacts.userassist requires Windows",
        ));

        #[cfg(windows)]
        {
            let (trees, w) = scan_live_trees(
                &["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"],
                Some(2),
                Some(2_000),
                "artifacts.userassist",
            )?;
            warnings.extend(w);
            for tree in &trees {
                records.extend(decode_userassist_tree(tree));
            }
        }
    } else {
        let hives = load_offline_hives(source, &["NTUSER.DAT"])?;
        for (label, hive) in hives {
            if let Some(key) = find_hive_key(
                &hive,
                &[
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
                    "Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
                    "UserAssist",
                ],
            ) {
                let tree = RegTree::from_hive_subkey(&hive, key, &label);
                records.extend(decode_userassist_tree(&tree));
            }
        }
    }

    Ok((records, warnings))
}

impl TableProvider for UserAssistProvider {
    fn tool_id(&self) -> &'static str {
        "artifacts.userassist"
    }

    fn description(&self) -> &'static str {
        "UserAssist ROT13 decoder and 16/72-byte execution counter parser"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "UserAssist View",
            vec![
                col("item_path", "ItemPath", ColumnType::Text, 320),
                col("guid", "GUID", ColumnType::Text, 260),
                col("run_count", "RunCount", ColumnType::Uint, 100),
                col("focus_count", "FocusCount", ColumnType::Uint, 100),
                col("focus_time_ms", "FocusTimeMs", ColumnType::Duration, 130),
                col("last_executed", "LastExecuted", ColumnType::Timestamp, 180),
                col("index", "Index", ColumnType::Uint, 80),
            ],
        )
        .with_default_sort(5, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        self.query_with_warnings(req).map(|(t, _)| t)
    }
}

// ---------------------------------------------------------------------------
// 6. artifacts.muicache — MUICache View
// ---------------------------------------------------------------------------

pub struct MuiCacheProvider {
    source: ForensicSource,
}

impl MuiCacheProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }

    pub fn query_with_warnings(&self, req: &TableQuery) -> Result<(TableData, Vec<DiagnosticWarning>), TableError> {
        let (records, warnings) = load_muicache(&self.source).map_err(|e| e.to_table_error())?;
        let is_live = self.source.is_live();

        let rows: Vec<Row> = records
            .iter()
            .enumerate()
            .map(|(idx, r)| {
                let file_exists = if is_live
                    && !r.application_path.starts_with('@')
                    && (r.application_path.contains(":\\") || r.application_path.starts_with("\\\\"))
                {
                    CellValue::Bool(Path::new(&r.application_path).exists())
                } else {
                    CellValue::Null
                };
                let detail = serde_json::to_value(r).unwrap_or(serde_json::Value::Null);
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(r.application_path.clone()),
                        CellValue::Text(r.application_name.clone()),
                        CellValue::Text(r.registry_value_name.clone()),
                        opt_timestamp(r.last_modified),
                        file_exists,
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        let table = apply_rows(&self.schema(), &rows, req)?;
        Ok((table, warnings))
    }
}

fn load_muicache(source: &ForensicSource) -> Result<(Vec<MuiCacheRecord>, Vec<DiagnosticWarning>), ForensicError> {
    let mut records = Vec::new();
    let mut warnings = Vec::new();

    if source.is_live() {
        #[cfg(not(windows))]
        return Err(ForensicError::unsupported_platform(
            "artifacts.muicache",
            "live artifacts.muicache requires Windows",
        ));

        #[cfg(windows)]
        {
            let (trees, w) = scan_live_trees(
                &[
                    "HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
                    "HKCU\\Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache",
                ],
                Some(0),
                Some(2_000),
                "artifacts.muicache",
            )?;
            warnings.extend(w);
            for tree in &trees {
                records.extend(decode_muicache_tree(tree));
            }
        }
    } else {
        let hives = load_offline_hives(
            source,
            &[
                "UsrClass.dat",
                "AppData\\Local\\Microsoft\\Windows\\UsrClass.dat",
                "NTUSER.DAT",
            ],
        )?;
        for (label, hive) in hives {
            for candidate in [
                "Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
                "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
                "Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache",
                "MuiCache",
            ] {
                if let Some(key) = hive.find_key(candidate) {
                    let tree = RegTree::from_hive_subkey(&hive, key, &label);
                    records.extend(decode_muicache_tree(&tree));
                }
            }
        }
    }

    Ok((records, warnings))
}

impl TableProvider for MuiCacheProvider {
    fn tool_id(&self) -> &'static str {
        "artifacts.muicache"
    }

    fn description(&self) -> &'static str {
        "MuiCache Registry application path and display name parser"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "MUICache View",
            vec![
                col("application_path", "ApplicationPath", ColumnType::Text, 320),
                col("application_name", "ApplicationName", ColumnType::Text, 220),
                col("registry_value_name", "RegistryValueName", ColumnType::Text, 320),
                col("last_modified", "LastModified", ColumnType::Timestamp, 180),
                col("file_exists", "FileExists", ColumnType::Bool, 90),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        self.query_with_warnings(req).map(|(t, _)| t)
    }
}

// ---------------------------------------------------------------------------
// 7. artifacts.opensave — OpenSave Files View
// ---------------------------------------------------------------------------

pub struct OpenSaveProvider {
    source: ForensicSource,
}

impl OpenSaveProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }

    pub fn query_with_warnings(&self, req: &TableQuery) -> Result<(TableData, Vec<DiagnosticWarning>), TableError> {
        let (records, warnings) = load_opensave(&self.source).map_err(|e| e.to_table_error())?;
        let rows: Vec<Row> = records
            .iter()
            .enumerate()
            .map(|(idx, r)| {
                let detail = serde_json::to_value(r).unwrap_or(serde_json::Value::Null);
                Row::new(
                    idx as u64 + 1,
                    vec![
                        non_empty_text(&r.filename),
                        non_empty_text(&r.extension),
                        non_empty_text(&r.full_path),
                        opt_timestamp(r.modified_time),
                        CellValue::Uint(u64::from(r.registry_order)),
                        CellValue::Text(r.dialog_type.clone()),
                    ],
                )
                .with_detail_json(detail)
                .with_raw_bytes(r.raw_bytes.clone())
            })
            .collect();

        let table = apply_rows(&self.schema(), &rows, req)?;
        Ok((table, warnings))
    }
}

fn load_opensave(source: &ForensicSource) -> Result<(Vec<OpenSaveRecord>, Vec<DiagnosticWarning>), ForensicError> {
    let mut records = Vec::new();
    let mut warnings = Vec::new();

    if source.is_live() {
        #[cfg(not(windows))]
        return Err(ForensicError::unsupported_platform(
            "artifacts.opensave",
            "live artifacts.opensave requires Windows",
        ));

        #[cfg(windows)]
        {
            let (os_trees, w1) = scan_live_trees(
                &["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU"],
                Some(2),
                Some(2_000),
                "artifacts.opensave",
            )?;
            warnings.extend(w1);
            for tree in &os_trees {
                records.extend(decode_opensave_pidl_mru(tree));
            }

            let (lv_trees, w2) = scan_live_trees(
                &["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU"],
                Some(1),
                Some(500),
                "artifacts.opensave",
            )?;
            warnings.extend(w2);
            for tree in &lv_trees {
                records.extend(decode_lastvisited_pidl_mru(tree));
            }
        }
    } else {
        let hives = load_offline_hives(source, &["NTUSER.DAT"])?;
        for (label, hive) in hives {
            if let Some(os_key) = find_hive_key(
                &hive,
                &[
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
                    "ComDlg32\\OpenSavePidlMRU",
                    "OpenSavePidlMRU",
                ],
            ) {
                let tree = RegTree::from_hive_subkey(&hive, os_key, &label);
                records.extend(decode_opensave_pidl_mru(&tree));
            }
            if let Some(lv_key) = find_hive_key(
                &hive,
                &[
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU",
                    "ComDlg32\\LastVisitedPidlMRU",
                    "LastVisitedPidlMRU",
                ],
            ) {
                let tree = RegTree::from_hive_subkey(&hive, lv_key, &label);
                records.extend(decode_lastvisited_pidl_mru(&tree));
            }
        }
    }

    Ok((records, warnings))
}

impl TableProvider for OpenSaveProvider {
    fn tool_id(&self) -> &'static str {
        "artifacts.opensave"
    }

    fn description(&self) -> &'static str {
        "OpenSavePidlMRU and LastVisitedPidlMRU file dialog PIDL decoder"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "OpenSave Files View",
            vec![
                col("filename", "Filename", ColumnType::Text, 180),
                col("extension", "Extension", ColumnType::Text, 90),
                col("full_path", "FullPath", ColumnType::Text, 320),
                col("modified_time", "ModifiedTime", ColumnType::Timestamp, 180),
                col("registry_order", "RegistryOrder", ColumnType::Uint, 110),
                col("dialog_type", "DialogType", ColumnType::Text, 160),
            ],
        )
        .with_default_sort(4, SortDirection::Asc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        self.query_with_warnings(req).map(|(t, _)| t)
    }
}

// ---------------------------------------------------------------------------
// 14. artifacts.profiles — User Profiles View
// ---------------------------------------------------------------------------

pub struct UserProfilesProvider {
    source: ForensicSource,
}

impl UserProfilesProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }

    pub fn query_with_warnings(&self, req: &TableQuery) -> Result<(TableData, Vec<DiagnosticWarning>), TableError> {
        let (records, warnings) = load_profiles(&self.source).map_err(|e| e.to_table_error())?;
        let rows: Vec<Row> = records
            .iter()
            .enumerate()
            .map(|(idx, r)| {
                let detail = serde_json::to_value(r).unwrap_or(serde_json::Value::Null);
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(r.username.clone()),
                        CellValue::Text(r.sid.clone()),
                        non_empty_text(&r.profile_path),
                        non_empty_text(&r.hive_path),
                        opt_timestamp(r.last_load_time),
                        opt_timestamp(r.last_unload_time),
                        r.local_profile_flags.map(CellValue::Uint).unwrap_or(CellValue::Null),
                        r.loaded.map(CellValue::Bool).unwrap_or(CellValue::Null),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        let table = apply_rows(&self.schema(), &rows, req)?;
        Ok((table, warnings))
    }
}

fn load_profiles(source: &ForensicSource) -> Result<(Vec<UserProfileRecord>, Vec<DiagnosticWarning>), ForensicError> {
    let mut records = Vec::new();
    let mut warnings = Vec::new();

    if source.is_live() {
        #[cfg(not(windows))]
        return Err(ForensicError::unsupported_platform(
            "artifacts.profiles",
            "live artifacts.profiles requires Windows",
        ));

        #[cfg(windows)]
        {
            let mut loaded_sids = HashSet::new();
            if let Ok((hku_trees, w)) = scan_live_trees(&["HKU"], Some(1), Some(500), "artifacts.profiles") {
                warnings.extend(w);
                if let Some(hku_root) = hku_trees.first().and_then(|t| t.root()) {
                    for &cidx in &hku_root.children {
                        if let Some(child) = hku_trees[0].node(cidx) {
                            loaded_sids.insert(child.name.to_ascii_uppercase());
                        }
                    }
                }
            }

            let (trees, w) = scan_live_trees(
                &["HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"],
                Some(1),
                Some(500),
                "artifacts.profiles",
            )?;
            warnings.extend(w);
            for tree in &trees {
                records.extend(decode_profile_list_tree(tree, Some(&loaded_sids)));
            }
        }
    } else {
        let hives = load_offline_hives(source, &["SOFTWARE", "Windows\\System32\\config\\SOFTWARE"])?;
        for (label, hive) in hives {
            if let Some(key) = find_hive_key(
                &hive,
                &[
                    "Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
                    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
                    "ProfileList",
                ],
            ) {
                let tree = RegTree::from_hive_subkey(&hive, key, &label);
                records.extend(decode_profile_list_tree(&tree, None));
            }
        }
    }

    Ok((records, warnings))
}

impl TableProvider for UserProfilesProvider {
    fn tool_id(&self) -> &'static str {
        "artifacts.profiles"
    }

    fn description(&self) -> &'static str {
        "ProfileList live and offline SOFTWARE hive user profile inventory"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "User Profiles View",
            vec![
                col("username", "Username", ColumnType::Text, 160),
                col("sid", "SID", ColumnType::Text, 260),
                col("profile_path", "ProfilePath", ColumnType::Text, 260),
                col("hive_path", "HivePath", ColumnType::Text, 300),
                col("last_load_time", "LastLoadTime", ColumnType::Timestamp, 180),
                col("last_unload_time", "LastUnloadTime", ColumnType::Timestamp, 180),
                col("local_profile_flags", "LocalProfileFlags", ColumnType::Uint, 120),
                col("loaded", "Loaded", ColumnType::Bool, 90),
            ],
        )
        .with_default_sort(4, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        self.query_with_warnings(req).map(|(t, _)| t)
    }
}
