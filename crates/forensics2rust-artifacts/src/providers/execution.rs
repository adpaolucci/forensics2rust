#![forbid(unsafe_code)]

//! Providers 1, 2, 3, 8, and 9:
//! - `LastActivityView` (`artifacts.activity`)
//! - `WinPrefetchView` (`artifacts.prefetch`)
//! - `JumpListsView` (`artifacts.jumplists`)
//! - `RecentFilesView` (`artifacts.recent`)
//! - `ExecutedProgramsList` (`artifacts.executed`)

use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc};
use forensics2rust_core::{DiagnosticWarning, ForensicError, ForensicSource, WarningSeverity};
use guap_table::{
    CellValue, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};
use walkdir::WalkDir;

use crate::correlator::{collect_executed_programs, collect_last_activity};
use crate::live;
use crate::parsers::cfbf::CFBF_MAGIC;
use crate::parsers::jumplist::{JumpListRecord, parse_automatic_destinations, parse_custom_destinations};
use crate::parsers::lnk::parse_lnk;
use crate::parsers::prefetch::parse_prefetch;
use crate::providers::{apply_rows, col, non_empty_text, opt_text, opt_text_owned, opt_timestamp};

// ---------------------------------------------------------------------------
// 1. artifacts.activity — LastActivityView
// ---------------------------------------------------------------------------

pub struct LastActivityProvider {
    source: ForensicSource,
}

impl LastActivityProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }

    pub fn query_with_warnings(&self, req: &TableQuery) -> Result<(TableData, Vec<DiagnosticWarning>), TableError> {
        let (events, warnings) = collect_last_activity(&self.source).map_err(|e| e.to_table_error())?;
        let rows: Vec<Row> = events
            .iter()
            .enumerate()
            .map(|(idx, ev)| {
                let detail = serde_json::to_value(ev).unwrap_or(serde_json::Value::Null);
                Row::new(
                    idx as u64 + 1,
                    vec![
                        opt_timestamp(ev.action_time),
                        non_empty_text(&ev.description),
                        non_empty_text(&ev.filename),
                        non_empty_text(&ev.full_path),
                        non_empty_text(&ev.more_info),
                        non_empty_text(&ev.source),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        let table = apply_rows(&self.schema(), &rows, req)?;
        Ok((table, warnings))
    }
}

impl TableProvider for LastActivityProvider {
    fn tool_id(&self) -> &'static str {
        "artifacts.activity"
    }

    fn description(&self) -> &'static str {
        "Cross-artifact forensic activity timeline correlating Prefetch, Registry, EVTX, Recent, and JumpLists"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "LastActivityView",
            vec![
                col("action_time", "ActionTime", ColumnType::Timestamp, 180),
                col("description", "Description", ColumnType::Text, 220),
                col("filename", "Filename", ColumnType::Text, 180),
                col("full_path", "FullPath", ColumnType::Text, 300),
                col("more_info", "MoreInfo", ColumnType::Text, 260),
                col("source", "Source", ColumnType::Text, 160),
            ],
        )
        .with_default_sort(0, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        self.query_with_warnings(req).map(|(t, _)| t)
    }
}

// ---------------------------------------------------------------------------
// 2. artifacts.prefetch — WinPrefetchView
// ---------------------------------------------------------------------------

pub struct WinPrefetchProvider {
    source: ForensicSource,
}

impl WinPrefetchProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }

    pub fn query_with_warnings(&self, req: &TableQuery) -> Result<(TableData, Vec<DiagnosticWarning>), TableError> {
        let (items, warnings) = load_prefetch_items(&self.source).map_err(|e| e.to_table_error())?;
        let rows: Vec<Row> = items
            .iter()
            .enumerate()
            .map(|(idx, item)| {
                let pf = &item.parsed;
                let last_runs_str = pf
                    .last_run_times
                    .iter()
                    .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true))
                    .collect::<Vec<_>>()
                    .join("; ");
                let loaded_files_str = pf.loaded_files.join("; ");
                let volumes_str = pf
                    .volumes
                    .iter()
                    .map(|v| format!("{} (SN:{:08X})", v.device_path, v.serial_number))
                    .collect::<Vec<_>>()
                    .join("; ");
                let detail = serde_json::json!({
                    "filename": item.filename,
                    "version": pf.version,
                    "compressed": pf.compressed,
                    "file_size": pf.file_size,
                    "executable_name": pf.executable_name,
                    "prefetch_hash": format!("{:08X}", pf.prefetch_hash),
                    "flags": pf.flags,
                    "run_count": pf.run_count,
                    "last_run_times": pf.last_run_times,
                    "process_path": pf.process_path,
                    "loaded_files": pf.loaded_files,
                    "metrics": pf.metrics,
                    "volumes": pf.volumes,
                });

                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(item.filename.clone()),
                        opt_timestamp(item.created_time),
                        opt_timestamp(item.modified_time),
                        CellValue::Uint(u64::from(pf.run_count)),
                        non_empty_text(&last_runs_str),
                        non_empty_text(&pf.process_path),
                        CellValue::Text(format!("{:08X}", pf.prefetch_hash)),
                        non_empty_text(&loaded_files_str),
                        non_empty_text(&volumes_str),
                    ],
                )
                .with_detail_json(detail)
                .with_raw_bytes(item.raw_bytes.clone())
            })
            .collect();

        let table = apply_rows(&self.schema(), &rows, req)?;
        Ok((table, warnings))
    }
}

struct LoadedPrefetch {
    filename: String,
    created_time: Option<DateTime<Utc>>,
    modified_time: Option<DateTime<Utc>>,
    parsed: crate::parsers::prefetch::PrefetchFile,
    raw_bytes: Vec<u8>,
}

fn load_prefetch_from_file(path: &Path) -> Result<LoadedPrefetch, ForensicError> {
    let bytes = fs::read(path).map_err(|err| ForensicError::io_classified(path.display().to_string(), err))?;
    let meta = fs::metadata(path).ok();
    let created_time = meta.as_ref().and_then(|m| m.created().ok()).map(DateTime::<Utc>::from);
    let modified_time = meta.as_ref().and_then(|m| m.modified().ok()).map(DateTime::<Utc>::from);
    let parsed = parse_prefetch(&bytes)?;
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
        .unwrap_or_else(|| parsed.executable_name.clone());
    Ok(LoadedPrefetch {
        filename,
        created_time,
        modified_time,
        parsed,
        raw_bytes: bytes.into_iter().take(4096).collect(),
    })
}

fn load_prefetch_items(
    source: &ForensicSource,
) -> Result<(Vec<LoadedPrefetch>, Vec<DiagnosticWarning>), ForensicError> {
    let mut items = Vec::new();
    let mut warnings = Vec::new();

    match source {
        ForensicSource::OfflineBytes(bytes) => {
            let parsed = parse_prefetch(bytes)?;
            let filename = parsed.executable_name.clone();
            items.push(LoadedPrefetch {
                filename,
                created_time: None,
                modified_time: None,
                parsed,
                raw_bytes: bytes.iter().copied().take(4096).collect(),
            });
        }
        ForensicSource::OfflinePath(path) => {
            if !path.exists() {
                return Err(ForensicError::NotFound(path.display().to_string()));
            }
            if path.is_file() {
                items.push(load_prefetch_from_file(path)?);
            } else {
                let mut last_err = None;
                for entry in WalkDir::new(path).follow_links(false).into_iter().flatten() {
                    if !entry.file_type().is_file() {
                        continue;
                    }
                    let p = entry.path();
                    if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("pf")) {
                        match load_prefetch_from_file(p) {
                            Ok(item) => items.push(item),
                            Err(err) => {
                                warnings.push(DiagnosticWarning {
                                    severity: WarningSeverity::Warn,
                                    tool_id: "artifacts.prefetch".to_string(),
                                    source: p.display().to_string(),
                                    message: err.to_string(),
                                });
                                last_err = Some(err);
                            }
                        }
                    }
                }
                if items.is_empty()
                    && let Some(err) = last_err
                {
                    return Err(err);
                }
            }
        }
        ForensicSource::Live => {
            #[cfg(not(windows))]
            return Err(ForensicError::unsupported_platform(
                "artifacts.prefetch",
                "live WinPrefetchView requires Windows",
            ));

            #[cfg(windows)]
            {
                let dir = live::live_prefetch_dir();
                let rd =
                    fs::read_dir(&dir).map_err(|err| ForensicError::io_classified(dir.display().to_string(), err))?;
                let mut saw_perm_denied = None;
                for entry in rd {
                    match entry {
                        Ok(de) => {
                            let p = de.path();
                            if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("pf")) {
                                match load_prefetch_from_file(&p) {
                                    Ok(item) => items.push(item),
                                    Err(err @ ForensicError::PermissionDenied { .. }) => {
                                        saw_perm_denied = Some(err);
                                    }
                                    Err(err) => warnings.push(DiagnosticWarning {
                                        severity: WarningSeverity::Warn,
                                        tool_id: "artifacts.prefetch".to_string(),
                                        source: p.display().to_string(),
                                        message: err.to_string(),
                                    }),
                                }
                            }
                        }
                        Err(err) => {
                            let ferr = ForensicError::io_classified(dir.display().to_string(), err);
                            if matches!(ferr, ForensicError::PermissionDenied { .. }) {
                                saw_perm_denied = Some(ferr);
                            }
                        }
                    }
                }
                if items.is_empty()
                    && let Some(err) = saw_perm_denied
                {
                    return Err(err);
                }
            }
        }
    }

    Ok((items, warnings))
}

impl TableProvider for WinPrefetchProvider {
    fn tool_id(&self) -> &'static str {
        "artifacts.prefetch"
    }

    fn description(&self) -> &'static str {
        "Pure-Rust MAM\\x04 LZ77/XPRESS Huffman and SCCA v17/23/26/30 .pf Prefetch parser"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "WinPrefetchView",
            vec![
                col("filename", "Filename", ColumnType::Text, 180),
                col("created_time", "CreatedTime", ColumnType::Timestamp, 180),
                col("modified_time", "ModifiedTime", ColumnType::Timestamp, 180),
                col("run_count", "RunCount", ColumnType::Uint, 90),
                col("last_run_times", "LastRunTimes", ColumnType::Text, 280),
                col("process_path", "ProcessPath", ColumnType::Text, 300),
                col("process_hash", "ProcessHash", ColumnType::Text, 100),
                col("loaded_files", "LoadedFiles", ColumnType::Text, 320),
                col("volumes", "Volumes", ColumnType::Text, 260),
            ],
        )
        .with_default_sort(2, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        self.query_with_warnings(req).map(|(t, _)| t)
    }
}

// ---------------------------------------------------------------------------
// 3. artifacts.jumplists — JumpListsView
// ---------------------------------------------------------------------------

pub struct JumpListsProvider {
    source: ForensicSource,
}

impl JumpListsProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }

    pub fn query_with_warnings(&self, req: &TableQuery) -> Result<(TableData, Vec<DiagnosticWarning>), TableError> {
        let (records, warnings) = load_jumplist_records(&self.source).map_err(|e| e.to_table_error())?;
        let rows: Vec<Row> = records
            .iter()
            .enumerate()
            .map(|(idx, rec)| {
                let detail = serde_json::to_value(rec).unwrap_or(serde_json::Value::Null);
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(rec.app_id.clone()),
                        CellValue::Text(rec.app_name.clone()),
                        non_empty_text(&rec.file_name),
                        non_empty_text(&rec.full_path),
                        opt_timestamp(rec.record_time),
                        rec.access_count
                            .map(|c| CellValue::Uint(u64::from(c)))
                            .unwrap_or(CellValue::Null),
                        CellValue::Text(rec.pin_status.clone()),
                        opt_text(rec.arguments.as_deref()),
                        opt_text(rec.volume_serial.as_deref()),
                        CellValue::Text(rec.entry_id.clone()),
                    ],
                )
                .with_detail_json(detail)
                .with_raw_bytes(rec.raw_bytes.clone())
            })
            .collect();

        let table = apply_rows(&self.schema(), &rows, req)?;
        Ok((table, warnings))
    }
}

fn app_id_from_path(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.split('.').next())
        .unwrap_or("<unknown>")
        .to_string()
}

fn load_jumplist_file(path: &Path) -> Result<(Vec<JumpListRecord>, Vec<DiagnosticWarning>), ForensicError> {
    let bytes = fs::read(path).map_err(|err| ForensicError::io_classified(path.display().to_string(), err))?;
    let app_id = app_id_from_path(path);
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if bytes.starts_with(&CFBF_MAGIC) || ext == "automaticdestinations-ms" {
        parse_automatic_destinations(&bytes, &app_id)
    } else {
        parse_custom_destinations(&bytes, &app_id)
    }
}

fn load_jumplist_records(
    source: &ForensicSource,
) -> Result<(Vec<JumpListRecord>, Vec<DiagnosticWarning>), ForensicError> {
    let mut records = Vec::new();
    let mut warnings = Vec::new();

    match source {
        ForensicSource::OfflineBytes(bytes) => {
            let (mut recs, mut w) = if bytes.starts_with(&CFBF_MAGIC) {
                parse_automatic_destinations(bytes, "<memory>")?
            } else {
                parse_custom_destinations(bytes, "<memory>")?
            };
            records.append(&mut recs);
            warnings.append(&mut w);
        }
        ForensicSource::OfflinePath(path) => {
            if !path.exists() {
                return Err(ForensicError::NotFound(path.display().to_string()));
            }
            if path.is_file() {
                return load_jumplist_file(path);
            }
            let mut last_err = None;
            for entry in WalkDir::new(path).follow_links(false).into_iter().flatten() {
                if !entry.file_type().is_file() {
                    continue;
                }
                let p = entry.path();
                let ext = p
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(str::to_ascii_lowercase)
                    .unwrap_or_default();
                if ext == "automaticdestinations-ms" || ext == "customdestinations-ms" {
                    match load_jumplist_file(p) {
                        Ok((mut recs, mut w)) => {
                            records.append(&mut recs);
                            warnings.append(&mut w);
                        }
                        Err(err) => {
                            warnings.push(DiagnosticWarning {
                                severity: WarningSeverity::Warn,
                                tool_id: "artifacts.jumplists".to_string(),
                                source: p.display().to_string(),
                                message: err.to_string(),
                            });
                            last_err = Some(err);
                        }
                    }
                }
            }
            if records.is_empty()
                && let Some(err) = last_err
            {
                return Err(err);
            }
        }
        ForensicSource::Live => {
            #[cfg(not(windows))]
            return Err(ForensicError::unsupported_platform(
                "artifacts.jumplists",
                "live JumpListsView requires Windows",
            ));

            #[cfg(windows)]
            {
                let Some(recent_dir) = live::live_recent_dir() else {
                    return Ok((records, warnings));
                };
                for sub in ["AutomaticDestinations", "CustomDestinations"] {
                    let sub_dir = recent_dir.join(sub);
                    if !sub_dir.is_dir() {
                        continue;
                    }
                    if let Ok(rd) = fs::read_dir(&sub_dir) {
                        for entry in rd.flatten() {
                            let p = entry.path();
                            if p.is_file() {
                                match load_jumplist_file(&p) {
                                    Ok((mut recs, mut w)) => {
                                        records.append(&mut recs);
                                        warnings.append(&mut w);
                                    }
                                    Err(err) => warnings.push(DiagnosticWarning {
                                        severity: WarningSeverity::Warn,
                                        tool_id: "artifacts.jumplists".to_string(),
                                        source: p.display().to_string(),
                                        message: err.to_string(),
                                    }),
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok((records, warnings))
}

impl TableProvider for JumpListsProvider {
    fn tool_id(&self) -> &'static str {
        "artifacts.jumplists"
    }

    fn description(&self) -> &'static str {
        "Pure-Rust OLE2/CFBF DestList and [MS-SHLLINK] LNK JumpList parser"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "JumpListsView",
            vec![
                col("app_id", "AppID", ColumnType::Text, 140),
                col("app_name", "AppName", ColumnType::Text, 180),
                col("file_name", "FileName", ColumnType::Text, 180),
                col("full_path", "FullPath", ColumnType::Text, 320),
                col("record_time", "RecordTime", ColumnType::Timestamp, 180),
                col("access_count", "AccessCount", ColumnType::Uint, 100),
                col("pin_status", "PinStatus", ColumnType::Text, 120),
                col("arguments", "Arguments", ColumnType::Text, 220),
                col("volume_serial", "VolumeSerial", ColumnType::Text, 110),
                col("entry_id", "EntryID", ColumnType::Text, 100),
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
// 8. artifacts.recent — RecentFilesView
// ---------------------------------------------------------------------------

pub struct RecentFilesProvider {
    source: ForensicSource,
}

impl RecentFilesProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }

    pub fn query_with_warnings(&self, req: &TableQuery) -> Result<(TableData, Vec<DiagnosticWarning>), TableError> {
        let (items, warnings) = load_recent_lnk_items(&self.source).map_err(|e| e.to_table_error())?;
        let rows: Vec<Row> = items
            .iter()
            .enumerate()
            .map(|(idx, item)| {
                let lnk = &item.lnk;
                let full_path = lnk.target_path.clone().or_else(|| lnk.name.clone()).unwrap_or_default();
                let filename = full_path
                    .trim_end_matches(['\\', '/'])
                    .rsplit(['\\', '/'])
                    .next()
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .unwrap_or_else(|| item.stem.clone());
                let extension = Path::new(&filename)
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(str::to_ascii_lowercase);
                let created = lnk.creation_time.or(item.os_created);
                let modified = lnk.write_time.or(item.os_modified);
                let detail = serde_json::json!({
                    "lnk_path": item.lnk_path,
                    "full_path": full_path,
                    "shell_link": lnk,
                });

                Row::new(
                    idx as u64 + 1,
                    vec![
                        non_empty_text(&filename),
                        non_empty_text(&full_path),
                        opt_text_owned(extension),
                        opt_timestamp(created),
                        opt_timestamp(modified),
                        CellValue::Text(item.lnk_path.clone()),
                        CellValue::Bytes(u64::from(lnk.file_size)),
                        CellValue::Text(lnk.file_attributes_text.clone()),
                    ],
                )
                .with_detail_json(detail)
                .with_raw_bytes(item.raw_bytes.clone())
            })
            .collect();

        let table = apply_rows(&self.schema(), &rows, req)?;
        Ok((table, warnings))
    }
}

struct LoadedLnk {
    lnk_path: String,
    stem: String,
    os_created: Option<DateTime<Utc>>,
    os_modified: Option<DateTime<Utc>>,
    lnk: crate::parsers::lnk::ShellLink,
    raw_bytes: Vec<u8>,
}

fn load_lnk_from_file(path: &Path) -> Result<LoadedLnk, ForensicError> {
    let bytes = fs::read(path).map_err(|err| ForensicError::io_classified(path.display().to_string(), err))?;
    let meta = fs::metadata(path).ok();
    let os_created = meta.as_ref().and_then(|m| m.created().ok()).map(DateTime::<Utc>::from);
    let os_modified = meta.as_ref().and_then(|m| m.modified().ok()).map(DateTime::<Utc>::from);
    let (lnk, _) = parse_lnk(&bytes)?;
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("shortcut")
        .to_string();
    Ok(LoadedLnk {
        lnk_path: path.display().to_string(),
        stem,
        os_created,
        os_modified,
        lnk,
        raw_bytes: bytes.into_iter().take(4096).collect(),
    })
}

fn load_recent_lnk_items(source: &ForensicSource) -> Result<(Vec<LoadedLnk>, Vec<DiagnosticWarning>), ForensicError> {
    let mut items = Vec::new();
    let mut warnings = Vec::new();

    match source {
        ForensicSource::OfflineBytes(bytes) => {
            let (lnk, _) = parse_lnk(bytes)?;
            items.push(LoadedLnk {
                lnk_path: "<memory>".to_string(),
                stem: "<memory>".to_string(),
                os_created: None,
                os_modified: None,
                lnk,
                raw_bytes: bytes.iter().copied().take(4096).collect(),
            });
        }
        ForensicSource::OfflinePath(path) => {
            if !path.exists() {
                return Err(ForensicError::NotFound(path.display().to_string()));
            }
            if path.is_file() {
                items.push(load_lnk_from_file(path)?);
            } else {
                let mut last_err = None;
                for entry in WalkDir::new(path).follow_links(false).into_iter().flatten() {
                    if !entry.file_type().is_file() {
                        continue;
                    }
                    let p = entry.path();
                    if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("lnk")) {
                        match load_lnk_from_file(p) {
                            Ok(item) => items.push(item),
                            Err(err) => {
                                warnings.push(DiagnosticWarning {
                                    severity: WarningSeverity::Warn,
                                    tool_id: "artifacts.recent".to_string(),
                                    source: p.display().to_string(),
                                    message: err.to_string(),
                                });
                                last_err = Some(err);
                            }
                        }
                    }
                }
                if items.is_empty()
                    && let Some(err) = last_err
                {
                    return Err(err);
                }
            }
        }
        ForensicSource::Live => {
            #[cfg(not(windows))]
            return Err(ForensicError::unsupported_platform(
                "artifacts.recent",
                "live RecentFilesView requires Windows",
            ));

            #[cfg(windows)]
            {
                let Some(dir) = live::live_recent_dir() else {
                    return Ok((items, warnings));
                };
                if dir.is_dir()
                    && let Ok(rd) = fs::read_dir(&dir)
                {
                    for entry in rd.flatten() {
                        let p = entry.path();
                        if p.is_file() && p.extension().is_some_and(|e| e.eq_ignore_ascii_case("lnk")) {
                            match load_lnk_from_file(&p) {
                                Ok(item) => items.push(item),
                                Err(err) => warnings.push(DiagnosticWarning {
                                    severity: WarningSeverity::Warn,
                                    tool_id: "artifacts.recent".to_string(),
                                    source: p.display().to_string(),
                                    message: err.to_string(),
                                }),
                            }
                        }
                    }
                }
            }
        }
    }

    Ok((items, warnings))
}

impl TableProvider for RecentFilesProvider {
    fn tool_id(&self) -> &'static str {
        "artifacts.recent"
    }

    fn description(&self) -> &'static str {
        "Pure-Rust [MS-SHLLINK] .lnk recent files and target metadata parser"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "RecentFilesView",
            vec![
                col("filename", "Filename", ColumnType::Text, 180),
                col("full_path", "FullPath", ColumnType::Text, 320),
                col("extension", "Extension", ColumnType::Text, 90),
                col("created_time", "CreatedTime", ColumnType::Timestamp, 180),
                col("modified_time", "ModifiedTime", ColumnType::Timestamp, 180),
                col("lnk_path", "LnkPath", ColumnType::Text, 300),
                col("target_size", "TargetSize", ColumnType::BytesSize, 110),
                col("file_attributes", "FileAttributes", ColumnType::Text, 150),
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
// 9. artifacts.executed — ExecutedProgramsList
// ---------------------------------------------------------------------------

pub struct ExecutedProgramsProvider {
    source: ForensicSource,
}

impl ExecutedProgramsProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }

    pub fn query_with_warnings(&self, req: &TableQuery) -> Result<(TableData, Vec<DiagnosticWarning>), TableError> {
        let (summaries, warnings) = collect_executed_programs(&self.source).map_err(|e| e.to_table_error())?;
        let rows: Vec<Row> = summaries
            .iter()
            .enumerate()
            .map(|(idx, s)| {
                let detail = serde_json::to_value(s).unwrap_or(serde_json::Value::Null);
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(s.program_path.clone()),
                        opt_timestamp(s.last_executed),
                        s.execution_count.map(CellValue::Uint).unwrap_or(CellValue::Null),
                        CellValue::Text(s.source_artifact.clone()),
                        opt_text(s.file_version.as_deref()),
                        opt_text(s.company.as_deref()),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        let table = apply_rows(&self.schema(), &rows, req)?;
        Ok((table, warnings))
    }
}

impl TableProvider for ExecutedProgramsProvider {
    fn tool_id(&self) -> &'static str {
        "artifacts.executed"
    }

    fn description(&self) -> &'static str {
        "Aggregated execution evidence across UserAssist, Bam/Dam, ShimCache, Amcache, Prefetch, and MUICache"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "ExecutedProgramsList",
            vec![
                col("program_path", "ProgramPath", ColumnType::Text, 320),
                col("last_executed", "LastExecuted", ColumnType::Timestamp, 180),
                col("execution_count", "ExecutionCount", ColumnType::Uint, 110),
                col("source_artifact", "SourceArtifact", ColumnType::Text, 180),
                col("file_version", "FileVersion", ColumnType::Text, 110),
                col("company", "Company", ColumnType::Text, 180),
            ],
        )
        .with_default_sort(1, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        self.query_with_warnings(req).map(|(t, _)| t)
    }
}
