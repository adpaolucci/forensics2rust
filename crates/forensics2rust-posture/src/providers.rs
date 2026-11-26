#![forbid(unsafe_code)]

//! `guap_table::TableProvider` implementations for the 4 read-only `forensics2rust-posture` tools:
//! - `posture.updates` (Windows Updates History)
//! - `posture.full_updates` (Full Updates History)
//! - `posture.defender_status`
//! - `posture.security_center`

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use forensics2rust_core::{DiagnosticWarning, ForensicError, ForensicSource, QueryHelper, WarningSeverity};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};

use crate::cbs_log::{parse_cbs_log_bytes, parse_cbs_log_path};
use crate::datastore_ese::{UpdateHistoryRecord, parse_datastore_ese_bytes, parse_datastore_ese_path, parse_wua_json};
use crate::defender::{
    DefenderPostureRecord, DefenderRegistrySnapshot, correlate_defender_snapshots, parse_defender_from_regf_bytes,
    parse_defender_from_regf_path, parse_defender_json, parse_defender_wmi_bundle_json,
};
use crate::discovery::{ArtifactKind, discover_files_in_dir, extract_build_version, sniff_file_head, sniff_magic};
use crate::live;
use crate::security_center::{SecurityCenterRecord, parse_security_center_json};
use crate::store_db::{FullUpdateRecord, parse_store_db_bytes, parse_store_db_path};

fn opt_text_cell(val: Option<&str>) -> CellValue {
    match val {
        Some(s) if !s.trim().is_empty() => CellValue::Text(s.to_string()),
        _ => CellValue::Null,
    }
}

fn opt_bool_cell(val: Option<bool>) -> CellValue {
    val.map_or(CellValue::Null, CellValue::Bool)
}

fn opt_u32_cell(val: Option<u32>) -> CellValue {
    val.map_or(CellValue::Null, |v| CellValue::Uint(u64::from(v)))
}

fn opt_ts_cell(val: Option<chrono::DateTime<chrono::Utc>>) -> CellValue {
    val.map_or(CellValue::Null, CellValue::Timestamp)
}

fn join_or_null(items: &[String]) -> CellValue {
    if items.is_empty() {
        CellValue::Null
    } else {
        CellValue::Text(items.join("; "))
    }
}

// ---------------------------------------------------------------------------
// 1. posture.updates (Windows Updates History)
// ---------------------------------------------------------------------------

pub struct PostureUpdatesProvider {
    source: ForensicSource,
}

impl PostureUpdatesProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }

    pub fn query_with_warnings(&self, req: &TableQuery) -> Result<(TableData, Vec<DiagnosticWarning>), ForensicError> {
        let (records, warnings) = collect_updates(&self.source)?;
        let schema = self.schema();
        let rows: Vec<Row> = records
            .into_iter()
            .enumerate()
            .map(|(idx, rec)| {
                let hresult_hex = rec.hresult.map(|h| format!("0x{:08X}", h as u32));
                let detail = serde_json::json!({
                    "title": rec.title,
                    "description": rec.description,
                    "install_date": rec.install_date.map(|d| d.to_rfc3339()),
                    "operation": rec.operation,
                    "result_code": rec.result_code,
                    "hresult": hresult_hex,
                    "unmapped_result_code": rec.unmapped_result_code,
                    "kb_article": rec.kb_article,
                    "update_id": rec.update_id,
                    "revision_number": rec.revision_number,
                    "support_url": rec.support_url,
                    "client_app_id": rec.client_app_id,
                    "service_id": rec.service_id,
                    "categories": rec.categories,
                    "source_db": rec.source_db,
                    "extra": rec.detail_extra,
                });
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(rec.title),
                        if rec.description.is_empty() {
                            CellValue::Null
                        } else {
                            CellValue::Text(rec.description)
                        },
                        opt_ts_cell(rec.install_date),
                        CellValue::Text(rec.operation),
                        CellValue::Text(rec.result_code),
                        opt_text_cell(hresult_hex.as_deref()),
                        opt_text_cell(rec.kb_article.as_deref()),
                        opt_text_cell(rec.update_id.as_deref()),
                        opt_text_cell(rec.support_url.as_deref()),
                        opt_text_cell(rec.client_app_id.as_deref()),
                        CellValue::Text(rec.source_db),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        let data = QueryHelper::apply(&schema, &rows, req)?;
        Ok((data, warnings))
    }
}

impl TableProvider for PostureUpdatesProvider {
    fn tool_id(&self) -> &'static str {
        "posture.updates"
    }

    fn description(&self) -> &'static str {
        "Windows Update Agent COM (IUpdateSearcher) and offline DataStore.edb history view"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Windows Updates History",
            vec![
                ColumnDef::new("title", "Title", ColumnType::Text).with_width_hint(240),
                ColumnDef::new("description", "Description", ColumnType::Text).with_width_hint(260),
                ColumnDef::new("install_date", "InstallDate", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("operation", "Operation", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("result_code", "ResultCode", ColumnType::Text).with_width_hint(130),
                ColumnDef::new("hresult", "HResult", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("kb_article", "KBArticle", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("update_id", "UpdateID", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("support_url", "SupportURL", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("client_app_id", "ClientAppID", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("source_db", "SourceDB", ColumnType::Text).with_width_hint(110),
            ],
        )
        .with_default_sort(2, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        self.query_with_warnings(req)
            .map(|(data, _)| data)
            .map_err(TableError::from)
    }
}

fn collect_updates(
    source: &ForensicSource,
) -> Result<(Vec<UpdateHistoryRecord>, Vec<DiagnosticWarning>), ForensicError> {
    match source {
        ForensicSource::Live => {
            #[cfg(not(windows))]
            {
                live::collect_live_wua_history().map(|r| (r, Vec::new()))
            }
            #[cfg(windows)]
            {
                match live::collect_live_wua_history() {
                    Ok(records) => Ok((records, Vec::new())),
                    Err(wua_err) => {
                        let edb_path = live::live_datastore_edb_path();
                        match parse_datastore_ese_path(&edb_path) {
                            Ok((records, mut warnings)) => {
                                warnings.push(DiagnosticWarning {
                                    severity: WarningSeverity::Warn,
                                    tool_id: "posture.updates".to_string(),
                                    source: "WUA COM".to_string(),
                                    message: format!("WUA COM failed ({wua_err}); fell back to DataStore.edb"),
                                });
                                Ok((records, warnings))
                            }
                            Err(_) => Err(wua_err),
                        }
                    }
                }
            }
        }
        ForensicSource::OfflinePath(path) => {
            if !path.exists() {
                return Err(ForensicError::NotFound(path.display().to_string()));
            }
            if path.is_file() {
                let kind = sniff_file_head(path)?;
                return match kind {
                    ArtifactKind::Ese => parse_datastore_ese_path(path),
                    ArtifactKind::Json => {
                        let bytes =
                            fs::read(path).map_err(|e| ForensicError::io_classified(path.display().to_string(), e))?;
                        parse_wua_json(&bytes, &path.display().to_string())
                    }
                    other => Err(ForensicError::parse(
                        path.display().to_string(),
                        format!("expected DataStore.edb (ESE) or WUA JSON, got {other:?}"),
                    )),
                };
            }

            let mut warnings = Vec::new();
            let candidates = discover_files_in_dir(path, "posture.updates", &mut warnings, |p| {
                let name = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                name == "datastore.edb"
                    || name.ends_with(".edb")
                    || name == "wua_updates.json"
                    || name == "updates.json"
            });

            for cand in candidates {
                let Ok(kind) = sniff_file_head(&cand) else {
                    continue;
                };
                match kind {
                    ArtifactKind::Ese => {
                        let (recs, mut w) = parse_datastore_ese_path(&cand)?;
                        warnings.append(&mut w);
                        return Ok((recs, warnings));
                    }
                    ArtifactKind::Json => {
                        let bytes =
                            fs::read(&cand).map_err(|e| ForensicError::io_classified(cand.display().to_string(), e))?;
                        if let Ok((recs, mut w)) = parse_wua_json(&bytes, &cand.display().to_string()) {
                            warnings.append(&mut w);
                            return Ok((recs, warnings));
                        }
                    }
                    _ => {}
                }
            }

            Err(ForensicError::NotFound(format!(
                "no DataStore.edb or WUA JSON artifact found under {}",
                path.display()
            )))
        }
        ForensicSource::OfflineBytes(bytes) => match sniff_magic(bytes) {
            ArtifactKind::Ese => parse_datastore_ese_bytes(bytes, "OfflineBytes(DataStore.edb)"),
            ArtifactKind::Json => parse_wua_json(bytes, "OfflineBytes(WuaJson)"),
            other => Err(ForensicError::parse(
                "OfflineBytes",
                format!("expected DataStore.edb (ESE) or WUA JSON bytes, got {other:?}"),
            )),
        },
    }
}

// ---------------------------------------------------------------------------
// 2. posture.full_updates (Full Updates History)
// ---------------------------------------------------------------------------

pub struct PostureFullUpdatesProvider {
    source: ForensicSource,
}

impl PostureFullUpdatesProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }

    pub fn query_with_warnings(&self, req: &TableQuery) -> Result<(TableData, Vec<DiagnosticWarning>), ForensicError> {
        let (records, warnings) = collect_full_updates(&self.source)?;
        let schema = self.schema();
        let rows: Vec<Row> = records
            .into_iter()
            .enumerate()
            .map(|(idx, rec)| {
                let detail = serde_json::json!({
                    "title": rec.title,
                    "install_date": rec.install_date.map(|d| d.to_rfc3339()),
                    "kb_number": rec.kb_number,
                    "category": rec.category,
                    "build_version": rec.build_version,
                    "source_db": rec.source_db,
                    "update_id": rec.update_id,
                    "result": rec.result,
                    "description": rec.description,
                    "more_info_url": rec.more_info_url,
                    "provider_id": rec.provider_id,
                    "extra": rec.detail_extra,
                });
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(rec.title),
                        opt_ts_cell(rec.install_date),
                        opt_text_cell(rec.kb_number.as_deref()),
                        CellValue::Text(rec.category),
                        opt_text_cell(rec.build_version.as_deref()),
                        CellValue::Text(rec.source_db),
                        opt_text_cell(rec.update_id.as_deref()),
                        opt_text_cell(rec.result.as_deref()),
                        opt_text_cell(rec.description.as_deref()),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        let data = QueryHelper::apply(&schema, &rows, req)?;
        Ok((data, warnings))
    }
}

impl TableProvider for PostureFullUpdatesProvider {
    fn tool_id(&self) -> &'static str {
        "posture.full_updates"
    }

    fn description(&self) -> &'static str {
        "USOPrivate\\UpdateStore\\store.db, CBS.log, and DataStore.edb update history"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Full Updates History",
            vec![
                ColumnDef::new("title", "Title", ColumnType::Text).with_width_hint(260),
                ColumnDef::new("install_date", "InstallDate", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("kb_number", "KBNumber", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("category", "Category", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("build_version", "BuildVersion", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("source_db", "SourceDB", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("update_id", "UpdateID", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("result", "Result", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("description", "Description", ColumnType::Text).with_width_hint(260),
            ],
        )
        .with_default_sort(1, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        self.query_with_warnings(req)
            .map(|(data, _)| data)
            .map_err(TableError::from)
    }
}

fn wua_records_to_full(records: Vec<UpdateHistoryRecord>, source_override: Option<&str>) -> Vec<FullUpdateRecord> {
    records
        .into_iter()
        .map(|h| {
            let build_version = extract_build_version(&h.title)
                .or_else(|| extract_build_version(&h.description))
                .or_else(|| {
                    h.detail_extra
                        .get("build_version")
                        .and_then(|v| v.as_str())
                        .map(ToOwned::to_owned)
                });
            let category = if !h.categories.is_empty() {
                h.categories.join("; ")
            } else {
                h.operation.clone()
            };
            FullUpdateRecord {
                title: h.title,
                install_date: h.install_date,
                kb_number: h.kb_article,
                category,
                build_version,
                source_db: source_override.unwrap_or(&h.source_db).to_string(),
                update_id: h.update_id,
                result: Some(h.result_code),
                description: if h.description.is_empty() {
                    None
                } else {
                    Some(h.description)
                },
                more_info_url: h.support_url,
                provider_id: h.client_app_id,
                detail_extra: h.detail_extra,
            }
        })
        .collect()
}

fn collect_full_updates(
    source: &ForensicSource,
) -> Result<(Vec<FullUpdateRecord>, Vec<DiagnosticWarning>), ForensicError> {
    match source {
        ForensicSource::Live => {
            #[cfg(not(windows))]
            {
                Err(ForensicError::unsupported_platform(
                    "posture.full_updates",
                    "live update database aggregation requires Windows",
                ))
            }
            #[cfg(windows)]
            {
                let mut all = Vec::new();
                let mut warnings = Vec::new();
                let mut succeeded_sources = 0usize;
                let mut fatal_errors: Vec<ForensicError> = Vec::new();

                // 1. USOPrivate\UpdateStore\store.db
                let store_path = live::live_uso_store_db_path();
                if store_path.exists() {
                    match parse_store_db_path(&store_path) {
                        Ok((mut recs, mut w)) => {
                            succeeded_sources += 1;
                            all.append(&mut recs);
                            warnings.append(&mut w);
                        }
                        Err(err) => {
                            warnings.push(DiagnosticWarning {
                                severity: WarningSeverity::Warn,
                                tool_id: "posture.full_updates".to_string(),
                                source: store_path.display().to_string(),
                                message: format!("failed reading USO store.db: {err}"),
                            });
                            fatal_errors.push(err);
                        }
                    }
                } else {
                    warnings.push(DiagnosticWarning {
                        severity: WarningSeverity::Info,
                        tool_id: "posture.full_updates".to_string(),
                        source: store_path.display().to_string(),
                        message: "USO store.db not present on host".to_string(),
                    });
                }

                // 2. CBS.log & CBS.persist.log
                for cbs_path in live::live_cbs_log_paths() {
                    if cbs_path.exists() {
                        match parse_cbs_log_path(&cbs_path) {
                            Ok((mut recs, mut w)) => {
                                succeeded_sources += 1;
                                all.append(&mut recs);
                                warnings.append(&mut w);
                            }
                            Err(err) => {
                                warnings.push(DiagnosticWarning {
                                    severity: WarningSeverity::Warn,
                                    tool_id: "posture.full_updates".to_string(),
                                    source: cbs_path.display().to_string(),
                                    message: format!("failed reading CBS log: {err}"),
                                });
                                fatal_errors.push(err);
                            }
                        }
                    }
                }

                // 3. DataStore.edb with WUA COM fallback if locked by wuauserv
                let edb_path = live::live_datastore_edb_path();
                if edb_path.exists() {
                    match parse_datastore_ese_path(&edb_path) {
                        Ok((recs, mut w)) => {
                            succeeded_sources += 1;
                            all.extend(wua_records_to_full(recs, Some("DataStore.edb")));
                            warnings.append(&mut w);
                        }
                        Err(edb_err) => {
                            warnings.push(DiagnosticWarning {
                                severity: WarningSeverity::Info,
                                tool_id: "posture.full_updates".to_string(),
                                source: edb_path.display().to_string(),
                                message: format!(
                                    "DataStore.edb locked/unreadable ({edb_err}); falling back to WUA COM"
                                ),
                            });
                            match live::collect_live_wua_history() {
                                Ok(recs) => {
                                    succeeded_sources += 1;
                                    all.extend(wua_records_to_full(recs, Some("WUA COM (DataStore fallback)")));
                                }
                                Err(wua_err) => {
                                    fatal_errors.push(wua_err);
                                }
                            }
                        }
                    }
                } else if let Ok(recs) = live::collect_live_wua_history() {
                    succeeded_sources += 1;
                    all.extend(wua_records_to_full(recs, Some("WUA COM")));
                }

                if succeeded_sources == 0 && !fatal_errors.is_empty() {
                    if let Some(perm) = fatal_errors
                        .iter()
                        .find(|e| matches!(e, ForensicError::PermissionDenied { .. }))
                    {
                        return Err(ForensicError::permission_denied(
                            "posture.full_updates",
                            perm.to_string(),
                        ));
                    }
                    return Err(fatal_errors.remove(0));
                }

                all.sort_by_key(|a| std::cmp::Reverse(a.install_date));
                Ok((all, warnings))
            }
        }
        ForensicSource::OfflinePath(path) => {
            if !path.exists() {
                return Err(ForensicError::NotFound(path.display().to_string()));
            }
            if path.is_file() {
                let kind = sniff_file_head(path)?;
                return match kind {
                    ArtifactKind::Sqlite => parse_store_db_path(path),
                    ArtifactKind::Ese => {
                        let name_lower = path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("")
                            .to_ascii_lowercase();
                        if name_lower.contains("store") {
                            parse_store_db_path(path)
                        } else {
                            let (recs, w) = parse_datastore_ese_path(path)?;
                            Ok((wua_records_to_full(recs, Some("DataStore.edb")), w))
                        }
                    }
                    ArtifactKind::CbsLog | ArtifactKind::GzipCbsLog => parse_cbs_log_path(path),
                    ArtifactKind::Json => {
                        let bytes =
                            fs::read(path).map_err(|e| ForensicError::io_classified(path.display().to_string(), e))?;
                        let (recs, w) = parse_wua_json(&bytes, &path.display().to_string())?;
                        Ok((wua_records_to_full(recs, Some("WuaJson")), w))
                    }
                    other => Err(ForensicError::parse(
                        path.display().to_string(),
                        format!("unsupported file format for full_updates: {other:?}"),
                    )),
                };
            }

            let mut warnings = Vec::new();
            let candidates = discover_files_in_dir(path, "posture.full_updates", &mut warnings, |p| {
                let name = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                name == "store.db"
                    || name == "datastore.edb"
                    || name.ends_with(".edb")
                    || name.ends_with(".db")
                    || name.starts_with("cbs") && (name.ends_with(".log") || name.ends_with(".log.gz"))
            });

            if candidates.is_empty() {
                return Err(ForensicError::NotFound(format!(
                    "no store.db, DataStore.edb, or CBS.log artifacts found under {}",
                    path.display()
                )));
            }

            let mut all = Vec::new();
            let mut parsed_count = 0usize;
            for cand in candidates {
                let kind = match sniff_file_head(&cand) {
                    Ok(k) => k,
                    Err(err) => {
                        warnings.push(DiagnosticWarning {
                            severity: WarningSeverity::Warn,
                            tool_id: "posture.full_updates".to_string(),
                            source: cand.display().to_string(),
                            message: format!("failed inspecting file header: {err}"),
                        });
                        continue;
                    }
                };
                match kind {
                    ArtifactKind::Sqlite => match parse_store_db_path(&cand) {
                        Ok((mut recs, mut w)) => {
                            parsed_count += 1;
                            all.append(&mut recs);
                            warnings.append(&mut w);
                        }
                        Err(err) => warnings.push(DiagnosticWarning {
                            severity: WarningSeverity::Warn,
                            tool_id: "posture.full_updates".to_string(),
                            source: cand.display().to_string(),
                            message: format!("failed parsing SQLite store.db: {err}"),
                        }),
                    },
                    ArtifactKind::Ese => {
                        let name_lower = cand
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("")
                            .to_ascii_lowercase();
                        let res = if name_lower.contains("store") {
                            parse_store_db_path(&cand)
                        } else {
                            parse_datastore_ese_path(&cand)
                                .map(|(r, w)| (wua_records_to_full(r, Some("DataStore.edb")), w))
                        };
                        match res {
                            Ok((mut recs, mut w)) => {
                                parsed_count += 1;
                                all.append(&mut recs);
                                warnings.append(&mut w);
                            }
                            Err(err) => warnings.push(DiagnosticWarning {
                                severity: WarningSeverity::Warn,
                                tool_id: "posture.full_updates".to_string(),
                                source: cand.display().to_string(),
                                message: format!("failed parsing ESE update db: {err}"),
                            }),
                        }
                    }
                    ArtifactKind::CbsLog | ArtifactKind::GzipCbsLog => match parse_cbs_log_path(&cand) {
                        Ok((mut recs, mut w)) => {
                            parsed_count += 1;
                            all.append(&mut recs);
                            warnings.append(&mut w);
                        }
                        Err(err) => warnings.push(DiagnosticWarning {
                            severity: WarningSeverity::Warn,
                            tool_id: "posture.full_updates".to_string(),
                            source: cand.display().to_string(),
                            message: format!("failed parsing CBS log: {err}"),
                        }),
                    },
                    _ => {}
                }
            }

            if parsed_count == 0 {
                return Err(ForensicError::parse(
                    path.display().to_string(),
                    "discovered candidate update files under directory, but none parsed cleanly",
                ));
            }
            all.sort_by_key(|a| std::cmp::Reverse(a.install_date));
            Ok((all, warnings))
        }
        ForensicSource::OfflineBytes(bytes) => match sniff_magic(bytes) {
            ArtifactKind::Sqlite => parse_store_db_bytes(bytes, "OfflineBytes(store.db)"),
            ArtifactKind::Ese => {
                let (recs, w) = parse_datastore_ese_bytes(bytes, "OfflineBytes(DataStore.edb)")?;
                Ok((wua_records_to_full(recs, Some("DataStore.edb")), w))
            }
            ArtifactKind::CbsLog | ArtifactKind::GzipCbsLog => parse_cbs_log_bytes(bytes, "OfflineBytes(CBS.log)"),
            ArtifactKind::Json => {
                let (recs, w) = parse_wua_json(bytes, "OfflineBytes(WuaJson)")?;
                Ok((wua_records_to_full(recs, Some("WuaJson")), w))
            }
            other => Err(ForensicError::parse(
                "OfflineBytes",
                format!("unrecognized full_updates artifact magic ({other:?})"),
            )),
        },
    }
}

// ---------------------------------------------------------------------------
// 3. posture.defender_status
// ---------------------------------------------------------------------------

pub struct PostureDefenderStatusProvider {
    source: ForensicSource,
}

impl PostureDefenderStatusProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }

    pub fn query_with_warnings(&self, req: &TableQuery) -> Result<(TableData, Vec<DiagnosticWarning>), ForensicError> {
        let (records, warnings) = collect_defender_status(&self.source)?;
        let schema = self.schema();
        let rows: Vec<Row> = records
            .into_iter()
            .enumerate()
            .map(|(idx, rec)| record_to_defender_row(idx as u64 + 1, rec))
            .collect();
        let data = QueryHelper::apply(&schema, &rows, req)?;
        Ok((data, warnings))
    }
}

fn record_to_defender_row(row_id: u64, rec: DefenderPostureRecord) -> Row {
    let detail = serde_json::json!({
        "am_service_enabled": rec.am_service_enabled,
        "antivirus_enabled": rec.antivirus_enabled,
        "real_time_protection": rec.real_time_protection,
        "behavior_monitor_enabled": rec.behavior_monitor_enabled,
        "ioav_protection_enabled": rec.ioav_protection_enabled,
        "on_access_protection": rec.on_access_protection,
        "tamper_protected": rec.tamper_protected,
        "tamper_source": rec.tamper_source,
        "am_running_mode": rec.am_running_mode,
        "am_product_version": rec.am_product_version,
        "am_engine_version": rec.am_engine_version,
        "signature_version": rec.signature_version,
        "signature_updated": rec.signature_updated.map(|d| d.to_rfc3339()),
        "signature_age_days": rec.signature_age_days,
        "quick_scan_age": rec.quick_scan_age,
        "full_scan_age": rec.full_scan_age,
        "pua_protection": rec.pua_protection,
        "maps_reporting": rec.maps_reporting,
        "submit_samples_consent": rec.submit_samples_consent,
        "passive_mode": rec.passive_mode,
        "gpo_override_count": rec.gpo_override_count,
        "gpo_overrides": rec.gpo_overrides,
        "exclusions_hidden": rec.exclusions_hidden,
        "exclusion_paths": rec.exclusion_paths,
        "exclusion_processes": rec.exclusion_processes,
        "exclusion_extensions": rec.exclusion_extensions,
        "exclusion_ip_addresses": rec.exclusion_ip_addresses,
        "source_origin": rec.source_origin,
        "raw": rec.raw_detail,
    });

    Row::new(
        row_id,
        vec![
            opt_bool_cell(rec.am_service_enabled),
            opt_bool_cell(rec.antivirus_enabled),
            opt_bool_cell(rec.real_time_protection),
            opt_bool_cell(rec.behavior_monitor_enabled),
            opt_bool_cell(rec.ioav_protection_enabled),
            opt_bool_cell(rec.on_access_protection),
            opt_bool_cell(rec.tamper_protected),
            opt_text_cell(rec.tamper_source.as_deref()),
            opt_text_cell(rec.am_running_mode.as_deref()),
            opt_text_cell(rec.am_product_version.as_deref()),
            opt_text_cell(rec.am_engine_version.as_deref()),
            opt_text_cell(rec.signature_version.as_deref()),
            opt_ts_cell(rec.signature_updated),
            opt_u32_cell(rec.signature_age_days),
            opt_u32_cell(rec.quick_scan_age),
            opt_u32_cell(rec.full_scan_age),
            opt_text_cell(rec.pua_protection.as_deref()),
            opt_text_cell(rec.maps_reporting.as_deref()),
            opt_text_cell(rec.submit_samples_consent.as_deref()),
            opt_bool_cell(rec.passive_mode),
            CellValue::Uint(u64::from(rec.gpo_override_count)),
            join_or_null(&rec.exclusion_paths),
            join_or_null(&rec.exclusion_processes),
            join_or_null(&rec.exclusion_extensions),
            CellValue::Text(rec.source_origin),
        ],
    )
    .with_detail_json(detail)
}

impl TableProvider for PostureDefenderStatusProvider {
    fn tool_id(&self) -> &'static str {
        "posture.defender_status"
    }

    fn description(&self) -> &'static str {
        "Windows Defender MSFT_MpComputerStatus/MSFT_MpPreference and Registry posture view"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Windows Defender Posture",
            vec![
                ColumnDef::new("am_service_enabled", "AMServiceEnabled", ColumnType::Bool).with_width_hint(110),
                ColumnDef::new("antivirus_enabled", "AntivirusEnabled", ColumnType::Bool).with_width_hint(110),
                ColumnDef::new("real_time_protection", "RealTimeProtection", ColumnType::Bool).with_width_hint(120),
                ColumnDef::new("behavior_monitor_enabled", "BehaviorMonitorEnabled", ColumnType::Bool)
                    .with_width_hint(130),
                ColumnDef::new("ioav_protection_enabled", "IoavProtectionEnabled", ColumnType::Bool)
                    .with_width_hint(130),
                ColumnDef::new("on_access_protection", "OnAccessProtection", ColumnType::Bool).with_width_hint(130),
                ColumnDef::new("tamper_protected", "TamperProtected", ColumnType::Bool).with_width_hint(110),
                ColumnDef::new("tamper_source", "TamperProtectionSource", ColumnType::Text).with_width_hint(130),
                ColumnDef::new("am_running_mode", "AMRunningMode", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("am_product_version", "AMProductVersion", ColumnType::Text).with_width_hint(130),
                ColumnDef::new("am_engine_version", "AMEngineVersion", ColumnType::Text).with_width_hint(130),
                ColumnDef::new("signature_version", "SignatureVersion", ColumnType::Text).with_width_hint(130),
                ColumnDef::new("signature_updated", "SignatureUpdated", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("signature_age_days", "SignatureAgeDays", ColumnType::Uint).with_width_hint(110),
                ColumnDef::new("quick_scan_age", "QuickScanAge", ColumnType::Uint).with_width_hint(100),
                ColumnDef::new("full_scan_age", "FullScanAge", ColumnType::Uint).with_width_hint(100),
                ColumnDef::new("pua_protection", "PUAProtection", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("maps_reporting", "MAPSReporting", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("submit_samples_consent", "SubmitSamplesConsent", ColumnType::Text).with_width_hint(130),
                ColumnDef::new("passive_mode", "PassiveMode", ColumnType::Bool).with_width_hint(100),
                ColumnDef::new("gpo_override_count", "GpoOverrides", ColumnType::Uint).with_width_hint(100),
                ColumnDef::new("exclusion_paths", "ExclusionPaths", ColumnType::Text).with_width_hint(240),
                ColumnDef::new("exclusion_processes", "ExclusionProcesses", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("exclusion_extensions", "ExclusionExtensions", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("source_origin", "Source", ColumnType::Text).with_width_hint(140),
            ],
        )
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        self.query_with_warnings(req)
            .map(|(data, _)| data)
            .map_err(TableError::from)
    }
}

fn collect_defender_status(
    source: &ForensicSource,
) -> Result<(Vec<DefenderPostureRecord>, Vec<DiagnosticWarning>), ForensicError> {
    match source {
        ForensicSource::Live => {
            #[cfg(not(windows))]
            {
                Err(ForensicError::unsupported_platform(
                    "posture.defender_status",
                    "live Windows Defender posture queries require Windows",
                ))
            }
            #[cfg(windows)]
            {
                let (wmi, mut wmi_warn) = live::collect_live_defender_wmi();
                let (reg, mut reg_warn) = live::collect_live_defender_registry();
                let mut warnings = Vec::new();
                warnings.append(&mut wmi_warn);
                warnings.append(&mut reg_warn);

                let origin = match (wmi.is_some(), reg.is_some()) {
                    (true, true) => "WMI+Registry",
                    (true, false) => "WMI",
                    (false, true) => "Registry",
                    (false, false) => {
                        return Ok((Vec::new(), warnings));
                    }
                };

                let rec = correlate_defender_snapshots(wmi, reg, origin, "posture.defender_status", &mut warnings);
                Ok((vec![rec], warnings))
            }
        }
        ForensicSource::OfflinePath(path) => {
            if !path.exists() {
                return Err(ForensicError::NotFound(path.display().to_string()));
            }
            if path.is_file() {
                let kind = sniff_file_head(path)?;
                return match kind {
                    ArtifactKind::Regf => {
                        let (reg, mut warnings) = parse_defender_from_regf_path(path)?;
                        let rec = correlate_defender_snapshots(
                            None,
                            Some(reg),
                            "OfflineHive",
                            "posture.defender_status",
                            &mut warnings,
                        );
                        Ok((vec![rec], warnings))
                    }
                    ArtifactKind::Json => {
                        let bytes =
                            fs::read(path).map_err(|e| ForensicError::io_classified(path.display().to_string(), e))?;
                        parse_defender_json(&bytes, &path.display().to_string())
                    }
                    other => Err(ForensicError::parse(
                        path.display().to_string(),
                        format!("expected SOFTWARE regf hive or Defender JSON, got {other:?}"),
                    )),
                };
            }

            let mut warnings = Vec::new();
            let mut reg_snap: Option<DefenderRegistrySnapshot> = None;
            let mut json_records: Vec<DefenderPostureRecord> = Vec::new();

            // Check well-known SOFTWARE hive locations first, then directory walk.
            let known_hive = [
                path.join("SOFTWARE"),
                path.join("Windows\\System32\\config\\SOFTWARE"),
                path.join("System32\\config\\SOFTWARE"),
            ]
            .into_iter()
            .find(|p| p.is_file());

            let hive_candidates: Vec<PathBuf> = if let Some(h) = known_hive {
                vec![h]
            } else {
                discover_files_in_dir(path, "posture.defender_status", &mut warnings, |p| {
                    let name = p
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    name == "software" || name.ends_with(".hiv") || name.ends_with(".regf")
                })
            };

            for cand in hive_candidates {
                if sniff_file_head(&cand).ok() == Some(ArtifactKind::Regf) {
                    match parse_defender_from_regf_path(&cand) {
                        Ok((snap, mut w)) => {
                            warnings.append(&mut w);
                            reg_snap = Some(snap);
                            break;
                        }
                        Err(err) => warnings.push(DiagnosticWarning {
                            severity: WarningSeverity::Warn,
                            tool_id: "posture.defender_status".to_string(),
                            source: cand.display().to_string(),
                            message: format!("Defender key read note: {err}"),
                        }),
                    }
                }
            }

            let json_candidates = discover_files_in_dir(path, "posture.defender_status", &mut warnings, |p| {
                let name = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                name.ends_with(".json") && (name.contains("defender") || name == "status.json")
            });

            if let Some(reg) = reg_snap {
                for cand in &json_candidates {
                    if let Ok(bytes) = fs::read(cand)
                        && let Ok(wmi_snaps) = parse_defender_wmi_bundle_json(&bytes, &cand.display().to_string())
                        && !wmi_snaps.is_empty()
                    {
                        let recs = wmi_snaps
                            .into_iter()
                            .map(|wmi_snap| {
                                correlate_defender_snapshots(
                                    Some(wmi_snap),
                                    Some(reg.clone()),
                                    "OfflineHive+Json",
                                    "posture.defender_status",
                                    &mut warnings,
                                )
                            })
                            .collect();
                        return Ok((recs, warnings));
                    }
                }
                let rec = correlate_defender_snapshots(
                    None,
                    Some(reg),
                    "OfflineHive",
                    "posture.defender_status",
                    &mut warnings,
                );
                return Ok((vec![rec], warnings));
            }

            for cand in &json_candidates {
                if let Ok(bytes) = fs::read(cand)
                    && let Ok((mut recs, mut w)) = parse_defender_json(&bytes, &cand.display().to_string())
                {
                    warnings.append(&mut w);
                    json_records.append(&mut recs);
                }
            }

            if !json_records.is_empty() {
                Ok((json_records, warnings))
            } else {
                Err(ForensicError::NotFound(format!(
                    "no SOFTWARE hive or Defender JSON found under {}",
                    path.display()
                )))
            }
        }
        ForensicSource::OfflineBytes(bytes) => match sniff_magic(bytes) {
            ArtifactKind::Regf => {
                let (reg, mut warnings) = parse_defender_from_regf_bytes(bytes, "OfflineBytes(SOFTWARE)")?;
                let rec = correlate_defender_snapshots(
                    None,
                    Some(reg),
                    "OfflineHive",
                    "posture.defender_status",
                    &mut warnings,
                );
                Ok((vec![rec], warnings))
            }
            ArtifactKind::Json => parse_defender_json(bytes, "OfflineBytes(DefenderJson)"),
            other => Err(ForensicError::parse(
                "OfflineBytes",
                format!("expected regf hive or Defender JSON bytes, got {other:?}"),
            )),
        },
    }
}

// ---------------------------------------------------------------------------
// 4. posture.security_center
// ---------------------------------------------------------------------------

pub struct PostureSecurityCenterProvider {
    source: ForensicSource,
}

impl PostureSecurityCenterProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }

    pub fn query_with_warnings(&self, req: &TableQuery) -> Result<(TableData, Vec<DiagnosticWarning>), ForensicError> {
        let (records, warnings) = collect_security_center(&self.source)?;
        let schema = self.schema();
        let rows: Vec<Row> = records
            .into_iter()
            .enumerate()
            .map(|(idx, rec)| {
                let detail = serde_json::json!({
                    "display_name": rec.display_name,
                    "product_type": rec.product_type,
                    "instance_guid": rec.instance_guid,
                    "product_state_hex": rec.product_state_hex,
                    "decoded_state": rec.decoded_state,
                    "enabled": rec.enabled,
                    "protection_state": rec.protection_state,
                    "up_to_date": rec.up_to_date,
                    "signature_status": rec.signature_status,
                    "provider_flags_hex": rec.provider_flags_hex,
                    "signed_executable": rec.signed_executable,
                    "reporting_executable": rec.reporting_executable,
                    "timestamp": rec.timestamp.map(|d| d.to_rfc3339()),
                    "is_default": rec.is_default,
                    "source": rec.source,
                });
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(rec.display_name),
                        CellValue::Text(rec.product_type),
                        opt_text_cell(rec.instance_guid.as_deref()),
                        opt_text_cell(rec.product_state_hex.as_deref()),
                        opt_bool_cell(rec.enabled),
                        CellValue::Text(rec.protection_state),
                        opt_bool_cell(rec.up_to_date),
                        CellValue::Text(rec.signature_status),
                        opt_text_cell(rec.provider_flags_hex.as_deref()),
                        opt_text_cell(rec.signed_executable.as_deref()),
                        opt_text_cell(rec.reporting_executable.as_deref()),
                        opt_ts_cell(rec.timestamp),
                        CellValue::Text(rec.source),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        let data = QueryHelper::apply(&schema, &rows, req)?;
        Ok((data, warnings))
    }
}

impl TableProvider for PostureSecurityCenterProvider {
    fn tool_id(&self) -> &'static str {
        "posture.security_center"
    }

    fn description(&self) -> &'static str {
        "WMI root\\SecurityCenter2 AV/Firewall/AntiSpyware productState bitmask decoder"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Windows Security Center Posture",
            vec![
                ColumnDef::new("display_name", "DisplayName", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("product_type", "ProductType", ColumnType::Text).with_width_hint(80),
                ColumnDef::new("instance_guid", "InstanceGuid", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("product_state_hex", "ProductStateHex", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("enabled", "Enabled", ColumnType::Bool).with_width_hint(90),
                ColumnDef::new("protection_state", "ProtectionState", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("up_to_date", "UpToDate", ColumnType::Bool).with_width_hint(90),
                ColumnDef::new("signature_status", "SignatureStatus", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("provider_flags_hex", "ProviderFlags", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("signed_executable", "SignedExecutable", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("reporting_executable", "ReportingExecutable", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("timestamp", "Timestamp", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("source", "Source", ColumnType::Text).with_width_hint(140),
            ],
        )
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        self.query_with_warnings(req)
            .map(|(data, _)| data)
            .map_err(TableError::from)
    }
}

fn collect_security_center(
    source: &ForensicSource,
) -> Result<(Vec<SecurityCenterRecord>, Vec<DiagnosticWarning>), ForensicError> {
    match source {
        ForensicSource::Live => {
            #[cfg(not(windows))]
            {
                Err(ForensicError::unsupported_platform(
                    "posture.security_center",
                    "live SecurityCenter2 / WSC queries require Windows",
                ))
            }
            #[cfg(windows)]
            {
                Ok(live::collect_live_security_center())
            }
        }
        ForensicSource::OfflinePath(path) => {
            if !path.exists() {
                return Err(ForensicError::NotFound(path.display().to_string()));
            }
            if path.is_file() {
                let bytes = fs::read(path).map_err(|e| ForensicError::io_classified(path.display().to_string(), e))?;
                return parse_security_center_json(&bytes, &path.display().to_string());
            }

            let mut warnings = Vec::new();
            let candidates = discover_files_in_dir(path, "posture.security_center", &mut warnings, |p| {
                let name = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                name.ends_with(".json") && (name.contains("security") || name.contains("wsc"))
            });
            for cand in candidates {
                if let Ok(bytes) = fs::read(&cand)
                    && let Ok((recs, mut w)) = parse_security_center_json(&bytes, &cand.display().to_string())
                {
                    warnings.append(&mut w);
                    return Ok((recs, warnings));
                }
            }

            Err(ForensicError::NotFound(format!(
                "no SecurityCenter2 JSON fixture found under {}",
                path.display()
            )))
        }
        ForensicSource::OfflineBytes(bytes) => parse_security_center_json(bytes, "OfflineBytes(SecurityCenter2)"),
    }
}

// ---------------------------------------------------------------------------
// Crate provider registry helpers
// ---------------------------------------------------------------------------

/// Instantiates all 4 strictly read-only posture `TableProvider`s bound to `source`
/// in canonical `FORENSIC_TOOL_CATALOG` order.
pub fn all_providers(source: &ForensicSource) -> Vec<Arc<dyn TableProvider>> {
    vec![
        Arc::new(PostureUpdatesProvider::new(source.clone())),
        Arc::new(PostureFullUpdatesProvider::new(source.clone())),
        Arc::new(PostureDefenderStatusProvider::new(source.clone())),
        Arc::new(PostureSecurityCenterProvider::new(source.clone())),
    ]
}

/// Instantiates all 4 posture providers bound to `ForensicSource::Live`.
pub fn default_providers() -> Vec<Arc<dyn TableProvider>> {
    all_providers(&ForensicSource::Live)
}

/// Looks up a single posture `TableProvider` by canonical `tool_id`.
pub fn provider_for_tool(tool_id: &str, source: &ForensicSource) -> Option<Arc<dyn TableProvider>> {
    match tool_id {
        "posture.updates" => Some(Arc::new(PostureUpdatesProvider::new(source.clone()))),
        "posture.full_updates" => Some(Arc::new(PostureFullUpdatesProvider::new(source.clone()))),
        "posture.defender_status" => Some(Arc::new(PostureDefenderStatusProvider::new(source.clone()))),
        "posture.security_center" => Some(Arc::new(PostureSecurityCenterProvider::new(source.clone()))),
        _ => None,
    }
}

/// Convenience helper checking whether `p` looks like a posture artifact file path.
pub fn is_known_posture_filename(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        name.as_str(),
        "datastore.edb" | "store.db" | "cbs.log" | "cbs.persist.log" | "software"
    )
}
