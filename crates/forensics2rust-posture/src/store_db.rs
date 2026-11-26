#![forbid(unsafe_code)]

//! Pure-Rust / `rusqlite` parser for `USOPrivate\UpdateStore\store.db`
//! (`COMPLETEDUPDATES` + `UPDATEEVENTHISTORYDIAGNOSTICS` SQLite tables, with ESE `0x89ABCDEF` fallback).

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc};
use forensics2rust_core::{DiagnosticWarning, ForensicError, WarningSeverity};
use forensics2rust_srum::ese::EseDatabase;
use rusqlite::{Connection, OpenFlags, types::ValueRef};

use crate::datastore_ese::parse_datastore_ese;
use crate::discovery::{
    ArtifactKind, TempDbFile, extract_build_version, extract_kb_articles, normalize_guid_str, parse_flexible_timestamp,
    sniff_file_head, sniff_magic,
};

/// Normalized aggregated update history record used by `posture.full_updates`.
#[derive(Debug, Clone)]
pub struct FullUpdateRecord {
    pub title: String,
    pub install_date: Option<DateTime<Utc>>,
    pub kb_number: Option<String>,
    pub category: String,
    pub build_version: Option<String>,
    pub source_db: String,
    pub update_id: Option<String>,
    pub result: Option<String>,
    pub description: Option<String>,
    pub more_info_url: Option<String>,
    pub provider_id: Option<String>,
    pub detail_extra: serde_json::Value,
}

/// Opens and parses `USOPrivate\UpdateStore\store.db` from a file path.
///
/// Supports SQLite 3 (with automatic RAII shared-copy fallback if locked by `UsoSvc`)
/// as well as legacy ESE `0x89ABCDEF` `store.db` files.
pub fn parse_store_db_path(path: &Path) -> Result<(Vec<FullUpdateRecord>, Vec<DiagnosticWarning>), ForensicError> {
    let source_label = path.display().to_string();
    let kind = sniff_file_head(path)?;
    match kind {
        ArtifactKind::Ese => {
            let db = EseDatabase::open(path)?;
            parse_ese_store_db(&db, &source_label)
        }
        ArtifactKind::Sqlite | ArtifactKind::Unknown => {
            let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
            match Connection::open_with_flags(path, flags) {
                Ok(conn) => match query_sqlite_store_db(&conn, &source_label) {
                    Ok(res) => Ok(res),
                    Err(err) => {
                        // Retry via shared byte copy in case of SQLite WAL / sharing-lock contention.
                        if let Ok(bytes) = fs::read(path)
                            && sniff_magic(&bytes) == ArtifactKind::Sqlite
                        {
                            let mut res = parse_sqlite_store_db_bytes(&bytes, &source_label)?;
                            res.1.push(DiagnosticWarning {
                                severity: WarningSeverity::Info,
                                tool_id: "posture.full_updates".to_string(),
                                source: source_label,
                                message: format!("used shared temp copy after direct SQLite read error: {err}"),
                            });
                            return Ok(res);
                        }
                        Err(err)
                    }
                },
                Err(open_err) => {
                    let bytes = fs::read(path)
                        .map_err(|io_err| ForensicError::io_classified(path.display().to_string(), io_err))?;
                    if sniff_magic(&bytes) == ArtifactKind::Ese {
                        let db = EseDatabase::from_bytes(&bytes)?;
                        return parse_ese_store_db(&db, &source_label);
                    }
                    if sniff_magic(&bytes) != ArtifactKind::Sqlite {
                        return Err(ForensicError::parse(
                            &source_label,
                            format!("unrecognized store.db format (SQLite open error: {open_err})"),
                        ));
                    }
                    let mut res = parse_sqlite_store_db_bytes(&bytes, &source_label)?;
                    res.1.push(DiagnosticWarning {
                        severity: WarningSeverity::Info,
                        tool_id: "posture.full_updates".to_string(),
                        source: source_label,
                        message: format!("opened shared temp copy after SQLite open error: {open_err}"),
                    });
                    Ok(res)
                }
            }
        }
        other => Err(ForensicError::parse(
            source_label,
            format!("expected SQLite or ESE store.db, detected {other:?}"),
        )),
    }
}

/// Parses an in-memory `store.db` byte slice (SQLite 3 via RAII `TempDbFile` or ESE fallback).
pub fn parse_store_db_bytes(
    bytes: &[u8],
    source_label: &str,
) -> Result<(Vec<FullUpdateRecord>, Vec<DiagnosticWarning>), ForensicError> {
    match sniff_magic(bytes) {
        ArtifactKind::Sqlite => parse_sqlite_store_db_bytes(bytes, source_label),
        ArtifactKind::Ese => {
            let db = EseDatabase::from_bytes(bytes)?;
            parse_ese_store_db(&db, source_label)
        }
        other => Err(ForensicError::parse(
            source_label,
            format!("unrecognized store.db magic ({other:?})"),
        )),
    }
}

fn parse_sqlite_store_db_bytes(
    bytes: &[u8],
    source_label: &str,
) -> Result<(Vec<FullUpdateRecord>, Vec<DiagnosticWarning>), ForensicError> {
    if !bytes.starts_with(b"SQLite format 3\0") {
        return Err(ForensicError::parse(
            source_label,
            "buffer does not start with SQLite format 3 magic",
        ));
    }
    let tmp = TempDbFile::from_bytes(bytes, "f2r_posture_storedb")?;
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(tmp.path(), flags)
        .map_err(|e| ForensicError::parse(source_label, format!("failed opening SQLite store.db: {e}")))?;
    query_sqlite_store_db(&conn, source_label)
}

fn query_sqlite_store_db(
    conn: &Connection,
    source_label: &str,
) -> Result<(Vec<FullUpdateRecord>, Vec<DiagnosticWarning>), ForensicError> {
    let mut warnings = Vec::new();
    let mut tables = HashSet::new();
    {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table'")
            .map_err(|e| ForensicError::parse(source_label, format!("sqlite_master query failed: {e}")))?;
        let mut rows = stmt
            .query([])
            .map_err(|e| ForensicError::parse(source_label, format!("sqlite_master exec failed: {e}")))?;
        while let Some(row) = rows
            .next()
            .map_err(|e| ForensicError::parse(source_label, format!("sqlite_master row failed: {e}")))?
        {
            if let Ok(name) = row.get::<_, String>(0) {
                tables.insert(name.to_ascii_uppercase());
            }
        }
    }

    if !tables.contains("COMPLETEDUPDATES") && !tables.contains("UPDATEEVENTHISTORYDIAGNOSTICS") {
        return Err(ForensicError::parse(
            source_label,
            "SQLite database missing COMPLETEDUPDATES and UPDATEEVENTHISTORYDIAGNOSTICS tables",
        ));
    }

    let mut records = Vec::new();
    let mut seen_completed_ids: HashSet<String> = HashSet::new();

    if tables.contains("COMPLETEDUPDATES") {
        let cols = table_column_names(conn, "COMPLETEDUPDATES", source_label)?;
        let select_sql = build_dynamic_select(
            "COMPLETEDUPDATES",
            &cols,
            &[
                "PROVIDERID",
                "UPDATEID",
                "TIME",
                "TITLE",
                "DESCRIPTION",
                "MOREINFOURL",
                "HISTORYCATEGORY",
                "UNINSTALL",
                "WASREBOOTREQUIRED",
                "FOROS",
                "METADATA",
            ],
        );
        let mut stmt = conn
            .prepare(&select_sql)
            .map_err(|e| ForensicError::parse(source_label, format!("COMPLETEDUPDATES prepare failed: {e}")))?;
        let mut rows = stmt
            .query([])
            .map_err(|e| ForensicError::parse(source_label, format!("COMPLETEDUPDATES query failed: {e}")))?;
        while let Some(row) = rows
            .next()
            .map_err(|e| ForensicError::parse(source_label, format!("COMPLETEDUPDATES row failed: {e}")))?
        {
            let provider_id = sql_opt_string(row, 0);
            let update_id = sql_opt_string(row, 1).and_then(|s| normalize_guid_str(&s).or(Some(s)));
            let time_raw = sql_opt_string(row, 2);
            let install_date = time_raw.as_deref().and_then(parse_flexible_timestamp);
            let title = sql_opt_string(row, 3).unwrap_or_default();
            let description = sql_opt_string(row, 4);
            let more_info_url = sql_opt_string(row, 5);
            let category = sql_opt_string(row, 6).unwrap_or_else(|| "Update".to_string());
            let uninstall = sql_opt_string(row, 7);
            let reboot_required = sql_opt_string(row, 8);
            let for_os = sql_opt_string(row, 9);
            let metadata = sql_opt_string(row, 10);

            if title.is_empty() && update_id.is_none() {
                continue;
            }

            if let Some(ref uid) = update_id {
                seen_completed_ids.insert(uid.clone());
            }

            let desc_str = description.as_deref().unwrap_or("");
            let url_str = more_info_url.as_deref().unwrap_or("");
            let meta_str = metadata.as_deref().unwrap_or("");
            let kbs = extract_kb_articles(&[&title, desc_str, url_str, meta_str]);
            let kb_number = if kbs.is_empty() { None } else { Some(kbs.join("; ")) };

            let build_version = extract_build_version(&title)
                .or_else(|| for_os.as_deref().and_then(extract_build_version))
                .or_else(|| extract_build_version(meta_str))
                .or_else(|| extract_build_version(desc_str));

            let display_title = if title.is_empty() {
                update_id.clone().unwrap_or_else(|| "USO Update".to_string())
            } else {
                title
            };

            records.push(FullUpdateRecord {
                title: display_title,
                install_date,
                kb_number,
                category,
                build_version,
                source_db: "store.db (COMPLETEDUPDATES)".to_string(),
                update_id,
                result: Some("Completed".to_string()),
                description,
                more_info_url,
                provider_id,
                detail_extra: serde_json::json!({
                    "table": "COMPLETEDUPDATES",
                    "raw_time": time_raw,
                    "uninstall": uninstall,
                    "was_reboot_required": reboot_required,
                    "for_os": for_os,
                    "metadata": metadata,
                    "source_label": source_label,
                }),
            });
        }
    }

    if tables.contains("UPDATEEVENTHISTORYDIAGNOSTICS") {
        let cols = table_column_names(conn, "UPDATEEVENTHISTORYDIAGNOSTICS", source_label)?;
        let select_sql = build_dynamic_select(
            "UPDATEEVENTHISTORYDIAGNOSTICS",
            &cols,
            &[
                "PROVIDERID",
                "UPDATEID",
                "STARTTIME",
                "ENDTIME",
                "EVENT",
                "CATEGORY",
                "TITLE",
                "RESULT",
                "REASON",
                "UPDATEMETADATA",
            ],
        );
        let mut stmt = conn.prepare(&select_sql).map_err(|e| {
            ForensicError::parse(
                source_label,
                format!("UPDATEEVENTHISTORYDIAGNOSTICS prepare failed: {e}"),
            )
        })?;
        let mut rows = stmt.query([]).map_err(|e| {
            ForensicError::parse(source_label, format!("UPDATEEVENTHISTORYDIAGNOSTICS query failed: {e}"))
        })?;
        while let Some(row) = rows
            .next()
            .map_err(|e| ForensicError::parse(source_label, format!("UPDATEEVENTHISTORYDIAGNOSTICS row failed: {e}")))?
        {
            let provider_id = sql_opt_string(row, 0);
            let update_id = sql_opt_string(row, 1).and_then(|s| normalize_guid_str(&s).or(Some(s)));
            let start_raw = sql_opt_string(row, 2);
            let end_raw = sql_opt_string(row, 3);
            let event = sql_opt_string(row, 4);
            let category = sql_opt_string(row, 5)
                .or_else(|| event.clone())
                .unwrap_or_else(|| "Diagnostic".to_string());
            let title = sql_opt_string(row, 6).unwrap_or_default();
            let result = sql_opt_string(row, 7);
            let reason = sql_opt_string(row, 8);
            let update_meta = sql_opt_string(row, 9);

            // Avoid flooding if update already has a Completed row unless this event failed/has distinct error.
            let is_error = result
                .as_deref()
                .is_some_and(|r| !r.eq_ignore_ascii_case("0") && !r.eq_ignore_ascii_case("Succeeded"));
            if let Some(ref uid) = update_id
                && seen_completed_ids.contains(uid)
                && !is_error
            {
                continue;
            }

            let install_date = end_raw
                .as_deref()
                .and_then(parse_flexible_timestamp)
                .or_else(|| start_raw.as_deref().and_then(parse_flexible_timestamp));

            let meta_str = update_meta.as_deref().unwrap_or("");
            let kbs = extract_kb_articles(&[&title, meta_str]);
            let kb_number = if kbs.is_empty() { None } else { Some(kbs.join("; ")) };
            let build_version = extract_build_version(&title).or_else(|| extract_build_version(meta_str));

            let display_title = if !title.is_empty() {
                title
            } else if let Some(ref ev) = event {
                format!("{ev} ({})", update_id.as_deref().unwrap_or("unknown"))
            } else {
                update_id.clone().unwrap_or_else(|| "USO Diagnostic Event".to_string())
            };

            records.push(FullUpdateRecord {
                title: display_title,
                install_date,
                kb_number,
                category,
                build_version,
                source_db: "store.db (UPDATEEVENTHISTORYDIAGNOSTICS)".to_string(),
                update_id,
                result: result.clone(),
                description: reason.clone(),
                more_info_url: None,
                provider_id,
                detail_extra: serde_json::json!({
                    "table": "UPDATEEVENTHISTORYDIAGNOSTICS",
                    "event": event,
                    "start_time": start_raw,
                    "end_time": end_raw,
                    "result": result,
                    "reason": reason,
                    "update_metadata": update_meta,
                    "source_label": source_label,
                }),
            });
        }
    }

    if records.is_empty() {
        warnings.push(DiagnosticWarning {
            severity: WarningSeverity::Info,
            tool_id: "posture.full_updates".to_string(),
            source: source_label.to_string(),
            message: "store.db contained 0 update rows".to_string(),
        });
    }

    Ok((records, warnings))
}

fn table_column_names(
    conn: &Connection,
    table_name: &str,
    source_label: &str,
) -> Result<HashSet<String>, ForensicError> {
    let mut cols = HashSet::new();
    let sql = format!("PRAGMA table_info(\"{table_name}\")");
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| ForensicError::parse(source_label, format!("PRAGMA table_info failed: {e}")))?;
    let mut rows = stmt
        .query([])
        .map_err(|e| ForensicError::parse(source_label, format!("PRAGMA table_info exec failed: {e}")))?;
    while let Some(row) = rows
        .next()
        .map_err(|e| ForensicError::parse(source_label, format!("PRAGMA table_info row failed: {e}")))?
    {
        if let Ok(name) = row.get::<_, String>(1) {
            cols.insert(name.to_ascii_uppercase());
        }
    }
    Ok(cols)
}

fn build_dynamic_select(table: &str, existing_cols: &HashSet<String>, desired: &[&str]) -> String {
    let exprs: Vec<String> = desired
        .iter()
        .map(|col| {
            if existing_cols.contains(&col.to_ascii_uppercase()) {
                format!("\"{col}\"")
            } else {
                "NULL".to_string()
            }
        })
        .collect();
    format!("SELECT {} FROM \"{table}\"", exprs.join(", "))
}

fn sql_opt_string(row: &rusqlite::Row<'_>, idx: usize) -> Option<String> {
    match row.get_ref(idx).ok()? {
        ValueRef::Null => None,
        ValueRef::Integer(i) => Some(i.to_string()),
        ValueRef::Real(f) => Some(f.to_string()),
        ValueRef::Text(bytes) => {
            let s = String::from_utf8_lossy(bytes).trim().to_string();
            if s.is_empty() { None } else { Some(s) }
        }
        ValueRef::Blob(bytes) => {
            if bytes.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(bytes).trim().to_string())
            }
        }
    }
}

fn parse_ese_store_db(
    db: &EseDatabase,
    source_label: &str,
) -> Result<(Vec<FullUpdateRecord>, Vec<DiagnosticWarning>), ForensicError> {
    if db.table_schema("tbHistory").is_some() {
        let (hist, warnings) = parse_datastore_ese(db, source_label)?;
        let out = hist
            .into_iter()
            .map(|h| {
                let build_version = extract_build_version(&h.title).or_else(|| extract_build_version(&h.description));
                FullUpdateRecord {
                    title: h.title,
                    install_date: h.install_date,
                    kb_number: h.kb_article,
                    category: h.operation,
                    build_version,
                    source_db: "store.db (ESE)".to_string(),
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
            .collect();
        return Ok((out, warnings));
    }

    let mut warnings = db.warnings().to_vec();
    let mut records = Vec::new();
    for table_name in db.table_names() {
        if table_name.starts_with("MSys") {
            continue;
        }
        match db.read_table(&table_name) {
            Ok(tbl) => {
                for row in &tbl.rows {
                    let title = row
                        .values
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("TITLE") || k.eq_ignore_ascii_case("Name"))
                        .map(|(_, v)| v.display_compact())
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| format!("{table_name} record"));
                    let install_date = row
                        .values
                        .iter()
                        .find(|(k, _)| {
                            k.eq_ignore_ascii_case("TIME")
                                || k.eq_ignore_ascii_case("Date")
                                || k.eq_ignore_ascii_case("InstallDate")
                        })
                        .and_then(|(_, v)| parse_flexible_timestamp(&v.display_compact()));
                    let kbs = extract_kb_articles(&[&title]);
                    let kb_number = if kbs.is_empty() { None } else { Some(kbs.join("; ")) };
                    records.push(FullUpdateRecord {
                        title,
                        install_date,
                        kb_number,
                        category: table_name.clone(),
                        build_version: None,
                        source_db: format!("store.db (ESE:{table_name})"),
                        update_id: None,
                        result: None,
                        description: None,
                        more_info_url: None,
                        provider_id: None,
                        detail_extra: serde_json::json!({ "table": table_name, "source_label": source_label }),
                    });
                }
            }
            Err(err) => warnings.push(DiagnosticWarning {
                severity: WarningSeverity::Warn,
                tool_id: "posture.full_updates".to_string(),
                source: source_label.to_string(),
                message: format!("failed reading ESE table {table_name}: {err}"),
            }),
        }
    }
    Ok((records, warnings))
}
