#![forbid(unsafe_code)]

//! Pure-Rust `DataStore.edb` ESE parser and offline WUA JSON parser for `posture.updates`
//! (Windows Updates History) and `posture.full_updates` (Full Updates History).

use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use forensics2rust_core::{
    DiagnosticWarning, ForensicError, WarningSeverity, ole_automation_date_to_utc, parse_guid_le,
};
use forensics2rust_srum::ese::{EseDatabase, EseRow, EseValue};
use serde::Deserialize;

use crate::discovery::{extract_build_version, extract_kb_articles, normalize_guid_str, parse_flexible_timestamp};

/// Normalized Windows Update history record produced by WUA COM, `DataStore.edb`, or WUA JSON.
#[derive(Debug, Clone)]
pub struct UpdateHistoryRecord {
    pub title: String,
    pub description: String,
    pub install_date: Option<DateTime<Utc>>,
    pub operation: String,
    pub result_code: String,
    pub hresult: Option<i32>,
    pub unmapped_result_code: Option<i32>,
    pub kb_article: Option<String>,
    pub update_id: Option<String>,
    pub revision_number: Option<i32>,
    pub support_url: Option<String>,
    pub client_app_id: Option<String>,
    pub service_id: Option<String>,
    pub categories: Vec<String>,
    pub source_db: String,
    pub detail_extra: serde_json::Value,
}

#[derive(Debug, Clone, Default)]
struct UpdateMeta {
    id_local: Option<i32>,
    revision_number: Option<i32>,
    flight_build: Option<i32>,
    kb_articles: Vec<String>,
    support_url: Option<String>,
    more_info_url: Option<String>,
    product_name: Option<String>,
    msrc_severity: Option<String>,
    security_bulletin_ids: Option<String>,
    cve_ids: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct LocalizedProps {
    language: Option<String>,
    title: Option<String>,
    description: Option<String>,
    support_url: Option<String>,
    more_info_url: Option<String>,
}

/// Maps WUA `OperationResultCode` / `tbHistory.Status` integer values to canonical labels.
pub fn map_operation_result_code(code: i32) -> String {
    match code {
        0 => "NotStarted".to_string(),
        1 => "InProgress".to_string(),
        2 => "Succeeded".to_string(),
        3 => "SucceededWithErrors".to_string(),
        4 => "Failed".to_string(),
        5 => "Aborted".to_string(),
        other => format!("Unknown({other})"),
    }
}

/// Maps WUA `UpdateOperation` / `tbHistory.Flags` integer values to canonical labels.
pub fn map_update_operation(op: i32) -> String {
    match op {
        2 => "Uninstallation".to_string(),
        1 | 0 => "Installation".to_string(),
        other => format!("Operation({other})"),
    }
}

/// Opens and parses a `DataStore.edb` file from disk via `forensics2rust-srum::ese::EseDatabase`.
pub fn parse_datastore_ese_path(
    path: &Path,
) -> Result<(Vec<UpdateHistoryRecord>, Vec<DiagnosticWarning>), ForensicError> {
    let db = EseDatabase::open(path)?;
    parse_datastore_ese(&db, &path.display().to_string())
}

/// Parses an in-memory `DataStore.edb` byte slice via `forensics2rust-srum::ese::EseDatabase`.
pub fn parse_datastore_ese_bytes(
    bytes: &[u8],
    source_label: &str,
) -> Result<(Vec<UpdateHistoryRecord>, Vec<DiagnosticWarning>), ForensicError> {
    let db = EseDatabase::from_bytes(bytes)?;
    parse_datastore_ese(&db, source_label)
}

/// Parses `tbHistory`, `tbUpdates`, `tbUpdateLocalizedProps`, and `tbFiles` from an opened `EseDatabase`.
pub fn parse_datastore_ese(
    db: &EseDatabase,
    source_label: &str,
) -> Result<(Vec<UpdateHistoryRecord>, Vec<DiagnosticWarning>), ForensicError> {
    let mut warnings = db.warnings().to_vec();

    // 1. Read tbUpdates (optional) for KBArticleIds, SupportUrl, MoreInfoUrl, IdLocal join.
    let mut updates_by_guid: HashMap<String, UpdateMeta> = HashMap::new();
    if db.table_schema("tbUpdates").is_some() {
        match db.read_table("tbUpdates") {
            Ok(tbl) => {
                for row in &tbl.rows {
                    if let Some(guid) = extract_ese_guid(row, &["UpdateId", "UpdateID"]) {
                        let id_local = extract_ese_i32(row, &["IdLocal"]);
                        let revision_number = extract_ese_i32(row, &["RevisionNumber"]);
                        let flight_build = extract_ese_i32(row, &["FlightBuildNumber"]);
                        let support_url = extract_ese_text(row, &["SupportUrl", "SupportURL"]);
                        let more_info_url = extract_ese_text(row, &["MoreInfoUrl", "MoreInfoURL"]);
                        let product_name = extract_ese_text(row, &["ProductName"]);
                        let msrc_severity = extract_ese_text(row, &["MsrcSeverity"]);
                        let security_bulletin_ids = extract_ese_text(row, &["SecurityBulletinIds"]);
                        let cve_ids = extract_ese_text(row, &["CveIds"]);
                        let kb_raw = extract_ese_text(row, &["KBArticleIds", "KBArticleIDs"]);
                        let kb_articles = parse_kb_column(kb_raw.as_deref());

                        let meta = UpdateMeta {
                            id_local,
                            revision_number,
                            flight_build,
                            kb_articles,
                            support_url,
                            more_info_url,
                            product_name,
                            msrc_severity,
                            security_bulletin_ids,
                            cve_ids,
                        };
                        match updates_by_guid.get_mut(&guid) {
                            None => {
                                updates_by_guid.insert(guid, meta);
                            }
                            Some(existing) => {
                                let incoming_rev = meta.revision_number.unwrap_or(i32::MIN);
                                let existing_rev = existing.revision_number.unwrap_or(i32::MIN);
                                if incoming_rev > existing_rev {
                                    let mut updated = meta;
                                    if updated.kb_articles.is_empty() {
                                        updated.kb_articles = std::mem::take(&mut existing.kb_articles);
                                    }
                                    updated.support_url = updated.support_url.or_else(|| existing.support_url.take());
                                    updated.more_info_url =
                                        updated.more_info_url.or_else(|| existing.more_info_url.take());
                                    updated.product_name =
                                        updated.product_name.or_else(|| existing.product_name.take());
                                    updated.msrc_severity =
                                        updated.msrc_severity.or_else(|| existing.msrc_severity.take());
                                    updated.security_bulletin_ids = updated
                                        .security_bulletin_ids
                                        .or_else(|| existing.security_bulletin_ids.take());
                                    updated.cve_ids = updated.cve_ids.or_else(|| existing.cve_ids.take());
                                    updated.id_local = updated.id_local.or(existing.id_local);
                                    *existing = updated;
                                } else {
                                    if existing.kb_articles.is_empty() {
                                        existing.kb_articles = meta.kb_articles;
                                    }
                                    if existing.support_url.is_none() {
                                        existing.support_url = meta.support_url;
                                    }
                                    if existing.more_info_url.is_none() {
                                        existing.more_info_url = meta.more_info_url;
                                    }
                                    if existing.product_name.is_none() {
                                        existing.product_name = meta.product_name;
                                    }
                                    if existing.msrc_severity.is_none() {
                                        existing.msrc_severity = meta.msrc_severity;
                                    }
                                    if existing.security_bulletin_ids.is_none() {
                                        existing.security_bulletin_ids = meta.security_bulletin_ids;
                                    }
                                    if existing.cve_ids.is_none() {
                                        existing.cve_ids = meta.cve_ids;
                                    }
                                    if existing.id_local.is_none() {
                                        existing.id_local = meta.id_local;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(err) => warnings.push(DiagnosticWarning {
                severity: WarningSeverity::Warn,
                tool_id: "posture.updates".to_string(),
                source: source_label.to_string(),
                message: format!("unable to read tbUpdates metadata table: {err}"),
            }),
        }
    }

    // 2. Read tbUpdateLocalizedProps (optional) keyed by IdLocal.
    let mut localized_by_id: HashMap<i32, LocalizedProps> = HashMap::new();
    if db.table_schema("tbUpdateLocalizedProps").is_some() {
        match db.read_table("tbUpdateLocalizedProps") {
            Ok(tbl) => {
                for row in &tbl.rows {
                    let Some(id_local) = extract_ese_i32(row, &["IdLocal"]) else {
                        continue;
                    };
                    let language = extract_ese_text(row, &["Language"]);
                    let title = extract_ese_text(row, &["Title"]);
                    let description = extract_ese_text(row, &["Description"]);
                    let support_url = extract_ese_text(row, &["SupportUrl", "SupportURL"]);
                    let more_info_url = extract_ese_text(row, &["MoreInfoUrl", "MoreInfoURL"]);
                    let props = LocalizedProps {
                        language,
                        title,
                        description,
                        support_url,
                        more_info_url,
                    };
                    match localized_by_id.get(&id_local) {
                        None => {
                            localized_by_id.insert(id_local, props);
                        }
                        Some(existing)
                            if !is_english(existing.language.as_deref()) && is_english(props.language.as_deref()) =>
                        {
                            localized_by_id.insert(id_local, props);
                        }
                        _ => {}
                    }
                }
            }
            Err(err) => warnings.push(DiagnosticWarning {
                severity: WarningSeverity::Warn,
                tool_id: "posture.updates".to_string(),
                source: source_label.to_string(),
                message: format!("unable to read tbUpdateLocalizedProps table: {err}"),
            }),
        }
    }

    // 3. Read tbFiles (optional) to record payload file stats in diagnostics/detail if small/present.
    let tb_files_count = if db.table_schema("tbFiles").is_some() {
        match db.read_table("tbFiles") {
            Ok(tbl) => Some(tbl.rows.len()),
            Err(err) => {
                warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Info,
                    tool_id: "posture.updates".to_string(),
                    source: source_label.to_string(),
                    message: format!("tbFiles metadata unavailable: {err}"),
                });
                None
            }
        }
    } else {
        None
    };

    // 4. Read tbHistory (required for DataStore.edb history).
    let history_tbl = db.read_table("tbHistory")?;
    let mut records = Vec::with_capacity(history_tbl.rows.len());

    for row in &history_tbl.rows {
        let update_id = extract_ese_guid(row, &["UpdateId", "UpdateID"]);
        let update_meta = update_id.as_deref().and_then(|g| updates_by_guid.get(g));
        let loc_props = update_meta
            .and_then(|m| m.id_local)
            .and_then(|id| localized_by_id.get(&id));

        let mut title = extract_ese_text(row, &["Title"]).unwrap_or_default();
        if title.is_empty()
            && let Some(loc) = loc_props
            && let Some(ref lt) = loc.title
        {
            title = lt.clone();
        }

        let mut description = extract_ese_text(row, &["Description"]).unwrap_or_default();
        if description.is_empty()
            && let Some(loc) = loc_props
            && let Some(ref ld) = loc.description
        {
            description = ld.clone();
        }

        let support_url = extract_ese_text(row, &["SupportUrl", "SupportURL"])
            .or_else(|| update_meta.and_then(|m| m.support_url.clone()))
            .or_else(|| loc_props.and_then(|l| l.support_url.clone()));

        let more_info_url = extract_ese_text(row, &["MoreInfoUrl", "MoreInfoURL"])
            .or_else(|| update_meta.and_then(|m| m.more_info_url.clone()))
            .or_else(|| loc_props.and_then(|l| l.more_info_url.clone()));

        let install_date = extract_ese_datetime(row, &["Date"]);

        let status_code = extract_ese_i32(row, &["Status", "ResultCode"]).unwrap_or(0);
        let result_code = map_operation_result_code(status_code);

        let flags = extract_ese_i32(row, &["Flags", "Operation"]).unwrap_or(1);
        let operation = if (flags & 2) != 0 {
            "Uninstallation".to_string()
        } else {
            map_update_operation(flags)
        };

        let hresult = extract_ese_i32(row, &["MappedResult", "HResult"]);
        let unmapped_result_code = extract_ese_i32(row, &["UnmappedResult", "UnmappedResultCode"]);
        let client_app_id = extract_ese_text(row, &["ClientId", "ClientApplicationId", "ClientApplicationID"]);
        let service_id = extract_ese_guid(row, &["ServerId", "ServiceId", "ServiceID"]);

        let categories_raw = extract_ese_text(row, &["Categories"]);
        let categories: Vec<String> = categories_raw
            .as_deref()
            .map(|s| {
                s.split(';')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default();

        let mut kb_list = update_meta.map(|m| m.kb_articles.clone()).unwrap_or_default();
        if kb_list.is_empty() {
            let support_str = support_url.as_deref().unwrap_or("");
            let more_str = more_info_url.as_deref().unwrap_or("");
            kb_list = extract_kb_articles(&[&title, &description, support_str, more_str]);
        }
        let kb_article = if kb_list.is_empty() {
            None
        } else {
            Some(kb_list.join("; "))
        };

        if title.is_empty() && update_id.is_none() && install_date.is_none() {
            continue;
        }
        if title.is_empty() {
            title = update_id.clone().unwrap_or_else(|| "Windows Update Entry".to_string());
        }

        let build_version = update_meta
            .and_then(|m| m.flight_build.filter(|&b| b > 0).map(|b| b.to_string()))
            .or_else(|| extract_build_version(&title))
            .or_else(|| extract_build_version(&description));

        let detail_extra = serde_json::json!({
            "id_event": extract_ese_i32(row, &["IdEvent"]),
            "status_code": status_code,
            "flags": flags,
            "unmapped_result_code": unmapped_result_code,
            "more_info_url": more_info_url,
            "categories": categories,
            "build_version": build_version,
            "product_name": update_meta.and_then(|m| m.product_name.clone()),
            "msrc_severity": update_meta.and_then(|m| m.msrc_severity.clone()),
            "security_bulletin_ids": update_meta.and_then(|m| m.security_bulletin_ids.clone()),
            "cve_ids": update_meta.and_then(|m| m.cve_ids.clone()),
            "tb_files_count": tb_files_count,
        });

        records.push(UpdateHistoryRecord {
            title,
            description,
            install_date,
            operation,
            result_code,
            hresult,
            unmapped_result_code,
            kb_article,
            update_id,
            revision_number: update_meta.and_then(|m| m.revision_number),
            support_url,
            client_app_id,
            service_id,
            categories,
            source_db: "DataStore.edb".to_string(),
            detail_extra,
        });
    }

    Ok((records, warnings))
}

fn is_english(lang: Option<&str>) -> bool {
    lang.is_some_and(|l| l.to_ascii_lowercase().starts_with("en"))
}

fn parse_kb_column(raw: Option<&str>) -> Vec<String> {
    let Some(s) = raw else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for part in s.split([';', ',', ' ']) {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        if p.len() >= 6 && p.len() <= 7 && p.bytes().all(|b| b.is_ascii_digit()) {
            let kb = format!("KB{p}");
            if !out.contains(&kb) {
                out.push(kb);
            }
        } else {
            for kb in extract_kb_articles(&[p]) {
                if !out.contains(&kb) {
                    out.push(kb);
                }
            }
        }
    }
    out
}

fn extract_ese_text(row: &EseRow, candidates: &[&str]) -> Option<String> {
    for name in candidates {
        if let Some(val) = get_case_insensitive(row, name) {
            match val {
                EseValue::Text(s) => {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
                EseValue::Guid(g) => {
                    if let Some(norm) = normalize_guid_str(g) {
                        return Some(norm);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

fn extract_ese_i32(row: &EseRow, candidates: &[&str]) -> Option<i32> {
    for name in candidates {
        if let Some(val) = get_case_insensitive(row, name) {
            match val {
                EseValue::I32(v) => return Some(*v),
                EseValue::U32(v) => return Some(*v as i32),
                EseValue::I16(v) => return Some(i32::from(*v)),
                EseValue::U16(v) => return Some(i32::from(*v)),
                EseValue::U8(v) => return Some(i32::from(*v)),
                EseValue::I64(v) => return i32::try_from(*v).ok(),
                _ => {}
            }
        }
    }
    None
}

fn extract_ese_datetime(row: &EseRow, candidates: &[&str]) -> Option<DateTime<Utc>> {
    for name in candidates {
        if let Some(val) = get_case_insensitive(row, name) {
            match val {
                EseValue::DateTime(dt) => return Some(*dt),
                EseValue::F64(days) => return ole_automation_date_to_utc(*days),
                EseValue::Text(s) => return parse_flexible_timestamp(s),
                _ => {}
            }
        }
    }
    None
}

fn extract_ese_guid(row: &EseRow, candidates: &[&str]) -> Option<String> {
    for name in candidates {
        if let Some(val) = get_case_insensitive(row, name) {
            match val {
                EseValue::Guid(g) => return normalize_guid_str(g),
                EseValue::Binary(bytes) if bytes.len() >= 16 => {
                    if let Ok(g) = parse_guid_le(bytes) {
                        return Some(g);
                    }
                }
                EseValue::Text(s) => return normalize_guid_str(s),
                _ => {}
            }
        }
    }
    None
}

fn get_case_insensitive<'a>(row: &'a EseRow, target: &str) -> Option<&'a EseValue> {
    row.values.get(target).or_else(|| {
        row.values
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(target))
            .map(|(_, v)| v)
    })
}

#[derive(Debug, Deserialize)]
struct WuaJsonEntry {
    #[serde(alias = "Title")]
    title: Option<String>,
    #[serde(alias = "Description")]
    description: Option<String>,
    #[serde(alias = "InstallDate", alias = "Date")]
    install_date: Option<String>,
    #[serde(alias = "Operation")]
    operation: Option<serde_json::Value>,
    #[serde(alias = "ResultCode", alias = "Status")]
    result_code: Option<serde_json::Value>,
    #[serde(alias = "HResult", alias = "MappedResult")]
    hresult: Option<i32>,
    #[serde(alias = "UnmappedResultCode")]
    unmapped_result_code: Option<i32>,
    #[serde(alias = "KBArticle", alias = "kb_articles")]
    kb_article: Option<String>,
    #[serde(alias = "UpdateID", alias = "UpdateId")]
    update_id: Option<String>,
    #[serde(alias = "RevisionNumber")]
    revision_number: Option<i32>,
    #[serde(alias = "SupportURL", alias = "SupportUrl")]
    support_url: Option<String>,
    #[serde(alias = "ClientAppID", alias = "ClientApplicationID", alias = "ClientId")]
    client_app_id: Option<String>,
    #[serde(alias = "ServiceID", alias = "ServiceId")]
    service_id: Option<String>,
    #[serde(alias = "Categories")]
    categories: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct WuaJsonWrapper {
    #[serde(alias = "UpdateHistory")]
    updates: Vec<WuaJsonEntry>,
}

/// Parses an offline WUA JSON snapshot (`[...]` or `{ "updates": [...] }`).
pub fn parse_wua_json(
    bytes: &[u8],
    source_label: &str,
) -> Result<(Vec<UpdateHistoryRecord>, Vec<DiagnosticWarning>), ForensicError> {
    let trimmed = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    let entries = if let Ok(list) = serde_json::from_slice::<Vec<WuaJsonEntry>>(trimmed) {
        list
    } else if let Ok(wrapper) = serde_json::from_slice::<WuaJsonWrapper>(trimmed) {
        wrapper.updates
    } else {
        return Err(ForensicError::parse(
            source_label,
            "invalid WUA update history JSON (expected array or {\"updates\": [...]})",
        ));
    };

    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let title = entry.title.unwrap_or_default();
        let description = entry.description.unwrap_or_default();
        let install_date = entry.install_date.as_deref().and_then(parse_flexible_timestamp);

        let operation = match entry.operation {
            Some(serde_json::Value::String(s)) => s,
            Some(serde_json::Value::Number(n)) => map_update_operation(n.as_i64().unwrap_or(1) as i32),
            _ => "Installation".to_string(),
        };

        let result_code = match entry.result_code {
            Some(serde_json::Value::String(s)) => s,
            Some(serde_json::Value::Number(n)) => map_operation_result_code(n.as_i64().unwrap_or(0) as i32),
            _ => "Unknown".to_string(),
        };

        let support_url = entry.support_url;
        let kb_article = entry.kb_article.or_else(|| {
            let kbs = extract_kb_articles(&[&title, &description, support_url.as_deref().unwrap_or("")]);
            if kbs.is_empty() { None } else { Some(kbs.join("; ")) }
        });

        let update_id = entry.update_id.as_deref().and_then(normalize_guid_str);
        let categories = entry.categories.unwrap_or_default();
        let build_version = extract_build_version(&title).or_else(|| extract_build_version(&description));

        out.push(UpdateHistoryRecord {
            title,
            description,
            install_date,
            operation,
            result_code,
            hresult: entry.hresult,
            unmapped_result_code: entry.unmapped_result_code,
            kb_article,
            update_id,
            revision_number: entry.revision_number,
            support_url,
            client_app_id: entry.client_app_id,
            service_id: entry.service_id,
            categories: categories.clone(),
            source_db: "WuaJson".to_string(),
            detail_extra: serde_json::json!({
                "categories": categories,
                "build_version": build_version,
                "source_label": source_label,
            }),
        });
    }

    Ok((out, Vec::new()))
}
