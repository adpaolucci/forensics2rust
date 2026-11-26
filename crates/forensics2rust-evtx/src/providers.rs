use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use forensics2rust_core::{DiagnosticWarning, ForensicSource, QueryHelper};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};

use crate::model::{EvtxRecord, LiveQueryOptions};
use crate::parser::{load_channels, load_records, load_sources};
use crate::xml::parse_u64_flex;

/// Returns all 14 read-only EVTX [`TableProvider`] implementations in canonical catalog order.
pub fn all_providers(source: &ForensicSource) -> Vec<Arc<dyn TableProvider>> {
    all_providers_with_options(source, LiveQueryOptions::default())
}

/// Returns all 14 read-only EVTX [`TableProvider`] implementations using custom [`LiveQueryOptions`].
pub fn all_providers_with_options(source: &ForensicSource, live_opts: LiveQueryOptions) -> Vec<Arc<dyn TableProvider>> {
    vec![
        Arc::new(FullEventLogProvider::with_options(source.clone(), live_opts.clone())),
        Arc::new(LegacyEventProvider::with_options(source.clone(), live_opts.clone())),
        Arc::new(ChannelsProvider::new(source.clone())),
        Arc::new(SourcesProvider::new(source.clone())),
        Arc::new(LogonProvider::with_options(source.clone(), live_opts.clone())),
        Arc::new(UptimeProvider::with_options(source.clone(), live_opts.clone())),
        Arc::new(WifiProvider::with_options(source.clone(), live_opts.clone())),
        Arc::new(DefenderProvider::with_options(source.clone(), live_opts.clone())),
        Arc::new(TimelineProvider::with_options(source.clone(), live_opts.clone())),
        Arc::new(RdpProvider::with_options(source.clone(), live_opts.clone())),
        Arc::new(PowerShellProvider::with_options(source.clone(), live_opts.clone())),
        Arc::new(ProcessProvider::with_options(source.clone(), live_opts.clone())),
        Arc::new(TasksProvider::with_options(source.clone(), live_opts.clone())),
        Arc::new(UsbProvider::with_options(source.clone(), live_opts)),
    ]
}

fn col(id: &str, label: &str, col_type: ColumnType, width_hint: u16) -> ColumnDef {
    ColumnDef::new(id, label, col_type).with_width_hint(width_hint)
}

fn opt_text(s: Option<&str>) -> CellValue {
    match s.map(str::trim).filter(|v| !v.is_empty() && *v != "-") {
        Some(v) => CellValue::Text(v.to_string()),
        None => CellValue::Null,
    }
}

fn non_empty_text(s: &str) -> CellValue {
    let t = s.trim();
    if t.is_empty() || t == "-" {
        CellValue::Null
    } else {
        CellValue::Text(t.to_string())
    }
}

fn first_data<'a>(rec: &'a EvtxRecord, keys: &[&str]) -> Option<&'a str> {
    for &key in keys {
        if let Some(val) = rec.get_data(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() && trimmed != "-" {
                return Some(trimmed);
            }
        }
    }
    None
}

fn record_detail_json(rec: &EvtxRecord, tool_id: &str, extra: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "tool_id": tool_id,
        "record_id": rec.record_id,
        "event_time": rec.event_time.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        "event_id": rec.event_id,
        "level": rec.level_name(),
        "channel": rec.channel,
        "provider": rec.provider,
        "provider_guid": rec.provider_guid,
        "computer": rec.computer,
        "user_sid": rec.user_sid,
        "process_id": rec.process_id,
        "thread_id": rec.thread_id,
        "activity_id": rec.activity_id,
        "source_file": rec.source_file,
        "event_data": rec.event_data,
        "user_data": rec.user_data,
        "extra": extra,
        "raw_xml": rec.raw_xml,
    })
}

fn apply_rows(schema: &TableSchema, rows: &[Row], req: &TableQuery) -> Result<TableData, TableError> {
    QueryHelper::apply(schema, rows, req).map_err(|e| e.to_table_error())
}

fn live_opts_with_xpath(base: &LiveQueryOptions, xpath: &str) -> LiveQueryOptions {
    let mut opts = base.clone();
    if opts.xpath_query.is_none() {
        opts.xpath_query = Some(xpath.to_string());
    }
    opts
}

// ---------------------------------------------------------------------------
// 1. evtx.all — All EVTX Events
// ---------------------------------------------------------------------------

pub struct FullEventLogProvider {
    source: ForensicSource,
    live_opts: LiveQueryOptions,
}

impl FullEventLogProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self::with_options(source, LiveQueryOptions::default())
    }

    pub fn with_options(source: ForensicSource, live_opts: LiveQueryOptions) -> Self {
        Self { source, live_opts }
    }

    /// Queries all event log records and returns any non-fatal [`DiagnosticWarning`]s
    /// (for example, skipped inaccessible live channels such as `Security` when non-elevated).
    pub fn query_with_warnings(&self, req: &TableQuery) -> Result<(TableData, Vec<DiagnosticWarning>), TableError> {
        let loaded = load_records(
            &self.source,
            self.tool_id(),
            &["System", "Application", "Security"],
            &self.live_opts,
        )
        .map_err(|e| e.to_table_error())?;

        let rows: Vec<Row> = loaded
            .records
            .iter()
            .enumerate()
            .map(|(idx, rec)| {
                let opcode = rec.opcode_name.clone().unwrap_or_else(|| rec.opcode.to_string());
                let task = rec.task_name.clone().unwrap_or_else(|| rec.task.to_string());
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Uint(rec.record_id),
                        CellValue::Timestamp(rec.event_time),
                        CellValue::Uint(u64::from(rec.event_id)),
                        CellValue::Text(rec.level_name().to_string()),
                        non_empty_text(&rec.channel),
                        non_empty_text(&rec.provider),
                        CellValue::Text(opcode),
                        CellValue::Text(task),
                        opt_text(rec.user_sid.as_deref()),
                        non_empty_text(&rec.computer),
                        non_empty_text(&rec.description),
                    ],
                )
                .with_detail_json(record_detail_json(
                    rec,
                    self.tool_id(),
                    serde_json::json!({
                        "warnings_count": loaded.warnings.len(),
                        "warnings": &loaded.warnings,
                    }),
                ))
                .with_raw_bytes(rec.raw_bytes.clone())
            })
            .collect();

        let data = apply_rows(&self.schema(), &rows, req)?;
        Ok((data, loaded.warnings))
    }
}

impl TableProvider for FullEventLogProvider {
    fn tool_id(&self) -> &'static str {
        "evtx.all"
    }

    fn description(&self) -> &'static str {
        "Full Windows Event Log viewer across .evtx files/directories and live channels"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "All EVTX Events",
            vec![
                col("record_id", "RecordID", ColumnType::Uint, 90),
                col("event_time", "EventTime", ColumnType::Timestamp, 180),
                col("event_id", "EventID", ColumnType::Uint, 80),
                col("level", "Level", ColumnType::Text, 100),
                col("channel", "Channel", ColumnType::Text, 180),
                col("provider", "Provider", ColumnType::Text, 220),
                col("opcode", "Opcode", ColumnType::Text, 100),
                col("task", "Task", ColumnType::Text, 100),
                col("user_sid", "UserSID", ColumnType::Text, 180),
                col("computer", "Computer", ColumnType::Text, 150),
                col("description", "Description", ColumnType::Text, 320),
            ],
        )
        .with_default_sort(1, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        self.query_with_warnings(req).map(|(data, _)| data)
    }
}

// ---------------------------------------------------------------------------
// 2. evtx.legacy — Legacy Event Logs
// ---------------------------------------------------------------------------

pub struct LegacyEventProvider {
    source: ForensicSource,
    live_opts: LiveQueryOptions,
}

impl LegacyEventProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self::with_options(source, LiveQueryOptions::default())
    }

    pub fn with_options(source: ForensicSource, live_opts: LiveQueryOptions) -> Self {
        Self { source, live_opts }
    }
}

impl TableProvider for LegacyEventProvider {
    fn tool_id(&self) -> &'static str {
        "evtx.legacy"
    }

    fn description(&self) -> &'static str {
        "Unified flat view across Application, System, and Security Event Logs"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Legacy Event Logs",
            vec![
                col("record_number", "RecordNumber", ColumnType::Uint, 100),
                col("time_generated", "TimeGenerated", ColumnType::Timestamp, 180),
                col("event_type", "EventType", ColumnType::Text, 110),
                col("event_id", "EventID", ColumnType::Uint, 80),
                col("source", "Source", ColumnType::Text, 200),
                col("category", "Category", ColumnType::Text, 120),
                col("user", "User", ColumnType::Text, 180),
                col("computer", "Computer", ColumnType::Text, 150),
                col("message", "Message", ColumnType::Text, 320),
            ],
        )
        .with_default_sort(1, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let loaded = load_records(
            &self.source,
            self.tool_id(),
            &["Application", "System", "Security"],
            &self.live_opts,
        )
        .map_err(|e| e.to_table_error())?;

        let rows: Vec<Row> = loaded
            .records
            .iter()
            .filter(|rec| {
                rec.channel.is_empty()
                    || rec.channel.eq_ignore_ascii_case("Application")
                    || rec.channel.eq_ignore_ascii_case("System")
                    || rec.channel.eq_ignore_ascii_case("Security")
            })
            .enumerate()
            .map(|(idx, rec)| {
                let event_type = legacy_event_type(rec);
                let category = rec.task_name.clone().unwrap_or_else(|| rec.task.to_string());
                let user = first_data(rec, &["TargetUserName", "SubjectUserName", "User"]).or(rec.user_sid.as_deref());
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Uint(rec.record_id),
                        CellValue::Timestamp(rec.event_time),
                        CellValue::Text(event_type.to_string()),
                        CellValue::Uint(u64::from(rec.event_id)),
                        non_empty_text(&rec.provider),
                        CellValue::Text(category),
                        opt_text(user),
                        non_empty_text(&rec.computer),
                        non_empty_text(&rec.description),
                    ],
                )
                .with_detail_json(record_detail_json(rec, self.tool_id(), serde_json::json!({})))
                .with_raw_bytes(rec.raw_bytes.clone())
            })
            .collect();

        apply_rows(&self.schema(), &rows, req)
    }
}

fn legacy_event_type(rec: &EvtxRecord) -> &'static str {
    const AUDIT_FAILURE: u64 = 0x0010_0000_0000_0000;
    const AUDIT_SUCCESS: u64 = 0x0020_0000_0000_0000;
    if (rec.keywords & AUDIT_FAILURE) != 0 {
        "Audit Failure"
    } else if (rec.keywords & AUDIT_SUCCESS) != 0 {
        "Audit Success"
    } else {
        rec.level_name()
    }
}

// ---------------------------------------------------------------------------
// 3. evtx.channels — EVTX Channels
// ---------------------------------------------------------------------------

pub struct ChannelsProvider {
    source: ForensicSource,
}

impl ChannelsProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }
}

impl TableProvider for ChannelsProvider {
    fn tool_id(&self) -> &'static str {
        "evtx.channels"
    }

    fn description(&self) -> &'static str {
        "EVTX channel configuration, file path, size, and enabled status viewer"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "EVTX Channels",
            vec![
                col("channel_name", "ChannelName", ColumnType::Text, 260),
                col("log_file_path", "LogFilePath", ColumnType::Text, 300),
                col("enabled", "Enabled", ColumnType::Bool, 80),
                col("channel_type", "Type", ColumnType::Text, 100),
                col("isolation", "Isolation", ColumnType::Text, 100),
                col("max_size_kb", "MaxSizeKB", ColumnType::Uint, 100),
                col("event_count", "EventCount", ColumnType::Uint, 100),
                col("file_size", "FileSize", ColumnType::BytesSize, 110),
                col("modified_time", "ModifiedTime", ColumnType::Timestamp, 180),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let (channels, warnings) = load_channels(&self.source).map_err(|e| e.to_table_error())?;
        let rows: Vec<Row> = channels
            .into_iter()
            .enumerate()
            .map(|(idx, ch)| {
                let detail = serde_json::json!({
                    "tool_id": self.tool_id(),
                    "channel_name": ch.channel_name,
                    "log_file_path": ch.log_file_path,
                    "enabled": ch.enabled,
                    "channel_type": ch.channel_type,
                    "isolation": ch.isolation,
                    "max_size_kb": ch.max_size_kb,
                    "event_count": ch.event_count,
                    "file_size": ch.file_size,
                    "modified_time": ch.modified_time.map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)),
                    "owning_publisher": ch.owning_publisher,
                    "classic_eventlog": ch.classic_eventlog,
                    "warnings_count": warnings.len(),
                });
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(ch.channel_name),
                        non_empty_text(&ch.log_file_path),
                        ch.enabled.map(CellValue::Bool).unwrap_or(CellValue::Null),
                        opt_text(ch.channel_type.as_deref()),
                        opt_text(ch.isolation.as_deref()),
                        ch.max_size_kb.map(CellValue::Uint).unwrap_or(CellValue::Null),
                        ch.event_count.map(CellValue::Uint).unwrap_or(CellValue::Null),
                        ch.file_size.map(CellValue::Bytes).unwrap_or(CellValue::Null),
                        ch.modified_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                    ],
                )
                .with_detail_json(detail)
                .with_raw_bytes(ch.raw_bytes)
            })
            .collect();

        apply_rows(&self.schema(), &rows, req)
    }
}

// ---------------------------------------------------------------------------
// 4. evtx.sources — EVTX Event Sources
// ---------------------------------------------------------------------------

pub struct SourcesProvider {
    source: ForensicSource,
}

impl SourcesProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }
}

impl TableProvider for SourcesProvider {
    fn tool_id(&self) -> &'static str {
        "evtx.sources"
    }

    fn description(&self) -> &'static str {
        "Event Log publisher and provider DLL metadata viewer"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "EVTX Event Sources",
            vec![
                col("source_name", "SourceName", ColumnType::Text, 240),
                col("channel", "Channel", ColumnType::Text, 220),
                col("provider_guid", "ProviderGuid", ColumnType::Text, 240),
                col("message_dll", "MessageDll", ColumnType::Text, 260),
                col("parameter_dll", "ParameterDll", ColumnType::Text, 240),
                col("dll_exists", "DllExists", ColumnType::Bool, 90),
                col("registry_modified", "RegistryModified", ColumnType::Timestamp, 180),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let (sources, warnings) = load_sources(&self.source).map_err(|e| e.to_table_error())?;
        let rows: Vec<Row> = sources
            .into_iter()
            .enumerate()
            .map(|(idx, src)| {
                let detail = serde_json::json!({
                    "tool_id": self.tool_id(),
                    "source_name": src.source_name,
                    "channel": src.channel,
                    "provider_guid": src.provider_guid,
                    "message_dll": src.message_dll,
                    "parameter_dll": src.parameter_dll,
                    "dll_exists": src.dll_exists,
                    "registry_modified": src.registry_modified.map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)),
                    "observed_event_count": src.observed_event_count,
                    "warnings_count": warnings.len(),
                });
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(src.source_name),
                        non_empty_text(&src.channel),
                        opt_text(src.provider_guid.as_deref()),
                        opt_text(src.message_dll.as_deref()),
                        opt_text(src.parameter_dll.as_deref()),
                        src.dll_exists.map(CellValue::Bool).unwrap_or(CellValue::Null),
                        src.registry_modified.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                    ],
                )
                .with_detail_json(detail)
                .with_raw_bytes(src.raw_bytes)
            })
            .collect();

        apply_rows(&self.schema(), &rows, req)
    }
}

// ---------------------------------------------------------------------------
// 5. evtx.logon — Windows Logon Sessions
// ---------------------------------------------------------------------------

pub struct LogonProvider {
    source: ForensicSource,
    live_opts: LiveQueryOptions,
}

impl LogonProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self::with_options(source, LiveQueryOptions::default())
    }

    pub fn with_options(source: ForensicSource, live_opts: LiveQueryOptions) -> Self {
        Self { source, live_opts }
    }
}

impl TableProvider for LogonProvider {
    fn tool_id(&self) -> &'static str {
        "evtx.logon"
    }

    fn description(&self) -> &'static str {
        "Security Event Log (4624/4634/4647/4625) logon session correlator"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Windows Logon Sessions",
            vec![
                col("logon_id", "LogonID", ColumnType::Text, 110),
                col("user_name", "UserName", ColumnType::Text, 150),
                col("domain", "Domain", ColumnType::Text, 140),
                col("computer", "Computer", ColumnType::Text, 150),
                col("logon_type", "LogonType", ColumnType::Text, 150),
                col("logon_time", "LogonTime", ColumnType::Timestamp, 180),
                col("logoff_time", "LogoffTime", ColumnType::Timestamp, 180),
                col("duration", "Duration", ColumnType::Duration, 110),
                col("source_ip", "SourceIP", ColumnType::IpAddr, 130),
                col("workstation", "Workstation", ColumnType::Text, 150),
            ],
        )
        .with_default_sort(5, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let opts = live_opts_with_xpath(
            &self.live_opts,
            "*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647)]]",
        );
        let loaded =
            load_records(&self.source, self.tool_id(), &["Security"], &opts).map_err(|e| e.to_table_error())?;
        let rows = correlate_logon_sessions(self.tool_id(), &loaded.records);
        apply_rows(&self.schema(), &rows, req)
    }
}

struct LogonSession {
    logon_id: String,
    user_name: Option<String>,
    domain: Option<String>,
    computer: String,
    logon_type: String,
    logon_time: Option<DateTime<Utc>>,
    logoff_time: Option<DateTime<Utc>>,
    source_ip: Option<String>,
    workstation: Option<String>,
    logon_record: EvtxRecord,
    logoff_record: Option<EvtxRecord>,
}

fn correlate_logon_sessions(tool_id: &str, records: &[EvtxRecord]) -> Vec<Row> {
    let mut relevant: Vec<&EvtxRecord> = records
        .iter()
        .filter(|r| {
            (r.channel.is_empty() || r.channel.eq_ignore_ascii_case("Security"))
                && matches!(r.event_id, 4624 | 4625 | 4634 | 4647)
        })
        .collect();
    relevant.sort_by_key(|r| (r.event_time, r.record_id));

    let mut active: BTreeMap<(String, String), LogonSession> = BTreeMap::new();
    let mut finished: Vec<LogonSession> = Vec::new();

    for rec in relevant {
        let raw_lid = first_data(rec, &["TargetLogonId", "SubjectLogonId"]).unwrap_or("");
        let lid = normalize_logon_id(raw_lid);
        let active_key = (rec.computer.trim().to_ascii_lowercase(), lid.clone());
        let logon_type_str = first_data(rec, &["LogonType"])
            .map(format_logon_type)
            .unwrap_or_else(|| "Unknown".to_string());

        match rec.event_id {
            4624 => {
                if let Some(prev) = active.remove(&active_key) {
                    finished.push(prev);
                }
                let session = LogonSession {
                    logon_id: lid.clone(),
                    user_name: first_data(rec, &["TargetUserName"]).map(str::to_string),
                    domain: first_data(rec, &["TargetDomainName"]).map(str::to_string),
                    computer: rec.computer.clone(),
                    logon_type: logon_type_str,
                    logon_time: Some(rec.event_time),
                    logoff_time: None,
                    source_ip: first_data(rec, &["IpAddress"]).map(str::to_string),
                    workstation: first_data(rec, &["WorkstationName"]).map(str::to_string),
                    logon_record: rec.clone(),
                    logoff_record: None,
                };
                if lid.is_empty() || lid == "0x0" {
                    finished.push(session);
                } else {
                    active.insert(active_key, session);
                }
            }
            4634 | 4647 => {
                if !lid.is_empty()
                    && lid != "0x0"
                    && let Some(mut sess) = active.remove(&active_key)
                {
                    sess.logoff_time = Some(rec.event_time);
                    sess.logoff_record = Some(rec.clone());
                    finished.push(sess);
                } else {
                    finished.push(LogonSession {
                        logon_id: lid,
                        user_name: first_data(rec, &["TargetUserName"]).map(str::to_string),
                        domain: first_data(rec, &["TargetDomainName"]).map(str::to_string),
                        computer: rec.computer.clone(),
                        logon_type: if rec.event_id == 4647 {
                            "User Logoff (4647)".to_string()
                        } else {
                            logon_type_str
                        },
                        logon_time: None,
                        logoff_time: Some(rec.event_time),
                        source_ip: None,
                        workstation: None,
                        logon_record: rec.clone(),
                        logoff_record: Some(rec.clone()),
                    });
                }
            }
            4625 => {
                finished.push(LogonSession {
                    logon_id: if lid.is_empty() { "0x0".to_string() } else { lid },
                    user_name: first_data(rec, &["TargetUserName"]).map(str::to_string),
                    domain: first_data(rec, &["TargetDomainName"]).map(str::to_string),
                    computer: rec.computer.clone(),
                    logon_type: format!("Failed: {logon_type_str}"),
                    logon_time: Some(rec.event_time),
                    logoff_time: None,
                    source_ip: first_data(rec, &["IpAddress"]).map(str::to_string),
                    workstation: first_data(rec, &["WorkstationName"]).map(str::to_string),
                    logon_record: rec.clone(),
                    logoff_record: None,
                });
            }
            _ => {}
        }
    }

    finished.extend(active.into_values());

    finished
        .into_iter()
        .enumerate()
        .map(|(idx, s)| {
            let duration = match (s.logon_time, s.logoff_time) {
                (Some(start), Some(end)) => {
                    let ms = (end - start).num_milliseconds().max(0) as u64;
                    CellValue::Uint(ms)
                }
                _ => CellValue::Null,
            };
            let extra = serde_json::json!({
                "logon_id": s.logon_id,
                "logoff_record_id": s.logoff_record.as_ref().map(|r| r.record_id),
                "status": first_data(&s.logon_record, &["Status"]),
                "sub_status": first_data(&s.logon_record, &["SubStatus"]),
                "failure_reason": first_data(&s.logon_record, &["FailureReason"]),
            });
            Row::new(
                idx as u64 + 1,
                vec![
                    non_empty_text(&s.logon_id),
                    opt_text(s.user_name.as_deref()),
                    opt_text(s.domain.as_deref()),
                    non_empty_text(&s.computer),
                    CellValue::Text(s.logon_type),
                    s.logon_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                    s.logoff_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                    duration,
                    opt_text(s.source_ip.as_deref()),
                    opt_text(s.workstation.as_deref()),
                ],
            )
            .with_detail_json(record_detail_json(&s.logon_record, tool_id, extra))
            .with_raw_bytes(s.logon_record.raw_bytes)
        })
        .collect()
}

fn normalize_logon_id(raw: &str) -> String {
    let t = raw.trim().to_ascii_lowercase();
    if let Some(hex) = t.strip_prefix("0x") {
        if let Ok(v) = u64::from_str_radix(hex, 16) {
            return format!("0x{v:x}");
        }
    } else if let Ok(v) = t.parse::<u64>() {
        return format!("0x{v:x}");
    }
    t
}

fn format_logon_type(raw: &str) -> String {
    let trimmed = raw.trim();
    let label = match trimmed {
        "2" => "Interactive",
        "3" => "Network",
        "4" => "Batch",
        "5" => "Service",
        "7" => "Unlock",
        "8" => "NetworkCleartext",
        "9" => "NewCredentials",
        "10" => "RemoteInteractive",
        "11" => "CachedInteractive",
        "12" => "CachedRemoteInteractive",
        "13" => "CachedUnlock",
        _ => return trimmed.to_string(),
    };
    format!("{trimmed} ({label})")
}

// ---------------------------------------------------------------------------
// 6. evtx.uptime — System Uptime & Boot History
// ---------------------------------------------------------------------------

pub struct UptimeProvider {
    source: ForensicSource,
    live_opts: LiveQueryOptions,
}

impl UptimeProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self::with_options(source, LiveQueryOptions::default())
    }

    pub fn with_options(source: ForensicSource, live_opts: LiveQueryOptions) -> Self {
        Self { source, live_opts }
    }
}

impl TableProvider for UptimeProvider {
    fn tool_id(&self) -> &'static str {
        "evtx.uptime"
    }

    fn description(&self) -> &'static str {
        "System Event Log (6005/6006/6008/6009/1074/41/12/13) boot and shutdown analyzer"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "System Uptime & Boot History",
            vec![
                col("startup_time", "StartupTime", ColumnType::Timestamp, 180),
                col("shutdown_time", "ShutdownTime", ColumnType::Timestamp, 180),
                col("duration", "Duration", ColumnType::Duration, 120),
                col("shutdown_reason", "ShutdownReason", ColumnType::Text, 220),
                col("shutdown_type", "ShutdownType", ColumnType::Text, 140),
                col("shutdown_code", "ShutdownCode", ColumnType::Text, 110),
                col("process", "Process", ColumnType::Text, 200),
            ],
        )
        .with_default_sort(0, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let opts = live_opts_with_xpath(
            &self.live_opts,
            "*[System[(EventID=6005 or EventID=6006 or EventID=6008 or EventID=6009 or EventID=1074 or EventID=41 or EventID=12 or EventID=13)]]",
        );
        let loaded = load_records(&self.source, self.tool_id(), &["System"], &opts).map_err(|e| e.to_table_error())?;
        let rows = correlate_uptime_sessions(self.tool_id(), &loaded.records);
        apply_rows(&self.schema(), &rows, req)
    }
}

struct UptimeSession {
    startup_time: Option<DateTime<Utc>>,
    shutdown_time: Option<DateTime<Utc>>,
    shutdown_reason: Option<String>,
    shutdown_type: String,
    shutdown_code: Option<String>,
    process: Option<String>,
    anchor_record: EvtxRecord,
    related_record_ids: Vec<u64>,
}

fn correlate_uptime_sessions(tool_id: &str, records: &[EvtxRecord]) -> Vec<Row> {
    let mut relevant: Vec<&EvtxRecord> = records
        .iter()
        .filter(|r| {
            (r.channel.is_empty() || r.channel.eq_ignore_ascii_case("System"))
                && matches!(r.event_id, 12 | 13 | 41 | 1074 | 6005 | 6006 | 6008 | 6009)
        })
        .collect();
    relevant.sort_by_key(|r| (r.event_time, r.record_id));

    let mut sessions: Vec<UptimeSession> = Vec::new();
    let mut current: Option<UptimeSession> = None;

    for rec in relevant {
        match rec.event_id {
            12 | 6005 | 6009 => {
                if let Some(mut open) = current.take() {
                    let within_boot_window = open
                        .startup_time
                        .is_some_and(|st| (rec.event_time - st).num_seconds().abs() <= 180);
                    if within_boot_window && open.shutdown_time.is_none() && open.shutdown_type == "Active" {
                        open.related_record_ids.push(rec.record_id);
                        current = Some(open);
                        continue;
                    }
                    if open.shutdown_type == "Active" {
                        open.shutdown_type = "Unexpected".to_string();
                    }
                    sessions.push(open);
                }
                current = Some(UptimeSession {
                    startup_time: Some(rec.event_time),
                    shutdown_time: None,
                    shutdown_reason: None,
                    shutdown_type: "Active".to_string(),
                    shutdown_code: None,
                    process: None,
                    anchor_record: rec.clone(),
                    related_record_ids: vec![rec.record_id],
                });
            }
            1074 => {
                let proc_val = first_data(rec, &["param1", "Data0", "Process"]).map(str::to_string);
                let reason_val = first_data(rec, &["param3", "Data2", "Reason"]).map(str::to_string);
                let code_val = first_data(rec, &["param4", "Data3", "ReasonCode"]).map(str::to_string);
                let raw_type = first_data(rec, &["param5", "Data4", "ShutdownType"]).unwrap_or("Clean");
                let norm_type = normalize_shutdown_type(raw_type);

                if let Some(ref mut open) = current {
                    if proc_val.is_some() {
                        open.process = proc_val;
                    }
                    if reason_val.is_some() {
                        open.shutdown_reason = reason_val;
                    }
                    if code_val.is_some() {
                        open.shutdown_code = code_val;
                    }
                    open.shutdown_type = norm_type;
                    open.related_record_ids.push(rec.record_id);
                } else {
                    current = Some(UptimeSession {
                        startup_time: None,
                        shutdown_time: Some(rec.event_time),
                        shutdown_reason: reason_val,
                        shutdown_type: norm_type,
                        shutdown_code: code_val,
                        process: proc_val,
                        anchor_record: rec.clone(),
                        related_record_ids: vec![rec.record_id],
                    });
                }
            }
            6006 | 13 => {
                if let Some(mut open) = current.take() {
                    open.shutdown_time = Some(rec.event_time);
                    if open.shutdown_type == "Active" {
                        open.shutdown_type = "Clean".to_string();
                    }
                    open.related_record_ids.push(rec.record_id);
                    sessions.push(open);
                } else {
                    sessions.push(UptimeSession {
                        startup_time: None,
                        shutdown_time: Some(rec.event_time),
                        shutdown_reason: None,
                        shutdown_type: "Clean".to_string(),
                        shutdown_code: None,
                        process: None,
                        anchor_record: rec.clone(),
                        related_record_ids: vec![rec.record_id],
                    });
                }
            }
            6008 => {
                let post_boot_for_prior = current.as_ref().is_some_and(|open| {
                    open.shutdown_type == "Active"
                        && open
                            .startup_time
                            .is_some_and(|st| (rec.event_time - st).num_seconds().abs() <= 180)
                        && sessions.last().is_some_and(|last| {
                            matches!(last.shutdown_type.as_str(), "Unexpected" | "Bugcheck/Unclean")
                                && last.shutdown_time.is_none()
                        })
                });
                if post_boot_for_prior && let Some(last) = sessions.last_mut() {
                    if last.shutdown_type != "Bugcheck/Unclean" {
                        last.shutdown_type = "Unexpected".to_string();
                    }
                    if last.shutdown_reason.is_none() {
                        last.shutdown_reason = Some("Unexpected shutdown".to_string());
                    }
                    last.related_record_ids.push(rec.record_id);
                } else if let Some(mut open) = current.take() {
                    open.shutdown_type = "Unexpected".to_string();
                    if open.shutdown_time.is_none() {
                        open.shutdown_time = Some(rec.event_time);
                    }
                    if open.shutdown_reason.is_none() {
                        open.shutdown_reason = Some("Unexpected shutdown".to_string());
                    }
                    open.related_record_ids.push(rec.record_id);
                    sessions.push(open);
                } else if let Some(last) = sessions.last_mut() {
                    if last.shutdown_type != "Bugcheck/Unclean" {
                        last.shutdown_type = "Unexpected".to_string();
                    }
                    if last.shutdown_reason.is_none() {
                        last.shutdown_reason = Some("Unexpected shutdown".to_string());
                    }
                    last.related_record_ids.push(rec.record_id);
                } else {
                    sessions.push(UptimeSession {
                        startup_time: None,
                        shutdown_time: Some(rec.event_time),
                        shutdown_reason: Some("Unexpected shutdown".to_string()),
                        shutdown_type: "Unexpected".to_string(),
                        shutdown_code: None,
                        process: None,
                        anchor_record: rec.clone(),
                        related_record_ids: vec![rec.record_id],
                    });
                }
            }
            41 => {
                let bugcheck = first_data(rec, &["BugcheckCode"]).map(str::to_string);
                let post_boot_for_prior = current.as_ref().is_some_and(|open| {
                    open.shutdown_type == "Active"
                        && open
                            .startup_time
                            .is_some_and(|st| (rec.event_time - st).num_seconds().abs() <= 180)
                        && sessions.last().is_some_and(|last| {
                            matches!(last.shutdown_type.as_str(), "Unexpected" | "Bugcheck/Unclean")
                                && last.shutdown_time.is_none()
                        })
                });
                if post_boot_for_prior && let Some(last) = sessions.last_mut() {
                    last.shutdown_type = "Bugcheck/Unclean".to_string();
                    last.shutdown_reason = Some("Kernel-Power Event 41".to_string());
                    if bugcheck.is_some() {
                        last.shutdown_code = bugcheck;
                    }
                    last.related_record_ids.push(rec.record_id);
                } else if let Some(mut open) = current.take() {
                    open.shutdown_type = "Bugcheck/Unclean".to_string();
                    if open.shutdown_time.is_none() {
                        open.shutdown_time = Some(rec.event_time);
                    }
                    open.shutdown_reason = Some("Kernel-Power Event 41".to_string());
                    if bugcheck.is_some() {
                        open.shutdown_code = bugcheck;
                    }
                    open.related_record_ids.push(rec.record_id);
                    sessions.push(open);
                } else if let Some(last) = sessions.last_mut() {
                    last.shutdown_type = "Bugcheck/Unclean".to_string();
                    last.shutdown_reason = Some("Kernel-Power Event 41".to_string());
                    if bugcheck.is_some() {
                        last.shutdown_code = bugcheck;
                    }
                    last.related_record_ids.push(rec.record_id);
                } else {
                    sessions.push(UptimeSession {
                        startup_time: None,
                        shutdown_time: Some(rec.event_time),
                        shutdown_reason: Some("Kernel-Power Event 41".to_string()),
                        shutdown_type: "Bugcheck/Unclean".to_string(),
                        shutdown_code: bugcheck,
                        process: None,
                        anchor_record: rec.clone(),
                        related_record_ids: vec![rec.record_id],
                    });
                }
            }
            _ => {}
        }
    }

    if let Some(open) = current {
        sessions.push(open);
    }

    sessions
        .into_iter()
        .enumerate()
        .map(|(idx, s)| {
            let duration = match (s.startup_time, s.shutdown_time) {
                (Some(start), Some(end)) => CellValue::Uint((end - start).num_milliseconds().max(0) as u64),
                _ => CellValue::Null,
            };
            let extra = serde_json::json!({
                "related_record_ids": s.related_record_ids,
                "shutdown_type": s.shutdown_type,
            });
            Row::new(
                idx as u64 + 1,
                vec![
                    s.startup_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                    s.shutdown_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                    duration,
                    opt_text(s.shutdown_reason.as_deref()),
                    CellValue::Text(s.shutdown_type),
                    opt_text(s.shutdown_code.as_deref()),
                    opt_text(s.process.as_deref()),
                ],
            )
            .with_detail_json(record_detail_json(&s.anchor_record, tool_id, extra))
            .with_raw_bytes(s.anchor_record.raw_bytes)
        })
        .collect()
}

fn normalize_shutdown_type(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    if lower.contains("restart") || lower.contains("reboot") {
        "Restart".to_string()
    } else if lower.contains("power") || lower.contains("shutdown") || lower.contains("halt") {
        "Power Off".to_string()
    } else {
        raw.trim().to_string()
    }
}

// ---------------------------------------------------------------------------
// 7. evtx.wifi — Wi-Fi Connection History
// ---------------------------------------------------------------------------

pub struct WifiProvider {
    source: ForensicSource,
    live_opts: LiveQueryOptions,
}

impl WifiProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self::with_options(source, LiveQueryOptions::default())
    }

    pub fn with_options(source: ForensicSource, live_opts: LiveQueryOptions) -> Self {
        Self { source, live_opts }
    }
}

impl TableProvider for WifiProvider {
    fn tool_id(&self) -> &'static str {
        "evtx.wifi"
    }

    fn description(&self) -> &'static str {
        "WLAN-AutoConfig Operational (8001..8003, 11000..11010) Wi-Fi connection history"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Wi-Fi Connection History",
            vec![
                col("event_time", "EventTime", ColumnType::Timestamp, 180),
                col("event_type", "EventType", ColumnType::Text, 160),
                col("ssid", "SSID", ColumnType::Text, 160),
                col("bssid", "BSSID", ColumnType::MacAddr, 140),
                col("interface_name", "InterfaceName", ColumnType::Text, 200),
                col("interface_guid", "InterfaceGuid", ColumnType::Text, 220),
                col("profile_name", "ProfileName", ColumnType::Text, 160),
                col("auth_algo", "AuthAlgo", ColumnType::Text, 130),
                col("cipher", "Cipher", ColumnType::Text, 110),
                col("reason", "Reason", ColumnType::Text, 160),
            ],
        )
        .with_default_sort(0, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let opts = live_opts_with_xpath(
            &self.live_opts,
            "*[System[(EventID>=8001 and EventID<=8003) or (EventID>=11000 and EventID<=11010)]]",
        );
        let loaded = load_records(
            &self.source,
            self.tool_id(),
            &["Microsoft-Windows-WLAN-AutoConfig/Operational"],
            &opts,
        )
        .map_err(|e| e.to_table_error())?;

        let rows: Vec<Row> = loaded
            .records
            .iter()
            .filter(|r| {
                (r.channel.is_empty()
                    || r.channel
                        .eq_ignore_ascii_case("Microsoft-Windows-WLAN-AutoConfig/Operational")
                    || r.channel.to_ascii_lowercase().contains("wlan-autoconfig"))
                    && matches!(r.event_id, 8001..=8003 | 11000..=11010)
            })
            .enumerate()
            .map(|(idx, rec)| {
                let event_type = match rec.event_id {
                    8001 => "Connected",
                    8002 => "Connection Failed",
                    8003 => "Disconnected",
                    11000 => "Association Started",
                    11001 => "Association Succeeded",
                    11002 => "Association Failed",
                    11004 => "Security Started",
                    11005 => "Security Succeeded",
                    11006 => "Security Failed",
                    11010 => "Roaming Started",
                    _ => "WLAN Event",
                };
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Timestamp(rec.event_time),
                        CellValue::Text(event_type.to_string()),
                        opt_text(first_data(rec, &["SSID"])),
                        opt_text(first_data(rec, &["BSSID", "APMacAddress"])),
                        opt_text(first_data(rec, &["InterfaceName", "InterfaceDescription"])),
                        opt_text(first_data(rec, &["InterfaceGuid"])),
                        opt_text(first_data(rec, &["ProfileName"])),
                        opt_text(first_data(rec, &["AuthenticationAlgorithm", "AuthAlgo"])),
                        opt_text(first_data(rec, &["CipherAlgorithm", "Cipher"])),
                        opt_text(first_data(rec, &["ReasonCode", "Reason", "FailureReason"])),
                    ],
                )
                .with_detail_json(record_detail_json(
                    rec,
                    self.tool_id(),
                    serde_json::json!({ "event_type": event_type }),
                ))
                .with_raw_bytes(rec.raw_bytes.clone())
            })
            .collect();

        apply_rows(&self.schema(), &rows, req)
    }
}

// ---------------------------------------------------------------------------
// 8. evtx.defender — Defender Event Log
// ---------------------------------------------------------------------------

pub struct DefenderProvider {
    source: ForensicSource,
    live_opts: LiveQueryOptions,
}

impl DefenderProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self::with_options(source, LiveQueryOptions::default())
    }

    pub fn with_options(source: ForensicSource, live_opts: LiveQueryOptions) -> Self {
        Self { source, live_opts }
    }
}

impl TableProvider for DefenderProvider {
    fn tool_id(&self) -> &'static str {
        "evtx.defender"
    }

    fn description(&self) -> &'static str {
        "Windows Defender Operational (1006..1015, 1116..1119, 5001..5012) threat/scan log"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Defender Event Log",
            vec![
                col("event_time", "EventTime", ColumnType::Timestamp, 180),
                col("event_id", "EventID", ColumnType::Uint, 80),
                col("threat_name", "ThreatName", ColumnType::Text, 200),
                col("severity", "Severity", ColumnType::Text, 100),
                col("category", "Category", ColumnType::Text, 140),
                col("path", "Path", ColumnType::Text, 260),
                col("process_name", "ProcessName", ColumnType::Text, 180),
                col("action_taken", "ActionTaken", ColumnType::Text, 140),
                col("user", "User", ColumnType::Text, 150),
            ],
        )
        .with_default_sort(0, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let opts = live_opts_with_xpath(
            &self.live_opts,
            "*[System[(EventID>=1006 and EventID<=1015) or (EventID>=1116 and EventID<=1119) or (EventID>=5001 and EventID<=5012)]]",
        );
        let loaded = load_records(
            &self.source,
            self.tool_id(),
            &["Microsoft-Windows-Windows Defender/Operational"],
            &opts,
        )
        .map_err(|e| e.to_table_error())?;

        let rows: Vec<Row> = loaded
            .records
            .iter()
            .filter(|r| {
                (r.channel.is_empty()
                    || r.channel
                        .eq_ignore_ascii_case("Microsoft-Windows-Windows Defender/Operational")
                    || r.channel.to_ascii_lowercase().contains("windows defender"))
                    && matches!(r.event_id, 1006..=1015 | 1116..=1119 | 5001..=5012)
            })
            .enumerate()
            .map(|(idx, rec)| {
                let fallback_action = defender_eid_action(rec.event_id);
                let action = first_data(rec, &["Action Name", "ActionName", "ActionTaken"]).unwrap_or(fallback_action);
                let user = first_data(rec, &["Detection User", "User"]).or(rec.user_sid.as_deref());
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Timestamp(rec.event_time),
                        CellValue::Uint(u64::from(rec.event_id)),
                        opt_text(first_data(rec, &["Threat Name", "ThreatName"])),
                        opt_text(first_data(rec, &["Severity Name", "SeverityName", "Severity"])),
                        opt_text(first_data(rec, &["Category Name", "CategoryName", "Category"])),
                        opt_text(first_data(rec, &["Path", "Resource"])),
                        opt_text(first_data(rec, &["Process Name", "ProcessName"])),
                        CellValue::Text(action.to_string()),
                        opt_text(user),
                    ],
                )
                .with_detail_json(record_detail_json(rec, self.tool_id(), serde_json::json!({})))
                .with_raw_bytes(rec.raw_bytes.clone())
            })
            .collect();

        apply_rows(&self.schema(), &rows, req)
    }
}

fn defender_eid_action(eid: u16) -> &'static str {
    match eid {
        1006 => "Malware Detected (Scan)",
        1007 => "Action Taken",
        1008 => "Action Failed",
        1015 => "Suspicious Behavior",
        1116 => "Threat Detected",
        1117 => "Threat Action Taken",
        1118 => "Threat Action Failed",
        1119 => "Threat Action Critical Failure",
        5001 => "Real-time Protection Disabled",
        5004 => "Real-time Protection Config Changed",
        5007 => "Defender Config Changed",
        5010 => "Anti-Spyware Scanning Disabled",
        5012 => "Antivirus Scanning Disabled",
        _ => "Defender Event",
    }
}

// ---------------------------------------------------------------------------
// 9. evtx.timeline — EVTX Forensic Timeline
// ---------------------------------------------------------------------------

pub struct TimelineProvider {
    source: ForensicSource,
    live_opts: LiveQueryOptions,
}

impl TimelineProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self::with_options(source, LiveQueryOptions::default())
    }

    pub fn with_options(source: ForensicSource, live_opts: LiveQueryOptions) -> Self {
        Self { source, live_opts }
    }
}

impl TableProvider for TimelineProvider {
    fn tool_id(&self) -> &'static str {
        "evtx.timeline"
    }

    fn description(&self) -> &'static str {
        "Cross-channel normalized Windows Event Log forensic timeline"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "EVTX Forensic Timeline",
            vec![
                col("timestamp", "Timestamp", ColumnType::Timestamp, 180),
                col("source_channel", "SourceChannel", ColumnType::Text, 200),
                col("event_id", "EventID", ColumnType::Uint, 80),
                col("category", "Category", ColumnType::Text, 130),
                col("subject", "Subject", ColumnType::Text, 180),
                col("target", "Target", ColumnType::Text, 220),
                col("detail", "Detail", ColumnType::Text, 300),
            ],
        )
        .with_default_sort(0, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        const CHANNELS: &[&str] = &[
            "System",
            "Application",
            "Security",
            "Microsoft-Windows-TaskScheduler/Operational",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-WLAN-AutoConfig/Operational",
            "Microsoft-Windows-Windows Defender/Operational",
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        ];
        let loaded =
            load_records(&self.source, self.tool_id(), CHANNELS, &self.live_opts).map_err(|e| e.to_table_error())?;

        let rows: Vec<Row> = loaded
            .records
            .iter()
            .enumerate()
            .map(|(idx, rec)| {
                let category = classify_timeline_category(rec);
                let subject = first_data(
                    rec,
                    &[
                        "SubjectUserName",
                        "TargetUserName",
                        "User",
                        "ProcessName",
                        "HostApplication",
                    ],
                )
                .or(rec.user_sid.as_deref())
                .unwrap_or(&rec.provider);
                let target = first_data(
                    rec,
                    &[
                        "NewProcessName",
                        "Image",
                        "TaskName",
                        "SSID",
                        "DeviceInstanceId",
                        "Path",
                        "Address",
                        "IpAddress",
                        "TargetUserName",
                    ],
                );
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Timestamp(rec.event_time),
                        non_empty_text(&rec.channel),
                        CellValue::Uint(u64::from(rec.event_id)),
                        CellValue::Text(category.to_string()),
                        non_empty_text(subject),
                        opt_text(target),
                        non_empty_text(&rec.description),
                    ],
                )
                .with_detail_json(record_detail_json(
                    rec,
                    self.tool_id(),
                    serde_json::json!({ "category": category }),
                ))
                .with_raw_bytes(rec.raw_bytes.clone())
            })
            .collect();

        apply_rows(&self.schema(), &rows, req)
    }
}

fn classify_timeline_category(rec: &EvtxRecord) -> &'static str {
    let ch = rec.channel.to_ascii_lowercase();
    if ch.contains("wlan") {
        "WiFi"
    } else if ch.contains("defender") {
        "Defender"
    } else if ch.contains("terminalservices") {
        "RDP"
    } else if ch.contains("powershell") {
        "PowerShell"
    } else if ch.contains("taskscheduler") {
        "TaskScheduler"
    } else if ch.contains("kernel-pnp") || ch.contains("driverframeworks") {
        "USB/PnP"
    } else if ch.contains("sysmon") || rec.event_id == 4688 {
        "Process"
    } else if matches!(rec.event_id, 4624 | 4625 | 4634 | 4647) {
        "Logon"
    } else if ch == "system" && matches!(rec.event_id, 12 | 13 | 41 | 1074 | 6005 | 6006 | 6008 | 6009) {
        "Power/Boot"
    } else if ch == "system" {
        "System"
    } else if ch == "application" {
        "Application"
    } else if ch == "security" {
        "Security"
    } else {
        "Other"
    }
}

// ---------------------------------------------------------------------------
// 10. evtx.rdp — RDP Session View
// ---------------------------------------------------------------------------

pub struct RdpProvider {
    source: ForensicSource,
    live_opts: LiveQueryOptions,
}

impl RdpProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self::with_options(source, LiveQueryOptions::default())
    }

    pub fn with_options(source: ForensicSource, live_opts: LiveQueryOptions) -> Self {
        Self { source, live_opts }
    }
}

impl TableProvider for RdpProvider {
    fn tool_id(&self) -> &'static str {
        "evtx.rdp"
    }

    fn description(&self) -> &'static str {
        "TerminalServices LSM (21..25) and RCM (1149) RDP session history view"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "RDP Session View",
            vec![
                col("event_time", "EventTime", ColumnType::Timestamp, 180),
                col("event_id", "EventID", ColumnType::Uint, 80),
                col("user_name", "UserName", ColumnType::Text, 160),
                col("source_ip", "SourceIP", ColumnType::IpAddr, 140),
                col("session_id", "SessionID", ColumnType::Uint, 90),
                col("direction", "Direction", ColumnType::Text, 110),
                col("action", "Action", ColumnType::Text, 180),
            ],
        )
        .with_default_sort(0, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let opts = live_opts_with_xpath(
            &self.live_opts,
            "*[System[(EventID>=21 and EventID<=25) or EventID=1149]]",
        );
        let loaded = load_records(
            &self.source,
            self.tool_id(),
            &[
                "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
            ],
            &opts,
        )
        .map_err(|e| e.to_table_error())?;

        let rows: Vec<Row> = loaded
            .records
            .iter()
            .filter(|r| {
                (r.channel.is_empty()
                    || r.channel
                        .eq_ignore_ascii_case("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational")
                    || r.channel
                        .eq_ignore_ascii_case("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"))
                    && matches!(r.event_id, 21..=25 | 1149)
            })
            .enumerate()
            .map(|(idx, rec)| {
                let user = first_data(rec, &["User", "Param1", "UserName"]);
                let ip = first_data(rec, &["Address", "Param3", "IpAddress"]);
                let sess_id = first_data(rec, &["SessionID"]).and_then(parse_u64_flex);
                let direction = if rec.event_id == 25 { "Reconnect" } else { "Inbound" };
                let action = match rec.event_id {
                    21 => "Session Logon",
                    22 => "Shell Start",
                    23 => "Session Logoff",
                    24 => "Session Disconnected",
                    25 => "Session Reconnected",
                    1149 => "Auth Succeeded",
                    _ => "RDP Event",
                };
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Timestamp(rec.event_time),
                        CellValue::Uint(u64::from(rec.event_id)),
                        opt_text(user),
                        opt_text(ip),
                        sess_id.map(CellValue::Uint).unwrap_or(CellValue::Null),
                        CellValue::Text(direction.to_string()),
                        CellValue::Text(action.to_string()),
                    ],
                )
                .with_detail_json(record_detail_json(
                    rec,
                    self.tool_id(),
                    serde_json::json!({ "action": action }),
                ))
                .with_raw_bytes(rec.raw_bytes.clone())
            })
            .collect();

        apply_rows(&self.schema(), &rows, req)
    }
}

// ---------------------------------------------------------------------------
// 11. evtx.powershell — PowerShell Audit View
// ---------------------------------------------------------------------------

pub struct PowerShellProvider {
    source: ForensicSource,
    live_opts: LiveQueryOptions,
}

impl PowerShellProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self::with_options(source, LiveQueryOptions::default())
    }

    pub fn with_options(source: ForensicSource, live_opts: LiveQueryOptions) -> Self {
        Self { source, live_opts }
    }
}

impl TableProvider for PowerShellProvider {
    fn tool_id(&self) -> &'static str {
        "evtx.powershell"
    }

    fn description(&self) -> &'static str {
        "PowerShell Operational (4103/4104) and classic (400/600) script audit view"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "PowerShell Audit View",
            vec![
                col("event_time", "EventTime", ColumnType::Timestamp, 180),
                col("event_id", "EventID", ColumnType::Uint, 80),
                col("host_app", "HostApp", ColumnType::Text, 200),
                col("script_block_id", "ScriptBlockID", ColumnType::Text, 220),
                col("path", "Path", ColumnType::Text, 240),
                col("command_text", "CommandText", ColumnType::Text, 340),
                col("pipeline_index", "PipelineIndex", ColumnType::Text, 130),
            ],
        )
        .with_default_sort(0, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let opts = live_opts_with_xpath(
            &self.live_opts,
            "*[System[(EventID=4103 or EventID=4104 or EventID=400 or EventID=600)]]",
        );
        let loaded = load_records(
            &self.source,
            self.tool_id(),
            &["Microsoft-Windows-PowerShell/Operational", "Windows PowerShell"],
            &opts,
        )
        .map_err(|e| e.to_table_error())?;

        let rows: Vec<Row> = loaded
            .records
            .iter()
            .filter(|r| {
                (r.channel.is_empty()
                    || r.channel
                        .eq_ignore_ascii_case("Microsoft-Windows-PowerShell/Operational")
                    || r.channel.eq_ignore_ascii_case("Windows PowerShell"))
                    && matches!(r.event_id, 4103 | 4104 | 400 | 600)
            })
            .enumerate()
            .map(|(idx, rec)| {
                let host_app = first_data(rec, &["HostApplication", "HostName"])
                    .map(str::to_string)
                    .or_else(|| first_data(rec, &["ContextInfo", "Data2"]).and_then(extract_ps_host_application));
                let script_block_id = first_data(rec, &["ScriptBlockId", "RunspaceId"]);
                let path = first_data(rec, &["Path", "ScriptName"]);
                let command_text = first_data(rec, &["ScriptBlockText", "Payload", "Data2", "Data0"]);
                let pipeline_index = match (first_data(rec, &["MessageNumber"]), first_data(rec, &["MessageTotal"])) {
                    (Some(n), Some(t)) => Some(format!("{n}/{t}")),
                    _ => first_data(rec, &["PipelineId"]).map(str::to_string),
                };

                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Timestamp(rec.event_time),
                        CellValue::Uint(u64::from(rec.event_id)),
                        opt_text(host_app.as_deref()),
                        opt_text(script_block_id),
                        opt_text(path),
                        opt_text(command_text),
                        opt_text(pipeline_index.as_deref()),
                    ],
                )
                .with_detail_json(record_detail_json(rec, self.tool_id(), serde_json::json!({})))
                .with_raw_bytes(rec.raw_bytes.clone())
            })
            .collect();

        apply_rows(&self.schema(), &rows, req)
    }
}

fn extract_ps_host_application(context_info: &str) -> Option<String> {
    for line in context_info.lines() {
        let trimmed = line.trim();
        if let Some((k, v)) = trimmed.split_once('=')
            && k.trim().eq_ignore_ascii_case("Host Application")
        {
            let val = v.trim();
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// 12. evtx.process — Process Creation EVTX View
// ---------------------------------------------------------------------------

pub struct ProcessProvider {
    source: ForensicSource,
    live_opts: LiveQueryOptions,
}

impl ProcessProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self::with_options(source, LiveQueryOptions::default())
    }

    pub fn with_options(source: ForensicSource, live_opts: LiveQueryOptions) -> Self {
        Self { source, live_opts }
    }
}

impl TableProvider for ProcessProvider {
    fn tool_id(&self) -> &'static str {
        "evtx.process"
    }

    fn description(&self) -> &'static str {
        "Security EID 4688 and Sysmon EID 1 process creation EVTX view"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Process Creation EVTX View",
            vec![
                col("event_time", "EventTime", ColumnType::Timestamp, 180),
                col("new_pid", "NewPID", ColumnType::Uint, 90),
                col("parent_pid", "ParentPID", ColumnType::Uint, 90),
                col("image_path", "ImagePath", ColumnType::Text, 260),
                col("parent_image", "ParentImage", ColumnType::Text, 240),
                col("command_line", "CommandLine", ColumnType::Text, 320),
                col("user", "User", ColumnType::Text, 160),
                col("token_elevation", "TokenElevation", ColumnType::Text, 150),
            ],
        )
        .with_default_sort(0, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let opts = live_opts_with_xpath(&self.live_opts, "*[System[(EventID=4688 or EventID=1)]]");
        let loaded = load_records(
            &self.source,
            self.tool_id(),
            &["Security", "Microsoft-Windows-Sysmon/Operational"],
            &opts,
        )
        .map_err(|e| e.to_table_error())?;

        let rows: Vec<Row> = loaded
            .records
            .iter()
            .filter(|r| {
                ((r.channel.is_empty() || r.channel.eq_ignore_ascii_case("Security")) && r.event_id == 4688)
                    || (r.event_id == 1
                        && (r.channel.is_empty()
                            || r.channel.to_ascii_lowercase().contains("sysmon")
                            || r.provider.to_ascii_lowercase().contains("sysmon")))
            })
            .enumerate()
            .map(|(idx, rec)| {
                let (new_pid, parent_pid, image, parent_image, cmd, user, elev) = if rec.event_id == 4688 {
                    let elev_raw = first_data(rec, &["TokenElevationType"]);
                    let elev = elev_raw.map(format_token_elevation);
                    (
                        first_data(rec, &["NewProcessId"]).and_then(parse_u64_flex),
                        first_data(rec, &["ProcessId"]).and_then(parse_u64_flex),
                        first_data(rec, &["NewProcessName"]),
                        first_data(rec, &["ParentProcessName"]),
                        first_data(rec, &["CommandLine"]),
                        first_data(rec, &["SubjectUserName", "TargetUserName"]).or(rec.user_sid.as_deref()),
                        elev,
                    )
                } else {
                    (
                        first_data(rec, &["ProcessId"]).and_then(parse_u64_flex),
                        first_data(rec, &["ParentProcessId"]).and_then(parse_u64_flex),
                        first_data(rec, &["Image"]),
                        first_data(rec, &["ParentImage"]),
                        first_data(rec, &["CommandLine"]),
                        first_data(rec, &["User"]).or(rec.user_sid.as_deref()),
                        first_data(rec, &["IntegrityLevel"]).map(str::to_string),
                    )
                };

                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Timestamp(rec.event_time),
                        new_pid.map(CellValue::Uint).unwrap_or(CellValue::Null),
                        parent_pid.map(CellValue::Uint).unwrap_or(CellValue::Null),
                        opt_text(image),
                        opt_text(parent_image),
                        opt_text(cmd),
                        opt_text(user),
                        opt_text(elev.as_deref()),
                    ],
                )
                .with_detail_json(record_detail_json(rec, self.tool_id(), serde_json::json!({})))
                .with_raw_bytes(rec.raw_bytes.clone())
            })
            .collect();

        apply_rows(&self.schema(), &rows, req)
    }
}

fn format_token_elevation(raw: &str) -> String {
    match raw.trim() {
        "%%1936" | "1" => "Full (1936)".to_string(),
        "%%1937" | "2" => "Elevated (1937)".to_string(),
        "%%1938" | "3" => "Limited (1938)".to_string(),
        other => other.to_string(),
    }
}

// ---------------------------------------------------------------------------
// 13. evtx.tasks — Task Scheduler EVTX View
// ---------------------------------------------------------------------------

pub struct TasksProvider {
    source: ForensicSource,
    live_opts: LiveQueryOptions,
}

impl TasksProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self::with_options(source, LiveQueryOptions::default())
    }

    pub fn with_options(source: ForensicSource, live_opts: LiveQueryOptions) -> Self {
        Self { source, live_opts }
    }
}

impl TableProvider for TasksProvider {
    fn tool_id(&self) -> &'static str {
        "evtx.tasks"
    }

    fn description(&self) -> &'static str {
        "Task Scheduler Operational (100..103, 106, 140, 200, 201) execution view"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Task Scheduler EVTX View",
            vec![
                col("event_time", "EventTime", ColumnType::Timestamp, 180),
                col("event_id", "EventID", ColumnType::Uint, 80),
                col("task_name", "TaskName", ColumnType::Text, 240),
                col("action_name", "ActionName", ColumnType::Text, 220),
                col("instance_id", "InstanceID", ColumnType::Text, 220),
                col("result_code", "ResultCode", ColumnType::Text, 110),
                col("user_context", "UserContext", ColumnType::Text, 160),
            ],
        )
        .with_default_sort(0, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let opts = live_opts_with_xpath(
            &self.live_opts,
            "*[System[((EventID>=100 and EventID<=103) or EventID=106 or EventID=140 or EventID=200 or EventID=201)]]",
        );
        let loaded = load_records(
            &self.source,
            self.tool_id(),
            &["Microsoft-Windows-TaskScheduler/Operational"],
            &opts,
        )
        .map_err(|e| e.to_table_error())?;

        let rows: Vec<Row> = loaded
            .records
            .iter()
            .filter(|r| {
                (r.channel.is_empty()
                    || r.channel
                        .eq_ignore_ascii_case("Microsoft-Windows-TaskScheduler/Operational"))
                    && matches!(r.event_id, 100..=103 | 106 | 140 | 200 | 201)
            })
            .enumerate()
            .map(|(idx, rec)| {
                let fallback_action = match rec.event_id {
                    100 => "Task Started",
                    101 => "Task Start Failed",
                    102 => "Task Completed",
                    103 => "Action Launch Failed",
                    106 => "Task Registered",
                    140 => "Task Updated",
                    200 => "Action Started",
                    201 => "Action Completed",
                    _ => "Task Event",
                };
                let action_name = first_data(rec, &["ActionName"]).unwrap_or(fallback_action);
                let user_ctx = first_data(rec, &["UserContext", "UserName"]).or(rec.user_sid.as_deref());
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Timestamp(rec.event_time),
                        CellValue::Uint(u64::from(rec.event_id)),
                        opt_text(first_data(rec, &["TaskName"])),
                        CellValue::Text(action_name.to_string()),
                        opt_text(first_data(rec, &["InstanceId", "TaskInstanceId"])),
                        opt_text(first_data(rec, &["ResultCode", "ErrorCode"])),
                        opt_text(user_ctx),
                    ],
                )
                .with_detail_json(record_detail_json(rec, self.tool_id(), serde_json::json!({})))
                .with_raw_bytes(rec.raw_bytes.clone())
            })
            .collect();

        apply_rows(&self.schema(), &rows, req)
    }
}

// ---------------------------------------------------------------------------
// 14. evtx.usb — USB / PnP EVTX View
// ---------------------------------------------------------------------------

pub struct UsbProvider {
    source: ForensicSource,
    live_opts: LiveQueryOptions,
}

impl UsbProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self::with_options(source, LiveQueryOptions::default())
    }

    pub fn with_options(source: ForensicSource, live_opts: LiveQueryOptions) -> Self {
        Self { source, live_opts }
    }
}

impl TableProvider for UsbProvider {
    fn tool_id(&self) -> &'static str {
        "evtx.usb"
    }

    fn description(&self) -> &'static str {
        "Kernel-PnP (400..430) and DriverFrameworks (2003..2102) USB/PnP event view"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "USB / PnP EVTX View",
            vec![
                col("event_time", "EventTime", ColumnType::Timestamp, 180),
                col("event_id", "EventID", ColumnType::Uint, 80),
                col("device_id", "DeviceID", ColumnType::Text, 280),
                col("vendor", "Vendor", ColumnType::Text, 120),
                col("product", "Product", ColumnType::Text, 120),
                col("serial", "Serial", ColumnType::Text, 160),
                col("driver", "Driver", ColumnType::Text, 180),
                col("action", "Action", ColumnType::Text, 180),
            ],
        )
        .with_default_sort(0, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let opts = live_opts_with_xpath(
            &self.live_opts,
            "*[System[((EventID>=400 and EventID<=430) or (EventID>=2003 and EventID<=2102))]]",
        );
        let loaded = load_records(
            &self.source,
            self.tool_id(),
            &[
                "Microsoft-Windows-Kernel-PnP/Configuration",
                "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
            ],
            &opts,
        )
        .map_err(|e| e.to_table_error())?;

        let rows: Vec<Row> = loaded
            .records
            .iter()
            .filter(|r| {
                (r.channel.is_empty()
                    || r.channel
                        .eq_ignore_ascii_case("Microsoft-Windows-Kernel-PnP/Configuration")
                    || r.channel
                        .eq_ignore_ascii_case("Microsoft-Windows-DriverFrameworks-UserMode/Operational"))
                    && matches!(r.event_id, 400..=430 | 2003..=2102)
            })
            .enumerate()
            .map(|(idx, rec)| {
                let device_id = first_data(rec, &["DeviceInstanceId", "InstanceId", "DeviceId"]);
                let (vendor, product, serial) = device_id.map(parse_pnp_device_id).unwrap_or((None, None, None));
                let driver = first_data(rec, &["DriverName", "ServiceName", "Driver"]);
                let action = usb_eid_action(rec.event_id);

                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Timestamp(rec.event_time),
                        CellValue::Uint(u64::from(rec.event_id)),
                        opt_text(device_id),
                        opt_text(vendor.as_deref()),
                        opt_text(product.as_deref()),
                        opt_text(serial.as_deref()),
                        opt_text(driver),
                        CellValue::Text(action.to_string()),
                    ],
                )
                .with_detail_json(record_detail_json(
                    rec,
                    self.tool_id(),
                    serde_json::json!({ "action": action }),
                ))
                .with_raw_bytes(rec.raw_bytes.clone())
            })
            .collect();

        apply_rows(&self.schema(), &rows, req)
    }
}

fn parse_pnp_device_id(device_id: &str) -> (Option<String>, Option<String>, Option<String>) {
    let parts: Vec<&str> = device_id.split('\\').collect();
    let hw = parts.get(1).copied().unwrap_or("");
    let serial = parts.get(2).map(|s| (*s).to_string()).filter(|s| !s.is_empty());

    let mut vendor = None;
    let mut product = None;
    for seg in hw.split('&') {
        if let Some(v) = seg.strip_prefix("VID_").or_else(|| seg.strip_prefix("vid_")) {
            vendor = Some(format!("VID_{v}"));
        } else if let Some(v) = seg.strip_prefix("Ven_").or_else(|| seg.strip_prefix("ven_")) {
            vendor = Some(v.to_string());
        } else if let Some(p) = seg.strip_prefix("PID_").or_else(|| seg.strip_prefix("pid_")) {
            product = Some(format!("PID_{p}"));
        } else if let Some(p) = seg.strip_prefix("Prod_").or_else(|| seg.strip_prefix("prod_")) {
            product = Some(p.to_string());
        }
    }

    (vendor, product, serial)
}

fn usb_eid_action(eid: u16) -> &'static str {
    match eid {
        400 => "Device Configured",
        410 => "Device Started",
        420 => "Device Deleted",
        430 => "Device Requires Reboot",
        401..=430 => "Kernel-PnP Event",
        2003 => "UMDF Host Startup",
        2004 => "UMDF Driver AddDevice",
        2010 => "UMDF Driver Start",
        2100 => "Device Arrival / PnP",
        2101 => "PnP Request Completed",
        2102 => "Device Removal / Surprise Remove",
        _ => "DriverFrameworks Event",
    }
}
