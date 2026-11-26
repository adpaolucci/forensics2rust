use forensics2rust_core::{ForensicError, ForensicSource, QueryHelper};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};
use serde_json::json;

use super::opt_text_cell;
use crate::etw::{
    RegistryWatchEvent, WatchOptions, export_watch_reg_script, is_mutation_event_id, parse_offline_watch_bytes,
    watch_live_registry,
};

#[derive(Debug, Clone)]
pub struct RegWatchProvider {
    source: ForensicSource,
    options: WatchOptions,
}

impl RegWatchProvider {
    pub const TOOL_ID: &'static str = "hive.watch";
    pub const DESCRIPTION: &'static str =
        "ETW Microsoft-Windows-Kernel-Registry ({70EB4F03-...}) monitor and .reg trace parser";

    pub fn new(source: ForensicSource) -> Self {
        Self {
            source,
            options: WatchOptions::default(),
        }
    }

    pub fn with_options(mut self, options: WatchOptions) -> Self {
        self.options = options;
        self
    }

    pub fn build_schema() -> TableSchema {
        TableSchema::new(
            Self::TOOL_ID,
            "Registry Activity Watch (ETW)",
            vec![
                ColumnDef::new("timestamp", "Timestamp", ColumnType::Timestamp).with_width_hint(180),
                ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("process_name", "ProcessName", ColumnType::Text).with_width_hint(150),
                ColumnDef::new("operation", "Operation", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("key_path", "KeyPath", ColumnType::Text).with_width_hint(280),
                ColumnDef::new("value_name", "ValueName", ColumnType::Text).with_width_hint(150),
                ColumnDef::new("reg_dotnet_line", "RegDotNetLine", ColumnType::Text).with_width_hint(280),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    pub fn collect_events(&self) -> Result<Vec<RegistryWatchEvent>, ForensicError> {
        let mut events = match &self.source {
            ForensicSource::Live => watch_live_registry(&self.options)?,
            ForensicSource::OfflinePath(_) | ForensicSource::OfflineBytes(_) => {
                let bytes = self.source.read_bytes()?;
                parse_offline_watch_bytes(&bytes)?
            }
        };

        if self.options.mutations_only {
            events.retain(|e| is_mutation_event_id(e.event_id));
        }
        if let Some(pid) = self.options.target_pid {
            events.retain(|e| e.pid == pid);
        }
        if let Some(ref pfilter) = self.options.process_filter {
            let needle = pfilter.to_ascii_lowercase();
            events.retain(|e| e.process_name.to_ascii_lowercase().contains(&needle));
        }
        if let Some(ref kfilter) = self.options.key_filter {
            let needle = kfilter.to_ascii_lowercase();
            events.retain(|e| e.key_path.to_ascii_lowercase().contains(&needle));
        }
        if events.len() > self.options.max_events {
            events.truncate(self.options.max_events);
        }

        Ok(events)
    }

    pub fn export_reg_script(&self) -> Result<String, ForensicError> {
        let events = self.collect_events()?;
        Ok(export_watch_reg_script(&events))
    }

    pub fn collect_rows(&self) -> Result<Vec<Row>, ForensicError> {
        let events = self.collect_events()?;
        let rows = events
            .into_iter()
            .enumerate()
            .map(|(idx, ev)| {
                let mut row = Row::new(
                    idx as u64,
                    vec![
                        CellValue::Timestamp(ev.timestamp),
                        CellValue::Uint(u64::from(ev.pid)),
                        CellValue::Text(ev.process_name),
                        CellValue::Text(ev.operation),
                        CellValue::Text(ev.key_path),
                        opt_text_cell(ev.value_name),
                        CellValue::Text(ev.reg_dotnet_line),
                    ],
                )
                .with_detail_json(json!({
                    "event_id": ev.event_id,
                    "opcode": ev.opcode,
                    "tid": ev.tid,
                    "status": ev.status,
                    "value_type": ev.value_type,
                }));
                if !ev.raw_bytes.is_empty() {
                    row = row.with_raw_bytes(ev.raw_bytes);
                }
                row
            })
            .collect();
        Ok(rows)
    }
}

impl TableProvider for RegWatchProvider {
    fn tool_id(&self) -> &'static str {
        Self::TOOL_ID
    }

    fn description(&self) -> &'static str {
        Self::DESCRIPTION
    }

    fn schema(&self) -> TableSchema {
        Self::build_schema()
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let rows = self.collect_rows().map_err(|e| e.to_table_error())?;
        QueryHelper::apply(&self.schema(), &rows, req).map_err(|e| e.to_table_error())
    }
}
