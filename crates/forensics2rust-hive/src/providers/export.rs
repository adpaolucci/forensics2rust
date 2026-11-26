use forensics2rust_core::{ForensicError, ForensicSource, QueryHelper};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};
use serde_json::json;

use crate::reg_format::{RegExportFormat, RegExportOptions, RegExportResult, export_hive};
use crate::regf::RegfHive;

#[derive(Debug, Clone)]
pub struct RegFileExportProvider {
    source: ForensicSource,
    options: RegExportOptions,
}

impl RegFileExportProvider {
    pub const TOOL_ID: &'static str = "hive.export";
    pub const DESCRIPTION: &'static str =
        "Pure-Rust tolerant regf to .reg (REGEDIT4/5) exporter recovering malformed cells";

    pub fn new(source: ForensicSource) -> Self {
        Self {
            source,
            options: RegExportOptions::default(),
        }
    }

    pub fn with_format(mut self, format: RegExportFormat) -> Self {
        self.options.format = format;
        self
    }

    pub fn with_root_name(mut self, root_name: impl Into<String>) -> Self {
        self.options.root_prefix = root_name.into();
        self
    }

    pub fn with_include_deleted(mut self, include_deleted: bool) -> Self {
        self.options.include_deleted = include_deleted;
        self
    }

    pub fn with_utf8_output(mut self, utf8_output: bool) -> Self {
        self.options.utf8_output = utf8_output;
        self
    }

    pub fn build_schema() -> TableSchema {
        TableSchema::new(
            Self::TOOL_ID,
            "Registry File Export",
            vec![
                ColumnDef::new("key_path", "KeyPath", ColumnType::Text).with_width_hint(300),
                ColumnDef::new("values_exported", "ValuesExported", ColumnType::Uint).with_width_hint(120),
                ColumnDef::new("malformed_cells_recovered", "MalformedCellsRecovered", ColumnType::Uint)
                    .with_width_hint(170),
                ColumnDef::new("output_bytes", "OutputBytes", ColumnType::BytesSize).with_width_hint(120),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    pub fn export_to_result(&self) -> Result<RegExportResult, ForensicError> {
        if self.source.is_live() {
            return Err(ForensicError::InvalidArgument(
                "hive.export requires an offline regf file or bytes".to_owned(),
            ));
        }
        let bytes = self.source.read_bytes()?;
        let hive = RegfHive::from_bytes_tolerant(&bytes)?;
        Ok(export_hive(&hive, &self.options))
    }

    pub fn export_to_string(&self) -> Result<String, ForensicError> {
        Ok(self.export_to_result()?.text)
    }

    pub fn collect_rows(&self) -> Result<Vec<Row>, ForensicError> {
        let exported = self.export_to_result()?;
        let rows = exported
            .per_key
            .into_iter()
            .enumerate()
            .map(|(idx, entry)| {
                Row::new(
                    idx as u64,
                    vec![
                        CellValue::Text(entry.key_path),
                        CellValue::Uint(entry.values_exported),
                        CellValue::Uint(entry.malformed_cells_recovered),
                        CellValue::Bytes(entry.output_bytes),
                    ],
                )
                .with_detail_json(json!({
                    "is_deleted": entry.is_deleted,
                    "reg_snippet": entry.snippet,
                }))
            })
            .collect();
        Ok(rows)
    }
}

impl TableProvider for RegFileExportProvider {
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
