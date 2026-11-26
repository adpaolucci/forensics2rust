use forensics2rust_core::{ForensicError, ForensicSource, QueryHelper};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};
use serde_json::json;

use super::opt_timestamp_cell;
use crate::reg_format::{RegExportFormat, RegExportOptions, export_hive};
use crate::regf::RegfHive;

#[derive(Debug, Clone)]
pub struct OfflineRegistryProvider {
    source: ForensicSource,
    key_prefix: Option<String>,
    include_keys: bool,
}

impl OfflineRegistryProvider {
    pub const TOOL_ID: &'static str = "hive.offline";
    pub const DESCRIPTION: &'static str = "Pure-Rust offline regf/hbin Registry hive key and value browser";

    pub fn new(source: ForensicSource) -> Self {
        Self {
            source,
            key_prefix: None,
            include_keys: true,
        }
    }

    pub fn with_key_prefix(mut self, prefix: Option<String>) -> Self {
        self.key_prefix = prefix;
        self
    }

    pub fn with_include_keys(mut self, include_keys: bool) -> Self {
        self.include_keys = include_keys;
        self
    }

    pub fn build_schema() -> TableSchema {
        TableSchema::new(
            Self::TOOL_ID,
            "Offline Registry View",
            vec![
                ColumnDef::new("key_path", "KeyPath", ColumnType::Text).with_width_hint(280),
                ColumnDef::new("value_name", "ValueName", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("value_type", "ValueType", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("data_hex", "DataHex", ColumnType::Hex).with_width_hint(180),
                ColumnDef::new("data_decoded", "DataDecoded", ColumnType::Text).with_width_hint(240),
                ColumnDef::new("last_write_time", "LastWriteTime", ColumnType::Timestamp).with_width_hint(180),
                ColumnDef::new("subkey_count", "SubkeyCount", ColumnType::Uint).with_width_hint(100),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    pub fn load_hive(&self) -> Result<RegfHive, ForensicError> {
        if self.source.is_live() {
            return Err(ForensicError::InvalidArgument(
                "hive.offline requires an offline regf file or bytes; use hive.scan for live registry".to_owned(),
            ));
        }
        let bytes = self.source.read_bytes()?;
        RegfHive::from_bytes(&bytes)
    }

    pub fn export_reg_v5(&self) -> Result<String, ForensicError> {
        let hive = self.load_hive()?;
        let opts = RegExportOptions {
            format: RegExportFormat::Regedit5,
            include_deleted: false,
            utf8_output: true,
            ..Default::default()
        };
        Ok(export_hive(&hive, &opts).text)
    }

    pub fn export_reg_v4(&self) -> Result<String, ForensicError> {
        let hive = self.load_hive()?;
        let opts = RegExportOptions {
            format: RegExportFormat::Regedit4,
            include_deleted: false,
            utf8_output: true,
            ..Default::default()
        };
        Ok(export_hive(&hive, &opts).text)
    }

    pub fn collect_rows(&self) -> Result<Vec<Row>, ForensicError> {
        let hive = self.load_hive()?;
        let filter_prefix = self.key_prefix.as_deref().map(|p| {
            p.trim_matches(|c| c == '\\' || c == '/')
                .replace('/', "\\")
                .to_ascii_lowercase()
        });

        let mut rows = Vec::new();
        let mut next_id = 0u64;

        for key in hive.walk_keys() {
            if let Some(ref pref) = filter_prefix
                && !pref.is_empty()
            {
                let path = key.path().to_ascii_lowercase();
                if path != *pref && !path.starts_with(&format!("{pref}\\")) {
                    continue;
                }
            }

            if key.values().is_empty() {
                if self.include_keys {
                    rows.push(
                        Row::new(
                            next_id,
                            vec![
                                CellValue::Text(key.path().to_owned()),
                                CellValue::Text(String::new()),
                                CellValue::Text("KEY".to_owned()),
                                CellValue::Null,
                                CellValue::Null,
                                opt_timestamp_cell(key.last_write_time()),
                                CellValue::Uint(key.subkey_count() as u64),
                            ],
                        )
                        .with_detail_json(json!({
                            "key_name": key.name(),
                            "cell_offset": key.cell_offset(),
                            "flags": key.flags(),
                            "declared_subkey_count": key.declared_subkey_count(),
                        })),
                    );
                    next_id += 1;
                }
                continue;
            }

            for val in key.values() {
                let data_hex = if val.raw_bytes.is_empty() {
                    CellValue::Null
                } else {
                    CellValue::Hex(val.raw_bytes.clone())
                };
                rows.push(
                    Row::new(
                        next_id,
                        vec![
                            CellValue::Text(key.path().to_owned()),
                            CellValue::Text(val.display_name().to_owned()),
                            CellValue::Text(val.type_name().into_owned()),
                            data_hex,
                            CellValue::Text(val.decoded_string()),
                            opt_timestamp_cell(key.last_write_time()),
                            CellValue::Uint(key.subkey_count() as u64),
                        ],
                    )
                    .with_raw_bytes(val.raw_bytes.clone())
                    .with_detail_json(json!({
                        "key_offset": key.cell_offset(),
                        "value_offset": val.cell_offset,
                        "raw_type": val.raw_type,
                        "data_len": val.raw_bytes.len(),
                        "is_dirty_hive": hive.header().is_dirty,
                    })),
                );
                next_id += 1;
            }
        }

        Ok(rows)
    }
}

impl TableProvider for OfflineRegistryProvider {
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
