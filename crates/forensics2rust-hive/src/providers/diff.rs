use std::collections::{BTreeMap, HashSet};

use chrono::{DateTime, Utc};
use forensics2rust_core::{ForensicError, ForensicSource, QueryHelper};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{display_value_name, opt_text_cell, opt_timestamp_cell};
use crate::live::{LiveScanOptions, scan_live_registry};
use crate::regf::RegfHive;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrySnapshotEntry {
    pub key_path: String,
    pub value_name: String,
    pub value_type: String,
    pub data_decoded: String,
    pub timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize)]
struct DiffPairSnapshot {
    left: Vec<RegistrySnapshotEntry>,
    right: Vec<RegistrySnapshotEntry>,
}

#[derive(Debug, Clone)]
pub struct RegistryChangesProvider {
    left: ForensicSource,
    right: Option<ForensicSource>,
    root_prefix: Option<String>,
}

impl RegistryChangesProvider {
    pub const TOOL_ID: &'static str = "hive.diff";
    pub const DESCRIPTION: &'static str =
        "Registry comparison across snapshots, live hives, offline regf files, or VSS";

    pub fn new(source: ForensicSource) -> Self {
        Self {
            left: source,
            right: None,
            root_prefix: None,
        }
    }

    pub fn between(left: ForensicSource, right: ForensicSource) -> Self {
        Self {
            left,
            right: Some(right),
            root_prefix: None,
        }
    }

    pub fn with_root_prefix(mut self, prefix: Option<String>) -> Self {
        self.root_prefix = prefix;
        self
    }

    pub fn build_schema() -> TableSchema {
        TableSchema::new(
            Self::TOOL_ID,
            "Registry Changes Diff",
            vec![
                ColumnDef::new("change_type", "ChangeType", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("key_path", "KeyPath", ColumnType::Text).with_width_hint(280),
                ColumnDef::new("value_name", "ValueName", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("old_type", "OldType", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("old_data", "OldData", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("new_type", "NewType", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("new_data", "NewData", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("timestamp", "Timestamp", ColumnType::Timestamp).with_width_hint(180),
            ],
        )
        .with_default_sort(1, SortDirection::Asc)
    }

    pub fn collect_rows(&self) -> Result<Vec<Row>, ForensicError> {
        let (left_entries, right_entries) = match &self.right {
            Some(right_src) => (
                load_snapshot(&self.left, self.root_prefix.as_deref())?,
                load_snapshot(right_src, self.root_prefix.as_deref())?,
            ),
            None => load_single_source_pair(&self.left, self.root_prefix.as_deref())?,
        };

        let mut left_map: BTreeMap<(String, String), RegistrySnapshotEntry> = BTreeMap::new();
        for item in left_entries {
            let key = (item.key_path.to_ascii_lowercase(), item.value_name.to_ascii_lowercase());
            left_map.insert(key, item);
        }

        let mut right_map: BTreeMap<(String, String), RegistrySnapshotEntry> = BTreeMap::new();
        for item in right_entries {
            let key = (item.key_path.to_ascii_lowercase(), item.value_name.to_ascii_lowercase());
            right_map.insert(key, item);
        }

        let left_keys: HashSet<String> = left_map.keys().map(|(kp, _)| kp.clone()).collect();
        let right_keys: HashSet<String> = right_map.keys().map(|(kp, _)| kp.clone()).collect();

        let mut rows = Vec::new();
        let mut next_id = 0u64;

        for (canon_key, right_val) in &right_map {
            match left_map.get(canon_key) {
                None => {
                    if right_val.value_type == "KEY"
                        && right_val.value_name.is_empty()
                        && left_keys.contains(&canon_key.0)
                    {
                        continue;
                    }
                    rows.push(
                        Row::new(
                            next_id,
                            vec![
                                CellValue::Text("Added".to_owned()),
                                CellValue::Text(right_val.key_path.clone()),
                                CellValue::Text(right_val.value_name.clone()),
                                CellValue::Null,
                                CellValue::Null,
                                CellValue::Text(right_val.value_type.clone()),
                                CellValue::Text(right_val.data_decoded.clone()),
                                opt_timestamp_cell(right_val.timestamp),
                            ],
                        )
                        .with_detail_json(json!({
                            "change_type": "Added",
                            "key_path": right_val.key_path,
                            "value_name": right_val.value_name,
                        })),
                    );
                    next_id += 1;
                }
                Some(left_val)
                    if left_val.value_type != right_val.value_type
                        || left_val.data_decoded != right_val.data_decoded =>
                {
                    rows.push(
                        Row::new(
                            next_id,
                            vec![
                                CellValue::Text("Modified".to_owned()),
                                CellValue::Text(right_val.key_path.clone()),
                                CellValue::Text(right_val.value_name.clone()),
                                opt_text_cell(Some(left_val.value_type.clone())),
                                opt_text_cell(Some(left_val.data_decoded.clone())),
                                opt_text_cell(Some(right_val.value_type.clone())),
                                opt_text_cell(Some(right_val.data_decoded.clone())),
                                opt_timestamp_cell(right_val.timestamp.or(left_val.timestamp)),
                            ],
                        )
                        .with_detail_json(json!({
                            "change_type": "Modified",
                            "key_path": right_val.key_path,
                            "value_name": right_val.value_name,
                            "old_type": left_val.value_type,
                            "new_type": right_val.value_type,
                        })),
                    );
                    next_id += 1;
                }
                Some(_) => {}
            }
        }

        for (canon_key, left_val) in &left_map {
            if !right_map.contains_key(canon_key) {
                if left_val.value_type == "KEY" && left_val.value_name.is_empty() && right_keys.contains(&canon_key.0) {
                    continue;
                }
                rows.push(
                    Row::new(
                        next_id,
                        vec![
                            CellValue::Text("Deleted".to_owned()),
                            CellValue::Text(left_val.key_path.clone()),
                            CellValue::Text(left_val.value_name.clone()),
                            CellValue::Text(left_val.value_type.clone()),
                            CellValue::Text(left_val.data_decoded.clone()),
                            CellValue::Null,
                            CellValue::Null,
                            opt_timestamp_cell(left_val.timestamp),
                        ],
                    )
                    .with_detail_json(json!({
                        "change_type": "Deleted",
                        "key_path": left_val.key_path,
                        "value_name": left_val.value_name,
                    })),
                );
                next_id += 1;
            }
        }

        Ok(rows)
    }
}

fn load_single_source_pair(
    source: &ForensicSource,
    root_prefix: Option<&str>,
) -> Result<(Vec<RegistrySnapshotEntry>, Vec<RegistrySnapshotEntry>), ForensicError> {
    if source.is_offline() {
        let bytes = source.read_bytes()?;
        if let Ok(text) = std::str::from_utf8(&bytes)
            && text.trim_start().starts_with('{')
            && let Ok(pair) = serde_json::from_str::<DiffPairSnapshot>(text)
        {
            return Ok((pair.left, pair.right));
        }
        let entries = load_snapshot_from_bytes(&bytes, root_prefix)?;
        return Ok((entries.clone(), entries));
    }

    let entries = load_snapshot(source, root_prefix)?;
    Ok((entries.clone(), entries))
}

fn load_snapshot(
    source: &ForensicSource,
    root_prefix: Option<&str>,
) -> Result<Vec<RegistrySnapshotEntry>, ForensicError> {
    match source {
        ForensicSource::Live => {
            let roots = match root_prefix {
                Some(p) if !p.trim().is_empty() => vec![p.to_owned()],
                _ => vec!["HKCU\\Software".to_owned()],
            };
            let opts = LiveScanOptions {
                roots,
                max_depth: Some(6),
                wow64_64: true,
                max_keys: Some(10_000),
            };
            let res = scan_live_registry(&opts, RegistryChangesProvider::TOOL_ID)?;
            let mut out = Vec::new();
            for entry in res.entries {
                let full_key = if entry.key_path.is_empty() {
                    entry.hive_root.clone()
                } else {
                    format!("{}\\{}", entry.hive_root, entry.key_path)
                };
                if entry.values.is_empty() {
                    out.push(RegistrySnapshotEntry {
                        key_path: full_key,
                        value_name: String::new(),
                        value_type: "KEY".to_owned(),
                        data_decoded: String::new(),
                        timestamp: entry.last_write_time,
                    });
                } else {
                    for val in entry.values {
                        out.push(RegistrySnapshotEntry {
                            key_path: full_key.clone(),
                            value_name: display_value_name(&val.name),
                            value_type: val.data.type_name().into_owned(),
                            data_decoded: val.data.decoded_string(),
                            timestamp: entry.last_write_time,
                        });
                    }
                }
            }
            Ok(out)
        }
        ForensicSource::OfflinePath(_) | ForensicSource::OfflineBytes(_) => {
            let bytes = source.read_bytes()?;
            load_snapshot_from_bytes(&bytes, root_prefix)
        }
    }
}

fn load_snapshot_from_bytes(
    bytes: &[u8],
    root_prefix: Option<&str>,
) -> Result<Vec<RegistrySnapshotEntry>, ForensicError> {
    if bytes.starts_with(b"regf") {
        let hive = RegfHive::from_bytes(bytes)?;
        let mut out = Vec::new();
        let prefix = root_prefix.unwrap_or("").trim_matches('\\');
        for key in hive.walk_keys() {
            let key_path = if prefix.is_empty() {
                key.path().to_owned()
            } else if key.path().is_empty() {
                prefix.to_owned()
            } else {
                format!("{prefix}\\{}", key.path())
            };
            if key.values().is_empty() {
                out.push(RegistrySnapshotEntry {
                    key_path,
                    value_name: String::new(),
                    value_type: "KEY".to_owned(),
                    data_decoded: String::new(),
                    timestamp: key.last_write_time(),
                });
            } else {
                for val in key.values() {
                    out.push(RegistrySnapshotEntry {
                        key_path: key_path.clone(),
                        value_name: val.display_name().to_owned(),
                        value_type: val.type_name().into_owned(),
                        data_decoded: val.data.decoded_string(),
                        timestamp: key.last_write_time(),
                    });
                }
            }
        }
        return Ok(out);
    }

    let text = std::str::from_utf8(bytes)
        .map_err(|e| ForensicError::parse("hive.diff", format!("invalid UTF-8 snapshot: {e}")))?;
    serde_json::from_str::<Vec<RegistrySnapshotEntry>>(text)
        .map_err(|e| ForensicError::parse("hive.diff", format!("expected regf hive or JSON snapshot: {e}")))
}

impl TableProvider for RegistryChangesProvider {
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
