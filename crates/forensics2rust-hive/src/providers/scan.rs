use chrono::{DateTime, Utc};
use forensics2rust_core::{ForensicError, ForensicSource, QueryHelper};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{display_value_name, opt_timestamp_cell};
use crate::live::{LiveScanOptions, scan_live_registry};
use crate::regf::{RegValueData, RegfHive};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    pub roots: Vec<String>,
    pub key_pattern: Option<String>,
    pub value_name_pattern: Option<String>,
    pub value_data_pattern: Option<String>,
    pub value_types: Vec<u32>,
    pub min_data_len: Option<usize>,
    pub max_data_len: Option<usize>,
    pub modified_after: Option<DateTime<Utc>>,
    pub modified_before: Option<DateTime<Utc>>,
    pub use_regex: bool,
    pub case_sensitive: bool,
    pub max_depth: Option<usize>,
    pub include_keys_without_values: bool,
    pub wow64_64: bool,
    pub max_keys: Option<usize>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            key_pattern: None,
            value_name_pattern: None,
            value_data_pattern: None,
            value_types: Vec::new(),
            min_data_len: None,
            max_data_len: None,
            modified_after: None,
            modified_before: None,
            use_regex: false,
            case_sensitive: false,
            max_depth: None,
            include_keys_without_values: false,
            wow64_64: true,
            max_keys: None,
        }
    }
}

impl ScanOptions {
    pub fn with_roots(mut self, roots: Vec<String>) -> Self {
        self.roots = roots;
        self
    }
}

enum Matcher {
    Substring { needle: String, case_sensitive: bool },
    Regex(Regex),
}

impl Matcher {
    fn compile(pattern: Option<&str>, use_regex: bool, case_sensitive: bool) -> Result<Option<Self>, ForensicError> {
        let Some(pat) = pattern.filter(|p| !p.is_empty()) else {
            return Ok(None);
        };
        if use_regex {
            let rx = RegexBuilder::new(pat)
                .case_insensitive(!case_sensitive)
                .build()
                .map_err(|e| ForensicError::InvalidArgument(format!("invalid scan regex '{pat}': {e}")))?;
            Ok(Some(Self::Regex(rx)))
        } else {
            let needle = if case_sensitive {
                pat.to_owned()
            } else {
                pat.to_ascii_lowercase()
            };
            Ok(Some(Self::Substring { needle, case_sensitive }))
        }
    }

    fn matches(&self, hay: &str) -> bool {
        match self {
            Self::Substring { needle, case_sensitive } => {
                if *case_sensitive {
                    hay.contains(needle)
                } else {
                    hay.to_ascii_lowercase().contains(needle)
                }
            }
            Self::Regex(rx) => rx.is_match(hay),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RegistryScannerProvider {
    source: ForensicSource,
    options: ScanOptions,
}

impl RegistryScannerProvider {
    pub const TOOL_ID: &'static str = "hive.scan";
    pub const DESCRIPTION: &'static str =
        "Recursive Windows Registry scanner with type, date, length, and regex filters";

    pub fn new(source: ForensicSource) -> Self {
        Self {
            source,
            options: ScanOptions {
                wow64_64: true,
                include_keys_without_values: false,
                ..Default::default()
            },
        }
    }

    pub fn with_options(mut self, options: ScanOptions) -> Self {
        self.options = options;
        self
    }

    pub fn build_schema() -> TableSchema {
        TableSchema::new(
            Self::TOOL_ID,
            "Registry Scanner",
            vec![
                ColumnDef::new("hive_root", "HiveRoot", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("key_path", "KeyPath", ColumnType::Text).with_width_hint(280),
                ColumnDef::new("value_name", "ValueName", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("value_type", "ValueType", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("data_preview", "DataPreview", ColumnType::Text).with_width_hint(240),
                ColumnDef::new("data_len", "DataLen", ColumnType::BytesSize).with_width_hint(90),
                ColumnDef::new("last_write_time", "LastWriteTime", ColumnType::Timestamp).with_width_hint(180),
            ],
        )
        .with_default_sort(6, SortDirection::Desc)
    }

    pub fn collect_rows(&self) -> Result<Vec<Row>, ForensicError> {
        let key_matcher = Matcher::compile(
            self.options.key_pattern.as_deref(),
            self.options.use_regex,
            self.options.case_sensitive,
        )?;
        let val_name_matcher = Matcher::compile(
            self.options.value_name_pattern.as_deref(),
            self.options.use_regex,
            self.options.case_sensitive,
        )?;
        let val_data_matcher = Matcher::compile(
            self.options.value_data_pattern.as_deref(),
            self.options.use_regex,
            self.options.case_sensitive,
        )?;

        let mut rows = Vec::new();
        let mut next_id = 0u64;

        match &self.source {
            ForensicSource::Live => {
                let mut live_opts = LiveScanOptions {
                    wow64_64: self.options.wow64_64,
                    max_depth: self.options.max_depth.or(Some(6)),
                    max_keys: self.options.max_keys.or(Some(10_000)),
                    ..Default::default()
                };
                if !self.options.roots.is_empty() {
                    live_opts.roots = self.options.roots.clone();
                }

                let res = scan_live_registry(&live_opts, Self::TOOL_ID)?;
                let warnings_json: Vec<serde_json::Value> = res
                    .warnings
                    .iter()
                    .map(|w| json!({ "severity": format!("{:?}", w.severity), "source": w.source, "message": w.message }))
                    .collect();

                for entry in res.entries {
                    if !self.time_matches(entry.last_write_time) {
                        continue;
                    }
                    if let Some(ref km) = key_matcher
                        && !km.matches(&entry.key_path)
                    {
                        continue;
                    }

                    if entry.values.is_empty() && self.options.include_keys_without_values && self.no_value_filters() {
                        rows.push(
                            Row::new(
                                next_id,
                                vec![
                                    CellValue::Text(entry.hive_root.clone()),
                                    CellValue::Text(entry.key_path.clone()),
                                    CellValue::Text(String::new()),
                                    CellValue::Text("KEY".to_owned()),
                                    CellValue::Text(format!("({} subkeys)", entry.subkey_count)),
                                    CellValue::Bytes(0),
                                    opt_timestamp_cell(entry.last_write_time),
                                ],
                            )
                            .with_detail_json(json!({
                                "subkey_count": entry.subkey_count,
                                "warnings": warnings_json,
                            })),
                        );
                        next_id += 1;
                        continue;
                    }

                    for val in entry.values {
                        if !self.value_matches(
                            &val.name,
                            val.raw_type,
                            &val.data,
                            val.raw_bytes.len(),
                            &val_name_matcher,
                            &val_data_matcher,
                        ) {
                            continue;
                        }
                        let preview = val.data.preview();
                        let type_name = val.data.type_name().into_owned();
                        rows.push(
                            Row::new(
                                next_id,
                                vec![
                                    CellValue::Text(entry.hive_root.clone()),
                                    CellValue::Text(entry.key_path.clone()),
                                    CellValue::Text(display_value_name(&val.name)),
                                    CellValue::Text(type_name),
                                    CellValue::Text(preview),
                                    CellValue::Bytes(val.raw_bytes.len() as u64),
                                    opt_timestamp_cell(entry.last_write_time),
                                ],
                            )
                            .with_raw_bytes(val.raw_bytes)
                            .with_detail_json(json!({
                                "raw_type": val.raw_type,
                                "subkey_count": entry.subkey_count,
                                "warnings_count": warnings_json.len(),
                            })),
                        );
                        next_id += 1;
                    }
                }
            }
            ForensicSource::OfflinePath(_) | ForensicSource::OfflineBytes(_) => {
                let bytes = self.source.read_bytes()?;
                let hive = RegfHive::from_bytes(&bytes)?;
                let hive_root = if hive.header().file_name.is_empty() {
                    "OFFLINE".to_owned()
                } else {
                    hive.header().file_name.clone()
                };

                for key in hive.walk_keys() {
                    if let Some(max_d) = self.options.max_depth {
                        let depth = if key.path().is_empty() {
                            0
                        } else {
                            key.path().split('\\').count()
                        };
                        if depth > max_d {
                            continue;
                        }
                    }
                    if !self.time_matches(key.last_write_time()) {
                        continue;
                    }
                    if let Some(ref km) = key_matcher
                        && !km.matches(key.path())
                    {
                        continue;
                    }

                    if key.values().is_empty() && self.options.include_keys_without_values && self.no_value_filters() {
                        rows.push(
                            Row::new(
                                next_id,
                                vec![
                                    CellValue::Text(hive_root.clone()),
                                    CellValue::Text(key.path().to_owned()),
                                    CellValue::Text(String::new()),
                                    CellValue::Text("KEY".to_owned()),
                                    CellValue::Text(format!("({} subkeys)", key.subkey_count())),
                                    CellValue::Bytes(0),
                                    opt_timestamp_cell(key.last_write_time()),
                                ],
                            )
                            .with_detail_json(json!({
                                "cell_offset": key.cell_offset(),
                                "subkey_count": key.subkey_count(),
                            })),
                        );
                        next_id += 1;
                        continue;
                    }

                    for val in key.values() {
                        if !self.value_matches(
                            &val.name,
                            val.raw_type,
                            &val.data,
                            val.raw_bytes.len(),
                            &val_name_matcher,
                            &val_data_matcher,
                        ) {
                            continue;
                        }
                        rows.push(
                            Row::new(
                                next_id,
                                vec![
                                    CellValue::Text(hive_root.clone()),
                                    CellValue::Text(key.path().to_owned()),
                                    CellValue::Text(val.display_name().to_owned()),
                                    CellValue::Text(val.type_name().into_owned()),
                                    CellValue::Text(val.preview()),
                                    CellValue::Bytes(val.raw_bytes.len() as u64),
                                    opt_timestamp_cell(key.last_write_time()),
                                ],
                            )
                            .with_raw_bytes(val.raw_bytes.clone())
                            .with_detail_json(json!({
                                "cell_offset": val.cell_offset,
                                "raw_type": val.raw_type,
                                "decoded": val.decoded_string(),
                            })),
                        );
                        next_id += 1;
                    }
                }
            }
        }

        Ok(rows)
    }

    fn no_value_filters(&self) -> bool {
        self.options.value_name_pattern.is_none()
            && self.options.value_data_pattern.is_none()
            && self.options.value_types.is_empty()
            && self.options.min_data_len.is_none()
            && self.options.max_data_len.is_none()
    }

    fn time_matches(&self, ts: Option<DateTime<Utc>>) -> bool {
        if let Some(after) = self.options.modified_after {
            match ts {
                Some(t) if t >= after => {}
                _ => return false,
            }
        }
        if let Some(before) = self.options.modified_before {
            match ts {
                Some(t) if t <= before => {}
                _ => return false,
            }
        }
        true
    }

    fn value_matches(
        &self,
        name: &str,
        raw_type: u32,
        data: &RegValueData,
        len: usize,
        name_matcher: &Option<Matcher>,
        data_matcher: &Option<Matcher>,
    ) -> bool {
        if !self.options.value_types.is_empty() && !self.options.value_types.contains(&raw_type) {
            return false;
        }
        if let Some(min_len) = self.options.min_data_len
            && len < min_len
        {
            return false;
        }
        if let Some(max_len) = self.options.max_data_len
            && len > max_len
        {
            return false;
        }
        if let Some(nm) = name_matcher
            && !nm.matches(name)
            && !nm.matches(&display_value_name(name))
        {
            return false;
        }
        if let Some(dm) = data_matcher {
            let decoded = data.decoded_string();
            if !dm.matches(&decoded) {
                return false;
            }
        }
        true
    }
}

impl TableProvider for RegistryScannerProvider {
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
