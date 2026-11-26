use chrono::{DateTime, Utc};
use forensics2rust_core::{ForensicError, ForensicSource, QueryHelper, bytes_to_hex_lower, read_utf16_le};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::opt_timestamp_cell;
use crate::regf::{RegValue, RegfHive};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindCriteria {
    pub query_text: Option<String>,
    pub hex_bytes: Option<Vec<u8>>,
    pub value_types: Vec<u32>,
    pub modified_after: Option<DateTime<Utc>>,
    pub modified_before: Option<DateTime<Utc>>,
    pub search_keys: bool,
    pub search_value_names: bool,
    pub search_value_data: bool,
    pub case_sensitive: bool,
    pub use_regex: bool,
}

impl Default for FindCriteria {
    fn default() -> Self {
        Self {
            query_text: None,
            hex_bytes: None,
            value_types: Vec::new(),
            modified_after: None,
            modified_before: None,
            search_keys: true,
            search_value_names: true,
            search_value_data: true,
            case_sensitive: false,
            use_regex: false,
        }
    }
}

impl FindCriteria {
    pub fn with_text(mut self, text: impl Into<String>) -> Self {
        self.query_text = Some(text.into());
        self
    }

    pub fn with_hex(mut self, bytes: Vec<u8>) -> Self {
        self.hex_bytes = Some(bytes);
        self
    }

    pub fn with_value_type(mut self, raw_type: u32) -> Self {
        self.value_types.push(raw_type);
        self
    }
}

#[derive(Debug, Clone)]
pub struct OfflineFinderProvider {
    source: ForensicSource,
    criteria: FindCriteria,
}

impl OfflineFinderProvider {
    pub const TOOL_ID: &'static str = "hive.find";
    pub const DESCRIPTION: &'static str = "Pure-Rust regf deep search by string, hex bytes, timestamp, or value type";

    pub fn new(source: ForensicSource) -> Self {
        Self {
            source,
            criteria: FindCriteria::default(),
        }
    }

    pub fn with_criteria(mut self, criteria: FindCriteria) -> Self {
        self.criteria = criteria;
        self
    }

    pub fn build_schema() -> TableSchema {
        TableSchema::new(
            Self::TOOL_ID,
            "Offline Registry Finder",
            vec![
                ColumnDef::new("hive_file", "HiveFile", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("key_path", "KeyPath", ColumnType::Text).with_width_hint(280),
                ColumnDef::new("value_name", "ValueName", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("value_type", "ValueType", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("matched_data", "MatchedData", ColumnType::Text).with_width_hint(260),
                ColumnDef::new("last_write_time", "LastWriteTime", ColumnType::Timestamp).with_width_hint(180),
            ],
        )
        .with_default_sort(1, SortDirection::Asc)
    }

    pub fn collect_rows(&self) -> Result<Vec<Row>, ForensicError> {
        if self.source.is_live() {
            return Err(ForensicError::InvalidArgument(
                "hive.find requires an offline regf file or bytes; use hive.scan for live registry".to_owned(),
            ));
        }

        let regex_opt: Option<Regex> = if self.criteria.use_regex
            && let Some(ref q) = self.criteria.query_text
            && !q.is_empty()
        {
            Some(
                RegexBuilder::new(q)
                    .case_insensitive(!self.criteria.case_sensitive)
                    .build()
                    .map_err(|e| ForensicError::InvalidArgument(format!("invalid search regex '{q}': {e}")))?,
            )
        } else {
            None
        };

        let bytes = self.source.read_bytes()?;
        let hive = RegfHive::from_bytes(&bytes)?;
        let hive_label = self.source.label();

        let text_query = self.criteria.query_text.as_deref().filter(|s| !s.is_empty());
        let hex_needle = self.criteria.hex_bytes.as_deref().filter(|b| !b.is_empty());
        let utf16_needle: Option<Vec<u8>> =
            text_query.map(|q| q.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<u8>>());

        let mut rows = Vec::new();
        let mut next_id = 0u64;

        for key in hive.walk_keys() {
            if !time_in_window(
                key.last_write_time(),
                self.criteria.modified_after,
                self.criteria.modified_before,
            ) {
                continue;
            }

            let key_text_match =
                if self.criteria.search_keys && hex_needle.is_none() && self.criteria.value_types.is_empty() {
                    match (text_query, &regex_opt) {
                        (None, _) => false,
                        (Some(_), Some(rx)) => rx.is_match(key.path()) || rx.is_match(key.name()),
                        (Some(q), None) => {
                            contains_str(key.path(), q, self.criteria.case_sensitive)
                                || contains_str(key.name(), q, self.criteria.case_sensitive)
                        }
                    }
                } else {
                    false
                };

            if key_text_match {
                rows.push(
                    Row::new(
                        next_id,
                        vec![
                            CellValue::Text(hive_label.clone()),
                            CellValue::Text(key.path().to_owned()),
                            CellValue::Text(String::new()),
                            CellValue::Text("KEY".to_owned()),
                            CellValue::Text(key.path().to_owned()),
                            opt_timestamp_cell(key.last_write_time()),
                        ],
                    )
                    .with_detail_json(json!({
                        "match_target": "key",
                        "cell_offset": key.cell_offset(),
                    })),
                );
                next_id += 1;
            }

            for val in key.values() {
                if !self.criteria.value_types.is_empty() && !self.criteria.value_types.contains(&val.raw_type) {
                    continue;
                }
                if !value_matches(
                    val,
                    text_query,
                    &regex_opt,
                    hex_needle,
                    utf16_needle.as_deref(),
                    &self.criteria,
                ) {
                    continue;
                }

                let matched_data = if hex_needle.is_some() {
                    bytes_to_hex_lower(&val.raw_bytes)
                } else {
                    val.decoded_string()
                };

                rows.push(
                    Row::new(
                        next_id,
                        vec![
                            CellValue::Text(hive_label.clone()),
                            CellValue::Text(key.path().to_owned()),
                            CellValue::Text(val.display_name().to_owned()),
                            CellValue::Text(val.type_name().into_owned()),
                            CellValue::Text(matched_data),
                            opt_timestamp_cell(key.last_write_time()),
                        ],
                    )
                    .with_raw_bytes(val.raw_bytes.clone())
                    .with_detail_json(json!({
                        "match_target": "value",
                        "cell_offset": val.cell_offset,
                        "raw_type": val.raw_type,
                    })),
                );
                next_id += 1;
            }
        }

        Ok(rows)
    }
}

fn time_in_window(ts: Option<DateTime<Utc>>, after: Option<DateTime<Utc>>, before: Option<DateTime<Utc>>) -> bool {
    if let Some(a) = after {
        match ts {
            Some(t) if t >= a => {}
            _ => return false,
        }
    }
    if let Some(b) = before {
        match ts {
            Some(t) if t <= b => {}
            _ => return false,
        }
    }
    true
}

fn contains_str(hay: &str, needle: &str, case_sensitive: bool) -> bool {
    if case_sensitive {
        hay.contains(needle)
    } else {
        hay.to_lowercase().contains(&needle.to_lowercase())
    }
}

fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

fn raw_bytes_match_text(
    raw_bytes: &[u8],
    q: &str,
    regex_opt: &Option<Regex>,
    utf16_needle: Option<&[u8]>,
    case_sensitive: bool,
) -> bool {
    if case_sensitive && regex_opt.is_none() {
        if let Some(u16_bytes) = utf16_needle
            && contains_subslice(raw_bytes, u16_bytes)
        {
            return true;
        }
        return contains_subslice(raw_bytes, q.as_bytes());
    }

    if !case_sensitive
        && regex_opt.is_none()
        && q.is_ascii()
        && raw_bytes.windows(q.len()).any(|w| w.eq_ignore_ascii_case(q.as_bytes()))
    {
        return true;
    }

    let utf8_lossy = String::from_utf8_lossy(raw_bytes);
    let ascii_hit = match regex_opt {
        Some(rx) => rx.is_match(&utf8_lossy),
        None => contains_str(&utf8_lossy, q, case_sensitive),
    };
    if ascii_hit {
        return true;
    }

    for offset in [0usize, 1usize] {
        if raw_bytes.len() > offset + 1 {
            let decoded_u16 = read_utf16_le(&raw_bytes[offset..]);
            let u16_hit = match regex_opt {
                Some(rx) => rx.is_match(&decoded_u16),
                None => contains_str(&decoded_u16, q, case_sensitive),
            };
            if u16_hit {
                return true;
            }
        }
    }

    false
}

fn value_matches(
    val: &RegValue,
    text_query: Option<&str>,
    regex_opt: &Option<Regex>,
    hex_needle: Option<&[u8]>,
    utf16_needle: Option<&[u8]>,
    criteria: &FindCriteria,
) -> bool {
    if let Some(hex_bytes) = hex_needle
        && !contains_subslice(&val.raw_bytes, hex_bytes)
    {
        return false;
    }

    let Some(q) = text_query else {
        return true;
    };

    if criteria.search_value_names {
        let name_hit = match regex_opt {
            Some(rx) => rx.is_match(&val.name) || rx.is_match(val.display_name()),
            None => {
                contains_str(&val.name, q, criteria.case_sensitive)
                    || contains_str(val.display_name(), q, criteria.case_sensitive)
            }
        };
        if name_hit {
            return true;
        }
    }

    if criteria.search_value_data {
        let decoded = val.decoded_string();
        let data_hit = match regex_opt {
            Some(rx) => rx.is_match(&decoded),
            None => contains_str(&decoded, q, criteria.case_sensitive),
        };
        if data_hit {
            return true;
        }
        if raw_bytes_match_text(&val.raw_bytes, q, regex_opt, utf16_needle, criteria.case_sensitive) {
            return true;
        }
    }

    false
}

impl TableProvider for OfflineFinderProvider {
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
