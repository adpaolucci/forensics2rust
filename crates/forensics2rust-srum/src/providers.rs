use std::sync::Arc;

use forensics2rust_core::{ForensicSource, QueryHelper, find_tool};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};
use serde_json::{Map, Value as JsonValue};

use crate::ese::{EseDatabase, EseRow, EseTableSchema, EseValue, JetColType};
use crate::id_map::{SruDbIdMap, decode_srum_timestamp, format_interface_luid};

pub const SRUM_NET_TABLE_GUID: &str = "{973F5D5C-1D90-4944-BE8E-24B94231A174}";
pub const SRUM_APP_TABLE_GUID: &str = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}";
pub const SRUM_ENERGY_TABLE_GUID: &str = "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}";
pub const SRUM_CONNECTIVITY_TABLE_GUID: &str = "{DD6636C4-8929-4683-974E-22C046A43763}";

fn catalog_description(tool_id: &str, fallback: &'static str) -> &'static str {
    find_tool(tool_id).map_or(fallback, |d| d.description)
}

fn find_col_ci<'a>(row: &'a EseRow, candidates: &[&str]) -> Option<&'a EseValue> {
    for candidate in candidates {
        if let Some(v) = row.values.get(*candidate)
            && !matches!(v, EseValue::Null)
        {
            return Some(v);
        }
    }
    for candidate in candidates {
        if let Some((_, v)) = row
            .values
            .iter()
            .find(|(k, v)| k.eq_ignore_ascii_case(candidate) && !matches!(v, EseValue::Null))
        {
            return Some(v);
        }
    }
    None
}

fn sum_optional_u64(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (None, None) => None,
        (Some(x), None) | (None, Some(x)) => Some(x),
        (Some(x), Some(y)) => Some(x.saturating_add(y)),
    }
}

fn row_to_json(source_table: &str, row: &EseRow, extra: &[(&str, JsonValue)]) -> JsonValue {
    let mut map = Map::new();
    map.insert("source_table".to_string(), JsonValue::String(source_table.to_string()));
    for (k, v) in extra {
        map.insert((*k).to_string(), v.clone());
    }
    let mut cols = Map::new();
    for (k, v) in &row.values {
        cols.insert(k.clone(), v.to_json_value());
    }
    map.insert("columns".to_string(), JsonValue::Object(cols));
    JsonValue::Object(map)
}

fn sanitize_col_id(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_').to_string();
    if trimmed.is_empty() { "col".to_string() } else { trimmed }
}

fn map_jet_col_type(coltyp: JetColType) -> ColumnType {
    match coltyp {
        JetColType::Bit => ColumnType::Bool,
        JetColType::UnsignedByte | JetColType::UnsignedShort | JetColType::UnsignedLong => ColumnType::Uint,
        JetColType::Short | JetColType::Long | JetColType::Currency | JetColType::LongLong => ColumnType::Int,
        JetColType::Single | JetColType::Double => ColumnType::Float,
        JetColType::DateTime => ColumnType::Timestamp,
        JetColType::Binary | JetColType::LongBinary | JetColType::Slv | JetColType::Unknown(_) => ColumnType::Hex,
        JetColType::Nil | JetColType::Text | JetColType::LongText | JetColType::Guid => ColumnType::Text,
    }
}

fn default_srum_db_schema() -> TableSchema {
    TableSchema::new(
        "srum.db",
        "ESE Database Catalog & Table Browser",
        vec![
            ColumnDef::new("table_name", "TableName", ColumnType::Text).with_width_hint(220),
            ColumnDef::new("record_index", "RecordIndex", ColumnType::Uint).with_width_hint(90),
            ColumnDef::new("table_id", "TableId", ColumnType::Uint).with_width_hint(80),
            ColumnDef::new("fdp_page", "FdpPage", ColumnType::Uint).with_width_hint(80),
            ColumnDef::new("column_count", "ColumnCount", ColumnType::Uint).with_width_hint(90),
            ColumnDef::new("record_summary", "RecordSummary", ColumnType::Text).with_width_hint(380),
            ColumnDef::new("dynamic_columns", "DynamicColumns", ColumnType::Text).with_width_hint(420),
        ],
    )
}

fn dynamic_table_schema(ese_schema: &EseTableSchema) -> TableSchema {
    let mut cols = Vec::with_capacity(ese_schema.columns.len() + 2);
    cols.push(ColumnDef::new("table_name", "TableName", ColumnType::Text).with_width_hint(200));
    cols.push(ColumnDef::new("record_index", "RecordIndex", ColumnType::Uint).with_width_hint(90));
    for col in &ese_schema.columns {
        cols.push(
            ColumnDef::new(sanitize_col_id(&col.name), &col.name, map_jet_col_type(col.col_type)).with_width_hint(160),
        );
    }
    TableSchema::new("srum.db", format!("ESE Table — {}", ese_schema.name), cols)
}

/// `srum.db` — Pure-Rust ESE (`0x89ABCDEF`) `MSysObjects` catalog and generic table browser.
#[derive(Debug, Clone)]
pub struct SrumDbProvider {
    source: ForensicSource,
    target_table: Option<String>,
}

impl SrumDbProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self {
            source,
            target_table: None,
        }
    }

    pub fn for_table(source: ForensicSource, table_name: impl Into<String>) -> Self {
        Self {
            source,
            target_table: Some(table_name.into()),
        }
    }
}

impl TableProvider for SrumDbProvider {
    fn tool_id(&self) -> &'static str {
        "srum.db"
    }

    fn description(&self) -> &'static str {
        catalog_description(
            "srum.db",
            "Pure-Rust ESE (0x89ABCDEF) MSysObjects catalog and generic table browser",
        )
    }

    fn schema(&self) -> TableSchema {
        if let Some(ref table_name) = self.target_table
            && let Ok(db) = EseDatabase::from_source(&self.source)
            && let Some(ese_schema) = db.table_schema(table_name)
        {
            return dynamic_table_schema(ese_schema);
        }
        default_srum_db_schema()
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let db = EseDatabase::from_source(&self.source).map_err(|e| e.to_table_error())?;

        if let Some(ref target) = self.target_table {
            let table = db.read_table(target).map_err(|e| e.to_table_error())?;
            let schema = dynamic_table_schema(&table.schema);
            let mut rows = Vec::with_capacity(table.rows.len());
            for (idx, row) in table.rows.into_iter().enumerate() {
                let mut cells = Vec::with_capacity(table.schema.columns.len() + 2);
                cells.push(CellValue::Text(table.schema.name.clone()));
                cells.push(CellValue::Uint(idx as u64));
                for col in &table.schema.columns {
                    let cell = row
                        .values
                        .get(&col.name)
                        .map_or(CellValue::Null, EseValue::to_cell_value);
                    cells.push(cell);
                }
                let detail = row_to_json(
                    &table.schema.name,
                    &row,
                    &[
                        ("table_id", JsonValue::from(table.schema.objid_table)),
                        ("fdp_page", JsonValue::from(table.schema.pgno_fdp)),
                    ],
                );
                rows.push(
                    Row::new(idx as u64, cells)
                        .with_detail_json(detail)
                        .with_raw_bytes(row.raw_bytes),
                );
            }
            return QueryHelper::apply(&schema, &rows, req).map_err(TableError::from);
        }

        let schema = default_srum_db_schema();
        let mut rows = Vec::new();
        let mut row_id = 0u64;

        for table_name in db.table_names() {
            let table = match db.read_table(&table_name) {
                Ok(t) => t,
                Err(err) => {
                    tracing::warn!("skipping ESE table '{table_name}': {err}");
                    continue;
                }
            };

            let col_count = table.schema.columns.len() as u64;
            for (rec_idx, row) in table.rows.into_iter().enumerate() {
                let summary = table
                    .schema
                    .columns
                    .iter()
                    .filter_map(|c| {
                        let val = row.values.get(&c.name)?;
                        if matches!(val, EseValue::Null) {
                            None
                        } else {
                            Some(format!("{}={}", c.name, val.display_compact()))
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("; ");

                let mut cols_json = Map::new();
                for (k, v) in &row.values {
                    cols_json.insert(k.clone(), v.to_json_value());
                }
                let dynamic_str = serde_json::to_string(&cols_json).unwrap_or_else(|_| "{}".to_string());
                let detail = row_to_json(
                    &table.schema.name,
                    &row,
                    &[
                        ("table_id", JsonValue::from(table.schema.objid_table)),
                        ("fdp_page", JsonValue::from(table.schema.pgno_fdp)),
                        ("record_index", JsonValue::from(rec_idx as u64)),
                    ],
                );

                rows.push(
                    Row::new(
                        row_id,
                        vec![
                            CellValue::Text(table.schema.name.clone()),
                            CellValue::Uint(rec_idx as u64),
                            CellValue::Uint(u64::from(table.schema.objid_table)),
                            CellValue::Uint(u64::from(table.schema.pgno_fdp)),
                            CellValue::Uint(col_count),
                            CellValue::Text(summary),
                            CellValue::Text(dynamic_str),
                        ],
                    )
                    .with_detail_json(detail)
                    .with_raw_bytes(row.raw_bytes),
                );
                row_id += 1;
            }
        }

        QueryHelper::apply(&schema, &rows, req).map_err(TableError::from)
    }
}

/// `srum.net` — SRUM `{973F5D5C-...}` + `SruDbIdMapTable` network usage view.
#[derive(Debug, Clone)]
pub struct SrumNetProvider {
    source: ForensicSource,
}

impl SrumNetProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }
}

impl TableProvider for SrumNetProvider {
    fn tool_id(&self) -> &'static str {
        "srum.net"
    }

    fn description(&self) -> &'static str {
        catalog_description(
            "srum.net",
            "SRUM {973F5D5C-...} and SruDbIdMapTable per-app/user network usage view",
        )
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            "srum.net",
            "SRUM Network Data Usage Monitor",
            vec![
                ColumnDef::new("timestamp", "Timestamp", ColumnType::Timestamp).with_width_hint(180),
                ColumnDef::new("app_id", "AppId", ColumnType::Text).with_width_hint(280),
                ColumnDef::new("user_sid", "UserSid", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("interface_luid", "InterfaceLuid", ColumnType::Text).with_width_hint(190),
                ColumnDef::new("profile_name", "ProfileName", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("bytes_sent", "BytesSent", ColumnType::BytesSize).with_width_hint(120),
                ColumnDef::new("bytes_recvd", "BytesRecvd", ColumnType::BytesSize).with_width_hint(120),
                ColumnDef::new("connect_start_time", "ConnectStartTime", ColumnType::Timestamp).with_width_hint(180),
            ],
        )
        .with_default_sort(0, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let db = EseDatabase::from_source(&self.source).map_err(|e| e.to_table_error())?;
        let schema = self.schema();
        let id_map = SruDbIdMap::from_ese(&db);

        let Some(table_name) = db
            .table_names()
            .into_iter()
            .find(|n| n.eq_ignore_ascii_case(SRUM_NET_TABLE_GUID))
        else {
            tracing::warn!("SRUM network usage table {SRUM_NET_TABLE_GUID} not present in ESE database");
            return QueryHelper::apply(&schema, &[], req).map_err(TableError::from);
        };

        let table = db.read_table(&table_name).map_err(|e| e.to_table_error())?;
        let mut rows = Vec::with_capacity(table.rows.len());

        for (idx, row) in table.rows.into_iter().enumerate() {
            let ts = decode_srum_timestamp(find_col_ci(&row, &["TimeStamp", "Timestamp", "EventTimestamp"]))
                .map_or(CellValue::Null, CellValue::Timestamp);

            let raw_app = find_col_ci(&row, &["AppId", "App"]);
            let app_cell = id_map.resolve_app(raw_app).map_or(CellValue::Null, CellValue::Text);

            let raw_user = find_col_ci(&row, &["UserId", "UserSid", "Sid"]);
            let user_cell = id_map.resolve_user(raw_user).map_or(CellValue::Null, CellValue::Text);

            let luid_cell = format_interface_luid(find_col_ci(&row, &["InterfaceLuid", "Luid", "Interface"]));

            let profile_cell = if let Some(EseValue::Text(s)) = find_col_ci(&row, &["ProfileName"]) {
                if s.is_empty() {
                    CellValue::Null
                } else {
                    CellValue::Text(s.clone())
                }
            } else if let Some(l2) = find_col_ci(&row, &["L2ProfileId"]).and_then(EseValue::as_i64) {
                if let Some(entry) = id_map.get(l2) {
                    CellValue::Text(entry.resolved.clone())
                } else if l2 != 0 {
                    CellValue::Text(format!("Profile #{l2}"))
                } else {
                    CellValue::Null
                }
            } else {
                CellValue::Null
            };

            let bytes_sent = find_col_ci(&row, &["BytesSent", "BytesOut", "SentBytes"])
                .and_then(EseValue::as_u64)
                .map_or(CellValue::Null, CellValue::Bytes);

            let bytes_recvd = find_col_ci(&row, &["BytesRecvd", "BytesReceived", "BytesIn", "RecvdBytes"])
                .and_then(EseValue::as_u64)
                .map_or(CellValue::Null, CellValue::Bytes);

            let connect_start = decode_srum_timestamp(find_col_ci(&row, &["ConnectStartTime", "StartTime"]))
                .map_or(CellValue::Null, CellValue::Timestamp);

            let detail = row_to_json(
                &table.schema.name,
                &row,
                &[
                    ("raw_app_id", raw_app.map_or(JsonValue::Null, EseValue::to_json_value)),
                    ("raw_user_id", raw_user.map_or(JsonValue::Null, EseValue::to_json_value)),
                ],
            );

            rows.push(
                Row::new(
                    idx as u64,
                    vec![
                        ts,
                        app_cell,
                        user_cell,
                        luid_cell,
                        profile_cell,
                        bytes_sent,
                        bytes_recvd,
                        connect_start,
                    ],
                )
                .with_detail_json(detail)
                .with_raw_bytes(row.raw_bytes),
            );
        }

        QueryHelper::apply(&schema, &rows, req).map_err(TableError::from)
    }
}

/// `srum.app` — SRUM `{D10CA2FE-...}` Application Resource Usage view.
#[derive(Debug, Clone)]
pub struct SrumAppProvider {
    source: ForensicSource,
}

impl SrumAppProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }
}

impl TableProvider for SrumAppProvider {
    fn tool_id(&self) -> &'static str {
        "srum.app"
    }

    fn description(&self) -> &'static str {
        catalog_description(
            "srum.app",
            "SRUM {D10CA2FE-...} Application Resource Usage (CPU cycles, I/O, context switches) view",
        )
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            "srum.app",
            "SRUM Application Resource Usage View",
            vec![
                ColumnDef::new("timestamp", "Timestamp", ColumnType::Timestamp).with_width_hint(180),
                ColumnDef::new("app_id", "AppId", ColumnType::Text).with_width_hint(280),
                ColumnDef::new("user_sid", "UserSid", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("cycle_time", "CycleTime", ColumnType::Uint).with_width_hint(130),
                ColumnDef::new("face_time", "FaceTime", ColumnType::Duration).with_width_hint(120),
                ColumnDef::new("foreground_bytes_read", "ForegroundBytesRead", ColumnType::BytesSize)
                    .with_width_hint(140),
                ColumnDef::new("background_bytes_read", "BackgroundBytesRead", ColumnType::BytesSize)
                    .with_width_hint(140),
                ColumnDef::new("bytes_written", "BytesWritten", ColumnType::BytesSize).with_width_hint(130),
                ColumnDef::new("context_switches", "ContextSwitches", ColumnType::Uint).with_width_hint(120),
            ],
        )
        .with_default_sort(0, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let db = EseDatabase::from_source(&self.source).map_err(|e| e.to_table_error())?;
        let schema = self.schema();
        let id_map = SruDbIdMap::from_ese(&db);

        let Some(table_name) = db
            .table_names()
            .into_iter()
            .find(|n| n.eq_ignore_ascii_case(SRUM_APP_TABLE_GUID))
        else {
            tracing::warn!("SRUM app usage table {SRUM_APP_TABLE_GUID} not present in ESE database");
            return QueryHelper::apply(&schema, &[], req).map_err(TableError::from);
        };

        let table = db.read_table(&table_name).map_err(|e| e.to_table_error())?;
        let mut rows = Vec::with_capacity(table.rows.len());

        for (idx, row) in table.rows.into_iter().enumerate() {
            let ts = decode_srum_timestamp(find_col_ci(&row, &["TimeStamp", "Timestamp"]))
                .map_or(CellValue::Null, CellValue::Timestamp);

            let raw_app = find_col_ci(&row, &["AppId", "App"]);
            let app_cell = id_map.resolve_app(raw_app).map_or(CellValue::Null, CellValue::Text);

            let raw_user = find_col_ci(&row, &["UserId", "UserSid", "Sid"]);
            let user_cell = id_map.resolve_user(raw_user).map_or(CellValue::Null, CellValue::Text);

            let cycle_time = find_col_ci(&row, &["CycleTime"])
                .and_then(EseValue::as_u64)
                .or_else(|| {
                    sum_optional_u64(
                        find_col_ci(&row, &["ForegroundCycleTime"]).and_then(EseValue::as_u64),
                        find_col_ci(&row, &["BackgroundCycleTime"]).and_then(EseValue::as_u64),
                    )
                })
                .map_or(CellValue::Null, CellValue::Uint);

            let face_time = find_col_ci(&row, &["FaceTime", "ForegroundFaceTime"])
                .and_then(EseValue::as_u64)
                .map_or(CellValue::Null, CellValue::Uint);

            let fg_bytes_read = find_col_ci(&row, &["ForegroundBytesRead", "FgBytesRead"])
                .and_then(EseValue::as_u64)
                .map_or(CellValue::Null, CellValue::Bytes);

            let bg_bytes_read = find_col_ci(&row, &["BackgroundBytesRead", "BgBytesRead"])
                .and_then(EseValue::as_u64)
                .map_or(CellValue::Null, CellValue::Bytes);

            let bytes_written = find_col_ci(&row, &["BytesWritten"])
                .and_then(EseValue::as_u64)
                .or_else(|| {
                    sum_optional_u64(
                        find_col_ci(&row, &["ForegroundBytesWritten"]).and_then(EseValue::as_u64),
                        find_col_ci(&row, &["BackgroundBytesWritten"]).and_then(EseValue::as_u64),
                    )
                })
                .map_or(CellValue::Null, CellValue::Bytes);

            let context_switches = find_col_ci(&row, &["ContextSwitches"])
                .and_then(EseValue::as_u64)
                .or_else(|| {
                    sum_optional_u64(
                        find_col_ci(&row, &["ForegroundContextSwitches"]).and_then(EseValue::as_u64),
                        find_col_ci(&row, &["BackgroundContextSwitches"]).and_then(EseValue::as_u64),
                    )
                })
                .map_or(CellValue::Null, CellValue::Uint);

            let detail = row_to_json(
                &table.schema.name,
                &row,
                &[
                    ("raw_app_id", raw_app.map_or(JsonValue::Null, EseValue::to_json_value)),
                    ("raw_user_id", raw_user.map_or(JsonValue::Null, EseValue::to_json_value)),
                ],
            );

            rows.push(
                Row::new(
                    idx as u64,
                    vec![
                        ts,
                        app_cell,
                        user_cell,
                        cycle_time,
                        face_time,
                        fg_bytes_read,
                        bg_bytes_read,
                        bytes_written,
                        context_switches,
                    ],
                )
                .with_detail_json(detail)
                .with_raw_bytes(row.raw_bytes),
            );
        }

        QueryHelper::apply(&schema, &rows, req).map_err(TableError::from)
    }
}

/// `srum.energy` — SRUM `{FEE4E14F-...}` Energy and `{DD6636C4-...}` Network Connectivity view.
#[derive(Debug, Clone)]
pub struct SrumEnergyProvider {
    source: ForensicSource,
}

impl SrumEnergyProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }
}

impl TableProvider for SrumEnergyProvider {
    fn tool_id(&self) -> &'static str {
        "srum.energy"
    }

    fn description(&self) -> &'static str {
        catalog_description(
            "srum.energy",
            "SRUM {FEE4E14F-...} Energy and {DD6636C4-...} Network Connectivity view",
        )
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            "srum.energy",
            "SRUM Energy & Network Connectivity View",
            vec![
                ColumnDef::new("timestamp", "Timestamp", ColumnType::Timestamp).with_width_hint(180),
                ColumnDef::new("app_id", "AppId", ColumnType::Text).with_width_hint(280),
                ColumnDef::new("user_sid", "UserSid", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("energy_loss", "EnergyLoss", ColumnType::Uint).with_width_hint(120),
                ColumnDef::new("cpu_energy", "CPUEnergy", ColumnType::Uint).with_width_hint(120),
                ColumnDef::new("network_energy", "NetworkEnergy", ColumnType::Uint).with_width_hint(120),
                ColumnDef::new("display_energy", "DisplayEnergy", ColumnType::Uint).with_width_hint(120),
                ColumnDef::new("connected_time", "ConnectedTime", ColumnType::Duration).with_width_hint(120),
            ],
        )
        .with_default_sort(0, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let db = EseDatabase::from_source(&self.source).map_err(|e| e.to_table_error())?;
        let schema = self.schema();
        let id_map = SruDbIdMap::from_ese(&db);
        let table_names = db.table_names();

        let mut rows = Vec::new();
        let mut row_id = 0u64;

        for guid in [SRUM_ENERGY_TABLE_GUID, SRUM_CONNECTIVITY_TABLE_GUID] {
            let Some(found_name) = table_names.iter().find(|n| n.eq_ignore_ascii_case(guid)) else {
                tracing::warn!("SRUM energy/connectivity table {guid} not present in ESE database");
                continue;
            };

            let table = db.read_table(found_name).map_err(|e| e.to_table_error())?;
            for row in table.rows {
                let ts = decode_srum_timestamp(find_col_ci(
                    &row,
                    &["TimeStamp", "Timestamp", "EventTimestamp", "ConnectStartTime"],
                ))
                .map_or(CellValue::Null, CellValue::Timestamp);

                let raw_app = find_col_ci(&row, &["AppId", "App"]);
                let app_cell = id_map.resolve_app(raw_app).map_or(CellValue::Null, CellValue::Text);

                let raw_user = find_col_ci(&row, &["UserId", "UserSid", "Sid"]);
                let user_cell = id_map.resolve_user(raw_user).map_or(CellValue::Null, CellValue::Text);

                let energy_loss = find_col_ci(
                    &row,
                    &[
                        "EnergyLoss",
                        "TotalEnergyConsumption",
                        "TotalEnergy",
                        "EnergyConsumption",
                        "Loss",
                    ],
                )
                .and_then(EseValue::as_u64)
                .map_or(CellValue::Null, CellValue::Uint);

                let cpu_energy = find_col_ci(&row, &["CPUEnergy", "CPUEnergyConsumption", "CpuEnergy"])
                    .and_then(EseValue::as_u64)
                    .or_else(|| {
                        sum_optional_u64(
                            find_col_ci(&row, &["ForegroundCpuEnergy"]).and_then(EseValue::as_u64),
                            find_col_ci(&row, &["BackgroundCpuEnergy"]).and_then(EseValue::as_u64),
                        )
                    })
                    .map_or(CellValue::Null, CellValue::Uint);

                let network_energy = find_col_ci(
                    &row,
                    &[
                        "NetworkEnergy",
                        "NetworkEnergyConsumption",
                        "NetworkTailEnergyConsumption",
                        "MBBEnergyConsumption",
                    ],
                )
                .and_then(EseValue::as_u64)
                .map_or(CellValue::Null, CellValue::Uint);

                let display_energy = find_col_ci(
                    &row,
                    &["DisplayEnergy", "DisplayEnergyConsumption", "DisplayRequiredTime"],
                )
                .and_then(EseValue::as_u64)
                .map_or(CellValue::Null, CellValue::Uint);

                let connected_time = find_col_ci(&row, &["ConnectedTime", "ConnectDuration"])
                    .and_then(EseValue::as_u64)
                    .map_or(CellValue::Null, CellValue::Uint);

                let detail = row_to_json(
                    &table.schema.name,
                    &row,
                    &[
                        ("raw_app_id", raw_app.map_or(JsonValue::Null, EseValue::to_json_value)),
                        ("raw_user_id", raw_user.map_or(JsonValue::Null, EseValue::to_json_value)),
                    ],
                );

                rows.push(
                    Row::new(
                        row_id,
                        vec![
                            ts,
                            app_cell,
                            user_cell,
                            energy_loss,
                            cpu_energy,
                            network_energy,
                            display_energy,
                            connected_time,
                        ],
                    )
                    .with_detail_json(detail)
                    .with_raw_bytes(row.raw_bytes),
                );
                row_id += 1;
            }
        }

        QueryHelper::apply(&schema, &rows, req).map_err(TableError::from)
    }
}

/// Returns all 4 read-only SRUM `TableProvider` tools bound to the supplied `ForensicSource`.
pub fn all_providers(source: &ForensicSource) -> Vec<Arc<dyn TableProvider>> {
    vec![
        Arc::new(SrumDbProvider::new(source.clone())),
        Arc::new(SrumNetProvider::new(source.clone())),
        Arc::new(SrumAppProvider::new(source.clone())),
        Arc::new(SrumEnergyProvider::new(source.clone())),
    ]
}
