#![forbid(unsafe_code)]

//! Strictly read-only JSON-RPC 2.0 stdio MCP server exposing all 45 `forensics2rust`
//! Windows DFIR `TableProvider`s via `guap-mcp`.

#[cfg(test)]
mod test_fixtures;

use std::fs;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use forensics2rust_core::{FORENSIC_TOOL_CATALOG, ForensicError, ForensicSource, ToolCategory, find_tool};
use forensics2rust_hive::RegistryChangesProvider;
use forensics2rust_srum::SrumDbProvider;
use guap_mcp::{ActionCommand, ActionRiskLevel, MCP_PROTOCOL_VERSION, McpServerRegistry, McpToolError, PolicyMode};
use guap_table::{FilterExpr, GetNirQuery, SortDirection, TableData, TableProvider, TableQuery, TableSchema};
use serde_json::{Map, Value, json};

pub const SERVER_NAME: &str = "forensics2rust-mcp";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the crate metadata descriptor tuple `(crate_name, version)`.
pub fn crate_info() -> (&'static str, &'static str) {
    (env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

/// Default MCP policy mode for `forensics2rust` (strictly read-only).
pub fn default_policy_mode() -> PolicyMode {
    PolicyMode::ReadOnlyOnly
}

/// Returns total number of read-only DFIR tools exposed by the catalog.
pub fn catalog_tool_count() -> usize {
    FORENSIC_TOOL_CATALOG.iter().filter(|t| t.read_only).count()
}

/// Resolves a domain-appropriate [`ForensicSource`] for `tool_id` when the caller supplies
/// a directory on `ForensicSource::OfflinePath`.
///
/// `-evtx`, `-crash`, `-artifacts`, and `-posture` natively accept directory paths.
/// `-hive` and `-srum` expect file paths; when given a directory in a suite-wide sweep,
/// this helper looks up canonical artifact files inside that directory without ever
/// fabricating missing data.
pub fn resolve_tool_source(tool_id: &str, source: &ForensicSource) -> Result<ForensicSource, ForensicError> {
    let Some(desc) = find_tool(tool_id) else {
        return Err(ForensicError::NotFound(format!("unknown tool '{tool_id}'")));
    };

    let ForensicSource::OfflinePath(path) = source else {
        return Ok(source.clone());
    };

    if !path.is_dir() {
        return Ok(source.clone());
    }

    match desc.category {
        ToolCategory::Evtx | ToolCategory::Crash | ToolCategory::Artifacts | ToolCategory::Posture => {
            Ok(source.clone())
        }
        ToolCategory::Hive => {
            if let Some(found) = resolve_hive_file_in_dir(tool_id, path) {
                Ok(ForensicSource::OfflinePath(found))
            } else {
                Err(ForensicError::NotFound(format!(
                    "offline directory '{}' contains no matching registry artifact for '{tool_id}'",
                    path.display()
                )))
            }
        }
        ToolCategory::Srum => {
            if let Some(found) = resolve_srum_file_in_dir(path) {
                Ok(ForensicSource::OfflinePath(found))
            } else {
                Err(ForensicError::NotFound(format!(
                    "offline directory '{}' contains no ESE SRUDB.dat/DataStore.edb file for '{tool_id}'",
                    path.display()
                )))
            }
        }
    }
}

fn resolve_hive_file_in_dir(tool_id: &str, dir: &Path) -> Option<PathBuf> {
    if tool_id == "hive.watch" {
        for candidate in [
            "watch.f2retw01",
            "watch.reg",
            "regwatch.reg",
            "watch.json",
            "regwatch.json",
        ] {
            let p = dir.join(candidate);
            if p.is_file() {
                return Some(p);
            }
        }
        return find_first_with_ext(dir, &["f2retw01", "reg"]);
    }

    if tool_id == "hive.diff" {
        for candidate in ["diff_pair.json", "hive_diff.json", "snapshot.json"] {
            let p = dir.join(candidate);
            if p.is_file() {
                return Some(p);
            }
        }
    }

    for candidate in [
        "NTUSER.DAT",
        "SOFTWARE",
        "SYSTEM",
        "UsrClass.dat",
        "SAM",
        "SECURITY",
        "DEFAULT",
        "Amcache.hve",
        "Windows/System32/config/SOFTWARE",
        "Windows/System32/config/SYSTEM",
        "Windows/System32/config/SAM",
        "Windows/System32/config/SECURITY",
        "Windows/System32/config/DEFAULT",
    ] {
        let p = dir.join(candidate);
        if p.is_file() {
            return Some(p);
        }
    }

    if let Some(user_ntuser) = find_user_ntuser(dir) {
        return Some(user_ntuser);
    }

    find_first_with_ext(dir, &["regf", "hiv", "hve"])
}

fn find_user_ntuser(dir: &Path) -> Option<PathBuf> {
    let users_dir = dir.join("Users");
    let Ok(entries) = fs::read_dir(users_dir) else {
        return None;
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    paths.sort();
    for entry in paths {
        let candidate = entry.join("NTUSER.DAT");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn resolve_srum_file_in_dir(dir: &Path) -> Option<PathBuf> {
    for candidate in [
        "SRUDB.dat",
        "srudb.dat",
        "Windows/System32/sru/SRUDB.dat",
        "DataStore.edb",
        "Windows/SoftwareDistribution/DataStore/DataStore.edb",
    ] {
        let p = dir.join(candidate);
        if p.is_file() {
            return Some(p);
        }
    }
    find_first_with_ext(dir, &["edb"])
}

fn find_first_with_ext(dir: &Path, exts: &[&str]) -> Option<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return None;
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    for path in files {
        if let Some(ext) = path.extension().and_then(|s| s.to_str())
            && exts.iter().any(|e| ext.eq_ignore_ascii_case(e))
        {
            return Some(path);
        }
    }
    None
}

/// Collects all 45 read-only [`TableProvider`] implementations across all 6 domain crates
/// in canonical `FORENSIC_TOOL_CATALOG` order.
pub fn collect_all_providers(source: &ForensicSource) -> Vec<Arc<dyn TableProvider>> {
    let hive_source = resolve_tool_source("hive.offline", source).unwrap_or_else(|_| source.clone());
    let hive_watch_source = resolve_tool_source("hive.watch", source).unwrap_or_else(|_| source.clone());
    let hive_diff_source = resolve_tool_source("hive.diff", source).unwrap_or_else(|_| source.clone());
    let srum_source = resolve_tool_source("srum.net", source).unwrap_or_else(|_| source.clone());

    let mut providers = Vec::with_capacity(FORENSIC_TOOL_CATALOG.len());
    providers.extend(forensics2rust_evtx::all_providers(source));

    for provider in forensics2rust_hive::all_providers(&hive_source) {
        match provider.tool_id() {
            "hive.watch" if hive_watch_source != hive_source => {
                if let Some(p) = forensics2rust_hive::all_providers(&hive_watch_source)
                    .into_iter()
                    .find(|p| p.tool_id() == "hive.watch")
                {
                    providers.push(p);
                } else {
                    providers.push(provider);
                }
            }
            "hive.diff" if hive_diff_source != hive_source => {
                if let Some(p) = forensics2rust_hive::all_providers(&hive_diff_source)
                    .into_iter()
                    .find(|p| p.tool_id() == "hive.diff")
                {
                    providers.push(p);
                } else {
                    providers.push(provider);
                }
            }
            _ => providers.push(provider),
        }
    }

    providers.extend(forensics2rust_srum::all_providers(&srum_source));
    providers.extend(forensics2rust_artifacts::all_providers(source));
    providers.extend(forensics2rust_crash::all_providers(source));
    providers.extend(forensics2rust_posture::all_providers(source));
    providers
}

/// Looks up a single read-only [`TableProvider`] by canonical `tool_id` bound to `source`.
pub fn provider_for_tool(tool_id: &str, source: &ForensicSource) -> Option<Arc<dyn TableProvider>> {
    let desc = find_tool(tool_id)?;
    let effective = resolve_tool_source(tool_id, source).unwrap_or_else(|_| source.clone());
    let list = match desc.category {
        ToolCategory::Evtx => forensics2rust_evtx::all_providers(&effective),
        ToolCategory::Hive => forensics2rust_hive::all_providers(&effective),
        ToolCategory::Srum => forensics2rust_srum::all_providers(&effective),
        ToolCategory::Artifacts => forensics2rust_artifacts::all_providers(&effective),
        ToolCategory::Crash => forensics2rust_crash::all_providers(&effective),
        ToolCategory::Posture => forensics2rust_posture::all_providers(&effective),
    };
    list.into_iter().find(|p| p.tool_id() == tool_id)
}

/// Strictly read-only `guap_mcp::ActionCommand` wrapper around any of the 45 DFIR
/// `TableProvider`s, enabling per-call `source_path`/`offline_path` overrides as well
/// as `filter`/`getnir`/`sort`/`columns`/`offset`/`limit` without modifying domain crates.
struct ForensicTableAction {
    tool_id: &'static str,
    description: &'static str,
    schema: TableSchema,
    default_source: ForensicSource,
}

impl ActionCommand for ForensicTableAction {
    fn command_id(&self) -> &'static str {
        self.tool_id
    }

    fn description(&self) -> &'static str {
        self.description
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::ReadOnly
    }

    fn input_schema(&self) -> Value {
        let col_ids: Vec<Value> = self
            .schema
            .columns
            .iter()
            .map(|c| Value::String(c.id.clone()))
            .collect();

        let mut props = Map::new();
        props.insert(
            "source_path".to_string(),
            json!({
                "type": "string",
                "description": "Optional offline artifact file or directory path overriding the server default source"
            }),
        );
        props.insert(
            "offline_path".to_string(),
            json!({
                "type": "string",
                "description": "Alias for source_path: offline artifact file or directory path"
            }),
        );
        props.insert(
            "filter".to_string(),
            json!({
                "description": "Filter expression string (GetNir syntax) or structured FilterExpr object"
            }),
        );
        props.insert(
            "getnir".to_string(),
            json!({
                "type": "string",
                "description": "Alias for GetNir filter expression string"
            }),
        );
        props.insert(
            "sort".to_string(),
            json!({
                "description": "Sort clauses as [{ column, direction }] array or GetNir sort spec (e.g. 'col:desc,-other')",
                "items": {
                    "type": "object",
                    "properties": {
                        "column": { "type": "string", "enum": col_ids },
                        "direction": { "type": "string", "enum": ["asc", "desc"] }
                    },
                    "required": ["column"]
                }
            }),
        );
        props.insert(
            "columns".to_string(),
            json!({
                "type": "array",
                "description": "Optional projected column IDs",
                "items": { "type": "string", "enum": col_ids }
            }),
        );
        props.insert(
            "offset".to_string(),
            json!({ "type": "integer", "minimum": 0, "default": 0 }),
        );
        props.insert("limit".to_string(), json!({ "type": "integer", "minimum": 1 }));

        if self.tool_id == "srum.db" {
            props.insert(
                "table_name".to_string(),
                json!({
                    "type": "string",
                    "description": "Optional ESE table name inside the database to inspect dynamically"
                }),
            );
        }

        if self.tool_id == "hive.diff" {
            props.insert(
                "baseline_path".to_string(),
                json!({
                    "type": "string",
                    "description": "Optional baseline/left hive or snapshot path for registry comparison"
                }),
            );
            props.insert(
                "right_path".to_string(),
                json!({
                    "type": "string",
                    "description": "Optional target/right hive or snapshot path for registry comparison"
                }),
            );
        }

        json!({
            "type": "object",
            "properties": Value::Object(props),
            "additionalProperties": false
        })
    }

    fn execute(&self, args: &Value, _dry_run: bool) -> Result<Value, McpToolError> {
        let obj = match args {
            Value::Null => None,
            Value::Object(map) => Some(map),
            _ => return Err(McpToolError::InvalidParams("arguments must be a JSON object".into())),
        };

        if let Some(map) = obj {
            for key in map.keys() {
                let allowed = matches!(
                    key.as_str(),
                    "source_path"
                        | "offline_path"
                        | "filter"
                        | "getnir"
                        | "sort"
                        | "columns"
                        | "offset"
                        | "limit"
                        | "dry_run"
                ) || (self.tool_id == "srum.db" && key == "table_name")
                    || (self.tool_id == "hive.diff" && matches!(key.as_str(), "baseline_path" | "right_path"));
                if !allowed {
                    return Err(McpToolError::InvalidParams(format!(
                        "unknown argument '{key}' for tool '{}'",
                        self.tool_id
                    )));
                }
            }
        }

        let source_path = extract_optional_nonempty_str(obj, "source_path")?;
        let offline_path = extract_optional_nonempty_str(obj, "offline_path")?;

        let override_path = match (source_path, offline_path) {
            (Some(a), Some(b)) if a != b => {
                return Err(McpToolError::InvalidParams(
                    "conflicting 'source_path' and 'offline_path' arguments".into(),
                ));
            }
            (Some(a), _) => Some(PathBuf::from(a)),
            (None, Some(b)) => Some(PathBuf::from(b)),
            (None, None) => None,
        };

        let base_source = match override_path {
            Some(p) => ForensicSource::OfflinePath(p),
            None => self.default_source.clone(),
        };

        let effective_source = resolve_tool_source(self.tool_id, &base_source)
            .map_err(|e| McpToolError::ExecutionFailed(e.to_string()))?;

        let provider: Arc<dyn TableProvider> = if self.tool_id == "srum.db" {
            if let Some(table_name) = extract_optional_nonempty_str(obj, "table_name")? {
                Arc::new(SrumDbProvider::for_table(effective_source, table_name))
            } else {
                provider_for_tool(self.tool_id, &effective_source)
                    .ok_or_else(|| McpToolError::NotFound(self.tool_id.to_string()))?
            }
        } else if self.tool_id == "hive.diff" {
            let baseline = extract_optional_nonempty_str(obj, "baseline_path")?;
            let right = extract_optional_nonempty_str(obj, "right_path")?;
            match (baseline, right) {
                (Some(left_p), Some(right_p)) => Arc::new(RegistryChangesProvider::between(
                    ForensicSource::OfflinePath(PathBuf::from(left_p)),
                    ForensicSource::OfflinePath(PathBuf::from(right_p)),
                )),
                (Some(left_p), None) => Arc::new(RegistryChangesProvider::between(
                    ForensicSource::OfflinePath(PathBuf::from(left_p)),
                    effective_source,
                )),
                (None, Some(right_p)) => Arc::new(RegistryChangesProvider::between(
                    effective_source,
                    ForensicSource::OfflinePath(PathBuf::from(right_p)),
                )),
                (None, None) => provider_for_tool(self.tool_id, &effective_source)
                    .ok_or_else(|| McpToolError::NotFound(self.tool_id.to_string()))?,
            }
        } else {
            provider_for_tool(self.tool_id, &effective_source)
                .ok_or_else(|| McpToolError::NotFound(self.tool_id.to_string()))?
        };

        let active_schema = provider.schema();
        let query = parse_mcp_table_query(&active_schema, args)?;
        let data = provider.query(&query)?;
        Ok(serialize_table_data(&data))
    }
}

fn extract_optional_nonempty_str(obj: Option<&Map<String, Value>>, key: &str) -> Result<Option<String>, McpToolError> {
    let Some(map) = obj else {
        return Ok(None);
    };
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
        Some(_) => Err(McpToolError::InvalidParams(format!("'{key}' must be a string"))),
    }
}

fn parse_mcp_table_query(schema: &TableSchema, args: &Value) -> Result<TableQuery, McpToolError> {
    let obj = match args {
        Value::Null => return Ok(TableQuery::default()),
        Value::Object(m) => m,
        _ => return Err(McpToolError::InvalidParams("arguments must be a JSON object".into())),
    };

    let raw_filter = obj.get("filter");
    let raw_getnir = obj.get("getnir");

    let filter = match (raw_filter, raw_getnir) {
        (Some(Value::String(f)), Some(Value::String(g)))
            if !f.trim().is_empty() && !g.trim().is_empty() && f.trim() != g.trim() =>
        {
            return Err(McpToolError::InvalidParams(
                "conflicting 'filter' and 'getnir' expressions".into(),
            ));
        }
        (Some(f), _) if !f.is_null() => parse_filter_value(f)?,
        (_, Some(g)) if !g.is_null() => parse_filter_value(g)?,
        _ => None,
    };

    let sort = match obj.get("sort") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(spec)) => {
            if spec.trim().is_empty() {
                Vec::new()
            } else {
                let parsed = GetNirQuery::parse_sort(spec)?;
                let mut resolved = Vec::with_capacity(parsed.len());
                for (col, dir) in parsed {
                    let idx = schema
                        .column_index(&col)
                        .ok_or_else(|| McpToolError::InvalidParams(format!("invalid sort column '{col}'")))?;
                    resolved.push((idx, dir));
                }
                resolved
            }
        }
        Some(Value::Array(items)) => {
            let mut resolved = Vec::with_capacity(items.len());
            for item in items {
                let item_obj = item
                    .as_object()
                    .ok_or_else(|| McpToolError::InvalidParams("sort entries must be objects".into()))?;
                let col = item_obj
                    .get("column")
                    .and_then(Value::as_str)
                    .ok_or_else(|| McpToolError::InvalidParams("sort entry missing string 'column'".into()))?;
                let idx = schema
                    .column_index(col)
                    .ok_or_else(|| McpToolError::InvalidParams(format!("invalid sort column '{col}'")))?;
                let dir = match item_obj.get("direction").and_then(Value::as_str) {
                    None | Some("asc") | Some("ASC") => SortDirection::Asc,
                    Some("desc") | Some("DESC") => SortDirection::Desc,
                    Some(other) => {
                        return Err(McpToolError::InvalidParams(format!("invalid sort direction '{other}'")));
                    }
                };
                resolved.push((idx, dir));
            }
            resolved
        }
        Some(_) => return Err(McpToolError::InvalidParams("'sort' must be an array or string".into())),
    };

    let columns = match obj.get("columns") {
        None | Some(Value::Null) => None,
        Some(Value::Array(arr)) => {
            let mut cols = Vec::with_capacity(arr.len());
            for item in arr {
                let c = item
                    .as_str()
                    .ok_or_else(|| McpToolError::InvalidParams("'columns' items must be strings".into()))?;
                if schema.column_index(c).is_none() {
                    return Err(McpToolError::InvalidParams(format!("invalid column '{c}'")));
                }
                cols.push(c.to_string());
            }
            Some(cols)
        }
        Some(_) => {
            return Err(McpToolError::InvalidParams(
                "'columns' must be an array of strings".into(),
            ));
        }
    };

    let offset = match obj.get("offset") {
        None | Some(Value::Null) => 0usize,
        Some(v) => v
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| McpToolError::InvalidParams("'offset' must be a non-negative integer".into()))?,
    };

    let limit = match obj.get("limit") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let n = v
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .filter(|&n| n > 0)
                .ok_or_else(|| McpToolError::InvalidParams("'limit' must be a positive integer".into()))?;
            Some(n)
        }
    };

    Ok(TableQuery {
        filter,
        sort,
        columns,
        offset,
        limit,
    })
}

fn parse_filter_value(val: &Value) -> Result<Option<FilterExpr>, McpToolError> {
    match val {
        Value::Null => Ok(None),
        Value::String(s) if s.trim().is_empty() => Ok(None),
        Value::String(s) => Ok(Some(GetNirQuery::parse_filter(s)?)),
        other => {
            let expr: FilterExpr = serde_json::from_value(other.clone())
                .map_err(|e| McpToolError::InvalidParams(format!("invalid filter object: {e}")))?;
            Ok(Some(expr))
        }
    }
}

fn serialize_table_data(data: &TableData) -> Value {
    let rows: Vec<Value> = data
        .rows
        .iter()
        .map(|row| {
            let mut row_obj = Map::with_capacity(data.schema.columns.len() + 2);
            row_obj.insert("row_id".to_string(), json!(row.id));
            for (idx, col) in data.schema.columns.iter().enumerate() {
                let val = row.cells.get(idx).map(|c| c.to_json_value()).unwrap_or(Value::Null);
                row_obj.insert(col.id.clone(), val);
            }
            if let Some(detail) = &row.detail_json {
                row_obj.insert("detail_json".to_string(), detail.clone());
            }
            Value::Object(row_obj)
        })
        .collect();

    json!({
        "tool_id": data.schema.tool_id,
        "title": data.schema.title,
        "total_rows": data.total_rows,
        "returned_rows": rows.len(),
        "columns": data.schema.columns,
        "rows": rows,
    })
}

/// Builds a [`guap_mcp::McpServerRegistry`] exposing all 45 strictly read-only DFIR tools.
pub fn build_registry(policy: PolicyMode, default_source: ForensicSource) -> McpServerRegistry {
    let mut registry = McpServerRegistry::new(policy).with_server_info(SERVER_NAME, SERVER_VERSION);
    for provider in collect_all_providers(&default_source) {
        registry.register_action(Arc::new(ForensicTableAction {
            tool_id: provider.tool_id(),
            description: provider.description(),
            schema: provider.schema(),
            default_source: default_source.clone(),
        }));
    }
    registry
}

/// Builds the default [`McpServerRegistry`] with [`PolicyMode::ReadOnlyOnly`] and [`ForensicSource::Live`].
pub fn build_default_registry() -> McpServerRegistry {
    build_registry(PolicyMode::ReadOnlyOnly, ForensicSource::Live)
}

/// Returns the JSON array value of all 45 MCP tool definitions.
pub fn tools_manifest_value(policy: PolicyMode, default_source: ForensicSource) -> Value {
    build_registry(policy, default_source).list_tools()
}

/// Returns pretty-printed JSON of all 45 MCP tool definitions.
pub fn tools_manifest_json(policy: PolicyMode, default_source: ForensicSource) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&tools_manifest_value(policy, default_source))
}

/// Processes a single JSON-RPC 2.0 `stdio` line, suppressing replies for all
/// JSON-RPC 2.0 Notifications (JSON objects containing `"method"` and no `"id"`).
pub fn handle_jsonrpc_line(registry: &McpServerRegistry, line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(val) = serde_json::from_str::<Value>(trimmed)
        && let Some(obj) = val.as_object()
        && obj.contains_key("method")
        && !obj.contains_key("id")
    {
        let _ = registry.handle_jsonrpc_request(&val);
        return None;
    }
    registry
        .handle_line(line)
        .and_then(|resp| serde_json::to_string(&resp).ok())
}

/// Runs the JSON-RPC 2.0 `stdio` loop over explicit `reader` and `writer` streams.
pub fn serve_reader_writer<R: BufRead, W: Write>(
    registry: &McpServerRegistry,
    reader: R,
    mut writer: W,
) -> anyhow::Result<()> {
    for line_res in reader.lines() {
        let line = line_res?;
        if let Some(encoded) = handle_jsonrpc_line(registry, &line) {
            writeln!(writer, "{encoded}")?;
            writer.flush()?;
        }
    }
    Ok(())
}

/// Runs the blocking JSON-RPC 2.0 `stdio` MCP server loop.
pub fn serve_stdio(policy: PolicyMode, default_source: ForensicSource) -> anyhow::Result<()> {
    let registry = build_registry(policy, default_source);
    tracing::info!(
        protocol = MCP_PROTOCOL_VERSION,
        tools = FORENSIC_TOOL_CATALOG.len(),
        "starting forensics2rust MCP stdio server"
    );
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    serve_reader_writer(&registry, stdin.lock(), stdout.lock())
}

#[cfg(test)]
mod tests {
    use guap_mcp::JsonRpcError;

    use super::*;

    struct DummyMutatingAction;

    impl ActionCommand for DummyMutatingAction {
        fn command_id(&self) -> &'static str {
            "test.mutating_action"
        }

        fn description(&self) -> &'static str {
            "Synthetic mutating action for PolicyMode::ReadOnlyOnly gate verification"
        }

        fn risk_level(&self) -> ActionRiskLevel {
            ActionRiskLevel::Mutating
        }

        fn input_schema(&self) -> Value {
            json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            })
        }

        fn execute(&self, _args: &Value, _dry_run: bool) -> Result<Value, McpToolError> {
            Ok(json!({"executed": true}))
        }
    }

    #[test]
    fn mcp_crate_skeleton_defaults_to_read_only() {
        assert_eq!(crate_info().0, "forensics2rust-mcp");
        assert_eq!(default_policy_mode(), PolicyMode::ReadOnlyOnly);
        assert_eq!(catalog_tool_count(), 45);
    }

    #[test]
    fn collect_all_providers_matches_catalog_45_in_order() {
        let providers = collect_all_providers(&ForensicSource::Live);
        assert_eq!(providers.len(), 45);
        for (provider, desc) in providers.iter().zip(FORENSIC_TOOL_CATALOG.iter()) {
            assert_eq!(provider.tool_id(), desc.tool_id);
            assert!(provider.is_read_only());
        }
    }

    #[test]
    fn jsonrpc_initialize_and_tools_list_expose_45_readonly_tools() {
        let registry = build_default_registry();

        let init_req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });
        let init_resp = registry.handle_jsonrpc_request(&init_req).unwrap();
        assert_eq!(init_resp["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(init_resp["result"]["serverInfo"]["name"], SERVER_NAME);

        let list_req = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        });
        let list_resp = registry.handle_jsonrpc_request(&list_req).unwrap();
        let tools = list_resp["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 45);

        for tool in tools {
            assert_eq!(tool["annotations"]["readOnlyHint"], json!(true));
            assert_eq!(tool["annotations"]["destructiveHint"], json!(false));
            assert!(tool["inputSchema"]["properties"]["confirm_destructive"].is_null());
            assert!(tool["inputSchema"]["properties"]["source_path"].is_object());
            assert!(tool["inputSchema"]["properties"]["offline_path"].is_object());
        }
    }

    #[test]
    fn jsonrpc_tools_call_executes_with_per_call_source_path_and_getnir_queries() {
        let suite = test_fixtures::SyntheticSuiteDir::create();
        // Server starts in Live mode, and per-call source_path/offline_path switches to offline fixtures!
        let registry = build_default_registry();

        // 1. EVTX with source_path + getnir filter + limit
        let evtx_call = json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "evtx.all",
                "arguments": {
                    "source_path": suite.evtx_file().display().to_string(),
                    "getnir": "event_id == 4688",
                    "limit": 1,
                    "offset": 0
                }
            }
        });
        let resp = registry.handle_jsonrpc_request(&evtx_call).unwrap();
        assert_eq!(resp["result"]["isError"], json!(false));
        let payload: Value = serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(payload["tool_id"], "evtx.all");
        assert_eq!(payload["returned_rows"], 1);

        // 2. Hive offline with offline_path + columns + sort
        let hive_call = json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "hive.offline",
                "arguments": {
                    "offline_path": suite.ntuser_path().display().to_string(),
                    "columns": ["value_name", "data_decoded"],
                    "sort": "value_name:asc",
                    "limit": 5
                }
            }
        });
        let hive_resp = registry.handle_jsonrpc_request(&hive_call).unwrap();
        assert_eq!(hive_resp["result"]["isError"], json!(false));
        let hive_payload: Value =
            serde_json::from_str(hive_resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(hive_payload["tool_id"], "hive.offline");
        assert!(hive_payload["total_rows"].as_u64().unwrap() >= 1);

        // 3. SRUM net + srum.db with table_name
        let srum_call = json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "srum.net",
                "arguments": {
                    "source_path": suite.srum_path().display().to_string(),
                    "filter": "bytes_sent >= 100"
                }
            }
        });
        let srum_resp = registry.handle_jsonrpc_request(&srum_call).unwrap();
        let srum_payload: Value =
            serde_json::from_str(srum_resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert!(srum_payload["total_rows"].as_u64().unwrap() >= 1);

        let srum_db_table = json!({
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": {
                "name": "srum.db",
                "arguments": {
                    "source_path": suite.srum_path().display().to_string(),
                    "table_name": "SruDbIdMapTable"
                }
            }
        });
        let srum_db_resp = registry.handle_jsonrpc_request(&srum_db_table).unwrap();
        let srum_db_payload: Value =
            serde_json::from_str(srum_db_resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert!(srum_db_payload["total_rows"].as_u64().unwrap() >= 1);

        // 4. Crash WER + Artifacts Prefetch + Posture Updates via suite dir
        for (tool_id, path) in [
            ("crash.wer", suite.root().to_path_buf()),
            ("artifacts.prefetch", suite.root().to_path_buf()),
            ("posture.updates", suite.root().to_path_buf()),
            ("hive.watch", suite.watch_path()),
        ] {
            let call = json!({
                "jsonrpc": "2.0",
                "id": 14,
                "method": "tools/call",
                "params": {
                    "name": tool_id,
                    "arguments": {
                        "source_path": path.display().to_string()
                    }
                }
            });
            let r = registry.handle_jsonrpc_request(&call).unwrap();
            assert!(r["error"].is_null(), "unexpected error for {tool_id}: {r}");
            let p: Value = serde_json::from_str(r["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
            assert!(p["total_rows"].as_u64().unwrap() >= 1, "expected rows for {tool_id}");
        }
    }

    #[test]
    fn jsonrpc_error_codes_for_invalid_params_unknown_tool_corrupt_input_and_policy_denial() {
        let suite = test_fixtures::SyntheticSuiteDir::create();
        let mut registry = build_registry(
            PolicyMode::ReadOnlyOnly,
            ForensicSource::OfflinePath(suite.root().to_path_buf()),
        );

        // 1. Unknown tool -> -32601
        let unknown = registry
            .handle_jsonrpc_request(&json!({
                "jsonrpc": "2.0",
                "id": 20,
                "method": "tools/call",
                "params": { "name": "nonexistent.tool", "arguments": {} }
            }))
            .unwrap();
        assert_eq!(unknown["error"]["code"], JsonRpcError::METHOD_NOT_FOUND);

        // 2. Malformed filter expression -> -32602
        let bad_filter = registry
            .handle_jsonrpc_request(&json!({
                "jsonrpc": "2.0",
                "id": 21,
                "method": "tools/call",
                "params": {
                    "name": "evtx.all",
                    "arguments": { "filter": "event_id == (" }
                }
            }))
            .unwrap();
        assert_eq!(bad_filter["error"]["code"], JsonRpcError::INVALID_PARAMS);

        // 3. Invalid column name -> -32602
        let bad_col = registry
            .handle_jsonrpc_request(&json!({
                "jsonrpc": "2.0",
                "id": 22,
                "method": "tools/call",
                "params": {
                    "name": "evtx.all",
                    "arguments": { "columns": ["no_such_col"] }
                }
            }))
            .unwrap();
        assert_eq!(bad_col["error"]["code"], JsonRpcError::INVALID_PARAMS);

        // 4. Missing/corrupt explicit file -> graceful JSON-RPC error (no panic)
        let missing = registry
            .handle_jsonrpc_request(&json!({
                "jsonrpc": "2.0",
                "id": 23,
                "method": "tools/call",
                "params": {
                    "name": "hive.offline",
                    "arguments": { "source_path": suite.root().join("does_not_exist.hiv").display().to_string() }
                }
            }))
            .unwrap();
        assert_eq!(missing["error"]["code"], JsonRpcError::INTERNAL_ERROR);

        let corrupt_path = suite.root().join("corrupt.hiv");
        fs::write(&corrupt_path, b"NOT_A_REGF_HIVE").unwrap();
        let corrupt = registry
            .handle_jsonrpc_request(&json!({
                "jsonrpc": "2.0",
                "id": 24,
                "method": "tools/call",
                "params": {
                    "name": "hive.offline",
                    "arguments": { "source_path": corrupt_path.display().to_string() }
                }
            }))
            .unwrap();
        assert_eq!(corrupt["error"]["code"], JsonRpcError::INTERNAL_ERROR);

        // 5. PolicyMode::ReadOnlyOnly mutating action denial -> -32003
        registry.register_action(Arc::new(DummyMutatingAction));
        let denied = registry
            .handle_jsonrpc_request(&json!({
                "jsonrpc": "2.0",
                "id": 25,
                "method": "tools/call",
                "params": {
                    "name": "test.mutating_action",
                    "arguments": { "confirm_destructive": true }
                }
            }))
            .unwrap();
        assert_eq!(denied["error"]["code"], JsonRpcError::POLICY_DENIED);
    }

    #[test]
    fn stdio_reader_writer_round_trip_handles_initialize_list_and_call() {
        let suite = test_fixtures::SyntheticSuiteDir::create();
        let registry = build_registry(
            PolicyMode::ReadOnlyOnly,
            ForensicSource::OfflinePath(suite.root().to_path_buf()),
        );

        let input = concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"crash.wer","arguments":{}}}"#,
            "\n"
        );
        let mut output = Vec::new();
        serve_reader_writer(&registry, std::io::Cursor::new(input.as_bytes()), &mut output).unwrap();

        let lines: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0]["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(lines[1]["result"]["tools"].as_array().unwrap().len(), 45);
        assert_eq!(lines[2]["result"]["isError"], json!(false));
    }

    #[test]
    fn handle_jsonrpc_line_suppresses_notifications_without_id_and_replies_with_id() {
        let registry = build_default_registry();

        // JSON-RPC 2.0 Notification without "id" (including non-"notifications/*" methods like "ping") -> silent
        assert!(handle_jsonrpc_line(&registry, r#"{"jsonrpc":"2.0","method":"ping"}"#).is_none());
        assert!(handle_jsonrpc_line(&registry, r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).is_none());
        assert!(handle_jsonrpc_line(&registry, "   ").is_none());

        // Requests with numeric "id" or explicit "id": null MUST receive a JSON-RPC response
        let ping_num = handle_jsonrpc_line(&registry, r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#).unwrap();
        let ping_num_val: Value = serde_json::from_str(&ping_num).unwrap();
        assert_eq!(ping_num_val["id"], json!(1));
        assert_eq!(ping_num_val["result"], json!({}));

        let ping_null = handle_jsonrpc_line(&registry, r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#).unwrap();
        let ping_null_val: Value = serde_json::from_str(&ping_null).unwrap();
        assert_eq!(ping_null_val["id"], Value::Null);
        assert_eq!(ping_null_val["result"], json!({}));

        // Invalid lines / objects missing "method" still return JSON-RPC errors
        let missing_method = handle_jsonrpc_line(&registry, r#"{"jsonrpc":"2.0"}"#).unwrap();
        let missing_method_val: Value = serde_json::from_str(&missing_method).unwrap();
        assert_eq!(missing_method_val["error"]["code"], JsonRpcError::INVALID_REQUEST);

        let non_object = handle_jsonrpc_line(&registry, "[1, 2, 3]").unwrap();
        let non_object_val: Value = serde_json::from_str(&non_object).unwrap();
        assert_eq!(non_object_val["error"]["code"], JsonRpcError::INVALID_REQUEST);

        let malformed = handle_jsonrpc_line(&registry, "{broken json").unwrap();
        let malformed_val: Value = serde_json::from_str(&malformed).unwrap();
        assert_eq!(malformed_val["error"]["code"], JsonRpcError::PARSE_ERROR);
    }

    #[test]
    fn serve_reader_writer_emits_zero_lines_for_notification_without_id() {
        let registry = build_default_registry();
        let input = concat!(
            r#"{"jsonrpc":"2.0","method":"ping"}"#,
            "\n",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
            "\n"
        );
        let mut output = Vec::new();
        serve_reader_writer(&registry, std::io::Cursor::new(input.as_bytes()), &mut output).unwrap();

        let text = String::from_utf8(output).unwrap();
        let lines: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["id"], json!(1));
        assert_eq!(lines[0]["result"], json!({}));
        assert_eq!(lines[1]["id"], Value::Null);
        assert_eq!(lines[1]["result"], json!({}));
    }
}
