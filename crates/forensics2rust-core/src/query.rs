use guap_table::{GetNirQuery, Row, TableData, TableProvider, TableQuery, TableSchema};

use crate::error::ForensicError;

/// Thin adapter delegating filtering, sorting, projection, pagination, and `GetNir`
/// query execution to `guap_table`.
pub struct QueryHelper;

impl QueryHelper {
    /// Delegates directly to `guap_table::apply_query`.
    pub fn apply(schema: &TableSchema, rows: &[Row], req: &TableQuery) -> Result<TableData, ForensicError> {
        guap_table::apply_query(schema, rows, req).map_err(ForensicError::from)
    }

    /// Parses `GetNir` filter and sort strings plus projection and pagination into a `TableQuery`.
    pub fn build_getnir_query(
        schema: &TableSchema,
        columns: Option<Vec<String>>,
        filter_expr: Option<&str>,
        sort_spec: Option<&str>,
        offset: usize,
        limit: Option<usize>,
    ) -> Result<TableQuery, ForensicError> {
        let sort = match sort_spec {
            Some(s) if !s.trim().is_empty() => GetNirQuery::parse_sort(s)?,
            _ => Vec::new(),
        };
        let nir = GetNirQuery {
            columns,
            filter_expr: filter_expr.map(str::to_string),
            sort,
            offset,
            limit,
        };
        nir.to_table_query(schema).map_err(ForensicError::from)
    }

    /// One-shot `GetNir` query over in-memory rows via `guap_table::apply_query`.
    pub fn apply_getnir(
        schema: &TableSchema,
        rows: &[Row],
        columns: Option<Vec<String>>,
        filter_expr: Option<&str>,
        sort_spec: Option<&str>,
        offset: usize,
        limit: Option<usize>,
    ) -> Result<TableData, ForensicError> {
        let query = Self::build_getnir_query(schema, columns, filter_expr, sort_spec, offset, limit)?;
        Self::apply(schema, rows, &query)
    }

    /// Executes a `GetNir` query against any `guap_table::TableProvider`.
    pub fn query_provider(
        provider: &dyn TableProvider,
        columns: Option<Vec<String>>,
        filter_expr: Option<&str>,
        sort_spec: Option<&str>,
        offset: usize,
        limit: Option<usize>,
    ) -> Result<TableData, ForensicError> {
        let schema = provider.schema();
        let query = Self::build_getnir_query(&schema, columns, filter_expr, sort_spec, offset, limit)?;
        provider.query(&query).map_err(ForensicError::from)
    }

    /// Constructs an empty `TableData` for a schema.
    pub fn empty(schema: TableSchema) -> TableData {
        TableData {
            schema,
            rows: Vec::new(),
            total_rows: 0,
        }
    }
}
