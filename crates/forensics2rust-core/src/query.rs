use guap_table::{GuapQuery, Row, TableData, TableProvider, TableQuery, TableSchema};

use crate::error::ForensicError;

/// Thin adapter delegating filtering, sorting, projection, pagination, and `GuapQuery`
/// query execution to `guap_table`.
pub struct QueryHelper;

impl QueryHelper {
    /// Delegates directly to `guap_table::apply_query`.
    pub fn apply(schema: &TableSchema, rows: &[Row], req: &TableQuery) -> Result<TableData, ForensicError> {
        guap_table::apply_query(schema, rows, req).map_err(ForensicError::from)
    }

    /// Parses `GuapQuery` filter and sort strings plus projection and pagination into a `TableQuery`.
    pub fn build_query(
        schema: &TableSchema,
        columns: Option<Vec<String>>,
        filter_expr: Option<&str>,
        sort_spec: Option<&str>,
        offset: usize,
        limit: Option<usize>,
    ) -> Result<TableQuery, ForensicError> {
        let sort = match sort_spec {
            Some(s) if !s.trim().is_empty() => GuapQuery::parse_sort(s)?,
            _ => Vec::new(),
        };
        let guap_query = GuapQuery {
            columns,
            filter_expr: filter_expr.map(str::to_string),
            sort,
            offset,
            limit,
        };
        guap_query.to_table_query(schema).map_err(ForensicError::from)
    }

    /// One-shot `GuapQuery` query over in-memory rows via `guap_table::apply_query`.
    pub fn apply_query(
        schema: &TableSchema,
        rows: &[Row],
        columns: Option<Vec<String>>,
        filter_expr: Option<&str>,
        sort_spec: Option<&str>,
        offset: usize,
        limit: Option<usize>,
    ) -> Result<TableData, ForensicError> {
        let query = Self::build_query(schema, columns, filter_expr, sort_spec, offset, limit)?;
        Self::apply(schema, rows, &query)
    }

    /// Executes a `GuapQuery` against any `guap_table::TableProvider`.
    pub fn query_provider(
        provider: &dyn TableProvider,
        columns: Option<Vec<String>>,
        filter_expr: Option<&str>,
        sort_spec: Option<&str>,
        offset: usize,
        limit: Option<usize>,
    ) -> Result<TableData, ForensicError> {
        let schema = provider.schema();
        let query = Self::build_query(&schema, columns, filter_expr, sort_spec, offset, limit)?;
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
