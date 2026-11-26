#![forbid(unsafe_code)]

//! All 14 read-only `guap_table::TableProvider` implementations for `forensics2rust-artifacts`.

pub mod execution;
pub mod registry;
pub mod usb_vss;

use std::sync::Arc;

use forensics2rust_core::{ForensicSource, QueryHelper};
use guap_table::{CellValue, ColumnDef, ColumnType, Row, TableData, TableError, TableQuery, TableSchema};

pub use execution::{
    ExecutedProgramsProvider, JumpListsProvider, LastActivityProvider, RecentFilesProvider, WinPrefetchProvider,
};
pub use registry::{MuiCacheProvider, OpenSaveProvider, ShellBagsProvider, UserAssistProvider, UserProfilesProvider};
pub use usb_vss::{PreviousFilesProvider, ShadowCopyProvider, UsbDevicesProvider, UsbLogProvider};

/// Returns all 14 read-only `forensics2rust-artifacts` [`guap_table::TableProvider`]
/// instances in canonical `FORENSIC_TOOL_CATALOG` order.
pub fn all_providers(source: &ForensicSource) -> Vec<Arc<dyn guap_table::TableProvider>> {
    vec![
        Arc::new(LastActivityProvider::new(source.clone())),
        Arc::new(WinPrefetchProvider::new(source.clone())),
        Arc::new(JumpListsProvider::new(source.clone())),
        Arc::new(ShellBagsProvider::new(source.clone())),
        Arc::new(UserAssistProvider::new(source.clone())),
        Arc::new(MuiCacheProvider::new(source.clone())),
        Arc::new(OpenSaveProvider::new(source.clone())),
        Arc::new(RecentFilesProvider::new(source.clone())),
        Arc::new(ExecutedProgramsProvider::new(source.clone())),
        Arc::new(UsbDevicesProvider::new(source.clone())),
        Arc::new(UsbLogProvider::new(source.clone())),
        Arc::new(ShadowCopyProvider::new(source.clone())),
        Arc::new(PreviousFilesProvider::new(source.clone())),
        Arc::new(UserProfilesProvider::new(source.clone())),
    ]
}

pub(crate) fn col(id: &str, label: &str, col_type: ColumnType, width_hint: u16) -> ColumnDef {
    ColumnDef::new(id, label, col_type).with_width_hint(width_hint)
}

pub(crate) fn opt_text(s: Option<&str>) -> CellValue {
    match s.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) => CellValue::Text(v.to_string()),
        None => CellValue::Null,
    }
}

pub(crate) fn opt_text_owned(s: Option<String>) -> CellValue {
    match s.filter(|v| !v.trim().is_empty()) {
        Some(v) => CellValue::Text(v),
        None => CellValue::Null,
    }
}

pub(crate) fn non_empty_text(s: &str) -> CellValue {
    if s.trim().is_empty() {
        CellValue::Null
    } else {
        CellValue::Text(s.to_string())
    }
}

pub(crate) fn opt_timestamp(dt: Option<chrono::DateTime<chrono::Utc>>) -> CellValue {
    match dt {
        Some(d) => CellValue::Timestamp(d),
        None => CellValue::Null,
    }
}

pub(crate) fn apply_rows(schema: &TableSchema, rows: &[Row], req: &TableQuery) -> Result<TableData, TableError> {
    QueryHelper::apply(schema, rows, req).map_err(|e| e.to_table_error())
}
