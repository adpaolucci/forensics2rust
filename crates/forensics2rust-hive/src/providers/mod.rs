pub mod diff;
pub mod export;
pub mod find;
pub mod offline;
pub mod scan;
pub mod watch;

pub use diff::{RegistryChangesProvider, RegistrySnapshotEntry};
pub use export::RegistryFileExportProvider;
pub use find::{FindCriteria, OfflineFinderProvider};
pub use offline::OfflineRegistryProvider;
pub use scan::{RegistryScannerProvider, ScanOptions};
pub use watch::RegWatchProvider;

use chrono::{DateTime, Utc};
use guap_table::CellValue;

pub(crate) fn opt_timestamp_cell(ts: Option<DateTime<Utc>>) -> CellValue {
    match ts {
        Some(dt) => CellValue::Timestamp(dt),
        None => CellValue::Null,
    }
}

pub(crate) fn opt_text_cell(val: Option<String>) -> CellValue {
    match val {
        Some(s) => CellValue::Text(s),
        None => CellValue::Null,
    }
}

pub(crate) fn display_value_name(name: &str) -> String {
    if name.is_empty() {
        "(Default)".to_owned()
    } else {
        name.to_owned()
    }
}
