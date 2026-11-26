pub mod btree;
pub mod catalog;
pub mod compress;
pub mod header;
pub mod lv;
pub mod page;
pub mod record;
pub mod value;

use std::collections::BTreeMap;
use std::path::Path;

use forensics2rust_core::{DiagnosticWarning, ForensicError, ForensicSource, WarningSeverity};

pub use btree::WalkOptions;
pub use catalog::{EseColumnSchema, EseTableSchema, JetColType};
pub use header::{DatabaseState, ESE_SIGNATURE, EseHeader, PageFormat};
pub use value::{EseRow, EseTableData, EseValue, decode_cp1252};

#[derive(Debug, Clone, Copy, Default)]
pub struct ReadTableOptions {
    pub include_versioned: bool,
}

impl ReadTableOptions {
    pub fn forensic_default() -> Self {
        Self {
            include_versioned: true,
        }
    }
}

pub struct EseDatabase {
    data: Vec<u8>,
    header: EseHeader,
    tables: BTreeMap<String, EseTableSchema>,
    warnings: Vec<DiagnosticWarning>,
}

impl EseDatabase {
    pub fn from_bytes(data: &[u8]) -> Result<Self, ForensicError> {
        let (header, mut warnings) = header::parse_database_header(data)?;
        let tables = catalog::parse_catalog(data, &header, &mut warnings)?;
        Ok(Self {
            data: data.to_vec(),
            header,
            tables,
            warnings,
        })
    }

    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        let bytes = crate::live::read_ese_path(path)?;
        Self::from_bytes(&bytes)
    }

    pub fn from_source(source: &ForensicSource) -> Result<Self, ForensicError> {
        match source {
            ForensicSource::Live => {
                let bytes = crate::live::read_live_srudb_bytes()?;
                Self::from_bytes(&bytes)
            }
            ForensicSource::OfflinePath(path) => Self::open(path),
            ForensicSource::OfflineBytes(bytes) => Self::from_bytes(bytes),
        }
    }

    pub fn header(&self) -> &EseHeader {
        &self.header
    }

    pub fn warnings(&self) -> &[DiagnosticWarning] {
        &self.warnings
    }

    pub fn table_names(&self) -> Vec<String> {
        self.tables.keys().cloned().collect()
    }

    pub fn table_schema(&self, name: &str) -> Option<&EseTableSchema> {
        self.tables.get(name).or_else(|| {
            self.tables
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v)
        })
    }

    pub fn read_table(&self, name: &str) -> Result<EseTableData, ForensicError> {
        self.read_table_with_options(name, ReadTableOptions::forensic_default())
    }

    pub fn read_table_with_options(
        &self,
        name: &str,
        options: ReadTableOptions,
    ) -> Result<EseTableData, ForensicError> {
        let Some(schema) = self.table_schema(name).cloned() else {
            return Err(ForensicError::NotFound(format!("ESE table '{name}'")));
        };

        let mut warnings = Vec::new();
        let lv_index = if let Some(lv_pgno) = schema.lv_pgno_fdp {
            lv::LongValueIndex::build(&self.data, &self.header, lv_pgno, &mut warnings)?
        } else {
            lv::LongValueIndex::empty()
        };

        let walk_opts = WalkOptions {
            include_versioned: options.include_versioned,
        };
        let entries = btree::walk_btree(&self.data, &self.header, schema.pgno_fdp, walk_opts, &mut warnings)?;
        let fixed_layouts = schema.fixed_column_layouts();

        let mut rows = Vec::with_capacity(entries.len());
        for entry in entries {
            if entry.tag_flags.is_versioned() && entry.data == [0x00] {
                continue;
            }
            let rec = match record::parse_record(&entry.data, entry.page_flags, self.header.page_format, &fixed_layouts)
            {
                Ok(r) => r,
                Err(err) => {
                    warnings.push(DiagnosticWarning {
                        severity: WarningSeverity::Warn,
                        tool_id: "srum.db".to_string(),
                        source: format!("ESE table {name}"),
                        message: format!("skipping malformed record: {err}"),
                    });
                    continue;
                }
            };

            let mut values = BTreeMap::new();
            for col in &schema.columns {
                let has_collision = col.id >= 256 && schema.columns.iter().filter(|c| c.id == col.id).count() > 1;
                let val =
                    value::decode_column_value_with_collision(col, &rec, &lv_index, has_collision, &mut warnings)?;
                values.insert(col.name.clone(), val);
            }
            rows.push(EseRow {
                values,
                raw_bytes: entry.data,
            });
        }

        for warning in &warnings {
            tracing::warn!(
                tool_id = %warning.tool_id,
                source = %warning.source,
                "{}",
                warning.message
            );
        }

        Ok(EseTableData { schema, rows })
    }
}
