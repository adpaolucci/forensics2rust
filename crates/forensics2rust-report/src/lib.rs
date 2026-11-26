#![forbid(unsafe_code)]

//! Forensic table rendering, multi-table bundle export, table diffing, and
//! SHA-256/SHA-512 Merkle chain-of-custody reporting via `guap-export`.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use forensics2rust_core::FORENSIC_TOOL_CATALOG;
pub use guap_export::{
    CustodyLeaf, CustodyManifest, ExportError, ExportFormat, ExportOptions, build_custody_manifest,
    compute_merkle_root_sha256, compute_merkle_root_sha512, export_table, neutralize_spreadsheet_cell, sha256_hex,
    sha512_hex, write_custody_manifest_json, write_table_export,
};
use guap_table::{TableData, TableError, TableTextCompare};
use serde::{Deserialize, Serialize};

/// Returns the crate metadata descriptor tuple `(crate_name, version)`.
pub fn crate_info() -> (&'static str, &'static str) {
    (env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

/// Returns total number of reportable DFIR tools registered in the catalog.
pub fn reportable_tool_count() -> usize {
    FORENSIC_TOOL_CATALOG.len()
}

/// Builds default [`ExportOptions`] branded with `forensics2rust-report`'s crate version.
pub fn default_export_options(title_override: Option<String>) -> ExportOptions {
    ExportOptions {
        include_header: true,
        neutralize_formulas: true,
        include_detail_json: false,
        pretty_json: true,
        title_override,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

/// Options governing single-table and multi-table forensic report generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForensicReportOptions {
    pub export: ExportOptions,
    pub write_custody_sidecar: bool,
    pub case_id: Option<String>,
    pub examiner: Option<String>,
    pub host_name: Option<String>,
    pub source_label: Option<String>,
}

impl Default for ForensicReportOptions {
    fn default() -> Self {
        Self {
            export: default_export_options(None),
            write_custody_sidecar: true,
            case_id: None,
            examiner: None,
            host_name: None,
            source_label: None,
        }
    }
}

impl ForensicReportOptions {
    pub fn with_title_override(mut self, title: impl Into<String>) -> Self {
        self.export.title_override = Some(title.into());
        self
    }

    pub fn with_include_detail_json(mut self, include: bool) -> Self {
        self.export.include_detail_json = include;
        self
    }

    pub fn with_custody_sidecar(mut self, enabled: bool) -> Self {
        self.write_custody_sidecar = enabled;
        self
    }

    pub fn with_case_metadata(
        mut self,
        case_id: Option<String>,
        examiner: Option<String>,
        host_name: Option<String>,
        source_label: Option<String>,
    ) -> Self {
        self.case_id = case_id;
        self.examiner = examiner;
        self.host_name = host_name;
        self.source_label = source_label;
        self
    }
}

/// Forensic report result combining written artifact paths with SHA-256/SHA-512 Merkle custody metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicCustodyReport {
    pub suite_name: String,
    pub suite_version: String,
    pub case_id: Option<String>,
    pub examiner: Option<String>,
    pub host_name: Option<String>,
    pub source_label: Option<String>,
    pub custody: CustodyManifest,
    pub artifact_paths: Vec<PathBuf>,
    pub sidecar_path: Option<PathBuf>,
}

/// Computes the canonical sidecar path (`<artifact_path>.custody.json`).
pub fn sidecar_path_for(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(".custody.json");
    PathBuf::from(os)
}

/// Renders a [`TableData`] payload in-memory in the requested [`ExportFormat`].
pub fn render_table_report(
    data: &TableData,
    format: ExportFormat,
    opts: &ForensicReportOptions,
) -> Result<Vec<u8>, ExportError> {
    export_table(data, format, &opts.export)
}

/// Writes a single-table export to `path` and optionally emits a `<path>.custody.json` sidecar
/// containing the SHA-256/SHA-512 [`CustodyManifest`].
pub fn write_table_report(
    data: &TableData,
    path: &Path,
    format: ExportFormat,
    opts: &ForensicReportOptions,
) -> Result<ForensicCustodyReport, ExportError> {
    let custody = write_table_export(data, path, format, &opts.export)?;
    let sidecar_path = if opts.write_custody_sidecar {
        let sidecar = sidecar_path_for(path);
        write_custody_manifest_json(&custody, &sidecar)?;
        Some(sidecar)
    } else {
        None
    };

    Ok(build_report_envelope(
        custody,
        vec![path.to_path_buf()],
        sidecar_path,
        opts,
    ))
}

/// Exports multiple [`TableData`] tables into `out_dir` using `format` and emits a unified
/// `custody_manifest.json` containing SHA-256 and SHA-512 Merkle roots over all exported files.
pub fn write_bundle_report(
    tables: &[TableData],
    out_dir: &Path,
    format: ExportFormat,
    opts: &ForensicReportOptions,
) -> Result<ForensicCustodyReport, ExportError> {
    fs::create_dir_all(out_dir)?;

    let mut leaves = Vec::with_capacity(tables.len());
    let mut artifact_paths = Vec::with_capacity(tables.len());
    let mut used_filenames: HashSet<String> = HashSet::new();
    used_filenames.insert("custody_manifest.json".to_string());

    for table in tables {
        let safe_tool_id = sanitize_filename_component(&table.schema.tool_id);
        let mut counter = 1usize;
        let filename = loop {
            let stem = if counter == 1 {
                safe_tool_id.clone()
            } else {
                format!("{safe_tool_id}_{counter}")
            };
            let candidate = match format {
                ExportFormat::HtmlVertical => format!("{stem}.vertical.html"),
                _ => format!("{stem}.{}", format.extension()),
            };
            if used_filenames.insert(candidate.to_ascii_lowercase()) {
                break candidate;
            }
            counter += 1;
        };

        let target = out_dir.join(filename);
        let bytes = export_table(table, format, &opts.export)?;
        fs::write(&target, &bytes)?;

        leaves.push(CustodyLeaf {
            index: leaves.len(),
            path: target.display().to_string(),
            size_bytes: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
            sha512: sha512_hex(&bytes),
        });
        artifact_paths.push(target);
    }

    let custody = build_custody_manifest("forensics2rust_bundle", &opts.export.tool_version, leaves);
    let sidecar_path = if opts.write_custody_sidecar {
        let manifest_path = out_dir.join("custody_manifest.json");
        write_custody_manifest_json(&custody, &manifest_path)?;
        Some(manifest_path)
    } else {
        None
    };

    Ok(build_report_envelope(custody, artifact_paths, sidecar_path, opts))
}

/// Compares two [`TableData`] tables by `key_cols` via [`TableTextCompare::diff`] and returns
/// the diff result as a [`TableData`].
pub fn diff_tables(left: &TableData, right: &TableData, key_cols: &[String]) -> Result<TableData, TableError> {
    TableTextCompare::diff(left, right, key_cols).map(|diff| diff.to_table_data())
}

fn build_report_envelope(
    custody: CustodyManifest,
    artifact_paths: Vec<PathBuf>,
    sidecar_path: Option<PathBuf>,
    opts: &ForensicReportOptions,
) -> ForensicCustodyReport {
    ForensicCustodyReport {
        suite_name: "forensics2rust".to_string(),
        suite_version: opts.export.tool_version.clone(),
        case_id: opts.case_id.clone(),
        examiner: opts.examiner.clone(),
        host_name: opts.host_name.clone(),
        source_label: opts.source_label.clone(),
        custody,
        artifact_paths,
        sidecar_path,
    }
}

fn sanitize_filename_component(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('.').to_string();
    let base = if trimmed.is_empty() {
        "table".to_string()
    } else {
        trimmed
    };
    if is_windows_reserved_stem(&base) {
        format!("table_{base}")
    } else {
        base
    }
}

fn is_windows_reserved_stem(stem: &str) -> bool {
    matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

#[cfg(test)]
mod tests {
    use guap_table::{CellValue, ColumnDef, ColumnType, Row, TableSchema};
    use tempfile::tempdir;

    use super::*;

    fn sample_table(tool_id: &str, rows: Vec<Row>) -> TableData {
        let total_rows = rows.len();
        TableData {
            schema: TableSchema::new(
                tool_id,
                format!("Sample {tool_id}"),
                vec![
                    ColumnDef::new("item_key", "ItemKey", ColumnType::Text),
                    ColumnDef::new("value", "Value", ColumnType::Text),
                    ColumnDef::new("count", "Count", ColumnType::Uint),
                ],
            ),
            rows,
            total_rows,
        }
    }

    #[test]
    fn report_crate_skeleton_sees_45_tools() {
        assert_eq!(crate_info().0, "forensics2rust-report");
        assert_eq!(reportable_tool_count(), 45);
    }

    #[test]
    fn renders_all_seven_export_formats_and_neutralizes_formulas() {
        let data = sample_table(
            "evtx.all",
            vec![
                Row::new(
                    1,
                    vec![
                        CellValue::Text("row1".into()),
                        CellValue::Text("=cmd|' /C calc'!A0".into()),
                        CellValue::Uint(42),
                    ],
                ),
                Row::new(
                    2,
                    vec![
                        CellValue::Text("row2".into()),
                        CellValue::Text("+SUM(A1:A2)".into()),
                        CellValue::Uint(7),
                    ],
                ),
            ],
        );
        let opts = ForensicReportOptions::default();

        let formats = [
            ExportFormat::Csv,
            ExportFormat::Tsv,
            ExportFormat::Json,
            ExportFormat::Jsonl,
            ExportFormat::Html,
            ExportFormat::HtmlVertical,
            ExportFormat::Markdown,
        ];

        for fmt in formats {
            let rendered = render_table_report(&data, fmt, &opts).unwrap();
            let text = String::from_utf8(rendered).unwrap();
            assert!(!text.is_empty(), "empty render for {fmt}");
            assert!(text.contains("row1"), "missing row1 in {fmt}");
        }

        // Verify CSV spreadsheet formula neutralization
        let csv_text = String::from_utf8(render_table_report(&data, ExportFormat::Csv, &opts).unwrap()).unwrap();
        assert!(csv_text.contains("'=cmd|"));
        assert!(csv_text.contains("'+SUM("));

        let tsv_text = String::from_utf8(render_table_report(&data, ExportFormat::Tsv, &opts).unwrap()).unwrap();
        assert!(tsv_text.contains("'=cmd|"));
    }

    #[test]
    fn writes_single_table_report_with_custody_sidecar_and_merkle_roots() {
        let dir = tempdir().unwrap();
        let out_path = dir.path().join("nested").join("evtx_all.json");
        let data = sample_table(
            "evtx.all",
            vec![Row::new(
                1,
                vec![
                    CellValue::Text("k1".into()),
                    CellValue::Text("Security".into()),
                    CellValue::Uint(10),
                ],
            )],
        );
        let opts = ForensicReportOptions::default().with_case_metadata(
            Some("CASE-2026-01".into()),
            Some("Analyst".into()),
            Some("DFIR-WS01".into()),
            Some("offline:evtx".into()),
        );

        let report = write_table_report(&data, &out_path, ExportFormat::Json, &opts).unwrap();
        assert!(out_path.is_file());
        let sidecar = report.sidecar_path.as_ref().expect("sidecar path");
        assert!(sidecar.is_file());
        assert_eq!(sidecar, &sidecar_path_for(&out_path));
        assert_eq!(report.case_id.as_deref(), Some("CASE-2026-01"));

        let file_bytes = fs::read(&out_path).unwrap();
        let expected_sha256 = sha256_hex(&file_bytes);
        let expected_sha512 = sha512_hex(&file_bytes);

        let parsed_manifest: CustodyManifest = serde_json::from_slice(&fs::read(sidecar).unwrap()).unwrap();
        assert_eq!(parsed_manifest.artifact_count, 1);
        assert_eq!(parsed_manifest.total_bytes, file_bytes.len() as u64);
        assert_eq!(parsed_manifest.leaves[0].sha256, expected_sha256);
        assert_eq!(parsed_manifest.leaves[0].sha512, expected_sha512);
        assert_eq!(
            parsed_manifest.merkle_root_sha256,
            compute_merkle_root_sha256(&[expected_sha256])
        );
        assert_eq!(
            parsed_manifest.merkle_root_sha512,
            compute_merkle_root_sha512(&[expected_sha512])
        );
    }

    #[test]
    fn writes_bundle_report_with_unified_custody_manifest() {
        let dir = tempdir().unwrap();
        let out_dir = dir.path().join("bundle");

        let t1 = sample_table(
            "evtx.all",
            vec![Row::new(
                1,
                vec![
                    CellValue::Text("e1".into()),
                    CellValue::Text("v1".into()),
                    CellValue::Uint(1),
                ],
            )],
        );
        let t2 = sample_table(
            "hive.offline",
            vec![Row::new(
                1,
                vec![
                    CellValue::Text("h1".into()),
                    CellValue::Text("v2".into()),
                    CellValue::Uint(2),
                ],
            )],
        );
        let t3 = sample_table(
            "srum.net",
            vec![Row::new(
                1,
                vec![
                    CellValue::Text("s1".into()),
                    CellValue::Text("v3".into()),
                    CellValue::Uint(3),
                ],
            )],
        );

        let opts = ForensicReportOptions::default();
        let report = write_bundle_report(&[t1, t2, t3], &out_dir, ExportFormat::Csv, &opts).unwrap();
        assert_eq!(report.artifact_paths.len(), 3);
        for p in &report.artifact_paths {
            assert!(p.is_file(), "missing artifact {}", p.display());
        }

        let manifest_path = out_dir.join("custody_manifest.json");
        assert!(manifest_path.is_file());
        assert_eq!(report.sidecar_path.as_ref(), Some(&manifest_path));

        let manifest: CustodyManifest = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        assert_eq!(manifest.tool_id, "forensics2rust_bundle");
        assert_eq!(manifest.artifact_count, 3);
        assert_eq!(manifest.leaves.len(), 3);

        let sha256s: Vec<String> = manifest.leaves.iter().map(|l| l.sha256.clone()).collect();
        let sha512s: Vec<String> = manifest.leaves.iter().map(|l| l.sha512.clone()).collect();
        assert_eq!(manifest.merkle_root_sha256, compute_merkle_root_sha256(&sha256s));
        assert_eq!(manifest.merkle_root_sha512, compute_merkle_root_sha512(&sha512s));
    }

    #[test]
    fn diff_tables_detects_added_removed_and_modified_rows() {
        let left = sample_table(
            "hive.offline",
            vec![
                Row::new(
                    1,
                    vec![
                        CellValue::Text("k_same".into()),
                        CellValue::Text("same".into()),
                        CellValue::Uint(1),
                    ],
                ),
                Row::new(
                    2,
                    vec![
                        CellValue::Text("k_mod".into()),
                        CellValue::Text("before".into()),
                        CellValue::Uint(2),
                    ],
                ),
                Row::new(
                    3,
                    vec![
                        CellValue::Text("k_del".into()),
                        CellValue::Text("gone".into()),
                        CellValue::Uint(3),
                    ],
                ),
            ],
        );
        let right = sample_table(
            "hive.offline",
            vec![
                Row::new(
                    1,
                    vec![
                        CellValue::Text("k_same".into()),
                        CellValue::Text("same".into()),
                        CellValue::Uint(1),
                    ],
                ),
                Row::new(
                    2,
                    vec![
                        CellValue::Text("k_mod".into()),
                        CellValue::Text("after".into()),
                        CellValue::Uint(2),
                    ],
                ),
                Row::new(
                    3,
                    vec![
                        CellValue::Text("k_add".into()),
                        CellValue::Text("new".into()),
                        CellValue::Uint(4),
                    ],
                ),
            ],
        );

        let diff = diff_tables(&left, &right, &["item_key".to_string()]).unwrap();
        assert_eq!(diff.schema.tool_id, "table_text_compare");
        assert!(diff.rows.len() >= 3);
        let rendered = String::from_utf8(
            render_table_report(&diff, ExportFormat::Json, &ForensicReportOptions::default()).unwrap(),
        )
        .unwrap();
        assert!(rendered.contains("k_mod"));
        assert!(rendered.contains("k_del"));
        assert!(rendered.contains("k_add"));
    }
}
