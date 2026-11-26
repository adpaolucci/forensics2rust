#![forbid(unsafe_code)]

//! Streaming BOM-aware parser for `CBS.log` and `CBS.persist.log` (including gzipped `.gz`
//! archives) extracting Windows servicing package events, `KB\d{6,7}` identifiers,
//! `wcp.dll` build versions, and `HRESULT` errors while filtering routine applicability noise.

use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Read};
use std::path::Path;
use std::sync::LazyLock;

use chrono::NaiveDateTime;
use flate2::read::GzDecoder;
use forensics2rust_core::{DiagnosticWarning, ForensicError};
use regex::Regex;

use crate::discovery::{extract_build_version, extract_kb_articles};
use crate::store_db::FullUpdateRecord;

static CBS_LINE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\s+([A-Za-z]+)\s+([A-Za-z0-9_.-]+)\s+(.*)$")
        .expect("valid CBS log line regex")
});

static PACKAGE_NAME_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(Package_for_[A-Za-z0-9_.~-]+)").expect("valid CBS package regex"));

static HRESULT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:HRESULT\s*=\s*|status:\s*|error:\s*)(0x[0-9A-Fa-f]{8})").expect("valid HRESULT regex")
});

/// Parses a `CBS.log` / `CBS.persist.log` file from disk using streaming `BufReader` I/O.
pub fn parse_cbs_log_path(path: &Path) -> Result<(Vec<FullUpdateRecord>, Vec<DiagnosticWarning>), ForensicError> {
    let source_label = path.display().to_string();
    let mut file = File::open(path).map_err(|e| ForensicError::io_classified(source_label.clone(), e))?;
    let mut head = [0u8; 4];
    let n = file
        .read(&mut head)
        .map_err(|e| ForensicError::io_classified(source_label.clone(), e))?;

    // Reopen cleanly from offset 0 for streaming dispatch.
    drop(file);
    let file = File::open(path).map_err(|e| ForensicError::io_classified(source_label.clone(), e))?;

    if n >= 2 && head[0] == 0x1F && head[1] == 0x8B {
        let gz = GzDecoder::new(BufReader::new(file));
        return parse_cbs_log_stream(BufReader::new(gz), &source_label, false);
    }
    if n >= 2 && head[0] == 0xFF && head[1] == 0xFE {
        return parse_cbs_utf16le_stream(file, &source_label);
    }

    parse_cbs_log_stream(BufReader::new(file), &source_label, true)
}

/// Parses `CBS.log` content from an in-memory byte slice (supporting UTF-8 BOM, UTF-16LE BOM, and `.gz`).
pub fn parse_cbs_log_bytes(
    bytes: &[u8],
    source_label: &str,
) -> Result<(Vec<FullUpdateRecord>, Vec<DiagnosticWarning>), ForensicError> {
    if bytes.starts_with(&[0x1F, 0x8B]) {
        let gz = GzDecoder::new(Cursor::new(bytes));
        return parse_cbs_log_stream(BufReader::new(gz), source_label, false);
    }
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return parse_cbs_utf16le_stream(Cursor::new(bytes), source_label);
    }
    parse_cbs_log_stream(BufReader::new(Cursor::new(bytes)), source_label, true)
}

fn parse_cbs_utf16le_stream<R: Read>(
    mut reader: R,
    source_label: &str,
) -> Result<(Vec<FullUpdateRecord>, Vec<DiagnosticWarning>), ForensicError> {
    let mut state = CbsParseState::new(source_label);
    let mut chunk = [0u8; 8192];
    let mut line_units: Vec<u16> = Vec::with_capacity(256);
    let mut carry: Option<u8> = None;
    let mut bom_checked = false;

    loop {
        let n = reader
            .read(&mut chunk)
            .map_err(|e| ForensicError::io_classified(source_label, e))?;
        if n == 0 {
            break;
        }
        for &b in &chunk[..n] {
            let Some(lo) = carry.take() else {
                carry = Some(b);
                continue;
            };
            let unit = u16::from_le_bytes([lo, b]);
            if !bom_checked {
                bom_checked = true;
                if unit == 0xFEFF {
                    continue;
                }
            }
            if unit == 0x000A {
                let line = String::from_utf16_lossy(&line_units);
                let trimmed = line.trim_start_matches('\u{FEFF}').trim_end_matches(['\r', '\n']);
                state.process_line(trimmed);
                line_units.clear();
            } else {
                line_units.push(unit);
            }
        }
    }

    if !line_units.is_empty() {
        let line = String::from_utf16_lossy(&line_units);
        let trimmed = line.trim_start_matches('\u{FEFF}').trim_end_matches(['\r', '\n']);
        state.process_line(trimmed);
    }

    Ok(state.finish())
}

/// Streams UTF-8 (optionally BOM-prefixed) lines from any `BufRead` without loading the full file into RAM.
pub fn parse_cbs_log_reader<R: BufRead>(
    reader: R,
    source_label: &str,
) -> Result<(Vec<FullUpdateRecord>, Vec<DiagnosticWarning>), ForensicError> {
    parse_cbs_log_stream(reader, source_label, true)
}

fn parse_cbs_log_stream<R: BufRead>(
    mut reader: R,
    source_label: &str,
    check_bom: bool,
) -> Result<(Vec<FullUpdateRecord>, Vec<DiagnosticWarning>), ForensicError> {
    let mut first_line_checked = !check_bom;
    let mut buf = Vec::with_capacity(512);
    let mut state = CbsParseState::new(source_label);

    loop {
        buf.clear();
        let bytes_read = reader
            .read_until(b'\n', &mut buf)
            .map_err(|e| ForensicError::io_classified(source_label, e))?;
        if bytes_read == 0 {
            break;
        }
        let mut slice = buf.as_slice();
        if !first_line_checked {
            first_line_checked = true;
            if let Some(stripped) = slice.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
                slice = stripped;
            }
        }
        let line = String::from_utf8_lossy(slice);
        let trimmed = line.trim_end_matches(['\r', '\n']);
        state.process_line(trimmed);
    }

    Ok(state.finish())
}

struct CbsParseState {
    source_label: String,
    source_db: String,
    current_build: Option<String>,
    records: Vec<FullUpdateRecord>,
    warnings: Vec<DiagnosticWarning>,
}

impl CbsParseState {
    fn new(source_label: &str) -> Self {
        let file_name = Path::new(source_label)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("CBS.log")
            .to_string();
        Self {
            source_label: source_label.to_string(),
            source_db: file_name,
            current_build: None,
            records: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn process_line(&mut self, line: &str) {
        let line = line.trim_start_matches('\u{FEFF}').trim();
        if line.is_empty() {
            return;
        }

        let Some(caps) = CBS_LINE_REGEX.captures(line) else {
            return;
        };

        let ts_str = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let level = caps.get(2).map(|m| m.as_str()).unwrap_or("Info");
        let component = caps.get(3).map(|m| m.as_str()).unwrap_or("CBS");
        let msg = caps.get(4).map(|m| m.as_str()).unwrap_or("");

        // Track active wcp.dll servicing stack build version.
        if msg.contains("WcpInitialize")
            && let Some(ver) = extract_build_version(msg)
        {
            self.current_build = Some(ver);
        }

        // Filter out high-volume routine applicability and cache probes.
        if is_cbs_noise(msg) {
            return;
        }

        let kbs = extract_kb_articles(&[msg]);
        let pkg_name = PACKAGE_NAME_REGEX
            .captures(msg)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());
        let hresult = HRESULT_REGEX
            .captures(msg)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        let is_error_level = level.eq_ignore_ascii_case("Error") || level.eq_ignore_ascii_case("Warning");
        let is_high_signal = pkg_name.is_some()
            || !kbs.is_empty()
            || msg.contains("Exec: Processing complete")
            || msg.contains("Finalized")
            || msg.contains("Committed")
            || msg.contains("Plan: Package:")
            || msg.contains("WcpInitialize")
            || (is_error_level && hresult.is_some());

        if !is_high_signal {
            return;
        }

        let install_date = NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%d %H:%M:%S")
            .ok()
            .map(|ndt| ndt.and_utc());

        let category = if is_error_level && hresult.is_some() {
            "ServicingError".to_string()
        } else if msg.contains("RollupFix") {
            "RollupFix".to_string()
        } else if msg.contains("WcpInitialize") {
            "ServicingStack".to_string()
        } else {
            component.to_string()
        };

        let kb_number = if kbs.is_empty() { None } else { Some(kbs.join("; ")) };

        let build_version = pkg_name
            .as_deref()
            .and_then(extract_build_version)
            .or_else(|| extract_build_version(msg))
            .or_else(|| self.current_build.clone());

        let title = if let Some(ref pkg) = pkg_name {
            if let Some(ref hr) = hresult {
                format!("{pkg} ({hr})")
            } else {
                pkg.clone()
            }
        } else if let Some(ref kb) = kb_number {
            if let Some(ref hr) = hresult {
                format!("{kb} ({hr})")
            } else {
                format!("CBS Servicing Event ({kb})")
            }
        } else {
            truncate_msg(msg, 160)
        };

        let result = if let Some(ref hr) = hresult {
            Some(hr.clone())
        } else if is_error_level {
            Some(level.to_string())
        } else if msg.contains("Finalized") || msg.contains("Committed") || msg.contains("complete") {
            Some("Completed".to_string())
        } else {
            Some(level.to_string())
        };

        self.records.push(FullUpdateRecord {
            title,
            install_date,
            kb_number,
            category,
            build_version,
            source_db: self.source_db.clone(),
            update_id: pkg_name.clone(),
            result,
            description: Some(msg.to_string()),
            more_info_url: None,
            provider_id: Some(component.to_string()),
            detail_extra: serde_json::json!({
                "level": level,
                "component": component,
                "package": pkg_name,
                "hresult": hresult,
                "wcp_build": self.current_build,
                "source_label": self.source_label,
            }),
        });
    }

    fn finish(self) -> (Vec<FullUpdateRecord>, Vec<DiagnosticWarning>) {
        (self.records, self.warnings)
    }
}

fn is_cbs_noise(msg: &str) -> bool {
    msg.contains("Perf: LRU Cache")
        || (msg.contains("Read out cached applicability") && msg.contains("ApplicableState: 0"))
        || (msg.contains("InternalOpenPackage failed") && msg.contains("CBS_E_INVALID_PACKAGE"))
        || msg.contains("Appl: detect Parent")
        || msg.contains("Exec: Processing started")
}

fn truncate_msg(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let head: String = s.chars().take(max_chars.saturating_sub(3)).collect();
        format!("{head}...")
    }
}
