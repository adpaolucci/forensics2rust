#![forbid(unsafe_code)]

//! Artifact magic-byte sniffing, directory discovery, RAII temp SQLite helper,
//! and shared timestamp / KB / build-version extractors for `forensics2rust-posture`.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, FixedOffset, NaiveDate, NaiveDateTime, TimeZone, Utc};
use forensics2rust_core::{DiagnosticWarning, ForensicError, WarningSeverity, filetime_to_utc, read_utf16_le};
use regex::Regex;
use walkdir::WalkDir;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

static KB_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:^|[^A-Za-z0-9])KB(\d{6,7})(?:[^0-9]|$)").expect("valid KB regex"));

static WCP_VERSION_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)wcp\.dll\s+version\s+(\d+\.\d+\.\d+\.\d+)").expect("valid wcp version regex"));

static WIN_BUILD_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:10\.0\.)?(?:1\d{4}|2\d{4})\.\d+(?:\.\d+)*\b").expect("valid build version regex")
});

/// Detected posture artifact format from header / magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    Ese,
    Sqlite,
    Regf,
    Json,
    CbsLog,
    GzipCbsLog,
    Unknown,
}

/// RAII temporary file for opening `OfflineBytes` or sharing-locked SQLite databases
/// read-only via `rusqlite` without requiring `tempfile` in `[dependencies]`.
pub struct TempDbFile {
    path: PathBuf,
}

impl TempDbFile {
    pub fn from_bytes(bytes: &[u8], prefix: &str) -> Result<Self, ForensicError> {
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        for _ in 0..64 {
            let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let candidate = dir.join(format!("{prefix}_{pid}_{seq}.tmp"));
            match OpenOptions::new().write(true).create_new(true).open(&candidate) {
                Ok(mut file) => {
                    if let Err(err) = file.write_all(bytes).and_then(|()| file.flush()) {
                        drop(file);
                        let _ = fs::remove_file(&candidate);
                        return Err(ForensicError::io(candidate.display().to_string(), err));
                    }
                    return Ok(Self { path: candidate });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(ForensicError::io_classified(candidate.display().to_string(), err)),
            }
        }
        Err(ForensicError::parse(
            "TempDbFile",
            "unable to allocate unique temporary SQLite file after 64 attempts",
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDbFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Sniffs magic bytes of an in-memory buffer to classify its posture artifact kind.
pub fn sniff_magic(bytes: &[u8]) -> ArtifactKind {
    if bytes.len() >= 8 && bytes[4..8] == [0xEF, 0xCD, 0xAB, 0x89] {
        return ArtifactKind::Ese;
    }
    if bytes.starts_with(b"SQLite format 3\0") {
        return ArtifactKind::Sqlite;
    }
    if bytes.starts_with(b"regf") {
        return ArtifactKind::Regf;
    }
    if bytes.starts_with(&[0x1F, 0x8B]) {
        return ArtifactKind::GzipCbsLog;
    }

    let utf8_body = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    if let Ok(text) = std::str::from_utf8(&utf8_body[..utf8_body.len().min(4096)]) {
        let trimmed = text.trim_start();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            return ArtifactKind::Json;
        }
        if looks_like_cbs_text(trimmed) {
            return ArtifactKind::CbsLog;
        }
    }

    if bytes.starts_with(&[0xFF, 0xFE]) && bytes.len() >= 4 {
        let sample_len = bytes.len().min(4096);
        let decoded = read_utf16_le(&bytes[2..sample_len]);
        let trimmed = decoded.trim_start();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            return ArtifactKind::Json;
        }
        if looks_like_cbs_text(trimmed) {
            return ArtifactKind::CbsLog;
        }
    }

    // Also allow UTF-8 lossy probe for logs containing occasional non-UTF8 bytes.
    let lossy = String::from_utf8_lossy(&utf8_body[..utf8_body.len().min(4096)]);
    if looks_like_cbs_text(lossy.trim_start()) {
        return ArtifactKind::CbsLog;
    }

    ArtifactKind::Unknown
}

fn looks_like_cbs_text(text: &str) -> bool {
    for line in text.lines().take(12) {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        if l.len() >= 20
            && l.as_bytes().get(4) == Some(&b'-')
            && l.as_bytes().get(7) == Some(&b'-')
            && l.as_bytes().get(10) == Some(&b' ')
            && l.as_bytes().get(13) == Some(&b':')
            && l.as_bytes().get(16) == Some(&b':')
            && l.as_bytes().get(19) == Some(&b',')
        {
            return true;
        }
        if l.contains("WcpInitialize") || l.contains("CBS ") || l.contains("CSI ") {
            return true;
        }
    }
    false
}

fn is_cbs_log_filename(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    name.starts_with("cbs") && name.ends_with(".log")
}

fn is_bom_only_or_blank_text(bytes: &[u8]) -> bool {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return std::str::from_utf8(rest).is_ok_and(|s| s.trim().is_empty());
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return rest.len() % 2 == 0 && read_utf16_le(rest).trim().is_empty();
    }
    false
}

/// Reads up to 4096 header bytes of a file and classifies its format.
pub fn sniff_file_head(path: &Path) -> Result<ArtifactKind, ForensicError> {
    let mut file = File::open(path).map_err(|e| ForensicError::io_classified(path.display().to_string(), e))?;
    let mut buf = [0u8; 4096];
    let n = file
        .read(&mut buf)
        .map_err(|e| ForensicError::io_classified(path.display().to_string(), e))?;
    let kind = sniff_magic(&buf[..n]);
    if kind == ArtifactKind::Unknown && is_cbs_log_filename(path) && is_bom_only_or_blank_text(&buf[..n]) {
        return Ok(ArtifactKind::CbsLog);
    }
    Ok(kind)
}

/// Recursively walks `dir` collecting files matching `predicate`, recording unreadable
/// subdirectory warnings instead of aborting traversal.
pub fn discover_files_in_dir<F>(
    dir: &Path,
    tool_id: &str,
    warnings: &mut Vec<DiagnosticWarning>,
    mut predicate: F,
) -> Vec<PathBuf>
where
    F: FnMut(&Path) -> bool,
{
    let mut matches = Vec::new();
    for entry in WalkDir::new(dir).follow_links(false).max_depth(8) {
        match entry {
            Ok(ent) => {
                if ent.file_type().is_file() && predicate(ent.path()) {
                    matches.push(ent.path().to_path_buf());
                }
            }
            Err(err) => {
                warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Warn,
                    tool_id: tool_id.to_string(),
                    source: dir.display().to_string(),
                    message: format!("directory walk warning: {err}"),
                });
            }
        }
    }
    matches.sort();
    matches
}

/// Parses a WMI CIM datetime string (`YYYYMMDDHHMMSS.ffffff±UUU` or `+***`) into `DateTime<Utc>`.
pub fn parse_cim_datetime(raw: &str) -> Option<DateTime<Utc>> {
    let s = raw.trim();
    if s.len() < 14 || !s.as_bytes()[..14].iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let year: i32 = s.get(0..4)?.parse().ok()?;
    let month: u32 = s.get(4..6)?.parse().ok()?;
    let day: u32 = s.get(6..8)?.parse().ok()?;
    let hour: u32 = s.get(8..10)?.parse().ok()?;
    let min: u32 = s.get(10..12)?.parse().ok()?;
    let sec: u32 = s.get(12..14)?.parse().ok()?;

    let mut micros: u32 = 0;
    let mut tz_part = "";
    if let Some(after_dot) = s.get(14..) {
        if let Some(rest) = after_dot.strip_prefix('.') {
            let digits_end = rest.find(['+', '-']).unwrap_or(rest.len());
            let frac = &rest[..digits_end];
            if !frac.is_empty() && !frac.starts_with('*') {
                let padded = format!("{frac:0<6}");
                micros = padded.get(..6).and_then(|p| p.parse().ok()).unwrap_or(0);
            }
            tz_part = &rest[digits_end..];
        } else {
            tz_part = after_dot;
        }
    }

    let naive = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_micro_opt(hour, min, sec, micros)?;
    if tz_part.len() >= 2 && (tz_part.starts_with('+') || tz_part.starts_with('-')) {
        let sign: i32 = if tz_part.starts_with('-') { -1 } else { 1 };
        let mins_str = &tz_part[1..];
        if !mins_str.starts_with('*')
            && let Ok(mins) = mins_str.parse::<i32>()
            && let Some(offset) = FixedOffset::east_opt(sign * mins * 60)
            && let Some(local_dt) = offset.from_local_datetime(&naive).single()
        {
            return Some(local_dt.with_timezone(&Utc));
        }
    }

    Some(naive.and_utc())
}

/// Parses timestamps across Windows FILETIME, Unix ms/s, RFC 3339, RFC 2822, WMI CIM, and
/// ISO-like naive UTC strings.
pub fn parse_flexible_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    let s = raw.trim().trim_matches('"').trim();
    if s.is_empty() || s.eq_ignore_ascii_case("null") || s.eq_ignore_ascii_case("none") {
        return None;
    }

    if s.bytes().all(|b| b.is_ascii_digit())
        && let Ok(num) = s.parse::<u64>()
    {
        if num == 0 {
            return None;
        }
        // 17-19 digit Windows FILETIME (e.g., 133700000000000000)
        if (17..=19).contains(&s.len()) {
            return filetime_to_utc(num);
        }
        // 12-16 digit Unix milliseconds (e.g., 1731094054357)
        if (12..=16).contains(&s.len())
            && let Ok(ms) = i64::try_from(num)
        {
            return DateTime::from_timestamp_millis(ms);
        }
        // 9-11 digit Unix seconds
        if (9..=11).contains(&s.len())
            && let Ok(secs) = i64::try_from(num)
        {
            return DateTime::from_timestamp(secs, 0);
        }
    }

    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(dt) = DateTime::parse_from_rfc2822(s) {
        return Some(dt.with_timezone(&Utc));
    }
    if s.len() >= 14
        && s.as_bytes().get(14) == Some(&b'.')
        && let Some(dt) = parse_cim_datetime(s)
    {
        return Some(dt);
    }

    for fmt in [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
    ] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(ndt.and_utc());
        }
    }

    if let Ok(nd) = NaiveDate::parse_from_str(s, "%Y-%m-%d")
        && let Some(ndt) = nd.and_hms_opt(0, 0, 0)
    {
        return Some(ndt.and_utc());
    }

    None
}

/// Extracts deduplicated uppercase `KB\d{6,7}` identifiers across one or more text fields.
pub fn extract_kb_articles(texts: &[&str]) -> Vec<String> {
    let mut found = Vec::new();
    for text in texts {
        let mut pos = 0;
        while pos < text.len() {
            let Some(cap) = KB_REGEX.captures_at(text, pos) else {
                break;
            };
            if let Some(digits) = cap.get(1) {
                let kb = format!("KB{}", digits.as_str());
                if !found.contains(&kb) {
                    found.push(kb);
                }
                pos = digits.end();
            } else {
                break;
            }
        }
    }
    found
}

/// Extracts a Windows build or `wcp.dll` version string from text if present.
pub fn extract_build_version(text: &str) -> Option<String> {
    if let Some(cap) = WCP_VERSION_REGEX.captures(text)
        && let Some(ver) = cap.get(1)
    {
        return Some(ver.as_str().to_string());
    }
    WIN_BUILD_REGEX.find(text).map(|m| m.as_str().to_string())
}

/// Normalizes a GUID string to lowercase hyphenated UUID without braces when possible.
pub fn normalize_guid_str(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("null") {
        return None;
    }
    let stripped = trimmed.trim_start_matches('{').trim_end_matches('}').trim();
    if stripped.is_empty() || stripped.eq_ignore_ascii_case("null") {
        return None;
    }
    Some(stripped.to_ascii_lowercase())
}
