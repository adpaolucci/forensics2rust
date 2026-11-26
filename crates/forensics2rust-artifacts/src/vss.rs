#![forbid(unsafe_code)]

//! Pure-Rust Volume Shadow Copy (VSS) metadata parsers (`Win32_ShadowCopy` CIM
//! datetimes, `vssadmin list shadows`, JSON catalogs) and safe read-only file
//! restoration helpers (`restore_previous_file`, `restore_previous_file_into_dir`).

use std::fs;
use std::path::{Component, Path, PathBuf};

use chrono::{DateTime, FixedOffset, NaiveDate, NaiveDateTime, TimeZone, Utc};
use forensics2rust_core::{ForensicError, ForensicSource};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowCopyRecord {
    pub shadow_copy_name: String,
    pub device_object: String,
    pub volume_name: String,
    pub created_time: Option<DateTime<Utc>>,
    pub snapshot_id: String,
    pub originating_machine: String,
    pub service_machine: String,
    pub provider_id: String,
    pub set_id: Option<String>,
    pub attributes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviousFileRecord {
    pub filename: String,
    pub folder: String,
    pub snapshot_date: Option<DateTime<Utc>>,
    pub file_size: u64,
    pub modified_time: Option<DateTime<Utc>>,
    pub shadow_volume_path: String,
}

#[derive(Debug, Clone)]
pub struct PreviousFilesOptions {
    pub target_subpath: Option<String>,
    pub max_depth: usize,
    pub max_entries: usize,
}

impl Default for PreviousFilesOptions {
    fn default() -> Self {
        Self {
            target_subpath: Some("Users".to_string()),
            max_depth: 4,
            max_entries: 5_000,
        }
    }
}

/// Parses a WMI CIM datetime string (`YYYYMMDDHHMMSS.ffffff±UUU`) into `DateTime<Utc>`.
pub fn parse_cim_datetime(raw: &str) -> Option<DateTime<Utc>> {
    let s = raw.trim();
    if s.len() < 14 {
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

#[derive(Debug, Deserialize)]
struct ShadowCatalogWrapper {
    shadow_copies: Vec<ShadowCopyRecord>,
}

pub fn parse_vss_json(bytes: &[u8]) -> Result<Vec<ShadowCopyRecord>, ForensicError> {
    if let Ok(list) = serde_json::from_slice::<Vec<ShadowCopyRecord>>(bytes) {
        return Ok(list);
    }
    if let Ok(wrapper) = serde_json::from_slice::<ShadowCatalogWrapper>(bytes) {
        return Ok(wrapper.shadow_copies);
    }
    if let Ok(single) = serde_json::from_slice::<ShadowCopyRecord>(bytes) {
        return Ok(vec![single]);
    }
    Err(ForensicError::parse("VSS", "invalid VSS JSON catalog"))
}

fn parse_vssadmin_datetime(s: &str) -> Option<DateTime<Utc>> {
    let trimmed = s.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in [
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M:%S",
    ] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(trimmed, fmt) {
            return Some(ndt.and_utc());
        }
    }
    None
}

/// Parses `vssadmin list shadows` text output into `ShadowCopyRecord` entries.
pub fn parse_vssadmin_text(text: &str) -> Vec<ShadowCopyRecord> {
    let mut records = Vec::new();
    let mut current: Option<ShadowCopyRecord> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("Contents of shadow copy set ID:") {
            let set_id = line.split_once(':').map(|(_, v)| v.trim().to_string());
            if let Some(ref mut cur) = current {
                cur.set_id = set_id;
            }
            continue;
        }
        if line.contains("creation time:") {
            if let Some(prev) = current.take()
                && !prev.snapshot_id.is_empty()
            {
                records.push(prev);
            }
            let created_time = line
                .split_once("creation time:")
                .and_then(|(_, v)| parse_vssadmin_datetime(v));
            current = Some(ShadowCopyRecord {
                shadow_copy_name: String::new(),
                device_object: String::new(),
                volume_name: String::new(),
                created_time,
                snapshot_id: String::new(),
                originating_machine: String::new(),
                service_machine: String::new(),
                provider_id: String::new(),
                set_id: None,
                attributes: None,
            });
            continue;
        }
        if let Some(ref mut cur) = current
            && let Some((k, v)) = line.split_once(':')
        {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key.starts_with("shadow copy id") {
                cur.snapshot_id = val;
            } else if key.starts_with("original volume") {
                cur.volume_name = val;
            } else if key.starts_with("shadow copy volume") {
                cur.shadow_copy_name = val.rsplit(['\\', '/']).next().unwrap_or(&val).to_string();
                cur.device_object = val;
            } else if key.starts_with("originating machine") {
                cur.originating_machine = val;
            } else if key.starts_with("service machine") {
                cur.service_machine = val;
            } else if key.starts_with("provider id") {
                cur.provider_id = val;
            } else if key.starts_with("attributes") {
                cur.attributes = Some(val);
            }
        }
    }

    if let Some(last) = current
        && !last.snapshot_id.is_empty()
    {
        records.push(last);
    }
    records
}

pub fn load_offline_shadow_copies(source: &ForensicSource) -> Result<Vec<ShadowCopyRecord>, ForensicError> {
    match source {
        ForensicSource::Live => Err(ForensicError::InvalidArgument(
            "load_offline_shadow_copies called with Live source".to_string(),
        )),
        ForensicSource::OfflineBytes(bytes) => {
            if let Ok(recs) = parse_vss_json(bytes) {
                return Ok(recs);
            }
            let text = String::from_utf8_lossy(bytes);
            let recs = parse_vssadmin_text(&text);
            if recs.is_empty() && !text.trim().is_empty() {
                return Err(ForensicError::parse("VSS", "unrecognized offline VSS catalog format"));
            }
            Ok(recs)
        }
        ForensicSource::OfflinePath(path) => {
            if !path.exists() {
                return Err(ForensicError::NotFound(path.display().to_string()));
            }
            if path.is_file() {
                let bytes =
                    fs::read(path).map_err(|err| ForensicError::io_classified(path.display().to_string(), err))?;
                return load_offline_shadow_copies(&ForensicSource::OfflineBytes(bytes));
            }
            if path.is_dir() {
                for name in ["vss_catalog.json", "shadows.json", "vssadmin.txt"] {
                    let candidate = path.join(name);
                    if candidate.is_file() {
                        let bytes = fs::read(&candidate)
                            .map_err(|err| ForensicError::io_classified(candidate.display().to_string(), err))?;
                        return load_offline_shadow_copies(&ForensicSource::OfflineBytes(bytes));
                    }
                }

                // Discover HarddiskVolumeShadowCopy* directories
                let mut records = Vec::new();
                let entries =
                    fs::read_dir(path).map_err(|err| ForensicError::io_classified(path.display().to_string(), err))?;
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir()
                        && let Some(name) = p.file_name().and_then(|n| n.to_str())
                        && name.to_ascii_lowercase().starts_with("harddiskvolumeshadowcopy")
                    {
                        let meta_path = p.join("shadow_metadata.json");
                        if meta_path.is_file()
                            && let Ok(bytes) = fs::read(&meta_path)
                            && let Ok(mut parsed) = parse_vss_json(&bytes)
                        {
                            records.append(&mut parsed);
                            continue;
                        }
                        let created = fs::metadata(&p)
                            .ok()
                            .and_then(|m| m.modified().ok())
                            .map(DateTime::<Utc>::from);
                        records.push(ShadowCopyRecord {
                            shadow_copy_name: name.to_string(),
                            device_object: p.display().to_string(),
                            volume_name: "\\\\?\\Volume{offline}\\".to_string(),
                            created_time: created,
                            snapshot_id: format!("{{{name}}}"),
                            originating_machine: "OFFLINE".to_string(),
                            service_machine: "OFFLINE".to_string(),
                            provider_id: "{b5946137-7b9f-4925-af80-51abd60b20d5}".to_string(),
                            set_id: None,
                            attributes: Some("OfflineDirectory".to_string()),
                        });
                    }
                }
                return Ok(records);
            }
            Err(ForensicError::NotFound(path.display().to_string()))
        }
    }
}

pub fn enumerate_shadow_root_files(
    shadow_root: &Path,
    snapshot_date: Option<DateTime<Utc>>,
    opts: &PreviousFilesOptions,
) -> Vec<PreviousFileRecord> {
    let mut out = Vec::new();
    let walk_root = match &opts.target_subpath {
        Some(sub) if !sub.trim().is_empty() => {
            let candidate = shadow_root.join(sub.trim_matches(['\\', '/']));
            if candidate.exists() {
                candidate
            } else {
                shadow_root.to_path_buf()
            }
        }
        _ => shadow_root.to_path_buf(),
    };

    for entry in WalkDir::new(&walk_root)
        .follow_links(false)
        .max_depth(opts.max_depth.max(1))
        .into_iter()
        .flatten()
    {
        if out.len() >= opts.max_entries {
            break;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
            n.eq_ignore_ascii_case("shadow_metadata.json") || n.eq_ignore_ascii_case("vss_catalog.json")
        }) {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
        let folder = path.parent().map(|p| p.display().to_string()).unwrap_or_default();
        let modified_time = meta.modified().ok().map(DateTime::<Utc>::from);

        out.push(PreviousFileRecord {
            filename,
            folder,
            snapshot_date,
            file_size: meta.len(),
            modified_time,
            shadow_volume_path: path.display().to_string(),
        });
    }

    out
}

pub fn load_offline_previous_files(
    source: &ForensicSource,
    opts: &PreviousFilesOptions,
) -> Result<Vec<PreviousFileRecord>, ForensicError> {
    match source {
        ForensicSource::Live => Err(ForensicError::InvalidArgument(
            "load_offline_previous_files called with Live source".to_string(),
        )),
        ForensicSource::OfflineBytes(bytes) => serde_json::from_slice::<Vec<PreviousFileRecord>>(bytes)
            .map_err(|e| ForensicError::parse("PreviousFiles", format!("invalid JSON file index: {e}"))),
        ForensicSource::OfflinePath(path) => {
            if !path.exists() {
                return Err(ForensicError::NotFound(path.display().to_string()));
            }
            if path.is_file() {
                let bytes =
                    fs::read(path).map_err(|err| ForensicError::io_classified(path.display().to_string(), err))?;
                return load_offline_previous_files(&ForensicSource::OfflineBytes(bytes), opts);
            }
            if path.is_dir() {
                // Check for vss_catalog.json / shadows.json to map shadow dirs -> snapshot_date
                let catalog = load_offline_shadow_copies(source).unwrap_or_default();
                let mut results = Vec::new();
                let mut found_shadow_subdirs = false;

                if let Ok(entries) = fs::read_dir(path) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.is_dir()
                            && let Some(name) = p.file_name().and_then(|n| n.to_str())
                            && name.to_ascii_lowercase().starts_with("harddiskvolumeshadowcopy")
                        {
                            found_shadow_subdirs = true;
                            let remaining = opts.max_entries.saturating_sub(results.len());
                            if remaining == 0 {
                                break;
                            }
                            let snap_date = catalog
                                .iter()
                                .find(|c| {
                                    c.shadow_copy_name.eq_ignore_ascii_case(name)
                                        || c.device_object
                                            .to_ascii_lowercase()
                                            .ends_with(&name.to_ascii_lowercase())
                                })
                                .and_then(|c| c.created_time)
                                .or_else(|| {
                                    fs::metadata(&p)
                                        .ok()
                                        .and_then(|m| m.modified().ok())
                                        .map(DateTime::<Utc>::from)
                                });
                            let mut per_shadow_opts = opts.clone();
                            per_shadow_opts.max_entries = remaining;
                            results.extend(enumerate_shadow_root_files(&p, snap_date, &per_shadow_opts));
                        }
                    }
                }

                if !found_shadow_subdirs {
                    results.extend(enumerate_shadow_root_files(path, None, opts));
                }
                return Ok(results);
            }
            Err(ForensicError::NotFound(path.display().to_string()))
        }
    }
}

fn contains_parent_dir(path: &Path) -> bool {
    path.components().any(|c| matches!(c, Component::ParentDir))
}

fn is_raw_shadow_device_path(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    lower.starts_with(r"\\?\globalroot\") || lower.starts_with(r"\\.\globalroot\")
}

fn check_no_symlink_components(path: &Path, allow_not_found: bool) -> Result<(), ForensicError> {
    let mut prefix = PathBuf::new();
    for comp in path.components() {
        prefix.push(comp);
        match comp {
            Component::Prefix(_) | Component::RootDir | Component::CurDir => continue,
            Component::ParentDir => {
                return Err(ForensicError::InvalidArgument(
                    "path traversal ('..') is prohibited in restore_previous_file".to_string(),
                ));
            }
            Component::Normal(_) => match fs::symlink_metadata(&prefix) {
                Ok(m) => {
                    if m.file_type().is_symlink() {
                        return Err(ForensicError::InvalidArgument(format!(
                            "refusing symlink or junction path component: {}",
                            prefix.display()
                        )));
                    }
                }
                Err(err) if allow_not_found && err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(ForensicError::io_classified(prefix.display().to_string(), err));
                }
            },
        }
    }
    Ok(())
}

fn paths_match_canonical(a: &Path, b: &Path) -> bool {
    #[cfg(windows)]
    {
        a.as_os_str().eq_ignore_ascii_case(b.as_os_str())
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}

/// Safely copies a single file from a read-only shadow volume or offline directory
/// to `dest_path`, rejecting `..` path traversal, symlinks/junctions, and same-file
/// destinations that would truncate the source.
pub fn restore_previous_file(shadow_file: &Path, dest_path: &Path) -> Result<u64, ForensicError> {
    if shadow_file.as_os_str().is_empty() || dest_path.as_os_str().is_empty() {
        return Err(ForensicError::InvalidArgument(
            "shadow_file and dest_path must be non-empty".to_string(),
        ));
    }
    if contains_parent_dir(shadow_file) || contains_parent_dir(dest_path) {
        return Err(ForensicError::InvalidArgument(
            "path traversal ('..') is prohibited in restore_previous_file".to_string(),
        ));
    }

    let raw_device_src = is_raw_shadow_device_path(shadow_file);
    if !raw_device_src {
        check_no_symlink_components(shadow_file, false)?;
    }

    let meta = fs::symlink_metadata(shadow_file)
        .map_err(|err| ForensicError::io_classified(shadow_file.display().to_string(), err))?;
    if meta.file_type().is_symlink() {
        return Err(ForensicError::InvalidArgument(format!(
            "refusing to copy symlink source: {}",
            shadow_file.display()
        )));
    }
    if !meta.file_type().is_file() {
        return Err(ForensicError::InvalidArgument(format!(
            "source is not a regular file: {}",
            shadow_file.display()
        )));
    }

    check_no_symlink_components(dest_path, true)?;

    let mut reader = fs::File::open(shadow_file)
        .map_err(|err| ForensicError::io_classified(shadow_file.display().to_string(), err))?;

    if !raw_device_src {
        let canon_src = fs::canonicalize(shadow_file)
            .map_err(|err| ForensicError::io_classified(shadow_file.display().to_string(), err))?;
        if fs::symlink_metadata(dest_path).is_ok() {
            let canon_dest = fs::canonicalize(dest_path)
                .map_err(|err| ForensicError::io_classified(dest_path.display().to_string(), err))?;
            if paths_match_canonical(&canon_src, &canon_dest) {
                return Err(ForensicError::InvalidArgument(
                    "destination resolves to the same path as source".to_string(),
                ));
            }
            if let Ok(existing_dest) = fs::File::open(dest_path)
                && crate::live::files_share_same_id(&reader, &existing_dest)
            {
                return Err(ForensicError::InvalidArgument(
                    "destination resolves to the same file as source".to_string(),
                ));
            }
        } else if let Some(parent) = dest_path.parent()
            && !parent.as_os_str().is_empty()
            && parent.exists()
            && let (Ok(canon_parent), Some(fname)) = (fs::canonicalize(parent), dest_path.file_name())
            && paths_match_canonical(&canon_src, &canon_parent.join(fname))
        {
            return Err(ForensicError::InvalidArgument(
                "destination resolves to the same path as source".to_string(),
            ));
        }
    } else if fs::symlink_metadata(dest_path).is_ok()
        && let Ok(existing_dest) = fs::File::open(dest_path)
        && crate::live::files_share_same_id(&reader, &existing_dest)
    {
        return Err(ForensicError::InvalidArgument(
            "destination resolves to the same file as source".to_string(),
        ));
    }

    if let Some(parent) = dest_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|err| ForensicError::io_classified(parent.display().to_string(), err))?;
    }
    let mut writer = fs::File::create(dest_path)
        .map_err(|err| ForensicError::io_classified(dest_path.display().to_string(), err))?;
    std::io::copy(&mut reader, &mut writer)
        .map_err(|err| ForensicError::io_classified(dest_path.display().to_string(), err))
}

/// Safely restores `relative_path` from inside `shadow_root` into `dest_dir`,
/// validating containment inside canonicalized `shadow_root` and rejecting `..`,
/// root prefixes, and symlinks.
pub fn restore_previous_file_into_dir(
    shadow_root: &Path,
    relative_path: &Path,
    dest_dir: &Path,
) -> Result<PathBuf, ForensicError> {
    if relative_path.as_os_str().is_empty() {
        return Err(ForensicError::InvalidArgument(
            "relative_path must be non-empty".to_string(),
        ));
    }
    for comp in relative_path.components() {
        match comp {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ForensicError::InvalidArgument(format!(
                    "unsafe path component in relative_path: {}",
                    relative_path.display()
                )));
            }
        }
    }

    let canon_root = fs::canonicalize(shadow_root)
        .map_err(|err| ForensicError::io_classified(shadow_root.display().to_string(), err))?;
    let src = shadow_root.join(relative_path);
    let src_meta =
        fs::symlink_metadata(&src).map_err(|err| ForensicError::io_classified(src.display().to_string(), err))?;
    if src_meta.file_type().is_symlink() || !src_meta.file_type().is_file() {
        return Err(ForensicError::InvalidArgument(format!(
            "refusing non-regular or symlink source: {}",
            src.display()
        )));
    }
    let canon_src =
        fs::canonicalize(&src).map_err(|err| ForensicError::io_classified(src.display().to_string(), err))?;
    if !canon_src.starts_with(&canon_root) {
        return Err(ForensicError::InvalidArgument(format!(
            "source {} escapes shadow_root {}",
            canon_src.display(),
            canon_root.display()
        )));
    }

    fs::create_dir_all(dest_dir).map_err(|err| ForensicError::io_classified(dest_dir.display().to_string(), err))?;
    let canon_dest_dir =
        fs::canonicalize(dest_dir).map_err(|err| ForensicError::io_classified(dest_dir.display().to_string(), err))?;
    let final_dest = canon_dest_dir.join(relative_path);
    if let Ok(dest_meta) = fs::symlink_metadata(&final_dest)
        && dest_meta.file_type().is_symlink()
    {
        return Err(ForensicError::InvalidArgument(format!(
            "refusing to overwrite symlink destination: {}",
            final_dest.display()
        )));
    }
    restore_previous_file(&canon_src, &final_dest)?;
    Ok(final_dest)
}
