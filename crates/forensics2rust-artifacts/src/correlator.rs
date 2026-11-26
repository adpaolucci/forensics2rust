#![forbid(unsafe_code)]

//! Cross-artifact correlators for Executed Programs (`artifacts.executed`)
//! and Cross-Artifact Activity Timeline (`artifacts.activity`), combining Prefetch, Registry,
//! ShimCache, Amcache, EVTX, Recent `.lnk`, and JumpLists with graceful partial
//! degradation (`DiagnosticWarning`).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc};
use forensics2rust_core::{DiagnosticWarning, ForensicError, ForensicSource, WarningSeverity};
use forensics2rust_evtx::parser::EvtxArchive;
use forensics2rust_evtx::providers::TimelineProvider;
use forensics2rust_evtx::{EvtxRecord, LiveQueryOptions};
use forensics2rust_hive::regf::RegfHive;
use guap_table::{TableProvider, TableQuery};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::live;
use crate::parsers::cfbf::CFBF_MAGIC;
use crate::parsers::jumplist::{parse_automatic_destinations, parse_custom_destinations};
use crate::parsers::lnk::parse_lnk;
use crate::parsers::prefetch::parse_prefetch;
use crate::parsers::reg_reader::{RegTree, find_hive_key, resolve_system_control_set, scan_live_trees};
use crate::parsers::registry_artifacts::{
    decode_amcache_hive, decode_bam_dam_tree, decode_lastvisited_pidl_mru, decode_muicache_tree,
    decode_opensave_pidl_mru, decode_run_mru_tree, decode_shellbags_tree, decode_userassist_tree,
    extract_shimcache_bytes_from_hive,
};
use crate::parsers::shimcache::parse_shimcache;

// ---------------------------------------------------------------------------
// 1. Executed Programs Correlator
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutedEvidenceItem {
    pub source_artifact: String,
    pub timestamp: Option<DateTime<Utc>>,
    pub execution_count: Option<u64>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutedProgramSummary {
    pub program_path: String,
    pub last_executed: Option<DateTime<Utc>>,
    pub execution_count: Option<u64>,
    pub source_artifact: String,
    pub file_version: Option<String>,
    pub company: Option<String>,
    pub evidence: Vec<ExecutedEvidenceItem>,
}

fn normalize_device_path(raw: &str, vol_map: &HashMap<String, String>) -> String {
    let trimmed = raw.trim();
    let lower = trimmed.to_ascii_lowercase();
    for (dev_prefix, drive) in vol_map {
        if lower.starts_with(dev_prefix) {
            let rest = &trimmed[dev_prefix.len()..];
            if rest.is_empty() || rest.starts_with('\\') {
                return format!("{drive}{rest}");
            }
        }
    }
    if let Some(rest) = trimmed.strip_prefix("\\??\\") {
        return rest.to_string();
    }
    trimmed.to_string()
}

fn strip_userassist_prefix(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("UEME_RUNPATH:") {
        rest.trim().to_string()
    } else if let Some(rest) = trimmed.strip_prefix("UEME_RUNPIDL:") {
        rest.trim().to_string()
    } else {
        trimmed.to_string()
    }
}

#[derive(Default)]
struct ExecutedAccumulator {
    by_path: BTreeMap<String, ExecutedProgramSummary>,
}

struct ExecutedInput<'a> {
    program_path: String,
    timestamp: Option<DateTime<Utc>>,
    execution_count: Option<u64>,
    source_artifact: &'a str,
    file_version: Option<String>,
    company: Option<String>,
    detail: String,
}

impl ExecutedAccumulator {
    fn add_entry(&mut self, input: ExecutedInput<'_>) {
        self.add_with_source(input);
    }

    fn add(
        &mut self,
        program_path: String,
        timestamp: Option<DateTime<Utc>>,
        execution_count: Option<u64>,
        source_artifact: &str,
        detail: String,
    ) {
        self.add_with_source(ExecutedInput {
            program_path,
            timestamp,
            execution_count,
            source_artifact,
            file_version: None,
            company: None,
            detail,
        });
    }

    fn add_with_source(&mut self, input: ExecutedInput<'_>) {
        let ExecutedInput {
            program_path,
            timestamp,
            execution_count,
            source_artifact,
            file_version,
            company,
            detail,
        } = input;
        let clean = program_path.trim().to_string();
        if clean.is_empty() {
            return;
        }
        let key = clean.to_ascii_lowercase();
        let ev = ExecutedEvidenceItem {
            source_artifact: source_artifact.to_string(),
            timestamp,
            execution_count,
            detail,
        };
        let entry = self.by_path.entry(key).or_insert_with(|| ExecutedProgramSummary {
            program_path: clean,
            last_executed: timestamp,
            execution_count,
            source_artifact: source_artifact.to_string(),
            file_version: file_version.clone(),
            company: company.clone(),
            evidence: Vec::new(),
        });

        // Update aggregated summary fields
        if let Some(ts) = timestamp
            && entry.last_executed.is_none_or(|prev| ts > prev)
        {
            entry.last_executed = Some(ts);
        }
        if let Some(cnt) = execution_count {
            entry.execution_count = Some(entry.execution_count.map_or(cnt, |prev| prev.max(cnt)));
        }
        if entry.file_version.is_none() {
            entry.file_version = file_version;
        }
        if entry.company.is_none() {
            entry.company = company;
        }
        let mut sources: BTreeSet<String> = entry
            .source_artifact
            .split(", ")
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        sources.insert(source_artifact.to_string());
        entry.source_artifact = sources.into_iter().collect::<Vec<_>>().join(", ");
        entry.evidence.push(ev);
    }

    fn into_vec(self) -> Vec<ExecutedProgramSummary> {
        self.by_path.into_values().collect()
    }
}

fn ingest_hive_for_executed(
    hive: &RegfHive,
    label: &str,
    vol_map: &HashMap<String, String>,
    acc: &mut ExecutedAccumulator,
) {
    // 1. UserAssist
    if let Some(ua_key) = find_hive_key(
        hive,
        &[
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
            "Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
        ],
    ) {
        let tree = RegTree::from_hive_subkey(hive, ua_key, label);
        for ua in decode_userassist_tree(&tree) {
            let p = strip_userassist_prefix(&ua.item_path);
            acc.add(
                p,
                ua.last_executed,
                Some(ua.run_count),
                "UserAssist",
                format!("GUID={}, focus_count={:?}", ua.guid, ua.focus_count),
            );
        }
    }

    // 2. MuiCache
    if let Some(mui_key) = find_hive_key(
        hive,
        &[
            "Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
            "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
            "Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache",
        ],
    ) {
        let tree = RegTree::from_hive_subkey(hive, mui_key, label);
        for mui in decode_muicache_tree(&tree) {
            acc.add_entry(ExecutedInput {
                program_path: mui.application_path,
                timestamp: mui.last_modified,
                execution_count: None,
                source_artifact: "MUICache",
                file_version: None,
                company: mui.company,
                detail: format!("FriendlyName={}", mui.application_name),
            });
        }
    }

    // 3. BAM / DAM + ShimCache from SYSTEM hive
    let cs = resolve_system_control_set(hive);
    for (rel, svc) in [
        (format!("{cs}\\Services\\bam\\State\\UserSettings"), "BAM"),
        (format!("{cs}\\Services\\bam\\UserSettings"), "BAM"),
        (format!("{cs}\\Services\\dam\\State\\UserSettings"), "DAM"),
        (format!("{cs}\\Services\\dam\\UserSettings"), "DAM"),
        ("Services\\bam\\State\\UserSettings".to_string(), "BAM"),
        ("Services\\dam\\State\\UserSettings".to_string(), "DAM"),
    ] {
        if let Some(k) = hive.find_key(&rel) {
            let tree = RegTree::from_hive_subkey(hive, k, &rel);
            for rec in decode_bam_dam_tree(&tree, svc) {
                let norm = normalize_device_path(&rec.path, vol_map);
                acc.add(norm, rec.last_executed, None, svc, format!("SID={}", rec.sid));
            }
        }
    }

    if let Some(shim_bytes) = extract_shimcache_bytes_from_hive(hive)
        && let Ok(entries) = parse_shimcache(&shim_bytes)
    {
        for e in entries {
            acc.add(
                e.path,
                e.last_modified,
                None,
                "ShimCache",
                format!("format={}, order={}", e.format, e.order_index),
            );
        }
    }

    // 4. Amcache.hve
    for am in decode_amcache_hive(hive) {
        acc.add_entry(ExecutedInput {
            program_path: am.path,
            timestamp: am.last_modified,
            execution_count: None,
            source_artifact: "Amcache",
            file_version: am.version,
            company: am.publisher,
            detail: format!("product={:?}, sha1={:?}", am.product_name, am.sha1),
        });
    }
}

pub fn collect_executed_programs(
    source: &ForensicSource,
) -> Result<(Vec<ExecutedProgramSummary>, Vec<DiagnosticWarning>), ForensicError> {
    let mut acc = ExecutedAccumulator::default();
    let mut warnings = Vec::new();
    let vol_map = if source.is_live() {
        live::query_dos_volume_map()
    } else {
        HashMap::new()
    };

    match source {
        ForensicSource::OfflineBytes(bytes) => {
            if bytes.starts_with(b"regf") {
                let hive = RegfHive::from_bytes_tolerant(bytes)?;
                ingest_hive_for_executed(&hive, "<memory>", &vol_map, &mut acc);
            } else if bytes.starts_with(b"MAM") || bytes.get(4..8) == Some(b"SCCA") {
                let pf = parse_prefetch(bytes)?;
                let norm = normalize_device_path(&pf.process_path, &vol_map);
                acc.add(
                    norm,
                    pf.last_run_times.iter().copied().max(),
                    Some(u64::from(pf.run_count)),
                    "Prefetch",
                    format!("hash={:08X}, version={}", pf.prefetch_hash, pf.version),
                );
            } else if let Ok(entries) = parse_shimcache(bytes) {
                for e in entries {
                    acc.add(
                        e.path,
                        e.last_modified,
                        None,
                        "ShimCache",
                        format!("format={}", e.format),
                    );
                }
            } else if let Ok(json_recs) = serde_json::from_slice::<Vec<ExecutedProgramSummary>>(bytes) {
                return Ok((json_recs, warnings));
            } else {
                return Err(ForensicError::parse(
                    "artifacts.executed",
                    "unrecognized offline artifact buffer",
                ));
            }
        }
        ForensicSource::OfflinePath(path) => {
            if !path.exists() {
                return Err(ForensicError::NotFound(path.display().to_string()));
            }
            if path.is_file() {
                let bytes =
                    fs::read(path).map_err(|err| ForensicError::io_classified(path.display().to_string(), err))?;
                return collect_executed_programs(&ForensicSource::OfflineBytes(bytes));
            }
            let mut succeeded = 0usize;
            let mut last_hard_err: Option<ForensicError> = None;
            for entry in WalkDir::new(path).follow_links(false).into_iter().flatten() {
                if !entry.file_type().is_file() {
                    continue;
                }
                let p = entry.path();
                let ext = p
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(str::to_ascii_lowercase)
                    .unwrap_or_default();
                let bytes = match fs::read(p) {
                    Ok(b) => b,
                    Err(e) => {
                        warnings.push(DiagnosticWarning {
                            severity: WarningSeverity::Warn,
                            tool_id: "artifacts.executed".to_string(),
                            source: p.display().to_string(),
                            message: e.to_string(),
                        });
                        continue;
                    }
                };
                if ext == "pf" || bytes.starts_with(b"MAM") || bytes.get(4..8) == Some(b"SCCA") {
                    match parse_prefetch(&bytes) {
                        Ok(pf) => {
                            succeeded += 1;
                            acc.add(
                                normalize_device_path(&pf.process_path, &vol_map),
                                pf.last_run_times.iter().copied().max(),
                                Some(u64::from(pf.run_count)),
                                "Prefetch",
                                format!("file={}, hash={:08X}", p.display(), pf.prefetch_hash),
                            );
                        }
                        Err(err) => {
                            warnings.push(DiagnosticWarning {
                                severity: WarningSeverity::Warn,
                                tool_id: "artifacts.executed".to_string(),
                                source: p.display().to_string(),
                                message: err.to_string(),
                            });
                            last_hard_err = Some(err);
                        }
                    }
                } else if bytes.starts_with(b"regf") {
                    match RegfHive::from_bytes_tolerant(&bytes) {
                        Ok(hive) => {
                            succeeded += 1;
                            ingest_hive_for_executed(&hive, &p.display().to_string(), &vol_map, &mut acc);
                        }
                        Err(err) => {
                            warnings.push(DiagnosticWarning {
                                severity: WarningSeverity::Warn,
                                tool_id: "artifacts.executed".to_string(),
                                source: p.display().to_string(),
                                message: err.to_string(),
                            });
                            last_hard_err = Some(err);
                        }
                    }
                } else if ext == "json"
                    && let Ok(mut items) = serde_json::from_slice::<Vec<ExecutedProgramSummary>>(&bytes)
                {
                    succeeded += 1;
                    for item in items.drain(..) {
                        acc.add_with_source(ExecutedInput {
                            program_path: item.program_path,
                            timestamp: item.last_executed,
                            execution_count: item.execution_count,
                            source_artifact: &item.source_artifact,
                            file_version: item.file_version,
                            company: item.company,
                            detail: "JSON fixture".to_string(),
                        });
                    }
                }
            }
            if succeeded == 0
                && let Some(err) = last_hard_err
            {
                return Err(err);
            }
        }
        ForensicSource::Live => {
            #[cfg(not(windows))]
            return Err(ForensicError::unsupported_platform(
                "artifacts.executed",
                "live artifacts.executed requires Windows",
            ));

            #[cfg(windows)]
            {
                // 1. UserAssist (HKCU)
                if let Ok((trees, w)) = scan_live_trees(
                    &["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"],
                    Some(2),
                    Some(2_000),
                    "artifacts.executed",
                ) {
                    warnings.extend(w);
                    for tree in &trees {
                        for ua in decode_userassist_tree(tree) {
                            acc.add(
                                strip_userassist_prefix(&ua.item_path),
                                ua.last_executed,
                                Some(ua.run_count),
                                "UserAssist",
                                format!("GUID={}", ua.guid),
                            );
                        }
                    }
                }

                // 2. MUICache (HKCU)
                if let Ok((trees, w)) = scan_live_trees(
                    &["HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache"],
                    Some(0),
                    Some(1_000),
                    "artifacts.executed",
                ) {
                    warnings.extend(w);
                    for tree in &trees {
                        for mui in decode_muicache_tree(tree) {
                            acc.add_entry(ExecutedInput {
                                program_path: mui.application_path,
                                timestamp: mui.last_modified,
                                execution_count: None,
                                source_artifact: "MUICache",
                                file_version: None,
                                company: mui.company,
                                detail: format!("FriendlyName={}", mui.application_name),
                            });
                        }
                    }
                }

                // 3. ShimCache (AppCompatCache — often readable non-elevated!)
                if let Ok((trees, w)) = scan_live_trees(
                    &["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache"],
                    Some(0),
                    Some(10),
                    "artifacts.executed",
                ) {
                    warnings.extend(w);
                    for tree in &trees {
                        if let Some(root) = tree.root()
                            && let Some(val) = root.value("AppCompatCache")
                            && let Ok(entries) = parse_shimcache(&val.raw_bytes)
                        {
                            for e in entries {
                                acc.add(
                                    e.path,
                                    e.last_modified,
                                    None,
                                    "ShimCache",
                                    format!("format={}", e.format),
                                );
                            }
                        }
                    }
                }

                // 4. BAM / DAM (often requires elevation; warn gracefully if denied)
                match scan_live_trees(
                    &[
                        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
                        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\dam\\State\\UserSettings",
                    ],
                    Some(1),
                    Some(1_000),
                    "artifacts.executed",
                ) {
                    Ok((trees, w)) => {
                        warnings.extend(w);
                        for tree in &trees {
                            let svc = if tree.root_label.contains("\\dam\\") {
                                "DAM"
                            } else {
                                "BAM"
                            };
                            for rec in decode_bam_dam_tree(tree, svc) {
                                acc.add(
                                    normalize_device_path(&rec.path, &vol_map),
                                    rec.last_executed,
                                    None,
                                    svc,
                                    format!("SID={}", rec.sid),
                                );
                            }
                        }
                    }
                    Err(err) => warnings.push(DiagnosticWarning {
                        severity: WarningSeverity::Warn,
                        tool_id: "artifacts.executed".to_string(),
                        source: "BAM/DAM".to_string(),
                        message: err.to_string(),
                    }),
                }

                // 5. Prefetch directory (requires elevation on Win11)
                let pf_dir = live::live_prefetch_dir();
                match fs::read_dir(&pf_dir) {
                    Ok(rd) => {
                        for entry in rd.flatten() {
                            let p = entry.path();
                            if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("pf"))
                                && let Ok(bytes) = fs::read(&p)
                                && let Ok(pf) = parse_prefetch(&bytes)
                            {
                                acc.add(
                                    normalize_device_path(&pf.process_path, &vol_map),
                                    pf.last_run_times.iter().copied().max(),
                                    Some(u64::from(pf.run_count)),
                                    "Prefetch",
                                    format!("hash={:08X}", pf.prefetch_hash),
                                );
                            }
                        }
                    }
                    Err(err) => warnings.push(DiagnosticWarning {
                        severity: WarningSeverity::Warn,
                        tool_id: "artifacts.executed".to_string(),
                        source: pf_dir.display().to_string(),
                        message: ForensicError::io_classified(pf_dir.display().to_string(), err).to_string(),
                    }),
                }

                // 6. Amcache.hve (locked/requires elevation on live OS)
                let am_path = live::live_amcache_path();
                if am_path.exists() {
                    match RegfHive::open_tolerant(&am_path) {
                        Ok(hive) => {
                            for am in decode_amcache_hive(&hive) {
                                acc.add_entry(ExecutedInput {
                                    program_path: am.path,
                                    timestamp: am.last_modified,
                                    execution_count: None,
                                    source_artifact: "Amcache",
                                    file_version: am.version,
                                    company: am.publisher,
                                    detail: format!("product={:?}", am.product_name),
                                });
                            }
                        }
                        Err(err) => warnings.push(DiagnosticWarning {
                            severity: WarningSeverity::Warn,
                            tool_id: "artifacts.executed".to_string(),
                            source: am_path.display().to_string(),
                            message: err.to_string(),
                        }),
                    }
                }
            }
        }
    }

    Ok((acc.into_vec(), warnings))
}

// ---------------------------------------------------------------------------
// 2. Cross-Artifact Activity Timeline Correlator
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEvent {
    pub action_time: Option<DateTime<Utc>>,
    pub description: String,
    pub filename: String,
    pub full_path: String,
    pub more_info: String,
    pub source: String,
}

fn basename_str(path: &str) -> String {
    let trimmed = path.trim_end_matches(['\\', '/']);
    trimmed
        .rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(path)
        .to_string()
}

fn map_evtx_record_to_activity(rec: &EvtxRecord) -> Option<ActivityEvent> {
    let desc = match rec.event_id {
        6005 => "System Started",
        6006 => "System Shutdown",
        6008 | 41 => "Unexpected Shutdown",
        1074 => "System Shutdown / Restart Initiated",
        4624 => "User Logon",
        4634 | 4647 => "User Logoff",
        4688 => "Process Created",
        1000 | 1002 => "Application Crash / Hang",
        8001 => "Wi-Fi Network Connected",
        8003 => "Wi-Fi Network Disconnected",
        106 | 200 => "Scheduled Task Activity",
        4104 => "PowerShell Script Block Executed",
        _ => return None,
    };

    let target_path = rec
        .get_data("NewProcessName")
        .or_else(|| rec.get_data("Application"))
        .or_else(|| rec.get_data("AppName"))
        .or_else(|| rec.get_data("TaskName"))
        .or_else(|| rec.get_data("ProcessName"))
        .or_else(|| rec.get_data("SSID"))
        .unwrap_or(&rec.channel)
        .to_string();
    let filename = basename_str(&target_path);
    let user = rec
        .get_data("TargetUserName")
        .or_else(|| rec.get_data("SubjectUserName"))
        .unwrap_or("");
    let more_info = if !user.is_empty() && user != "-" {
        format!(
            "Channel={}, EventID={}, User={user}, Computer={}",
            rec.channel, rec.event_id, rec.computer
        )
    } else {
        format!(
            "Channel={}, EventID={}, Computer={}",
            rec.channel, rec.event_id, rec.computer
        )
    };

    Some(ActivityEvent {
        action_time: Some(rec.event_time),
        description: desc.to_string(),
        filename,
        full_path: target_path,
        more_info,
        source: format!("EVTX:{}", rec.channel),
    })
}

fn ingest_hive_for_activity(hive: &RegfHive, label: &str, events: &mut Vec<ActivityEvent>) {
    if let Some(ua_key) = find_hive_key(
        hive,
        &[
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
            "Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
        ],
    ) {
        let tree = RegTree::from_hive_subkey(hive, ua_key, label);
        for ua in decode_userassist_tree(&tree) {
            let p = strip_userassist_prefix(&ua.item_path);
            events.push(ActivityEvent {
                action_time: ua.last_executed,
                description: "Run .EXE / Shortcut (UserAssist)".to_string(),
                filename: basename_str(&p),
                full_path: p,
                more_info: format!("RunCount={}, GUID={}", ua.run_count, ua.guid),
                source: "Registry:UserAssist".to_string(),
            });
        }
    }

    if let Some(run_key) = find_hive_key(
        hive,
        &[
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
            "Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
        ],
    ) {
        let tree = RegTree::from_hive_subkey(hive, run_key, label);
        for rm in decode_run_mru_tree(&tree) {
            events.push(ActivityEvent {
                action_time: rm.last_write_time,
                description: "Execute Run Command".to_string(),
                filename: basename_str(&rm.command),
                full_path: rm.command,
                more_info: format!("Slot={}, Order={}", rm.slot, rm.order),
                source: "Registry:RunMRU".to_string(),
            });
        }
    }

    if let Some(os_key) = find_hive_key(
        hive,
        &[
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
            "Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
        ],
    ) {
        let tree = RegTree::from_hive_subkey(hive, os_key, label);
        for rec in decode_opensave_pidl_mru(&tree) {
            events.push(ActivityEvent {
                action_time: rec.modified_time,
                description: "Open/Save File Dialog".to_string(),
                filename: rec.filename,
                full_path: rec.full_path,
                more_info: format!("Ext={}, Order={}", rec.extension, rec.registry_order),
                source: "Registry:OpenSavePidlMRU".to_string(),
            });
        }
    }

    if let Some(lv_key) = find_hive_key(
        hive,
        &[
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU",
            "Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU",
        ],
    ) {
        let tree = RegTree::from_hive_subkey(hive, lv_key, label);
        for rec in decode_lastvisited_pidl_mru(&tree) {
            events.push(ActivityEvent {
                action_time: rec.modified_time,
                description: "Last Visited Folder in Dialog".to_string(),
                filename: rec.filename,
                full_path: rec.full_path,
                more_info: format!("Order={}", rec.registry_order),
                source: "Registry:LastVisitedPidlMRU".to_string(),
            });
        }
    }

    for bag_path in [
        "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
        "Software\\Microsoft\\Windows\\Shell\\BagMRU",
        "Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU",
    ] {
        if let Some(bag_key) = hive.find_key(bag_path) {
            let tree = RegTree::from_hive_subkey(hive, bag_key, bag_path);
            for sb in decode_shellbags_tree(&tree, None) {
                events.push(ActivityEvent {
                    action_time: sb.last_modified,
                    description: "View Folder in Explorer".to_string(),
                    filename: basename_str(&sb.folder_path),
                    full_path: sb.folder_path,
                    more_info: format!("Type={}, Key={}", sb.item_type, sb.registry_key),
                    source: "Registry:ShellBags".to_string(),
                });
            }
        }
    }
}

fn ingest_file_bytes_for_activity(
    bytes: &[u8],
    path_opt: Option<&Path>,
    events: &mut Vec<ActivityEvent>,
) -> Result<(), ForensicError> {
    let label = path_opt
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<memory>".to_string());
    let ext = path_opt
        .and_then(|p| p.extension())
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();

    if bytes.starts_with(b"ElfFile\0") || ext == "evtx" {
        let archive = EvtxArchive::from_bytes(bytes)?;
        for rec in archive.records() {
            if let Some(ev) = map_evtx_record_to_activity(rec) {
                events.push(ev);
            }
        }
        return Ok(());
    }
    if bytes.starts_with(b"regf") {
        let hive = RegfHive::from_bytes_tolerant(bytes)?;
        ingest_hive_for_activity(&hive, &label, events);
        return Ok(());
    }
    if bytes.starts_with(b"MAM") || bytes.get(4..8) == Some(b"SCCA") || ext == "pf" {
        let pf = parse_prefetch(bytes)?;
        for dt in &pf.last_run_times {
            events.push(ActivityEvent {
                action_time: Some(*dt),
                description: "Run .EXE file".to_string(),
                filename: pf.executable_name.clone(),
                full_path: pf.process_path.clone(),
                more_info: format!("RunCount={}, Hash={:08X}", pf.run_count, pf.prefetch_hash),
                source: "Prefetch".to_string(),
            });
        }
        return Ok(());
    }
    if bytes.len() >= 20 && bytes[0..4] == [0x4C, 0x00, 0x00, 0x00] && ext != "customdestinations-ms" {
        let (lnk, _) = parse_lnk(bytes)?;
        let full = lnk.target_path.clone().unwrap_or_else(|| label.clone());
        events.push(ActivityEvent {
            action_time: lnk.write_time.or(lnk.creation_time),
            description: "Open File / Folder (LNK)".to_string(),
            filename: basename_str(&full),
            full_path: full,
            more_info: format!("LNK={label}"),
            source: "RecentLnk".to_string(),
        });
        return Ok(());
    }
    if bytes.starts_with(&CFBF_MAGIC) || ext == "automaticdestinations-ms" {
        let app_id = path_opt
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .and_then(|n| n.split('.').next())
            .unwrap_or("memory");
        let (recs, _) = parse_automatic_destinations(bytes, app_id)?;
        for jr in recs {
            events.push(ActivityEvent {
                action_time: jr.record_time,
                description: "Access JumpList Entry".to_string(),
                filename: jr.file_name,
                full_path: jr.full_path,
                more_info: format!("App={}, Pin={}", jr.app_name, jr.pin_status),
                source: "JumpLists".to_string(),
            });
        }
        return Ok(());
    }
    if ext == "customdestinations-ms" {
        let app_id = path_opt
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .and_then(|n| n.split('.').next())
            .unwrap_or("memory");
        let (recs, _) = parse_custom_destinations(bytes, app_id)?;
        for jr in recs {
            events.push(ActivityEvent {
                action_time: jr.record_time,
                description: "Access JumpList Entry".to_string(),
                filename: jr.file_name,
                full_path: jr.full_path,
                more_info: format!("App={}, Pin={}", jr.app_name, jr.pin_status),
                source: "JumpLists".to_string(),
            });
        }
        return Ok(());
    }
    if let Ok(mut json_events) = serde_json::from_slice::<Vec<ActivityEvent>>(bytes) {
        events.append(&mut json_events);
        return Ok(());
    }

    Err(ForensicError::parse(
        "artifacts.activity",
        format!("unrecognized artifact file: {label}"),
    ))
}

pub fn collect_last_activity(
    source: &ForensicSource,
) -> Result<(Vec<ActivityEvent>, Vec<DiagnosticWarning>), ForensicError> {
    let mut events = Vec::new();
    let mut warnings = Vec::new();

    match source {
        ForensicSource::OfflineBytes(bytes) => {
            ingest_file_bytes_for_activity(bytes, None, &mut events)?;
        }
        ForensicSource::OfflinePath(path) => {
            if !path.exists() {
                return Err(ForensicError::NotFound(path.display().to_string()));
            }
            if path.is_file() {
                let bytes =
                    fs::read(path).map_err(|err| ForensicError::io_classified(path.display().to_string(), err))?;
                ingest_file_bytes_for_activity(&bytes, Some(path), &mut events)?;
            } else {
                let mut succeeded = 0usize;
                let mut last_err: Option<ForensicError> = None;
                for entry in WalkDir::new(path).follow_links(false).into_iter().flatten() {
                    if !entry.file_type().is_file() {
                        continue;
                    }
                    let p = entry.path();
                    let ext = p
                        .extension()
                        .and_then(|e| e.to_str())
                        .map(str::to_ascii_lowercase)
                        .unwrap_or_default();
                    let is_known_ext = matches!(
                        ext.as_str(),
                        "evtx" | "pf" | "lnk" | "automaticdestinations-ms" | "customdestinations-ms" | "dat" | "hve"
                    );
                    let bytes = match fs::read(p) {
                        Ok(b) => b,
                        Err(_) => continue,
                    };
                    let has_magic = bytes.starts_with(b"ElfFile\0")
                        || bytes.starts_with(b"regf")
                        || bytes.starts_with(b"MAM")
                        || bytes.get(4..8) == Some(b"SCCA")
                        || bytes.starts_with(&CFBF_MAGIC);
                    if !is_known_ext && !has_magic {
                        continue;
                    }
                    match ingest_file_bytes_for_activity(&bytes, Some(p), &mut events) {
                        Ok(()) => succeeded += 1,
                        Err(err) => {
                            warnings.push(DiagnosticWarning {
                                severity: WarningSeverity::Warn,
                                tool_id: "artifacts.activity".to_string(),
                                source: p.display().to_string(),
                                message: err.to_string(),
                            });
                            last_err = Some(err);
                        }
                    }
                }
                if succeeded == 0
                    && let Some(err) = last_err
                {
                    return Err(err);
                }
            }
        }
        ForensicSource::Live => {
            #[cfg(not(windows))]
            return Err(ForensicError::unsupported_platform(
                "artifacts.activity",
                "live artifacts.activity requires Windows",
            ));

            #[cfg(windows)]
            {
                // 1. Live HKCU Registry (UserAssist, RunMRU, OpenSave, BagMRU)
                if let Ok((trees, w)) = scan_live_trees(
                    &[
                        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
                        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
                        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
                        "HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
                    ],
                    Some(4),
                    Some(2_000),
                    "artifacts.activity",
                ) {
                    warnings.extend(w);
                    for tree in &trees {
                        let lbl = tree.root_label.to_ascii_lowercase();
                        if lbl.contains("userassist") {
                            for ua in decode_userassist_tree(tree) {
                                let p = strip_userassist_prefix(&ua.item_path);
                                events.push(ActivityEvent {
                                    action_time: ua.last_executed,
                                    description: "Run .EXE / Shortcut (UserAssist)".to_string(),
                                    filename: basename_str(&p),
                                    full_path: p,
                                    more_info: format!("RunCount={}", ua.run_count),
                                    source: "Registry:UserAssist".to_string(),
                                });
                            }
                        } else if lbl.contains("runmru") {
                            for rm in decode_run_mru_tree(tree) {
                                events.push(ActivityEvent {
                                    action_time: rm.last_write_time,
                                    description: "Execute Run Command".to_string(),
                                    filename: basename_str(&rm.command),
                                    full_path: rm.command,
                                    more_info: format!("Slot={}", rm.slot),
                                    source: "Registry:RunMRU".to_string(),
                                });
                            }
                        } else if lbl.contains("opensavepidlmru") {
                            for rec in decode_opensave_pidl_mru(tree) {
                                events.push(ActivityEvent {
                                    action_time: rec.modified_time,
                                    description: "Open/Save File Dialog".to_string(),
                                    filename: rec.filename,
                                    full_path: rec.full_path,
                                    more_info: format!("Ext={}", rec.extension),
                                    source: "Registry:OpenSavePidlMRU".to_string(),
                                });
                            }
                        } else if lbl.contains("bagmru") {
                            for sb in decode_shellbags_tree(tree, None) {
                                events.push(ActivityEvent {
                                    action_time: sb.last_modified,
                                    description: "View Folder in Explorer".to_string(),
                                    filename: basename_str(&sb.folder_path),
                                    full_path: sb.folder_path,
                                    more_info: format!("Type={}", sb.item_type),
                                    source: "Registry:ShellBags".to_string(),
                                });
                            }
                        }
                    }
                }

                // 2. Recent .lnk and JumpLists
                if let Some(recent_dir) = live::live_recent_dir() {
                    if let Ok(rd) = fs::read_dir(&recent_dir) {
                        for entry in rd.flatten().take(500) {
                            let p = entry.path();
                            if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("lnk"))
                                && let Ok(b) = fs::read(&p)
                            {
                                let _ = ingest_file_bytes_for_activity(&b, Some(&p), &mut events);
                            }
                        }
                    }
                    let auto_dir = recent_dir.join("AutomaticDestinations");
                    if let Ok(rd) = fs::read_dir(&auto_dir) {
                        for entry in rd.flatten().take(200) {
                            let p = entry.path();
                            if p.is_file()
                                && let Ok(b) = fs::read(&p)
                            {
                                let _ = ingest_file_bytes_for_activity(&b, Some(&p), &mut events);
                            }
                        }
                    }
                }

                // 3. Prefetch (graceful warning if non-elevated)
                let pf_dir = live::live_prefetch_dir();
                match fs::read_dir(&pf_dir) {
                    Ok(rd) => {
                        for entry in rd.flatten().take(500) {
                            let p = entry.path();
                            if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("pf"))
                                && let Ok(b) = fs::read(&p)
                            {
                                let _ = ingest_file_bytes_for_activity(&b, Some(&p), &mut events);
                            }
                        }
                    }
                    Err(err) => warnings.push(DiagnosticWarning {
                        severity: WarningSeverity::Warn,
                        tool_id: "artifacts.activity".to_string(),
                        source: pf_dir.display().to_string(),
                        message: ForensicError::io_classified(pf_dir.display().to_string(), err).to_string(),
                    }),
                }

                // 4. EVTX TimelineProvider (bounded live query)
                let tl = TimelineProvider::with_options(
                    ForensicSource::Live,
                    LiveQueryOptions {
                        max_records: Some(500),
                        xpath_query: None,
                        reverse_direction: true,
                    },
                );
                match tl.query(&TableQuery::default()) {
                    Ok(table) => {
                        for row in table.rows {
                            let ts = row.cells.first().and_then(|c| match c {
                                guap_table::CellValue::Timestamp(dt) => Some(*dt),
                                _ => None,
                            });
                            let channel = row.cells.get(1).map(|c| c.to_string()).unwrap_or_default();
                            let cat = row
                                .cells
                                .get(3)
                                .map(|c| c.to_string())
                                .unwrap_or_else(|| "EVTX".to_string());
                            let target = row.cells.get(5).map(|c| c.to_string()).unwrap_or_default();
                            let detail = row.cells.get(6).map(|c| c.to_string()).unwrap_or_default();
                            events.push(ActivityEvent {
                                action_time: ts,
                                description: cat,
                                filename: basename_str(&target),
                                full_path: target,
                                more_info: detail,
                                source: format!("EVTX:{channel}"),
                            });
                        }
                    }
                    Err(err) => warnings.push(DiagnosticWarning {
                        severity: WarningSeverity::Warn,
                        tool_id: "artifacts.activity".to_string(),
                        source: "EVTX".to_string(),
                        message: err.to_string(),
                    }),
                }
            }
        }
    }

    Ok((events, warnings))
}
