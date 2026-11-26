#![forbid(unsafe_code)]

//! Unified Registry tree reader over offline `RegfHive` (`forensics2rust-hive`)
//! and live `scan_live_registry`, supporting single-file, byte-buffer, and
//! directory evidence layouts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use forensics2rust_core::{DiagnosticWarning, ForensicError, ForensicSource, WarningSeverity};
use forensics2rust_hive::live::{LiveRegistryEntry, LiveScanOptions, scan_live_registry};
use forensics2rust_hive::regf::{RegKeyRef, RegValueData, RegfHive};

#[derive(Debug, Clone)]
pub struct RegNormValue {
    pub name: String,
    pub raw_type: u32,
    pub data: RegValueData,
    pub raw_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RegTree {
    pub root_label: String,
    pub nodes: Vec<RegNode>,
}

#[derive(Debug, Clone)]
pub struct RegNode {
    pub name: String,
    pub path: String,
    pub last_write_time: Option<DateTime<Utc>>,
    pub values: Vec<RegNormValue>,
    pub children: Vec<usize>,
}

impl RegTree {
    pub fn from_hive_subkey(hive: &RegfHive, key: RegKeyRef<'_>, root_label: &str) -> Self {
        let mut nodes = Vec::new();
        Self::push_regf_node(key, "", &mut nodes);
        let _ = hive;
        Self {
            root_label: root_label.to_string(),
            nodes,
        }
    }

    fn push_regf_node(key: RegKeyRef<'_>, rel_path: &str, nodes: &mut Vec<RegNode>) -> usize {
        let idx = nodes.len();
        let values = key
            .values()
            .iter()
            .filter(|v| !v.is_deleted)
            .map(|v| RegNormValue {
                name: v.name.clone(),
                raw_type: v.raw_type,
                data: v.data.clone(),
                raw_bytes: v.raw_bytes.clone(),
            })
            .collect();
        nodes.push(RegNode {
            name: key.name().to_string(),
            path: rel_path.to_string(),
            last_write_time: key.last_write_time(),
            values,
            children: Vec::new(),
        });

        let mut child_indices = Vec::new();
        for sub in key.subkeys() {
            if sub.is_deleted() {
                continue;
            }
            let child_rel = if rel_path.is_empty() {
                sub.name().to_string()
            } else {
                format!("{rel_path}\\{}", sub.name())
            };
            let cidx = Self::push_regf_node(sub, &child_rel, nodes);
            child_indices.push(cidx);
        }
        nodes[idx].children = child_indices;
        idx
    }

    pub fn from_live_entries(root_prefix: &str, entries: &[LiveRegistryEntry]) -> Option<Self> {
        if entries.is_empty() {
            return None;
        }
        let norm_prefix = root_prefix
            .split_once('\\')
            .map(|(_, sub)| sub)
            .unwrap_or("")
            .trim_matches('\\');

        let mut by_rel: BTreeMap<String, &LiveRegistryEntry> = BTreeMap::new();
        for entry in entries {
            let rel = if norm_prefix.is_empty() {
                entry.key_path.trim_matches('\\').to_string()
            } else if entry.key_path.eq_ignore_ascii_case(norm_prefix) {
                String::new()
            } else if entry.key_path.len() > norm_prefix.len()
                && entry.key_path[..norm_prefix.len()].eq_ignore_ascii_case(norm_prefix)
            {
                entry.key_path[norm_prefix.len()..].trim_start_matches('\\').to_string()
            } else {
                entry.key_path.trim_matches('\\').to_string()
            };
            by_rel.insert(rel, entry);
        }

        let mut nodes: Vec<RegNode> = Vec::new();
        let mut idx_map: BTreeMap<String, usize> = BTreeMap::new();

        for (rel, entry) in &by_rel {
            let name = if rel.is_empty() {
                norm_prefix.rsplit('\\').next().unwrap_or(&entry.hive_root).to_string()
            } else {
                rel.rsplit('\\').next().unwrap_or(rel).to_string()
            };
            let values = entry
                .values
                .iter()
                .map(|v| RegNormValue {
                    name: v.name.clone(),
                    raw_type: v.raw_type,
                    data: v.data.clone(),
                    raw_bytes: v.raw_bytes.clone(),
                })
                .collect();
            let idx = nodes.len();
            idx_map.insert(rel.to_ascii_lowercase(), idx);
            nodes.push(RegNode {
                name,
                path: rel.clone(),
                last_write_time: entry.last_write_time,
                values,
                children: Vec::new(),
            });
        }

        // Link parent -> child relationships
        for i in 0..nodes.len() {
            let path = nodes[i].path.clone();
            if path.is_empty() {
                continue;
            }
            let parent_rel = match path.rsplit_once('\\') {
                Some((p, _)) => p.to_ascii_lowercase(),
                None => String::new(),
            };
            if let Some(&pidx) = idx_map.get(&parent_rel)
                && pidx != i
            {
                nodes[pidx].children.push(i);
            }
        }

        if nodes.is_empty() {
            return None;
        }
        Some(Self {
            root_label: root_prefix.to_string(),
            nodes,
        })
    }

    pub fn root(&self) -> Option<&RegNode> {
        self.nodes.first()
    }

    pub fn node(&self, idx: usize) -> Option<&RegNode> {
        self.nodes.get(idx)
    }

    pub fn find_child<'a>(&'a self, node: &RegNode, name: &str) -> Option<(usize, &'a RegNode)> {
        for &cidx in &node.children {
            if let Some(child) = self.nodes.get(cidx)
                && child.name.eq_ignore_ascii_case(name)
            {
                return Some((cidx, child));
            }
        }
        None
    }

    pub fn find_path<'a>(&'a self, rel_path: &str) -> Option<(usize, &'a RegNode)> {
        let trimmed = rel_path.trim_matches(['\\', '/']);
        let mut cur_idx = 0usize;
        let mut cur = self.nodes.first()?;
        if trimmed.is_empty() {
            return Some((cur_idx, cur));
        }
        for seg in trimmed.split(['\\', '/']).filter(|s| !s.is_empty()) {
            let (next_idx, next_node) = self.find_child(cur, seg)?;
            cur_idx = next_idx;
            cur = next_node;
        }
        Some((cur_idx, cur))
    }
}

impl RegNode {
    pub fn value(&self, name: &str) -> Option<&RegNormValue> {
        self.values.iter().find(|v| v.name.eq_ignore_ascii_case(name))
    }
}

/// Discovers candidate hive files inside an offline directory for the given relative hive names.
pub fn discover_hives_in_dir(dir: &Path, candidate_rel_paths: &[&str]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for rel in candidate_rel_paths {
        let candidate = dir.join(rel);
        if candidate.is_file() && !found.contains(&candidate) {
            found.push(candidate);
        }
    }
    // Also check Users\<user>\... if looking for NTUSER.DAT / UsrClass.dat
    let users_dir = dir.join("Users");
    if users_dir.is_dir()
        && let Ok(rd) = std::fs::read_dir(&users_dir)
    {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                for rel in candidate_rel_paths {
                    let candidate = p.join(rel);
                    if candidate.is_file() && !found.contains(&candidate) {
                        found.push(candidate);
                    }
                }
            }
        }
    }
    found
}

/// Loads offline hives from `ForensicSource` (`OfflinePath` file/dir or `OfflineBytes`).
pub fn load_offline_hives(
    source: &ForensicSource,
    candidate_rel_paths: &[&str],
) -> Result<Vec<(String, RegfHive)>, ForensicError> {
    match source {
        ForensicSource::Live => Ok(Vec::new()),
        ForensicSource::OfflineBytes(bytes) => {
            let hive = RegfHive::from_bytes_tolerant(bytes)?;
            Ok(vec![("<memory>".to_string(), hive)])
        }
        ForensicSource::OfflinePath(path) => {
            if !path.exists() {
                return Err(ForensicError::NotFound(path.display().to_string()));
            }
            if path.is_file() {
                let hive = RegfHive::open_tolerant(path)?;
                return Ok(vec![(path.display().to_string(), hive)]);
            }
            if path.is_dir() {
                let paths = discover_hives_in_dir(path, candidate_rel_paths);
                let mut hives = Vec::new();
                for p in paths {
                    if let Ok(hive) = RegfHive::open_tolerant(&p) {
                        hives.push((p.display().to_string(), hive));
                    }
                }
                return Ok(hives);
            }
            Err(ForensicError::NotFound(path.display().to_string()))
        }
    }
}

/// Queries live Registry subtrees one root at a time, ignoring `NotFound` for optional paths
/// and turning `PermissionDenied` into a `DiagnosticWarning` (or error if caller demands it).
pub fn scan_live_trees(
    roots: &[&str],
    max_depth: Option<usize>,
    max_keys: Option<usize>,
    tool_id: &str,
) -> Result<(Vec<RegTree>, Vec<DiagnosticWarning>), ForensicError> {
    let mut trees = Vec::new();
    let mut warnings = Vec::new();
    let mut saw_permission_denied: Option<ForensicError> = None;

    for &root in roots {
        let opts = LiveScanOptions {
            roots: vec![root.to_string()],
            max_depth,
            wow64_64: true,
            max_keys,
        };
        match scan_live_registry(&opts, tool_id) {
            Ok(res) => {
                warnings.extend(res.warnings);
                if let Some(tree) = RegTree::from_live_entries(root, &res.entries) {
                    trees.push(tree);
                }
            }
            Err(ForensicError::NotFound(_)) => {}
            Err(err @ ForensicError::UnsupportedPlatform { .. }) => return Err(err),
            Err(err @ ForensicError::PermissionDenied { .. }) => {
                warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Warn,
                    tool_id: tool_id.to_string(),
                    source: root.to_string(),
                    message: err.to_string(),
                });
                if saw_permission_denied.is_none() {
                    saw_permission_denied = Some(err);
                }
            }
            Err(err) => {
                warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Warn,
                    tool_id: tool_id.to_string(),
                    source: root.to_string(),
                    message: err.to_string(),
                });
            }
        }
    }

    if trees.is_empty()
        && let Some(perm_err) = saw_permission_denied
        && warnings.len() == roots.len()
    {
        return Err(perm_err);
    }

    Ok((trees, warnings))
}

/// Finds a subkey in an offline `RegfHive`, trying multiple relative paths (handling hives whose
/// root is `ROOT` vs `SOFTWARE` vs `CMI-CreateHive{...}`).
pub fn find_hive_key<'a>(hive: &'a RegfHive, candidate_paths: &[&str]) -> Option<RegKeyRef<'a>> {
    for &p in candidate_paths {
        if let Some(k) = hive.find_key(p) {
            return Some(k);
        }
    }
    None
}

/// Resolves the active ControlSet name inside a `SYSTEM` hive (`ControlSet001` etc.).
pub fn resolve_system_control_set(hive: &RegfHive) -> String {
    if let Some(select) = hive.find_key("Select")
        && let Some(cur) = select.value("Current").and_then(|v| v.data.as_u32())
    {
        let cs = format!("ControlSet{cur:03}");
        if hive.find_key(&cs).is_some() {
            return cs;
        }
    }
    for fallback in ["ControlSet001", "ControlSet002", "CurrentControlSet"] {
        if hive.find_key(fallback).is_some() {
            return fallback.to_string();
        }
    }
    "ControlSet001".to_string()
}
