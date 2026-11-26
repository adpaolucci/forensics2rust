#![forbid(unsafe_code)]

//! Pure-Rust decoders for Registry-backed DFIR artifacts:
//! `ShellBags`, `UserAssist`, `MUICache`, `OpenSavePidlMRU`/`LastVisitedPidlMRU`,
//! `RunMRU`, `BAM`/`DAM`, `Amcache.hve`, `USBSTOR`/`USB`/`MountedDevices`, and `ProfileList`.

use std::collections::{BTreeMap, HashSet};

use chrono::{DateTime, Utc};
use forensics2rust_core::{filetime_to_utc, parse_sid, read_utf16_le, rot13};
use forensics2rust_hive::regf::RegfHive;
use serde::{Deserialize, Serialize};

use crate::parsers::pidl::{DecodedShellItem, join_pidl_path, parse_pidl, parse_single_item};
use crate::parsers::reg_reader::{RegNode, RegTree, find_hive_key, resolve_system_control_set};
use crate::parsers::setupapi_log::extract_vid_pid_serial;

// ---------------------------------------------------------------------------
// 1. ShellBags (BagMRU + Bags)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellBagRecord {
    pub folder_path: String,
    pub item_type: String,
    pub shell_slot: Option<u64>,
    pub registry_key: String,
    pub last_modified: Option<DateTime<Utc>>,
    pub created: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    pub mft_entry: Option<String>,
    pub view_mode: Option<String>,
    pub mru_order: Vec<u32>,
    pub raw_bytes: Vec<u8>,
}

fn decode_mrulist_ex(bytes: &[u8]) -> Vec<u32> {
    let mut out = Vec::new();
    for chunk in bytes.as_chunks::<4>().0 {
        let v = u32::from_le_bytes(*chunk);
        if v == 0xFFFF_FFFF {
            break;
        }
        out.push(v);
    }
    out
}

fn view_mode_name(mode: u32) -> &'static str {
    match mode {
        1 => "Icons",
        2 => "SmallIcons",
        3 => "List",
        4 => "Details",
        5 => "Thumbnail",
        6 => "Tiles",
        7 => "Filmstrip",
        8 => "Content",
        _ => "Custom",
    }
}

fn lookup_bag_view_mode(bags_tree: Option<&RegTree>, slot: u32) -> Option<String> {
    let bags = bags_tree?;
    let (_, slot_node) = bags.find_path(&slot.to_string())?;
    let (_, shell_node) = bags.find_child(slot_node, "Shell")?;
    for &cidx in &shell_node.children {
        if let Some(guid_node) = bags.node(cidx)
            && let Some(mode) = guid_node
                .value("LogicalViewMode")
                .or_else(|| guid_node.value("Mode"))
                .and_then(|v| v.data.as_u32())
        {
            return Some(format!("{} ({mode})", view_mode_name(mode)));
        }
    }
    None
}

pub fn decode_shellbags_tree(bagmru: &RegTree, bags: Option<&RegTree>) -> Vec<ShellBagRecord> {
    let mut records = Vec::new();
    let Some(root) = bagmru.root() else {
        return records;
    };
    let mut visited = HashSet::new();
    walk_bagmru_node(bagmru, bags, 0, root, &[], &mut visited, &mut records, 0);
    records
}

#[allow(clippy::too_many_arguments)]
fn walk_bagmru_node(
    bagmru: &RegTree,
    bags: Option<&RegTree>,
    node_idx: usize,
    node: &RegNode,
    prefix_items: &[DecodedShellItem],
    visited: &mut HashSet<usize>,
    out: &mut Vec<ShellBagRecord>,
    depth: usize,
) {
    if depth >= 128 || !visited.insert(node_idx) {
        return;
    }

    let mru_order = node
        .value("MRUListEx")
        .map(|v| decode_mrulist_ex(&v.raw_bytes))
        .unwrap_or_default();

    for val in &node.values {
        if val.name.is_empty() || !val.name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Some(item) = parse_single_item(&val.raw_bytes) else {
            continue;
        };
        let mut chain = prefix_items.to_vec();
        chain.push(item.clone());
        let folder_path = join_pidl_path(&chain);

        let child_pair = bagmru.find_child(node, &val.name);
        let child_slot = child_pair
            .and_then(|(_, cn)| cn.value("NodeSlot"))
            .and_then(|v| v.data.as_u32());
        let view_mode = child_slot.and_then(|slot| lookup_bag_view_mode(bags, slot));
        let last_modified = child_pair
            .and_then(|(_, cn)| cn.last_write_time)
            .or(node.last_write_time)
            .or(item.modified);
        let reg_key = if node.path.is_empty() {
            format!("{}\\{}", bagmru.root_label, val.name)
        } else {
            format!("{}\\{}\\{}", bagmru.root_label, node.path, val.name)
        };

        out.push(ShellBagRecord {
            folder_path,
            item_type: item.kind.as_str().to_string(),
            shell_slot: child_slot.map(u64::from),
            registry_key: reg_key,
            last_modified,
            created: item.created,
            accessed: item.accessed,
            mft_entry: item.mft_entry.clone(),
            view_mode,
            mru_order: mru_order.clone(),
            raw_bytes: val.raw_bytes.clone(),
        });

        if let Some((cidx, child_node)) = child_pair {
            walk_bagmru_node(bagmru, bags, cidx, child_node, &chain, visited, out, depth + 1);
        }
    }
}

// ---------------------------------------------------------------------------
// 2. UserAssist
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAssistRecord {
    pub item_path: String,
    pub guid: String,
    pub guid_description: String,
    pub run_count: u64,
    pub focus_count: Option<u64>,
    pub focus_time_ms: Option<u64>,
    pub last_executed: Option<DateTime<Utc>>,
    pub session_id: Option<u32>,
    pub raw_bytes: Vec<u8>,
}

pub fn userassist_guid_name(guid: &str) -> &'static str {
    match guid.to_ascii_uppercase().as_str() {
        "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}" => "Executable File Execution",
        "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}" => "Shortcut File Execution",
        "{75048700-EF1F-11D0-9888-006097DEACF9}" => "ActiveDesktop (XP)",
        "{5E6AB780-7743-11CF-A12B-00AA004AE837}" => "Internet Explorer Toolbar (XP)",
        "{0D6D4F41-2994-4BA0-8FEF-620E43CD2812}" => "Explorer Frame",
        "{9E04CAB2-CC14-11DF-BB8C-A2F1DED72085}" => "Start Menu",
        _ => "UserAssist Category",
    }
}

pub fn decode_userassist_tree(tree: &RegTree) -> Vec<UserAssistRecord> {
    let mut records = Vec::new();
    let Some(root) = tree.root() else {
        return records;
    };

    for &guid_idx in &root.children {
        let Some(guid_node) = tree.node(guid_idx) else {
            continue;
        };
        let guid = guid_node.name.clone();
        let guid_desc = userassist_guid_name(&guid).to_string();
        let Some((_, count_node)) = tree.find_child(guid_node, "Count") else {
            continue;
        };
        for val in &count_node.values {
            if val.name.is_empty() {
                continue;
            }
            let decoded_name = rot13(&val.name);
            let upper = decoded_name.to_ascii_uppercase();
            if upper.starts_with("UEME_CTLSESSION") || upper.starts_with("UEME_CTLCUACOUNT") {
                continue;
            }
            let b = &val.raw_bytes;
            let (session_id, run_count, focus_count, focus_time_ms, last_executed) = if b.len() >= 72 {
                let sess = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
                let rc = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
                let fc = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
                let ft_ms = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);
                let ft = u64::from_le_bytes([b[60], b[61], b[62], b[63], b[64], b[65], b[66], b[67]]);
                (
                    Some(sess),
                    u64::from(rc),
                    Some(u64::from(fc)),
                    Some(u64::from(ft_ms)),
                    filetime_to_utc(ft),
                )
            } else if b.len() == 16 {
                let sess = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
                let raw_rc = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
                let rc = raw_rc.saturating_sub(5);
                let ft = u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
                (Some(sess), u64::from(rc), None, None, filetime_to_utc(ft))
            } else {
                continue;
            };

            records.push(UserAssistRecord {
                item_path: decoded_name,
                guid: guid.clone(),
                guid_description: guid_desc.clone(),
                run_count,
                focus_count,
                focus_time_ms,
                last_executed,
                session_id,
                raw_bytes: b.clone(),
            });
        }
    }

    records
}

// ---------------------------------------------------------------------------
// 3. MUICache
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MuiCacheRecord {
    pub application_path: String,
    pub application_name: String,
    pub company: Option<String>,
    pub registry_value_name: String,
    pub last_modified: Option<DateTime<Utc>>,
}

pub fn decode_muicache_tree(tree: &RegTree) -> Vec<MuiCacheRecord> {
    let mut by_path: BTreeMap<String, MuiCacheRecord> = BTreeMap::new();

    for node in &tree.nodes {
        for val in &node.values {
            if val.name.is_empty() || val.name.eq_ignore_ascii_case("LangID") {
                continue;
            }
            let text = val.data.decoded_string();
            if text.is_empty() {
                continue;
            }
            if let Some(base) = val.name.strip_suffix(".ApplicationCompany") {
                let key = base.to_ascii_lowercase();
                by_path
                    .entry(key)
                    .and_modify(|e| e.company = Some(text.clone()))
                    .or_insert_with(|| MuiCacheRecord {
                        application_path: base.to_string(),
                        application_name: base.rsplit(['\\', '/']).next().unwrap_or(base).to_string(),
                        company: Some(text.clone()),
                        registry_value_name: val.name.clone(),
                        last_modified: node.last_write_time,
                    });
            } else if let Some(base) = val.name.strip_suffix(".FriendlyAppName") {
                let key = base.to_ascii_lowercase();
                by_path
                    .entry(key)
                    .and_modify(|e| {
                        e.application_name = text.clone();
                        e.registry_value_name = val.name.clone();
                        if e.last_modified.is_none() {
                            e.last_modified = node.last_write_time;
                        }
                    })
                    .or_insert_with(|| MuiCacheRecord {
                        application_path: base.to_string(),
                        application_name: text.clone(),
                        company: None,
                        registry_value_name: val.name.clone(),
                        last_modified: node.last_write_time,
                    });
            } else {
                let key = val.name.to_ascii_lowercase();
                by_path.entry(key).or_insert_with(|| MuiCacheRecord {
                    application_path: val.name.clone(),
                    application_name: text.clone(),
                    company: None,
                    registry_value_name: val.name.clone(),
                    last_modified: node.last_write_time,
                });
            }
        }
    }

    by_path.into_values().collect()
}

// ---------------------------------------------------------------------------
// 4. OpenSavePidlMRU & LastVisitedPidlMRU
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenSaveRecord {
    pub filename: String,
    pub extension: String,
    pub full_path: String,
    pub modified_time: Option<DateTime<Utc>>,
    pub registry_order: u32,
    pub dialog_type: String,
    pub key_modified_time: Option<DateTime<Utc>>,
    pub raw_bytes: Vec<u8>,
}

fn order_map_from_mrulist_ex(node: &RegNode) -> BTreeMap<String, u32> {
    let mut map = BTreeMap::new();
    if let Some(mru_val) = node.value("MRUListEx") {
        for (order_idx, entry_id) in decode_mrulist_ex(&mru_val.raw_bytes).into_iter().enumerate() {
            map.insert(entry_id.to_string(), order_idx as u32);
        }
    }
    map
}

pub fn decode_opensave_pidl_mru(tree: &RegTree) -> Vec<OpenSaveRecord> {
    let mut out = Vec::new();
    let Some(root) = tree.root() else {
        return out;
    };

    for &ext_idx in &root.children {
        let Some(ext_node) = tree.node(ext_idx) else {
            continue;
        };
        let order_map = order_map_from_mrulist_ex(ext_node);
        for val in &ext_node.values {
            if val.name.is_empty()
                || val.name.eq_ignore_ascii_case("MRUListEx")
                || !val.name.chars().all(|c| c.is_ascii_digit())
            {
                continue;
            }
            let decoded = parse_pidl(&val.raw_bytes);
            if decoded.items.is_empty() {
                continue;
            }
            let full_path = join_pidl_path(&decoded.items);
            let filename = decoded
                .items
                .last()
                .map(|i| i.name.clone())
                .unwrap_or_else(|| full_path.clone());
            let pidl_mod = decoded.items.last().and_then(|i| i.modified);
            let extension = if ext_node.name == "*" {
                filename
                    .rsplit_once('.')
                    .map(|(_, ext)| ext.to_ascii_lowercase())
                    .unwrap_or_else(|| "*".to_string())
            } else {
                ext_node.name.clone()
            };
            let order = order_map
                .get(&val.name)
                .copied()
                .unwrap_or_else(|| val.name.parse::<u32>().unwrap_or(u32::MAX));

            out.push(OpenSaveRecord {
                filename,
                extension,
                full_path,
                modified_time: pidl_mod.or(ext_node.last_write_time),
                registry_order: order,
                dialog_type: "OpenSavePidlMRU".to_string(),
                key_modified_time: ext_node.last_write_time,
                raw_bytes: val.raw_bytes.clone(),
            });
        }
    }

    out
}

pub fn decode_lastvisited_pidl_mru(tree: &RegTree) -> Vec<OpenSaveRecord> {
    let mut out = Vec::new();
    let Some(root) = tree.root() else {
        return out;
    };
    let order_map = order_map_from_mrulist_ex(root);

    for val in &root.values {
        if val.name.is_empty()
            || val.name.eq_ignore_ascii_case("MRUListEx")
            || !val.name.chars().all(|c| c.is_ascii_digit())
        {
            continue;
        }
        // Leading UTF-16LE NUL-terminated executable name followed by PIDL
        let b = &val.raw_bytes;
        let mut units = Vec::new();
        let mut pos = 0usize;
        while pos + 2 <= b.len() {
            let u = u16::from_le_bytes([b[pos], b[pos + 1]]);
            pos += 2;
            if u == 0 {
                break;
            }
            units.push(u);
        }
        let app_exe = String::from_utf16_lossy(&units);
        let decoded = if pos < b.len() {
            parse_pidl(&b[pos..])
        } else {
            crate::parsers::pidl::DecodedPidl {
                items: Vec::new(),
                diagnostics: Vec::new(),
            }
        };
        let full_path = if !decoded.items.is_empty() {
            join_pidl_path(&decoded.items)
        } else {
            app_exe.clone()
        };
        let pidl_mod = decoded.items.last().and_then(|i| i.modified);
        let filename = if !app_exe.is_empty() {
            app_exe
        } else {
            decoded.items.last().map(|i| i.name.clone()).unwrap_or_default()
        };
        let extension = filename
            .rsplit_once('.')
            .map(|(_, ext)| ext.to_ascii_lowercase())
            .unwrap_or_else(|| "exe".to_string());
        let order = order_map
            .get(&val.name)
            .copied()
            .unwrap_or_else(|| val.name.parse::<u32>().unwrap_or(u32::MAX));

        out.push(OpenSaveRecord {
            filename,
            extension,
            full_path,
            modified_time: pidl_mod.or(root.last_write_time),
            registry_order: order,
            dialog_type: "LastVisitedPidlMRU".to_string(),
            key_modified_time: root.last_write_time,
            raw_bytes: val.raw_bytes.clone(),
        });
    }

    out
}

// ---------------------------------------------------------------------------
// 5. RunMRU
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMruRecord {
    pub slot: String,
    pub command: String,
    pub order: usize,
    pub last_write_time: Option<DateTime<Utc>>,
}

pub fn decode_run_mru_tree(tree: &RegTree) -> Vec<RunMruRecord> {
    let mut out = Vec::new();
    let Some(root) = tree.root() else {
        return out;
    };
    let mru_order = root
        .value("MRUList")
        .map(|v| v.data.decoded_string())
        .unwrap_or_default();

    for val in &root.values {
        if val.name.is_empty() || val.name.eq_ignore_ascii_case("MRUList") {
            continue;
        }
        let raw_cmd = val.data.decoded_string();
        let cmd = raw_cmd.trim_end_matches("\\1").trim().to_string();
        if cmd.is_empty() {
            continue;
        }
        let order = mru_order
            .chars()
            .position(|c| c.to_string().eq_ignore_ascii_case(&val.name))
            .unwrap_or(usize::MAX);
        out.push(RunMruRecord {
            slot: val.name.clone(),
            command: cmd,
            order,
            last_write_time: root.last_write_time,
        });
    }
    out.sort_by_key(|r| r.order);
    out
}

// ---------------------------------------------------------------------------
// 6. BAM / DAM
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BamDamRecord {
    pub path: String,
    pub last_executed: Option<DateTime<Utc>>,
    pub sid: String,
    pub service: String,
}

pub fn decode_bam_dam_tree(tree: &RegTree, service: &str) -> Vec<BamDamRecord> {
    let mut out = Vec::new();
    for node in &tree.nodes {
        let sid = node.name.clone();
        if !sid.to_ascii_uppercase().starts_with("S-1-") {
            continue;
        }
        for val in &node.values {
            if val.name.is_empty()
                || val.name.eq_ignore_ascii_case("Version")
                || val.name.eq_ignore_ascii_case("SequenceNumber")
            {
                continue;
            }
            if val.raw_bytes.len() >= 8 {
                let ft = u64::from_le_bytes([
                    val.raw_bytes[0],
                    val.raw_bytes[1],
                    val.raw_bytes[2],
                    val.raw_bytes[3],
                    val.raw_bytes[4],
                    val.raw_bytes[5],
                    val.raw_bytes[6],
                    val.raw_bytes[7],
                ]);
                out.push(BamDamRecord {
                    path: val.name.clone(),
                    last_executed: filetime_to_utc(ft),
                    sid: sid.clone(),
                    service: service.to_string(),
                });
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 7. Amcache.hve
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmcacheRecord {
    pub path: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub product_name: Option<String>,
    pub sha1: Option<String>,
    pub last_modified: Option<DateTime<Utc>>,
}

pub fn decode_amcache_hive(hive: &RegfHive) -> Vec<AmcacheRecord> {
    let mut out = Vec::new();

    // Win10/11: Root\InventoryApplicationFile\*
    if let Some(inv) = find_hive_key(hive, &["Root\\InventoryApplicationFile", "InventoryApplicationFile"]) {
        for sub in inv.subkeys() {
            if sub.is_deleted() {
                continue;
            }
            let path = sub
                .value("LowerCaseLongPath")
                .or_else(|| sub.value("Path"))
                .map(|v| v.decoded_string())
                .unwrap_or_default();
            if path.is_empty() {
                continue;
            }
            let version = sub
                .value("Version")
                .or_else(|| sub.value("ProductVersion"))
                .map(|v| v.decoded_string())
                .filter(|s| !s.is_empty());
            let publisher = sub
                .value("Publisher")
                .map(|v| v.decoded_string())
                .filter(|s| !s.is_empty());
            let product_name = sub
                .value("ProductName")
                .map(|v| v.decoded_string())
                .filter(|s| !s.is_empty());
            let sha1 = sub
                .value("FileId")
                .map(|v| {
                    let s = v.decoded_string();
                    s.strip_prefix("0000").unwrap_or(&s).to_string()
                })
                .filter(|s| !s.is_empty());

            out.push(AmcacheRecord {
                path,
                version,
                publisher,
                product_name,
                sha1,
                last_modified: sub.last_write_time(),
            });
        }
    }

    // Win8 / early Win10: Root\File\<vol_guid>\<file_id>
    if let Some(file_root) = find_hive_key(hive, &["Root\\File", "File"]) {
        for vol in file_root.subkeys() {
            if vol.is_deleted() {
                continue;
            }
            for entry in vol.subkeys() {
                if entry.is_deleted() {
                    continue;
                }
                let path = entry.value("15").map(|v| v.decoded_string()).unwrap_or_default();
                if path.is_empty() {
                    continue;
                }
                let product_name = entry.value("0").map(|v| v.decoded_string()).filter(|s| !s.is_empty());
                let publisher = entry.value("1").map(|v| v.decoded_string()).filter(|s| !s.is_empty());
                let version = entry.value("5").map(|v| v.decoded_string()).filter(|s| !s.is_empty());
                let sha1 = entry
                    .value("101")
                    .map(|v| {
                        let s = v.decoded_string();
                        s.strip_prefix("0000").unwrap_or(&s).to_string()
                    })
                    .filter(|s| !s.is_empty());

                out.push(AmcacheRecord {
                    path,
                    version,
                    publisher,
                    product_name,
                    sha1,
                    last_modified: entry.last_write_time(),
                });
            }
        }
    }

    out
}

// ---------------------------------------------------------------------------
// 8. ProfileList
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfileRecord {
    pub username: String,
    pub sid: String,
    pub profile_path: String,
    pub hive_path: String,
    pub last_load_time: Option<DateTime<Utc>>,
    pub last_unload_time: Option<DateTime<Utc>>,
    pub local_profile_flags: Option<u64>,
    pub loaded: Option<bool>,
}

fn well_known_sid_username(sid: &str) -> Option<&'static str> {
    match sid.to_ascii_uppercase().as_str() {
        "S-1-5-18" => Some("SYSTEM"),
        "S-1-5-19" => Some("LOCAL SERVICE"),
        "S-1-5-20" => Some("NETWORK SERVICE"),
        _ => None,
    }
}

fn combine_high_low_ft(high: Option<u32>, low: Option<u32>) -> Option<DateTime<Utc>> {
    let h = high?;
    let l = low?;
    let ft = (u64::from(h) << 32) | u64::from(l);
    filetime_to_utc(ft)
}

pub fn decode_profile_list_tree(tree: &RegTree, loaded_sids: Option<&HashSet<String>>) -> Vec<UserProfileRecord> {
    let mut out = Vec::new();
    let Some(root) = tree.root() else {
        return out;
    };

    for &cidx in &root.children {
        let Some(node) = tree.node(cidx) else {
            continue;
        };
        let sid = if node.name.to_ascii_uppercase().starts_with("S-1-") {
            node.name.clone()
        } else if let Some(sid_val) = node.value("Sid")
            && let Ok(parsed) = parse_sid(&sid_val.raw_bytes)
        {
            parsed
        } else {
            continue;
        };

        let profile_path = node
            .value("ProfileImagePath")
            .map(|v| v.data.decoded_string())
            .unwrap_or_default();
        let username = well_known_sid_username(&sid)
            .map(str::to_string)
            .or_else(|| {
                profile_path
                    .trim_end_matches(['\\', '/'])
                    .rsplit(['\\', '/'])
                    .next()
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| sid.clone());
        let hive_path = if profile_path.is_empty() {
            String::new()
        } else {
            format!("{}\\NTUSER.DAT", profile_path.trim_end_matches(['\\', '/']))
        };

        let last_load_time = combine_high_low_ft(
            node.value("LocalProfileLoadTimeHigh").and_then(|v| v.data.as_u32()),
            node.value("LocalProfileLoadTimeLow").and_then(|v| v.data.as_u32()),
        );
        let last_unload_time = combine_high_low_ft(
            node.value("LocalProfileUnloadTimeHigh").and_then(|v| v.data.as_u32()),
            node.value("LocalProfileUnloadTimeLow").and_then(|v| v.data.as_u32()),
        );
        let local_profile_flags = node.value("Flags").and_then(|v| v.data.as_u32()).map(u64::from);
        let loaded = loaded_sids.map(|set| set.contains(&sid.to_ascii_uppercase()));

        out.push(UserProfileRecord {
            username,
            sid,
            profile_path,
            hive_path,
            last_load_time,
            last_unload_time,
            local_profile_flags,
            loaded,
        });
    }

    out
}

// ---------------------------------------------------------------------------
// 9. USBSTOR / USB / MountedDevices
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDeviceRecord {
    pub device_name: String,
    pub description: String,
    pub device_type: String,
    pub connected: Option<bool>,
    pub safe_to_unplug: Option<bool>,
    pub vendor_id: Option<String>,
    pub product_id: Option<String>,
    pub serial_number: Option<String>,
    pub drive_letter: Option<String>,
    pub created_date: Option<DateTime<Utc>>,
    pub last_plug_date: Option<DateTime<Utc>>,
    pub last_removal_date: Option<DateTime<Utc>>,
    pub registry_key: String,
    pub instance_id: String,
}

fn strip_inf_resource_prefix(raw: &str) -> String {
    if let Some((_, after_semi)) = raw.split_once(';') {
        after_semi.trim().to_string()
    } else {
        raw.trim().to_string()
    }
}

fn parse_usbstor_class_name(class_name: &str) -> (Option<String>, Option<String>) {
    let mut vendor = None;
    let mut product = None;
    for part in class_name.split('&') {
        if let Some(v) = part.strip_prefix("Ven_").or_else(|| part.strip_prefix("ven_")) {
            vendor = Some(v.replace('_', " "));
        } else if let Some(p) = part.strip_prefix("Prod_").or_else(|| part.strip_prefix("prod_")) {
            product = Some(p.replace('_', " "));
        }
    }
    (vendor, product)
}

fn read_prop_filetime(tree: &RegTree, inst_node: &RegNode, prop_id: &str) -> Option<DateTime<Utc>> {
    let (_, props) = tree.find_child(inst_node, "Properties")?;
    let (_, guid_node) = tree.find_child(props, "{83da6326-97a6-4088-9453-a1923f573b29}")?;
    let val = guid_node.value(prop_id)?;
    if val.raw_bytes.len() >= 8 {
        let ft = u64::from_le_bytes([
            val.raw_bytes[0],
            val.raw_bytes[1],
            val.raw_bytes[2],
            val.raw_bytes[3],
            val.raw_bytes[4],
            val.raw_bytes[5],
            val.raw_bytes[6],
            val.raw_bytes[7],
        ]);
        filetime_to_utc(ft)
    } else {
        None
    }
}

pub fn decode_mounted_devices_tree(tree: &RegTree) -> BTreeMap<String, String> {
    let mut serial_to_drive = BTreeMap::new();
    let Some(root) = tree.root() else {
        return serial_to_drive;
    };
    for val in &root.values {
        let Some(drive_part) = val.name.strip_prefix("\\DosDevices\\") else {
            continue;
        };
        let utf16 = read_utf16_le(&val.raw_bytes);
        let upper = utf16.to_ascii_uppercase();
        if let Some(idx) = upper.find("USBSTOR#") {
            let tail = &utf16[idx..];
            let segs: Vec<&str> = tail.split('#').collect();
            if segs.len() >= 3 {
                let raw_ser = segs[2].split('&').next().unwrap_or(segs[2]).trim();
                if !raw_ser.is_empty() {
                    serial_to_drive.insert(raw_ser.to_ascii_uppercase(), drive_part.to_string());
                }
            }
        }
    }
    serial_to_drive
}

pub fn decode_usb_trees(
    usbstor: Option<&RegTree>,
    usb: Option<&RegTree>,
    mounted_drives: &BTreeMap<String, String>,
) -> Vec<UsbDeviceRecord> {
    let mut usb_vid_pid_by_serial: BTreeMap<String, (Option<String>, Option<String>)> = BTreeMap::new();
    let mut records = Vec::new();

    if let Some(usb_tree) = usb
        && let Some(root) = usb_tree.root()
    {
        for &hw_idx in &root.children {
            let Some(hw_node) = usb_tree.node(hw_idx) else {
                continue;
            };
            let hw_upper = hw_node.name.to_ascii_uppercase();
            if hw_upper.starts_with("ROOT_HUB") {
                continue;
            }
            for &inst_idx in &hw_node.children {
                let Some(inst_node) = usb_tree.node(inst_idx) else {
                    continue;
                };
                let instance_id = format!("USB\\{}\\{}", hw_node.name, inst_node.name);
                let (vid, pid, serial_opt, dev_type) = extract_vid_pid_serial(&instance_id);
                if let Some(ref ser) = serial_opt {
                    usb_vid_pid_by_serial.insert(ser.to_ascii_uppercase(), (vid.clone(), pid.clone()));
                }
                let raw_desc = inst_node
                    .value("DeviceDesc")
                    .map(|v| strip_inf_resource_prefix(&v.data.decoded_string()))
                    .unwrap_or_else(|| hw_node.name.clone());
                let friendly = inst_node
                    .value("FriendlyName")
                    .map(|v| v.data.decoded_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| raw_desc.clone());
                let created_date = read_prop_filetime(usb_tree, inst_node, "0065").or(inst_node.last_write_time);
                let last_plug_date = read_prop_filetime(usb_tree, inst_node, "0066").or(inst_node.last_write_time);
                let last_removal_date = read_prop_filetime(usb_tree, inst_node, "0067");
                let drive_letter = serial_opt
                    .as_deref()
                    .and_then(|s| mounted_drives.get(&s.to_ascii_uppercase()).cloned());
                let reg_key = format!("{}\\{}\\{}", usb_tree.root_label, hw_node.name, inst_node.name);

                records.push(UsbDeviceRecord {
                    device_name: friendly,
                    description: raw_desc,
                    device_type: dev_type,
                    connected: None,
                    safe_to_unplug: None,
                    vendor_id: vid,
                    product_id: pid,
                    serial_number: serial_opt,
                    drive_letter,
                    created_date,
                    last_plug_date,
                    last_removal_date,
                    registry_key: reg_key,
                    instance_id,
                });
            }
        }
    }

    if let Some(stor_tree) = usbstor
        && let Some(root) = stor_tree.root()
    {
        for &hw_idx in &root.children {
            let Some(hw_node) = stor_tree.node(hw_idx) else {
                continue;
            };
            let (ven, prod) = parse_usbstor_class_name(&hw_node.name);
            for &inst_idx in &hw_node.children {
                let Some(inst_node) = stor_tree.node(inst_idx) else {
                    continue;
                };
                let instance_id = format!("USBSTOR\\{}\\{}", hw_node.name, inst_node.name);
                let serial = inst_node.name.split('&').next().unwrap_or(&inst_node.name).to_string();
                let (vid, pid) = usb_vid_pid_by_serial
                    .get(&serial.to_ascii_uppercase())
                    .cloned()
                    .unwrap_or((None, None));
                let raw_desc = inst_node
                    .value("DeviceDesc")
                    .map(|v| strip_inf_resource_prefix(&v.data.decoded_string()))
                    .unwrap_or_else(|| match (&ven, &prod) {
                        (Some(v), Some(p)) => format!("{v} {p}"),
                        _ => hw_node.name.clone(),
                    });
                let friendly = inst_node
                    .value("FriendlyName")
                    .map(|v| v.data.decoded_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| raw_desc.clone());
                let created_date = read_prop_filetime(stor_tree, inst_node, "0065").or(inst_node.last_write_time);
                let last_plug_date = read_prop_filetime(stor_tree, inst_node, "0066").or(inst_node.last_write_time);
                let last_removal_date = read_prop_filetime(stor_tree, inst_node, "0067");
                let drive_letter = mounted_drives.get(&serial.to_ascii_uppercase()).cloned();
                let reg_key = format!("{}\\{}\\{}", stor_tree.root_label, hw_node.name, inst_node.name);

                records.push(UsbDeviceRecord {
                    device_name: friendly,
                    description: raw_desc,
                    device_type: "Mass Storage".to_string(),
                    connected: None,
                    safe_to_unplug: None,
                    vendor_id: vid,
                    product_id: pid,
                    serial_number: Some(serial),
                    drive_letter,
                    created_date,
                    last_plug_date,
                    last_removal_date,
                    registry_key: reg_key,
                    instance_id,
                });
            }
        }
    }

    records
}

/// Extracts `SYSTEM` hive `AppCompatCache` bytes from an offline `SYSTEM` hive.
pub fn extract_shimcache_bytes_from_hive(hive: &RegfHive) -> Option<Vec<u8>> {
    let cs = resolve_system_control_set(hive);
    let path1 = format!("{cs}\\Control\\Session Manager\\AppCompatCache");
    let key = find_hive_key(
        hive,
        &[
            &path1,
            "Control\\Session Manager\\AppCompatCache",
            "CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
        ],
    )?;
    key.value("AppCompatCache").map(|v| v.raw_bytes.clone())
}
