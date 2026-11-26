#![forbid(unsafe_code)]

//! Windows Defender posture model, WMI + Registry + GPO correlation, exclusion sentinel
//! filtering, and offline `regf` `SOFTWARE` hive / WMI JSON parsers for `posture.defender_status`.

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use forensics2rust_core::{DiagnosticWarning, ForensicError, WarningSeverity, filetime_to_utc};
use forensics2rust_hive::live::LiveRegistryEntry;
use forensics2rust_hive::regf::{RegKeyRef, RegValueData, RegfHive};
use serde::Deserialize;

use crate::discovery::parse_flexible_timestamp;

/// Windows 11 non-admin sentinel string returned by `MSFT_MpPreference` when
/// `HideExclusionsFromLocalUsers` is enabled.
pub const HIDDEN_EXCLUSIONS_SENTINEL: &str = "N/A: Must be an administrator to view exclusions";

/// Raw WMI snapshot collected from `root\Microsoft\Windows\Defender` (`MSFT_MpComputerStatus` + `MSFT_MpPreference`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DefenderWmiSnapshot {
    #[serde(alias = "AMServiceEnabled")]
    pub am_service_enabled: Option<bool>,
    #[serde(alias = "AntivirusEnabled")]
    pub antivirus_enabled: Option<bool>,
    #[serde(alias = "AntispywareEnabled")]
    pub antispyware_enabled: Option<bool>,
    #[serde(alias = "RealTimeProtectionEnabled")]
    pub real_time_protection_enabled: Option<bool>,
    #[serde(alias = "BehaviorMonitorEnabled")]
    pub behavior_monitor_enabled: Option<bool>,
    #[serde(alias = "IoavProtectionEnabled")]
    pub ioav_protection_enabled: Option<bool>,
    #[serde(alias = "OnAccessProtectionEnabled")]
    pub on_access_protection_enabled: Option<bool>,
    #[serde(alias = "NISEnabled")]
    pub nis_enabled: Option<bool>,
    #[serde(alias = "IsTamperProtected")]
    pub is_tamper_protected: Option<bool>,
    #[serde(alias = "TamperProtectionSource")]
    pub tamper_protection_source: Option<String>,
    #[serde(alias = "AMRunningMode")]
    pub am_running_mode: Option<String>,
    #[serde(alias = "AMProductVersion")]
    pub am_product_version: Option<String>,
    #[serde(alias = "AMServiceVersion")]
    pub am_service_version: Option<String>,
    #[serde(alias = "AMEngineVersion")]
    pub am_engine_version: Option<String>,
    #[serde(alias = "AntivirusSignatureVersion")]
    pub antivirus_signature_version: Option<String>,
    #[serde(alias = "AntivirusSignatureLastUpdated")]
    pub antivirus_signature_last_updated: Option<String>,
    #[serde(alias = "AntivirusSignatureAge")]
    pub antivirus_signature_age: Option<u32>,
    #[serde(alias = "QuickScanAge")]
    pub quick_scan_age: Option<u32>,
    #[serde(alias = "FullScanAge")]
    pub full_scan_age: Option<u32>,
    #[serde(alias = "QuickScanEndTime")]
    pub quick_scan_end_time: Option<String>,
    #[serde(alias = "FullScanEndTime")]
    pub full_scan_end_time: Option<String>,
    #[serde(alias = "DefenderSignaturesOutOfDate")]
    pub defender_signatures_out_of_date: Option<bool>,
    #[serde(alias = "RebootRequired")]
    pub reboot_required: Option<bool>,
    #[serde(alias = "SmartAppControlState")]
    pub smart_app_control_state: Option<String>,
    #[serde(alias = "ProductStatus")]
    pub product_status: Option<u32>,

    // MSFT_MpPreference fields
    #[serde(alias = "DisableRealtimeMonitoring")]
    pub disable_realtime_monitoring: Option<bool>,
    #[serde(alias = "DisableBehaviorMonitoring")]
    pub disable_behavior_monitoring: Option<bool>,
    #[serde(alias = "DisableIOAVProtection")]
    pub disable_ioav_protection: Option<bool>,
    #[serde(alias = "DisableTamperProtection")]
    pub disable_tamper_protection: Option<bool>,
    #[serde(alias = "PUAProtection")]
    pub pua_protection: Option<u32>,
    #[serde(alias = "MAPSReporting")]
    pub maps_reporting: Option<u32>,
    #[serde(alias = "SubmitSamplesConsent")]
    pub submit_samples_consent: Option<u32>,
    #[serde(alias = "CloudBlockLevel")]
    pub cloud_block_level: Option<u32>,
    #[serde(alias = "HideExclusionsFromLocalUsers")]
    pub hide_exclusions_from_local_users: Option<bool>,
    #[serde(alias = "ExclusionPath", default)]
    pub exclusion_path: Vec<String>,
    #[serde(alias = "ExclusionProcess", default)]
    pub exclusion_process: Vec<String>,
    #[serde(alias = "ExclusionExtension", default)]
    pub exclusion_extension: Vec<String>,
    #[serde(alias = "ExclusionIpAddress", default)]
    pub exclusion_ip_address: Vec<String>,
    #[serde(alias = "AttackSurfaceReductionRules_Ids", default)]
    pub asr_rule_ids: Vec<String>,
    #[serde(alias = "AttackSurfaceReductionRules_Actions", default)]
    pub asr_rule_actions: Vec<u8>,
}

/// Registry-derived Defender snapshot supporting local keys and `Policies` GPO overrides.
#[derive(Debug, Clone, Default)]
pub struct DefenderRegistrySnapshot {
    pub passive_mode: Option<bool>,
    pub is_service_running: Option<bool>,
    pub disable_anti_spyware: Option<bool>,
    pub disable_anti_virus: Option<bool>,
    pub disable_realtime_monitoring: Option<bool>,
    pub disable_behavior_monitoring: Option<bool>,
    pub disable_on_access_protection: Option<bool>,
    pub disable_ioav_protection: Option<bool>,
    pub tamper_protected: Option<bool>,
    pub tamper_source: Option<String>,
    pub engine_version: Option<String>,
    pub signature_version: Option<String>,
    pub signature_updated: Option<DateTime<Utc>>,
    pub signature_location: Option<String>,
    pub quick_scan_age: Option<u32>,
    pub full_scan_age: Option<u32>,
    pub pua_protection: Option<u32>,
    pub maps_reporting: Option<u32>,
    pub submit_samples_consent: Option<u32>,
    pub install_location: Option<String>,
    pub exclusion_paths: Vec<String>,
    pub exclusion_processes: Vec<String>,
    pub exclusion_extensions: Vec<String>,
    pub exclusion_ip_addresses: Vec<String>,
    pub exclusions_access_denied: bool,
    pub gpo_overrides: BTreeMap<String, serde_json::Value>,
}

/// Unified correlated Defender posture row for `posture.defender_status`.
#[derive(Debug, Clone)]
pub struct DefenderPostureRecord {
    pub am_service_enabled: Option<bool>,
    pub antivirus_enabled: Option<bool>,
    pub real_time_protection: Option<bool>,
    pub behavior_monitor_enabled: Option<bool>,
    pub ioav_protection_enabled: Option<bool>,
    pub on_access_protection: Option<bool>,
    pub tamper_protected: Option<bool>,
    pub tamper_source: Option<String>,
    pub am_running_mode: Option<String>,
    pub am_product_version: Option<String>,
    pub am_engine_version: Option<String>,
    pub signature_version: Option<String>,
    pub signature_updated: Option<DateTime<Utc>>,
    pub signature_age_days: Option<u32>,
    pub quick_scan_age: Option<u32>,
    pub full_scan_age: Option<u32>,
    pub pua_protection: Option<String>,
    pub maps_reporting: Option<String>,
    pub submit_samples_consent: Option<String>,
    pub passive_mode: Option<bool>,
    pub gpo_override_count: u32,
    pub exclusion_paths: Vec<String>,
    pub exclusion_processes: Vec<String>,
    pub exclusion_extensions: Vec<String>,
    pub exclusion_ip_addresses: Vec<String>,
    pub exclusions_hidden: bool,
    pub source_origin: String,
    pub gpo_overrides: BTreeMap<String, serde_json::Value>,
    pub raw_detail: serde_json::Value,
}

pub fn map_pua_protection(code: u32) -> String {
    match code {
        0 => "Disabled".to_string(),
        1 => "Enabled".to_string(),
        2 => "AuditMode".to_string(),
        other => format!("Unknown({other})"),
    }
}

pub fn map_maps_reporting(code: u32) -> String {
    match code {
        0 => "Disabled".to_string(),
        1 => "Basic".to_string(),
        2 => "Advanced".to_string(),
        other => format!("Unknown({other})"),
    }
}

pub fn map_submit_samples_consent(code: u32) -> String {
    match code {
        0 => "AlwaysPrompt".to_string(),
        1 => "SendSafeSamples".to_string(),
        2 => "NeverSend".to_string(),
        3 => "SendAllSamples".to_string(),
        other => format!("Unknown({other})"),
    }
}

fn map_tamper_source_code(code: u32) -> String {
    match code {
        1 => "Disabled".to_string(),
        2 => "UI".to_string(),
        3 => "ATP".to_string(),
        4 => "MDM".to_string(),
        5 => "Default".to_string(),
        other => format!("Source({other})"),
    }
}

/// Checks if a string matches the Windows non-admin exclusion redaction sentinel.
pub fn is_hidden_exclusions_sentinel(s: &str) -> bool {
    let lower = s.trim().to_ascii_lowercase();
    lower == HIDDEN_EXCLUSIONS_SENTINEL.to_ascii_lowercase()
        || lower.contains("must be an administrator to view exclusions")
}

fn sanitize_scan_age(age: Option<u32>) -> Option<u32> {
    age.filter(|&v| v != u32::MAX)
}

fn filter_exclusions(items: &[String], hidden: &mut bool) -> Vec<String> {
    let mut out = Vec::new();
    for item in items {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        if is_hidden_exclusions_sentinel(trimmed) {
            *hidden = true;
            continue;
        }
        if !out.contains(&trimmed.to_string()) {
            out.push(trimmed.to_string());
        }
    }
    out
}

/// Merges optional WMI and Registry snapshots into a correlated `DefenderPostureRecord`.
pub fn correlate_defender_snapshots(
    wmi: Option<DefenderWmiSnapshot>,
    reg: Option<DefenderRegistrySnapshot>,
    source_origin: &str,
    tool_id: &str,
    warnings: &mut Vec<DiagnosticWarning>,
) -> DefenderPostureRecord {
    let mut exclusions_hidden = wmi
        .as_ref()
        .and_then(|w| w.hide_exclusions_from_local_users)
        .unwrap_or(false);

    if reg.as_ref().is_some_and(|r| r.exclusions_access_denied) {
        exclusions_hidden = true;
    }

    let mut exclusion_paths = Vec::new();
    let mut exclusion_processes = Vec::new();
    let mut exclusion_extensions = Vec::new();
    let mut exclusion_ip_addresses = Vec::new();

    if let Some(ref w) = wmi {
        exclusion_paths.extend(filter_exclusions(&w.exclusion_path, &mut exclusions_hidden));
        exclusion_processes.extend(filter_exclusions(&w.exclusion_process, &mut exclusions_hidden));
        exclusion_extensions.extend(filter_exclusions(&w.exclusion_extension, &mut exclusions_hidden));
        exclusion_ip_addresses.extend(filter_exclusions(&w.exclusion_ip_address, &mut exclusions_hidden));
    }

    if let Some(ref r) = reg {
        for p in &r.exclusion_paths {
            if !exclusion_paths.contains(p) {
                exclusion_paths.push(p.clone());
            }
        }
        for p in &r.exclusion_processes {
            if !exclusion_processes.contains(p) {
                exclusion_processes.push(p.clone());
            }
        }
        for p in &r.exclusion_extensions {
            if !exclusion_extensions.contains(p) {
                exclusion_extensions.push(p.clone());
            }
        }
        for p in &r.exclusion_ip_addresses {
            if !exclusion_ip_addresses.contains(p) {
                exclusion_ip_addresses.push(p.clone());
            }
        }
    }

    if exclusions_hidden {
        warnings.push(DiagnosticWarning {
            severity: WarningSeverity::Warn,
            tool_id: tool_id.to_string(),
            source: source_origin.to_string(),
            message: "Windows Defender exclusions are hidden for non-administrator users (HideExclusionsFromLocalUsers=true / access denied)".to_string(),
        });
    }

    let gpo_overrides = reg.as_ref().map(|r| r.gpo_overrides.clone()).unwrap_or_default();
    let gpo_override_count = gpo_overrides.len() as u32;

    let am_service_enabled = wmi
        .as_ref()
        .and_then(|w| w.am_service_enabled)
        .or_else(|| reg.as_ref().and_then(|r| r.is_service_running));

    let antivirus_enabled = if gpo_overrides.contains_key("DisableAntiVirus") {
        reg.as_ref().and_then(|r| r.disable_anti_virus.map(|d| !d))
    } else if gpo_overrides.contains_key("DisableAntiSpyware") {
        reg.as_ref().and_then(|r| r.disable_anti_spyware.map(|d| !d))
    } else {
        wmi.as_ref()
            .and_then(|w| w.antivirus_enabled)
            .or_else(|| reg.as_ref().and_then(|r| r.disable_anti_virus.map(|d| !d)))
            .or_else(|| reg.as_ref().and_then(|r| r.disable_anti_spyware.map(|d| !d)))
    };

    let real_time_protection = if gpo_overrides.contains_key("Real-Time Protection\\DisableRealtimeMonitoring")
        || gpo_overrides.contains_key("DisableRealtimeMonitoring")
    {
        reg.as_ref().and_then(|r| r.disable_realtime_monitoring.map(|d| !d))
    } else {
        wmi.as_ref()
            .and_then(|w| w.real_time_protection_enabled)
            .or_else(|| wmi.as_ref().and_then(|w| w.disable_realtime_monitoring.map(|d| !d)))
            .or_else(|| reg.as_ref().and_then(|r| r.disable_realtime_monitoring.map(|d| !d)))
    };

    let behavior_monitor_enabled = if gpo_overrides.contains_key("Real-Time Protection\\DisableBehaviorMonitoring")
        || gpo_overrides.contains_key("DisableBehaviorMonitoring")
    {
        reg.as_ref().and_then(|r| r.disable_behavior_monitoring.map(|d| !d))
    } else {
        wmi.as_ref()
            .and_then(|w| w.behavior_monitor_enabled)
            .or_else(|| wmi.as_ref().and_then(|w| w.disable_behavior_monitoring.map(|d| !d)))
            .or_else(|| reg.as_ref().and_then(|r| r.disable_behavior_monitoring.map(|d| !d)))
    };

    let ioav_protection_enabled = if gpo_overrides.contains_key("Real-Time Protection\\DisableIOAVProtection")
        || gpo_overrides.contains_key("DisableIOAVProtection")
    {
        reg.as_ref().and_then(|r| r.disable_ioav_protection.map(|d| !d))
    } else {
        wmi.as_ref()
            .and_then(|w| w.ioav_protection_enabled)
            .or_else(|| wmi.as_ref().and_then(|w| w.disable_ioav_protection.map(|d| !d)))
            .or_else(|| reg.as_ref().and_then(|r| r.disable_ioav_protection.map(|d| !d)))
    };

    let on_access_protection = if gpo_overrides.contains_key("Real-Time Protection\\DisableOnAccessProtection")
        || gpo_overrides.contains_key("DisableOnAccessProtection")
    {
        reg.as_ref().and_then(|r| r.disable_on_access_protection.map(|d| !d))
    } else {
        wmi.as_ref()
            .and_then(|w| w.on_access_protection_enabled)
            .or_else(|| reg.as_ref().and_then(|r| r.disable_on_access_protection.map(|d| !d)))
    };

    let tamper_protected = wmi
        .as_ref()
        .and_then(|w| w.is_tamper_protected)
        .or_else(|| wmi.as_ref().and_then(|w| w.disable_tamper_protection.map(|d| !d)))
        .or_else(|| reg.as_ref().and_then(|r| r.tamper_protected));

    let tamper_source = wmi
        .as_ref()
        .and_then(|w| w.tamper_protection_source.clone())
        .or_else(|| reg.as_ref().and_then(|r| r.tamper_source.clone()));

    let passive_mode = reg.as_ref().and_then(|r| r.passive_mode);

    let am_running_mode = if gpo_overrides.contains_key("PassiveMode") {
        passive_mode
            .map(|p| if p { "Passive" } else { "Normal" }.to_string())
            .or_else(|| wmi.as_ref().and_then(|w| w.am_running_mode.clone()))
    } else {
        wmi.as_ref()
            .and_then(|w| w.am_running_mode.clone())
            .or_else(|| passive_mode.map(|p| if p { "Passive" } else { "Normal" }.to_string()))
    };

    let am_product_version = wmi.as_ref().and_then(|w| w.am_product_version.clone());
    let am_engine_version = wmi
        .as_ref()
        .and_then(|w| w.am_engine_version.clone())
        .or_else(|| reg.as_ref().and_then(|r| r.engine_version.clone()));

    let signature_version = wmi
        .as_ref()
        .and_then(|w| w.antivirus_signature_version.clone())
        .or_else(|| reg.as_ref().and_then(|r| r.signature_version.clone()));

    let signature_updated = wmi
        .as_ref()
        .and_then(|w| w.antivirus_signature_last_updated.as_deref())
        .and_then(parse_flexible_timestamp)
        .or_else(|| reg.as_ref().and_then(|r| r.signature_updated));

    let signature_age_days = sanitize_scan_age(wmi.as_ref().and_then(|w| w.antivirus_signature_age));
    let quick_scan_age = sanitize_scan_age(
        wmi.as_ref()
            .and_then(|w| w.quick_scan_age)
            .or_else(|| reg.as_ref().and_then(|r| r.quick_scan_age)),
    );
    let full_scan_age = sanitize_scan_age(
        wmi.as_ref()
            .and_then(|w| w.full_scan_age)
            .or_else(|| reg.as_ref().and_then(|r| r.full_scan_age)),
    );

    // GPO / Registry override precedes WMI preference when GPO overrides exist for PUA/MAPS/Consent.
    let pua_code = if gpo_overrides.contains_key("PUAProtection") {
        reg.as_ref().and_then(|r| r.pua_protection)
    } else {
        wmi.as_ref()
            .and_then(|w| w.pua_protection)
            .or_else(|| reg.as_ref().and_then(|r| r.pua_protection))
    };
    let pua_protection = pua_code.map(map_pua_protection);

    let maps_code = if gpo_overrides.contains_key("SpyNetReporting") {
        reg.as_ref().and_then(|r| r.maps_reporting)
    } else {
        wmi.as_ref()
            .and_then(|w| w.maps_reporting)
            .or_else(|| reg.as_ref().and_then(|r| r.maps_reporting))
    };
    let maps_reporting = maps_code.map(map_maps_reporting);

    let consent_code = if gpo_overrides.contains_key("SubmitSamplesConsent") {
        reg.as_ref().and_then(|r| r.submit_samples_consent)
    } else {
        wmi.as_ref()
            .and_then(|w| w.submit_samples_consent)
            .or_else(|| reg.as_ref().and_then(|r| r.submit_samples_consent))
    };
    let submit_samples_consent = consent_code.map(map_submit_samples_consent);

    let raw_detail = serde_json::json!({
        "exclusions_hidden": exclusions_hidden,
        "exclusion_paths": exclusion_paths,
        "exclusion_processes": exclusion_processes,
        "exclusion_extensions": exclusion_extensions,
        "exclusion_ip_addresses": exclusion_ip_addresses,
        "gpo_override_count": gpo_override_count,
        "gpo_overrides": gpo_overrides,
        "install_location": reg.as_ref().and_then(|r| r.install_location.clone()),
        "signature_location": reg.as_ref().and_then(|r| r.signature_location.clone()),
        "quick_scan_end_time": wmi.as_ref().and_then(|w| w.quick_scan_end_time.clone()),
        "full_scan_end_time": wmi.as_ref().and_then(|w| w.full_scan_end_time.clone()),
        "smart_app_control_state": wmi.as_ref().and_then(|w| w.smart_app_control_state.clone()),
        "reboot_required": wmi.as_ref().and_then(|w| w.reboot_required),
        "defender_signatures_out_of_date": wmi.as_ref().and_then(|w| w.defender_signatures_out_of_date),
        "nis_enabled": wmi.as_ref().and_then(|w| w.nis_enabled),
        "asr_rule_ids": wmi.as_ref().map(|w| &w.asr_rule_ids),
        "asr_rule_actions": wmi.as_ref().map(|w| &w.asr_rule_actions),
        "source_origin": source_origin,
    });

    DefenderPostureRecord {
        am_service_enabled,
        antivirus_enabled,
        real_time_protection,
        behavior_monitor_enabled,
        ioav_protection_enabled,
        on_access_protection,
        tamper_protected,
        tamper_source,
        am_running_mode,
        am_product_version,
        am_engine_version,
        signature_version,
        signature_updated,
        signature_age_days,
        quick_scan_age,
        full_scan_age,
        pua_protection,
        maps_reporting,
        submit_samples_consent,
        passive_mode,
        gpo_override_count,
        exclusion_paths,
        exclusion_processes,
        exclusion_extensions,
        exclusion_ip_addresses,
        exclusions_hidden,
        source_origin: source_origin.to_string(),
        gpo_overrides,
        raw_detail,
    }
}

/// Parses Defender configuration & GPO policy overrides from an offline `SOFTWARE` `regf` hive.
pub fn parse_defender_from_regf_path(
    path: &Path,
) -> Result<(DefenderRegistrySnapshot, Vec<DiagnosticWarning>), ForensicError> {
    let hive = RegfHive::open_tolerant(path)?;
    parse_defender_from_regf(&hive, &path.display().to_string())
}

/// Parses Defender configuration & GPO policy overrides from in-memory `SOFTWARE` `regf` bytes.
pub fn parse_defender_from_regf_bytes(
    bytes: &[u8],
    source_label: &str,
) -> Result<(DefenderRegistrySnapshot, Vec<DiagnosticWarning>), ForensicError> {
    let hive = RegfHive::from_bytes_tolerant(bytes)?;
    parse_defender_from_regf(&hive, source_label)
}

/// Extracts Defender Registry posture from an opened `RegfHive` (`SOFTWARE`).
pub fn parse_defender_from_regf(
    hive: &RegfHive,
    source_label: &str,
) -> Result<(DefenderRegistrySnapshot, Vec<DiagnosticWarning>), ForensicError> {
    let mut warnings: Vec<DiagnosticWarning> = hive
        .diagnostics()
        .iter()
        .map(|msg| DiagnosticWarning {
            severity: WarningSeverity::Info,
            tool_id: "posture.defender_status".to_string(),
            source: source_label.to_string(),
            message: msg.clone(),
        })
        .collect();

    let local_root = hive
        .find_key("Microsoft\\Windows Defender")
        .or_else(|| hive.find_key("SOFTWARE\\Microsoft\\Windows Defender"));

    let policy_root = hive
        .find_key("Policies\\Microsoft\\Windows Defender")
        .or_else(|| hive.find_key("SOFTWARE\\Policies\\Microsoft\\Windows Defender"));

    if local_root.is_none() && policy_root.is_none() {
        return Err(ForensicError::NotFound(format!(
            "Microsoft\\Windows Defender key not found in hive {source_label}"
        )));
    }

    let mut snap = DefenderRegistrySnapshot::default();
    if let Some(root) = local_root {
        apply_regf_defender_subtree(&root, &mut snap, false);
    }
    if let Some(pol) = policy_root {
        apply_regf_defender_subtree(&pol, &mut snap, true);
    }

    if snap.exclusion_paths.is_empty()
        && snap.exclusion_processes.is_empty()
        && snap.exclusion_extensions.is_empty()
        && snap.exclusion_ip_addresses.is_empty()
        && local_root.is_some_and(|k| k.find_subkey("Exclusions").is_none())
    {
        warnings.push(DiagnosticWarning {
            severity: WarningSeverity::Info,
            tool_id: "posture.defender_status".to_string(),
            source: source_label.to_string(),
            message: "Exclusions subkey not present in offline hive".to_string(),
        });
    }

    Ok((snap, warnings))
}

fn apply_regf_defender_subtree(root: &RegKeyRef<'_>, snap: &mut DefenderRegistrySnapshot, is_policy: bool) {
    apply_root_values(
        root.values()
            .iter()
            .map(|v| (v.name.as_str(), reg_value_to_typed(&v.data))),
        snap,
        is_policy,
    );

    if let Some(rtp) = root.find_subkey("Real-Time Protection") {
        apply_rtp_values(
            rtp.values()
                .iter()
                .map(|v| (v.name.as_str(), reg_value_to_typed(&v.data))),
            snap,
            is_policy,
        );
    }
    if let Some(sig) = root.find_subkey("Signature Updates") {
        apply_signature_values(
            sig.values()
                .iter()
                .map(|v| (v.name.as_str(), reg_value_to_typed(&v.data))),
            snap,
            is_policy,
        );
    }
    if let Some(feat) = root.find_subkey("Features") {
        apply_features_values(
            feat.values()
                .iter()
                .map(|v| (v.name.as_str(), reg_value_to_typed(&v.data))),
            snap,
            is_policy,
        );
    }
    if let Some(spynet) = root.find_subkey("Spynet") {
        apply_spynet_values(
            spynet
                .values()
                .iter()
                .map(|v| (v.name.as_str(), reg_value_to_typed(&v.data))),
            snap,
            is_policy,
        );
    }
    if let Some(scan) = root.find_subkey("Scan") {
        apply_scan_values(
            scan.values()
                .iter()
                .map(|v| (v.name.as_str(), reg_value_to_typed(&v.data))),
            snap,
            is_policy,
        );
    }
    if let Some(excl) = root.find_subkey("Exclusions") {
        for (subname, target) in [
            ("Paths", &mut snap.exclusion_paths),
            ("Processes", &mut snap.exclusion_processes),
            ("Extensions", &mut snap.exclusion_extensions),
            ("IpAddresses", &mut snap.exclusion_ip_addresses),
        ] {
            if let Some(sub) = excl.find_subkey(subname) {
                for val in sub.values() {
                    let name = val.name.trim();
                    if !name.is_empty() && !target.contains(&name.to_string()) {
                        target.push(name.to_string());
                        if is_policy {
                            snap.gpo_overrides
                                .insert(format!("Exclusions\\{subname}\\{name}"), serde_json::json!(true));
                        }
                    }
                }
            }
        }
    }
}

/// Converts live Registry scan entries (`forensics2rust_hive::live::scan_live_registry`)
/// into a correlated `DefenderRegistrySnapshot`.
pub fn parse_defender_from_live_registry(
    local_entries: &[LiveRegistryEntry],
    policy_entries: &[LiveRegistryEntry],
    live_warnings: Vec<DiagnosticWarning>,
) -> (Option<DefenderRegistrySnapshot>, Vec<DiagnosticWarning>) {
    if local_entries.is_empty() && policy_entries.is_empty() {
        return (None, live_warnings);
    }

    let mut snap = DefenderRegistrySnapshot::default();
    let mut warnings = Vec::new();
    for w in live_warnings {
        if w.source.to_ascii_lowercase().contains("exclusions") {
            snap.exclusions_access_denied = true;
        } else {
            warnings.push(w);
        }
    }

    for entry in local_entries {
        apply_live_entry(entry, &mut snap, false);
    }
    for entry in policy_entries {
        apply_live_entry(entry, &mut snap, true);
    }

    (Some(snap), warnings)
}

fn apply_live_entry(entry: &LiveRegistryEntry, snap: &mut DefenderRegistrySnapshot, is_policy: bool) {
    let lower = entry.key_path.to_ascii_lowercase();
    let leaf = lower.rsplit('\\').next().unwrap_or("");

    let pairs = entry
        .values
        .iter()
        .map(|v| (v.name.as_str(), reg_value_to_typed(&v.data)));

    if lower.ends_with("\\windows defender") || leaf == "windows defender" {
        apply_root_values(pairs, snap, is_policy);
    } else if leaf == "real-time protection" {
        apply_rtp_values(pairs, snap, is_policy);
    } else if leaf == "signature updates" {
        apply_signature_values(pairs, snap, is_policy);
    } else if leaf == "features" {
        apply_features_values(pairs, snap, is_policy);
    } else if leaf == "spynet" {
        apply_spynet_values(pairs, snap, is_policy);
    } else if leaf == "scan" {
        apply_scan_values(pairs, snap, is_policy);
    } else if lower.contains("\\exclusions\\paths") {
        collect_live_exclusions(
            entry,
            &mut snap.exclusion_paths,
            is_policy,
            &mut snap.gpo_overrides,
            "Paths",
        );
    } else if lower.contains("\\exclusions\\processes") {
        collect_live_exclusions(
            entry,
            &mut snap.exclusion_processes,
            is_policy,
            &mut snap.gpo_overrides,
            "Processes",
        );
    } else if lower.contains("\\exclusions\\extensions") {
        collect_live_exclusions(
            entry,
            &mut snap.exclusion_extensions,
            is_policy,
            &mut snap.gpo_overrides,
            "Extensions",
        );
    } else if lower.contains("\\exclusions\\ipaddresses") {
        collect_live_exclusions(
            entry,
            &mut snap.exclusion_ip_addresses,
            is_policy,
            &mut snap.gpo_overrides,
            "IpAddresses",
        );
    }
}

fn collect_live_exclusions(
    entry: &LiveRegistryEntry,
    target: &mut Vec<String>,
    is_policy: bool,
    gpo_overrides: &mut BTreeMap<String, serde_json::Value>,
    subname: &str,
) {
    for val in &entry.values {
        let name = val.name.trim();
        if !name.is_empty() && !target.contains(&name.to_string()) {
            target.push(name.to_string());
            if is_policy {
                gpo_overrides.insert(format!("Exclusions\\{subname}\\{name}"), serde_json::json!(true));
            }
        }
    }
}

enum TypedRegVal<'a> {
    Dword(u32),
    Text(String),
    Bytes(&'a [u8]),
    None,
}

fn reg_value_to_typed<'a>(data: &'a RegValueData) -> TypedRegVal<'a> {
    if let Some(d) = data.as_u32() {
        TypedRegVal::Dword(d)
    } else if let Some(s) = data.as_str() {
        TypedRegVal::Text(s.to_string())
    } else if let Some(b) = data.as_bytes() {
        TypedRegVal::Bytes(b)
    } else {
        TypedRegVal::None
    }
}

fn apply_root_values<'a, I>(iter: I, snap: &mut DefenderRegistrySnapshot, is_policy: bool)
where
    I: Iterator<Item = (&'a str, TypedRegVal<'a>)>,
{
    for (name, val) in iter {
        if name.eq_ignore_ascii_case("PassiveMode") {
            if let TypedRegVal::Dword(v) = val {
                snap.passive_mode = Some(v != 0);
                if is_policy {
                    snap.gpo_overrides
                        .insert("PassiveMode".to_string(), serde_json::json!(v));
                }
            }
        } else if name.eq_ignore_ascii_case("IsServiceRunning") {
            if let TypedRegVal::Dword(v) = val {
                snap.is_service_running = Some(v != 0);
            }
        } else if name.eq_ignore_ascii_case("DisableAntiSpyware") {
            if let TypedRegVal::Dword(v) = val {
                snap.disable_anti_spyware = Some(v != 0);
                if is_policy {
                    snap.gpo_overrides
                        .insert("DisableAntiSpyware".to_string(), serde_json::json!(v));
                }
            }
        } else if name.eq_ignore_ascii_case("DisableAntiVirus") {
            if let TypedRegVal::Dword(v) = val {
                snap.disable_anti_virus = Some(v != 0);
                if is_policy {
                    snap.gpo_overrides
                        .insert("DisableAntiVirus".to_string(), serde_json::json!(v));
                }
            }
        } else if name.eq_ignore_ascii_case("PUAProtection") {
            if let TypedRegVal::Dword(v) = val {
                snap.pua_protection = Some(v);
                if is_policy {
                    snap.gpo_overrides
                        .insert("PUAProtection".to_string(), serde_json::json!(v));
                }
            }
        } else if name.eq_ignore_ascii_case("DisableRealtimeMonitoring") {
            if let TypedRegVal::Dword(v) = val {
                snap.disable_realtime_monitoring = Some(v != 0);
                if is_policy {
                    snap.gpo_overrides
                        .insert("DisableRealtimeMonitoring".to_string(), serde_json::json!(v));
                }
            }
        } else if name.eq_ignore_ascii_case("InstallLocation")
            && let TypedRegVal::Text(s) = val
            && !s.is_empty()
        {
            snap.install_location = Some(s);
        }
    }
}

fn apply_rtp_values<'a, I>(iter: I, snap: &mut DefenderRegistrySnapshot, is_policy: bool)
where
    I: Iterator<Item = (&'a str, TypedRegVal<'a>)>,
{
    for (name, val) in iter {
        if let TypedRegVal::Dword(v) = val {
            let b = v != 0;
            if name.eq_ignore_ascii_case("DisableRealtimeMonitoring") {
                snap.disable_realtime_monitoring = Some(b);
                if is_policy {
                    snap.gpo_overrides.insert(
                        "Real-Time Protection\\DisableRealtimeMonitoring".to_string(),
                        serde_json::json!(v),
                    );
                }
            } else if name.eq_ignore_ascii_case("DisableBehaviorMonitoring") {
                snap.disable_behavior_monitoring = Some(b);
                if is_policy {
                    snap.gpo_overrides.insert(
                        "Real-Time Protection\\DisableBehaviorMonitoring".to_string(),
                        serde_json::json!(v),
                    );
                }
            } else if name.eq_ignore_ascii_case("DisableOnAccessProtection") {
                snap.disable_on_access_protection = Some(b);
                if is_policy {
                    snap.gpo_overrides.insert(
                        "Real-Time Protection\\DisableOnAccessProtection".to_string(),
                        serde_json::json!(v),
                    );
                }
            } else if name.eq_ignore_ascii_case("DisableIOAVProtection") {
                snap.disable_ioav_protection = Some(b);
                if is_policy {
                    snap.gpo_overrides.insert(
                        "Real-Time Protection\\DisableIOAVProtection".to_string(),
                        serde_json::json!(v),
                    );
                }
            }
        }
    }
}

fn apply_signature_values<'a, I>(iter: I, snap: &mut DefenderRegistrySnapshot, is_policy: bool)
where
    I: Iterator<Item = (&'a str, TypedRegVal<'a>)>,
{
    for (name, val) in iter {
        if name.eq_ignore_ascii_case("EngineVersion") {
            if let TypedRegVal::Text(s) = val
                && !s.is_empty()
            {
                snap.engine_version = Some(s);
            }
        } else if name.eq_ignore_ascii_case("AVSignatureVersion") {
            if let TypedRegVal::Text(s) = val
                && !s.is_empty()
            {
                snap.signature_version = Some(s);
            }
        } else if name.eq_ignore_ascii_case("ASSignatureVersion") {
            if snap.signature_version.is_none()
                && let TypedRegVal::Text(s) = val
                && !s.is_empty()
            {
                snap.signature_version = Some(s);
            }
        } else if name.eq_ignore_ascii_case("SignatureLocation") {
            if let TypedRegVal::Text(s) = val
                && !s.is_empty()
            {
                snap.signature_location = Some(s.clone());
                if is_policy {
                    snap.gpo_overrides
                        .insert("Signature Updates\\SignatureLocation".to_string(), serde_json::json!(s));
                }
            }
        } else if (name.eq_ignore_ascii_case("SignaturesLastUpdated")
            || name.eq_ignore_ascii_case("AVSignatureApplied")
            || name.eq_ignore_ascii_case("ASSignatureApplied"))
            && let TypedRegVal::Bytes(b) = val
            && b.len() >= 8
        {
            let ft = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
            if let Some(dt) = filetime_to_utc(ft)
                && (snap.signature_updated.is_none() || name.eq_ignore_ascii_case("SignaturesLastUpdated"))
            {
                snap.signature_updated = Some(dt);
            }
        }
    }
}

fn apply_features_values<'a, I>(iter: I, snap: &mut DefenderRegistrySnapshot, _is_policy: bool)
where
    I: Iterator<Item = (&'a str, TypedRegVal<'a>)>,
{
    for (name, val) in iter {
        if let TypedRegVal::Dword(v) = val {
            if name.eq_ignore_ascii_case("TamperProtection") {
                snap.tamper_protected = Some(v != 0 && v != 4);
            } else if name.eq_ignore_ascii_case("TamperProtectionSource") {
                snap.tamper_source = Some(map_tamper_source_code(v));
            }
        }
    }
}

fn apply_spynet_values<'a, I>(iter: I, snap: &mut DefenderRegistrySnapshot, is_policy: bool)
where
    I: Iterator<Item = (&'a str, TypedRegVal<'a>)>,
{
    for (name, val) in iter {
        if let TypedRegVal::Dword(v) = val {
            if name.eq_ignore_ascii_case("SpyNetReporting") {
                snap.maps_reporting = Some(v);
                if is_policy {
                    snap.gpo_overrides
                        .insert("SpyNetReporting".to_string(), serde_json::json!(v));
                }
            } else if name.eq_ignore_ascii_case("SubmitSamplesConsent") {
                snap.submit_samples_consent = Some(v);
                if is_policy {
                    snap.gpo_overrides
                        .insert("SubmitSamplesConsent".to_string(), serde_json::json!(v));
                }
            }
        }
    }
}

fn apply_scan_values<'a, I>(iter: I, snap: &mut DefenderRegistrySnapshot, is_policy: bool)
where
    I: Iterator<Item = (&'a str, TypedRegVal<'a>)>,
{
    for (name, val) in iter {
        if let TypedRegVal::Dword(v) = val {
            if name.eq_ignore_ascii_case("QuickScanAge") {
                snap.quick_scan_age = Some(v);
            } else if name.eq_ignore_ascii_case("FullScanAge") {
                snap.full_scan_age = Some(v);
            } else if name.eq_ignore_ascii_case("ScanParameters") && is_policy {
                snap.gpo_overrides
                    .insert("Scan\\ScanParameters".to_string(), serde_json::json!(v));
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct DefenderJsonBundle {
    #[serde(alias = "MSFT_MpComputerStatus")]
    computer_status: Option<DefenderWmiSnapshot>,
    #[serde(alias = "MSFT_MpPreference")]
    preferences: Option<DefenderWmiSnapshot>,
}

/// Parses a Defender WMI JSON payload (`{computer_status, preferences}`, array, or flat snapshot)
/// into one or more `DefenderWmiSnapshot`s, handling JSON arrays before `DefenderJsonBundle`
/// so `serde` struct `visit_seq` cannot collapse 1- or 2-element arrays.
pub(crate) fn parse_defender_wmi_bundle_json(
    bytes: &[u8],
    source_label: &str,
) -> Result<Vec<DefenderWmiSnapshot>, ForensicError> {
    let trimmed = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    let trimmed_ws = trimmed.trim_ascii_start();

    if trimmed_ws.starts_with(b"[") {
        return serde_json::from_slice::<Vec<DefenderWmiSnapshot>>(trimmed).map_err(|_| {
            ForensicError::parse(
                source_label,
                "invalid Defender JSON array fixture (expected array of Defender snapshots)",
            )
        });
    }

    if let Ok(bundle) = serde_json::from_slice::<DefenderJsonBundle>(trimmed)
        && (bundle.computer_status.is_some() || bundle.preferences.is_some())
    {
        return Ok(vec![merge_two_wmi_snapshots(
            bundle.computer_status,
            bundle.preferences,
        )]);
    }

    if let Ok(single) = serde_json::from_slice::<DefenderWmiSnapshot>(trimmed) {
        return Ok(vec![single]);
    }

    Err(ForensicError::parse(
        source_label,
        "invalid Defender JSON fixture (expected {computer_status, preferences}, flat snapshot, or array)",
    ))
}

/// Parses an offline Defender WMI JSON fixture into `DefenderPostureRecord`s.
pub fn parse_defender_json(
    bytes: &[u8],
    source_label: &str,
) -> Result<(Vec<DefenderPostureRecord>, Vec<DiagnosticWarning>), ForensicError> {
    let snapshots = parse_defender_wmi_bundle_json(bytes, source_label)?;
    let mut warnings = Vec::new();
    let records = snapshots
        .into_iter()
        .map(|snap| {
            correlate_defender_snapshots(
                Some(snap),
                None,
                "OfflineJson",
                "posture.defender_status",
                &mut warnings,
            )
        })
        .collect();
    Ok((records, warnings))
}

fn merge_two_wmi_snapshots(
    status: Option<DefenderWmiSnapshot>,
    prefs: Option<DefenderWmiSnapshot>,
) -> DefenderWmiSnapshot {
    let Some(mut s) = status else {
        return prefs.unwrap_or_default();
    };
    let Some(p) = prefs else {
        return s;
    };
    s.disable_realtime_monitoring = s.disable_realtime_monitoring.or(p.disable_realtime_monitoring);
    s.disable_behavior_monitoring = s.disable_behavior_monitoring.or(p.disable_behavior_monitoring);
    s.disable_ioav_protection = s.disable_ioav_protection.or(p.disable_ioav_protection);
    s.disable_tamper_protection = s.disable_tamper_protection.or(p.disable_tamper_protection);
    s.pua_protection = s.pua_protection.or(p.pua_protection);
    s.maps_reporting = s.maps_reporting.or(p.maps_reporting);
    s.submit_samples_consent = s.submit_samples_consent.or(p.submit_samples_consent);
    s.cloud_block_level = s.cloud_block_level.or(p.cloud_block_level);
    s.hide_exclusions_from_local_users = s
        .hide_exclusions_from_local_users
        .or(p.hide_exclusions_from_local_users);
    if s.exclusion_path.is_empty() {
        s.exclusion_path = p.exclusion_path;
    }
    if s.exclusion_process.is_empty() {
        s.exclusion_process = p.exclusion_process;
    }
    if s.exclusion_extension.is_empty() {
        s.exclusion_extension = p.exclusion_extension;
    }
    if s.exclusion_ip_address.is_empty() {
        s.exclusion_ip_address = p.exclusion_ip_address;
    }
    if s.asr_rule_ids.is_empty() {
        s.asr_rule_ids = p.asr_rule_ids;
    }
    if s.asr_rule_actions.is_empty() {
        s.asr_rule_actions = p.asr_rule_actions;
    }
    s
}
