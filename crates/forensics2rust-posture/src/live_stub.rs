#![forbid(unsafe_code)]

//! Non-Windows platform stubs for live OS posture collection helpers.

use std::path::PathBuf;

use forensics2rust_core::{DiagnosticWarning, ForensicError};

use crate::datastore_ese::UpdateHistoryRecord;
use crate::defender::{DefenderRegistrySnapshot, DefenderWmiSnapshot};
use crate::security_center::SecurityCenterRecord;

pub fn collect_live_wua_history() -> Result<Vec<UpdateHistoryRecord>, ForensicError> {
    Err(ForensicError::unsupported_platform(
        "posture.updates",
        "live Windows Update Agent COM queries require Windows",
    ))
}

pub fn collect_live_defender_wmi() -> (Option<DefenderWmiSnapshot>, Vec<DiagnosticWarning>) {
    (
        None,
        vec![DiagnosticWarning {
            severity: forensics2rust_core::WarningSeverity::Warn,
            tool_id: "posture.defender_status".to_string(),
            source: "WMI".to_string(),
            message: "live Windows Defender WMI queries require Windows".to_string(),
        }],
    )
}

pub fn collect_live_defender_registry() -> (Option<DefenderRegistrySnapshot>, Vec<DiagnosticWarning>) {
    (
        None,
        vec![DiagnosticWarning {
            severity: forensics2rust_core::WarningSeverity::Warn,
            tool_id: "posture.defender_status".to_string(),
            source: "Registry".to_string(),
            message: "live Windows Registry inspection requires Windows".to_string(),
        }],
    )
}

pub fn collect_live_security_center() -> (Vec<SecurityCenterRecord>, Vec<DiagnosticWarning>) {
    (
        Vec::new(),
        vec![DiagnosticWarning {
            severity: forensics2rust_core::WarningSeverity::Warn,
            tool_id: "posture.security_center".to_string(),
            source: "SecurityCenter2".to_string(),
            message: "live SecurityCenter2 / WSC queries require Windows".to_string(),
        }],
    )
}

pub fn live_datastore_edb_path() -> PathBuf {
    PathBuf::new()
}

pub fn live_uso_store_db_path() -> PathBuf {
    PathBuf::new()
}

pub fn live_cbs_log_paths() -> Vec<PathBuf> {
    Vec::new()
}
