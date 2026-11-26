#![forbid(unsafe_code)]

//! Non-Windows platform stubs for live-only OS collection helpers.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Utc};
use forensics2rust_core::ForensicError;

use crate::parsers::registry_artifacts::UsbDeviceRecord;
use crate::parsers::setupapi_log::SetupApiUsbEvent;
use crate::vss::ShadowCopyRecord;

#[derive(Debug, Clone)]
pub struct LiveUsbPropSnapshot {
    pub instance_id: String,
    pub connected: bool,
    pub safe_to_unplug: bool,
    pub friendly_name: Option<String>,
    pub description: Option<String>,
    pub first_install: Option<DateTime<Utc>>,
    pub last_arrival: Option<DateTime<Utc>>,
    pub last_removal: Option<DateTime<Utc>>,
}

pub fn enumerate_live_shadow_copies() -> Result<Vec<ShadowCopyRecord>, ForensicError> {
    Err(ForensicError::unsupported_platform(
        "artifacts.vss",
        "live WMI Win32_ShadowCopy enumeration requires Windows",
    ))
}

pub fn enumerate_live_usb_snapshot() -> Result<BTreeMap<String, LiveUsbPropSnapshot>, ForensicError> {
    Err(ForensicError::unsupported_platform(
        "artifacts.usb_devices",
        "live SetupAPI USB enumeration requires Windows",
    ))
}

pub fn merge_live_usb_snapshot(_records: &mut Vec<UsbDeviceRecord>, _snapshot: &BTreeMap<String, LiveUsbPropSnapshot>) {
}

pub fn watch_pnp_events(_duration: Duration) -> Result<Vec<SetupApiUsbEvent>, ForensicError> {
    Err(ForensicError::unsupported_platform(
        "artifacts.usb_log",
        "live CM_Register_Notification PnP monitoring requires Windows",
    ))
}

pub fn query_dos_volume_map() -> HashMap<String, String> {
    HashMap::new()
}

pub fn live_prefetch_dir() -> PathBuf {
    PathBuf::new()
}

pub fn live_recent_dir() -> Option<PathBuf> {
    None
}

pub fn live_setupapi_log_path() -> PathBuf {
    PathBuf::new()
}

pub fn live_amcache_path() -> PathBuf {
    PathBuf::new()
}

pub fn files_share_same_id(a: &std::fs::File, b: &std::fs::File) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(ma), Ok(mb)) = (a.metadata(), b.metadata()) {
            return ma.dev() == mb.dev() && ma.ino() == mb.ino();
        }
    }
    #[cfg(not(unix))]
    let _ = (a, b);
    false
}
