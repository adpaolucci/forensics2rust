#![forbid(unsafe_code)]

//! Pure-Rust `setupapi.dev.log` parser supporting UTF-8, UTF-16LE (BOM-aware),
//! and Latin-1 encodings for USB PnP device install/removal forensics (`USBLogView`).

use chrono::{DateTime, NaiveDateTime, Utc};
use forensics2rust_core::read_utf16_le;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupApiUsbEvent {
    pub event_time: Option<DateTime<Utc>>,
    pub event_type: String,
    pub instance_id: String,
    pub device_name: String,
    pub description: String,
    pub device_type: String,
    pub drive_letter: Option<String>,
    pub serial_number: Option<String>,
    pub vendor_id: Option<String>,
    pub product_id: Option<String>,
    pub exit_status: Option<String>,
}

pub fn decode_log_text(raw: &[u8]) -> String {
    if raw.starts_with(&[0xFF, 0xFE]) {
        return read_utf16_le(&raw[2..]);
    }
    if raw.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(&raw[3..]).into_owned();
    }
    // Heuristic UTF-16LE detection without BOM (read_utf16_le ignores a trailing odd byte)
    if raw.len() >= 8 {
        let zero_odd = raw.iter().skip(1).step_by(2).take(32).filter(|&&b| b == 0).count();
        if zero_odd >= 12 {
            return read_utf16_le(raw);
        }
    }
    match std::str::from_utf8(raw) {
        Ok(s) => s.to_string(),
        Err(_) => raw.iter().map(|&b| b as char).collect(),
    }
}

pub fn extract_vid_pid_serial(instance_id: &str) -> (Option<String>, Option<String>, Option<String>, String) {
    let upper = instance_id.to_ascii_uppercase();
    let mut vid = None;
    let mut pid = None;
    let mut serial = None;

    if let Some(idx) = upper.find("VID_")
        && let Some(sub) = upper.get(idx + 4..idx + 8)
        && sub.chars().all(|c| c.is_ascii_hexdigit())
    {
        vid = Some(sub.to_string());
    }
    if let Some(idx) = upper.find("PID_")
        && let Some(sub) = upper.get(idx + 4..idx + 8)
        && sub.chars().all(|c| c.is_ascii_hexdigit())
    {
        pid = Some(sub.to_string());
    }

    let parts: Vec<&str> = instance_id
        .split(['\\', '#'])
        .filter(|p| !p.is_empty() && !(p.starts_with('{') && p.ends_with('}')))
        .collect();
    if parts.len() >= 3 {
        let raw_ser = parts.last().copied().unwrap_or("").trim();
        let cleaned = raw_ser.split('&').next().unwrap_or(raw_ser);
        if !cleaned.is_empty() && !cleaned.eq_ignore_ascii_case("0") {
            serial = Some(cleaned.to_string());
        }
    }

    let device_type = if upper.starts_with("USBSTOR\\") || upper.starts_with("STORAGE\\VOLUME\\_??_USBSTOR#") {
        "Mass Storage".to_string()
    } else if upper.starts_with("SWD\\WPDBUSENUM\\") {
        "WPD/Portable".to_string()
    } else if upper.starts_with("USB\\") || upper.starts_with("\\\\?\\USB#") {
        "USB".to_string()
    } else {
        "PnP".to_string()
    };

    (vid, pid, serial, device_type)
}

fn parse_section_timestamp(line: &str) -> Option<DateTime<Utc>> {
    // e.g. ">>>  Section start 2025/05/10 14:22:11.123"
    let marker = "Section start";
    let idx = line.find(marker)?;
    let ts_str = line[idx + marker.len()..].trim();
    for fmt in ["%Y/%m/%d %H:%M:%S%.f", "%Y/%m/%d %H:%M:%S"] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(ts_str, fmt) {
            return Some(ndt.and_utc());
        }
    }
    None
}

fn is_usb_instance_id(instance_id: &str) -> bool {
    let upper = instance_id.to_ascii_uppercase();
    upper.starts_with("USB\\")
        || upper.starts_with("USBSTOR\\")
        || upper.starts_with("SWD\\WPDBUSENUM\\")
        || upper.starts_with("STORAGE\\VOLUME\\_??_USBSTOR#")
}

/// Parses a `setupapi.dev.log` buffer into USB PnP plug/unplug events.
pub fn parse_setupapi_dev_log(raw: &[u8]) -> Vec<SetupApiUsbEvent> {
    let text = decode_log_text(raw);
    let mut events = Vec::new();

    let mut cur_action: Option<String> = None;
    let mut cur_instance: Option<String> = None;
    let mut cur_time: Option<DateTime<Utc>> = None;
    let mut cur_friendly: Option<String> = None;
    let mut cur_desc: Option<String> = None;
    let mut cur_exit: Option<String> = None;

    let flush_current = |events: &mut Vec<SetupApiUsbEvent>,
                         cur_action: &mut Option<String>,
                         cur_instance: &mut Option<String>,
                         cur_time: &mut Option<DateTime<Utc>>,
                         cur_friendly: &mut Option<String>,
                         cur_desc: &mut Option<String>,
                         cur_exit: &mut Option<String>| {
        if let (Some(action), Some(inst)) = (cur_action.take(), cur_instance.take())
            && is_usb_instance_id(&inst)
        {
            let lower_act = action.to_ascii_lowercase();
            let event_type =
                if lower_act.contains("uninstall") || lower_act.contains("remov") || lower_act.contains("delete") {
                    "Unplug".to_string()
                } else {
                    "Plug".to_string()
                };
            let (vid, pid, serial, dev_type) = extract_vid_pid_serial(&inst);
            let desc = cur_desc.take().unwrap_or_else(|| action.clone());
            let name = cur_friendly
                .take()
                .or_else(|| Some(desc.clone()))
                .unwrap_or_else(|| inst.clone());
            events.push(SetupApiUsbEvent {
                event_time: cur_time.take(),
                event_type,
                instance_id: inst,
                device_name: name,
                description: desc,
                device_type: dev_type,
                drive_letter: None,
                serial_number: serial,
                vendor_id: vid,
                product_id: pid,
                exit_status: cur_exit.take(),
            });
        } else {
            *cur_time = None;
            *cur_friendly = None;
            *cur_desc = None;
            *cur_exit = None;
        }
    };

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.starts_with(">>>  [") && line.ends_with(']') {
            let inner = &line[6..line.len() - 1];
            if let Some((action, inst)) = inner.split_once(" - ") {
                flush_current(
                    &mut events,
                    &mut cur_action,
                    &mut cur_instance,
                    &mut cur_time,
                    &mut cur_friendly,
                    &mut cur_desc,
                    &mut cur_exit,
                );
                cur_action = Some(action.trim().to_string());
                cur_instance = Some(inst.trim().to_string());
            }
        } else if cur_instance.is_some() {
            if line.contains("Section start") {
                if cur_time.is_none() {
                    cur_time = parse_section_timestamp(line);
                }
            } else if let Some(rest) = line.strip_prefix("dvi: Friendly Name:") {
                let v = rest.trim();
                if !v.is_empty() {
                    cur_friendly = Some(v.to_string());
                }
            } else if let Some(rest) = line.strip_prefix("dvi: Device Description:") {
                let v = rest.trim();
                if !v.is_empty() {
                    cur_desc = Some(v.to_string());
                }
            } else if line.starts_with("<<<  [Exit status:") {
                cur_exit = Some(line.trim_start_matches("<<<  [").trim_end_matches(']').to_string());
            } else if line.starts_with("<<<  Section end") {
                flush_current(
                    &mut events,
                    &mut cur_action,
                    &mut cur_instance,
                    &mut cur_time,
                    &mut cur_friendly,
                    &mut cur_desc,
                    &mut cur_exit,
                );
            }
        }
    }

    flush_current(
        &mut events,
        &mut cur_action,
        &mut cur_instance,
        &mut cur_time,
        &mut cur_friendly,
        &mut cur_desc,
        &mut cur_exit,
    );

    events
}
