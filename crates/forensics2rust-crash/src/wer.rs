use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use forensics2rust_core::{ForensicError, filetime_to_utc, read_utf16_le};
use serde::{Deserialize, Serialize};

/// Detected character encoding of a `Report.wer` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WerEncoding {
    Utf16LeBom,
    Utf16LeNoBom,
    Utf16BeBom,
    Utf16BeNoBom,
    Utf8Bom,
    Utf8,
}

/// Decodes raw `Report.wer` bytes into UTF-8 text and identifies the encoding.
pub fn decode_wer_text(bytes: &[u8]) -> (String, WerEncoding) {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return (strip_leading_bom(&read_utf16_le(&bytes[2..])), WerEncoding::Utf16LeBom);
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return (strip_leading_bom(&read_utf16_be(&bytes[2..])), WerEncoding::Utf16BeBom);
    }
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        let s = String::from_utf8_lossy(&bytes[3..]).into_owned();
        return (strip_leading_bom(&s), WerEncoding::Utf8Bom);
    }

    let sample_len = bytes.len().min(2048);
    let pairs = sample_len / 2;
    if pairs >= 2 {
        let mut le_ascii_pairs = 0usize;
        let mut be_ascii_pairs = 0usize;
        for i in 0..pairs {
            let b0 = bytes[2 * i];
            let b1 = bytes[2 * i + 1];
            if b0 != 0 && b1 == 0 && (b0.is_ascii_graphic() || matches!(b0, b' ' | b'\t' | b'\r' | b'\n')) {
                le_ascii_pairs += 1;
            } else if b0 == 0 && b1 != 0 && (b1.is_ascii_graphic() || matches!(b1, b' ' | b'\t' | b'\r' | b'\n')) {
                be_ascii_pairs += 1;
            }
        }
        if le_ascii_pairs * 2 >= pairs {
            return (strip_leading_bom(&read_utf16_le(bytes)), WerEncoding::Utf16LeNoBom);
        }
        if be_ascii_pairs * 2 >= pairs {
            return (strip_leading_bom(&read_utf16_be(bytes)), WerEncoding::Utf16BeNoBom);
        }
    }

    let s = String::from_utf8_lossy(bytes).into_owned();
    (strip_leading_bom(&s), WerEncoding::Utf8)
}

fn read_utf16_be(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .collect();
    String::from_utf16_lossy(&units)
}

fn strip_leading_bom(s: &str) -> String {
    s.strip_prefix('\u{FEFF}').unwrap_or(s).to_string()
}

/// Parses a Windows FILETIME string encoded either as decimal ticks or hexadecimal (`0x...` or 16 hex chars).
pub fn parse_wer_filetime(raw: &str) -> Option<DateTime<Utc>> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(hex_body) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(hex_body, 16).ok().and_then(filetime_to_utc);
    }
    if (1..=20).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit()) {
        return s.parse::<u64>().ok().and_then(filetime_to_utc);
    }
    if s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return u64::from_str_radix(s, 16).ok().and_then(filetime_to_utc);
    }
    None
}

/// Indexed `Sig[N]` or `DynamicSig[N]` parameter pair.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WerSigParam {
    pub name: Option<String>,
    pub value: String,
}

/// Indexed `OsInfo[N]` key-value entry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WerOsInfoEntry {
    pub key: Option<String>,
    pub value: String,
}

/// Parsed Windows Error Reporting (`Report.wer`) document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WerReport {
    pub wer_file_path: String,
    pub encoding: WerEncoding,
    pub event_time: Option<DateTime<Utc>>,
    pub event_type: Option<String>,
    pub friendly_event_name: Option<String>,
    pub app_name: Option<String>,
    pub app_version: Option<String>,
    pub app_path: Option<String>,
    pub ns_app_name: Option<String>,
    pub report_id: Option<String>,
    pub report_type: Option<u64>,
    pub report_status: Option<u64>,
    pub consent: Option<u64>,
    pub fault_module: Option<String>,
    pub fault_module_version: Option<String>,
    pub exception_code: Option<String>,
    pub exception_name: Option<String>,
    pub exception_offset: Option<String>,
    pub os_version: Option<String>,
    pub sigs: BTreeMap<u32, WerSigParam>,
    pub dynamic_sigs: BTreeMap<u32, WerSigParam>,
    pub os_info: BTreeMap<u32, WerOsInfoEntry>,
    pub loaded_modules: BTreeMap<u32, String>,
    pub ui: BTreeMap<u32, String>,
    pub state: BTreeMap<String, String>,
    pub response: BTreeMap<String, String>,
    pub fields: BTreeMap<String, String>,
    #[serde(skip)]
    pub raw_prefix: Vec<u8>,
}

fn parse_indexed_key<'a>(key: &'a str, prefix: &str) -> Option<(u32, &'a str)> {
    let rest = key.strip_prefix(prefix)?;
    let rest = rest.strip_prefix('[')?;
    let (idx_str, after) = rest.split_once(']')?;
    let idx: u32 = idx_str.parse().ok()?;
    let suffix = after.strip_prefix('.').unwrap_or(after);
    Some((idx, suffix))
}

fn get_ci<'a>(fields: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .filter(|v| !v.is_empty())
}

fn normalize_hex_if_hex(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(body) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X"))
        && !body.is_empty()
        && body.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return format!("0x{}", body.to_ascii_lowercase());
    }
    if (8..=16).contains(&trimmed.len()) && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return format!("0x{}", trimmed.to_ascii_lowercase());
    }
    trimmed.to_string()
}

fn parse_hex_u32(raw: &str) -> Option<u32> {
    let s = raw.trim();
    let hex_body = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if hex_body.is_empty() || hex_body.len() > 8 || !hex_body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(hex_body, 16).ok()
}

fn find_sig_by_names<'a>(sigs: &'a BTreeMap<u32, WerSigParam>, candidates: &[&str]) -> Option<&'a str> {
    for param in sigs.values() {
        if let Some(name) = &param.name {
            let norm = name.trim();
            if candidates.iter().any(|c| norm.eq_ignore_ascii_case(c)) && !param.value.is_empty() {
                return Some(param.value.as_str());
            }
        }
    }
    None
}

impl WerReport {
    /// Parses a `Report.wer` payload from raw bytes.
    pub fn from_bytes(bytes: &[u8], wer_file_path: impl Into<String>) -> Result<Self, ForensicError> {
        let source_path = wer_file_path.into();
        if bytes.is_empty() {
            return Err(ForensicError::parse(
                format!("Report.wer ({source_path})"),
                "empty Report.wer buffer",
            ));
        }

        let (text, encoding) = decode_wer_text(bytes);
        let mut fields: BTreeMap<String, String> = BTreeMap::new();
        let mut sigs: BTreeMap<u32, WerSigParam> = BTreeMap::new();
        let mut dynamic_sigs: BTreeMap<u32, WerSigParam> = BTreeMap::new();
        let mut os_info: BTreeMap<u32, WerOsInfoEntry> = BTreeMap::new();
        let mut loaded_modules: BTreeMap<u32, String> = BTreeMap::new();
        let mut ui: BTreeMap<u32, String> = BTreeMap::new();
        let mut state: BTreeMap<String, String> = BTreeMap::new();
        let mut response: BTreeMap<String, String> = BTreeMap::new();
        let mut current_section: Option<String> = None;

        for raw_line in text.lines() {
            let line = raw_line.trim_matches(&['\r', '\0'][..]).trim();
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') && !line.contains('=') {
                current_section = Some(line[1..line.len() - 1].trim().to_string());
                continue;
            }
            let Some((raw_key, raw_val)) = line.split_once('=') else {
                continue;
            };
            let key = raw_key.trim();
            if key.is_empty() {
                continue;
            }
            let val = raw_val.trim_matches(&['\r', '\0'][..]).trim().to_string();
            let store_key = if let Some(sec) = &current_section
                && !key.contains('.')
                && !key.contains('[')
            {
                let _ = sec;
                key.to_string()
            } else {
                key.to_string()
            };

            fields.insert(store_key.clone(), val.clone());

            if let Some((idx, suffix)) = parse_indexed_key(key, "Sig") {
                let entry = sigs.entry(idx).or_default();
                if suffix.eq_ignore_ascii_case("Name") {
                    entry.name = Some(val);
                } else if suffix.eq_ignore_ascii_case("Value") {
                    entry.value = val;
                }
            } else if let Some((idx, suffix)) = parse_indexed_key(key, "DynamicSig") {
                let entry = dynamic_sigs.entry(idx).or_default();
                if suffix.eq_ignore_ascii_case("Name") {
                    entry.name = Some(val);
                } else if suffix.eq_ignore_ascii_case("Value") {
                    entry.value = val;
                }
            } else if let Some((idx, suffix)) = parse_indexed_key(key, "OsInfo") {
                let entry = os_info.entry(idx).or_default();
                if suffix.eq_ignore_ascii_case("Key") {
                    entry.key = Some(val);
                } else if suffix.eq_ignore_ascii_case("Value") {
                    entry.value = val;
                }
            } else if let Some((idx, suffix)) = parse_indexed_key(key, "LoadedModule") {
                if suffix.is_empty() {
                    loaded_modules.insert(idx, val);
                }
            } else if let Some((idx, suffix)) = parse_indexed_key(key, "UI") {
                if suffix.is_empty() {
                    ui.insert(idx, val);
                }
            } else if let Some(rest) = key.strip_prefix("Response.") {
                response.insert(rest.to_string(), val);
            } else if key.starts_with("State[") || key.starts_with("State.") {
                state.insert(key.to_string(), val);
            }
        }

        if fields.is_empty() {
            return Err(ForensicError::parse(
                format!("Report.wer ({source_path})"),
                "no valid Key=Value entries found in Report.wer",
            ));
        }

        let event_time = get_ci(&fields, "EventTime")
            .and_then(parse_wer_filetime)
            .or_else(|| get_ci(&fields, "UploadTime").and_then(parse_wer_filetime))
            .or_else(|| get_ci(&fields, "ReportCreationTime").and_then(parse_wer_filetime));

        let event_type = get_ci(&fields, "EventType")
            .or_else(|| get_ci(&fields, "OriginalEventType"))
            .map(str::to_string);
        let friendly_event_name = get_ci(&fields, "FriendlyEventName").map(str::to_string);
        let ns_app_name = get_ci(&fields, "NsAppName").map(str::to_string);

        let is_mo_app = event_type
            .as_deref()
            .is_some_and(|e| e.eq_ignore_ascii_case("MoAppCrash") || e.eq_ignore_ascii_case("MoBEX"));
        let is_clr20r3 = event_type.as_deref().is_some_and(|e| e.eq_ignore_ascii_case("CLR20r3"));
        let is_apphang_b1 = event_type
            .as_deref()
            .is_some_and(|e| e.eq_ignore_ascii_case("AppHangB1"));
        let is_appcrash_like = event_type.as_deref().is_none_or(|e| {
            e.eq_ignore_ascii_case("APPCRASH") || e.eq_ignore_ascii_case("BEX") || e.eq_ignore_ascii_case("BEX64")
        });

        let sig_val =
            |idx: u32| -> Option<&str> { sigs.get(&idx).filter(|p| !p.value.is_empty()).map(|p| p.value.as_str()) };

        let app_name = get_ci(&fields, "AppName")
            .map(str::to_string)
            .or_else(|| find_sig_by_names(&sigs, &["Application Name", "AppName"]).map(str::to_string))
            .or_else(|| {
                if is_mo_app {
                    sig_val(1).map(str::to_string)
                } else if is_appcrash_like || is_clr20r3 || is_apphang_b1 {
                    sig_val(0).map(str::to_string)
                } else {
                    None
                }
            })
            .or_else(|| ns_app_name.clone());

        let app_version = find_sig_by_names(&sigs, &["Application Version", "AppVersion"])
            .map(str::to_string)
            .or_else(|| {
                if is_mo_app {
                    sig_val(2).map(str::to_string)
                } else if is_appcrash_like || is_clr20r3 || is_apphang_b1 {
                    sig_val(1).map(str::to_string)
                } else {
                    None
                }
            });

        let app_path = get_ci(&fields, "AppPath")
            .or_else(|| get_ci(&fields, "TargetAppPath"))
            .map(str::to_string)
            .or_else(|| ui.get(&2).filter(|s| s.contains('\\') || s.contains('/')).cloned())
            .or_else(|| loaded_modules.get(&0).filter(|s| !s.is_empty()).cloned())
            .or_else(|| app_name.clone());

        let report_id = get_ci(&fields, "ReportIdentifier")
            .or_else(|| get_ci(&fields, "ReportId"))
            .map(str::to_string);

        let report_type = get_ci(&fields, "ReportType").and_then(|v| v.parse::<u64>().ok());
        let report_status = get_ci(&fields, "ReportStatus").and_then(|v| v.parse::<u64>().ok());
        let consent = get_ci(&fields, "Consent").and_then(|v| v.parse::<u64>().ok());

        let fault_module = find_sig_by_names(
            &sigs,
            &["Fault Module Name", "FaultModuleName", "Fault Module", "Module Name"],
        )
        .map(str::to_string)
        .or_else(|| {
            if is_mo_app {
                sig_val(4).map(str::to_string)
            } else if is_appcrash_like || is_clr20r3 {
                sig_val(3).map(str::to_string)
            } else {
                None
            }
        });

        let fault_module_version =
            find_sig_by_names(&sigs, &["Fault Module Version", "FaultModuleVersion", "Module Version"])
                .map(str::to_string)
                .or_else(|| {
                    if is_mo_app {
                        sig_val(5).map(str::to_string)
                    } else if is_appcrash_like {
                        sig_val(4).map(str::to_string)
                    } else {
                        None
                    }
                });

        let raw_exc_code = find_sig_by_names(
            &sigs,
            &[
                "Exception Code",
                "ExceptionCode",
                "BugcheckCode",
                "Code",
                "Status Code",
                "Exception Type",
            ],
        )
        .map(str::to_string)
        .or_else(|| {
            if is_mo_app {
                sig_val(7).map(str::to_string)
            } else if is_appcrash_like {
                sig_val(6).map(str::to_string)
            } else if is_clr20r3 {
                sig_val(8).map(str::to_string)
            } else {
                None
            }
        });

        let exception_code = raw_exc_code.as_deref().map(normalize_hex_if_hex);
        let exception_name = raw_exc_code
            .as_deref()
            .and_then(parse_hex_u32)
            .map(|c| crate::bugcheck::format_exception_description(c, &[]));

        let exception_offset = find_sig_by_names(
            &sigs,
            &["Exception Offset", "ExceptionOffset", "Offset", "Fault Offset"],
        )
        .map(normalize_hex_if_hex)
        .or_else(|| {
            if is_mo_app {
                sig_val(8).map(normalize_hex_if_hex)
            } else if is_appcrash_like {
                sig_val(7).map(normalize_hex_if_hex)
            } else {
                None
            }
        });

        let os_version = get_ci(&fields, "OSVersion")
            .or_else(|| get_ci(&fields, "OS Version"))
            .map(str::to_string)
            .or_else(|| find_sig_by_names(&dynamic_sigs, &["OS Version", "OSVersion"]).map(str::to_string))
            .or_else(|| {
                let mut build = None;
                let mut edition = None;
                for entry in os_info.values() {
                    if let Some(k) = &entry.key {
                        if k.eq_ignore_ascii_case("BuildString") || k.eq_ignore_ascii_case("Build") {
                            build = Some(entry.value.clone());
                        } else if k.eq_ignore_ascii_case("ProductName") || k.eq_ignore_ascii_case("Edition") {
                            edition = Some(entry.value.clone());
                        }
                    }
                }
                match (edition, build) {
                    (Some(ed), Some(b)) => Some(format!("{ed} ({b})")),
                    (None, Some(b)) => Some(b),
                    (Some(ed), None) => Some(ed),
                    (None, None) => None,
                }
            });

        let raw_cap = bytes.len().min(65_536);

        Ok(Self {
            wer_file_path: source_path,
            encoding,
            event_time,
            event_type,
            friendly_event_name,
            app_name,
            app_version,
            app_path,
            ns_app_name,
            report_id,
            report_type,
            report_status,
            consent,
            fault_module,
            fault_module_version,
            exception_code,
            exception_name,
            exception_offset,
            os_version,
            sigs,
            dynamic_sigs,
            os_info,
            loaded_modules,
            ui,
            state,
            response,
            fields,
            raw_prefix: bytes[..raw_cap].to_vec(),
        })
    }
}
