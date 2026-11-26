#![forbid(unsafe_code)]

//! Windows Security Center (`root\SecurityCenter2` + `IWSCProductList`) posture model,
//! exact `productState` 24-bit/32-bit bitmask decoder, WMI+WSC merge/dedup logic, and
//! offline WMI JSON fixture parser for `posture.security_center`.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use forensics2rust_core::{DiagnosticWarning, ForensicError, WarningSeverity};
use serde::{Deserialize, Serialize};

use crate::discovery::{normalize_guid_str, parse_flexible_timestamp};

/// Decoded `root\SecurityCenter2` `productState` bitmask fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedProductState {
    pub raw: u32,
    pub state_hex: String,
    pub provider_flags: u8,
    pub scanner_nibble: u8,
    pub sub_flags_hi: u8,
    pub signature_nibble: u8,
    pub sub_flags_lo: u8,
    pub protection_state: String,
    pub enabled: Option<bool>,
    pub signature_status: String,
    pub up_to_date: Option<bool>,
}

/// Decodes a `root\SecurityCenter2` `productState` DWORD bitmask into structured status fields.
///
/// Layout (hex nibbles `0xPP_S_H_U_L`):
/// - `(raw >> 16) & 0xFF` -> `provider_flags`
/// - `(raw >> 12) & 0xF`  -> `scanner_nibble` (`0`=Off, `1`=On, `2`=Snoozed, `3`=Expired)
/// - `(raw >> 8)  & 0xF`  -> `sub_flags_hi`
/// - `(raw >> 4)  & 0xF`  -> `signature_nibble` (`0`=UpToDate, `1`=OutOfDate)
/// - `raw & 0xF`          -> `sub_flags_lo`
pub fn decode_product_state(raw: u32) -> DecodedProductState {
    let provider_flags = ((raw >> 16) & 0xFF) as u8;
    let scanner_nibble = ((raw >> 12) & 0xF) as u8;
    let sub_flags_hi = ((raw >> 8) & 0xF) as u8;
    let signature_nibble = ((raw >> 4) & 0xF) as u8;
    let sub_flags_lo = (raw & 0xF) as u8;

    let (protection_state, enabled) = match scanner_nibble {
        0 => ("Off".to_string(), Some(false)),
        1 => ("On".to_string(), Some(true)),
        2 => ("Snoozed".to_string(), Some(false)),
        3 => ("Expired".to_string(), Some(false)),
        other => (format!("Unknown(0x{other:X})"), None),
    };

    let (signature_status, up_to_date) = match signature_nibble {
        0 => ("UpToDate".to_string(), Some(true)),
        1 => ("OutOfDate".to_string(), Some(false)),
        other => (format!("Unknown(0x{other:X})"), None),
    };

    DecodedProductState {
        raw,
        state_hex: format!("0x{raw:06X}"),
        provider_flags,
        scanner_nibble,
        sub_flags_hi,
        signature_nibble,
        sub_flags_lo,
        protection_state,
        enabled,
        signature_status,
        up_to_date,
    }
}

/// Normalized security product record for `posture.security_center`.
#[derive(Debug, Clone)]
pub struct SecurityCenterRecord {
    pub display_name: String,
    pub product_type: String,
    pub instance_guid: Option<String>,
    pub product_state_hex: Option<String>,
    pub decoded_state: Option<DecodedProductState>,
    pub enabled: Option<bool>,
    pub protection_state: String,
    pub up_to_date: Option<bool>,
    pub signature_status: String,
    pub provider_flags_hex: Option<String>,
    pub signed_executable: Option<String>,
    pub reporting_executable: Option<String>,
    pub timestamp: Option<DateTime<Utc>>,
    pub source: String,
    pub is_default: Option<bool>,
}

/// Classifies SecurityCenter2 / WMI / COM HRESULTs into structured non-fatal `DiagnosticWarning`s
/// (for Windows Server `WBEM_E_INVALID_NAMESPACE`, missing WSC COM class, or non-admin access denied).
pub fn classify_security_center_hresult(hr: i32, context: &str) -> DiagnosticWarning {
    let code = hr as u32;
    match code {
        0x8004_100E => DiagnosticWarning {
            severity: WarningSeverity::Info,
            tool_id: "posture.security_center".to_string(),
            source: context.to_string(),
            message: format!(
                "root\\SecurityCenter2 WMI namespace is not present on this Windows edition (e.g. Windows Server) [WBEM_E_INVALID_NAMESPACE 0x{code:08X}]"
            ),
        },
        0x8004_1010 | 0x8004_1002 | 0x8004_1013 => DiagnosticWarning {
            severity: WarningSeverity::Info,
            tool_id: "posture.security_center".to_string(),
            source: context.to_string(),
            message: format!("SecurityCenter2 WMI class/provider unavailable (0x{code:08X})"),
        },
        0x8004_0154 => DiagnosticWarning {
            severity: WarningSeverity::Info,
            tool_id: "posture.security_center".to_string(),
            source: context.to_string(),
            message: format!(
                "WSCProductList COM class not registered on this Windows edition [REGDB_E_CLASSNOTREG 0x{code:08X}]"
            ),
        },
        0x8007_0005 | 0x8004_1003 => DiagnosticWarning {
            severity: WarningSeverity::Warn,
            tool_id: "posture.security_center".to_string(),
            source: context.to_string(),
            message: format!("access denied querying Security Center (0x{code:08X})"),
        },
        _ => DiagnosticWarning {
            severity: WarningSeverity::Warn,
            tool_id: "posture.security_center".to_string(),
            source: context.to_string(),
            message: format!("Security Center query failed with HRESULT 0x{code:08X}"),
        },
    }
}

/// Merges `root\SecurityCenter2` WMI records with `IWSCProductList` fallback records,
/// deduplicating by `(product_type, normalized_guid)` or `(product_type, display_name)`.
pub fn merge_security_center_records(
    wmi_records: Vec<SecurityCenterRecord>,
    wsc_records: Vec<SecurityCenterRecord>,
) -> Vec<SecurityCenterRecord> {
    let mut out = Vec::with_capacity(wmi_records.len() + wsc_records.len());
    let mut seen_guids: HashSet<(String, String)> = HashSet::new();
    let mut seen_names: HashSet<(String, String)> = HashSet::new();

    for rec in wmi_records {
        if let Some(ref g) = rec.instance_guid {
            seen_guids.insert((rec.product_type.clone(), g.to_ascii_lowercase()));
        }
        seen_names.insert((rec.product_type.clone(), rec.display_name.trim().to_ascii_lowercase()));
        out.push(rec);
    }

    for rec in wsc_records {
        let dup_by_guid = rec
            .instance_guid
            .as_ref()
            .is_some_and(|g| seen_guids.contains(&(rec.product_type.clone(), g.to_ascii_lowercase())));
        let dup_by_name =
            seen_names.contains(&(rec.product_type.clone(), rec.display_name.trim().to_ascii_lowercase()));
        if dup_by_guid || dup_by_name {
            continue;
        }
        if let Some(ref g) = rec.instance_guid {
            seen_guids.insert((rec.product_type.clone(), g.to_ascii_lowercase()));
        }
        seen_names.insert((rec.product_type.clone(), rec.display_name.trim().to_ascii_lowercase()));
        out.push(rec);
    }

    out
}

#[derive(Debug, Deserialize)]
struct ScJsonItem {
    #[serde(alias = "displayName", alias = "DisplayName", alias = "productName")]
    display_name: Option<String>,
    #[serde(alias = "productType", alias = "ProductType")]
    product_type: Option<String>,
    #[serde(alias = "instanceGuid", alias = "InstanceGuid", alias = "productGuid")]
    instance_guid: Option<String>,
    #[serde(
        alias = "pathToSignedProductExe",
        alias = "SignedExecutable",
        alias = "remediationPath"
    )]
    path_to_signed_product_exe: Option<String>,
    #[serde(alias = "pathToSignedReportingExe", alias = "ReportingExecutable")]
    path_to_signed_reporting_exe: Option<String>,
    #[serde(alias = "productState", alias = "ProductState", alias = "productStateHex")]
    product_state: Option<serde_json::Value>,
    #[serde(alias = "timestamp", alias = "Timestamp")]
    timestamp: Option<String>,
    #[serde(alias = "isDefault")]
    is_default: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ScJsonCategorized {
    #[serde(alias = "AntiVirusProduct", default)]
    anti_virus_product: Vec<ScJsonItem>,
    #[serde(alias = "FirewallProduct", default)]
    firewall_product: Vec<ScJsonItem>,
    #[serde(alias = "AntiSpywareProduct", default)]
    anti_spyware_product: Vec<ScJsonItem>,
    #[serde(default)]
    products: Vec<ScJsonItem>,
}

/// Parses an offline SecurityCenter2 JSON fixture (`{AntiVirusProduct, FirewallProduct, AntiSpywareProduct}`,
/// `{products: [...]}`, single product object, `{}` empty object, or `[...]`).
pub fn parse_security_center_json(
    bytes: &[u8],
    source_label: &str,
) -> Result<(Vec<SecurityCenterRecord>, Vec<DiagnosticWarning>), ForensicError> {
    let trimmed = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    let value: serde_json::Value = serde_json::from_slice(trimmed)
        .map_err(|_| ForensicError::parse(source_label, "invalid SecurityCenter2 JSON fixture"))?;

    match value {
        serde_json::Value::Array(_) => {
            let items: Vec<ScJsonItem> = serde_json::from_value(value)
                .map_err(|_| ForensicError::parse(source_label, "invalid SecurityCenter2 JSON array fixture"))?;
            let recs = items.into_iter().map(|it| json_item_to_record(it, None)).collect();
            Ok((recs, Vec::new()))
        }
        serde_json::Value::Object(ref map) => {
            if map.is_empty() {
                return Ok((Vec::new(), Vec::new()));
            }

            let has_categorized_key = [
                "AntiVirusProduct",
                "anti_virus_product",
                "FirewallProduct",
                "firewall_product",
                "AntiSpywareProduct",
                "anti_spyware_product",
                "products",
            ]
            .iter()
            .any(|k| map.contains_key(*k));

            if has_categorized_key {
                let cat: ScJsonCategorized = serde_json::from_value(value).map_err(|_| {
                    ForensicError::parse(source_label, "invalid SecurityCenter2 categorized JSON fixture")
                })?;
                let mut recs = Vec::new();
                for it in cat.anti_virus_product {
                    recs.push(json_item_to_record(it, Some("AV")));
                }
                for it in cat.firewall_product {
                    recs.push(json_item_to_record(it, Some("FW")));
                }
                for it in cat.anti_spyware_product {
                    recs.push(json_item_to_record(it, Some("AS")));
                }
                for it in cat.products {
                    recs.push(json_item_to_record(it, None));
                }
                return Ok((recs, Vec::new()));
            }

            let has_single_product_key = [
                "displayName",
                "DisplayName",
                "productName",
                "display_name",
                "productType",
                "ProductType",
                "product_type",
                "instanceGuid",
                "InstanceGuid",
                "productGuid",
                "instance_guid",
                "pathToSignedProductExe",
                "SignedExecutable",
                "remediationPath",
                "path_to_signed_product_exe",
                "pathToSignedReportingExe",
                "ReportingExecutable",
                "path_to_signed_reporting_exe",
                "productState",
                "ProductState",
                "productStateHex",
                "product_state",
            ]
            .iter()
            .any(|k| map.contains_key(*k));

            if has_single_product_key {
                let item: ScJsonItem = serde_json::from_value(value)
                    .map_err(|_| ForensicError::parse(source_label, "invalid SecurityCenter2 product JSON object"))?;
                return Ok((vec![json_item_to_record(item, None)], Vec::new()));
            }

            Err(ForensicError::parse(
                source_label,
                "invalid SecurityCenter2 JSON fixture: unrecognized object schema",
            ))
        }
        _ => Err(ForensicError::parse(
            source_label,
            "invalid SecurityCenter2 JSON fixture (expected JSON array or object)",
        )),
    }
}

fn json_item_to_record(item: ScJsonItem, default_type: Option<&str>) -> SecurityCenterRecord {
    let display_name = item
        .display_name
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "Unknown Security Product".to_string());
    let product_type = item
        .product_type
        .as_deref()
        .map(normalize_product_type)
        .or_else(|| default_type.map(ToOwned::to_owned))
        .unwrap_or_else(|| "AV".to_string());

    let instance_guid = item.instance_guid.as_deref().and_then(normalize_guid_str);

    let raw_state = item.product_state.as_ref().and_then(|v| match v {
        serde_json::Value::Number(n) => n.as_u64().and_then(|u| u32::try_from(u).ok()),
        serde_json::Value::String(s) => {
            let clean = s.trim();
            if let Some(hex) = clean.strip_prefix("0x").or_else(|| clean.strip_prefix("0X")) {
                u32::from_str_radix(hex, 16).ok()
            } else {
                clean.parse::<u32>().ok()
            }
        }
        _ => None,
    });

    let decoded = raw_state.map(decode_product_state);
    let product_state_hex = decoded.as_ref().map(|d| d.state_hex.clone());
    let enabled = decoded.as_ref().and_then(|d| d.enabled);
    let protection_state = decoded
        .as_ref()
        .map(|d| d.protection_state.clone())
        .unwrap_or_else(|| "Unknown".to_string());
    let up_to_date = decoded.as_ref().and_then(|d| d.up_to_date);
    let signature_status = decoded
        .as_ref()
        .map(|d| d.signature_status.clone())
        .unwrap_or_else(|| "Unknown".to_string());
    let provider_flags_hex = decoded.as_ref().map(|d| format!("0x{:02X}", d.provider_flags));

    let timestamp = item.timestamp.as_deref().and_then(parse_flexible_timestamp);

    SecurityCenterRecord {
        display_name,
        product_type,
        instance_guid,
        product_state_hex,
        decoded_state: decoded,
        enabled,
        protection_state,
        up_to_date,
        signature_status,
        provider_flags_hex,
        signed_executable: item.path_to_signed_product_exe,
        reporting_executable: item.path_to_signed_reporting_exe,
        timestamp,
        source: "OfflineJson".to_string(),
        is_default: item.is_default,
    }
}

fn normalize_product_type(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "av" | "antivirus" | "antivirusproduct" => "AV".to_string(),
        "fw" | "firewall" | "firewallproduct" => "FW".to_string(),
        "as" | "antispyware" | "antispywareproduct" => "AS".to_string(),
        other => other.to_ascii_uppercase(),
    }
}
