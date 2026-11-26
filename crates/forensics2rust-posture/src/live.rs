//! Windows-only read-only COM/WMI/Registry adapters for `forensics2rust-posture`:
//! - WUA COM (`IUpdateSession` / `IUpdateSearcher::QueryHistory`)
//! - WMI `root\Microsoft\Windows\Defender` (`MSFT_MpComputerStatus`, `MSFT_MpPreference`)
//! - Live Defender Registry (`HKLM\SOFTWARE\Microsoft\Windows Defender` & `Policies`)
//! - WMI `root\SecurityCenter2` + `IWSCProductList` (`WSCProductList`)

use std::ffi::c_void;
use std::mem::ManuallyDrop;
use std::path::PathBuf;

use forensics2rust_core::{DiagnosticWarning, ForensicError, WarningSeverity, ole_automation_date_to_utc};
use forensics2rust_hive::live::{LiveScanOptions, scan_live_registry};
use windows::Win32::Foundation::{E_ACCESSDENIED, RPC_E_CHANGED_MODE, RPC_E_TOO_LATE, S_FALSE, S_OK};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoInitializeSecurity,
    CoSetProxyBlanket, CoUninitialize, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL, RPC_C_AUTHN_LEVEL_DEFAULT,
    RPC_C_IMP_LEVEL_IMPERSONATE, SAFEARRAY,
};
use windows::Win32::System::Ole::{
    SafeArrayAccessData, SafeArrayGetDim, SafeArrayGetElemsize, SafeArrayGetLBound, SafeArrayGetUBound,
    SafeArrayUnaccessData,
};
use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
use windows::Win32::System::SecurityCenter::{
    IWSCProductList, WSC_SECURITY_PRODUCT_STATE_EXPIRED, WSC_SECURITY_PRODUCT_STATE_OFF, WSC_SECURITY_PRODUCT_STATE_ON,
    WSC_SECURITY_PRODUCT_STATE_SNOOZED, WSC_SECURITY_PRODUCT_UP_TO_DATE, WSC_SECURITY_PROVIDER,
    WSC_SECURITY_PROVIDER_ANTISPYWARE, WSC_SECURITY_PROVIDER_ANTIVIRUS, WSC_SECURITY_PROVIDER_FIREWALL, WSCProductList,
};
use windows::Win32::System::UpdateAgent::{IUpdateSession, UpdateSession};
use windows::Win32::System::Variant::{
    VARIANT, VT_ARRAY, VT_BOOL, VT_BSTR, VT_EMPTY, VT_I1, VT_I2, VT_I4, VT_I8, VT_INT, VT_NULL, VT_TYPEMASK, VT_UI1,
    VT_UI2, VT_UI4, VT_UI8, VT_UINT, VariantClear,
};
use windows::Win32::System::Wmi::{
    IWbemClassObject, IWbemLocator, IWbemServices, WBEM_E_ACCESS_DENIED, WBEM_E_INITIALIZATION_FAILURE,
    WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_INFINITE, WBEM_S_FALSE, WbemLocator,
};
use windows::core::{BSTR, PCWSTR};

use crate::datastore_ese::{UpdateHistoryRecord, map_operation_result_code, map_update_operation};
use crate::defender::{DefenderRegistrySnapshot, DefenderWmiSnapshot, parse_defender_from_live_registry};
use crate::discovery::{extract_build_version, extract_kb_articles, normalize_guid_str, parse_flexible_timestamp};
use crate::security_center::{
    SecurityCenterRecord, classify_security_center_hresult, decode_product_state, merge_security_center_records,
};

struct ComGuard {
    should_uninit: bool,
}

impl ComGuard {
    fn init_multithreaded() -> Result<Self, ForensicError> {
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if hr == S_OK || hr == S_FALSE {
            Ok(Self { should_uninit: true })
        } else if hr == RPC_E_CHANGED_MODE {
            Ok(Self { should_uninit: false })
        } else {
            Err(ForensicError::parse(
                "COM",
                format!("CoInitializeEx failed with HRESULT 0x{:08X}", hr.0 as u32),
            ))
        }
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.should_uninit {
            unsafe { CoUninitialize() };
        }
    }
}

struct VariantGuard(VARIANT);

impl VariantGuard {
    fn new() -> Self {
        Self(VARIANT::default())
    }
}

impl Drop for VariantGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = VariantClear(&mut self.0);
        }
    }
}

struct SafeArrayAccessGuard(*const SAFEARRAY);

impl Drop for SafeArrayAccessGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = SafeArrayUnaccessData(self.0);
        }
    }
}

fn ensure_com_security() -> Result<(), ForensicError> {
    let sec_hr = unsafe {
        CoInitializeSecurity(
            None,
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
            None,
        )
    };
    if let Err(err) = sec_hr
        && err.code() != RPC_E_TOO_LATE
    {
        return Err(ForensicError::parse(
            "COM",
            format!("CoInitializeSecurity failed with HRESULT 0x{:08X}", err.code().0 as u32),
        ));
    }
    Ok(())
}

fn connect_wmi_namespace(namespace: &str) -> Result<IWbemServices, windows::core::Error> {
    let locator: IWbemLocator = unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)? };
    let services = unsafe {
        locator.ConnectServer(
            &BSTR::from(namespace),
            &BSTR::new(),
            &BSTR::new(),
            &BSTR::new(),
            0,
            &BSTR::new(),
            None,
        )?
    };
    unsafe {
        CoSetProxyBlanket(
            &services,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            None,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )?;
    }
    Ok(services)
}

fn query_wmi_objects(services: &IWbemServices, wql: &str) -> Result<Vec<IWbemClassObject>, windows::core::Error> {
    let enumerator = unsafe {
        services.ExecQuery(
            &BSTR::from("WQL"),
            &BSTR::from(wql),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            None,
        )?
    };
    let mut out = Vec::new();
    loop {
        let mut objs: [Option<IWbemClassObject>; 1] = [None];
        let mut returned: u32 = 0;
        let hr = unsafe { enumerator.Next(WBEM_INFINITE, &mut objs, &mut returned) };
        if hr.is_err() {
            return Err(windows::core::Error::from(hr));
        }
        if returned == 0 || objs[0].is_none() {
            break;
        }
        if let Some(obj) = objs[0].take() {
            out.push(obj);
        }
        if hr.0 == WBEM_S_FALSE.0 {
            break;
        }
    }
    Ok(out)
}

fn wmi_get_variant(obj: &IWbemClassObject, prop: &str) -> Option<VariantGuard> {
    let mut wide: Vec<u16> = prop.encode_utf16().collect();
    wide.push(0);
    let mut var = VariantGuard::new();
    let res = unsafe { obj.Get(PCWSTR(wide.as_ptr()), 0, &mut var.0, None, None) };
    if res.is_err() {
        return None;
    }
    let vt = unsafe { var.0.Anonymous.Anonymous.vt };
    if vt == VT_EMPTY || vt == VT_NULL {
        return None;
    }
    Some(var)
}

fn wmi_get_bool(obj: &IWbemClassObject, prop: &str) -> Option<bool> {
    let var = wmi_get_variant(obj, prop)?;
    unsafe {
        let vt = var.0.Anonymous.Anonymous.vt;
        if vt == VT_BOOL {
            Some(var.0.Anonymous.Anonymous.Anonymous.boolVal.as_bool())
        } else if vt == VT_I4 {
            Some(var.0.Anonymous.Anonymous.Anonymous.lVal != 0)
        } else if vt == VT_UI1 {
            Some(var.0.Anonymous.Anonymous.Anonymous.bVal != 0)
        } else {
            None
        }
    }
}

fn wmi_get_u32(obj: &IWbemClassObject, prop: &str) -> Option<u32> {
    let var = wmi_get_variant(obj, prop)?;
    unsafe {
        let vt = var.0.Anonymous.Anonymous.vt;
        let u = &var.0.Anonymous.Anonymous.Anonymous;
        if vt == VT_UI4 {
            Some(u.ulVal)
        } else if vt == VT_I4 {
            Some(u.lVal as u32)
        } else if vt == VT_UINT {
            Some(u.uintVal)
        } else if vt == VT_INT {
            Some(u.intVal as u32)
        } else if vt == VT_UI1 {
            Some(u32::from(u.bVal))
        } else if vt == VT_I1 {
            u32::try_from(u.cVal).ok()
        } else if vt == VT_UI2 {
            Some(u32::from(u.uiVal))
        } else if vt == VT_I2 {
            u32::try_from(u.iVal).ok()
        } else if vt == VT_UI8 {
            u32::try_from(u.ullVal).ok()
        } else if vt == VT_I8 {
            u32::try_from(u.llVal).ok()
        } else if vt == VT_BSTR {
            let s = (*u.bstrVal).to_string();
            s.trim().parse::<u32>().ok()
        } else {
            None
        }
    }
}

fn wmi_get_string(obj: &IWbemClassObject, prop: &str) -> Option<String> {
    let var = wmi_get_variant(obj, prop)?;
    unsafe {
        let vt = var.0.Anonymous.Anonymous.vt;
        if vt == VT_BSTR {
            let s = (*var.0.Anonymous.Anonymous.Anonymous.bstrVal).to_string();
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        } else if vt == VT_BOOL {
            Some(
                if var.0.Anonymous.Anonymous.Anonymous.boolVal.as_bool() {
                    "true"
                } else {
                    "false"
                }
                .to_string(),
            )
        } else {
            None
        }
    }
}

fn wmi_get_string_array(obj: &IWbemClassObject, prop: &str) -> Vec<String> {
    let Some(var) = wmi_get_variant(obj, prop) else {
        return Vec::new();
    };
    unsafe {
        let vt = var.0.Anonymous.Anonymous.vt;
        if (vt.0 & VT_ARRAY.0) == 0 || (vt.0 & VT_TYPEMASK.0) != VT_BSTR.0 {
            if vt == VT_BSTR {
                let s = (*var.0.Anonymous.Anonymous.Anonymous.bstrVal).to_string();
                if !s.trim().is_empty() {
                    return vec![s];
                }
            }
            return Vec::new();
        }
        let psa = var.0.Anonymous.Anonymous.Anonymous.parray;
        if psa.is_null() || SafeArrayGetDim(psa) != 1 {
            return Vec::new();
        }
        let Ok(lbound) = SafeArrayGetLBound(psa, 1) else {
            return Vec::new();
        };
        let Ok(ubound) = SafeArrayGetUBound(psa, 1) else {
            return Vec::new();
        };
        if ubound < lbound {
            return Vec::new();
        }
        let count_i64 = i64::from(ubound) - i64::from(lbound) + 1;
        let Ok(count) = usize::try_from(count_i64) else {
            return Vec::new();
        };
        if SafeArrayGetElemsize(psa) as usize != std::mem::size_of::<ManuallyDrop<BSTR>>() {
            return Vec::new();
        }
        let mut raw_ptr: *mut c_void = std::ptr::null_mut();
        if SafeArrayAccessData(psa, &mut raw_ptr).is_err() || raw_ptr.is_null() {
            return Vec::new();
        }
        let _guard = SafeArrayAccessGuard(psa);
        let slice = std::slice::from_raw_parts(raw_ptr as *const ManuallyDrop<BSTR>, count);
        slice
            .iter()
            .map(|b| (*b).to_string())
            .filter(|s| !s.trim().is_empty())
            .collect()
    }
}

fn wmi_get_u8_array(obj: &IWbemClassObject, prop: &str) -> Vec<u8> {
    let Some(var) = wmi_get_variant(obj, prop) else {
        return Vec::new();
    };
    unsafe {
        let vt = var.0.Anonymous.Anonymous.vt;
        if (vt.0 & VT_ARRAY.0) == 0 || (vt.0 & VT_TYPEMASK.0) != VT_UI1.0 {
            return Vec::new();
        }
        let psa = var.0.Anonymous.Anonymous.Anonymous.parray;
        if psa.is_null() || SafeArrayGetDim(psa) != 1 {
            return Vec::new();
        }
        let Ok(lbound) = SafeArrayGetLBound(psa, 1) else {
            return Vec::new();
        };
        let Ok(ubound) = SafeArrayGetUBound(psa, 1) else {
            return Vec::new();
        };
        if ubound < lbound {
            return Vec::new();
        }
        let count_i64 = i64::from(ubound) - i64::from(lbound) + 1;
        let Ok(count) = usize::try_from(count_i64) else {
            return Vec::new();
        };
        if SafeArrayGetElemsize(psa) != 1 {
            return Vec::new();
        }
        let mut raw_ptr: *mut c_void = std::ptr::null_mut();
        if SafeArrayAccessData(psa, &mut raw_ptr).is_err() || raw_ptr.is_null() {
            return Vec::new();
        }
        let _guard = SafeArrayAccessGuard(psa);
        std::slice::from_raw_parts(raw_ptr as *const u8, count).to_vec()
    }
}

/// Collects live Windows Update history via read-only WUA COM (`IUpdateSession` -> `IUpdateSearcher::QueryHistory`).
pub fn collect_live_wua_history() -> Result<Vec<UpdateHistoryRecord>, ForensicError> {
    let _com = ComGuard::init_multithreaded()?;
    let session: IUpdateSession = unsafe {
        CoCreateInstance(&UpdateSession, None, CLSCTX_INPROC_SERVER).map_err(|e| {
            let hr = e.code().0;
            if hr == E_ACCESSDENIED.0 {
                ForensicError::permission_denied("WUA COM", format!("UpdateSession denied: {e}"))
            } else {
                ForensicError::parse("WUA COM", format!("CoCreateInstance(UpdateSession) failed: {e}"))
            }
        })
    }?;

    let searcher = unsafe {
        session
            .CreateUpdateSearcher()
            .map_err(|e| ForensicError::parse("WUA COM", format!("CreateUpdateSearcher failed: {e}")))?
    };

    let total = unsafe {
        searcher
            .GetTotalHistoryCount()
            .map_err(|e| ForensicError::parse("WUA COM", format!("GetTotalHistoryCount failed: {e}")))?
    };

    if total <= 0 {
        return Ok(Vec::new());
    }

    let mut records = Vec::with_capacity(total as usize);
    const PAGE_SIZE: i32 = 256;
    let mut start = 0i32;

    while start < total {
        let count = (total - start).min(PAGE_SIZE);
        let collection = unsafe {
            searcher
                .QueryHistory(start, count)
                .map_err(|e| ForensicError::parse("WUA COM", format!("QueryHistory({start}, {count}) failed: {e}")))?
        };
        let actual_count = unsafe {
            collection
                .Count()
                .map_err(|e| ForensicError::parse("WUA COM", format!("Collection.Count failed: {e}")))?
        };

        for idx in 0..actual_count {
            let Ok(entry) = (unsafe { collection.get_Item(idx) }) else {
                continue;
            };
            let title = unsafe { entry.Title() }.map(|b| b.to_string()).unwrap_or_default();
            let description = unsafe { entry.Description() }
                .map(|b| b.to_string())
                .unwrap_or_default();
            let install_date = unsafe { entry.Date() }.ok().and_then(ole_automation_date_to_utc);
            let op_code = unsafe { entry.Operation() }.map(|o| o.0).unwrap_or(1);
            let res_code = unsafe { entry.ResultCode() }.map(|r| r.0).unwrap_or(0);
            let hresult = unsafe { entry.HResult() }.ok();
            let unmapped_result_code = unsafe { entry.UnmappedResultCode() }.ok();
            let client_app_id = unsafe { entry.ClientApplicationID() }
                .ok()
                .map(|b| b.to_string())
                .filter(|s| !s.trim().is_empty());
            let service_id = unsafe { entry.ServiceID() }
                .ok()
                .and_then(|b| normalize_guid_str(&b.to_string()));
            let support_url = unsafe { entry.SupportUrl() }
                .ok()
                .map(|b| b.to_string())
                .filter(|s| !s.trim().is_empty());

            let (update_id, revision_number) = match unsafe { entry.UpdateIdentity() } {
                Ok(ident) => {
                    let uid = unsafe { ident.UpdateID() }
                        .ok()
                        .and_then(|b| normalize_guid_str(&b.to_string()));
                    let rev = unsafe { ident.RevisionNumber() }.ok();
                    (uid, rev)
                }
                Err(_) => (None, None),
            };

            let support_ref = support_url.as_deref().unwrap_or("");
            let kbs = extract_kb_articles(&[&title, &description, support_ref]);
            let kb_article = if kbs.is_empty() { None } else { Some(kbs.join("; ")) };
            let build_version = extract_build_version(&title).or_else(|| extract_build_version(&description));

            records.push(UpdateHistoryRecord {
                title,
                description,
                install_date,
                operation: map_update_operation(op_code),
                result_code: map_operation_result_code(res_code),
                hresult,
                unmapped_result_code,
                kb_article,
                update_id,
                revision_number,
                support_url,
                client_app_id,
                service_id,
                categories: Vec::new(),
                source_db: "WUA COM".to_string(),
                detail_extra: serde_json::json!({
                    "operation_code": op_code,
                    "result_code_num": res_code,
                    "unmapped_result_code": unmapped_result_code,
                    "build_version": build_version,
                }),
            });
        }

        start += count;
    }

    Ok(records)
}

/// Queries live Windows Defender status & preferences via read-only WMI `root\Microsoft\Windows\Defender`.
pub fn collect_live_defender_wmi() -> (Option<DefenderWmiSnapshot>, Vec<DiagnosticWarning>) {
    let mut warnings = Vec::new();
    let Ok(_com) = ComGuard::init_multithreaded() else {
        warnings.push(DiagnosticWarning {
            severity: WarningSeverity::Warn,
            tool_id: "posture.defender_status".to_string(),
            source: "COM".to_string(),
            message: "COM initialization failed for Defender WMI query".to_string(),
        });
        return (None, warnings);
    };
    if let Err(err) = ensure_com_security() {
        warnings.push(DiagnosticWarning {
            severity: WarningSeverity::Info,
            tool_id: "posture.defender_status".to_string(),
            source: "COM".to_string(),
            message: format!("CoInitializeSecurity note: {err}"),
        });
    }

    let services = match connect_wmi_namespace("root\\Microsoft\\Windows\\Defender") {
        Ok(s) => s,
        Err(err) => {
            let hr = err.code().0;
            let sev = if hr == E_ACCESSDENIED.0 || hr == WBEM_E_ACCESS_DENIED.0 {
                WarningSeverity::Warn
            } else {
                WarningSeverity::Info
            };
            warnings.push(DiagnosticWarning {
                severity: sev,
                tool_id: "posture.defender_status".to_string(),
                source: "root\\Microsoft\\Windows\\Defender".to_string(),
                message: format!(
                    "Defender WMI namespace unavailable (HRESULT 0x{:08X}): {err}",
                    hr as u32
                ),
            });
            return (None, warnings);
        }
    };

    let mut snap = DefenderWmiSnapshot::default();
    let mut got_any = false;

    match query_wmi_objects(&services, "SELECT * FROM MSFT_MpComputerStatus") {
        Ok(objs) => {
            if let Some(obj) = objs.first() {
                got_any = true;
                snap.am_service_enabled = wmi_get_bool(obj, "AMServiceEnabled");
                snap.antivirus_enabled = wmi_get_bool(obj, "AntivirusEnabled");
                snap.antispyware_enabled = wmi_get_bool(obj, "AntispywareEnabled");
                snap.real_time_protection_enabled = wmi_get_bool(obj, "RealTimeProtectionEnabled");
                snap.behavior_monitor_enabled = wmi_get_bool(obj, "BehaviorMonitorEnabled");
                snap.ioav_protection_enabled = wmi_get_bool(obj, "IoavProtectionEnabled");
                snap.on_access_protection_enabled = wmi_get_bool(obj, "OnAccessProtectionEnabled");
                snap.nis_enabled = wmi_get_bool(obj, "NISEnabled");
                snap.is_tamper_protected = wmi_get_bool(obj, "IsTamperProtected");
                snap.tamper_protection_source = wmi_get_string(obj, "TamperProtectionSource");
                snap.am_running_mode = wmi_get_string(obj, "AMRunningMode");
                snap.am_product_version = wmi_get_string(obj, "AMProductVersion");
                snap.am_service_version = wmi_get_string(obj, "AMServiceVersion");
                snap.am_engine_version = wmi_get_string(obj, "AMEngineVersion");
                snap.antivirus_signature_version = wmi_get_string(obj, "AntivirusSignatureVersion");
                snap.antivirus_signature_last_updated = wmi_get_string(obj, "AntivirusSignatureLastUpdated");
                snap.antivirus_signature_age = wmi_get_u32(obj, "AntivirusSignatureAge");
                snap.quick_scan_age = wmi_get_u32(obj, "QuickScanAge");
                snap.full_scan_age = wmi_get_u32(obj, "FullScanAge");
                snap.quick_scan_end_time = wmi_get_string(obj, "QuickScanEndTime");
                snap.full_scan_end_time = wmi_get_string(obj, "FullScanEndTime");
                snap.defender_signatures_out_of_date = wmi_get_bool(obj, "DefenderSignaturesOutOfDate");
                snap.reboot_required = wmi_get_bool(obj, "RebootRequired");
                snap.smart_app_control_state = wmi_get_string(obj, "SmartAppControlState");
                snap.product_status = wmi_get_u32(obj, "ProductStatus");
            }
        }
        Err(err) => warnings.push(DiagnosticWarning {
            severity: WarningSeverity::Warn,
            tool_id: "posture.defender_status".to_string(),
            source: "MSFT_MpComputerStatus".to_string(),
            message: format!("MSFT_MpComputerStatus query failed: {err}"),
        }),
    }

    match query_wmi_objects(&services, "SELECT * FROM MSFT_MpPreference") {
        Ok(objs) => {
            if let Some(obj) = objs.first() {
                got_any = true;
                snap.disable_realtime_monitoring = wmi_get_bool(obj, "DisableRealtimeMonitoring");
                snap.disable_behavior_monitoring = wmi_get_bool(obj, "DisableBehaviorMonitoring");
                snap.disable_ioav_protection = wmi_get_bool(obj, "DisableIOAVProtection");
                snap.disable_tamper_protection = wmi_get_bool(obj, "DisableTamperProtection");
                snap.pua_protection = wmi_get_u32(obj, "PUAProtection");
                snap.maps_reporting = wmi_get_u32(obj, "MAPSReporting");
                snap.submit_samples_consent = wmi_get_u32(obj, "SubmitSamplesConsent");
                snap.cloud_block_level = wmi_get_u32(obj, "CloudBlockLevel");
                snap.hide_exclusions_from_local_users = wmi_get_bool(obj, "HideExclusionsFromLocalUsers");
                snap.exclusion_path = wmi_get_string_array(obj, "ExclusionPath");
                snap.exclusion_process = wmi_get_string_array(obj, "ExclusionProcess");
                snap.exclusion_extension = wmi_get_string_array(obj, "ExclusionExtension");
                snap.exclusion_ip_address = wmi_get_string_array(obj, "ExclusionIpAddress");
                snap.asr_rule_ids = wmi_get_string_array(obj, "AttackSurfaceReductionRules_Ids");
                snap.asr_rule_actions = wmi_get_u8_array(obj, "AttackSurfaceReductionRules_Actions");
            }
        }
        Err(err) => warnings.push(DiagnosticWarning {
            severity: WarningSeverity::Warn,
            tool_id: "posture.defender_status".to_string(),
            source: "MSFT_MpPreference".to_string(),
            message: format!("MSFT_MpPreference query failed: {err}"),
        }),
    }

    if got_any {
        (Some(snap), warnings)
    } else {
        (None, warnings)
    }
}

/// Reads live Defender Registry keys (`HKLM\SOFTWARE\Microsoft\Windows Defender` and
/// optional `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`) via `forensics2rust-hive`.
pub fn collect_live_defender_registry() -> (Option<DefenderRegistrySnapshot>, Vec<DiagnosticWarning>) {
    let mut warnings = Vec::new();
    let mut local_entries = Vec::new();
    let mut policy_entries = Vec::new();

    let local_opts = LiveScanOptions {
        roots: vec!["HKLM\\SOFTWARE\\Microsoft\\Windows Defender".to_string()],
        max_depth: Some(3),
        wow64_64: true,
        max_keys: Some(512),
    };
    match scan_live_registry(&local_opts, "posture.defender_status") {
        Ok(res) => {
            local_entries = res.entries;
            warnings.extend(res.warnings);
        }
        Err(ForensicError::NotFound(_)) => {}
        Err(err) => warnings.push(DiagnosticWarning {
            severity: WarningSeverity::Warn,
            tool_id: "posture.defender_status".to_string(),
            source: "HKLM\\SOFTWARE\\Microsoft\\Windows Defender".to_string(),
            message: format!("live registry scan warning: {err}"),
        }),
    }

    let policy_opts = LiveScanOptions {
        roots: vec!["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender".to_string()],
        max_depth: Some(3),
        wow64_64: true,
        max_keys: Some(256),
    };
    match scan_live_registry(&policy_opts, "posture.defender_status") {
        Ok(res) => {
            policy_entries = res.entries;
            warnings.extend(res.warnings);
        }
        // Policies key is legitimately absent when no Defender GPO is configured.
        Err(ForensicError::NotFound(_)) => {}
        Err(err) => warnings.push(DiagnosticWarning {
            severity: WarningSeverity::Warn,
            tool_id: "posture.defender_status".to_string(),
            source: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender".to_string(),
            message: format!("live policy registry scan warning: {err}"),
        }),
    }

    parse_defender_from_live_registry(&local_entries, &policy_entries, warnings)
}

/// Queries live `root\SecurityCenter2` WMI (`AntiVirusProduct`, `FirewallProduct`, `AntiSpywareProduct`)
/// supplemented with `IWSCProductList` (`WSC_SECURITY_PROVIDER_{FIREWALL,ANTIVIRUS,ANTISPYWARE}`).
pub fn collect_live_security_center() -> (Vec<SecurityCenterRecord>, Vec<DiagnosticWarning>) {
    let mut warnings = Vec::new();
    let Ok(_com) = ComGuard::init_multithreaded() else {
        warnings.push(DiagnosticWarning {
            severity: WarningSeverity::Warn,
            tool_id: "posture.security_center".to_string(),
            source: "COM".to_string(),
            message: "COM initialization failed for SecurityCenter2 query".to_string(),
        });
        return (Vec::new(), warnings);
    };
    let _ = ensure_com_security();

    let mut wmi_records = Vec::new();
    match connect_wmi_namespace("root\\SecurityCenter2") {
        Ok(services) => {
            for (class_name, ptype) in [
                ("AntiVirusProduct", "AV"),
                ("FirewallProduct", "FW"),
                ("AntiSpywareProduct", "AS"),
            ] {
                let wql = format!(
                    "SELECT displayName, instanceGuid, pathToSignedProductExe, pathToSignedReportingExe, productState, timestamp FROM {class_name}"
                );
                match query_wmi_objects(&services, &wql) {
                    Ok(objs) => {
                        for obj in &objs {
                            let display_name = wmi_get_string(obj, "displayName")
                                .unwrap_or_else(|| format!("Unknown {ptype} Product"));
                            let instance_guid = wmi_get_string(obj, "instanceGuid")
                                .as_deref()
                                .and_then(normalize_guid_str);
                            let signed_executable = wmi_get_string(obj, "pathToSignedProductExe");
                            let reporting_executable = wmi_get_string(obj, "pathToSignedReportingExe");
                            let raw_state = wmi_get_u32(obj, "productState");
                            let decoded = raw_state.map(decode_product_state);
                            let timestamp = wmi_get_string(obj, "timestamp")
                                .as_deref()
                                .and_then(parse_flexible_timestamp);

                            wmi_records.push(SecurityCenterRecord {
                                display_name,
                                product_type: ptype.to_string(),
                                instance_guid,
                                product_state_hex: decoded.as_ref().map(|d| d.state_hex.clone()),
                                decoded_state: decoded.clone(),
                                enabled: decoded.as_ref().and_then(|d| d.enabled),
                                protection_state: decoded
                                    .as_ref()
                                    .map(|d| d.protection_state.clone())
                                    .unwrap_or_else(|| "Unknown".to_string()),
                                up_to_date: decoded.as_ref().and_then(|d| d.up_to_date),
                                signature_status: decoded
                                    .as_ref()
                                    .map(|d| d.signature_status.clone())
                                    .unwrap_or_else(|| "Unknown".to_string()),
                                provider_flags_hex: decoded.as_ref().map(|d| format!("0x{:02X}", d.provider_flags)),
                                signed_executable,
                                reporting_executable,
                                timestamp,
                                source: "WMI:SecurityCenter2".to_string(),
                                is_default: None,
                            });
                        }
                    }
                    Err(err) => {
                        warnings.push(classify_security_center_hresult(err.code().0, class_name));
                    }
                }
            }
        }
        Err(err) => {
            let hr = err.code().0;
            if hr == WBEM_E_INITIALIZATION_FAILURE.0 {
                warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Warn,
                    tool_id: "posture.security_center".to_string(),
                    source: "root\\SecurityCenter2".to_string(),
                    message: format!("SecurityCenter2 initialization failure (0x{:08X})", hr as u32),
                });
            } else {
                warnings.push(classify_security_center_hresult(hr, "root\\SecurityCenter2"));
            }
        }
    }

    let wsc_records = query_wsc_product_list(&mut warnings);
    let merged = merge_security_center_records(wmi_records, wsc_records);
    (merged, warnings)
}

fn query_wsc_product_list(warnings: &mut Vec<DiagnosticWarning>) -> Vec<SecurityCenterRecord> {
    let mut records = Vec::new();
    for (provider, ptype) in [
        (WSC_SECURITY_PROVIDER_ANTIVIRUS, "AV"),
        (WSC_SECURITY_PROVIDER_FIREWALL, "FW"),
        (WSC_SECURITY_PROVIDER_ANTISPYWARE, "AS"),
    ] {
        let list: IWSCProductList = match unsafe { CoCreateInstance(&WSCProductList, None, CLSCTX_INPROC_SERVER) } {
            Ok(l) => l,
            Err(err) => {
                warnings.push(classify_security_center_hresult(err.code().0, "WSCProductList"));
                break;
            }
        };

        if let Err(err) = unsafe { list.Initialize(WSC_SECURITY_PROVIDER(provider.0)) } {
            warnings.push(classify_security_center_hresult(
                err.code().0,
                &format!("IWSCProductList::Initialize({ptype})"),
            ));
            continue;
        }

        let count = match unsafe { list.Count() } {
            Ok(c) => c,
            Err(_) => continue,
        };

        for idx in 0..count.max(0) as u32 {
            let Ok(prod) = (unsafe { list.get_Item(idx) }) else {
                continue;
            };
            let display_name = unsafe { prod.ProductName() }
                .ok()
                .map(|b| b.to_string())
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| format!("WSC {ptype} Product"));

            let state = unsafe { prod.ProductState() }.ok();
            let (protection_state, enabled) = match state {
                Some(s) if s == WSC_SECURITY_PRODUCT_STATE_ON => ("On".to_string(), Some(true)),
                Some(s) if s == WSC_SECURITY_PRODUCT_STATE_OFF => ("Off".to_string(), Some(false)),
                Some(s) if s == WSC_SECURITY_PRODUCT_STATE_SNOOZED => ("Snoozed".to_string(), Some(false)),
                Some(s) if s == WSC_SECURITY_PRODUCT_STATE_EXPIRED => ("Expired".to_string(), Some(false)),
                Some(other) => (format!("Unknown({})", other.0), None),
                None => ("Unknown".to_string(), None),
            };

            let sig = unsafe { prod.SignatureStatus() }.ok();
            let (signature_status, up_to_date) = match sig {
                Some(s) if s == WSC_SECURITY_PRODUCT_UP_TO_DATE => ("UpToDate".to_string(), Some(true)),
                Some(_) => ("OutOfDate".to_string(), Some(false)),
                None => ("Unknown".to_string(), None),
            };

            let signed_executable = unsafe { prod.RemediationPath() }
                .ok()
                .map(|b| b.to_string())
                .filter(|s| !s.trim().is_empty() && !s.eq_ignore_ascii_case("NULL"));
            let instance_guid = unsafe { prod.ProductGuid() }
                .ok()
                .and_then(|b| normalize_guid_str(&b.to_string()));
            let timestamp = unsafe { prod.ProductStateTimestamp() }
                .ok()
                .and_then(|b| parse_flexible_timestamp(&b.to_string()));
            let is_default = unsafe { prod.ProductIsDefault() }.ok().map(|b| b.as_bool());

            records.push(SecurityCenterRecord {
                display_name,
                product_type: ptype.to_string(),
                instance_guid,
                product_state_hex: None,
                decoded_state: None,
                enabled,
                protection_state,
                up_to_date,
                signature_status,
                provider_flags_hex: None,
                signed_executable,
                reporting_executable: None,
                timestamp,
                source: "WSC:IWSCProductList".to_string(),
                is_default,
            });
        }
    }
    records
}

fn system_root() -> PathBuf {
    std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("WINDIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\Windows"))
}

pub fn live_datastore_edb_path() -> PathBuf {
    system_root()
        .join("SoftwareDistribution")
        .join("DataStore")
        .join("DataStore.edb")
}

pub fn live_uso_store_db_path() -> PathBuf {
    let program_data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"));
    program_data.join("USOPrivate").join("UpdateStore").join("store.db")
}

pub fn live_cbs_log_paths() -> Vec<PathBuf> {
    let cbs_dir = system_root().join("Logs").join("CBS");
    vec![cbs_dir.join("CBS.log"), cbs_dir.join("CBS.persist.log")]
}
