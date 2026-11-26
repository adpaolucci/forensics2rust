//! Windows-only read-only Win32 FFI adapters (`WMI Win32_ShadowCopy`,
//! `SetupDi*` USB inventory, `CM_Register_Notification` bounded PnP watcher,
//! and `QueryDosDeviceW` volume resolution).

use std::collections::{BTreeMap, HashMap};
use std::ffi::c_void;
use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use forensics2rust_core::{ForensicError, filetime_to_utc};
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_DEVNODE_STATUS_FLAGS, CM_Get_DevNode_Status, CM_NOTIFY_ACTION, CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL,
    CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL, CM_NOTIFY_EVENT_DATA, CM_NOTIFY_FILTER,
    CM_NOTIFY_FILTER_FLAG_ALL_INTERFACE_CLASSES, CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE, CM_PROB,
    CM_Register_Notification, CM_Unregister_Notification, CR_SUCCESS, DIGCF_ALLCLASSES, DIGCF_PRESENT, DN_REMOVABLE,
    HCMNOTIFICATION, HDEVINFO, SP_DEVINFO_DATA, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
    SetupDiGetClassDevsW, SetupDiGetDeviceInstanceIdW, SetupDiGetDevicePropertyW,
};
use windows::Win32::Devices::Properties::{
    DEVPKEY_Device_DeviceDesc, DEVPKEY_Device_FirstInstallDate, DEVPKEY_Device_FriendlyName,
    DEVPKEY_Device_LastArrivalDate, DEVPKEY_Device_LastRemovalDate, DEVPKEY_Device_Manufacturer, DEVPROP_TYPE_FILETIME,
    DEVPROP_TYPE_STRING, DEVPROPTYPE,
};
use windows::Win32::Foundation::{
    DEVPROPKEY, E_ACCESSDENIED, FILETIME, HANDLE, RPC_E_CHANGED_MODE, RPC_E_TOO_LATE, S_FALSE, S_OK,
};
use windows::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle, QueryDosDeviceW};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoInitializeSecurity,
    CoSetProxyBlanket, CoUninitialize, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL, RPC_C_AUTHN_LEVEL_DEFAULT,
    RPC_C_IMP_LEVEL_IMPERSONATE,
};
use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
use windows::Win32::System::Variant::{VARIANT, VT_BOOL, VT_BSTR, VariantClear};
use windows::Win32::System::Wmi::{
    IWbemClassObject, IWbemLocator, WBEM_E_ACCESS_DENIED, WBEM_E_INITIALIZATION_FAILURE, WBEM_FLAG_FORWARD_ONLY,
    WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_INFINITE, WBEM_S_FALSE, WbemLocator,
};
use windows::core::{BSTR, PCWSTR};

use crate::parsers::registry_artifacts::UsbDeviceRecord;
use crate::parsers::setupapi_log::{SetupApiUsbEvent, extract_vid_pid_serial};
use crate::vss::{ShadowCopyRecord, parse_cim_datetime};

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

fn wmi_get_string(obj: &IWbemClassObject, prop: &str) -> Option<String> {
    let mut wide: Vec<u16> = prop.encode_utf16().collect();
    wide.push(0);
    let mut var = VariantGuard::new();
    let res = unsafe { obj.Get(PCWSTR(wide.as_ptr()), 0, &mut var.0, None, None) };
    if res.is_err() {
        return None;
    }
    unsafe {
        if var.0.Anonymous.Anonymous.vt == VT_BSTR {
            let bstr = &*var.0.Anonymous.Anonymous.Anonymous.bstrVal;
            let s = bstr.to_string();
            if s.is_empty() { None } else { Some(s) }
        } else if var.0.Anonymous.Anonymous.vt == VT_BOOL {
            let b = var.0.Anonymous.Anonymous.Anonymous.boolVal;
            Some(if b.as_bool() { "true" } else { "false" }.to_string())
        } else {
            None
        }
    }
}

fn map_wmi_hresult(hr: i32, context: &str) -> ForensicError {
    if hr == E_ACCESSDENIED.0 || hr == WBEM_E_ACCESS_DENIED.0 || hr == WBEM_E_INITIALIZATION_FAILURE.0 {
        ForensicError::permission_denied(
            context,
            format!(
                "WMI Win32_ShadowCopy access denied or requires elevation (HRESULT 0x{:08X})",
                hr as u32
            ),
        )
    } else {
        ForensicError::parse(context, format!("WMI query failed with HRESULT 0x{:08X}", hr as u32))
    }
}

/// Enumerates live Volume Shadow Copies via read-only WMI `SELECT ... FROM Win32_ShadowCopy`.
pub fn enumerate_live_shadow_copies() -> Result<Vec<ShadowCopyRecord>, ForensicError> {
    let _com = ComGuard::init_multithreaded()?;
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
        return Err(map_wmi_hresult(err.code().0, "WMI CoInitializeSecurity"));
    }

    let locator: IWbemLocator = unsafe {
        CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| map_wmi_hresult(e.code().0, "WbemLocator"))?
    };

    let services = unsafe {
        locator
            .ConnectServer(
                &BSTR::from("root\\cimv2"),
                &BSTR::new(),
                &BSTR::new(),
                &BSTR::new(),
                0,
                &BSTR::new(),
                None,
            )
            .map_err(|e| map_wmi_hresult(e.code().0, "WMI ConnectServer"))?
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
        )
        .map_err(|e| map_wmi_hresult(e.code().0, "WMI CoSetProxyBlanket"))?;
    }

    let query = BSTR::from(
        "SELECT ID, DeviceObject, VolumeName, InstallDate, OriginatingMachine, ServiceMachine, ProviderID, SetID, ClientAccessible FROM Win32_ShadowCopy",
    );
    let enumerator = unsafe {
        services
            .ExecQuery(
                &BSTR::from("WQL"),
                &query,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )
            .map_err(|e| map_wmi_hresult(e.code().0, "Win32_ShadowCopy ExecQuery"))?
    };

    let mut records = Vec::new();
    loop {
        let mut objs: [Option<IWbemClassObject>; 1] = [None];
        let mut returned: u32 = 0;
        let hr = unsafe { enumerator.Next(WBEM_INFINITE, &mut objs, &mut returned) };
        if hr.is_err() {
            return Err(map_wmi_hresult(hr.0, "Win32_ShadowCopy Next"));
        }
        if returned == 0 || objs[0].is_none() {
            break;
        }
        if let Some(ref obj) = objs[0] {
            let snapshot_id = wmi_get_string(obj, "ID").unwrap_or_default();
            let device_object = wmi_get_string(obj, "DeviceObject").unwrap_or_default();
            let shadow_copy_name = device_object
                .rsplit(['\\', '/'])
                .next()
                .filter(|s| !s.is_empty())
                .unwrap_or(&snapshot_id)
                .to_string();
            let volume_name = wmi_get_string(obj, "VolumeName").unwrap_or_default();
            let created_time = wmi_get_string(obj, "InstallDate").and_then(|s| parse_cim_datetime(&s));
            let originating_machine = wmi_get_string(obj, "OriginatingMachine").unwrap_or_default();
            let service_machine = wmi_get_string(obj, "ServiceMachine").unwrap_or_default();
            let provider_id = wmi_get_string(obj, "ProviderID").unwrap_or_default();
            let set_id = wmi_get_string(obj, "SetID");
            let attributes = wmi_get_string(obj, "ClientAccessible").map(|c| format!("ClientAccessible={c}"));

            records.push(ShadowCopyRecord {
                shadow_copy_name,
                device_object,
                volume_name,
                created_time,
                snapshot_id,
                originating_machine,
                service_machine,
                provider_id,
                set_id,
                attributes,
            });
        }
        if hr.0 == WBEM_S_FALSE.0 {
            break;
        }
    }

    Ok(records)
}

struct DevInfoGuard(HDEVINFO);

impl Drop for DevInfoGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = SetupDiDestroyDeviceInfoList(self.0);
            }
        }
    }
}

fn get_devprop_string(hdev: HDEVINFO, dev: &SP_DEVINFO_DATA, key: &DEVPROPKEY) -> Option<String> {
    let mut prop_type = DEVPROPTYPE::default();
    let mut buf = vec![0u8; 512];
    let mut req_size = 0u32;
    let res =
        unsafe { SetupDiGetDevicePropertyW(hdev, dev, key, &mut prop_type, Some(&mut buf), Some(&mut req_size), 0) };
    if res.is_err() || prop_type != DEVPROP_TYPE_STRING {
        return None;
    }
    let len = (req_size as usize).min(buf.len());
    let units: Vec<u16> = buf[..len]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    let s = String::from_utf16_lossy(&units);
    if s.is_empty() { None } else { Some(s) }
}

fn get_devprop_filetime(hdev: HDEVINFO, dev: &SP_DEVINFO_DATA, key: &DEVPROPKEY) -> Option<DateTime<Utc>> {
    let mut prop_type = DEVPROPTYPE::default();
    let mut buf = [0u8; 8];
    let mut req_size = 0u32;
    let res =
        unsafe { SetupDiGetDevicePropertyW(hdev, dev, key, &mut prop_type, Some(&mut buf), Some(&mut req_size), 0) };
    if res.is_err() || prop_type != DEVPROP_TYPE_FILETIME || req_size < 8 {
        return None;
    }
    let ft = FILETIME {
        dwLowDateTime: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        dwHighDateTime: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
    };
    let val = (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime);
    filetime_to_utc(val)
}

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

/// Enumerates currently present PnP USB devices via `SetupDi*` + `CM_Get_DevNode_Status`.
pub fn enumerate_live_usb_snapshot() -> Result<BTreeMap<String, LiveUsbPropSnapshot>, ForensicError> {
    let hdev = unsafe { SetupDiGetClassDevsW(None, None, None, DIGCF_ALLCLASSES | DIGCF_PRESENT) }
        .map_err(|e| ForensicError::parse("SetupAPI", format!("SetupDiGetClassDevsW failed: {e}")))?;
    let guard = DevInfoGuard(hdev);

    let mut out = BTreeMap::new();
    let mut idx = 0u32;
    loop {
        let mut dev = SP_DEVINFO_DATA {
            cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };
        if unsafe { SetupDiEnumDeviceInfo(guard.0, idx, &mut dev) }.is_err() {
            break;
        }
        idx += 1;

        let mut id_buf = [0u16; 512];
        if unsafe { SetupDiGetDeviceInstanceIdW(guard.0, &dev, Some(&mut id_buf), None) }.is_err() {
            continue;
        }
        let end = id_buf.iter().position(|&c| c == 0).unwrap_or(id_buf.len());
        let inst = String::from_utf16_lossy(&id_buf[..end]);
        let upper = inst.to_ascii_uppercase();
        if !upper.starts_with("USB\\") && !upper.starts_with("USBSTOR\\") && !upper.starts_with("SWD\\WPDBUSENUM\\") {
            continue;
        }
        if upper.contains("ROOT_HUB") {
            continue;
        }

        let mut status = CM_DEVNODE_STATUS_FLAGS::default();
        let mut problem = CM_PROB::default();
        let cr = unsafe { CM_Get_DevNode_Status(&mut status, &mut problem, dev.DevInst, 0) };
        let safe_to_unplug = cr == CR_SUCCESS && (status.0 & DN_REMOVABLE.0) != 0;

        let friendly_name = get_devprop_string(guard.0, &dev, &DEVPKEY_Device_FriendlyName);
        let description = get_devprop_string(guard.0, &dev, &DEVPKEY_Device_DeviceDesc)
            .or_else(|| get_devprop_string(guard.0, &dev, &DEVPKEY_Device_Manufacturer));
        let first_install = get_devprop_filetime(guard.0, &dev, &DEVPKEY_Device_FirstInstallDate);
        let last_arrival = get_devprop_filetime(guard.0, &dev, &DEVPKEY_Device_LastArrivalDate);
        let last_removal = get_devprop_filetime(guard.0, &dev, &DEVPKEY_Device_LastRemovalDate);

        out.insert(
            upper,
            LiveUsbPropSnapshot {
                instance_id: inst,
                connected: true,
                safe_to_unplug,
                friendly_name,
                description,
                first_install,
                last_arrival,
                last_removal,
            },
        );
    }

    Ok(out)
}

/// Converts present `SetupAPI` snapshots into `UsbDeviceRecord` entries for devices not yet
/// matched from Registry (or enriches existing Registry entries).
pub fn merge_live_usb_snapshot(records: &mut Vec<UsbDeviceRecord>, snapshot: &BTreeMap<String, LiveUsbPropSnapshot>) {
    let mut matched = std::collections::HashSet::new();
    for rec in records.iter_mut() {
        let key = rec.instance_id.to_ascii_uppercase();
        if let Some(snap) = snapshot.get(&key) {
            matched.insert(key);
            rec.connected = Some(snap.connected);
            rec.safe_to_unplug = Some(snap.safe_to_unplug);
            if let Some(ref f) = snap.friendly_name
                && (rec.device_name.is_empty() || rec.device_name == rec.description)
            {
                rec.device_name = f.clone();
            }
            if let Some(d) = snap.first_install
                && rec.created_date.is_none()
            {
                rec.created_date = Some(d);
            }
            if let Some(d) = snap.last_arrival {
                rec.last_plug_date = Some(d);
            }
            if let Some(d) = snap.last_removal {
                rec.last_removal_date = Some(d);
            }
        } else {
            rec.connected = Some(false);
            rec.safe_to_unplug = Some(false);
        }
    }

    for (upper_key, snap) in snapshot {
        if matched.contains(upper_key) {
            continue;
        }
        let (vid, pid, serial, dev_type) = extract_vid_pid_serial(&snap.instance_id);
        let desc = snap.description.clone().unwrap_or_else(|| snap.instance_id.clone());
        let name = snap.friendly_name.clone().unwrap_or_else(|| desc.clone());
        records.push(UsbDeviceRecord {
            device_name: name,
            description: desc,
            device_type: dev_type,
            connected: Some(snap.connected),
            safe_to_unplug: Some(snap.safe_to_unplug),
            vendor_id: vid,
            product_id: pid,
            serial_number: serial,
            drive_letter: None,
            created_date: snap.first_install,
            last_plug_date: snap.last_arrival,
            last_removal_date: snap.last_removal,
            registry_key: format!("HKLM\\SYSTEM\\CurrentControlSet\\Enum\\{}", snap.instance_id),
            instance_id: snap.instance_id.clone(),
        });
    }
}

struct PnpNotifyState {
    events: Mutex<Vec<SetupApiUsbEvent>>,
    cvar: Condvar,
}

unsafe extern "system" fn pnp_notify_callback(
    _hnotify: HCMNOTIFICATION,
    context: *const c_void,
    action: CM_NOTIFY_ACTION,
    eventdata: *const CM_NOTIFY_EVENT_DATA,
    eventdatasize: u32,
) -> u32 {
    if context.is_null()
        || eventdata.is_null()
        || (eventdatasize as usize) < std::mem::size_of::<CM_NOTIFY_EVENT_DATA>()
    {
        return 0;
    }
    if unsafe { (*eventdata).FilterType } != CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE {
        return 0;
    }
    let state = unsafe { &*(context as *const PnpNotifyState) };
    let event_type = if action == CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL {
        "Plug"
    } else if action == CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL {
        "Unplug"
    } else {
        return 0;
    };

    let sym_ptr = unsafe { (*eventdata).u.DeviceInterface.SymbolicLink.as_ptr() };
    let sym_offset = (sym_ptr as usize).saturating_sub(eventdata as usize);
    let max_units = (eventdatasize as usize).saturating_sub(sym_offset) / 2;
    let mut len = 0usize;
    while len < max_units {
        if unsafe { *sym_ptr.add(len) } == 0 {
            break;
        }
        len += 1;
    }
    let sym = if len > 0 {
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(sym_ptr, len) })
    } else {
        "USB PnP Interface".to_string()
    };
    let (vid, pid, serial, dev_type) = extract_vid_pid_serial(&sym);

    if let Ok(mut guard) = state.events.lock() {
        guard.push(SetupApiUsbEvent {
            event_time: Some(Utc::now()),
            event_type: event_type.to_string(),
            instance_id: sym.clone(),
            device_name: sym.clone(),
            description: format!("Live PnP {event_type} notification"),
            device_type: dev_type,
            drive_letter: None,
            serial_number: serial,
            vendor_id: vid,
            product_id: pid,
            exit_status: None,
        });
        state.cvar.notify_all();
    }
    0
}

struct CmNotifyGuard(HCMNOTIFICATION);

impl Drop for CmNotifyGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CM_Unregister_Notification(self.0);
            }
        }
    }
}

/// Bounded real-time PnP event listener using `CM_Register_Notification` + `Condvar::wait_timeout`.
/// Unregisters cleanly on drop after `duration` elapses.
pub fn watch_pnp_events(duration: Duration) -> Result<Vec<SetupApiUsbEvent>, ForensicError> {
    let state = Arc::new(PnpNotifyState {
        events: Mutex::new(Vec::new()),
        cvar: Condvar::new(),
    });
    let filter = CM_NOTIFY_FILTER {
        cbSize: size_of::<CM_NOTIFY_FILTER>() as u32,
        Flags: CM_NOTIFY_FILTER_FLAG_ALL_INTERFACE_CLASSES,
        FilterType: CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE,
        ..Default::default()
    };
    let mut handle = HCMNOTIFICATION::default();
    let ctx_ptr = Arc::as_ptr(&state) as *const c_void;
    let cr = unsafe { CM_Register_Notification(&filter, Some(ctx_ptr), Some(pnp_notify_callback), &mut handle) };
    if cr != CR_SUCCESS {
        return Err(ForensicError::parse(
            "PnPNotify",
            format!("CM_Register_Notification failed with CONFIGRET {}", cr.0),
        ));
    }
    let _guard = CmNotifyGuard(handle);

    let deadline = Instant::now() + duration;
    let mut guard = state
        .events
        .lock()
        .map_err(|_| ForensicError::parse("PnPNotify", "mutex poisoned"))?;
    while guard.is_empty() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let (next_guard, timeout) = state
            .cvar
            .wait_timeout(guard, deadline - now)
            .map_err(|_| ForensicError::parse("PnPNotify", "condvar wait failed"))?;
        guard = next_guard;
        if timeout.timed_out() {
            break;
        }
    }
    Ok(guard.clone())
}

/// Resolves `\Device\HarddiskVolumeN` prefixes to `C:` drive letters via `QueryDosDeviceW`.
pub fn query_dos_volume_map() -> HashMap<String, String> {
    let mut map = HashMap::new();
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let mut wide: Vec<u16> = drive.encode_utf16().collect();
        wide.push(0);
        let mut target = [0u16; 512];
        let count = unsafe { QueryDosDeviceW(PCWSTR(wide.as_ptr()), Some(&mut target)) };
        if count > 0 {
            let len = (count as usize).min(target.len());
            let first_nul = target[..len].iter().position(|&c| c == 0).unwrap_or(len);
            let dev_path = String::from_utf16_lossy(&target[..first_nul]);
            if !dev_path.is_empty() {
                map.insert(dev_path.to_ascii_lowercase(), drive);
            }
        }
    }
    map
}

pub fn live_prefetch_dir() -> PathBuf {
    let root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("WINDIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\Windows"));
    root.join("Prefetch")
}

pub fn live_recent_dir() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|p| PathBuf::from(p).join("Microsoft\\Windows\\Recent"))
}

pub fn live_setupapi_log_path() -> PathBuf {
    let root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("WINDIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\Windows"));
    root.join("INF").join("setupapi.dev.log")
}

pub fn live_amcache_path() -> PathBuf {
    let root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("WINDIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\Windows"));
    root.join("AppCompat").join("Programs").join("Amcache.hve")
}

/// Checks whether two open file handles refer to the exact same NTFS volume/file ID
/// (catching hardlinks and case/alias paths before truncating writes).
pub fn files_share_same_id(a: &File, b: &File) -> bool {
    let mut info_a = BY_HANDLE_FILE_INFORMATION::default();
    let mut info_b = BY_HANDLE_FILE_INFORMATION::default();
    let ok_a = unsafe { GetFileInformationByHandle(HANDLE(a.as_raw_handle()), &mut info_a) }.is_ok();
    let ok_b = unsafe { GetFileInformationByHandle(HANDLE(b.as_raw_handle()), &mut info_b) }.is_ok();
    ok_a && ok_b
        && info_a.dwVolumeSerialNumber == info_b.dwVolumeSerialNumber
        && info_a.nFileIndexHigh == info_b.nFileIndexHigh
        && info_a.nFileIndexLow == info_b.nFileIndexLow
}
