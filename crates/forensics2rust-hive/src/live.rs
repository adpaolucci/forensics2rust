use chrono::{DateTime, Utc};
use forensics2rust_core::DiagnosticWarning;
use serde::{Deserialize, Serialize};

use crate::regf::RegValueData;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegistryHiveRoot {
    Hklm,
    Hkcu,
    Hku,
    Hkcr,
    Hkcc,
}

impl RegistryHiveRoot {
    pub fn as_short_str(self) -> &'static str {
        match self {
            Self::Hklm => "HKLM",
            Self::Hkcu => "HKCU",
            Self::Hku => "HKU",
            Self::Hkcr => "HKCR",
            Self::Hkcc => "HKCC",
        }
    }

    pub fn as_full_str(self) -> &'static str {
        match self {
            Self::Hklm => "HKEY_LOCAL_MACHINE",
            Self::Hkcu => "HKEY_CURRENT_USER",
            Self::Hku => "HKEY_USERS",
            Self::Hkcr => "HKEY_CLASSES_ROOT",
            Self::Hkcc => "HKEY_CURRENT_CONFIG",
        }
    }
}

/// Parses a live registry root prefix (`HKLM\...`, `HKEY_LOCAL_MACHINE\...`, `\REGISTRY\MACHINE\...`).
pub fn parse_root_and_subpath(input: &str) -> Option<(RegistryHiveRoot, String)> {
    let trimmed = input.trim().trim_matches(|c| c == '\\' || c == '/');
    if trimmed.is_empty() {
        return None;
    }

    let upper = trimmed.to_ascii_uppercase();
    let (root, rest) = if upper == "REGISTRY\\MACHINE" || upper.starts_with("REGISTRY\\MACHINE\\") {
        let idx = "REGISTRY\\MACHINE".len();
        (RegistryHiveRoot::Hklm, trimmed[idx..].trim_start_matches('\\'))
    } else if upper == "REGISTRY\\USER" || upper.starts_with("REGISTRY\\USER\\") {
        let idx = "REGISTRY\\USER".len();
        (RegistryHiveRoot::Hku, trimmed[idx..].trim_start_matches('\\'))
    } else {
        let (first, tail) = match trimmed.split_once(['\\', '/']) {
            Some((a, b)) => (a, b.trim_matches(|c| c == '\\' || c == '/')),
            None => (trimmed, ""),
        };
        let root = match first.to_ascii_uppercase().as_str() {
            "HKLM" | "HKEY_LOCAL_MACHINE" => RegistryHiveRoot::Hklm,
            "HKCU" | "HKEY_CURRENT_USER" => RegistryHiveRoot::Hkcu,
            "HKU" | "HKEY_USERS" => RegistryHiveRoot::Hku,
            "HKCR" | "HKEY_CLASSES_ROOT" => RegistryHiveRoot::Hkcr,
            "HKCC" | "HKEY_CURRENT_CONFIG" => RegistryHiveRoot::Hkcc,
            _ => return None,
        };
        (root, tail)
    };

    Some((root, rest.replace('/', "\\")))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveRegistryValue {
    pub name: String,
    pub raw_type: u32,
    pub data: RegValueData,
    pub raw_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveRegistryEntry {
    pub hive_root: String,
    pub key_path: String,
    pub last_write_time: Option<DateTime<Utc>>,
    pub subkey_count: u32,
    pub values: Vec<LiveRegistryValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveScanOptions {
    pub roots: Vec<String>,
    pub max_depth: Option<usize>,
    pub wow64_64: bool,
    pub max_keys: Option<usize>,
}

impl Default for LiveScanOptions {
    fn default() -> Self {
        Self {
            roots: vec!["HKCU\\Software".to_owned(), "HKLM\\SOFTWARE".to_owned()],
            max_depth: Some(6),
            wow64_64: true,
            max_keys: Some(10_000),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveScanResult {
    pub entries: Vec<LiveRegistryEntry>,
    pub warnings: Vec<DiagnosticWarning>,
}

#[cfg(windows)]
mod imp {
    use forensics2rust_core::{DiagnosticWarning, ForensicError, WarningSeverity, filetime_to_utc};
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_PRIVILEGE_NOT_HELD,
        ERROR_SUCCESS, FILETIME, WIN32_ERROR,
    };
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ,
        KEY_WOW64_64KEY, REG_SAM_FLAGS, RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryInfoKeyW,
    };
    use windows::core::{PCWSTR, PWSTR};

    use super::{
        LiveRegistryEntry, LiveRegistryValue, LiveScanOptions, LiveScanResult, RegistryHiveRoot, parse_root_and_subpath,
    };
    use crate::regf::RegValueData;

    const MAX_VALUE_DATA_BYTES: usize = 16 * 1024 * 1024;
    const MAX_NAME_CHARS: usize = 32_768;

    struct SafeRegKey {
        handle: HKEY,
        owned: bool,
    }

    impl SafeRegKey {
        fn predefined(root: RegistryHiveRoot) -> Self {
            let handle = match root {
                RegistryHiveRoot::Hklm => HKEY_LOCAL_MACHINE,
                RegistryHiveRoot::Hkcu => HKEY_CURRENT_USER,
                RegistryHiveRoot::Hku => HKEY_USERS,
                RegistryHiveRoot::Hkcr => HKEY_CLASSES_ROOT,
                RegistryHiveRoot::Hkcc => HKEY_CURRENT_CONFIG,
            };
            Self { handle, owned: false }
        }

        fn open(parent: HKEY, subkey: &str, sam: REG_SAM_FLAGS) -> Result<Self, WIN32_ERROR> {
            let mut wide: Vec<u16> = subkey.encode_utf16().collect();
            wide.push(0);
            let mut out = HKEY::default();
            let err = unsafe { RegOpenKeyExW(parent, PCWSTR(wide.as_ptr()), None, sam, &mut out) };
            if err == ERROR_SUCCESS {
                Ok(Self {
                    handle: out,
                    owned: true,
                })
            } else {
                Err(err)
            }
        }
    }

    impl Drop for SafeRegKey {
        fn drop(&mut self) {
            if self.owned && !self.handle.is_invalid() {
                unsafe {
                    let _ = RegCloseKey(self.handle);
                }
            }
        }
    }

    fn filetime_struct_to_utc(ft: FILETIME) -> Option<chrono::DateTime<Utc>> {
        let raw = (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime);
        filetime_to_utc(raw)
    }

    use chrono::Utc;

    fn map_root_open_error(path: &str, err: WIN32_ERROR) -> ForensicError {
        if err == ERROR_ACCESS_DENIED || err == ERROR_PRIVILEGE_NOT_HELD {
            ForensicError::permission_denied(path, format!("registry access denied (Win32 error {})", err.0))
        } else if err == ERROR_FILE_NOT_FOUND {
            ForensicError::NotFound(format!("registry key not found: {path}"))
        } else {
            ForensicError::io_classified(path, std::io::Error::from_raw_os_error(err.0 as i32))
        }
    }

    struct KeyInfoAndValues {
        subkey_count: u32,
        max_subkey_buf: usize,
        last_write_time: Option<chrono::DateTime<Utc>>,
        values: Vec<LiveRegistryValue>,
    }

    fn read_key_info_and_values(key: &SafeRegKey) -> Result<KeyInfoAndValues, WIN32_ERROR> {
        let mut subkey_count: u32 = 0;
        let mut max_subkey_len: u32 = 0;
        let mut value_count: u32 = 0;
        let mut max_val_name_len: u32 = 0;
        let mut max_val_data_len: u32 = 0;
        let mut last_write = FILETIME::default();

        let err = unsafe {
            RegQueryInfoKeyW(
                key.handle,
                None,
                None,
                None,
                Some(&mut subkey_count),
                Some(&mut max_subkey_len),
                None,
                Some(&mut value_count),
                Some(&mut max_val_name_len),
                Some(&mut max_val_data_len),
                None,
                Some(&mut last_write),
            )
        };
        if err != ERROR_SUCCESS {
            return Err(err);
        }

        let last_write_time = filetime_struct_to_utc(last_write);
        let mut name_buf = vec![0u16; ((max_val_name_len as usize) + 2).clamp(256, MAX_NAME_CHARS)];
        let mut data_buf = vec![0u8; (max_val_data_len as usize).clamp(256, MAX_VALUE_DATA_BYTES)];
        let mut values = Vec::with_capacity(value_count as usize);

        let mut idx: u32 = 0;
        loop {
            let mut name_len = name_buf.len() as u32;
            let mut val_type: u32 = 0;
            let mut data_len = data_buf.len() as u32;

            let v_err = unsafe {
                RegEnumValueW(
                    key.handle,
                    idx,
                    Some(PWSTR(name_buf.as_mut_ptr())),
                    &mut name_len,
                    None,
                    Some(&mut val_type),
                    Some(data_buf.as_mut_ptr()),
                    Some(&mut data_len),
                )
            };

            if v_err == ERROR_NO_MORE_ITEMS {
                break;
            }
            if v_err == ERROR_MORE_DATA {
                let mut grew = false;
                if ((name_len as usize) + 1 >= name_buf.len() || (data_len as usize) <= data_buf.len())
                    && name_buf.len() < MAX_NAME_CHARS
                {
                    let next = (name_buf.len() * 2).min(MAX_NAME_CHARS);
                    name_buf.resize(next, 0);
                    grew = true;
                }
                if (data_len as usize) > data_buf.len() && (data_len as usize) <= MAX_VALUE_DATA_BYTES {
                    data_buf.resize(data_len as usize, 0);
                    grew = true;
                }
                if grew {
                    continue;
                }
                idx += 1;
                continue;
            }
            if v_err != ERROR_SUCCESS {
                break;
            }

            let val_name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            let actual_len = (data_len as usize).min(data_buf.len());
            let raw_bytes = data_buf[..actual_len].to_vec();
            let data = RegValueData::from_raw(val_type, &raw_bytes);
            values.push(LiveRegistryValue {
                name: val_name,
                raw_type: val_type,
                data,
                raw_bytes,
            });
            idx += 1;
        }

        Ok(KeyInfoAndValues {
            subkey_count,
            max_subkey_buf: ((max_subkey_len as usize) + 2).clamp(256, MAX_NAME_CHARS),
            last_write_time,
            values,
        })
    }

    fn enum_subkey_names(key: &SafeRegKey, initial_cap: usize) -> Vec<String> {
        let mut names = Vec::new();
        let mut name_buf = vec![0u16; initial_cap.max(256)];
        let mut idx: u32 = 0;

        loop {
            let mut name_len = name_buf.len() as u32;
            let err = unsafe {
                RegEnumKeyExW(
                    key.handle,
                    idx,
                    Some(PWSTR(name_buf.as_mut_ptr())),
                    &mut name_len,
                    None,
                    None,
                    None,
                    None,
                )
            };
            if err == ERROR_NO_MORE_ITEMS {
                break;
            }
            if err == ERROR_MORE_DATA {
                if name_buf.len() < MAX_NAME_CHARS {
                    let next = (name_buf.len() * 2).min(MAX_NAME_CHARS);
                    name_buf.resize(next, 0);
                    continue;
                }
                idx += 1;
                continue;
            }
            if err != ERROR_SUCCESS {
                break;
            }
            names.push(String::from_utf16_lossy(&name_buf[..name_len as usize]));
            idx += 1;
        }

        names
    }

    pub fn scan_live_registry(options: &LiveScanOptions, tool_id: &str) -> Result<LiveScanResult, ForensicError> {
        let sam = if options.wow64_64 {
            KEY_READ | KEY_WOW64_64KEY
        } else {
            KEY_READ
        };
        let mut entries = Vec::new();
        let mut warnings = Vec::new();

        for root_spec in &options.roots {
            let Some((hive_root, sub_path)) = parse_root_and_subpath(root_spec) else {
                return Err(ForensicError::InvalidArgument(format!(
                    "unrecognized Windows Registry root path: '{root_spec}'"
                )));
            };

            let predefined = SafeRegKey::predefined(hive_root);
            let start_key = if sub_path.is_empty() {
                SafeRegKey::predefined(hive_root)
            } else {
                SafeRegKey::open(predefined.handle, &sub_path, sam)
                    .map_err(|err| map_root_open_error(root_spec, err))?
            };

            let mut stack: Vec<(SafeRegKey, String, usize)> = vec![(start_key, sub_path, 0)];

            while let Some((cur_key, cur_path, depth)) = stack.pop() {
                if let Some(limit) = options.max_keys
                    && entries.len() >= limit
                {
                    warnings.push(DiagnosticWarning {
                        severity: WarningSeverity::Info,
                        tool_id: tool_id.to_owned(),
                        source: format!("{}\\{cur_path}", hive_root.as_short_str()),
                        message: format!("stopped live scan after reaching max_keys={limit}"),
                    });
                    return Ok(LiveScanResult { entries, warnings });
                }

                let KeyInfoAndValues {
                    subkey_count,
                    max_subkey_buf,
                    last_write_time,
                    values,
                } = match read_key_info_and_values(&cur_key) {
                    Ok(res) => res,
                    Err(err) => {
                        let full = if cur_path.is_empty() {
                            hive_root.as_short_str().to_owned()
                        } else {
                            format!("{}\\{cur_path}", hive_root.as_short_str())
                        };
                        if err == ERROR_ACCESS_DENIED || err == ERROR_PRIVILEGE_NOT_HELD {
                            warnings.push(DiagnosticWarning {
                                severity: WarningSeverity::Warn,
                                tool_id: tool_id.to_owned(),
                                source: full,
                                message: "access denied querying registry key; skipped".to_owned(),
                            });
                            continue;
                        }
                        warnings.push(DiagnosticWarning {
                            severity: WarningSeverity::Warn,
                            tool_id: tool_id.to_owned(),
                            source: full,
                            message: format!("registry query failed (Win32 error {})", err.0),
                        });
                        continue;
                    }
                };

                entries.push(LiveRegistryEntry {
                    hive_root: hive_root.as_short_str().to_owned(),
                    key_path: cur_path.clone(),
                    last_write_time,
                    subkey_count,
                    values,
                });

                let descend = options.max_depth.is_none_or(|max| depth < max);
                if descend && subkey_count > 0 {
                    let child_names = enum_subkey_names(&cur_key, max_subkey_buf);
                    for child_name in child_names.into_iter().rev() {
                        let child_path = if cur_path.is_empty() {
                            child_name.clone()
                        } else {
                            format!("{cur_path}\\{child_name}")
                        };
                        match SafeRegKey::open(cur_key.handle, &child_name, sam) {
                            Ok(child_key) => stack.push((child_key, child_path, depth + 1)),
                            Err(err) if err == ERROR_ACCESS_DENIED || err == ERROR_PRIVILEGE_NOT_HELD => {
                                warnings.push(DiagnosticWarning {
                                    severity: WarningSeverity::Warn,
                                    tool_id: tool_id.to_owned(),
                                    source: format!("{}\\{child_path}", hive_root.as_short_str()),
                                    message: "access denied on child registry key; skipped".to_owned(),
                                });
                            }
                            Err(err) => {
                                warnings.push(DiagnosticWarning {
                                    severity: WarningSeverity::Warn,
                                    tool_id: tool_id.to_owned(),
                                    source: format!("{}\\{child_path}", hive_root.as_short_str()),
                                    message: format!("failed opening child key (Win32 error {})", err.0),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(LiveScanResult { entries, warnings })
    }
}

#[cfg(not(windows))]
mod imp {
    use forensics2rust_core::ForensicError;

    use super::{LiveScanOptions, LiveScanResult};

    pub fn scan_live_registry(_options: &LiveScanOptions, _tool_id: &str) -> Result<LiveScanResult, ForensicError> {
        Err(ForensicError::unsupported_platform(
            "live_registry",
            "live Windows Registry enumeration requires Windows",
        ))
    }
}

pub use imp::scan_live_registry;
