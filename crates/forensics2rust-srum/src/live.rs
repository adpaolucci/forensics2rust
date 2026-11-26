use std::path::PathBuf;

use forensics2rust_core::ForensicError;

/// Resolves `%SystemRoot%\System32\sru\SRUDB.dat` (falling back to `C:\Windows\System32\sru\SRUDB.dat`).
pub fn default_live_srudb_path() -> PathBuf {
    let sys_root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("WINDIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    sys_root.join("System32").join("sru").join("SRUDB.dat")
}

/// Classifies OS I/O errors encountered when opening `SRUDB.dat` / ESE databases into
/// actionable `ForensicError` variants.
pub fn classify_srum_io_error(path: &str, err: std::io::Error) -> ForensicError {
    if err.kind() == std::io::ErrorKind::NotFound || matches!(err.raw_os_error(), Some(2 | 3)) {
        return ForensicError::NotFound(path.to_string());
    }
    if err.kind() == std::io::ErrorKind::PermissionDenied || matches!(err.raw_os_error(), Some(5 | 1314)) {
        return ForensicError::PermissionDenied {
            context: path.to_string(),
            message: format!("{err} (SRUDB.dat requires Administrator privileges or an offline/VSS copy)"),
        };
    }
    if matches!(err.raw_os_error(), Some(32 | 33)) {
        return ForensicError::Io {
            path: path.to_string(),
            source: std::io::Error::new(
                err.kind(),
                format!(
                    "{err} (SRUDB.dat is actively locked by Diagnostic Policy Service (DPS) / ESENT; supply an offline copy or VSS shadow-copy path)"
                ),
            ),
        };
    }
    ForensicError::Io {
        path: path.to_string(),
        source: err,
    }
}

#[cfg(windows)]
mod win_impl {
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::Path;

    use forensics2rust_core::ForensicError;
    use windows::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, GetLastError, HANDLE, LUID};
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_BACKUP_NAME, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::{classify_srum_io_error, default_live_srudb_path};

    struct TokenHandleGuard(HANDLE);

    impl Drop for TokenHandleGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                // SAFETY: `self.0` is a valid process token handle obtained from `OpenProcessToken`
                // and is closed exactly once on drop.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    pub fn try_enable_backup_privilege() -> bool {
        let mut raw_token = HANDLE::default();
        // SAFETY: `GetCurrentProcess()` returns a pseudo-handle valid for the current process,
        // and `raw_token` is a valid stack out-pointer for `OpenProcessToken`.
        let opened = unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut raw_token,
            )
        };
        if opened.is_err() {
            return false;
        }
        let token = TokenHandleGuard(raw_token);

        let mut luid = LUID::default();
        // SAFETY: `SE_BACKUP_NAME` is a valid null-terminated UTF-16 constant from `windows`,
        // and `luid` is a valid stack out-pointer.
        let looked_up = unsafe { LookupPrivilegeValueW(None, SE_BACKUP_NAME, &mut luid) };
        if looked_up.is_err() {
            return false;
        }

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        // SAFETY: `token.0` is an open token handle with `TOKEN_ADJUST_PRIVILEGES`, and `&tp`
        // points to a properly initialized single-privilege `TOKEN_PRIVILEGES` struct.
        let adjusted = unsafe { AdjustTokenPrivileges(token.0, false, Some(&tp), 0, None, None) };
        if adjusted.is_err() {
            return false;
        }
        // SAFETY: `GetLastError` reads the calling thread's last Win32 error code immediately
        // after `AdjustTokenPrivileges` to distinguish `ERROR_NOT_ALL_ASSIGNED` from `ERROR_SUCCESS`.
        unsafe { GetLastError() == ERROR_SUCCESS }
    }

    pub fn read_ese_path(path: &Path) -> Result<Vec<u8>, ForensicError> {
        let has_backup = try_enable_backup_privilege();
        let share = (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0;
        let flags = if has_backup { FILE_FLAG_BACKUP_SEMANTICS.0 } else { 0 };

        let mut file = OpenOptions::new()
            .read(true)
            .access_mode(FILE_GENERIC_READ.0)
            .share_mode(share)
            .custom_flags(flags)
            .open(path)
            .map_err(|err| classify_srum_io_error(&path.display().to_string(), err))?;

        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .map_err(|err| classify_srum_io_error(&path.display().to_string(), err))?;
        Ok(buf)
    }

    pub fn read_live_srudb_bytes() -> Result<Vec<u8>, ForensicError> {
        read_ese_path(&default_live_srudb_path())
    }
}

#[cfg(not(windows))]
mod non_win_impl {
    use std::path::Path;

    use forensics2rust_core::ForensicError;

    use super::classify_srum_io_error;

    pub fn read_ese_path(path: &Path) -> Result<Vec<u8>, ForensicError> {
        std::fs::read(path).map_err(|err| classify_srum_io_error(&path.display().to_string(), err))
    }

    pub fn read_live_srudb_bytes() -> Result<Vec<u8>, ForensicError> {
        Err(ForensicError::unsupported_platform(
            "srum",
            "live SRUDB.dat inspection requires Windows; supply OfflinePath or OfflineBytes",
        ))
    }
}

#[cfg(windows)]
pub use win_impl::{read_ese_path, read_live_srudb_bytes, try_enable_backup_privilege};

#[cfg(not(windows))]
pub use non_win_impl::{read_ese_path, read_live_srudb_bytes};
