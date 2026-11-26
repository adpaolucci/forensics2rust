use serde::{Deserialize, Serialize};

/// Metadata describing a known Windows kernel BugCheck (BSOD) code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BugCheckInfo {
    pub code: u32,
    pub name: &'static str,
    pub summary: &'static str,
}

const BUGCHECK_TABLE: &[BugCheckInfo] = &[
    BugCheckInfo {
        code: 0x0000_0001,
        name: "APC_INDEX_MISMATCH",
        summary: "Mismatch in kernel APC disable count upon thread exit from system call",
    },
    BugCheckInfo {
        code: 0x0000_000A,
        name: "IRQL_NOT_LESS_OR_EQUAL",
        summary: "Kernel-mode memory access to pageable memory at too high an IRQL",
    },
    BugCheckInfo {
        code: 0x0000_0019,
        name: "BAD_POOL_HEADER",
        summary: "Kernel pool header corruption detected",
    },
    BugCheckInfo {
        code: 0x0000_001A,
        name: "MEMORY_MANAGEMENT",
        summary: "Severe kernel memory management violation",
    },
    BugCheckInfo {
        code: 0x0000_001E,
        name: "KMODE_EXCEPTION_NOT_HANDLED",
        summary: "Unhandled kernel-mode exception",
    },
    BugCheckInfo {
        code: 0x0000_0024,
        name: "NTFS_FILE_SYSTEM",
        summary: "Fatal error in NTFS.sys file system driver",
    },
    BugCheckInfo {
        code: 0x0000_003B,
        name: "SYSTEM_SERVICE_EXCEPTION",
        summary: "Unhandled exception while executing a routine transitioning from non-privileged to privileged code",
    },
    BugCheckInfo {
        code: 0x0000_004E,
        name: "PFN_LIST_CORRUPT",
        summary: "Page Frame Number (PFN) list corruption",
    },
    BugCheckInfo {
        code: 0x0000_0050,
        name: "PAGE_FAULT_IN_NONPAGED_AREA",
        summary: "Invalid system memory referenced (missing or unmapped kernel address)",
    },
    BugCheckInfo {
        code: 0x0000_0074,
        name: "BAD_SYSTEM_CONFIG_INFO",
        summary: "System Registry hive error preventing kernel initialization",
    },
    BugCheckInfo {
        code: 0x0000_0077,
        name: "KERNEL_STACK_INPAGE_ERROR",
        summary: "Requested page of kernel data could not be read from paging file",
    },
    BugCheckInfo {
        code: 0x0000_007A,
        name: "KERNEL_DATA_INPAGE_ERROR",
        summary: "Requested kernel page could not be paged into memory from disk",
    },
    BugCheckInfo {
        code: 0x0000_007E,
        name: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        summary: "System thread generated an exception that the error handler did not catch",
    },
    BugCheckInfo {
        code: 0x0000_007F,
        name: "UNEXPECTED_KERNEL_MODE_TRAP",
        summary: "CPU trap (such as double fault or divide error) in kernel mode",
    },
    BugCheckInfo {
        code: 0x0000_008E,
        name: "KERNEL_MODE_EXCEPTION_NOT_HANDLED",
        summary: "Unhandled kernel-mode application/driver exception",
    },
    BugCheckInfo {
        code: 0x0000_009C,
        name: "MACHINE_CHECK_EXCEPTION",
        summary: "Fatal hardware machine-check error reported by CPU",
    },
    BugCheckInfo {
        code: 0x0000_009F,
        name: "DRIVER_POWER_STATE_FAILURE",
        summary: "Driver failed to complete a power IRP within the required timeout",
    },
    BugCheckInfo {
        code: 0x0000_00BE,
        name: "ATTEMPTED_WRITE_TO_READONLY_MEMORY",
        summary: "Driver attempted to write to a read-only memory segment",
    },
    BugCheckInfo {
        code: 0x0000_00C2,
        name: "BAD_POOL_CALLER",
        summary: "Current thread made an invalid kernel pool allocation or free request",
    },
    BugCheckInfo {
        code: 0x0000_00C5,
        name: "DRIVER_CORRUPTED_EXPOOL",
        summary: "Kernel attempted to access invalid memory at too high an IRQL (pool corruption)",
    },
    BugCheckInfo {
        code: 0x0000_00C9,
        name: "DRIVER_VERIFIER_IOMANAGER_VIOLATION",
        summary: "Driver Verifier detected an I/O Manager usage violation",
    },
    BugCheckInfo {
        code: 0x0000_00D1,
        name: "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        summary: "Kernel driver accessed pageable memory at an IRQL that was too high",
    },
    BugCheckInfo {
        code: 0x0000_00D6,
        name: "DRIVER_PAGE_FAULT_BEYOND_END_OF_ALLOCATION",
        summary: "Driver accessed memory beyond the end of an allocated pool block",
    },
    BugCheckInfo {
        code: 0x0000_00EA,
        name: "THREAD_STUCK_IN_DEVICE_DRIVER",
        summary: "Thread in a device driver (typically display) entered an infinite loop",
    },
    BugCheckInfo {
        code: 0x0000_00ED,
        name: "UNMOUNTABLE_BOOT_VOLUME",
        summary: "Kernel I/O subsystem failed to mount the boot volume",
    },
    BugCheckInfo {
        code: 0x0000_00EF,
        name: "CRITICAL_PROCESS_DIED",
        summary: "A critical Windows process terminated unexpectedly",
    },
    BugCheckInfo {
        code: 0x0000_00F4,
        name: "CRITICAL_OBJECT_TERMINATION",
        summary: "A critical system process or thread exited unexpectedly",
    },
    BugCheckInfo {
        code: 0x0000_0109,
        name: "CRITICAL_STRUCTURE_CORRUPTION",
        summary: "PatchGuard detected modification of critical kernel code or data",
    },
    BugCheckInfo {
        code: 0x0000_0113,
        name: "VIDEO_DXGKRNL_FATAL_ERROR",
        summary: "DirectX Graphics Kernel subsystem detected a fatal violation",
    },
    BugCheckInfo {
        code: 0x0000_0116,
        name: "VIDEO_TDR_FAILURE",
        summary: "Display driver failed to respond and reset via Timeout Detection and Recovery",
    },
    BugCheckInfo {
        code: 0x0000_0119,
        name: "VIDEO_SCHEDULER_INTERNAL_ERROR",
        summary: "Video scheduler detected a fatal internal violation",
    },
    BugCheckInfo {
        code: 0x0000_0124,
        name: "WHEA_UNCORRECTABLE_ERROR",
        summary: "Fatal hardware error reported via Windows Hardware Error Architecture",
    },
    BugCheckInfo {
        code: 0x0000_0133,
        name: "DPC_WATCHDOG_VIOLATION",
        summary: "Deferred Procedure Call (DPC) ran longer than allowed watchdog interval",
    },
    BugCheckInfo {
        code: 0x0000_0139,
        name: "KERNEL_SECURITY_CHECK_FAILURE",
        summary: "Kernel detected corruption of a critical security data structure (/GS cookie or CFG)",
    },
    BugCheckInfo {
        code: 0x0000_0154,
        name: "UNEXPECTED_STORE_EXCEPTION",
        summary: "Kernel memory store component caught an unexpected exception",
    },
    BugCheckInfo {
        code: 0x0000_019C,
        name: "WIN32K_POWER_WATCHDOG_TIMEOUT",
        summary: "Win32k power state transition timed out",
    },
    BugCheckInfo {
        code: 0xC000_0218,
        name: "STATUS_CANNOT_LOAD_REGISTRY_FILE",
        summary: "Registry hive file could not be loaded during boot",
    },
    BugCheckInfo {
        code: 0xC000_021A,
        name: "WINLOGON_FATAL_ERROR",
        summary: "Session Manager or Winlogon terminated unexpectedly",
    },
    BugCheckInfo {
        code: 0xDEAD_DEAD,
        name: "MANUALLY_INITIATED_CRASH",
        summary: "Crash dump was manually triggered by the user or debugger",
    },
];

/// Normalizes legacy `0x100000xx` bugcheck codes (e.g. `0x1000007E -> 0x0000007E`).
pub fn normalize_bugcheck_code(code: u32) -> u32 {
    if (code & 0xFFFF_FF00) == 0x1000_0000 {
        code & 0x0000_00FF
    } else {
        code
    }
}

/// Looks up full metadata for a Windows BugCheck code.
pub fn lookup_bugcheck(code: u32) -> Option<BugCheckInfo> {
    let normalized = normalize_bugcheck_code(code);
    BUGCHECK_TABLE.iter().copied().find(|entry| entry.code == normalized)
}

/// Returns the canonical BugCheck symbol name (e.g. `SYSTEM_SERVICE_EXCEPTION`).
pub fn bugcheck_name(code: u32) -> Option<&'static str> {
    lookup_bugcheck(code).map(|info| info.name)
}

/// Returns `true` if the code represents a known BSOD BugCheck rather than a user-mode exception.
pub fn is_bugcheck_code(code: u32) -> bool {
    let norm = normalize_bugcheck_code(code);
    (1..=0xFFFF).contains(&norm) || matches!(norm, 0xC000_0218 | 0xC000_021A | 0xDEAD_DEAD)
}

/// Looks up a common Windows NTSTATUS / Win32 / CLR / MSVC exception code name.
pub fn lookup_exception_name(code: u32) -> Option<&'static str> {
    match code {
        0x8000_0001 => Some("STATUS_GUARD_PAGE_VIOLATION"),
        0x8000_0002 => Some("STATUS_DATATYPE_MISALIGNMENT"),
        0x8000_0003 => Some("STATUS_BREAKPOINT"),
        0x8000_0004 => Some("STATUS_SINGLE_STEP"),
        0xC000_0005 => Some("ACCESS_VIOLATION"),
        0xC000_0006 => Some("IN_PAGE_ERROR"),
        0xC000_0008 => Some("INVALID_HANDLE"),
        0xC000_0017 => Some("NO_MEMORY"),
        0xC000_001D => Some("ILLEGAL_INSTRUCTION"),
        0xC000_0025 => Some("NONCONTINUABLE_EXCEPTION"),
        0xC000_0026 => Some("INVALID_DISPOSITION"),
        0xC000_008C => Some("ARRAY_BOUNDS_EXCEEDED"),
        0xC000_008D => Some("FLOAT_DENORMAL_OPERAND"),
        0xC000_008E => Some("FLOAT_DIVIDE_BY_ZERO"),
        0xC000_008F => Some("FLOAT_INEXACT_RESULT"),
        0xC000_0090 => Some("FLOAT_INVALID_OPERATION"),
        0xC000_0091 => Some("FLOAT_OVERFLOW"),
        0xC000_0092 => Some("FLOAT_STACK_CHECK"),
        0xC000_0093 => Some("FLOAT_UNDERFLOW"),
        0xC000_0094 => Some("INT_DIVIDE_BY_ZERO"),
        0xC000_0095 => Some("INT_OVERFLOW"),
        0xC000_0096 => Some("PRIVILEGED_INSTRUCTION"),
        0xC000_00FD => Some("STACK_OVERFLOW"),
        0xC000_0135 => Some("DLL_NOT_FOUND"),
        0xC000_0138 => Some("ORDINAL_NOT_FOUND"),
        0xC000_0139 => Some("ENTRYPOINT_NOT_FOUND"),
        0xC000_0142 => Some("DLL_INIT_FAILED"),
        0xC000_0374 => Some("HEAP_CORRUPTION"),
        0xC000_0409 => Some("STACK_BUFFER_OVERRUN"),
        0xC000_0417 => Some("INVALID_CRUNTIME_PARAMETER"),
        0xC000_0602 => Some("FAIL_FAST_EXCEPTION"),
        0xE043_4352 => Some("CLR_EXCEPTION"),
        0xE06D_7363 => Some("CPP_EXCEPTION"),
        _ => None,
    }
}

/// Formats a human-readable exception description including access violation details if available.
pub fn format_exception_description(code: u32, params: &[u64]) -> String {
    match code {
        0xC000_0005 => {
            if params.len() >= 2 {
                let op = match params[0] {
                    0 => "reading",
                    1 => "writing",
                    8 => "executing (DEP)",
                    _ => "accessing",
                };
                format!("ACCESS_VIOLATION ({op} 0x{:016x})", params[1])
            } else {
                "ACCESS_VIOLATION".to_string()
            }
        }
        0xC000_0409 => {
            if let Some(&subcode) = params.first() {
                format!("STACK_BUFFER_OVERRUN (FAST_FAIL subcode 0x{subcode:x})")
            } else {
                "STACK_BUFFER_OVERRUN".to_string()
            }
        }
        other => {
            if let Some(name) = lookup_exception_name(other) {
                name.to_string()
            } else if let Some(bc) = lookup_bugcheck(other) {
                bc.name.to_string()
            } else {
                format!("EXCEPTION_0x{other:08X}")
            }
        }
    }
}

/// Extracts candidate faulting code addresses from BugCheck `Param1..4` based on Windows BugCheck conventions.
pub fn bugcheck_fault_address_candidates(code: u32, params: &[u64]) -> Vec<u64> {
    let norm = normalize_bugcheck_code(code);
    let mut out = Vec::new();
    let get = |idx: usize| -> Option<u64> { params.get(idx).copied().filter(|&v| v != 0) };
    match norm {
        // Param2 = faulting IP
        0x0000_001E | 0x0000_003B | 0x0000_007E | 0x0000_008E | 0x0000_00C9 | 0x0000_0116 => {
            if let Some(addr) = get(1) {
                out.push(addr);
            }
        }
        // Param3 = faulting IP
        0x0000_0050 | 0x0000_00BE => {
            if let Some(addr) = get(2) {
                out.push(addr);
            }
        }
        // Param4 = faulting IP
        0x0000_000A | 0x0000_00D1 | 0x0000_00D6 => {
            if let Some(addr) = get(3) {
                out.push(addr);
            }
        }
        _ => {}
    }
    // Also consider any remaining non-zero parameters as weak candidates if needed later.
    out
}

/// Returns `true` if `module_name` is a core Windows kernel/system image that often hosts
/// the trap handler rather than the root-cause third-party driver.
pub fn is_core_os_module(module_name: &str) -> bool {
    let base = module_name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(module_name)
        .to_ascii_lowercase();
    matches!(
        base.as_str(),
        "ntoskrnl.exe"
            | "ntkrnlmp.exe"
            | "ntkrnlpa.exe"
            | "ntkrpamp.exe"
            | "hal.dll"
            | "win32k.sys"
            | "win32kbase.sys"
            | "win32kfull.sys"
            | "ntdll.dll"
    )
}
