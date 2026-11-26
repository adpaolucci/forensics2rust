use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::bugcheck::{bugcheck_fault_address_candidates, is_core_os_module};
use crate::mdmp::MinidumpFile;
use crate::pe::{PeImageExports, resolve_va_with_cache};

/// Method by which a stack frame was reconstructed offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameMethod {
    ContextIp,
    FramePointer,
    StackScan,
}

/// Reconstructed offline call-stack frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackFrame {
    pub index: usize,
    pub instruction_pointer: u64,
    pub stack_pointer: Option<u64>,
    pub module_name: Option<String>,
    pub module_path: Option<String>,
    pub module_offset: Option<u64>,
    pub symbol: Option<String>,
    pub unloaded: bool,
    pub method: FrameMethod,
}

impl StackFrame {
    pub fn display_location(&self) -> String {
        if let Some(sym) = &self.symbol {
            return sym.clone();
        }
        match (&self.module_name, self.module_offset) {
            (Some(name), Some(off)) if self.unloaded => format!("<unloaded> {name}+0x{off:x}"),
            (Some(name), Some(off)) => format!("{name}+0x{off:x}"),
            _ => format!("0x{:016x}", self.instruction_pointer),
        }
    }
}

/// Result of root-cause driver / fault module attribution.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultAttribution {
    pub module_name: Option<String>,
    pub module_path: Option<String>,
    pub module_version: Option<String>,
    pub caused_by_address: Option<String>,
    pub crash_address: Option<u64>,
    pub fault_symbol: Option<String>,
    pub unloaded: bool,
}

fn resolve_frame_symbol(
    dump: &MinidumpFile,
    va: u64,
    pe_cache: Option<&mut HashMap<String, Option<PeImageExports>>>,
) -> (Option<String>, Option<String>, Option<u64>, Option<String>, bool) {
    if let Some(resolved) = dump.resolve_address(va) {
        let pe_sym = if let Some(cache) = pe_cache
            && !resolved.unloaded
            && !resolved.module_path.is_empty()
        {
            resolve_va_with_cache(cache, &resolved.module_path, resolved.base_of_image, va)
        } else {
            None
        };
        let symbol = pe_sym.or_else(|| Some(resolved.format_symbolic()));
        (
            Some(resolved.module_name),
            Some(resolved.module_path),
            Some(resolved.offset),
            symbol,
            resolved.unloaded,
        )
    } else {
        (None, None, None, None, false)
    }
}

/// Reconstructs the faulting thread call stack offline from `CONTEXT` and captured stack memory
/// (zero DLL injection, zero `dbghelp.dll`).
pub fn walk_stack(dump: &MinidumpFile, try_local_pe: bool) -> Vec<StackFrame> {
    let mut frames = Vec::new();
    let mut seen_ips = HashSet::new();
    let mut pe_cache: Option<HashMap<String, Option<PeImageExports>>> = try_local_pe.then(HashMap::new);

    let ctx = dump.faulting_context();
    let initial_ip = ctx
        .and_then(|c| c.ip())
        .or_else(|| dump.exception.as_ref().map(|e| e.exception_address))
        .unwrap_or(0);
    let initial_sp = ctx.and_then(|c| c.sp());

    if initial_ip != 0 {
        let (module_name, module_path, module_offset, symbol, unloaded) =
            resolve_frame_symbol(dump, initial_ip, pe_cache.as_mut());
        seen_ips.insert(initial_ip);
        frames.push(StackFrame {
            index: 0,
            instruction_pointer: initial_ip,
            stack_pointer: initial_sp,
            module_name,
            module_path,
            module_offset,
            symbol,
            unloaded,
            method: FrameMethod::ContextIp,
        });
    }

    let Some(ctx) = ctx else {
        return frames;
    };
    let (Some(ptr_size), Some(sp), Some(mut bp)) = (ctx.ptr_size(), ctx.sp(), ctx.bp()) else {
        return frames;
    };
    let Some(stack_win) = dump.stack_window_for(sp) else {
        return frames;
    };
    let stack_start = stack_win.start_va;
    let stack_end = stack_win.start_va.saturating_add(stack_win.data_size);
    let ptr_u64 = ptr_size as u64;

    // Phase A: Frame-pointer chain walk (up to 64 frames).
    for _ in 0..64 {
        if bp < stack_start
            || !bp.is_multiple_of(ptr_u64)
            || bp.checked_add(ptr_u64 * 2).is_none_or(|end| end > stack_end)
        {
            break;
        }
        let (next_bp, ret_addr) = if ptr_size == 8 {
            let Some(nbp) = dump.read_va_u64(bp) else {
                break;
            };
            let Some(ret) = dump.read_va_u64(bp + 8) else {
                break;
            };
            (nbp, ret)
        } else {
            let Some(nbp) = dump.read_va_u32(bp) else {
                break;
            };
            let Some(ret) = dump.read_va_u32(bp + 4) else {
                break;
            };
            (u64::from(nbp), u64::from(ret))
        };

        if ret_addr == 0 {
            break;
        }

        let (module_name, module_path, module_offset, symbol, unloaded) =
            resolve_frame_symbol(dump, ret_addr, pe_cache.as_mut());
        seen_ips.insert(ret_addr);
        frames.push(StackFrame {
            index: frames.len(),
            instruction_pointer: ret_addr,
            stack_pointer: Some(bp + ptr_u64),
            module_name,
            module_path,
            module_offset,
            symbol,
            unloaded,
            method: FrameMethod::FramePointer,
        });

        if next_bp == 0 || next_bp <= bp {
            break;
        }
        bp = next_bp;
    }

    // Phase B: Stack return-address scan for frameless/leaf frames (up to 4 KiB from SP).
    let scan_end = stack_end.min(sp.saturating_add(4096));
    let mut cursor = sp;
    let mut last_scan_ip: Option<u64> = None;
    while cursor.checked_add(ptr_u64).is_some_and(|end| end <= scan_end) && frames.len() < 128 {
        let word = if ptr_size == 8 {
            dump.read_va_u64(cursor)
        } else {
            dump.read_va_u32(cursor).map(u64::from)
        };
        if let Some(addr) = word
            && addr != 0
            && !seen_ips.contains(&addr)
            && last_scan_ip != Some(addr)
            && dump.resolve_loaded_address(addr).is_some()
        {
            let (module_name, module_path, module_offset, symbol, unloaded) =
                resolve_frame_symbol(dump, addr, pe_cache.as_mut());
            seen_ips.insert(addr);
            last_scan_ip = Some(addr);
            frames.push(StackFrame {
                index: frames.len(),
                instruction_pointer: addr,
                stack_pointer: Some(cursor),
                module_name,
                module_path,
                module_offset,
                symbol,
                unloaded,
                method: FrameMethod::StackScan,
            });
        }
        cursor = cursor.saturating_add(ptr_u64);
    }

    frames
}

/// Attributes the most likely faulting module / driver using exception address, BugCheck parameters,
/// reconstructed call stack (preferring non-core drivers over `ntoskrnl.exe`/`hal.dll`), and
/// unloaded module fallback.
pub fn attribute_fault_module(dump: &MinidumpFile, frames: &[StackFrame], try_local_pe: bool) -> FaultAttribution {
    let exc_addr = dump
        .exception
        .as_ref()
        .map(|e| e.exception_address)
        .filter(|&a| a != 0)
        .or_else(|| frames.first().map(|f| f.instruction_pointer));

    let mut pe_cache: Option<HashMap<String, Option<PeImageExports>>> = try_local_pe.then(HashMap::new);

    let mut make_attr = |va: u64, sym_hint: Option<String>| -> Option<FaultAttribution> {
        let resolved = dump.resolve_address(va)?;
        let pe_sym = sym_hint.or_else(|| {
            if let Some(cache) = pe_cache.as_mut()
                && !resolved.unloaded
                && !resolved.module_path.is_empty()
            {
                resolve_va_with_cache(cache, &resolved.module_path, resolved.base_of_image, va)
            } else {
                None
            }
        });
        Some(FaultAttribution {
            module_name: Some(resolved.module_name.clone()),
            module_path: if resolved.module_path.is_empty() {
                None
            } else {
                Some(resolved.module_path.clone())
            },
            module_version: resolved.file_version.clone(),
            caused_by_address: Some(resolved.format_symbolic()),
            crash_address: exc_addr.or(Some(va)),
            fault_symbol: pe_sym.or_else(|| Some(resolved.format_symbolic())),
            unloaded: resolved.unloaded,
        })
    };

    // 1. ExceptionAddress inside a non-core loaded module.
    if let Some(va) = exc_addr
        && let Some(resolved) = dump.resolve_loaded_address(va)
        && !is_core_os_module(&resolved.module_name)
        && let Some(attr) = make_attr(va, frames.first().and_then(|f| f.symbol.clone()))
    {
        return attr;
    }

    // 2. BugCheck-specific parameter IP inside a non-core loaded module.
    if let Some(exc) = &dump.exception {
        for cand in bugcheck_fault_address_candidates(exc.exception_code, &exc.exception_information) {
            if let Some(resolved) = dump.resolve_loaded_address(cand)
                && !is_core_os_module(&resolved.module_name)
                && let Some(attr) = make_attr(cand, None)
            {
                return attr;
            }
        }
    }

    // 3. First ContextIp / FramePointer stack frame inside a non-core loaded module.
    for frame in frames
        .iter()
        .filter(|f| matches!(f.method, FrameMethod::ContextIp | FrameMethod::FramePointer))
    {
        if !frame.unloaded
            && let Some(name) = &frame.module_name
            && !is_core_os_module(name)
            && let Some(attr) = make_attr(frame.instruction_pointer, frame.symbol.clone())
        {
            return attr;
        }
    }

    // 4. First StackScan frame inside a non-core loaded module.
    for frame in frames.iter().filter(|f| f.method == FrameMethod::StackScan) {
        if !frame.unloaded
            && let Some(name) = &frame.module_name
            && !is_core_os_module(name)
            && let Some(attr) = make_attr(frame.instruction_pointer, frame.symbol.clone())
        {
            return attr;
        }
    }

    // 5. Fallback: loaded module containing ExceptionAddress (even if core OS), else UnloadedModuleListStream.
    if let Some(va) = exc_addr
        && let Some(attr) = make_attr(va, frames.first().and_then(|f| f.symbol.clone()))
    {
        return attr;
    }

    if let Some(exc) = &dump.exception {
        for cand in bugcheck_fault_address_candidates(exc.exception_code, &exc.exception_information) {
            if let Some(attr) = make_attr(cand, None) {
                return attr;
            }
        }
    }

    FaultAttribution {
        crash_address: exc_addr,
        ..FaultAttribution::default()
    }
}
