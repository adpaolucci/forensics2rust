use std::path::PathBuf;

use chrono::DateTime;
use forensics2rust_core::{
    FORENSIC_TOOL_CATALOG, ForensicError, ForensicSource, QueryHelper, ToolCategory, WarningSeverity, utc_to_filetime,
};
use guap_table::{TableData, TableError, TableProvider, TableQuery};

use crate::bugcheck::{bugcheck_name, lookup_exception_name, normalize_bugcheck_code};
use crate::context::{CpuContext, ProcessorArch};
use crate::discovery::{LiveRootSpec, discover_from_live_roots, is_dmp_file};
use crate::mdmp::{MDMP_SIGNATURE, MINIDUMP_VERSION, MinidumpFile, VS_FFI_SIGNATURE, stream_type};
use crate::pe::PeImageExports;
use crate::providers::{CrashBsodProvider, CrashReportProvider, CrashWerProvider};
use crate::stack::{FrameMethod, attribute_fault_module, walk_stack};
use crate::wer::{WerEncoding, WerReport, parse_wer_filetime};
use crate::{all_providers, crate_info, default_providers, domain_tools, provider_for_tool};

fn push_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn push_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn push_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn write_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn encode_minidump_string(s: &str) -> Vec<u8> {
    let units: Vec<u16> = s.encode_utf16().collect();
    let byte_len = (units.len() * 2) as u32;
    let mut out = Vec::with_capacity(4 + units.len() * 2 + 2);
    push_u32(&mut out, byte_len);
    for u in units {
        push_u16(&mut out, u);
    }
    push_u16(&mut out, 0);
    out
}

#[allow(clippy::too_many_arguments)]
fn append_module_entry(
    buf: &mut Vec<u8>,
    base: u64,
    size: u32,
    name_rva: u32,
    fv_ms: u32,
    fv_ls: u32,
    pv_ms: u32,
    pv_ls: u32,
    cv_size: u32,
    cv_rva: u32,
) {
    push_u64(buf, base);
    push_u32(buf, size);
    push_u32(buf, 0x1234_5678); // CheckSum
    push_u32(buf, 1_732_340_000); // TimeDateStamp
    push_u32(buf, name_rva);
    // VS_FIXEDFILEINFO (52 bytes)
    push_u32(buf, VS_FFI_SIGNATURE);
    push_u32(buf, 0x0001_0000); // dwStrucVersion
    push_u32(buf, fv_ms);
    push_u32(buf, fv_ls);
    push_u32(buf, pv_ms);
    push_u32(buf, pv_ls);
    push_u32(buf, 0x3F); // dwFileFlagsMask
    push_u32(buf, 0); // dwFileFlags
    push_u32(buf, 0x40004); // VOS_NT_WINDOWS32
    push_u32(buf, 3); // VFT_DRV
    push_u32(buf, 0);
    push_u32(buf, 0);
    push_u32(buf, 0);
    // CvRecord (8B)
    push_u32(buf, cv_size);
    push_u32(buf, cv_rva);
    // MiscRecord (8B)
    push_u32(buf, 0);
    push_u32(buf, 0);
    // Reserved0, Reserved1 (16B)
    push_u64(buf, 0);
    push_u64(buf, 0);
}

/// Builds Explorer 2 Fixture 1: Kernel BSOD `0x0000003B` (`SYSTEM_SERVICE_EXCEPTION`) x64 `MDMP` (`2168` bytes).
fn build_kernel_bsod_x64_mdmp() -> Vec<u8> {
    let mut buf = Vec::new();
    // MINIDUMP_HEADER (32B)
    push_u32(&mut buf, MDMP_SIGNATURE);
    push_u32(&mut buf, MINIDUMP_VERSION);
    push_u32(&mut buf, 6); // NumberOfStreams
    push_u32(&mut buf, 0x0020); // StreamDirectoryRva
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 1_732_350_000);
    push_u64(&mut buf, 0x0121);

    // MINIDUMP_DIRECTORY (6 * 12 = 72B at 0x0020..0x0068)
    let dir = [
        (stream_type::SYSTEM_INFO, 56u32, 0x0068u32),
        (stream_type::EXCEPTION, 168, 0x00A0),
        (stream_type::MODULE_LIST, 220, 0x0148),
        (stream_type::THREAD_LIST, 52, 0x0224),
        (stream_type::UNLOADED_MODULE_LIST, 36, 0x0258),
        (stream_type::MISC_INFO, 24, 0x027C),
    ];
    for (stype, size, rva) in dir {
        push_u32(&mut buf, stype);
        push_u32(&mut buf, size);
        push_u32(&mut buf, rva);
    }
    assert_eq!(buf.len(), 0x0068);

    // SystemInfoStream (56B at 0x0068..0x00A0)
    push_u16(&mut buf, 9); // AMD64
    push_u16(&mut buf, 6);
    push_u16(&mut buf, 0x9E0A);
    buf.push(8); // NumberOfProcessors
    buf.push(1); // Workstation
    push_u32(&mut buf, 10);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 22631);
    push_u32(&mut buf, 2);
    push_u32(&mut buf, 0x0294); // CSDVersionRva
    push_u16(&mut buf, 0x0100);
    push_u16(&mut buf, 0);
    buf.extend_from_slice(&[0u8; 24]);
    assert_eq!(buf.len(), 0x00A0);

    // ExceptionStream (168B at 0x00A0..0x0148)
    push_u32(&mut buf, 0x1234); // ThreadId
    push_u32(&mut buf, 0); // alignment
    push_u32(&mut buf, 0x0000_003B); // BugCheckCode
    push_u32(&mut buf, 1);
    push_u64(&mut buf, 0);
    push_u64(&mut buf, 0xFFFF_F801_1234_0500); // ExceptionAddress -> bad_driver.sys+0x500
    push_u32(&mut buf, 4);
    push_u32(&mut buf, 0);
    push_u64(&mut buf, 0xC000_0005);
    push_u64(&mut buf, 0xFFFF_F801_1234_0500);
    push_u64(&mut buf, 0xFFFF_9A00_0000_1000);
    push_u64(&mut buf, 0);
    for _ in 4..15 {
        push_u64(&mut buf, 0);
    }
    push_u32(&mut buf, 1232); // ThreadContext.DataSize
    push_u32(&mut buf, 0x0368); // ThreadContext.Rva
    assert_eq!(buf.len(), 0x0148);

    // ModuleListStream (220B at 0x0148..0x0224)
    push_u32(&mut buf, 2);
    append_module_entry(
        &mut buf,
        0xFFFF_F801_0000_0000,
        0x0100_0000,
        0x029A,
        10 << 16,
        (22621 << 16) | 3007,
        10 << 16,
        (22621 << 16) | 3007,
        0,
        0,
    );
    append_module_entry(
        &mut buf,
        0xFFFF_F801_1234_0000,
        0x0002_0000,
        0x02E2,
        (1 << 16) | 2,
        (3 << 16) | 4,
        (1 << 16) | 2,
        (3 << 16) | 4,
        0,
        0,
    );
    assert_eq!(buf.len(), 0x0224);

    // ThreadListStream (52B at 0x0224..0x0258)
    push_u32(&mut buf, 1);
    push_u32(&mut buf, 0x1234);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 8);
    push_u64(&mut buf, 0xFFFF_F801_0000_9000);
    push_u64(&mut buf, 0xFFFF_9A00_0000_2000); // Stack.Start
    push_u32(&mut buf, 64); // Stack.DataSize
    push_u32(&mut buf, 0x0838); // Stack.Rva
    push_u32(&mut buf, 1232);
    push_u32(&mut buf, 0x0368);
    assert_eq!(buf.len(), 0x0258);

    // UnloadedModuleListStream (36B at 0x0258..0x027C)
    push_u32(&mut buf, 12);
    push_u32(&mut buf, 24);
    push_u32(&mut buf, 1);
    push_u64(&mut buf, 0xFFFF_F801_2000_0000);
    push_u32(&mut buf, 0x0001_0000);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 1_732_345_000);
    push_u32(&mut buf, 0x033E);
    assert_eq!(buf.len(), 0x027C);

    // MiscInfoStream (24B at 0x027C..0x0294)
    push_u32(&mut buf, 24);
    push_u32(&mut buf, 3);
    push_u32(&mut buf, 4); // PID 4
    push_u32(&mut buf, 1_732_349_000);
    push_u32(&mut buf, 100);
    push_u32(&mut buf, 200);
    assert_eq!(buf.len(), 0x0294);

    // String table (0x0294..0x0368)
    buf.extend_from_slice(&encode_minidump_string(""));
    assert_eq!(buf.len(), 0x029A);
    buf.extend_from_slice(&encode_minidump_string(r"\SystemRoot\system32\ntoskrnl.exe"));
    assert_eq!(buf.len(), 0x02E2);
    buf.extend_from_slice(&encode_minidump_string(r"\SystemRoot\System32\drivers\bad_driver.sys"));
    assert_eq!(buf.len(), 0x033E);
    buf.extend_from_slice(&encode_minidump_string("unloaded_drv.sys"));
    buf.extend_from_slice(&[0u8; 4]);
    assert_eq!(buf.len(), 0x0368);

    // x64 CONTEXT (1232B at 0x0368..0x0838)
    let mut ctx = vec![0u8; 1232];
    write_u32(&mut ctx, 0x030, 0x0010_001F);
    write_u16(&mut ctx, 0x038, 0x0010);
    write_u32(&mut ctx, 0x044, 0x0001_0246);
    write_u64(&mut ctx, 0x078, 0xDEAD_BEEF_0000_0001); // Rax
    write_u64(&mut ctx, 0x098, 0xFFFF_9A00_0000_2000); // Rsp
    write_u64(&mut ctx, 0x0A0, 0xFFFF_9A00_0000_2010); // Rbp
    write_u64(&mut ctx, 0x0F8, 0xFFFF_F801_1234_0500); // Rip
    buf.extend_from_slice(&ctx);
    assert_eq!(buf.len(), 0x0838);

    // Stack memory (64B at 0x0838..0x0878)
    let mut stack = vec![0u8; 64];
    write_u64(&mut stack, 0x08, 0xFFFF_F801_1234_0420); // scan frame in bad_driver.sys+0x420
    write_u64(&mut stack, 0x10, 0xFFFF_9A00_0000_2030); // next_bp
    write_u64(&mut stack, 0x18, 0xFFFF_F801_0001_2340); // ret -> ntoskrnl.exe+0x12340
    write_u64(&mut stack, 0x30, 0); // next_bp = 0
    write_u64(&mut stack, 0x38, 0xFFFF_F801_0002_0080); // ret -> ntoskrnl.exe+0x20080
    buf.extend_from_slice(&stack);
    assert_eq!(buf.len(), 2168);

    buf
}

/// Builds a synthetic PE32 DLL with `IMAGE_EXPORT_DIRECTORY` exporting `CrashHere` at RVA `0x1000`.
fn build_synthetic_pe32_dll() -> Vec<u8> {
    let mut pe = vec![0u8; 0x400];
    // DOS header
    write_u16(&mut pe, 0x00, 0x5A4D); // MZ
    write_u32(&mut pe, 0x3C, 0x80); // e_lfanew = 0x80
    // PE\0\0 + IMAGE_FILE_HEADER (20B) at 0x80
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    write_u16(&mut pe, 0x84, 0x014C); // x86
    write_u16(&mut pe, 0x86, 1); // NumberOfSections = 1
    write_u16(&mut pe, 0x94, 0xE0); // SizeOfOptionalHeader = 224 (PE32)
    // IMAGE_OPTIONAL_HEADER32 at 0x98
    write_u16(&mut pe, 0x98, 0x010B); // PE32 magic
    write_u32(&mut pe, 0x98 + 0x3C, 0x200); // SizeOfHeaders
    write_u32(&mut pe, 0x98 + 0x5C, 16); // NumberOfRvaAndSizes
    write_u32(&mut pe, 0x98 + 0x60, 0x1100); // Export RVA
    write_u32(&mut pe, 0x98 + 0x64, 0x80); // Export Size
    // Section header .text at 0x98 + 0xE0 = 0x178
    let sec = 0x178;
    pe[sec..sec + 5].copy_from_slice(b".text");
    write_u32(&mut pe, sec + 0x08, 0x1000); // VirtualSize
    write_u32(&mut pe, sec + 0x0C, 0x1000); // VirtualAddress
    write_u32(&mut pe, sec + 0x10, 0x200); // SizeOfRawData
    write_u32(&mut pe, sec + 0x14, 0x200); // PointerToRawData

    // .text raw data starts at file offset 0x200 (RVA 0x1000).
    // RVA 0x1100 -> file offset 0x300: IMAGE_EXPORT_DIRECTORY (40B)
    let exp = 0x300;
    write_u32(&mut pe, exp + 0x10, 1); // Base = 1
    write_u32(&mut pe, exp + 0x14, 1); // NumberOfFunctions = 1
    write_u32(&mut pe, exp + 0x18, 1); // NumberOfNames = 1
    write_u32(&mut pe, exp + 0x1C, 0x1130); // AddressOfFunctions RVA -> 0x330
    write_u32(&mut pe, exp + 0x20, 0x1138); // AddressOfNames RVA -> 0x338
    write_u32(&mut pe, exp + 0x24, 0x1140); // AddressOfNameOrdinals RVA -> 0x340

    write_u32(&mut pe, 0x330, 0x1000); // CrashHere RVA = 0x1000
    write_u32(&mut pe, 0x338, 0x1148); // Name RVA = 0x1148 -> 0x348
    write_u16(&mut pe, 0x340, 0); // Ordinal index = 0
    pe[0x348..0x352].copy_from_slice(b"CrashHere\0");

    pe
}

/// Builds a minimal PE32+ (x64) image with one exported symbol + one forwarded export.
fn build_synthetic_pe64_dll() -> Vec<u8> {
    let mut pe = vec![0u8; 0x400];
    write_u16(&mut pe, 0x00, 0x5A4D);
    write_u32(&mut pe, 0x3C, 0x80);
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    write_u16(&mut pe, 0x84, 0x8664); // AMD64
    write_u16(&mut pe, 0x86, 1);
    write_u16(&mut pe, 0x94, 0xF0); // SizeOfOptionalHeader = 240 (PE32+)
    // Optional header at 0x98
    write_u16(&mut pe, 0x98, 0x020B); // PE32+
    write_u32(&mut pe, 0x98 + 0x3C, 0x200);
    write_u32(&mut pe, 0x98 + 0x6C, 16);
    write_u32(&mut pe, 0x98 + 0x70, 0x1100);
    write_u32(&mut pe, 0x98 + 0x74, 0x90);
    // Section header at 0x98 + 0xF0 = 0x188
    let sec = 0x188;
    pe[sec..sec + 5].copy_from_slice(b".text");
    write_u32(&mut pe, sec + 0x08, 0x1000);
    write_u32(&mut pe, sec + 0x0C, 0x1000);
    write_u32(&mut pe, sec + 0x10, 0x200);
    write_u32(&mut pe, sec + 0x14, 0x200);

    let exp = 0x300;
    write_u32(&mut pe, exp + 0x10, 10);
    write_u32(&mut pe, exp + 0x14, 2);
    write_u32(&mut pe, exp + 0x18, 2);
    write_u32(&mut pe, exp + 0x1C, 0x1130);
    write_u32(&mut pe, exp + 0x20, 0x1138);
    write_u32(&mut pe, exp + 0x24, 0x1140);

    write_u32(&mut pe, 0x330, 0x1040); // RealExport RVA
    write_u32(&mut pe, 0x334, 0x1168); // Forwarded RVA inside [0x1100, 0x1190)
    write_u32(&mut pe, 0x338, 0x1148);
    write_u32(&mut pe, 0x33C, 0x1154);
    write_u16(&mut pe, 0x340, 0);
    write_u16(&mut pe, 0x342, 1);

    pe[0x348..0x353].copy_from_slice(b"RealExport\0");
    pe[0x354..0x35F].copy_from_slice(b"FwdExport\0\0");
    pe[0x368..0x37B].copy_from_slice(b"NTDLL.RtlAllocHeap\0");
    pe
}

/// Builds Explorer 2 Fixture 2: User-Mode `0xC0000005` x86 `MDMP` pointing Mod 1 to `faulting_dll_path`.
fn build_usermode_x86_mdmp(faulting_dll_path: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, MDMP_SIGNATURE);
    push_u32(&mut buf, MINIDUMP_VERSION);
    push_u32(&mut buf, 6); // SystemInfo, Exception, ModuleList, ThreadList, MemoryList, MiscInfo
    push_u32(&mut buf, 0x0020);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 1_732_350_100);
    push_u64(&mut buf, 0);

    let dir_off = buf.len();
    buf.resize(dir_off + 6 * 12, 0);

    // SystemInfo (56B)
    let sys_rva = buf.len() as u32;
    push_u16(&mut buf, 0); // INTEL x86
    push_u16(&mut buf, 6);
    push_u16(&mut buf, 0);
    buf.push(4);
    buf.push(1);
    push_u32(&mut buf, 10);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 22631);
    push_u32(&mut buf, 2);
    let csd_rva_patch = buf.len();
    push_u32(&mut buf, 0);
    push_u16(&mut buf, 0);
    push_u16(&mut buf, 0);
    buf.extend_from_slice(&[0u8; 24]);

    // ExceptionStream (168B)
    let exc_rva = buf.len() as u32;
    push_u32(&mut buf, 0x0555);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 0xC000_0005);
    push_u32(&mut buf, 0);
    push_u64(&mut buf, 0);
    push_u64(&mut buf, 0x1000_1020);
    push_u32(&mut buf, 2);
    push_u32(&mut buf, 0);
    push_u64(&mut buf, 0); // Read
    push_u64(&mut buf, 0); // NULL deref
    for _ in 2..15 {
        push_u64(&mut buf, 0);
    }
    push_u32(&mut buf, 716);
    let exc_ctx_rva_patch = buf.len();
    push_u32(&mut buf, 0);

    // ModuleListStream (220B)
    let mod_rva = buf.len() as u32;
    push_u32(&mut buf, 2);
    let mod0_name_patch = buf.len() + 0x14;
    append_module_entry(&mut buf, 0x0040_0000, 0x0002_0000, 0, 1 << 16, 1, 1 << 16, 1, 0, 0);
    let mod1_name_patch = buf.len() + 0x14;
    append_module_entry(
        &mut buf,
        0x1000_0000,
        0x0001_0000,
        0,
        (2 << 16) | 5,
        9,
        (2 << 16) | 5,
        9,
        0,
        0,
    );

    // ThreadListStream (52B)
    let thd_rva = buf.len() as u32;
    push_u32(&mut buf, 1);
    push_u32(&mut buf, 0x0555);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 8);
    push_u64(&mut buf, 0x7FFD_E000);
    push_u64(&mut buf, 0x0019_FF00);
    push_u32(&mut buf, 64);
    let thd_stack_rva_patch = buf.len();
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 716);
    let thd_ctx_rva_patch = buf.len();
    push_u32(&mut buf, 0);

    // MemoryListStream (20B)
    let mem_rva = buf.len() as u32;
    push_u32(&mut buf, 1);
    push_u64(&mut buf, 0x0019_FF00);
    push_u32(&mut buf, 64);
    let mem_stack_rva_patch = buf.len();
    push_u32(&mut buf, 0);

    // MiscInfoStream (24B)
    let misc_rva = buf.len() as u32;
    push_u32(&mut buf, 24);
    push_u32(&mut buf, 3);
    push_u32(&mut buf, 4242); // PID
    push_u32(&mut buf, 1_732_349_900);
    push_u32(&mut buf, 12);
    push_u32(&mut buf, 5);

    // Strings
    let csd_rva = buf.len() as u32;
    buf.extend_from_slice(&encode_minidump_string(""));
    let mod0_rva = buf.len() as u32;
    buf.extend_from_slice(&encode_minidump_string(r"C:\app\demo.exe"));
    let mod1_rva = buf.len() as u32;
    buf.extend_from_slice(&encode_minidump_string(faulting_dll_path));

    // x86 CONTEXT (716B)
    let ctx_rva = buf.len() as u32;
    let mut ctx = vec![0u8; 716];
    write_u32(&mut ctx, 0x000, 0x0001_003F);
    write_u32(&mut ctx, 0x0B0, 0x1122_3344); // Eax
    write_u32(&mut ctx, 0x0B4, 0x0019_FF10); // Ebp
    write_u32(&mut ctx, 0x0B8, 0x1000_1020); // Eip
    write_u32(&mut ctx, 0x0BC, 0x0023);
    write_u32(&mut ctx, 0x0C0, 0x0001_0202);
    write_u32(&mut ctx, 0x0C4, 0x0019_FF00); // Esp
    write_u32(&mut ctx, 0x0C8, 0x002B);
    buf.extend_from_slice(&ctx);

    // Stack memory (64B)
    let stack_rva = buf.len() as u32;
    let mut stack = vec![0u8; 64];
    write_u32(&mut stack, 0x10, 0x0019_FF28);
    write_u32(&mut stack, 0x14, 0x0040_1200); // demo.exe+0x1200
    write_u32(&mut stack, 0x28, 0);
    write_u32(&mut stack, 0x2C, 0x0040_1050); // demo.exe+0x1050
    buf.extend_from_slice(&stack);

    // Patch RVAs
    write_u32(&mut buf, csd_rva_patch, csd_rva);
    write_u32(&mut buf, exc_ctx_rva_patch, ctx_rva);
    write_u32(&mut buf, mod0_name_patch, mod0_rva);
    write_u32(&mut buf, mod1_name_patch, mod1_rva);
    write_u32(&mut buf, thd_stack_rva_patch, stack_rva);
    write_u32(&mut buf, thd_ctx_rva_patch, ctx_rva);
    write_u32(&mut buf, mem_stack_rva_patch, stack_rva);

    let entries = [
        (stream_type::SYSTEM_INFO, 56u32, sys_rva),
        (stream_type::EXCEPTION, 168, exc_rva),
        (stream_type::MODULE_LIST, 220, mod_rva),
        (stream_type::THREAD_LIST, 52, thd_rva),
        (stream_type::MEMORY_LIST, 20, mem_rva),
        (stream_type::MISC_INFO, 24, misc_rva),
    ];
    for (i, (st, sz, rva)) in entries.into_iter().enumerate() {
        let off = dir_off + i * 12;
        write_u32(&mut buf, off, st);
        write_u32(&mut buf, off + 4, sz);
        write_u32(&mut buf, off + 8, rva);
    }

    buf
}

fn encode_utf16le(text: &str, with_bom: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if with_bom {
        out.extend_from_slice(&[0xFF, 0xFE]);
    }
    for u in text.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

fn encode_utf16be(text: &str, with_bom: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if with_bom {
        out.extend_from_slice(&[0xFE, 0xFF]);
    }
    for u in text.encode_utf16() {
        out.extend_from_slice(&u.to_be_bytes());
    }
    out
}

#[test]
fn mdmp_kernel_bsod_fixture_parses_stream_ids_registers_stack_and_driver() {
    let bytes = build_kernel_bsod_x64_mdmp();
    let dump = MinidumpFile::from_bytes(&bytes).expect("valid kernel BSOD MDMP");

    assert_eq!(dump.header.signature, MDMP_SIGNATURE);
    assert_eq!(dump.directory.len(), 6);
    assert_eq!(dump.directory[0].stream_type, 7); // SystemInfoStream
    assert_eq!(dump.directory[1].stream_type, 6); // ExceptionStream
    assert_eq!(dump.directory[2].stream_type, 4); // ModuleListStream
    assert_eq!(dump.directory[3].stream_type, 3); // ThreadListStream
    assert_eq!(dump.directory[4].stream_type, 14); // UnloadedModuleListStream
    assert_eq!(dump.directory[5].stream_type, 15); // MiscInfoStream

    let si = dump.system_info.as_ref().unwrap();
    assert_eq!(si.processor_architecture, ProcessorArch::Amd64);
    assert_eq!(si.build_number, 22631);
    assert_eq!(si.number_of_processors, 8);

    let frames = walk_stack(&dump, false);
    assert!(frames.len() >= 3);
    assert_eq!(frames[0].display_location(), "bad_driver.sys+0x500");
    assert_eq!(frames[0].method, FrameMethod::ContextIp);
    assert_eq!(frames[1].display_location(), "ntoskrnl.exe+0x12340");
    assert_eq!(frames[1].method, FrameMethod::FramePointer);
    assert_eq!(frames[2].display_location(), "ntoskrnl.exe+0x20080");
    assert_eq!(frames[2].method, FrameMethod::FramePointer);

    let attr = attribute_fault_module(&dump, &frames, false);
    assert_eq!(attr.module_name.as_deref(), Some("bad_driver.sys"));
    assert_eq!(attr.caused_by_address.as_deref(), Some("bad_driver.sys+0x500"));
    assert_eq!(attr.module_version.as_deref(), Some("1.2.3.4"));
    assert!(!attr.unloaded);

    assert_eq!(dump.unloaded_modules.len(), 1);
    assert_eq!(dump.unloaded_modules[0].module_name, "unloaded_drv.sys");
    assert_eq!(dump.misc_info.as_ref().and_then(|m| m.process_id), Some(4));

    // Verify CrashBsodProvider output & GuapQuery compatibility
    let provider = CrashBsodProvider::new(ForensicSource::OfflineBytes(bytes));
    assert!(provider.is_read_only());
    let data = provider.query(&TableQuery::default()).unwrap();
    assert_eq!(data.total_rows, 1);
    let row = &data.rows[0];
    let schema = provider.schema();
    let idx = |name: &str| schema.column_index(name).unwrap();
    assert_eq!(row.cells[idx("bugcheck_code")].to_string(), "0x0000003b");
    assert_eq!(row.cells[idx("bugcheck_name")].to_string(), "SYSTEM_SERVICE_EXCEPTION");
    assert_eq!(row.cells[idx("caused_by_driver")].to_string(), "bad_driver.sys");
    assert_eq!(row.cells[idx("caused_by_address")].to_string(), "bad_driver.sys+0x500");
    assert_eq!(row.cells[idx("architecture")].to_string(), "x64 (AMD64)");
    assert!(row.detail_json.is_some());
    assert_eq!(row.raw_bytes.as_ref().unwrap().len(), 2168);

    // GuapQuery filter on hex column
    let filtered = QueryHelper::query_provider(
        &provider,
        None,
        Some(r#"bugcheck_code = "0x0000003b" && caused_by_driver contains "bad_driver""#),
        None,
        0,
        None,
    )
    .unwrap();
    assert_eq!(filtered.total_rows, 1);
}

#[test]
fn bsod_param_heuristic_skips_ntoskrnl_to_blame_driver_and_unloaded_fallback() {
    // Mutate Fixture 1 so ExceptionCode=0xD1 (DRIVER_IRQL_NOT_LESS_OR_EQUAL),
    // ExceptionAddress is inside ntoskrnl.exe, and Param4 points into bad_driver.sys.
    let mut bytes = build_kernel_bsod_x64_mdmp();
    write_u32(&mut bytes, 0x00A0 + 0x08, 0x0000_00D1);
    write_u64(&mut bytes, 0x00A0 + 0x18, 0xFFFF_F801_0000_5000); // ntoskrnl.exe+0x5000
    write_u64(&mut bytes, 0x00A0 + 0x28 + 3 * 8, 0xFFFF_F801_1234_0880); // Param4 -> bad_driver.sys+0x880
    write_u64(&mut bytes, 0x0368 + 0xF8, 0xFFFF_F801_0000_5000); // Rip in ntoskrnl.exe

    let dump = MinidumpFile::from_bytes(&bytes).unwrap();
    let frames = walk_stack(&dump, false);
    let attr = attribute_fault_module(&dump, &frames, false);
    assert_eq!(attr.module_name.as_deref(), Some("bad_driver.sys"));
    assert_eq!(attr.caused_by_address.as_deref(), Some("bad_driver.sys+0x880"));

    // Now also test UnloadedModuleListStream fallback when ExceptionAddress lands in unloaded_drv.sys
    let mut unloaded_bytes = build_kernel_bsod_x64_mdmp();
    write_u64(&mut unloaded_bytes, 0x00A0 + 0x18, 0xFFFF_F801_2000_0400); // unloaded_drv.sys+0x400
    write_u64(&mut unloaded_bytes, 0x00A0 + 0x28 + 8, 0);
    write_u64(&mut unloaded_bytes, 0x0368 + 0xF8, 0xFFFF_F801_2000_0400);
    // Clear stack scan hit in bad_driver.sys
    write_u64(&mut unloaded_bytes, 0x0838 + 0x08, 0);
    let dump2 = MinidumpFile::from_bytes(&unloaded_bytes).unwrap();
    let frames2 = walk_stack(&dump2, false);
    let attr2 = attribute_fault_module(&dump2, &frames2, false);
    assert!(attr2.unloaded);
    assert_eq!(attr2.module_name.as_deref(), Some("unloaded_drv.sys"));
    assert_eq!(
        attr2.caused_by_address.as_deref(),
        Some("<unloaded> unloaded_drv.sys+0x400")
    );
}

#[test]
fn mdmp_memory64_and_comments_and_legacy_bugcheck_normalization() {
    assert_eq!(normalize_bugcheck_code(0x1000_007E), 0x0000_007E);
    assert_eq!(bugcheck_name(0x1000_007E), Some("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED"));
    assert_eq!(lookup_exception_name(0xC000_0005), Some("ACCESS_VIOLATION"));

    // Build a minimal MDMP using Memory64ListStream (9), CommentStreamA (10), CommentStreamW (11)
    let mut buf = Vec::new();
    push_u32(&mut buf, MDMP_SIGNATURE);
    push_u32(&mut buf, MINIDUMP_VERSION);
    push_u32(&mut buf, 3);
    push_u32(&mut buf, 32);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 1_732_350_200);
    push_u64(&mut buf, 0);

    let dir_off = buf.len();
    buf.resize(dir_off + 3 * 12, 0);

    let mem64_rva = buf.len() as u32;
    push_u64(&mut buf, 1); // NumberOfMemoryRanges
    let base_rva_patch = buf.len();
    push_u64(&mut buf, 0);
    push_u64(&mut buf, 0x0000_7FF0_0000_1000);
    push_u64(&mut buf, 8);
    let mem64_size = (buf.len() as u32) - mem64_rva;

    let ca_rva = buf.len() as u32;
    buf.extend_from_slice(b"ascii comment\0");
    let ca_size = (buf.len() as u32) - ca_rva;

    let cw_rva = buf.len() as u32;
    for u in "utf16 comment".encode_utf16() {
        push_u16(&mut buf, u);
    }
    push_u16(&mut buf, 0);
    let cw_size = (buf.len() as u32) - cw_rva;

    let mem_payload_rva = buf.len() as u64;
    push_u64(&mut buf, 0xCAFE_BABE_1234_5678);
    write_u64(&mut buf, base_rva_patch, mem_payload_rva);

    let entries = [
        (stream_type::MEMORY64_LIST, mem64_size, mem64_rva),
        (stream_type::COMMENT_A, ca_size, ca_rva),
        (stream_type::COMMENT_W, cw_size, cw_rva),
    ];
    for (i, (st, sz, rva)) in entries.into_iter().enumerate() {
        write_u32(&mut buf, dir_off + i * 12, st);
        write_u32(&mut buf, dir_off + i * 12 + 4, sz);
        write_u32(&mut buf, dir_off + i * 12 + 8, rva);
    }

    let dump = MinidumpFile::from_bytes(&buf).unwrap();
    assert!(dump.exception.is_none());
    assert_eq!(dump.read_va_u64(0x0000_7FF0_0000_1000), Some(0xCAFE_BABE_1234_5678));
    assert_eq!(dump.comments, vec!["ascii comment", "utf16 comment"]);
}

#[test]
fn usermode_x86_mdmp_and_pe32_pe64_exports_resolve_symbols() {
    let dir = tempfile::tempdir().unwrap();
    let dll_path = dir.path().join("faulting.dll");
    std::fs::write(&dll_path, build_synthetic_pe32_dll()).unwrap();

    // Direct PE32 + PE32+ unit checks
    let pe32 = PeImageExports::from_path(&dll_path).unwrap();
    assert!(!pe32.is_pe64);
    let m32 = pe32.resolve_rva(0x1020).unwrap();
    assert_eq!(m32.format_symbol("faulting.dll"), "faulting.dll!CrashHere+0x20");

    let pe64 = PeImageExports::from_bytes(&build_synthetic_pe64_dll()).unwrap();
    assert!(pe64.is_pe64);
    assert_eq!(pe64.exports.len(), 2);
    assert_eq!(
        pe64.resolve_rva(0x1040).unwrap().format_symbol("x64.dll"),
        "x64.dll!RealExport"
    );
    // Forwarder export should be skipped by resolve_rva
    assert_eq!(
        pe64.exports
            .iter()
            .find(|e| e.name == "FwdExport")
            .unwrap()
            .forwarder
            .as_deref(),
        Some("NTDLL.RtlAllocHeap")
    );

    let dmp_path = dir.path().join("demo.dmp");
    let dmp_bytes = build_usermode_x86_mdmp(&dll_path.display().to_string());
    std::fs::write(&dmp_path, &dmp_bytes).unwrap();

    let provider = CrashReportProvider::new(ForensicSource::OfflinePath(dmp_path));
    assert!(provider.is_read_only());
    let data = provider.query(&TableQuery::default()).unwrap();
    assert_eq!(data.total_rows, 1);

    let schema = provider.schema();
    let idx = |name: &str| schema.column_index(name).unwrap();
    let row = &data.rows[0];

    assert_eq!(row.cells[idx("process_name")].to_string(), "demo.exe");
    assert_eq!(row.cells[idx("process_id")].to_string(), "4242");
    assert_eq!(row.cells[idx("thread_id")].to_string(), "1365"); // 0x0555
    assert_eq!(row.cells[idx("exception_code")].to_string(), "0xc0000005");
    assert!(
        row.cells[idx("exception_desc")]
            .to_string()
            .contains("ACCESS_VIOLATION")
    );
    assert_eq!(row.cells[idx("fault_module")].to_string(), "faulting.dll");
    assert_eq!(
        row.cells[idx("fault_symbol")].to_string(),
        "faulting.dll!CrashHere+0x20"
    );
    assert!(row.cells[idx("registers")].to_string().contains("EIP=0x10001020"));
    let cs = row.cells[idx("call_stack_frames")].to_string();
    assert!(cs.contains("faulting.dll!CrashHere+0x20"));
    assert!(cs.contains("demo.exe+0x1200"));
    assert!(cs.contains("demo.exe+0x1050"));
    assert_eq!(row.cells[idx("architecture")].to_string(), "x86 (INTEL)");
    assert!(row.detail_json.is_some());
    assert!(row.raw_bytes.is_some());
}

#[test]
fn mdmp_malformed_truncated_pagedump_and_overflow_guards() {
    // Short / empty
    assert!(matches!(
        MinidumpFile::from_bytes(b""),
        Err(ForensicError::Parse { .. })
    ));
    assert!(matches!(
        MinidumpFile::from_bytes(b"MDMP"),
        Err(ForensicError::Parse { .. })
    ));

    // PAGEDUMP / PAGEDU64 -> UnsupportedPlatform
    let mut paged = b"PAGEDU64".to_vec();
    paged.resize(64, 0);
    assert!(matches!(
        MinidumpFile::from_bytes(&paged),
        Err(ForensicError::UnsupportedPlatform { .. })
    ));

    // Directory overflow (NumberOfStreams = 0xFFFF_FFFF)
    let mut oob = build_kernel_bsod_x64_mdmp();
    write_u32(&mut oob, 0x08, 0xFFFF_FFFF);
    assert!(matches!(
        MinidumpFile::from_bytes(&oob),
        Err(ForensicError::Parse { .. })
    ));

    // Overflowed MINIDUMP_STRING Length = 0xFFFF_FFFF
    let mut bad_str = build_kernel_bsod_x64_mdmp();
    write_u32(&mut bad_str, 0x029A, 0xFFFF_FFFF);
    assert!(matches!(
        MinidumpFile::from_bytes(&bad_str),
        Err(ForensicError::Parse { .. })
    ));

    // Arm64 CONTEXT truncated
    assert!(matches!(
        CpuContext::parse(ProcessorArch::Arm64, &[0u8; 32]),
        Err(ForensicError::Parse { .. })
    ));
    // Valid Arm64 CONTEXT minimum slice
    let mut arm64_ctx = vec![0u8; CpuContext::MIN_ARM64_GPR_SIZE];
    write_u64(&mut arm64_ctx, 0x100, 0x0000_0010_0000_8000); // Sp
    write_u64(&mut arm64_ctx, 0x108, 0x0000_7FF8_1234_0010); // Pc
    let parsed_arm64 = CpuContext::parse(ProcessorArch::Arm64, &arm64_ctx).unwrap();
    assert_eq!(parsed_arm64.sp(), Some(0x0000_0010_0000_8000));
    assert_eq!(parsed_arm64.ip(), Some(0x0000_7FF8_1234_0010));
}

#[test]
fn wer_parses_utf16le_bom_nobom_utf16be_and_utf8_with_appcrash_and_moappcrash() {
    let dt = DateTime::parse_from_rfc3339("2026-10-15T14:30:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let ft = utc_to_filetime(dt).unwrap();

    let appcrash_text = format!(
        "Version=1\r\n\
         EventType=APPCRASH\r\n\
         FriendlyEventName=Stopped working\r\n\
         Consent=1\r\n\
         ReportType=2\r\n\
         EventTime={ft}\r\n\
         ReportIdentifier=11223344-5566-7788-99aa-bbccddeeff00\r\n\
         AppPath=C:\\Program Files\\Demo\\app.exe\r\n\
         NsAppName=app.exe\r\n\
         Sig[0].Name=Application Name\r\n\
         Sig[0].Value=app.exe\r\n\
         Sig[1].Name=Application Version\r\n\
         Sig[1].Value=2.4.0.1\r\n\
         Sig[3].Name=Fault Module Name\r\n\
         Sig[3].Value=ucrtbase.dll\r\n\
         Sig[4].Name=Fault Module Version\r\n\
         Sig[4].Value=10.0.22621.2506\r\n\
         Sig[6].Name=Exception Code\r\n\
         Sig[6].Value=c0000005\r\n\
         Sig[7].Name=Exception Offset\r\n\
         Sig[7].Value=000000000007e340\r\n\
         DynamicSig[0].Name=OS Version\r\n\
         DynamicSig[0].Value=10.0.22631.2.0.0.256.48\r\n\
         LoadedModule[0]=C:\\Program Files\\Demo\\app.exe\r\n\
         UI[2]=C:\\Program Files\\Demo\\app.exe\r\n\
         State[0].Key=Transport.DoneStage1\r\n\
         State[0].Value=1\r\n\
         Response.BucketId=abcdef0123456789\r\n"
    );

    // 1. UTF-16LE with BOM + CRLF
    let le_bom = encode_utf16le(&appcrash_text, true);
    let r1 = WerReport::from_bytes(&le_bom, "Report.wer").unwrap();
    assert_eq!(r1.encoding, WerEncoding::Utf16LeBom);
    assert_eq!(r1.event_time, Some(dt));
    assert_eq!(r1.event_type.as_deref(), Some("APPCRASH"));
    assert_eq!(r1.app_name.as_deref(), Some("app.exe"));
    assert_eq!(r1.fault_module.as_deref(), Some("ucrtbase.dll"));
    assert_eq!(r1.exception_code.as_deref(), Some("0xc0000005"));
    assert_eq!(r1.exception_offset.as_deref(), Some("0x000000000007e340"));
    assert_eq!(r1.os_version.as_deref(), Some("10.0.22631.2.0.0.256.48"));
    assert_eq!(
        r1.response.get("BucketId").map(String::as_str),
        Some("abcdef0123456789")
    );

    // 2. UTF-16LE without BOM + LF + '=' inside value
    let nobom_text = "Version=1\nEventType=APPCRASH\nAppPath=C:\\x.exe?a=1&b=2\nSig[0].Value=x.exe\nSig[3].Value=ntdll.dll\nSig[6].Value=c0000409\nSig[7].Value=00010020\n";
    let le_nobom = encode_utf16le(nobom_text, false);
    let r2 = WerReport::from_bytes(&le_nobom, "nobom.wer").unwrap();
    assert_eq!(r2.encoding, WerEncoding::Utf16LeNoBom);
    assert_eq!(r2.app_path.as_deref(), Some("C:\\x.exe?a=1&b=2"));
    assert_eq!(r2.fault_module.as_deref(), Some("ntdll.dll"));
    assert_eq!(r2.exception_code.as_deref(), Some("0xc0000409"));

    // 3. UTF-16BE with BOM
    let be_bom = encode_utf16be("Version=1\nEventType=BEX64\nAppName=be.exe\n", true);
    let r3 = WerReport::from_bytes(&be_bom, "be.wer").unwrap();
    assert_eq!(r3.encoding, WerEncoding::Utf16BeBom);
    assert_eq!(r3.app_name.as_deref(), Some("be.exe"));

    // 4. UTF-8 with BOM + MoAppCrash positional + hex EventTime
    let mut utf8_bom = vec![0xEF, 0xBB, 0xBF];
    let hex_ft = format!("0x{ft:016x}");
    let moapp = format!(
        "[Header]\n\
         Version=1\n\
         EventType=MoAppCrash\n\
         EventTime={hex_ft}\n\
         Sig[0].Value=Contoso.App_1.0_x64\n\
         Sig[1].Value=uwp.exe\n\
         Sig[4].Value=Windows.UI.Xaml.dll\n\
         Sig[5].Value=10.0.22621.1\n\
         Sig[7].Value=c000027b\n\
         Sig[8].Value=0000000000123456\n\
         OsInfo[0].Key=ProductName\n\
         OsInfo[0].Value=Windows 11 Pro\n\
         OsInfo[1].Key=BuildString\n\
         OsInfo[1].Value=22631.1\n"
    );
    utf8_bom.extend_from_slice(moapp.as_bytes());
    let r4 = WerReport::from_bytes(&utf8_bom, "moapp.wer").unwrap();
    assert_eq!(r4.encoding, WerEncoding::Utf8Bom);
    assert_eq!(r4.event_time, Some(dt));
    assert_eq!(r4.app_name.as_deref(), Some("uwp.exe"));
    assert_eq!(r4.fault_module.as_deref(), Some("Windows.UI.Xaml.dll"));
    assert_eq!(r4.exception_code.as_deref(), Some("0xc000027b"));
    assert_eq!(r4.os_version.as_deref(), Some("Windows 11 Pro (22631.1)"));

    // 5. Hex without 0x prefix
    assert_eq!(parse_wer_filetime(&format!("{ft:016x}")), Some(dt));

    // 6. Malformed/empty Report.wer -> Parse error
    assert!(matches!(
        WerReport::from_bytes(b"", "empty.wer"),
        Err(ForensicError::Parse { .. })
    ));
    assert!(matches!(
        WerReport::from_bytes(b"not valid ini at all", "bad.wer"),
        Err(ForensicError::Parse { .. })
    ));
}

#[test]
fn directory_discovery_query_helper_and_graceful_live_handling() {
    let dir = tempfile::tempdir().unwrap();
    let wer_dir = dir.path().join("ReportArchive").join("AppCrash_demo_1");
    let minidump_dir = dir.path().join("Minidumps");
    let user_dir = dir.path().join("UserDumps");
    std::fs::create_dir_all(&wer_dir).unwrap();
    std::fs::create_dir_all(&minidump_dir).unwrap();
    std::fs::create_dir_all(&user_dir).unwrap();

    // Write valid Report.wer + corrupt .wer
    let wer_bytes = encode_utf16le("Version=1\r\nEventType=APPCRASH\r\nAppName=calc.exe\r\n", true);
    std::fs::write(wer_dir.join("Report.wer"), &wer_bytes).unwrap();
    std::fs::write(wer_dir.join("bad.wer"), b"garbage_no_equals").unwrap();

    // Write valid kernel MDMP + PAGEDU64 MEMORY.DMP in Minidumps
    std::fs::write(minidump_dir.join("crash1.dmp"), build_kernel_bsod_x64_mdmp()).unwrap();
    let mut paged = b"PAGEDU64".to_vec();
    paged.resize(64, 0);
    std::fs::write(minidump_dir.join("MEMORY.DMP"), &paged).unwrap();

    // Write user-mode MDMP
    let dll_path = user_dir.join("faulting.dll");
    std::fs::write(&dll_path, build_synthetic_pe32_dll()).unwrap();
    std::fs::write(
        user_dir.join("app.dmp"),
        build_usermode_x86_mdmp(&dll_path.display().to_string()),
    )
    .unwrap();

    // Directory walk on crash.wer collects Report.wer and skips bad.wer with a warning
    let wer_provider = CrashWerProvider::new(ForensicSource::OfflinePath(dir.path().to_path_buf()));
    let (wer_rows, wer_warnings) = wer_provider.collect_with_diagnostics().unwrap();
    assert_eq!(wer_rows.len(), 1);
    assert_eq!(wer_warnings.len(), 1);

    // QueryHelper filtering/projection/pagination on crash.wer
    let projected: TableData = QueryHelper::query_provider(
        &wer_provider,
        Some(vec!["app_name".to_string(), "event_type".to_string()]),
        Some(r#"event_type = "APPCRASH""#),
        Some("-app_name"),
        0,
        Some(10),
    )
    .unwrap();
    assert_eq!(projected.total_rows, 1);
    assert_eq!(projected.schema.columns.len(), 2);
    assert_eq!(projected.rows[0].cells[0].to_string(), "calc.exe");

    // Directory walk on crash.bsod parses valid MDMPs and skips PAGEDU64 with Info warning
    let bsod_provider = CrashBsodProvider::new(ForensicSource::OfflinePath(minidump_dir));
    let (bsod_rows, bsod_warnings) = bsod_provider.collect_with_diagnostics().unwrap();
    assert_eq!(bsod_rows.len(), 1);
    assert_eq!(bsod_warnings.len(), 1);
    assert_eq!(bsod_warnings[0].severity, WarningSeverity::Info);

    // Single-file PAGEDU64 returns UnsupportedPlatform
    let single_paged = CrashBsodProvider::new(ForensicSource::OfflineBytes(paged));
    assert!(matches!(
        single_paged.collect_with_diagnostics(),
        Err(ForensicError::UnsupportedPlatform { .. })
    ));

    // Missing OfflinePath -> TableError::Provider containing "not found"
    let missing_path = dir.path().join("does_not_exist.dmp");
    let missing_provider = CrashBsodProvider::new(ForensicSource::OfflinePath(missing_path));
    let err = missing_provider.query(&TableQuery::default()).unwrap_err();
    match err {
        TableError::Provider(msg) => assert!(msg.to_ascii_lowercase().contains("not found"), "got: {msg}"),
        other => panic!("expected TableError::Provider, got {other:?}"),
    }

    // Simulated absent Live roots -> Ok(0 items) with Info warnings
    let absent_roots = vec![
        LiveRootSpec::dir(PathBuf::from(r"Z:\definitely_nonexistent_minidump_dir_12345")),
        LiveRootSpec::file(PathBuf::from(r"Z:\definitely_nonexistent_memory_12345.dmp")),
    ];
    let live_res = discover_from_live_roots(&absent_roots, "crash.bsod", is_dmp_file).unwrap();
    assert!(live_res.items.is_empty());
    assert_eq!(live_res.warnings.len(), 2);
    assert!(live_res.warnings.iter().all(|w| w.severity == WarningSeverity::Info));

    // Actual ForensicSource::Live query across all 3 providers never panics
    for p in default_providers() {
        let _ = p.query(&TableQuery::default());
    }
}

#[test]
fn crate_exports_all_providers_read_only_and_r4_compliance() {
    assert_eq!(crate_info().0, "forensics2rust-crash");
    assert_eq!(domain_tools().len(), 3);

    let providers = all_providers(&ForensicSource::Live);
    assert_eq!(providers.len(), 3);
    let ids: Vec<&str> = providers.iter().map(|p| p.tool_id()).collect();
    assert_eq!(ids, vec!["crash.bsod", "crash.wer", "crash.report"]);

    for p in &providers {
        assert!(p.is_read_only(), "provider {} must be read-only", p.tool_id());
        assert!(provider_for_tool(p.tool_id(), &ForensicSource::Live).is_some());
    }
    assert!(provider_for_tool("crash.nonexistent", &ForensicSource::Live).is_none());

    // Verify zero R4 exclusions across crate sources and catalog descriptions
    let forbidden: &[&str] = &[
        concat!("dr", "watson"),
        concat!("dr", "wtsn32"),
        concat!("cred", "2rust"),
        concat!("Create", "RemoteThread"),
        concat!("SetWindows", "HookEx"),
        concat!("Cred", "Enumerate"),
        concat!("CryptUnprotect", "Data"),
        concat!("LsaRetrieve", "PrivateData"),
        concat!("VaultEnumerate", "Items"),
    ];

    let unsafe_marker = concat!("unsafe", " {");
    let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in std::fs::read_dir(&src_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let content = std::fs::read_to_string(&path).unwrap();
            let lower = content.to_ascii_lowercase();
            assert!(
                !lower.contains(unsafe_marker),
                "unsafe block found in {}",
                path.display()
            );
            for bad in forbidden {
                assert!(
                    !lower.contains(&bad.to_ascii_lowercase()),
                    "R4 forbidden pattern '{bad}' found in {}",
                    path.display()
                );
            }
        }
    }

    for tool in FORENSIC_TOOL_CATALOG
        .iter()
        .filter(|t| t.category == ToolCategory::Crash)
    {
        assert!(tool.read_only);
        assert!(tool.supports_offline);
    }
}

#[test]
fn codeview_rsds_unsupported_arch_and_pe_error_paths() {
    // Unsupported CPU context falls back gracefully without panicking
    let unk_ctx = CpuContext::parse(ProcessorArch::Unknown(99), &[1, 2, 3, 4]).unwrap();
    assert!(matches!(unk_ctx, CpuContext::Unsupported { data_size: 4, .. }));
    assert!(unk_ctx.summary_string().contains("unsupported CONTEXT"));

    // Malformed PE checks
    assert!(matches!(
        PeImageExports::from_bytes(b"short"),
        Err(ForensicError::Parse { .. })
    ));
    let mut bad_pe = vec![0u8; 128];
    write_u16(&mut bad_pe, 0, 0x5A4D);
    write_u32(&mut bad_pe, 0x3C, 64);
    assert!(matches!(
        PeImageExports::from_bytes(&bad_pe),
        Err(ForensicError::Parse { .. })
    ));

    // Minimal MDMP with ModuleListStream containing a CodeView RSDS record
    let mut buf = Vec::new();
    push_u32(&mut buf, MDMP_SIGNATURE);
    push_u32(&mut buf, MINIDUMP_VERSION);
    push_u32(&mut buf, 1);
    push_u32(&mut buf, 32);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 1_732_350_300);
    push_u64(&mut buf, 0);

    let dir_off = buf.len();
    buf.resize(dir_off + 12, 0);

    let mod_rva = buf.len() as u32;
    push_u32(&mut buf, 1);
    let mod_name_patch = buf.len() + 0x14;
    let cv_patch = buf.len() + 0x4C;
    append_module_entry(&mut buf, 0x7FF7_0000_0000, 0x1_0000, 0, 0, 0, 0, 0, 0, 0);
    let mod_size = (buf.len() as u32) - mod_rva;

    let name_rva = buf.len() as u32;
    buf.extend_from_slice(&encode_minidump_string(r"C:\app\widget.exe"));

    let cv_rva = buf.len() as u32;
    buf.extend_from_slice(b"RSDS");
    buf.extend_from_slice(&[0x11u8; 16]);
    push_u32(&mut buf, 7);
    buf.extend_from_slice(b"widget.pdb\0");
    let cv_size = (buf.len() as u32) - cv_rva;

    write_u32(&mut buf, mod_name_patch, name_rva);
    write_u32(&mut buf, cv_patch, cv_size);
    write_u32(&mut buf, cv_patch + 4, cv_rva);
    write_u32(&mut buf, dir_off, stream_type::MODULE_LIST);
    write_u32(&mut buf, dir_off + 4, mod_size);
    write_u32(&mut buf, dir_off + 8, mod_rva);

    let dump = MinidumpFile::from_bytes(&buf).unwrap();
    let cv = dump.modules[0].codeview.as_ref().unwrap();
    assert_eq!(cv.signature, "RSDS");
    assert_eq!(cv.age, Some(7));
    assert_eq!(cv.pdb_name, "widget.pdb");
    assert!(cv.guid.is_some());
}

#[test]
fn discovery_header_peek_skips_oversized_pagedump_and_non_mdmp_without_reading_body() {
    use std::io::Write;

    let dir = tempfile::tempdir().unwrap();
    let mem_dmp = dir.path().join("MEMORY.DMP");
    {
        let mut f = std::fs::File::create(&mem_dmp).unwrap();
        f.write_all(b"PAGEDU64").unwrap();
        // 8 GiB logical file size: std::fs::read would OOM/fail, 8-byte peek handles it instantly.
        f.set_len(8 * 1024 * 1024 * 1024).unwrap();
    }

    // 1. Single-file OfflinePath(MEMORY.DMP) rejects via header peek -> UnsupportedPlatform
    let single_provider = CrashBsodProvider::new(ForensicSource::OfflinePath(mem_dmp.clone()));
    assert!(matches!(
        single_provider.collect_with_diagnostics(),
        Err(ForensicError::UnsupportedPlatform { .. })
    ));

    // 2. LiveRootSpec::file(MEMORY.DMP) skips via header peek with Info warning
    let live_res = discover_from_live_roots(&[LiveRootSpec::file(mem_dmp)], "crash.bsod", is_dmp_file).unwrap();
    assert!(live_res.items.is_empty());
    assert_eq!(live_res.warnings.len(), 1);
    assert_eq!(live_res.warnings[0].severity, WarningSeverity::Info);

    // 3. Directory scan skips oversized PAGEDUMP + oversized non-MDMP and still parses valid MDMP
    let paged32 = dir.path().join("MEMORY32.DMP");
    {
        let mut f = std::fs::File::create(&paged32).unwrap();
        f.write_all(b"PAGEDUMP").unwrap();
        f.set_len(8 * 1024 * 1024 * 1024).unwrap();
    }
    let garbage_dmp = dir.path().join("huge_blob.dmp");
    {
        let mut f = std::fs::File::create(&garbage_dmp).unwrap();
        f.write_all(b"NOTMDMP!").unwrap();
        f.set_len(8 * 1024 * 1024 * 1024).unwrap();
    }
    std::fs::write(dir.path().join("valid.dmp"), build_kernel_bsod_x64_mdmp()).unwrap();

    let dir_provider = CrashBsodProvider::new(ForensicSource::OfflinePath(dir.path().to_path_buf()));
    let (rows, warnings) = dir_provider.collect_with_diagnostics().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(warnings.len(), 3);
    assert_eq!(
        warnings.iter().filter(|w| w.severity == WarningSeverity::Info).count(),
        2
    );
    assert_eq!(
        warnings.iter().filter(|w| w.severity == WarningSeverity::Warn).count(),
        1
    );
}

#[test]
fn wer_localized_sig_names_and_clr20r3_apphang_and_encoding_window() {
    // 1. German localized APPCRASH Report.wer without AppName/NsAppName
    let german_appcrash = "\
Version=1\r\n\
EventType=APPCRASH\r\n\
Sig[0].Name=Anwendungsname\r\n\
Sig[0].Value=rechner.exe\r\n\
Sig[1].Name=Anwendungsversion\r\n\
Sig[1].Value=10.1.2.3\r\n\
Sig[3].Name=Fehlermodulname\r\n\
Sig[3].Value=ntdll.dll\r\n\
Sig[4].Name=Fehlermodulversion\r\n\
Sig[4].Value=10.0.22621.1\r\n\
Sig[6].Name=Ausnahmecode\r\n\
Sig[6].Value=c0000005\r\n\
Sig[7].Name=Ausnahmeoffset\r\n\
Sig[7].Value=0000000000054321\r\n\
LoadedModule[0]=\r\n";

    let r_de = WerReport::from_bytes(german_appcrash.as_bytes(), "de_Report.wer").unwrap();
    assert_eq!(r_de.app_name.as_deref(), Some("rechner.exe"));
    assert_eq!(r_de.app_version.as_deref(), Some("10.1.2.3"));
    assert_eq!(r_de.fault_module.as_deref(), Some("ntdll.dll"));
    assert_eq!(r_de.fault_module_version.as_deref(), Some("10.0.22621.1"));
    assert_eq!(r_de.exception_code.as_deref(), Some("0xc0000005"));
    assert_eq!(r_de.exception_offset.as_deref(), Some("0x0000000000054321"));
    // Empty LoadedModule[0] must be skipped so app_path falls back to app_name
    assert_eq!(r_de.app_path.as_deref(), Some("rechner.exe"));

    // 2. French localized MoAppCrash
    let french_moapp = "\
Version=1\n\
EventType=MoAppCrash\n\
Sig[0].Name=Nom complet du package\n\
Sig[0].Value=Contoso.App_1.0\n\
Sig[1].Name=Nom de l'application\n\
Sig[1].Value=prax:app.exe\n\
Sig[2].Name=Version de l'application\n\
Sig[2].Value=3.2.1.0\n\
Sig[4].Name=Nom du module défaillant\n\
Sig[4].Value=Windows.UI.dll\n\
Sig[5].Name=Version du module défaillant\n\
Sig[5].Value=10.0.22621.99\n\
Sig[7].Name=Code de l'exception\n\
Sig[7].Value=c000027b\n\
Sig[8].Name=Décalage de l'exception\n\
Sig[8].Value=00000000000abcde\n";

    let r_fr = WerReport::from_bytes(french_moapp.as_bytes(), "fr_Report.wer").unwrap();
    assert_eq!(r_fr.app_name.as_deref(), Some("prax:app.exe"));
    assert_eq!(r_fr.app_version.as_deref(), Some("3.2.1.0"));
    assert_eq!(r_fr.fault_module.as_deref(), Some("Windows.UI.dll"));
    assert_eq!(r_fr.fault_module_version.as_deref(), Some("10.0.22621.99"));
    assert_eq!(r_fr.exception_code.as_deref(), Some("0xc000027b"));
    assert_eq!(r_fr.exception_offset.as_deref(), Some("0x00000000000abcde"));

    // 3. CLR20r3 Problem Signature 01..09
    let clr20r3 = "\
Version=1\r\n\
EventType=CLR20r3\r\n\
Sig[0].Name=Problem Signature 01\r\n\
Sig[0].Value=WorkerHost.exe\r\n\
Sig[1].Name=Problem Signature 02\r\n\
Sig[1].Value=4.8.1.0\r\n\
Sig[3].Name=Problem Signature 04\r\n\
Sig[3].Value=MyBusinessLogic\r\n\
Sig[8].Name=Problem Signature 09\r\n\
Sig[8].Value=System.NullReferenceException\r\n";

    let r_clr = WerReport::from_bytes(clr20r3.as_bytes(), "clr.wer").unwrap();
    assert_eq!(r_clr.app_name.as_deref(), Some("WorkerHost.exe"));
    assert_eq!(r_clr.app_version.as_deref(), Some("4.8.1.0"));
    assert_eq!(r_clr.fault_module.as_deref(), Some("MyBusinessLogic"));
    assert_eq!(r_clr.exception_code.as_deref(), Some("System.NullReferenceException"));

    // 4. Positional AppHangB1
    let apphang = "\
Version=1\r\n\
EventType=AppHangB1\r\n\
Sig[0].Value=frozen.exe\r\n\
Sig[1].Value=2.0.0.1\r\n\
Sig[3].Value=128\r\n";
    let r_hang = WerReport::from_bytes(apphang.as_bytes(), "hang.wer").unwrap();
    assert_eq!(r_hang.app_name.as_deref(), Some("frozen.exe"));
    assert_eq!(r_hang.app_version.as_deref(), Some("2.0.0.1"));
    assert_eq!(r_hang.fault_module, None);

    // 5. No-BOM UTF-16LE with >128 non-ASCII chars in leading comment followed by ASCII keys (2048B window)
    let cjk_prefix = format!(
        "; {}\r\nVersion=1\r\nEventType=APPCRASH\r\nAppName=cjk_window.exe\r\nAppPath=C:\\Tools\\CJK\\cjk_window_application_binary.exe\r\nFriendlyEventName=Stopped working unexpectedly during test\r\nReportIdentifier=00112233-4455-6677-8899-aabbccddeeff\r\n",
        "あ".repeat(150)
    );
    let cjk_bytes = encode_utf16le(&cjk_prefix, false);
    let r_cjk = WerReport::from_bytes(&cjk_bytes, "cjk.wer").unwrap();
    assert_eq!(r_cjk.encoding, WerEncoding::Utf16LeNoBom);
    assert_eq!(r_cjk.app_name.as_deref(), Some("cjk_window.exe"));
}

#[test]
fn mdmp_rva_inside_header_pe_oob_slot_continue_and_exe_module_selection() {
    // 1. MINIDUMP_DIRECTORY stream with rva < 32 and data_size > 0 -> Parse error
    let mut bad_rva = build_kernel_bsod_x64_mdmp();
    write_u32(&mut bad_rva, 0x20 + 8, 0); // SystemInfoStream.Rva = 0 (< 32)
    assert!(matches!(
        MinidumpFile::from_bytes(&bad_rva),
        Err(ForensicError::Parse { .. })
    ));

    // 2. PE with one OOB AddressOfFunctions slot continues to parse subsequent valid exports
    let mut pe = build_synthetic_pe64_dll();
    // Slot 0 (RealExport): point ord_idx 0 -> 5000 (past EOF while num_functions = 6000),
    // and keep Slot 1 pointing to RealExport/ValidExport at ord_idx 0? Let's swap:
    // Make Name[0] ("RealExport") use ord_idx = 5000 (OOB in AddressOfFunctions),
    // and Name[1] ("FwdExport") use ord_idx = 0 (RVA 0x1040, valid non-forwarded!).
    write_u32(&mut pe, 0x300 + 0x14, 6000); // NumberOfFunctions = 6000
    write_u16(&mut pe, 0x340, 5000); // Name[0] -> ord_idx 5000 (func_pos OOB)
    write_u16(&mut pe, 0x342, 0); // Name[1] -> ord_idx 0 (RVA 0x1040)
    let parsed_pe = PeImageExports::from_bytes(&pe).unwrap();
    assert_eq!(parsed_pe.exports.len(), 1);
    assert_eq!(parsed_pe.exports[0].name, "FwdExport");
    assert_eq!(parsed_pe.exports[0].rva, 0x1040);

    // 3. CrashReportProvider prefers .exe module over earlier DLL module, and PE cache caches per module
    let dir = tempfile::tempdir().unwrap();
    let dll_path = dir.path().join("cached.dll");
    std::fs::write(&dll_path, build_synthetic_pe32_dll()).unwrap();
    let dll_str = dll_path.display().to_string();
    let mut pe_cache = std::collections::HashMap::new();
    assert_eq!(
        crate::pe::resolve_va_with_cache(&mut pe_cache, &dll_str, 0x1000_0000, 0x1000_1020).as_deref(),
        Some("cached.dll!CrashHere+0x20")
    );
    // Remove DLL on disk to prove the second lookup hits the in-memory cache rather than re-reading disk
    std::fs::remove_file(&dll_path).unwrap();
    assert_eq!(
        crate::pe::resolve_va_with_cache(&mut pe_cache, &dll_str, 0x1000_0000, 0x1000_1030).as_deref(),
        Some("cached.dll!CrashHere+0x30")
    );

    // Build a minimal user-mode MDMP where Module 0 is ntdll.dll and Module 1 is C:\app\MyCrasher.EXE.
    let mut buf = Vec::new();
    push_u32(&mut buf, MDMP_SIGNATURE);
    push_u32(&mut buf, MINIDUMP_VERSION);
    push_u32(&mut buf, 2);
    push_u32(&mut buf, 32);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 1_732_350_400);
    push_u64(&mut buf, 0);
    let dir_off = buf.len();
    buf.resize(dir_off + 2 * 12, 0);
    let sys_rva = buf.len() as u32;
    push_u16(&mut buf, 9);
    buf.resize(buf.len() + 54, 0);
    let mod_rva = buf.len() as u32;
    push_u32(&mut buf, 2);
    let m0_patch = buf.len() + 0x14;
    append_module_entry(&mut buf, 0x7FF9_0000_0000, 0x1_0000, 0, 0, 0, 0, 0, 0, 0);
    let m1_patch = buf.len() + 0x14;
    append_module_entry(&mut buf, 0x7FF7_0000_0000, 0x1_0000, 0, 0, 0, 0, 0, 0, 0);
    let mod_size = (buf.len() as u32) - mod_rva;
    let m0_name = buf.len() as u32;
    buf.extend_from_slice(&encode_minidump_string(r"C:\Windows\System32\ntdll.dll"));
    let m1_name = buf.len() as u32;
    buf.extend_from_slice(&encode_minidump_string(r"C:\app\MyCrasher.EXE"));
    write_u32(&mut buf, m0_patch, m0_name);
    write_u32(&mut buf, m1_patch, m1_name);
    write_u32(&mut buf, dir_off, stream_type::SYSTEM_INFO);
    write_u32(&mut buf, dir_off + 4, 56);
    write_u32(&mut buf, dir_off + 8, sys_rva);
    write_u32(&mut buf, dir_off + 12, stream_type::MODULE_LIST);
    write_u32(&mut buf, dir_off + 16, mod_size);
    write_u32(&mut buf, dir_off + 20, mod_rva);

    let report_provider = CrashReportProvider::new(ForensicSource::OfflineBytes(buf));
    let data = report_provider.query(&TableQuery::default()).unwrap();
    let schema = report_provider.schema();
    let row = &data.rows[0];
    assert_eq!(
        row.cells[schema.column_index("process_name").unwrap()].to_string(),
        "MyCrasher.EXE"
    );
    assert_eq!(
        row.cells[schema.column_index("process_path").unwrap()].to_string(),
        r"C:\app\MyCrasher.EXE"
    );
}
