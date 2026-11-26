use forensics2rust_core::ForensicError;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// `PROCESSOR_ARCHITECTURE` values from Windows `SystemInfoStream`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessorArch {
    X86,
    Arm,
    Ia64,
    Amd64,
    Arm64,
    Unknown(u16),
}

impl ProcessorArch {
    pub fn from_raw(raw: u16) -> Self {
        match raw {
            0 => Self::X86,
            5 => Self::Arm,
            6 => Self::Ia64,
            9 => Self::Amd64,
            12 => Self::Arm64,
            other => Self::Unknown(other),
        }
    }

    pub fn raw_value(self) -> u16 {
        match self {
            Self::X86 => 0,
            Self::Arm => 5,
            Self::Ia64 => 6,
            Self::Amd64 => 9,
            Self::Arm64 => 12,
            Self::Unknown(v) => v,
        }
    }

    pub fn display_name(self) -> String {
        match self {
            Self::X86 => "x86 (INTEL)".to_string(),
            Self::Arm => "ARM".to_string(),
            Self::Ia64 => "IA64".to_string(),
            Self::Amd64 => "x64 (AMD64)".to_string(),
            Self::Arm64 => "ARM64".to_string(),
            Self::Unknown(v) => format!("Unknown ({v})"),
        }
    }
}

/// Decoded x64 (`AMD64`) `CONTEXT` registers (`windows-0.62.2` `1232` B layout, min `256` B GPR slice).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X64Context {
    pub context_flags: u32,
    pub mx_csr: u32,
    pub seg_cs: u16,
    pub seg_ds: u16,
    pub seg_es: u16,
    pub seg_fs: u16,
    pub seg_gs: u16,
    pub seg_ss: u16,
    pub eflags: u32,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
}

/// Decoded x86 (`INTEL`) `CONTEXT` registers (`windows-0.62.2` `716` B layout, min `204` B GPR slice).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X86Context {
    pub context_flags: u32,
    pub seg_gs: u32,
    pub seg_fs: u32,
    pub seg_es: u32,
    pub seg_ds: u32,
    pub edi: u32,
    pub esi: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,
    pub ebp: u32,
    pub eip: u32,
    pub seg_cs: u32,
    pub eflags: u32,
    pub esp: u32,
    pub seg_ss: u32,
}

/// Decoded ARM64 `CONTEXT` registers (`windows-0.62.2` layout, min `272` B GPR slice).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arm64Context {
    pub context_flags: u32,
    pub cpsr: u32,
    pub x: [u64; 29],
    pub fp: u64,
    pub lr: u64,
    pub sp: u64,
    pub pc: u64,
}

/// Architecture-tagged CPU register context decoded from `MINIDUMP_THREAD.ThreadContext` or `ExceptionStream`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CpuContext {
    X64(X64Context),
    X86(X86Context),
    Arm64(Arm64Context),
    Unsupported { arch: ProcessorArch, data_size: usize },
}

fn read_u16_le(bytes: &[u8], off: usize) -> Result<u16, ForensicError> {
    let slice = bytes
        .get(off..off + 2)
        .ok_or_else(|| ForensicError::parse("CONTEXT", format!("truncated u16 at 0x{off:x}")))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(bytes: &[u8], off: usize) -> Result<u32, ForensicError> {
    let slice = bytes
        .get(off..off + 4)
        .ok_or_else(|| ForensicError::parse("CONTEXT", format!("truncated u32 at 0x{off:x}")))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64_le(bytes: &[u8], off: usize) -> Result<u64, ForensicError> {
    let slice = bytes
        .get(off..off + 8)
        .ok_or_else(|| ForensicError::parse("CONTEXT", format!("truncated u64 at 0x{off:x}")))?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

impl CpuContext {
    /// Minimum byte slice required to decode integer/control registers for each architecture.
    pub const MIN_X64_GPR_SIZE: usize = 0x100;
    pub const FULL_X64_SIZE: usize = 1232;
    pub const MIN_X86_GPR_SIZE: usize = 0x0CC;
    pub const FULL_X86_SIZE: usize = 716;
    pub const MIN_ARM64_GPR_SIZE: usize = 0x110;

    /// Parses a `ThreadContext` buffer according to `ProcessorArchitecture`.
    pub fn parse(arch: ProcessorArch, data: &[u8]) -> Result<Self, ForensicError> {
        match arch {
            ProcessorArch::Amd64 => {
                if data.len() < Self::MIN_X64_GPR_SIZE {
                    return Err(ForensicError::parse(
                        "x64 CONTEXT",
                        format!(
                            "buffer too short ({} bytes, minimum {} bytes)",
                            data.len(),
                            Self::MIN_X64_GPR_SIZE
                        ),
                    ));
                }
                Ok(Self::X64(X64Context {
                    context_flags: read_u32_le(data, 0x030)?,
                    mx_csr: read_u32_le(data, 0x034)?,
                    seg_cs: read_u16_le(data, 0x038)?,
                    seg_ds: read_u16_le(data, 0x03A)?,
                    seg_es: read_u16_le(data, 0x03C)?,
                    seg_fs: read_u16_le(data, 0x03E)?,
                    seg_gs: read_u16_le(data, 0x040)?,
                    seg_ss: read_u16_le(data, 0x042)?,
                    eflags: read_u32_le(data, 0x044)?,
                    rax: read_u64_le(data, 0x078)?,
                    rcx: read_u64_le(data, 0x080)?,
                    rdx: read_u64_le(data, 0x088)?,
                    rbx: read_u64_le(data, 0x090)?,
                    rsp: read_u64_le(data, 0x098)?,
                    rbp: read_u64_le(data, 0x0A0)?,
                    rsi: read_u64_le(data, 0x0A8)?,
                    rdi: read_u64_le(data, 0x0B0)?,
                    r8: read_u64_le(data, 0x0B8)?,
                    r9: read_u64_le(data, 0x0C0)?,
                    r10: read_u64_le(data, 0x0C8)?,
                    r11: read_u64_le(data, 0x0D0)?,
                    r12: read_u64_le(data, 0x0D8)?,
                    r13: read_u64_le(data, 0x0E0)?,
                    r14: read_u64_le(data, 0x0E8)?,
                    r15: read_u64_le(data, 0x0F0)?,
                    rip: read_u64_le(data, 0x0F8)?,
                }))
            }
            ProcessorArch::X86 => {
                if data.len() < Self::MIN_X86_GPR_SIZE {
                    return Err(ForensicError::parse(
                        "x86 CONTEXT",
                        format!(
                            "buffer too short ({} bytes, minimum {} bytes)",
                            data.len(),
                            Self::MIN_X86_GPR_SIZE
                        ),
                    ));
                }
                Ok(Self::X86(X86Context {
                    context_flags: read_u32_le(data, 0x000)?,
                    seg_gs: read_u32_le(data, 0x08C)?,
                    seg_fs: read_u32_le(data, 0x090)?,
                    seg_es: read_u32_le(data, 0x094)?,
                    seg_ds: read_u32_le(data, 0x098)?,
                    edi: read_u32_le(data, 0x09C)?,
                    esi: read_u32_le(data, 0x0A0)?,
                    ebx: read_u32_le(data, 0x0A4)?,
                    edx: read_u32_le(data, 0x0A8)?,
                    ecx: read_u32_le(data, 0x0AC)?,
                    eax: read_u32_le(data, 0x0B0)?,
                    ebp: read_u32_le(data, 0x0B4)?,
                    eip: read_u32_le(data, 0x0B8)?,
                    seg_cs: read_u32_le(data, 0x0BC)?,
                    eflags: read_u32_le(data, 0x0C0)?,
                    esp: read_u32_le(data, 0x0C4)?,
                    seg_ss: read_u32_le(data, 0x0C8)?,
                }))
            }
            ProcessorArch::Arm64 => {
                if data.len() < Self::MIN_ARM64_GPR_SIZE {
                    return Err(ForensicError::parse(
                        "ARM64 CONTEXT",
                        format!(
                            "buffer too short ({} bytes, minimum {} bytes)",
                            data.len(),
                            Self::MIN_ARM64_GPR_SIZE
                        ),
                    ));
                }
                let mut x = [0u64; 29];
                for (i, slot) in x.iter_mut().enumerate() {
                    *slot = read_u64_le(data, 0x008 + i * 8)?;
                }
                Ok(Self::Arm64(Arm64Context {
                    context_flags: read_u32_le(data, 0x000)?,
                    cpsr: read_u32_le(data, 0x004)?,
                    x,
                    fp: read_u64_le(data, 0x0F0)?,
                    lr: read_u64_le(data, 0x0F8)?,
                    sp: read_u64_le(data, 0x100)?,
                    pc: read_u64_le(data, 0x108)?,
                }))
            }
            other => Ok(Self::Unsupported {
                arch: other,
                data_size: data.len(),
            }),
        }
    }

    pub fn ip(&self) -> Option<u64> {
        match self {
            Self::X64(c) => Some(c.rip),
            Self::X86(c) => Some(u64::from(c.eip)),
            Self::Arm64(c) => Some(c.pc),
            Self::Unsupported { .. } => None,
        }
    }

    pub fn sp(&self) -> Option<u64> {
        match self {
            Self::X64(c) => Some(c.rsp),
            Self::X86(c) => Some(u64::from(c.esp)),
            Self::Arm64(c) => Some(c.sp),
            Self::Unsupported { .. } => None,
        }
    }

    pub fn bp(&self) -> Option<u64> {
        match self {
            Self::X64(c) => Some(c.rbp),
            Self::X86(c) => Some(u64::from(c.ebp)),
            Self::Arm64(c) => Some(c.fp),
            Self::Unsupported { .. } => None,
        }
    }

    pub fn ptr_size(&self) -> Option<usize> {
        match self {
            Self::X64(_) | Self::Arm64(_) => Some(8),
            Self::X86(_) => Some(4),
            Self::Unsupported { .. } => None,
        }
    }

    /// Formats a concise one-line register summary suitable for table cells.
    pub fn summary_string(&self) -> String {
        match self {
            Self::X64(c) => format!(
                "RIP=0x{:016x} RSP=0x{:016x} RBP=0x{:016x} RAX=0x{:016x} RCX=0x{:016x} RDX=0x{:016x} EFLAGS=0x{:08x}",
                c.rip, c.rsp, c.rbp, c.rax, c.rcx, c.rdx, c.eflags
            ),
            Self::X86(c) => format!(
                "EIP=0x{:08x} ESP=0x{:08x} EBP=0x{:08x} EAX=0x{:08x} ECX=0x{:08x} EDX=0x{:08x} EFLAGS=0x{:08x}",
                c.eip, c.esp, c.ebp, c.eax, c.ecx, c.edx, c.eflags
            ),
            Self::Arm64(c) => format!(
                "PC=0x{:016x} SP=0x{:016x} FP=0x{:016x} LR=0x{:016x} X0=0x{:016x} CPSR=0x{:08x}",
                c.pc, c.sp, c.fp, c.lr, c.x[0], c.cpsr
            ),
            Self::Unsupported { arch, data_size } => {
                format!("unsupported CONTEXT ({}, {data_size} bytes)", arch.display_name())
            }
        }
    }

    /// Converts register values into structured JSON with hex-formatted addresses.
    pub fn to_json_value(&self) -> serde_json::Value {
        match self {
            Self::X64(c) => json!({
                "arch": "x64",
                "rip": format!("0x{:016x}", c.rip),
                "rsp": format!("0x{:016x}", c.rsp),
                "rbp": format!("0x{:016x}", c.rbp),
                "rax": format!("0x{:016x}", c.rax),
                "rbx": format!("0x{:016x}", c.rbx),
                "rcx": format!("0x{:016x}", c.rcx),
                "rdx": format!("0x{:016x}", c.rdx),
                "rsi": format!("0x{:016x}", c.rsi),
                "rdi": format!("0x{:016x}", c.rdi),
                "r8": format!("0x{:016x}", c.r8),
                "r9": format!("0x{:016x}", c.r9),
                "r10": format!("0x{:016x}", c.r10),
                "r11": format!("0x{:016x}", c.r11),
                "r12": format!("0x{:016x}", c.r12),
                "r13": format!("0x{:016x}", c.r13),
                "r14": format!("0x{:016x}", c.r14),
                "r15": format!("0x{:016x}", c.r15),
                "eflags": format!("0x{:08x}", c.eflags),
                "cs": format!("0x{:04x}", c.seg_cs),
                "ss": format!("0x{:04x}", c.seg_ss),
            }),
            Self::X86(c) => json!({
                "arch": "x86",
                "eip": format!("0x{:08x}", c.eip),
                "esp": format!("0x{:08x}", c.esp),
                "ebp": format!("0x{:08x}", c.ebp),
                "eax": format!("0x{:08x}", c.eax),
                "ebx": format!("0x{:08x}", c.ebx),
                "ecx": format!("0x{:08x}", c.ecx),
                "edx": format!("0x{:08x}", c.edx),
                "esi": format!("0x{:08x}", c.esi),
                "edi": format!("0x{:08x}", c.edi),
                "eflags": format!("0x{:08x}", c.eflags),
                "cs": format!("0x{:04x}", c.seg_cs),
                "ss": format!("0x{:04x}", c.seg_ss),
            }),
            Self::Arm64(c) => json!({
                "arch": "arm64",
                "pc": format!("0x{:016x}", c.pc),
                "sp": format!("0x{:016x}", c.sp),
                "fp": format!("0x{:016x}", c.fp),
                "lr": format!("0x{:016x}", c.lr),
                "cpsr": format!("0x{:08x}", c.cpsr),
                "x0": format!("0x{:016x}", c.x[0]),
                "x1": format!("0x{:016x}", c.x[1]),
                "x2": format!("0x{:016x}", c.x[2]),
                "x3": format!("0x{:016x}", c.x[3]),
            }),
            Self::Unsupported { arch, data_size } => json!({
                "arch": arch.display_name(),
                "data_size": data_size,
            }),
        }
    }
}
