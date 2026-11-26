use std::io::Read;
use std::path::{Path, PathBuf};

use forensics2rust_core::{DiagnosticWarning, ForensicError, ForensicSource, WarningSeverity, is_elevation_error};
use walkdir::WalkDir;

/// A discovered crash artifact buffer with its provenance label.
#[derive(Debug, Clone)]
pub struct DiscoveredArtifact {
    pub path: String,
    pub bytes: Vec<u8>,
    pub from_live_scan: bool,
}

/// Result of artifact discovery including non-fatal diagnostic warnings.
#[derive(Debug, Default)]
pub struct DiscoveryResult {
    pub items: Vec<DiscoveredArtifact>,
    pub warnings: Vec<DiagnosticWarning>,
}

/// Candidate live filesystem location (directory or single file).
#[derive(Debug, Clone)]
pub struct LiveRootSpec {
    pub path: PathBuf,
    pub is_single_file: bool,
}

impl LiveRootSpec {
    pub fn dir(path: PathBuf) -> Self {
        Self {
            path,
            is_single_file: false,
        }
    }

    pub fn file(path: PathBuf) -> Self {
        Self {
            path,
            is_single_file: true,
        }
    }
}

fn env_path_or(var: &str, fallback: &str) -> PathBuf {
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(fallback))
}

/// Default live Windows locations for `crash.bsod` (BSOD Minidumps).
pub fn live_bsod_roots() -> Vec<LiveRootSpec> {
    let sys_root = env_path_or("SystemRoot", r"C:\Windows");
    vec![
        LiveRootSpec::dir(sys_root.join("Minidump")),
        LiveRootSpec::dir(sys_root.join("LiveKernelReports")),
        LiveRootSpec::file(sys_root.join("MEMORY.DMP")),
    ]
}

/// Default live Windows locations for `crash.wer` (Windows Error Reporting).
pub fn live_wer_roots() -> Vec<LiveRootSpec> {
    let program_data = env_path_or("ProgramData", r"C:\ProgramData");
    let mut roots = vec![
        LiveRootSpec::dir(program_data.join(r"Microsoft\Windows\WER\ReportArchive")),
        LiveRootSpec::dir(program_data.join(r"Microsoft\Windows\WER\ReportQueue")),
    ];
    if let Some(local_app) = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
        let local = PathBuf::from(local_app);
        roots.push(LiveRootSpec::dir(local.join(r"Microsoft\Windows\WER\ReportArchive")));
        roots.push(LiveRootSpec::dir(local.join(r"Microsoft\Windows\WER\ReportQueue")));
    }
    roots
}

/// Default live Windows locations for `crash.report` (User-Mode Crash Reports).
pub fn live_report_roots() -> Vec<LiveRootSpec> {
    let program_data = env_path_or("ProgramData", r"C:\ProgramData");
    let mut roots = Vec::new();
    if let Some(local_app) = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
        let local = PathBuf::from(local_app);
        roots.push(LiveRootSpec::dir(local.join("CrashDumps")));
        roots.push(LiveRootSpec::dir(local.join(r"Microsoft\Windows\WER\ReportArchive")));
        roots.push(LiveRootSpec::dir(local.join(r"Microsoft\Windows\WER\ReportQueue")));
    }
    roots.push(LiveRootSpec::dir(
        program_data.join(r"Microsoft\Windows\WER\ReportArchive"),
    ));
    roots.push(LiveRootSpec::dir(
        program_data.join(r"Microsoft\Windows\WER\ReportQueue"),
    ));
    roots
}

pub fn is_dmp_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("dmp") || ext.eq_ignore_ascii_case("mdmp"))
}

pub fn is_wer_file(path: &Path) -> bool {
    let name_match = path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.eq_ignore_ascii_case("report.wer"));
    let ext_match = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("wer"));
    name_match || ext_match
}

fn is_dump_artifact(path: &Path, tool_id: &str) -> bool {
    is_dmp_file(path) || matches!(tool_id, "crash.bsod" | "crash.report")
}

/// Reads up to the first 8 bytes of a candidate dump file without loading its body.
pub fn peek_dump_magic(path: &Path) -> std::io::Result<([u8; 8], usize)> {
    let mut file = std::fs::File::open(path)?;
    let mut buf = [0u8; 8];
    let mut total = 0usize;
    while total < buf.len() {
        match file.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok((buf, total))
}

fn is_pagedump_magic(buf: &[u8; 8], len: usize) -> bool {
    len >= 8 && (&buf[..8] == b"PAGEDUMP" || &buf[..8] == b"PAGEDU64")
}

fn validate_single_dump_magic(path: &Path) -> Result<(), ForensicError> {
    let (buf, len) =
        peek_dump_magic(path).map_err(|err| ForensicError::io_classified(path.display().to_string(), err))?;
    if is_pagedump_magic(&buf, len) {
        return Err(ForensicError::unsupported_platform(
            "MDMP",
            "full kernel MEMORY.DMP (PAGEDUMP/PAGEDU64) is not an MDMP minidump; supply C:\\Windows\\Minidump\\*.dmp",
        ));
    }
    if len >= 4 && &buf[..4] != b"MDMP" {
        let signature = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        return Err(ForensicError::parse(
            "MINIDUMP_HEADER",
            format!("invalid MDMP signature 0x{signature:08x} (expected 0x504d444d)"),
        ));
    }
    Ok(())
}

enum DumpPeekDecision {
    ReadFull,
    Skip(DiagnosticWarning),
    IoError(std::io::Error),
}

fn peek_dump_for_scan(path: &Path, tool_id: &str) -> DumpPeekDecision {
    match peek_dump_magic(path) {
        Err(err) => DumpPeekDecision::IoError(err),
        Ok((buf, len)) => {
            if is_pagedump_magic(&buf, len) {
                DumpPeekDecision::Skip(DiagnosticWarning {
                    severity: WarningSeverity::Info,
                    tool_id: tool_id.to_string(),
                    source: path.display().to_string(),
                    message: "full kernel MEMORY.DMP (PAGEDUMP/PAGEDU64) is not an MDMP minidump; skipping".to_string(),
                })
            } else if len >= 4 && &buf[..4] != b"MDMP" {
                DumpPeekDecision::Skip(DiagnosticWarning {
                    severity: WarningSeverity::Warn,
                    tool_id: tool_id.to_string(),
                    source: path.display().to_string(),
                    message: "file does not start with MDMP signature; skipping".to_string(),
                })
            } else {
                DumpPeekDecision::ReadFull
            }
        }
    }
}

/// Discovers crash artifacts from `Live`, `OfflinePath` (file or directory), or `OfflineBytes`.
pub fn discover_artifacts(
    source: &ForensicSource,
    tool_id: &str,
    live_roots: &[LiveRootSpec],
    matcher: impl Fn(&Path) -> bool,
) -> Result<DiscoveryResult, ForensicError> {
    match source {
        ForensicSource::OfflineBytes(bytes) => Ok(DiscoveryResult {
            items: vec![DiscoveredArtifact {
                path: "<memory>".to_string(),
                bytes: bytes.clone(),
                from_live_scan: false,
            }],
            warnings: Vec::new(),
        }),
        ForensicSource::OfflinePath(path) => {
            let meta =
                std::fs::metadata(path).map_err(|err| ForensicError::io_classified(path.display().to_string(), err))?;
            if meta.is_file() {
                if is_dump_artifact(path, tool_id) {
                    validate_single_dump_magic(path)?;
                }
                let bytes =
                    std::fs::read(path).map_err(|err| ForensicError::io_classified(path.display().to_string(), err))?;
                return Ok(DiscoveryResult {
                    items: vec![DiscoveredArtifact {
                        path: path.display().to_string(),
                        bytes,
                        from_live_scan: false,
                    }],
                    warnings: Vec::new(),
                });
            }

            let mut out = DiscoveryResult::default();
            collect_dir_sorted(path, tool_id, &matcher, false, &mut out);
            Ok(out)
        }
        ForensicSource::Live => discover_from_live_roots(live_roots, tool_id, matcher),
    }
}

/// Probes candidate live roots gracefully: missing dirs emit `Info` warnings, individual
/// `PermissionDenied` entries emit `Warn` and continue, and `Err(PermissionDenied)` is returned
/// ONLY when at least one candidate existed and ALL existing candidates failed with `PermissionDenied`.
pub fn discover_from_live_roots(
    roots: &[LiveRootSpec],
    tool_id: &str,
    matcher: impl Fn(&Path) -> bool,
) -> Result<DiscoveryResult, ForensicError> {
    let mut out = DiscoveryResult::default();
    let mut existing_roots = 0usize;
    let mut denied_roots = 0usize;
    let mut last_denied: Option<(String, String)> = None;

    for root in roots {
        let path_str = root.path.display().to_string();
        match std::fs::metadata(&root.path) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                out.warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Info,
                    tool_id: tool_id.to_string(),
                    source: path_str,
                    message: "crash artifact location absent on host".to_string(),
                });
            }
            Err(err) if is_elevation_error(&err) => {
                existing_roots += 1;
                denied_roots += 1;
                last_denied = Some((path_str.clone(), err.to_string()));
                out.warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Warn,
                    tool_id: tool_id.to_string(),
                    source: path_str,
                    message: format!("permission denied ({err}); run elevated or supply an offline artifact path"),
                });
            }
            Err(err) => {
                out.warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Warn,
                    tool_id: tool_id.to_string(),
                    source: path_str,
                    message: format!("unable to inspect crash path: {err}"),
                });
            }
            Ok(meta) => {
                existing_roots += 1;
                if root.is_single_file || meta.is_file() {
                    if is_dump_artifact(&root.path, tool_id) {
                        match peek_dump_for_scan(&root.path, tool_id) {
                            DumpPeekDecision::ReadFull => {}
                            DumpPeekDecision::Skip(warning) => {
                                out.warnings.push(warning);
                                continue;
                            }
                            DumpPeekDecision::IoError(err) if is_elevation_error(&err) => {
                                denied_roots += 1;
                                last_denied = Some((path_str.clone(), err.to_string()));
                                out.warnings.push(DiagnosticWarning {
                                    severity: WarningSeverity::Warn,
                                    tool_id: tool_id.to_string(),
                                    source: path_str,
                                    message: format!("permission denied ({err}); skipping"),
                                });
                                continue;
                            }
                            DumpPeekDecision::IoError(err) => {
                                out.warnings.push(DiagnosticWarning {
                                    severity: WarningSeverity::Warn,
                                    tool_id: tool_id.to_string(),
                                    source: path_str,
                                    message: format!("failed to read crash file: {err}"),
                                });
                                continue;
                            }
                        }
                    }
                    match std::fs::read(&root.path) {
                        Ok(bytes) => {
                            out.items.push(DiscoveredArtifact {
                                path: path_str,
                                bytes,
                                from_live_scan: true,
                            });
                        }
                        Err(err) if is_elevation_error(&err) => {
                            denied_roots += 1;
                            last_denied = Some((path_str.clone(), err.to_string()));
                            out.warnings.push(DiagnosticWarning {
                                severity: WarningSeverity::Warn,
                                tool_id: tool_id.to_string(),
                                source: path_str,
                                message: format!("permission denied ({err}); skipping"),
                            });
                        }
                        Err(err) => {
                            out.warnings.push(DiagnosticWarning {
                                severity: WarningSeverity::Warn,
                                tool_id: tool_id.to_string(),
                                source: path_str,
                                message: format!("failed to read crash file: {err}"),
                            });
                        }
                    }
                } else {
                    match std::fs::read_dir(&root.path) {
                        Err(err) if is_elevation_error(&err) => {
                            denied_roots += 1;
                            last_denied = Some((path_str.clone(), err.to_string()));
                            out.warnings.push(DiagnosticWarning {
                                severity: WarningSeverity::Warn,
                                tool_id: tool_id.to_string(),
                                source: path_str,
                                message: format!("permission denied ({err}); run elevated or supply an offline path"),
                            });
                        }
                        Err(err) => {
                            out.warnings.push(DiagnosticWarning {
                                severity: WarningSeverity::Warn,
                                tool_id: tool_id.to_string(),
                                source: path_str,
                                message: format!("failed to enumerate directory: {err}"),
                            });
                        }
                        Ok(_) => {
                            collect_dir_sorted(&root.path, tool_id, &matcher, true, &mut out);
                        }
                    }
                }
            }
        }
    }

    if existing_roots > 0 && denied_roots == existing_roots {
        let (ctx, msg) = last_denied.unwrap_or_else(|| ("live".to_string(), "access denied".to_string()));
        return Err(ForensicError::permission_denied(ctx, msg));
    }

    Ok(out)
}

fn collect_dir_sorted(
    dir: &Path,
    tool_id: &str,
    matcher: &impl Fn(&Path) -> bool,
    from_live_scan: bool,
    out: &mut DiscoveryResult,
) {
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry_res in WalkDir::new(dir).follow_links(false) {
        match entry_res {
            Ok(entry) => {
                if entry.file_type().is_file() && matcher(entry.path()) {
                    paths.push(entry.into_path());
                }
            }
            Err(err) => {
                let src = err
                    .path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| dir.display().to_string());
                out.warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Warn,
                    tool_id: tool_id.to_string(),
                    source: src,
                    message: format!("directory walk entry skipped: {err}"),
                });
            }
        }
    }

    paths.sort();

    for file_path in paths {
        let path_str = file_path.display().to_string();
        if is_dump_artifact(&file_path, tool_id) {
            match peek_dump_for_scan(&file_path, tool_id) {
                DumpPeekDecision::ReadFull => {}
                DumpPeekDecision::Skip(warning) => {
                    out.warnings.push(warning);
                    continue;
                }
                DumpPeekDecision::IoError(err) => {
                    out.warnings.push(DiagnosticWarning {
                        severity: WarningSeverity::Warn,
                        tool_id: tool_id.to_string(),
                        source: path_str,
                        message: format!("failed to read artifact: {err}"),
                    });
                    continue;
                }
            }
        }
        match std::fs::read(&file_path) {
            Ok(bytes) => out.items.push(DiscoveredArtifact {
                path: path_str,
                bytes,
                from_live_scan,
            }),
            Err(err) => out.warnings.push(DiagnosticWarning {
                severity: WarningSeverity::Warn,
                tool_id: tool_id.to_string(),
                source: path_str,
                message: format!("failed to read artifact: {err}"),
            }),
        }
    }
}
