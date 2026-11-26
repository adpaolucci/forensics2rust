use std::path::Path;

use forensics2rust_core::{DiagnosticWarning, ForensicError, ForensicSource, QueryHelper, WarningSeverity, find_tool};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};
use serde_json::json;

use crate::bugcheck::{format_exception_description, is_bugcheck_code, lookup_bugcheck, normalize_bugcheck_code};
use crate::discovery::{
    discover_artifacts, is_dmp_file, is_wer_file, live_bsod_roots, live_report_roots, live_wer_roots,
};
use crate::mdmp::MinidumpFile;
use crate::stack::{attribute_fault_module, walk_stack};
use crate::wer::WerReport;

fn opt_text(val: Option<String>) -> CellValue {
    match val {
        Some(s) if !s.is_empty() => CellValue::Text(s),
        _ => CellValue::Null,
    }
}

fn short_name(path: &str) -> String {
    if path == "<memory>" {
        return path.to_string();
    }
    Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
        .unwrap_or_else(|| path.to_string())
}

fn is_single_item_source(source: &ForensicSource) -> bool {
    match source {
        ForensicSource::OfflineBytes(_) => true,
        ForensicSource::OfflinePath(p) => p.is_file(),
        ForensicSource::Live => false,
    }
}

fn join_module_names(dump: &MinidumpFile, max_items: usize) -> CellValue {
    if dump.modules.is_empty() {
        return CellValue::Null;
    }
    let total = dump.modules.len();
    let shown: Vec<&str> = dump
        .modules
        .iter()
        .take(max_items)
        .map(|m| m.module_name.as_str())
        .collect();
    if total > max_items {
        CellValue::Text(format!("{} (+{} more)", shown.join(", "), total - max_items))
    } else {
        CellValue::Text(shown.join(", "))
    }
}

/// `BlueScreenView` (`crash.bsod`) — pure-Rust kernel/BSOD `MDMP` minidump analyzer.
#[derive(Debug, Clone)]
pub struct CrashBsodProvider {
    source: ForensicSource,
}

impl CrashBsodProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }

    pub fn collect_with_diagnostics(&self) -> Result<(Vec<Row>, Vec<DiagnosticWarning>), ForensicError> {
        let live_roots = if self.source.is_live() {
            live_bsod_roots()
        } else {
            Vec::new()
        };
        let mut discovered = discover_artifacts(&self.source, self.tool_id(), &live_roots, is_dmp_file)?;
        let strict_single = is_single_item_source(&self.source);
        let mut rows = Vec::new();

        for item in discovered.items {
            let dump = match MinidumpFile::parse(item.bytes) {
                Ok(d) => d,
                Err(err) => {
                    if strict_single {
                        return Err(err);
                    }
                    discovered.warnings.push(DiagnosticWarning {
                        severity: WarningSeverity::Info,
                        tool_id: self.tool_id().to_string(),
                        source: item.path,
                        message: err.to_string(),
                    });
                    continue;
                }
            };

            let frames = walk_stack(&dump, false);
            let attr = attribute_fault_module(&dump, &frames, false);

            let (raw_code, norm_code, bc_info, params, exc_addr) = match &dump.exception {
                Some(exc) => {
                    let norm = normalize_bugcheck_code(exc.exception_code);
                    let info = lookup_bugcheck(exc.exception_code);
                    (
                        Some(exc.exception_code),
                        Some(norm),
                        info,
                        exc.exception_information.clone(),
                        if exc.exception_address != 0 {
                            Some(exc.exception_address)
                        } else {
                            attr.crash_address
                        },
                    )
                }
                None => (None, None, None, Vec::new(), attr.crash_address),
            };

            let bugcheck_code_cell = norm_code
                .map(|c| CellValue::Text(format!("0x{c:08x}")))
                .unwrap_or(CellValue::Null);
            let bugcheck_name_cell = bc_info
                .map(|i| CellValue::Text(i.name.to_string()))
                .or_else(|| raw_code.map(|c| CellValue::Text(format_exception_description(c, &params))))
                .unwrap_or(CellValue::Null);

            let param_cell = |idx: usize| -> CellValue {
                params
                    .get(idx)
                    .map(|p| CellValue::Text(format!("0x{p:016x}")))
                    .unwrap_or(CellValue::Null)
            };

            let crash_time_cell = dump
                .header
                .timestamp_utc
                .map(CellValue::Timestamp)
                .unwrap_or(CellValue::Null);
            let crash_addr_cell = exc_addr
                .map(|a| CellValue::Text(format!("0x{a:016x}")))
                .unwrap_or(CellValue::Null);

            let arch_cell = dump
                .system_info
                .as_ref()
                .map(|si| CellValue::Text(si.processor_architecture.display_name()))
                .unwrap_or(CellValue::Null);
            let os_build_cell = dump
                .system_info
                .as_ref()
                .map(|si| CellValue::Text(si.os_build_string()))
                .unwrap_or(CellValue::Null);
            let cpu_count_cell = dump
                .system_info
                .as_ref()
                .map(|si| CellValue::Uint(u64::from(si.number_of_processors)))
                .unwrap_or(CellValue::Null);

            let file_desc_cell = bc_info
                .map(|i| CellValue::Text(i.summary.to_string()))
                .unwrap_or(CellValue::Null);
            let product_name_cell = attr
                .module_name
                .as_ref()
                .and_then(|name| dump.modules.iter().find(|m| &m.module_name == name))
                .and_then(|m| m.product_version.clone())
                .map(|pv| CellValue::Text(format!("Windows Driver ({pv})")))
                .unwrap_or(CellValue::Null);

            let detail = json!({
                "dump_file": item.path,
                "header": dump.header,
                "system_info": dump.system_info,
                "bugcheck_code": norm_code.map(|c| format!("0x{c:08x}")),
                "raw_exception_code": raw_code.map(|c| format!("0x{c:08x}")),
                "bugcheck_name": bc_info.map(|i| i.name),
                "bugcheck_summary": bc_info.map(|i| i.summary),
                "is_bugcheck_code": raw_code.map(is_bugcheck_code),
                "parameters": params.iter().map(|p| format!("0x{p:016x}")).collect::<Vec<_>>(),
                "caused_by_driver": attr.module_name,
                "caused_by_address": attr.caused_by_address,
                "driver_version": attr.module_version,
                "unloaded_fault": attr.unloaded,
                "call_stack": frames.iter().map(|f| json!({
                    "index": f.index,
                    "ip": format!("0x{:016x}", f.instruction_pointer),
                    "location": f.display_location(),
                    "method": f.method,
                    "unloaded": f.unloaded,
                })).collect::<Vec<_>>(),
                "modules": dump.modules,
                "unloaded_modules": dump.unloaded_modules,
                "misc_info": dump.misc_info,
                "comments": dump.comments,
            });

            let row_id = (rows.len() + 1) as u64;
            let raw_bytes = dump.bounded_raw_bytes();
            let mut row = Row::new(
                row_id,
                vec![
                    CellValue::Text(short_name(&item.path)),
                    crash_time_cell,
                    bugcheck_code_cell,
                    bugcheck_name_cell,
                    param_cell(0),
                    param_cell(1),
                    param_cell(2),
                    param_cell(3),
                    opt_text(attr.module_name),
                    opt_text(attr.caused_by_address),
                    crash_addr_cell,
                    opt_text(attr.module_version),
                    file_desc_cell,
                    product_name_cell,
                    arch_cell,
                    os_build_cell,
                    cpu_count_cell,
                    CellValue::Uint(dump.modules.len() as u64),
                    join_module_names(&dump, 16),
                    CellValue::Text(item.path),
                ],
            )
            .with_detail_json(detail);
            if !raw_bytes.is_empty() {
                row = row.with_raw_bytes(raw_bytes);
            }
            rows.push(row);
        }

        Ok((rows, discovered.warnings))
    }
}

impl TableProvider for CrashBsodProvider {
    fn tool_id(&self) -> &'static str {
        "crash.bsod"
    }

    fn description(&self) -> &'static str {
        find_tool("crash.bsod")
            .map(|d| d.description)
            .unwrap_or("Pure-Rust MDMP kernel/BSOD minidump analyzer")
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "BlueScreenView — BSOD Minidumps",
            vec![
                ColumnDef::new("dump_file", "Dump File", ColumnType::Text).with_width_hint(190),
                ColumnDef::new("crash_time", "Crash Time", ColumnType::Timestamp).with_width_hint(175),
                ColumnDef::new("bugcheck_code", "Bug Check Code", ColumnType::Hex).with_width_hint(120),
                ColumnDef::new("bugcheck_name", "Bug Check String", ColumnType::Text).with_width_hint(210),
                ColumnDef::new("param1", "Parameter 1", ColumnType::Hex).with_width_hint(145),
                ColumnDef::new("param2", "Parameter 2", ColumnType::Hex).with_width_hint(145),
                ColumnDef::new("param3", "Parameter 3", ColumnType::Hex).with_width_hint(145),
                ColumnDef::new("param4", "Parameter 4", ColumnType::Hex).with_width_hint(145),
                ColumnDef::new("caused_by_driver", "Caused By Driver", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("caused_by_address", "Caused By Address", ColumnType::Hex).with_width_hint(165),
                ColumnDef::new("crash_address", "Crash Address", ColumnType::Hex).with_width_hint(150),
                ColumnDef::new("driver_version", "Driver Version", ColumnType::Text).with_width_hint(130),
                ColumnDef::new("file_description", "File Description", ColumnType::Text).with_width_hint(190),
                ColumnDef::new("product_name", "Product Name", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("architecture", "Processor", ColumnType::Text).with_width_hint(105),
                ColumnDef::new("os_build", "OS Build", ColumnType::Text).with_width_hint(115),
                ColumnDef::new("processor_count", "CPUs", ColumnType::Uint).with_width_hint(65),
                ColumnDef::new("module_count", "Modules", ColumnType::Uint).with_width_hint(75),
                ColumnDef::new("module_list", "Module List", ColumnType::Text).with_width_hint(240),
                ColumnDef::new("full_path", "Full Path", ColumnType::Text).with_width_hint(260),
            ],
        )
        .with_default_sort(1, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let (rows, _warnings) = self.collect_with_diagnostics().map_err(|e| e.to_table_error())?;
        QueryHelper::apply(&self.schema(), &rows, req).map_err(|e| e.to_table_error())
    }
}

/// `AppCrashView` (`crash.wer`) — UTF-16LE / UTF-8 `Report.wer` Windows Error Reporting parser.
#[derive(Debug, Clone)]
pub struct CrashWerProvider {
    source: ForensicSource,
}

impl CrashWerProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }

    pub fn collect_with_diagnostics(&self) -> Result<(Vec<Row>, Vec<DiagnosticWarning>), ForensicError> {
        let live_roots = if self.source.is_live() {
            live_wer_roots()
        } else {
            Vec::new()
        };
        let mut discovered = discover_artifacts(&self.source, self.tool_id(), &live_roots, is_wer_file)?;
        let strict_single = is_single_item_source(&self.source);
        let mut rows = Vec::new();

        for item in discovered.items {
            let report = match WerReport::from_bytes(&item.bytes, &item.path) {
                Ok(r) => r,
                Err(err) => {
                    if strict_single {
                        return Err(err);
                    }
                    discovered.warnings.push(DiagnosticWarning {
                        severity: WarningSeverity::Warn,
                        tool_id: self.tool_id().to_string(),
                        source: item.path,
                        message: err.to_string(),
                    });
                    continue;
                }
            };

            let detail = serde_json::to_value(&report).unwrap_or_else(|_| json!({ "wer_file_path": item.path }));
            let row_id = (rows.len() + 1) as u64;
            let mut row = Row::new(
                row_id,
                vec![
                    report.event_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                    opt_text(report.event_type),
                    opt_text(report.friendly_event_name),
                    opt_text(report.app_name),
                    opt_text(report.app_version),
                    opt_text(report.fault_module),
                    opt_text(report.fault_module_version),
                    opt_text(report.exception_code),
                    opt_text(report.exception_name),
                    opt_text(report.exception_offset),
                    opt_text(report.os_version),
                    opt_text(report.app_path),
                    opt_text(report.report_id),
                    report.report_type.map(CellValue::Uint).unwrap_or(CellValue::Null),
                    report.report_status.map(CellValue::Uint).unwrap_or(CellValue::Null),
                    report.consent.map(CellValue::Uint).unwrap_or(CellValue::Null),
                    CellValue::Text(report.wer_file_path),
                ],
            )
            .with_detail_json(detail);
            if !report.raw_prefix.is_empty() {
                row = row.with_raw_bytes(report.raw_prefix);
            }
            rows.push(row);
        }

        Ok((rows, discovered.warnings))
    }
}

impl TableProvider for CrashWerProvider {
    fn tool_id(&self) -> &'static str {
        "crash.wer"
    }

    fn description(&self) -> &'static str {
        find_tool("crash.wer")
            .map(|d| d.description)
            .unwrap_or("UTF-16LE / UTF-8 Report.wer Windows Error Reporting crash parser")
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "AppCrashView — Windows Error Reporting",
            vec![
                ColumnDef::new("event_time", "Crash Time", ColumnType::Timestamp).with_width_hint(175),
                ColumnDef::new("event_type", "Event Type", ColumnType::Text).with_width_hint(130),
                ColumnDef::new("friendly_event", "Friendly Event Name", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("app_name", "App Name", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("app_version", "App Version", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("fault_module", "Fault Module", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("fault_module_version", "Fault Module Version", ColumnType::Text).with_width_hint(130),
                ColumnDef::new("exception_code", "Exception Code", ColumnType::Hex).with_width_hint(120),
                ColumnDef::new("exception_name", "Exception Description", ColumnType::Text).with_width_hint(190),
                ColumnDef::new("exception_offset", "Exception Offset", ColumnType::Hex).with_width_hint(135),
                ColumnDef::new("os_version", "OS Version", ColumnType::Text).with_width_hint(145),
                ColumnDef::new("app_path", "Process Path", ColumnType::Text).with_width_hint(260),
                ColumnDef::new("report_id", "Report ID", ColumnType::Text).with_width_hint(240),
                ColumnDef::new("report_type", "Report Type", ColumnType::Uint).with_width_hint(95),
                ColumnDef::new("report_status", "Report Status", ColumnType::Uint).with_width_hint(105),
                ColumnDef::new("consent", "Consent", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("wer_file_path", "WerFilePath", ColumnType::Text).with_width_hint(280),
            ],
        )
        .with_default_sort(0, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let (rows, _warnings) = self.collect_with_diagnostics().map_err(|e| e.to_table_error())?;
        QueryHelper::apply(&self.schema(), &rows, req).map_err(|e| e.to_table_error())
    }
}

/// `WinCrashReport` (`crash.report`) — user-mode `MDMP` analyzer with offline PE export lookup.
#[derive(Debug, Clone)]
pub struct CrashReportProvider {
    source: ForensicSource,
}

impl CrashReportProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }

    pub fn collect_with_diagnostics(&self) -> Result<(Vec<Row>, Vec<DiagnosticWarning>), ForensicError> {
        let live_roots = if self.source.is_live() {
            live_report_roots()
        } else {
            Vec::new()
        };
        let mut discovered = discover_artifacts(&self.source, self.tool_id(), &live_roots, is_dmp_file)?;
        let strict_single = is_single_item_source(&self.source);
        let mut rows = Vec::new();

        for item in discovered.items {
            let dump = match MinidumpFile::parse(item.bytes) {
                Ok(d) => d,
                Err(err) => {
                    if strict_single {
                        return Err(err);
                    }
                    discovered.warnings.push(DiagnosticWarning {
                        severity: WarningSeverity::Info,
                        tool_id: self.tool_id().to_string(),
                        source: item.path,
                        message: err.to_string(),
                    });
                    continue;
                }
            };

            let frames = walk_stack(&dump, true);
            let attr = attribute_fault_module(&dump, &frames, true);

            let primary_mod = dump
                .modules
                .iter()
                .find(|m| {
                    m.module_name.len() >= 4
                        && m.module_name.as_bytes()[m.module_name.len() - 4..].eq_ignore_ascii_case(b".exe")
                })
                .or_else(|| dump.modules.first());
            let process_name = primary_mod.map(|m| m.module_name.clone()).filter(|s| !s.is_empty());
            let process_path = primary_mod.map(|m| m.full_path.clone()).filter(|s| !s.is_empty());

            let crash_time_cell = dump
                .header
                .timestamp_utc
                .map(CellValue::Timestamp)
                .unwrap_or(CellValue::Null);
            let pid_cell = dump
                .misc_info
                .as_ref()
                .and_then(|mi| mi.process_id)
                .map(|pid| CellValue::Uint(u64::from(pid)))
                .unwrap_or(CellValue::Null);
            let tid_cell = dump
                .exception
                .as_ref()
                .map(|e| CellValue::Uint(u64::from(e.thread_id)))
                .or_else(|| dump.threads.first().map(|t| CellValue::Uint(u64::from(t.thread_id))))
                .unwrap_or(CellValue::Null);

            let exc_code_cell = dump
                .exception
                .as_ref()
                .map(|e| CellValue::Text(format!("0x{:08x}", e.exception_code)))
                .unwrap_or(CellValue::Null);
            let exc_desc_cell = dump
                .exception
                .as_ref()
                .map(|e| CellValue::Text(format_exception_description(e.exception_code, &e.exception_information)))
                .unwrap_or(CellValue::Null);
            let exc_addr_cell = dump
                .exception
                .as_ref()
                .map(|e| CellValue::Text(format!("0x{:016x}", e.exception_address)))
                .or_else(|| {
                    dump.faulting_context()
                        .and_then(|c| c.ip())
                        .map(|ip| CellValue::Text(format!("0x{ip:016x}")))
                })
                .unwrap_or(CellValue::Null);

            let arch_cell = dump
                .system_info
                .as_ref()
                .map(|si| CellValue::Text(si.processor_architecture.display_name()))
                .unwrap_or(CellValue::Null);
            let os_build_cell = dump
                .system_info
                .as_ref()
                .map(|si| CellValue::Text(si.os_build_string()))
                .unwrap_or(CellValue::Null);

            let faulting_ctx = dump.faulting_context();
            let registers_cell = faulting_ctx
                .map(|c| CellValue::Text(c.summary_string()))
                .unwrap_or(CellValue::Null);
            let call_stack_cell = if frames.is_empty() {
                CellValue::Null
            } else {
                let text = frames
                    .iter()
                    .take(16)
                    .map(crate::stack::StackFrame::display_location)
                    .collect::<Vec<_>>()
                    .join("; ");
                CellValue::Text(text)
            };

            let detail = json!({
                "dump_file": item.path,
                "header": dump.header,
                "system_info": dump.system_info,
                "misc_info": dump.misc_info,
                "exception": dump.exception.as_ref().map(|e| json!({
                    "thread_id": e.thread_id,
                    "exception_code": format!("0x{:08x}", e.exception_code),
                    "description": format_exception_description(e.exception_code, &e.exception_information),
                    "exception_address": format!("0x{:016x}", e.exception_address),
                    "parameters": e.exception_information.iter().map(|p| format!("0x{p:016x}")).collect::<Vec<_>>(),
                })),
                "registers": faulting_ctx.map(|c| c.to_json_value()),
                "call_stack_frames": frames.iter().map(|f| json!({
                    "index": f.index,
                    "ip": format!("0x{:016x}", f.instruction_pointer),
                    "sp": f.stack_pointer.map(|s| format!("0x{s:016x}")),
                    "location": f.display_location(),
                    "module": f.module_name,
                    "symbol": f.symbol,
                    "method": f.method,
                    "unloaded": f.unloaded,
                })).collect::<Vec<_>>(),
                "loaded_modules": dump.modules,
                "unloaded_modules": dump.unloaded_modules,
                "thread_count": dump.threads.len(),
            });

            let row_id = (rows.len() + 1) as u64;
            let raw_bytes = dump.bounded_raw_bytes();
            let mut row = Row::new(
                row_id,
                vec![
                    opt_text(process_name),
                    crash_time_cell,
                    pid_cell,
                    tid_cell,
                    exc_code_cell,
                    exc_desc_cell,
                    exc_addr_cell,
                    opt_text(attr.module_name),
                    opt_text(attr.fault_symbol),
                    opt_text(attr.module_version),
                    arch_cell,
                    os_build_cell,
                    CellValue::Uint(dump.threads.len() as u64),
                    CellValue::Uint(dump.modules.len() as u64),
                    registers_cell,
                    call_stack_cell,
                    join_module_names(&dump, 16),
                    CellValue::Bytes(dump.raw_len() as u64),
                    opt_text(process_path),
                    CellValue::Text(item.path),
                ],
            )
            .with_detail_json(detail);
            if !raw_bytes.is_empty() {
                row = row.with_raw_bytes(raw_bytes);
            }
            rows.push(row);
        }

        Ok((rows, discovered.warnings))
    }
}

impl TableProvider for CrashReportProvider {
    fn tool_id(&self) -> &'static str {
        "crash.report"
    }

    fn description(&self) -> &'static str {
        find_tool("crash.report")
            .map(|d| d.description)
            .unwrap_or("User-mode MDMP and PE export crash report viewer (no DLL injection)")
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "WinCrashReport — User-Mode Crash Reports",
            vec![
                ColumnDef::new("process_name", "Process Name", ColumnType::Text).with_width_hint(150),
                ColumnDef::new("crash_time", "Crash Time", ColumnType::Timestamp).with_width_hint(175),
                ColumnDef::new("process_id", "PID", ColumnType::Uint).with_width_hint(75),
                ColumnDef::new("thread_id", "TID", ColumnType::Uint).with_width_hint(75),
                ColumnDef::new("exception_code", "Exception Code", ColumnType::Hex).with_width_hint(120),
                ColumnDef::new("exception_desc", "Exception Description", ColumnType::Text).with_width_hint(190),
                ColumnDef::new("exception_address", "Exception Address", ColumnType::Hex).with_width_hint(150),
                ColumnDef::new("fault_module", "Fault Module", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("fault_symbol", "Fault Symbol", ColumnType::Text).with_width_hint(210),
                ColumnDef::new("module_version", "Module Version", ColumnType::Text).with_width_hint(125),
                ColumnDef::new("architecture", "Architecture", ColumnType::Text).with_width_hint(105),
                ColumnDef::new("os_build", "OS Build", ColumnType::Text).with_width_hint(115),
                ColumnDef::new("thread_count", "Threads", ColumnType::Uint).with_width_hint(75),
                ColumnDef::new("module_count", "Modules", ColumnType::Uint).with_width_hint(75),
                ColumnDef::new("registers", "Registers", ColumnType::Text).with_width_hint(260),
                ColumnDef::new("call_stack_frames", "Call Stack Frames", ColumnType::Text).with_width_hint(280),
                ColumnDef::new("loaded_modules", "Loaded Modules", ColumnType::Text).with_width_hint(240),
                ColumnDef::new("dump_size", "Dump Size", ColumnType::BytesSize).with_width_hint(100),
                ColumnDef::new("process_path", "Process Path", ColumnType::Text).with_width_hint(250),
                ColumnDef::new("dump_file", "Dump File", ColumnType::Text).with_width_hint(250),
            ],
        )
        .with_default_sort(1, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let (rows, _warnings) = self.collect_with_diagnostics().map_err(|e| e.to_table_error())?;
        QueryHelper::apply(&self.schema(), &rows, req).map_err(|e| e.to_table_error())
    }
}
