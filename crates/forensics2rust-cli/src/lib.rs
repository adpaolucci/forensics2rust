#![forbid(unsafe_code)]

//! Unified CLI command router and table/custody runner for `forensics2rust`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use forensics2rust_artifacts::restore_previous_file;
use forensics2rust_core::{FORENSIC_TOOL_CATALOG, ForensicSource, QueryHelper, ToolCategory, tools_by_category};
use forensics2rust_hive::reg_format::RegExportFormat;
use forensics2rust_hive::{
    FindCriteria, OfflineFinderProvider, OfflineRegistryProvider, RegFileExportProvider, RegScannerProvider,
    RegistryChangesProvider, ScanOptions,
};
use forensics2rust_mcp::{
    build_registry, collect_all_providers, provider_for_tool, resolve_tool_source, serve_stdio, tools_manifest_json,
};
use forensics2rust_report::{
    ForensicReportOptions, diff_tables, render_table_report, write_bundle_report, write_table_report,
};
use forensics2rust_srum::SrumDbProvider;
use guap_export::ExportFormat;
use guap_mcp::PolicyMode;
use guap_table::{TableData, TableProvider};
use serde_json::json;

/// Supported CLI output formats.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum CliOutputFormat {
    #[default]
    Table,
    Csv,
    Tsv,
    Json,
    Jsonl,
    Html,
    HtmlVertical,
    Markdown,
}

impl CliOutputFormat {
    pub fn to_export_format(self) -> Option<ExportFormat> {
        match self {
            Self::Table => None,
            Self::Csv => Some(ExportFormat::Csv),
            Self::Tsv => Some(ExportFormat::Tsv),
            Self::Json => Some(ExportFormat::Json),
            Self::Jsonl => Some(ExportFormat::Jsonl),
            Self::Html => Some(ExportFormat::Html),
            Self::HtmlVertical => Some(ExportFormat::HtmlVertical),
            Self::Markdown => Some(ExportFormat::Markdown),
        }
    }
}

/// Domain tool categories for `export`/`report`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum CliCategory {
    Evtx,
    Hive,
    Srum,
    Artifacts,
    Crash,
    Posture,
}

impl From<CliCategory> for ToolCategory {
    fn from(value: CliCategory) -> Self {
        match value {
            CliCategory::Evtx => ToolCategory::Evtx,
            CliCategory::Hive => ToolCategory::Hive,
            CliCategory::Srum => ToolCategory::Srum,
            CliCategory::Artifacts => ToolCategory::Artifacts,
            CliCategory::Crash => ToolCategory::Crash,
            CliCategory::Posture => ToolCategory::Posture,
        }
    }
}

/// `.reg` output format for `hive export`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum CliRegFormat {
    #[default]
    Regedit5,
    Regedit4,
}

impl From<CliRegFormat> for RegExportFormat {
    fn from(value: CliRegFormat) -> Self {
        match value {
            CliRegFormat::Regedit5 => RegExportFormat::Regedit5,
            CliRegFormat::Regedit4 => RegExportFormat::Regedit4,
        }
    }
}

/// Unified 45-tool pure-Rust read-only Windows DFIR CLI.
#[derive(Debug, Parser)]
#[command(
    name = "forensics2rust",
    author = "Forensics2Rust Contributors",
    version,
    about = "45-tool pure-Rust read-only Windows DFIR suite (EVTX, Registry, SRUM, Artifacts, Crash, Posture)"
)]
pub struct Cli {
    /// Logging level written strictly to stderr (error, warn, info, debug, trace)
    #[arg(long, global = true, default_value = "warn")]
    pub log_level: String,

    /// Optional log file path (non-ANSI structured logs)
    #[arg(long, global = true, value_name = "FILE")]
    pub log_file: Option<PathBuf>,

    /// Offline forensic artifact file or directory (omit for live Windows OS collection)
    #[arg(long = "source", visible_alias = "offline", global = true, value_name = "PATH")]
    pub source: Option<PathBuf>,

    /// Output format for tabular views and exports
    #[arg(short = 'f', long, global = true, value_enum, default_value_t = CliOutputFormat::Table)]
    pub format: CliOutputFormat,

    /// Destination file or directory path for output / exports
    #[arg(
        short = 'o',
        long = "out",
        visible_alias = "output",
        global = true,
        value_name = "PATH"
    )]
    pub output: Option<PathBuf>,

    /// Write SHA-256/SHA-512 custody manifest JSON to PATH (or enable sidecar beside --out)
    #[arg(long, global = true, value_name = "PATH")]
    pub custody: Option<PathBuf>,

    /// GetNir filter expression (e.g. "event_id == 4688 && channel contains 'Security'")
    #[arg(long, global = true, value_name = "EXPR")]
    pub filter: Option<String>,

    /// Alias for GetNir filter expression
    #[arg(long, global = true, value_name = "EXPR")]
    pub getnir: Option<String>,

    /// Comma-separated sort specification (e.g. "timestamp:desc,event_id:asc" or "-timestamp")
    #[arg(long, global = true, value_name = "SPEC")]
    pub sort: Option<String>,

    /// Comma-separated column IDs to project
    #[arg(long, global = true, value_name = "COLS")]
    pub columns: Option<String>,

    /// Maximum number of table rows to return
    #[arg(long, global = true)]
    pub limit: Option<usize>,

    /// Starting row offset for pagination
    #[arg(long, global = true)]
    pub offset: Option<usize>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Args, Debug, Default, Clone)]
pub struct SourcePathArgs {
    /// Optional positional offline artifact file or directory path
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// List all 45 registered read-only DFIR tools
    List {
        /// Output catalog as JSON
        #[arg(long)]
        json: bool,
    },
    /// Inspect platform, elevation, and artifact readiness diagnostics
    Diag {
        /// Output diagnostics as JSON
        #[arg(long)]
        json: bool,
    },
    /// Export single tool or category/suite bundle with SHA-256/SHA-512 custody manifest
    #[command(visible_alias = "report")]
    Export(ExportArgs),
    /// Compare two offline forensic runs for any tool using TableTextCompare
    Diff(DiffArgs),
    /// Run the strictly read-only JSON-RPC 2.0 stdio MCP server or print the 45-tool schema
    Mcp {
        /// Print all 45 MCP tool schemas as JSON and exit
        #[arg(long)]
        tools: bool,
    },
    /// Launch the native Win32 (forensics2rust-win32) or Iced (forensics2rust-iced) GUI
    Gui {
        /// Launch the cross-platform Iced GUI instead of native Win32
        #[arg(long)]
        iced: bool,
        /// Initial tool ID to select on startup (e.g. evtx.all)
        #[arg(long, value_name = "TOOL_ID")]
        tool: Option<String>,
        /// Start GUI in light mode
        #[arg(long)]
        light: bool,
    },
    /// 14 Windows Event Log (EVTX) DFIR views
    Evtx {
        #[command(subcommand)]
        action: EvtxSubcommand,
    },
    /// 6 Registry Hive (live, offline regf, diff, find, export, ETW watch) tools
    Hive {
        #[command(subcommand)]
        action: HiveSubcommand,
    },
    /// 4 Pure-Rust ESE SRUDB.dat telemetry views
    Srum {
        #[command(subcommand)]
        action: SrumSubcommand,
    },
    /// 14 Windows execution, shell, USB, profile, and VSS artifact tools
    Artifacts {
        #[command(subcommand)]
        action: ArtifactsSubcommand,
    },
    /// 3 Minidump (MDMP) and Windows Error Reporting (WER) crash views
    Crash {
        #[command(subcommand)]
        action: CrashSubcommand,
    },
    /// 4 Windows Updates, Defender, and SecurityCenter2 posture views
    Posture {
        #[command(subcommand)]
        action: PostureSubcommand,
    },
}

#[derive(Args, Debug, Default)]
pub struct ExportArgs {
    /// Export a single tool by canonical ID (e.g. evtx.all)
    #[arg(long, value_name = "TOOL_ID")]
    pub tool: Option<String>,
    /// Export all tools in a single category
    #[arg(long, value_enum)]
    pub category: Option<CliCategory>,
    /// Include all 45 catalog tools in a multi-table bundle (default when --tool and --category are omitted)
    #[arg(long)]
    pub all: bool,
    /// Optional positional offline source path
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct DiffArgs {
    /// Left/baseline offline artifact file or directory
    #[arg(long, value_name = "PATH")]
    pub left: PathBuf,
    /// Right/target offline artifact file or directory
    #[arg(long, value_name = "PATH")]
    pub right: PathBuf,
    /// Canonical tool ID to compare (e.g. evtx.all, hive.offline, posture.updates)
    #[arg(long, default_value = "hive.offline", value_name = "TOOL_ID")]
    pub tool: String,
    /// Comma-separated key columns used to match rows across left and right tables
    #[arg(long, value_name = "COLS")]
    pub keys: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum EvtxSubcommand {
    /// FullEventLogView — all EVTX channels and files
    All(SourcePathArgs),
    /// MyEventViewer — Application, System, and Security unified view
    Legacy(SourcePathArgs),
    /// EventLogChannelsView — EVTX channel metadata and status
    Channels(SourcePathArgs),
    /// EventLogSourcesView — Event Log publishers and provider DLLs
    Sources(SourcePathArgs),
    /// WinLogOnView — Security EID 4624/4634/4647/4625 logon sessions
    Logon(SourcePathArgs),
    /// TurnedOnTimesView — System boot/shutdown/unexpected-shutdown events
    Uptime(SourcePathArgs),
    /// WifiHistoryView — WLAN-AutoConfig connection history
    Wifi(SourcePathArgs),
    /// WinDefLogView — Windows Defender Operational log view
    Defender(SourcePathArgs),
    /// ComputerTimeLine — cross-channel normalized EVTX timeline
    Timeline(SourcePathArgs),
    /// TerminalServices RDP logon/session history
    Rdp(SourcePathArgs),
    /// PowerShell script block and module audit log view
    Powershell(SourcePathArgs),
    /// Security 4688 and Sysmon 1 process creation view
    Process(SourcePathArgs),
    /// Task Scheduler Operational execution view
    Tasks(SourcePathArgs),
    /// Kernel-PnP and DriverFrameworks USB/PnP event view
    Usb(SourcePathArgs),
}

#[derive(Subcommand, Debug)]
pub enum HiveSubcommand {
    /// RegScanner — recursive live or offline Registry scanner
    Scan {
        #[command(flatten)]
        src: SourcePathArgs,
        /// Optional key substring/regex filter
        #[arg(long)]
        key_pattern: Option<String>,
        /// Optional value name substring/regex filter
        #[arg(long)]
        value_pattern: Option<String>,
        /// Interpret patterns as regular expressions
        #[arg(long)]
        regex: bool,
    },
    /// RegistryChangesView — compare snapshots, live hives, or offline regf files
    Diff {
        #[command(flatten)]
        src: SourcePathArgs,
        /// Right/target hive or snapshot path for two-hive comparison
        #[arg(long, value_name = "PATH")]
        right: Option<PathBuf>,
        /// Optional Registry root prefix label
        #[arg(long)]
        root_prefix: Option<String>,
    },
    /// OfflineRegistryView — pure-Rust regf/hbin key and value browser
    Offline {
        #[command(flatten)]
        src: SourcePathArgs,
        /// Optional key path prefix to filter traversal
        #[arg(long)]
        key_prefix: Option<String>,
    },
    /// OfflineRegistryFinder — pure-Rust regf deep search
    Find {
        #[command(flatten)]
        src: SourcePathArgs,
        /// Text query to match against key paths, value names, and decoded data
        #[arg(long)]
        query: Option<String>,
        /// Hex byte pattern (e.g. "de ad be ef" or "deadbeef")
        #[arg(long)]
        hex: Option<String>,
    },
    /// RegFileExport — tolerant regf to .reg (REGEDIT4/5) exporter
    Export {
        #[command(flatten)]
        src: SourcePathArgs,
        /// .reg script format (regedit5 or regedit4)
        #[arg(long, value_enum, default_value_t = CliRegFormat::Regedit5)]
        reg_format: CliRegFormat,
        /// Write rendered .reg script text to PATH
        #[arg(long, value_name = "FILE")]
        reg_out: Option<PathBuf>,
    },
    /// RegFromApp — ETW Kernel-Registry monitor and .reg/F2RETW01 trace parser
    Watch(SourcePathArgs),
}

#[derive(Subcommand, Debug)]
pub enum SrumSubcommand {
    /// ESEDatabaseView — MSysObjects catalog and generic ESE table browser
    Db {
        #[command(flatten)]
        src: SourcePathArgs,
        /// Specific ESE table name to inspect dynamically
        #[arg(long)]
        table: Option<String>,
    },
    /// NetworkUsageView — SRUM {973F5D5C-...} per-app network usage
    Net(SourcePathArgs),
    /// SRUM {D10CA2FE-...} Application Resource Usage view
    App(SourcePathArgs),
    /// SRUM {FEE4E14F-...} Energy and {DD6636C4-...} Network Connectivity view
    Energy(SourcePathArgs),
}

#[derive(Subcommand, Debug)]
pub enum ArtifactsSubcommand {
    /// LastActivityView — cross-artifact forensic activity timeline
    Activity(SourcePathArgs),
    /// WinPrefetchView — MAM\x04 / SCCA .pf Prefetch parser
    Prefetch(SourcePathArgs),
    /// JumpListsView — OLE2/CFBF DestList and LNK parser
    Jumplists(SourcePathArgs),
    /// ShellBagsView — BagMRU SHITEMID PIDL parser
    Shellbags(SourcePathArgs),
    /// UserAssistView — ROT13 and 16/72-byte execution counter parser
    Userassist(SourcePathArgs),
    /// MUICacheView — MuiCache Registry key parser
    Muicache(SourcePathArgs),
    /// OpenSaveFilesView — OpenSavePidlMRU and LastVisitedPidlMRU decoder
    Opensave(SourcePathArgs),
    /// RecentFilesView — [MS-SHLLINK] .lnk recent files parser
    Recent(SourcePathArgs),
    /// ExecutedProgramsList — aggregated execution evidence
    Executed(SourcePathArgs),
    /// USBDeview — USBSTOR/USB/MountedDevices/SetupAPI inventory
    UsbDevices(SourcePathArgs),
    /// USBLogView — setupapi.dev.log and PnP plug/unplug view
    UsbLog(SourcePathArgs),
    /// ShadowCopyView — read-only VSS catalog and shadow copy enumeration
    Vss(SourcePathArgs),
    /// PreviousFilesRecovery — read-only shadow-volume browser and safe copy-out restore
    Previous {
        #[command(flatten)]
        src: SourcePathArgs,
        /// Safe read-only copy-out of a single shadow file (requires --dest)
        #[arg(long, value_name = "SHADOW_FILE")]
        restore: Option<PathBuf>,
        /// Destination file path for --restore copy-out
        #[arg(long, value_name = "DEST_FILE")]
        dest: Option<PathBuf>,
    },
    /// UserProfilesView — ProfileList live and offline SOFTWARE hive view
    Profiles(SourcePathArgs),
}

#[derive(Subcommand, Debug)]
pub enum CrashSubcommand {
    /// BlueScreenView — pure-Rust MDMP kernel/BSOD minidump analyzer
    Bsod(SourcePathArgs),
    /// AppCrashView — UTF-16LE / UTF-8 Report.wer parser
    Wer(SourcePathArgs),
    /// WinCrashReport — user-mode MDMP and PE export crash report viewer
    Report(SourcePathArgs),
}

#[derive(Subcommand, Debug)]
pub enum PostureSubcommand {
    /// WinUpdatesView — WUA COM and offline DataStore.edb update history
    Updates(SourcePathArgs),
    /// FullUpdatesHistoryView — store.db, CBS.log, and DataStore.edb history
    FullUpdates(SourcePathArgs),
    /// Windows Defender posture (MSFT_MpComputerStatus / Registry)
    DefenderStatus(SourcePathArgs),
    /// Windows SecurityCenter2 AV/Firewall/AntiSpyware bitmask posture
    SecurityCenter(SourcePathArgs),
}

/// Executes the parsed CLI invocation and writes output to `stdout` or `--out`.
pub fn run_cli(cli: &Cli) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    run_cli_with_writer(cli, &mut stdout)
}

/// Executes `cli` writing stdout output to `out` (facilitates clean in-process E2E tests).
pub fn run_cli_with_writer<W: Write>(cli: &Cli, out: &mut W) -> Result<()> {
    match &cli.command {
        None => {
            print_tool_list(false, out)?;
            Ok(())
        }
        Some(Commands::List { json }) => {
            print_tool_list(*json, out)?;
            Ok(())
        }
        Some(Commands::Diag { json }) => run_diag(cli, *json, out),
        Some(Commands::Export(args)) => run_export_command(cli, args, out),
        Some(Commands::Diff(args)) => run_diff_command(cli, args, out),
        Some(Commands::Mcp { tools }) => {
            let source = effective_source(cli.source.as_ref(), None);
            if *tools {
                let json = tools_manifest_json(PolicyMode::ReadOnlyOnly, source)?;
                writeln!(out, "{json}")?;
                Ok(())
            } else {
                serve_stdio(PolicyMode::ReadOnlyOnly, source)
            }
        }
        Some(Commands::Gui { iced, tool, light }) => launch_gui(*iced, cli.source.as_deref(), tool.as_deref(), *light),
        Some(Commands::Evtx { action }) => {
            let (tool_id, local_path) = match action {
                EvtxSubcommand::All(s) => ("evtx.all", s.path.as_ref()),
                EvtxSubcommand::Legacy(s) => ("evtx.legacy", s.path.as_ref()),
                EvtxSubcommand::Channels(s) => ("evtx.channels", s.path.as_ref()),
                EvtxSubcommand::Sources(s) => ("evtx.sources", s.path.as_ref()),
                EvtxSubcommand::Logon(s) => ("evtx.logon", s.path.as_ref()),
                EvtxSubcommand::Uptime(s) => ("evtx.uptime", s.path.as_ref()),
                EvtxSubcommand::Wifi(s) => ("evtx.wifi", s.path.as_ref()),
                EvtxSubcommand::Defender(s) => ("evtx.defender", s.path.as_ref()),
                EvtxSubcommand::Timeline(s) => ("evtx.timeline", s.path.as_ref()),
                EvtxSubcommand::Rdp(s) => ("evtx.rdp", s.path.as_ref()),
                EvtxSubcommand::Powershell(s) => ("evtx.powershell", s.path.as_ref()),
                EvtxSubcommand::Process(s) => ("evtx.process", s.path.as_ref()),
                EvtxSubcommand::Tasks(s) => ("evtx.tasks", s.path.as_ref()),
                EvtxSubcommand::Usb(s) => ("evtx.usb", s.path.as_ref()),
            };
            let source = effective_source(cli.source.as_ref(), local_path);
            let resolved = resolve_tool_source(tool_id, &source)?;
            let provider =
                provider_for_tool(tool_id, &resolved).ok_or_else(|| anyhow!("provider '{tool_id}' not registered"))?;
            execute_and_emit_provider(cli, provider.as_ref(), &resolved, out)
        }
        Some(Commands::Hive { action }) => run_hive_subcommand(cli, action, out),
        Some(Commands::Srum { action }) => run_srum_subcommand(cli, action, out),
        Some(Commands::Artifacts { action }) => run_artifacts_subcommand(cli, action, out),
        Some(Commands::Crash { action }) => {
            let (tool_id, local_path) = match action {
                CrashSubcommand::Bsod(s) => ("crash.bsod", s.path.as_ref()),
                CrashSubcommand::Wer(s) => ("crash.wer", s.path.as_ref()),
                CrashSubcommand::Report(s) => ("crash.report", s.path.as_ref()),
            };
            let source = effective_source(cli.source.as_ref(), local_path);
            let provider =
                provider_for_tool(tool_id, &source).ok_or_else(|| anyhow!("provider '{tool_id}' not registered"))?;
            execute_and_emit_provider(cli, provider.as_ref(), &source, out)
        }
        Some(Commands::Posture { action }) => {
            let (tool_id, local_path) = match action {
                PostureSubcommand::Updates(s) => ("posture.updates", s.path.as_ref()),
                PostureSubcommand::FullUpdates(s) => ("posture.full_updates", s.path.as_ref()),
                PostureSubcommand::DefenderStatus(s) => ("posture.defender_status", s.path.as_ref()),
                PostureSubcommand::SecurityCenter(s) => ("posture.security_center", s.path.as_ref()),
            };
            let source = effective_source(cli.source.as_ref(), local_path);
            let provider =
                provider_for_tool(tool_id, &source).ok_or_else(|| anyhow!("provider '{tool_id}' not registered"))?;
            execute_and_emit_provider(cli, provider.as_ref(), &source, out)
        }
    }
}

fn run_hive_subcommand<W: Write>(cli: &Cli, action: &HiveSubcommand, out: &mut W) -> Result<()> {
    match action {
        HiveSubcommand::Scan {
            src,
            key_pattern,
            value_pattern,
            regex,
        } => {
            let source = resolve_tool_source("hive.scan", &effective_source(cli.source.as_ref(), src.path.as_ref()))?;
            let opts = ScanOptions {
                key_pattern: key_pattern.clone(),
                value_name_pattern: value_pattern.clone(),
                use_regex: *regex,
                ..ScanOptions::default()
            };
            let provider = RegScannerProvider::new(source.clone()).with_options(opts);
            execute_and_emit_provider(cli, &provider, &source, out)
        }
        HiveSubcommand::Diff {
            src,
            right,
            root_prefix,
        } => {
            let left = resolve_tool_source("hive.diff", &effective_source(cli.source.as_ref(), src.path.as_ref()))?;
            let mut provider = match right {
                Some(right_path) => {
                    RegistryChangesProvider::between(left.clone(), ForensicSource::OfflinePath(right_path.clone()))
                }
                None => RegistryChangesProvider::new(left.clone()),
            };
            if let Some(prefix) = root_prefix {
                provider = provider.with_root_prefix(Some(prefix.clone()));
            }
            execute_and_emit_provider(cli, &provider, &left, out)
        }
        HiveSubcommand::Offline { src, key_prefix } => {
            let source = resolve_tool_source(
                "hive.offline",
                &effective_source(cli.source.as_ref(), src.path.as_ref()),
            )?;
            let mut provider = OfflineRegistryProvider::new(source.clone());
            if let Some(prefix) = key_prefix {
                provider = provider.with_key_prefix(Some(prefix.clone()));
            }
            execute_and_emit_provider(cli, &provider, &source, out)
        }
        HiveSubcommand::Find { src, query, hex } => {
            let source = resolve_tool_source("hive.find", &effective_source(cli.source.as_ref(), src.path.as_ref()))?;
            let mut criteria = FindCriteria::default();
            if let Some(q) = query {
                criteria = criteria.with_text(q);
            }
            if let Some(hex_str) = hex {
                let bytes = parse_hex_bytes(hex_str)?;
                criteria = criteria.with_hex(bytes);
            }
            let provider = OfflineFinderProvider::new(source.clone()).with_criteria(criteria);
            execute_and_emit_provider(cli, &provider, &source, out)
        }
        HiveSubcommand::Export {
            src,
            reg_format,
            reg_out,
        } => {
            let source = resolve_tool_source("hive.export", &effective_source(cli.source.as_ref(), src.path.as_ref()))?;
            let provider = RegFileExportProvider::new(source.clone()).with_format((*reg_format).into());
            if let Some(reg_path) = reg_out {
                let reg_text = provider.export_to_string()?;
                if let Some(parent) = reg_path.parent().filter(|p| !p.as_os_str().is_empty()) {
                    fs::create_dir_all(parent)?;
                }
                fs::write(reg_path, reg_text)?;
            }
            execute_and_emit_provider(cli, &provider, &source, out)
        }
        HiveSubcommand::Watch(s) => {
            let source = resolve_tool_source("hive.watch", &effective_source(cli.source.as_ref(), s.path.as_ref()))?;
            let provider = provider_for_tool("hive.watch", &source)
                .ok_or_else(|| anyhow!("provider 'hive.watch' not registered"))?;
            execute_and_emit_provider(cli, provider.as_ref(), &source, out)
        }
    }
}

fn run_srum_subcommand<W: Write>(cli: &Cli, action: &SrumSubcommand, out: &mut W) -> Result<()> {
    match action {
        SrumSubcommand::Db { src, table } => {
            let source = resolve_tool_source("srum.db", &effective_source(cli.source.as_ref(), src.path.as_ref()))?;
            let provider = match table {
                Some(t) => SrumDbProvider::for_table(source.clone(), t),
                None => SrumDbProvider::new(source.clone()),
            };
            execute_and_emit_provider(cli, &provider, &source, out)
        }
        SrumSubcommand::Net(s) => {
            let source = resolve_tool_source("srum.net", &effective_source(cli.source.as_ref(), s.path.as_ref()))?;
            let provider =
                provider_for_tool("srum.net", &source).ok_or_else(|| anyhow!("provider 'srum.net' not registered"))?;
            execute_and_emit_provider(cli, provider.as_ref(), &source, out)
        }
        SrumSubcommand::App(s) => {
            let source = resolve_tool_source("srum.app", &effective_source(cli.source.as_ref(), s.path.as_ref()))?;
            let provider =
                provider_for_tool("srum.app", &source).ok_or_else(|| anyhow!("provider 'srum.app' not registered"))?;
            execute_and_emit_provider(cli, provider.as_ref(), &source, out)
        }
        SrumSubcommand::Energy(s) => {
            let source = resolve_tool_source("srum.energy", &effective_source(cli.source.as_ref(), s.path.as_ref()))?;
            let provider = provider_for_tool("srum.energy", &source)
                .ok_or_else(|| anyhow!("provider 'srum.energy' not registered"))?;
            execute_and_emit_provider(cli, provider.as_ref(), &source, out)
        }
    }
}

fn run_artifacts_subcommand<W: Write>(cli: &Cli, action: &ArtifactsSubcommand, out: &mut W) -> Result<()> {
    if let ArtifactsSubcommand::Previous {
        src,
        restore: Some(shadow_file),
        dest,
    } = action
    {
        let dest_path = dest
            .as_ref()
            .ok_or_else(|| anyhow!("--dest <DEST_FILE> is required when --restore is specified"))?;
        let copied = restore_previous_file(shadow_file, dest_path)?;
        let _ = src;
        writeln!(
            out,
            "Restored {} bytes (read-only copy) from '{}' to '{}'",
            copied,
            shadow_file.display(),
            dest_path.display()
        )?;
        return Ok(());
    }

    let (tool_id, local_path) = match action {
        ArtifactsSubcommand::Activity(s) => ("artifacts.activity", s.path.as_ref()),
        ArtifactsSubcommand::Prefetch(s) => ("artifacts.prefetch", s.path.as_ref()),
        ArtifactsSubcommand::Jumplists(s) => ("artifacts.jumplists", s.path.as_ref()),
        ArtifactsSubcommand::Shellbags(s) => ("artifacts.shellbags", s.path.as_ref()),
        ArtifactsSubcommand::Userassist(s) => ("artifacts.userassist", s.path.as_ref()),
        ArtifactsSubcommand::Muicache(s) => ("artifacts.muicache", s.path.as_ref()),
        ArtifactsSubcommand::Opensave(s) => ("artifacts.opensave", s.path.as_ref()),
        ArtifactsSubcommand::Recent(s) => ("artifacts.recent", s.path.as_ref()),
        ArtifactsSubcommand::Executed(s) => ("artifacts.executed", s.path.as_ref()),
        ArtifactsSubcommand::UsbDevices(s) => ("artifacts.usb_devices", s.path.as_ref()),
        ArtifactsSubcommand::UsbLog(s) => ("artifacts.usb_log", s.path.as_ref()),
        ArtifactsSubcommand::Vss(s) => ("artifacts.vss", s.path.as_ref()),
        ArtifactsSubcommand::Previous { src, .. } => ("artifacts.previous", src.path.as_ref()),
        ArtifactsSubcommand::Profiles(s) => ("artifacts.profiles", s.path.as_ref()),
    };

    let source = effective_source(cli.source.as_ref(), local_path);
    let provider = provider_for_tool(tool_id, &source).ok_or_else(|| anyhow!("provider '{tool_id}' not registered"))?;
    execute_and_emit_provider(cli, provider.as_ref(), &source, out)
}

fn effective_source(global: Option<&PathBuf>, local: Option<&PathBuf>) -> ForensicSource {
    ForensicSource::from_optional_path(local.cloned().or_else(|| global.cloned()))
}

fn active_filter_expr(cli: &Cli) -> Result<Option<&str>> {
    match (cli.filter.as_deref(), cli.getnir.as_deref()) {
        (Some(f), Some(g)) if f.trim() != g.trim() => {
            bail!("conflicting --filter and --getnir expressions supplied")
        }
        (Some(f), _) => Ok(Some(f)),
        (None, Some(g)) => Ok(Some(g)),
        (None, None) => Ok(None),
    }
}

fn parsed_columns(cli: &Cli) -> Option<Vec<String>> {
    cli.columns.as_deref().and_then(|raw| {
        let cols: Vec<String> = raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if cols.is_empty() { None } else { Some(cols) }
    })
}

fn query_provider_with_cli_flags(cli: &Cli, provider: &dyn TableProvider) -> Result<TableData> {
    let filter = active_filter_expr(cli)?;
    let cols = parsed_columns(cli);
    let data = QueryHelper::query_provider(
        provider,
        cols,
        filter,
        cli.sort.as_deref(),
        cli.offset.unwrap_or(0),
        cli.limit,
    )?;
    Ok(data)
}

fn execute_and_emit_provider<W: Write>(
    cli: &Cli,
    provider: &dyn TableProvider,
    source: &ForensicSource,
    out: &mut W,
) -> Result<()> {
    let data = query_provider_with_cli_flags(cli, provider)?;
    emit_table_data(cli, &data, source, out)
}

fn emit_table_data<W: Write>(cli: &Cli, data: &TableData, source: &ForensicSource, out: &mut W) -> Result<()> {
    let report_opts = ForensicReportOptions::default().with_case_metadata(None, None, None, Some(source.label()));

    if let Some(out_path) = &cli.output {
        let fmt = cli.format.to_export_format().unwrap_or(ExportFormat::Json);
        let mut opts = report_opts;
        opts.write_custody_sidecar = cli.custody.is_none();
        let report = write_table_report(data, out_path, fmt, &opts)?;
        if let Some(custody_path) = &cli.custody {
            forensics2rust_report::write_custody_manifest_json(&report.custody, custody_path)?;
        }
        writeln!(
            out,
            "Exported {} rows ({}) -> {} [sha256: {}]",
            data.rows.len(),
            fmt,
            out_path.display(),
            report.custody.merkle_root_sha256
        )?;
        return Ok(());
    }

    if let Some(fmt) = cli.format.to_export_format() {
        let mut bytes = render_table_report(data, fmt, &report_opts)?;
        if !bytes.ends_with(b"\n") {
            bytes.push(b'\n');
        }
        out.write_all(&bytes)?;
        if let Some(custody_path) = &cli.custody {
            let leaf = forensics2rust_report::CustodyLeaf {
                index: 0,
                path: format!("stdout:{}.{}", data.schema.tool_id, fmt.extension()),
                size_bytes: bytes.len() as u64,
                sha256: forensics2rust_report::sha256_hex(&bytes),
                sha512: forensics2rust_report::sha512_hex(&bytes),
            };
            let manifest = forensics2rust_report::build_custody_manifest(
                &data.schema.tool_id,
                env!("CARGO_PKG_VERSION"),
                vec![leaf],
            );
            forensics2rust_report::write_custody_manifest_json(&manifest, custody_path)?;
        }
        return Ok(());
    }

    render_ascii_table(data, out)?;
    if let Some(custody_path) = &cli.custody {
        let bytes = render_table_report(data, ExportFormat::Json, &report_opts)?;
        let leaf = forensics2rust_report::CustodyLeaf {
            index: 0,
            path: format!("table:{}", data.schema.tool_id),
            size_bytes: bytes.len() as u64,
            sha256: forensics2rust_report::sha256_hex(&bytes),
            sha512: forensics2rust_report::sha512_hex(&bytes),
        };
        let manifest =
            forensics2rust_report::build_custody_manifest(&data.schema.tool_id, env!("CARGO_PKG_VERSION"), vec![leaf]);
        forensics2rust_report::write_custody_manifest_json(&manifest, custody_path)?;
    }
    Ok(())
}

fn run_export_command<W: Write>(cli: &Cli, args: &ExportArgs, out: &mut W) -> Result<()> {
    let source = effective_source(cli.source.as_ref(), args.path.as_ref());
    let fmt = cli.format.to_export_format().unwrap_or(ExportFormat::Json);
    let report_opts = ForensicReportOptions::default().with_case_metadata(None, None, None, Some(source.label()));

    if let Some(tool_id) = &args.tool {
        let resolved = resolve_tool_source(tool_id, &source)?;
        let provider = provider_for_tool(tool_id, &resolved).ok_or_else(|| anyhow!("unknown tool ID '{tool_id}'"))?;
        let data = query_provider_with_cli_flags(cli, provider.as_ref())?;
        if let Some(out_path) = &cli.output {
            let mut opts = report_opts;
            opts.write_custody_sidecar = cli.custody.is_none();
            let report = write_table_report(&data, out_path, fmt, &opts)?;
            if let Some(custody_path) = &cli.custody {
                forensics2rust_report::write_custody_manifest_json(&report.custody, custody_path)?;
            }
            writeln!(
                out,
                "Exported '{}' ({} rows, {}) -> {} [merkle_sha256={}]",
                tool_id,
                data.rows.len(),
                fmt,
                out_path.display(),
                report.custody.merkle_root_sha256
            )?;
        } else {
            let out_dir = PathBuf::from("forensics2rust_report");
            let report = write_bundle_report(&[data], &out_dir, fmt, &report_opts)?;
            if let Some(custody_path) = &cli.custody {
                forensics2rust_report::write_custody_manifest_json(&report.custody, custody_path)?;
            }
            writeln!(
                out,
                "Exported '{}' bundle -> {} ({} artifacts, merkle_sha256={})",
                tool_id,
                out_dir.display(),
                report.custody.artifact_count,
                report.custody.merkle_root_sha256
            )?;
        }
        return Ok(());
    }

    let providers: Vec<Arc<dyn TableProvider>> = if let Some(cat) = args.category {
        let target_cat: ToolCategory = cat.into();
        tools_by_category(target_cat)
            .filter_map(|desc| {
                let resolved = resolve_tool_source(desc.tool_id, &source).unwrap_or_else(|_| source.clone());
                provider_for_tool(desc.tool_id, &resolved)
            })
            .collect()
    } else {
        let _ = args.all;
        collect_all_providers(&source)
    };

    let out_dir = cli
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from("forensics2rust_report"));

    let mut tables = Vec::new();
    let mut skipped = 0usize;
    for provider in &providers {
        match query_provider_with_cli_flags(cli, provider.as_ref()) {
            Ok(data) => tables.push(data),
            Err(err) => {
                skipped += 1;
                tracing::warn!(tool_id = provider.tool_id(), error = %err, "skipping tool during bundle export");
            }
        }
    }

    if tables.is_empty() {
        bail!("no tools produced exportable tables from source '{}'", source.label());
    }

    let report = write_bundle_report(&tables, &out_dir, fmt, &report_opts)?;
    if let Some(custody_path) = &cli.custody {
        forensics2rust_report::write_custody_manifest_json(&report.custody, custody_path)?;
    }
    writeln!(
        out,
        "Bundle exported {} tables ({} skipped) -> {} [merkle_sha256={}, merkle_sha512={}]",
        report.custody.artifact_count,
        skipped,
        out_dir.display(),
        report.custody.merkle_root_sha256,
        report.custody.merkle_root_sha512
    )?;
    Ok(())
}

fn run_diff_command<W: Write>(cli: &Cli, args: &DiffArgs, out: &mut W) -> Result<()> {
    let left_src = resolve_tool_source(&args.tool, &ForensicSource::OfflinePath(args.left.clone()))?;
    let right_src = resolve_tool_source(&args.tool, &ForensicSource::OfflinePath(args.right.clone()))?;

    let left_prov = provider_for_tool(&args.tool, &left_src).ok_or_else(|| anyhow!("unknown tool '{}'", args.tool))?;
    let right_prov =
        provider_for_tool(&args.tool, &right_src).ok_or_else(|| anyhow!("unknown tool '{}'", args.tool))?;

    let left_data = QueryHelper::query_provider(left_prov.as_ref(), None, None, None, 0, None)?;
    let right_data = QueryHelper::query_provider(right_prov.as_ref(), None, None, None, 0, None)?;

    let key_cols: Vec<String> = match &args.keys {
        Some(raw) => raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        None => left_data
            .schema
            .columns
            .first()
            .map(|c| vec![c.id.clone()])
            .unwrap_or_default(),
    };

    let diff_data = diff_tables(&left_data, &right_data, &key_cols)?;
    let filtered = QueryHelper::apply_getnir(
        &diff_data.schema,
        &diff_data.rows,
        parsed_columns(cli),
        active_filter_expr(cli)?,
        cli.sort.as_deref(),
        cli.offset.unwrap_or(0),
        cli.limit,
    )?;

    emit_table_data(cli, &filtered, &left_src, out)
}

fn print_tool_list<W: Write>(as_json: bool, out: &mut W) -> Result<()> {
    if as_json {
        writeln!(out, "{}", serde_json::to_string_pretty(FORENSIC_TOOL_CATALOG)?)?;
    } else {
        for tool in FORENSIC_TOOL_CATALOG {
            writeln!(out, "{}\t{}\t{}", tool.tool_id, tool.cli_subcommand, tool.description)?;
        }
    }
    Ok(())
}

fn run_diag<W: Write>(cli: &Cli, as_json: bool, out: &mut W) -> Result<()> {
    let source = effective_source(cli.source.as_ref(), None);
    let elevated = detect_elevation();
    let registry_tools = build_registry(PolicyMode::ReadOnlyOnly, source.clone())
        .list_tools()
        .as_array()
        .map(Vec::len)
        .unwrap_or(0);

    let source_exists = source.path().map(|p| p.exists()).unwrap_or(true);
    let source_is_dir = source.path().map(|p| p.is_dir()).unwrap_or(false);

    let mut categories = serde_json::Map::new();
    for cat in [
        ToolCategory::Evtx,
        ToolCategory::Hive,
        ToolCategory::Srum,
        ToolCategory::Artifacts,
        ToolCategory::Crash,
        ToolCategory::Posture,
    ] {
        let count = tools_by_category(cat).count();
        categories.insert(cat.as_str().to_string(), json!(count));
    }

    let diag = json!({
        "suite": "forensics2rust",
        "version": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "elevated": elevated,
        "read_only": true,
        "catalog_tools": FORENSIC_TOOL_CATALOG.len(),
        "mcp_tools": registry_tools,
        "categories": categories,
        "source": {
            "label": source.label(),
            "is_live": source.is_live(),
            "exists": source_exists,
            "is_dir": source_is_dir,
        },
        "win32_binary_found": find_sibling_binary("forensics2rust-win32").is_some(),
        "iced_binary_found": find_sibling_binary("forensics2rust-iced").is_some(),
    });

    if as_json {
        writeln!(out, "{}", serde_json::to_string_pretty(&diag)?)?;
    } else {
        writeln!(out, "forensics2rust diagnostics")?;
        writeln!(
            out,
            "  OS / Arch       : {} / {}",
            std::env::consts::OS,
            std::env::consts::ARCH
        )?;
        writeln!(out, "  Elevated        : {elevated}")?;
        writeln!(out, "  Catalog Tools   : {} (read-only)", FORENSIC_TOOL_CATALOG.len())?;
        writeln!(out, "  MCP Tools       : {registry_tools}")?;
        writeln!(out, "  Source          : {} (exists={source_exists})", source.label())?;
        writeln!(
            out,
            "  GUI Binaries    : win32={}, iced={}",
            find_sibling_binary("forensics2rust-win32").is_some(),
            find_sibling_binary("forensics2rust-iced").is_some()
        )?;
    }

    Ok(())
}

fn detect_elevation() -> bool {
    #[cfg(windows)]
    {
        // Non-invasive check: attempt to open protected SystemRoot\System32\config\SAM metadata or Security channel;
        // fallback cleanly to false when unprivileged.
        fs::OpenOptions::new().read(true).open(r"\\.\PHYSICALDRIVE0").is_ok()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn find_sibling_binary(name: &str) -> Option<PathBuf> {
    let exe_name = if cfg!(windows) && !name.ends_with(".exe") {
        format!("{name}.exe")
    } else {
        name.to_string()
    };

    if let Ok(current) = std::env::current_exe()
        && let Some(dir) = current.parent()
    {
        let candidate = dir.join(&exe_name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(&exe_name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    None
}

fn launch_gui(iced: bool, source: Option<&Path>, tool: Option<&str>, light: bool) -> Result<()> {
    let target = if iced || !cfg!(windows) {
        "forensics2rust-iced"
    } else {
        "forensics2rust-win32"
    };

    let binary = find_sibling_binary(target)
        .with_context(|| format!("could not locate GUI executable '{target}' next to forensics2rust or on PATH"))?;

    let mut cmd = Command::new(&binary);
    if let Some(src) = source {
        cmd.arg("--source").arg(src);
    }
    if let Some(t) = tool {
        cmd.arg("--tool").arg(t);
    }
    if light {
        cmd.arg("--light");
    }

    let status = cmd
        .status()
        .with_context(|| format!("failed to launch GUI binary '{}'", binary.display()))?;
    if !status.success() {
        bail!("GUI binary '{}' exited with status {status}", binary.display());
    }
    Ok(())
}

fn render_ascii_table<W: Write>(data: &TableData, out: &mut W) -> Result<()> {
    if data.schema.columns.is_empty() {
        writeln!(out, "{} (0 columns, {} rows)", data.schema.title, data.total_rows)?;
        return Ok(());
    }

    let mut widths: Vec<usize> = data
        .schema
        .columns
        .iter()
        .map(|c| c.label.chars().count().clamp(4, 48))
        .collect();

    let formatted_rows: Vec<Vec<String>> = data
        .rows
        .iter()
        .map(|row| {
            data.schema
                .columns
                .iter()
                .enumerate()
                .map(|(i, col)| {
                    let raw = row
                        .cells
                        .get(i)
                        .map(|c| c.format_human(col.col_type))
                        .unwrap_or_default();
                    let single_line = raw.replace(['\r', '\n'], " ");
                    let clipped = truncate_display(&single_line, 64);
                    widths[i] = widths[i].max(clipped.chars().count()).min(64);
                    clipped
                })
                .collect()
        })
        .collect();

    for (i, col) in data.schema.columns.iter().enumerate() {
        if i > 0 {
            write!(out, " | ")?;
        }
        write!(
            out,
            "{:<width$}",
            truncate_display(&col.label, widths[i]),
            width = widths[i]
        )?;
    }
    writeln!(out)?;

    for (i, w) in widths.iter().enumerate() {
        if i > 0 {
            write!(out, "-+-")?;
        }
        write!(out, "{}", "-".repeat(*w))?;
    }
    writeln!(out)?;

    for row in &formatted_rows {
        for (i, cell) in row.iter().enumerate() {
            if i > 0 {
                write!(out, " | ")?;
            }
            write!(out, "{:<width$}", cell, width = widths[i])?;
        }
        writeln!(out)?;
    }

    writeln!(
        out,
        "[{}] {} shown (total_rows={})",
        data.schema.tool_id,
        data.rows.len(),
        data.total_rows
    )?;
    Ok(())
}

fn truncate_display(s: &str, max_chars: usize) -> String {
    let count = s.chars().count();
    if count <= max_chars {
        s.to_string()
    } else if max_chars <= 3 {
        s.chars().take(max_chars).collect()
    } else {
        let mut out: String = s.chars().take(max_chars - 3).collect();
        out.push_str("...");
        out
    }
}

fn parse_hex_bytes(raw: &str) -> Result<Vec<u8>> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':' && *c != '-')
        .collect();
    let stripped = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
        .unwrap_or(&cleaned);
    if !stripped.len().is_multiple_of(2) || stripped.is_empty() {
        bail!("hex pattern must contain an even non-zero number of hex digits");
    }
    let mut out = Vec::with_capacity(stripped.len() / 2);
    let (chunks, _) = stripped.as_bytes().as_chunks::<2>();
    for chunk in chunks {
        let pair = std::str::from_utf8(chunk)?;
        let byte = u8::from_str_radix(pair, 16).with_context(|| format!("invalid hex byte '{pair}'"))?;
        out.push(byte);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_debug_assert_and_45_subcommands_match_catalog() {
        Cli::command().debug_assert();

        for desc in FORENSIC_TOOL_CATALOG {
            let mut argv = vec!["forensics2rust"];
            argv.extend(desc.cli_subcommand.split_whitespace());
            let parsed = Cli::try_parse_from(&argv);
            assert!(
                parsed.is_ok(),
                "failed to parse catalog cli_subcommand '{}': {:?}",
                desc.cli_subcommand,
                parsed.err()
            );
        }
    }

    #[test]
    fn cli_list_diag_and_mcp_tools_succeed() {
        let list_cli = Cli::try_parse_from(["forensics2rust", "list"]).unwrap();
        let mut buf = Vec::new();
        run_cli_with_writer(&list_cli, &mut buf).unwrap();
        let list_out = String::from_utf8(buf).unwrap();
        assert_eq!(list_out.lines().count(), 45);

        let diag_cli = Cli::try_parse_from(["forensics2rust", "diag", "--json"]).unwrap();
        let mut diag_buf = Vec::new();
        run_cli_with_writer(&diag_cli, &mut diag_buf).unwrap();
        let diag_json: serde_json::Value = serde_json::from_slice(&diag_buf).unwrap();
        assert_eq!(diag_json["catalog_tools"], 45);
        assert_eq!(diag_json["mcp_tools"], 45);

        let mcp_cli = Cli::try_parse_from(["forensics2rust", "mcp", "--tools"]).unwrap();
        let mut mcp_buf = Vec::new();
        run_cli_with_writer(&mcp_cli, &mut mcp_buf).unwrap();
        let tools: Vec<serde_json::Value> = serde_json::from_slice(&mcp_buf).unwrap();
        assert_eq!(tools.len(), 45);
    }
}
