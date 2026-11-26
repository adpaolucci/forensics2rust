# `forensics2rust` — 45-Tool Pure-Rust Read-Only Windows DFIR Suite

Part of the **GUAP** Ecosystem (`guap.ca`) • [**Project Hub & Web Documentation: https://forensics2rust.guap.ca**](https://forensics2rust.guap.ca) • [**Project Wiki**](https://github.com/adpaolucci/forensics2rust/wiki)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Rust: 2024](https://img.shields.io/badge/Rust-2024%20(1.88%2B)-orange.svg)](Cargo.toml)
[![Workspace: 12 Crates](https://img.shields.io/badge/Workspace-12%20Crates-emerald.svg)](Cargo.toml)
[![GUI: WinSafe Win32 + Iced 0.14](https://img.shields.io/badge/GUI-WinSafe%20Win32%20%2B%20Iced%200.14-cyan.svg)](crates/forensics2rust-win32)
[![MCP: stdio JSON-RPC](https://img.shields.io/badge/MCP-stdio%20JSON--RPC%202.0-purple.svg)](crates/forensics2rust-mcp)

Ready-to-submit **WinGet** & **Homebrew** manifests live in [`packaging/`](packaging/README.md).

**`forensics2rust`** is a 100% pure-Rust, **strictly read-only 45-tool Windows Digital Forensics and Incident Response (DFIR) suite** built on [`guap-kit`](https://github.com/adpaolucci/guap-kit). It unifies EVTX Event Log parsing, live and offline Registry hive (`regf`/`hbin`) analysis, ESE `SRUDB.dat` telemetry, execution/shell/USB/VSS artifacts, Minidump (`MDMP`) / WER crash triage, and Windows Update/Defender/SecurityCenter2 posture in four cohesive interfaces:
1. **`forensics2rust-win32`** (**WinSafe `0.0.29`**) — Native zero-GPU Win32 virtual list console (`LVS_OWNERDATA`, ComCtl v6, Per-Monitor DPI v2) safe over RDP and elevated DFIR triage sessions.
2. **`forensics2rust-iced`** (**Iced `0.14`**) — Cross-platform retained-mode GUI (`wgpu` + `tiny-skia` CPU fallback) for offline artifact triage on Windows, Linux, and macOS.
3. **`forensics2rust`** — Unified `clap` CLI exposing all 45 read-only subcommands, `GetNir` query filtering, `diff`, multi-table `export` bundles, and `diag`.
4. **`forensics2rust-mcp`** — Strictly read-only JSON-RPC 2.0 (`2024-11-05`) `stdio` MCP server exposing all 45 `TableProvider` tools (`readOnlyHint: true`, `destructiveHint: false`).

---

## Comparison: `forensics2rust` vs. Legacy DFIR Workflows

| Capability | `forensics2rust` | Scattered Legacy GUIs | Manual PowerShell / Python |
|---|---|---|---|
| **Artifact Coverage** | **45 unified views** across EVTX, `regf`, ESE SRUM, Artifacts, Crash, Posture | 45 separate single-purpose executables | Custom scripts per artifact |
| **Pure-Rust Offline Parsers** | **Binary parsers for BinXML, `regf`/`hbin`, `0x89ABCDEF` ESE, SCCA/MAM Prefetch, CFBF JumpLists, MDMP** | Windows-only API reliance on many tools | External C libraries required |
| **Spreadsheet & XSS Safety** | **RFC-4180 CSV formula neutralization + CSP-strict HTML via `guap-export`** | Unescaped CSV cells | Manual CSV escaping |
| **Chain of Custody** | **Deterministic SHA-256 + SHA-512 Merkle `CustodyManifest` on every export** | Manual file hashing | Separate hashing pass |
| **Agent Integration** | **45 read-only MCP `2024-11-05` tools (`mcp.json` / `smithery.yaml`)** | None | None |
| **Execution Safety** | **Strictly read-only; zero DLL injection, zero credential extraction** | Mixed GUI/legacy posture | Error-prone manual flags |

---

## Read-Only Posture & Scope Exclusions

- **Strictly Read-Only DFIR**: All 45 `TableProvider` views and MCP tools are strictly read-only (`readOnlyHint: true`, `destructiveHint: false`). Zero OS state is mutated; `PreviousFilesRecovery` restores strictly via safe read-only copy-out (`--source`).
- **Zero Credential Extraction**: Excludes password recovery, DPAPI/Vault/LSA secret dumping, and browser/mail credential extraction.
- **Zero DLL Injection / API Hooking**: Uses pure-Rust binary decoders, documented Win32/WMI/COM APIs, and passive ETW (`Microsoft-Windows-Kernel-Registry`).
- **Zero Retired Legacy Utilities**: Excludes obsolete/retired legacy tools (`DrWatsonLogView`, `WinUpdatesList`, etc.).

---

## Workspace Architecture (12 Crates)

```text
forensics2rust/
├── Cargo.toml                            # Workspace root (12 crates, edition 2024, resolver 2, Apache-2.0)
├── deny.toml                             # cargo-deny v2 security & license policy
├── mcp.json / smithery.yaml              # Standard MCP & Smithery manifests (45 tools)
├── metadata.json                         # Machine-readable suite & capability metadata
├── packaging/                            # WinGet & Homebrew packaging manifests
└── crates/
    ├── forensics2rust-core/              # ForensicSource, ForensicError, 45-tool catalog, FILETIME/SID/GUID/UTF-16LE/CRC32 decoders
    ├── forensics2rust-evtx/              # 14 EVTX Event Log tools & pure-Rust [MS-EVEN6] BinXML parser
    ├── forensics2rust-hive/              # 6 Registry hive tools, pure-Rust regf/hbin parser, snapshot diff, & ETW watcher
    ├── forensics2rust-srum/              # 4 ESE SRUDB.dat tools & pure-Rust 0x89ABCDEF ESE parser
    ├── forensics2rust-artifacts/         # 14 artifact tools (Prefetch, JumpLists, ShellBags, UserAssist, MUICache, Recent, USB, VSS, Profiles)
    ├── forensics2rust-crash/             # 3 Minidump (MDMP) & UTF-16LE/UTF-8 WER crash report tools
    ├── forensics2rust-posture/           # 4 Windows Update (DataStore.edb/CBS.log/WUA), Defender, & SecurityCenter2 posture tools
    ├── forensics2rust-report/            # 7-format exporter (guap-export) + SHA-256/512 Merkle custody_manifest.json
    ├── forensics2rust-mcp/               # Strictly read-only JSON-RPC 2.0 stdio MCP server (`forensics2rust-mcp`)
    ├── forensics2rust-cli/               # Unified CLI (`forensics2rust`)
    ├── forensics2rust-win32/             # Native zero-GPU Win32 virtual-list console (`forensics2rust-win32`)
    └── forensics2rust-iced/              # Cross-platform Iced 0.14 data-grid console (`forensics2rust-iced`)
```

---

## Tool Groups (45 Read-Only Tools)

### `forensics2rust-evtx` (14 Tools)
| CLI Subcommand | NirSoft / DFIR Equivalent | Primary Scope / Telemetry | MCP Tool ID |
|---|---|---|---|
| `evtx all` | `FullEventLogView` | All EVTX channels and `.evtx` files | `evtx.all` |
| `evtx legacy` | `MyEventViewer` | Unified Application, System, and Security view | `evtx.legacy` |
| `evtx channels` | `EventLogChannelsView` | EVTX channel metadata, limits, and enablement status | `evtx.channels` |
| `evtx sources` | `EventLogSourcesView` | Event Log publishers and provider message DLLs | `evtx.sources` |
| `evtx logon` | `WinLogOnView` | Security EID `4624`/`4634`/`4647`/`4625` logon sessions | `evtx.logon` |
| `evtx uptime` | `TurnedOnTimesView` | System boot, shutdown, and unexpected-shutdown events | `evtx.uptime` |
| `evtx wifi` | `WifiHistoryView` | `WLAN-AutoConfig/Operational` connection history | `evtx.wifi` |
| `evtx defender` | `WinDefLogView` | `Windows Defender/Operational` detection & scan events | `evtx.defender` |
| `evtx timeline` | `ComputerTimeLine` | Cross-channel normalized EVTX timeline | `evtx.timeline` |
| `evtx rdp` | *EVTX RDP View* | `TerminalServices` LocalSession/RemoteConnection history | `evtx.rdp` |
| `evtx powershell` | *EVTX PowerShell View* | PowerShell `4103`/`4104` script block & module audit | `evtx.powershell` |
| `evtx process` | *EVTX Process View* | Security EID `4688` & Sysmon EID `1` process creation | `evtx.process` |
| `evtx tasks` | *EVTX TaskScheduler View* | Task Scheduler Operational execution log | `evtx.tasks` |
| `evtx usb` | *EVTX USB PnP View* | `Kernel-PnP/Configuration` & DriverFrameworks USB events | `evtx.usb` |

### `forensics2rust-hive` (6 Tools)
| CLI Subcommand | NirSoft Equivalent | Mechanism | MCP Tool ID |
|---|---|---|---|
| `hive scan` | `RegScanner` | Recursive live or offline `regf` Registry scanner | `hive.scan` |
| `hive diff` | `RegistryChangesView` | Diff two hives or snapshots (`left` vs `right`) | `hive.diff` |
| `hive offline` | `OfflineRegistryView` | Pure-Rust `regf`/`hbin` cell/key/value browser | `hive.offline` |
| `hive find` | `OfflineRegistryFinder` | Pure-Rust `regf` deep substring/type search | `hive.find` |
| `hive export` | `RegFileExport` | Tolerant `regf` to `REGEDIT4`/`Windows Registry Editor 5.00` exporter | `hive.export` |
| `hive watch` | `RegFromApp` | Live ETW `Kernel-Registry` monitor & `.reg`/`F2RETW01` trace parser | `hive.watch` |

### `forensics2rust-srum` (4 Tools)
| CLI Subcommand | NirSoft / DFIR Equivalent | Primary Scope / Telemetry | MCP Tool ID |
|---|---|---|---|
| `srum db` | `ESEDatabaseView` | `MSysObjects` catalog & generic `0x89ABCDEF` ESE table browser | `srum.db` |
| `srum net` | `NetworkUsageView` | SRUM `{973F5D5C-...}` per-app & interface bytes sent/received | `srum.net` |
| `srum app` | *SRUM App Resource* | SRUM `{D10CA2FE-...}` CPU cycles, context switches, bytes I/O | `srum.app` |
| `srum energy` | *SRUM Energy/Connectivity* | SRUM `{FEE4E14F-...}` energy & `{DD6636C4-...}` connectivity | `srum.energy` |

### `forensics2rust-artifacts` (14 Tools)
| CLI Subcommand | NirSoft Equivalent | Artifact / Source Parsed | MCP Tool ID |
|---|---|---|---|
| `artifacts activity` | `LastActivityView` | Cross-artifact correlated forensic activity timeline | `artifacts.activity` |
| `artifacts prefetch` | `WinPrefetchView` | Windows `.pf` (`SCCA` & `MAM\x04` XPRESS Huffman) | `artifacts.prefetch` |
| `artifacts jumplists` | `JumpListsView` | MS-CFB `.automaticDestinations-ms` (`DestList` + `LNK`) | `artifacts.jumplists` |
| `artifacts shellbags` | `ShellBagsView` | `UsrClass.dat` `BagMRU` `SHITEMID` PIDL parser | `artifacts.shellbags` |
| `artifacts userassist` | `UserAssistView` | ROT13-decoded 16/72-byte `UserAssist` counters | `artifacts.userassist` |
| `artifacts muicache` | `MUICacheView` | `MuiCache` Registry application title strings | `artifacts.muicache` |
| `artifacts opensave` | `OpenSaveFilesView` | `OpenSavePidlMRU` & `LastVisitedPidlMRU` decoder | `artifacts.opensave` |
| `artifacts recent` | `RecentFilesView` | `[MS-SHLLINK]` `.lnk` shortcut target & timestamp decoder | `artifacts.recent` |
| `artifacts executed` | `ExecutedProgramsList` | Aggregated Prefetch, UserAssist, AppCompatCache & BAM/DAM evidence | `artifacts.executed` |
| `artifacts usb-devices` | `USBDeview` | `USBSTOR`/`USB`/`MountedDevices`/`SetupAPI` inventory | `artifacts.usb_devices` |
| `artifacts usb-log` | `USBLogView` | `setupapi.dev.log` & PnP arrival/removal correlation | `artifacts.usb_log` |
| `artifacts vss` | `ShadowCopyView` | Read-only VSS snapshot catalog enumeration | `artifacts.vss` |
| `artifacts previous` | `PreviousFilesRecovery` | Read-only previous-version directory browser & safe copy-out | `artifacts.previous` |
| `artifacts profiles` | `UserProfilesView` | `ProfileList` live & offline `SOFTWARE` hive profile view | `artifacts.profiles` |

### `forensics2rust-crash` (3 Tools) & `forensics2rust-posture` (4 Tools)
| CLI Subcommand | NirSoft / DFIR Equivalent | Artifact / Source Parsed | MCP Tool ID |
|---|---|---|---|
| `crash bsod` | `BlueScreenView` | Pure-Rust `MDMP` kernel/BSOD bugcheck & driver stack analyzer | `crash.bsod` |
| `crash wer` | `AppCrashView` | UTF-16LE / UTF-8 `Report.wer` Windows Error Reporting parser | `crash.wer` |
| `crash report` | `WinCrashReport` | User-mode `MDMP` & PE exception/module analyzer | `crash.report` |
| `posture updates` | `WinUpdatesView` | WUA COM API & offline `DataStore.edb` update history | `posture.updates` |
| `posture full-updates` | `FullUpdatesHistoryView` | Unified `DataStore.edb`, `CBS.log`, & `store.db` update timeline | `posture.full_updates` |
| `posture defender-status` | *Defender Posture* | `MSFT_MpComputerStatus` WMI / offline posture JSON & Registry | `posture.defender_status` |
| `posture security-center` | *SecurityCenter2* | AV/Firewall/AntiSpyware WSC `productState` bitmask decoder | `posture.security_center` |

---

## Usage Examples (CLI, MCP & Dual GUI)

```powershell
# List all 45 read-only DFIR tools & inspect host elevation / artifact readiness
forensics2rust list
forensics2rust diag --json

# Offline DFIR queries with GetNir filtering, sorting & RFC-4180 CSV + Merkle custody
forensics2rust --source .\evidence --filter "event_id == 4688" --sort "timestamp:desc" --limit 50 evtx all
forensics2rust --offline .\evidence\NTUSER.DAT --format json hive offline
forensics2rust --offline .\evidence\SRUDB.dat --format csv --out .\out\srum_net.csv --custody .\out\custody.json srum net
forensics2rust --source .\evidence artifacts prefetch
forensics2rust --source .\evidence crash bsod
forensics2rust --source .\evidence posture security-center

# Compare two offline hives or artifact runs deterministically
forensics2rust diff --left .\baseline\NTUSER.DAT --right .\incident\NTUSER.DAT --tool hive.offline --keys key_path,value_name

# Export a category or full 45-tool bundle with SHA-256/512 custody_manifest.json
forensics2rust --source .\evidence --format json --out .\bundle export --category posture

# Start the strictly read-only MCP stdio server (see mcp.json) or inspect all 45 schemas
forensics2rust mcp --tools
forensics2rust mcp

# Launch dual desktop GUIs
forensics2rust gui --source .\evidence --tool evtx.all
forensics2rust gui --iced --source .\evidence --tool artifacts.prefetch
```

### MCP Client Configuration (`mcp.json`)

```json
{
  "mcpServers": {
    "forensics2rust": {
      "command": "forensics2rust-mcp",
      "args": []
    }
  }
}
```

---

## Building & Testing

```powershell
cargo check --workspace --all-targets --offline --locked
cargo test --workspace --offline --locked
cargo clippy --workspace --all-targets --offline --locked -- -D warnings
cargo build --workspace --release --offline --locked
```

Emitted binaries in `target/release/`:
- `forensics2rust.exe` — Unified 45-tool DFIR CLI
- `forensics2rust-win32.exe` — Native zero-GPU Win32 virtual list console
- `forensics2rust-iced.exe` — Cross-platform Iced `0.14` console
- `forensics2rust-mcp.exe` — Strictly read-only MCP JSON-RPC 2.0 stdio server

---

## Wiki Documentation

Browse the full [`forensics2rust` Project Wiki](https://github.com/adpaolucci/forensics2rust/wiki):
- [Architecture](https://github.com/adpaolucci/forensics2rust/wiki/Architecture)
- [Forensic Parsers & 45-Tool Matrix](https://github.com/adpaolucci/forensics2rust/wiki/Forensic-Parsers-and-45-Tool-Matrix)
- [CLI Reference](https://github.com/adpaolucci/forensics2rust/wiki/CLI-Reference)
- [Dual-GUI Guide (Win32 & Iced)](https://github.com/adpaolucci/forensics2rust/wiki/Dual-GUI-Guide)
- [GUI Framework Decision & Comparison](https://github.com/adpaolucci/forensics2rust/wiki/GUI-Framework-Decision-and-Comparison)
- [MCP Server Guide](https://github.com/adpaolucci/forensics2rust/wiki/MCP-Server-Guide)
- [Reports & Forensic Exports](https://github.com/adpaolucci/forensics2rust/wiki/Reports-and-Forensic-Exports)
- [Validation Rules & Status Codes](https://github.com/adpaolucci/forensics2rust/wiki/Validation-Rules-and-Status-Codes)
- [Building, Testing & CI/CD](https://github.com/adpaolucci/forensics2rust/wiki/Building-Testing-and-CI-CD)
- [Security & Stability](https://github.com/adpaolucci/forensics2rust/wiki/Security-and-Stability)

## License

Licensed under the [**Apache License, Version 2.0**](LICENSE). See [`NOTICE`](NOTICE) for attribution.
