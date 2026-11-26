# `forensics2rust` — 45-Tool Pure-Rust Read-Only Windows DFIR Suite

Part of the **GUAP** Ecosystem (`guap.ca`) • [**Project Hub: https://forensics2rust.guap.ca**](https://forensics2rust.guap.ca) • [**Project Wiki**](https://github.com/adpaolucci/forensics2rust/wiki)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Rust: 2024](https://img.shields.io/badge/Rust-2024%20(1.88%2B)-orange.svg)](Cargo.toml)
[![Architecture: 12 Crates](https://img.shields.io/badge/Workspace-12%20Crates-emerald.svg)](Cargo.toml)
[![GUI: WinSafe Win32 + Iced 0.14](https://img.shields.io/badge/GUI-WinSafe%20Win32%20%2B%20Iced%200.14-cyan.svg)](crates/forensics2rust-win32)
[![MCP: stdio JSON-RPC](https://img.shields.io/badge/MCP-stdio%20JSON--RPC%202.0-purple.svg)](crates/forensics2rust-mcp)

**`forensics2rust`** is a 100% pure-Rust, strictly read-only 45-tool Windows Digital Forensics and Incident Response (DFIR) suite spanning EVTX Event Logs, live & offline Registry hives, ESE `SRUDB.dat` telemetry, execution/USB/VSS artifacts, Minidump/WER crash diagnostics, and Windows security/update posture.

Every tool supports deterministic offline analysis on raw artifact files/bytes as well as live Windows OS/ETW/WMI/COM collection with graceful elevation and missing-artifact diagnostics.

---

## Read-Only Posture & Scope Exclusions

- **Strictly Read-Only DFIR**: All 45 `guap_table::TableProvider` views and MCP tools are strictly `ReadOnly` (`is_read_only() == true`).
- **Zero Credential Extraction**: Excludes password recovery, DPAPI/Vault/LSA secret dumping, or credential sniffing.
- **Zero DLL Injection / API Hooking**: Uses pure-Rust binary parsers, standard Win32/WMI/COM APIs, and Windows ETW (`Microsoft-Windows-Kernel-Registry`) with zero process injection or API hooking.
- **Zero Legacy Obsolete Tools**: Excludes retired legacy tools (`DrWatsonLogView`, `WinUpdatesList`, etc.).

---

## Workspace Architecture (12 Crates)

```text
forensics2rust/
├── Cargo.toml                            # Workspace root (12 crates, edition 2024, resolver 2)
├── mcp.json                              # Standard MCP server client configuration
├── packaging/                            # WinGet & Homebrew manifests
└── crates/
    ├── forensics2rust-core/              # ForensicSource, ForensicError, 45-tool catalog, FILETIME/SID/GUID/UTF-16LE/CRC32 decoders, guap-table QueryHelper
    ├── forensics2rust-evtx/              # 14 EVTX Event Log tools & pure-Rust [MS-EVEN6] BinXML parser
    ├── forensics2rust-hive/              # 6 Registry hive tools, pure-Rust regf/hbin parser, & ETW monitor
    ├── forensics2rust-srum/              # 4 ESE SRUDB.dat tools & pure-Rust 0x89ABCDEF ESE parser
    ├── forensics2rust-crash/             # 3 Minidump (MDMP) & WER crash report tools
    ├── forensics2rust-artifacts/         # 14 artifact tools (Prefetch, JumpLists, ShellBags, UserAssist, MUICache, Recent, USB, VSS, Profiles)
    ├── forensics2rust-posture/           # 4 security & Windows Update posture tools
    ├── forensics2rust-report/            # CSV/TSV/JSON/JSONL/HTML/MD export + SHA-256/512 Merkle chain-of-custody via guap-export
    ├── forensics2rust-mcp/               # Read-only JSON-RPC 2.0 stdio MCP server via guap-mcp
    ├── forensics2rust-cli/               # Unified CLI (`forensics2rust`)
    ├── forensics2rust-win32/             # Native zero-GPU Win32 virtual-list console (`forensics2rust-win32`)
    └── forensics2rust-iced/              # Cross-platform Iced 0.14 data-grid console (`forensics2rust-iced`)
```

---

## Tool Groups (45 Tools)

| Crate | Count | Tools |
| :--- | :---: | :--- |
| `forensics2rust-evtx` | 14 | `evtx.all`, `evtx.legacy`, `evtx.channels`, `evtx.sources`, `evtx.logon`, `evtx.uptime`, `evtx.wifi`, `evtx.defender`, `evtx.timeline`, `evtx.rdp`, `evtx.powershell`, `evtx.process`, `evtx.tasks`, `evtx.usb` |
| `forensics2rust-hive` | 6 | `hive.scan`, `hive.diff`, `hive.offline`, `hive.find`, `hive.export`, `hive.watch` |
| `forensics2rust-srum` | 4 | `srum.db`, `srum.net`, `srum.app`, `srum.energy` |
| `forensics2rust-artifacts` | 14 | `artifacts.activity`, `artifacts.prefetch`, `artifacts.jumplists`, `artifacts.shellbags`, `artifacts.userassist`, `artifacts.muicache`, `artifacts.opensave`, `artifacts.recent`, `artifacts.executed`, `artifacts.usb_devices`, `artifacts.usb_log`, `artifacts.vss`, `artifacts.previous`, `artifacts.profiles` |
| `forensics2rust-crash` | 3 | `crash.bsod`, `crash.wer`, `crash.report` |
| `forensics2rust-posture` | 4 | `posture.updates`, `posture.full_updates`, `posture.defender_status`, `posture.security_center` |

---

## Usage Examples (CLI, MCP & Dual GUI)

### Unified CLI (`forensics2rust`)

```powershell
# List all 45 read-only DFIR tools and check platform/elevation diagnostics
forensics2rust list
forensics2rust diag --json

# Query EVTX, Registry hives, SRUM, Artifacts, Crash dumps, or Posture offline with GetNir filtering
forensics2rust --source .\evidence --filter "event_id == 4688" --sort "timestamp:desc" --limit 50 evtx all
forensics2rust --offline .\evidence\NTUSER.DAT --format json hive offline
forensics2rust --offline .\evidence\SRUDB.dat --format csv --out .\out\srum_net.csv --custody .\out\custody.json srum net
forensics2rust --source .\evidence crash wer
forensics2rust --source .\evidence artifacts prefetch
forensics2rust --source .\evidence posture full-updates

# Export a multi-table forensic bundle with SHA-256 + SHA-512 Merkle custody_manifest.json
forensics2rust --source .\evidence --format json --out .\bundle export --category posture

# Diff two offline hives or artifact runs
forensics2rust diff --left .\baseline\NTUSER.DAT --right .\incident\NTUSER.DAT --tool hive.offline --keys key_path,value_name
```

### Read-Only MCP Server (`forensics2rust mcp`)

```powershell
# Inspect all 45 read-only MCP tool schemas (readOnlyHint=true, destructiveHint=false)
forensics2rust mcp --tools

# Start the JSON-RPC 2.0 stdio MCP server (also configured in mcp.json)
forensics2rust mcp
```

### Dual Desktop Consoles (`forensics2rust-win32` & `forensics2rust-iced`)

```powershell
# Launch via unified CLI or directly
forensics2rust gui --source .\evidence --tool evtx.all
forensics2rust gui --iced --source .\evidence --tool artifacts.prefetch --light

forensics2rust-win32 --source .\evidence --tool hive.offline
forensics2rust-iced --source .\evidence --tool srum.net --light
```

---

## Building & Testing

```powershell
cargo check --workspace --all-targets --offline --locked
cargo test --workspace --offline --locked
cargo clippy --workspace --all-targets --offline --locked -- -D warnings
```

---

## License

Licensed under the **Apache License, Version 2.0** (`LICENSE`). See `NOTICE` for attribution.
