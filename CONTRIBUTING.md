# Contributing to `forensics2rust`

Thank you for your interest in contributing to `forensics2rust`!

## Code Architecture

The workspace is organized into 12 modular crates under `crates/`:
- `forensics2rust-core`: `#![forbid(unsafe_code)]` core source models, error classification, 45-tool catalog, DFIR decoders, and `guap-table` query helpers.
- Domain crates (`-evtx`, `-hive`, `-srum`, `-crash`, `-artifacts`, `-posture`): Pure-Rust offline parsers paired with `#[cfg(windows)]` live API/ETW/WMI/COM collectors.
- Surface crates (`-report`, `-mcp`, `-cli`, `-win32`, `-iced`): Chain-of-custody exports, read-only JSON-RPC stdio MCP server, CLI, native Win32 virtual-list console, and Iced 0.14 GUI.

## Development Workflow

1. Fork and clone the repository alongside `../guap-kit`.
2. Ensure Rust `1.88+` (Edition 2024) is installed.
3. Run checks, formatter, linter, and tests:
   ```powershell
   cargo fmt --check
   cargo check --workspace --all-targets --offline --locked
   cargo clippy --workspace --all-targets --offline --locked -- -D warnings
   cargo test --workspace --offline --locked
   ```

## Guidelines
- **Strictly Read-Only DFIR**: Never add credential extraction, password dumping/decryption, DLL injection, or API hooking.
- **Offline Testability**: Every binary parser and provider must be testable deterministically on synthetic byte fixtures without requiring elevation or live OS artifacts.
- **Logging**: Write diagnostics via `tracing` to `stderr` so CLI `stdout` and MCP `stdio` streams stay uncorrupted.
