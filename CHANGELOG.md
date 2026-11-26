# Changelog

All notable changes to `forensics2rust` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-23

### Added
- **12-Crate Pure-Rust DFIR Workspace (Edition 2024, MSRV `1.88`)**: `forensics2rust-core`, `forensics2rust-evtx`, `forensics2rust-hive`, `forensics2rust-srum`, `forensics2rust-crash`, `forensics2rust-artifacts`, `forensics2rust-posture`, `forensics2rust-report`, `forensics2rust-mcp`, `forensics2rust-cli`, `forensics2rust-win32`, and `forensics2rust-iced`.
- **`forensics2rust-core` (`#![forbid(unsafe_code)]`)**: `ForensicSource` (`Live`/`OfflinePath`/`OfflineBytes`), `ForensicError` with graceful `guap_table::TableError` mapping and elevation/missing-artifact classification, 45-tool `FORENSIC_TOOL_CATALOG`, pure-Rust Windows DFIR primitive decoders (FILETIME, OLE Automation DATE, SID, mixed-endian GUID, UTF-16LE, IEEE 802.3 CRC-32, hex, ROT13), `QueryHelper` over `guap-table`, and `tracing_subscriber` logging.
- **Governance & Packaging**: Apache-2.0 `LICENSE`, `NOTICE`, `deny.toml`, `rustfmt.toml`, `.cargo/config.toml`, `mcp.json`, `smithery.yaml`, `metadata.json`, and `packaging/` manifests for WinGet and Homebrew.
