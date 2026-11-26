#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Parser;
use forensics2rust_core::{FORENSIC_TOOL_CATALOG, ForensicSource, init_logging};
use guap_gui_iced::{IcedSuiteConfig, run_iced_suite};
use guap_table::TableProvider;

#[derive(Debug, Parser)]
#[command(
    name = "forensics2rust-iced",
    version,
    about = "Cross-platform Iced 0.14 DFIR Desktop Console"
)]
struct IcedArgs {
    /// Offline forensic artifact file or directory (omit for live Windows OS collection)
    #[arg(long = "source", visible_alias = "offline", value_name = "PATH")]
    source: Option<PathBuf>,

    /// Optional positional offline artifact file or directory
    #[arg(value_name = "PATH")]
    path: Option<PathBuf>,

    /// Initial tool ID to display at startup (e.g. evtx.all, hive.offline)
    #[arg(long, value_name = "TOOL_ID")]
    tool: Option<String>,

    /// Start in light mode
    #[arg(long)]
    light: bool,

    /// Default directory for exports
    #[arg(long, value_name = "DIR")]
    export_dir: Option<PathBuf>,
}

fn default_suite_config(dark_mode: bool) -> IcedSuiteConfig {
    IcedSuiteConfig {
        app_title: format!("Forensics2Rust Iced Console ({} tools)", FORENSIC_TOOL_CATALOG.len()),
        dark_mode,
        window_size: (1360.0, 860.0),
    }
}

fn resolve_hive_file_in_dir(tool_id: &str, dir: &Path) -> Option<PathBuf> {
    if tool_id == "hive.watch" {
        for candidate in ["watch.f2retw01", "watch.reg", "regwatch.reg", "watch.json"] {
            let p = dir.join(candidate);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    if tool_id == "hive.diff" {
        for candidate in ["diff_pair.json", "hive_diff.json", "snapshot.json"] {
            let p = dir.join(candidate);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    for candidate in [
        "NTUSER.DAT",
        "SOFTWARE",
        "SYSTEM",
        "UsrClass.dat",
        "SAM",
        "SECURITY",
        "DEFAULT",
        "Amcache.hve",
    ] {
        let p = dir.join(candidate);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn resolve_srum_file_in_dir(dir: &Path) -> Option<PathBuf> {
    for candidate in ["SRUDB.dat", "srudb.dat", "DataStore.edb"] {
        let p = dir.join(candidate);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn collect_all_providers(source: &ForensicSource) -> Vec<Arc<dyn TableProvider>> {
    let (hive_source, hive_watch_source, hive_diff_source, srum_source) = match source {
        ForensicSource::OfflinePath(dir) if dir.is_dir() => {
            let h = resolve_hive_file_in_dir("hive.offline", dir)
                .map(ForensicSource::OfflinePath)
                .unwrap_or_else(|| ForensicSource::OfflinePath(dir.join("NTUSER.DAT")));
            let hw = resolve_hive_file_in_dir("hive.watch", dir)
                .map(ForensicSource::OfflinePath)
                .unwrap_or_else(|| ForensicSource::OfflinePath(dir.join("watch.reg")));
            let hd = resolve_hive_file_in_dir("hive.diff", dir)
                .map(ForensicSource::OfflinePath)
                .unwrap_or_else(|| h.clone());
            let s = resolve_srum_file_in_dir(dir)
                .map(ForensicSource::OfflinePath)
                .unwrap_or_else(|| ForensicSource::OfflinePath(dir.join("SRUDB.dat")));
            (h, hw, hd, s)
        }
        _ => (source.clone(), source.clone(), source.clone(), source.clone()),
    };

    let mut providers = Vec::with_capacity(FORENSIC_TOOL_CATALOG.len());
    providers.extend(forensics2rust_evtx::all_providers(source));
    for p in forensics2rust_hive::all_providers(&hive_source) {
        match p.tool_id() {
            "hive.watch" if hive_watch_source != hive_source => {
                if let Some(wp) = forensics2rust_hive::all_providers(&hive_watch_source)
                    .into_iter()
                    .find(|x| x.tool_id() == "hive.watch")
                {
                    providers.push(wp);
                } else {
                    providers.push(p);
                }
            }
            "hive.diff" if hive_diff_source != hive_source => {
                if let Some(dp) = forensics2rust_hive::all_providers(&hive_diff_source)
                    .into_iter()
                    .find(|x| x.tool_id() == "hive.diff")
                {
                    providers.push(dp);
                } else {
                    providers.push(p);
                }
            }
            _ => providers.push(p),
        }
    }
    providers.extend(forensics2rust_srum::all_providers(&srum_source));
    providers.extend(forensics2rust_artifacts::all_providers(source));
    providers.extend(forensics2rust_crash::all_providers(source));
    providers.extend(forensics2rust_posture::all_providers(source));
    providers
}

fn prioritize_initial_tool(providers: &mut Vec<Arc<dyn TableProvider>>, tool_id: Option<&str>) {
    if let Some(target) = tool_id
        && let Some(pos) = providers.iter().position(|p| p.tool_id() == target)
        && pos > 0
    {
        let chosen = providers.remove(pos);
        providers.insert(0, chosen);
    }
}

fn main() -> anyhow::Result<()> {
    let args = IcedArgs::parse();
    init_logging("warn", None)?;
    if let Some(ref exp) = args.export_dir {
        let _ = std::fs::create_dir_all(exp);
    }
    let source = ForensicSource::from_optional_path(args.source.or(args.path));
    let mut providers = collect_all_providers(&source);
    prioritize_initial_tool(&mut providers, args.tool.as_deref());
    let cfg = default_suite_config(!args.light);
    run_iced_suite(cfg, providers).map_err(|e| anyhow::anyhow!("Iced GUI error: {e}"))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;

    use clap::CommandFactory;
    use forensics2rust_core::crc32_ieee;
    use forensics2rust_hive::regf::RegfBuilder;
    use forensics2rust_srum::ese::header::compute_header_xor32_checksum;
    use forensics2rust_srum::ese::page::PageFlags;
    use guap_export::ExportFormat;
    use guap_gui_iced::{DataGridMessage, IcedDataGrid};
    use tempfile::tempdir;

    use super::*;

    fn build_minimal_evtx() -> Vec<u8> {
        const CHUNK_SIZE: usize = 65_536;
        let mut chunk = vec![0u8; 0x200];
        let mut name_cache: HashMap<String, u32> = HashMap::new();
        let write_name_ref = |buf: &mut Vec<u8>, cache: &mut HashMap<String, u32>, name: &str| {
            let slot = buf.len();
            buf.extend_from_slice(&0u32.to_le_bytes());
            if let Some(&off) = cache.get(name) {
                buf[slot..slot + 4].copy_from_slice(&off.to_le_bytes());
                return;
            }
            let off = buf.len() as u32;
            buf[slot..slot + 4].copy_from_slice(&off.to_le_bytes());
            cache.insert(name.to_string(), off);
            let units: Vec<u16> = name.encode_utf16().collect();
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes());
            buf.extend_from_slice(&(units.len() as u16).to_le_bytes());
            for u in units {
                buf.extend_from_slice(&u.to_le_bytes());
            }
            buf.extend_from_slice(&0u16.to_le_bytes());
        };
        let write_inline_utf16 = |buf: &mut Vec<u8>, s: &str| {
            buf.push(0x05);
            buf.push(0x01);
            let units: Vec<u16> = s.encode_utf16().collect();
            buf.extend_from_slice(&(units.len() as u16).to_le_bytes());
            for u in units {
                buf.extend_from_slice(&u.to_le_bytes());
            }
        };
        let open_elem = |buf: &mut Vec<u8>, cache: &mut HashMap<String, u32>, name: &str, attrs: &[(&str, &str)]| {
            buf.push(if attrs.is_empty() { 0x01 } else { 0x41 });
            buf.extend_from_slice(&0xFFFFu16.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            write_name_ref(buf, cache, name);
            if !attrs.is_empty() {
                let size_slot = buf.len();
                buf.extend_from_slice(&0u32.to_le_bytes());
                let list_start = buf.len();
                for (i, (k, v)) in attrs.iter().enumerate() {
                    buf.push(if i + 1 < attrs.len() { 0x46 } else { 0x06 });
                    write_name_ref(buf, cache, k);
                    write_inline_utf16(buf, v);
                }
                let list_size = (buf.len() - list_start) as u32;
                buf[size_slot..size_slot + 4].copy_from_slice(&list_size.to_le_bytes());
            }
            buf.push(0x02);
        };
        let empty_elem = |buf: &mut Vec<u8>, cache: &mut HashMap<String, u32>, name: &str, attrs: &[(&str, &str)]| {
            buf.push(if attrs.is_empty() { 0x01 } else { 0x41 });
            buf.extend_from_slice(&0xFFFFu16.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            write_name_ref(buf, cache, name);
            if !attrs.is_empty() {
                let size_slot = buf.len();
                buf.extend_from_slice(&0u32.to_le_bytes());
                let list_start = buf.len();
                for (i, (k, v)) in attrs.iter().enumerate() {
                    buf.push(if i + 1 < attrs.len() { 0x46 } else { 0x06 });
                    write_name_ref(buf, cache, k);
                    write_inline_utf16(buf, v);
                }
                let list_size = (buf.len() - list_start) as u32;
                buf[size_slot..size_slot + 4].copy_from_slice(&list_size.to_le_bytes());
            }
            buf.push(0x03);
        };
        let text_elem = |buf: &mut Vec<u8>, cache: &mut HashMap<String, u32>, name: &str, val: &str| {
            open_elem(buf, cache, name, &[]);
            write_inline_utf16(buf, val);
            buf.push(0x04);
        };

        let rec_start = chunk.len();
        chunk.extend_from_slice(&[0x2A, 0x2A, 0x00, 0x00]);
        chunk.extend_from_slice(&0u32.to_le_bytes());
        chunk.extend_from_slice(&1u64.to_le_bytes());
        chunk.extend_from_slice(&133_814_000_000_000_000u64.to_le_bytes());
        chunk.extend_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
        open_elem(&mut chunk, &mut name_cache, "Event", &[]);
        open_elem(&mut chunk, &mut name_cache, "System", &[]);
        empty_elem(
            &mut chunk,
            &mut name_cache,
            "Provider",
            &[("Name", "Microsoft-Windows-Security-Auditing")],
        );
        text_elem(&mut chunk, &mut name_cache, "EventID", "4688");
        text_elem(&mut chunk, &mut name_cache, "Level", "0");
        empty_elem(
            &mut chunk,
            &mut name_cache,
            "TimeCreated",
            &[("SystemTime", "2025-01-15T10:00:00Z")],
        );
        text_elem(&mut chunk, &mut name_cache, "EventRecordID", "1");
        text_elem(&mut chunk, &mut name_cache, "Channel", "Security");
        text_elem(&mut chunk, &mut name_cache, "Computer", "DFIR-HOST01");
        chunk.push(0x04);
        open_elem(&mut chunk, &mut name_cache, "EventData", &[]);
        open_elem(&mut chunk, &mut name_cache, "Data", &[("Name", "NewProcessName")]);
        write_inline_utf16(&mut chunk, r"C:\Windows\System32\notepad.exe");
        chunk.push(0x04);
        chunk.push(0x04);
        chunk.push(0x04);
        chunk.push(0x00);
        chunk.extend_from_slice(&0u32.to_le_bytes());
        let rec_size = (chunk.len() - rec_start) as u32;
        chunk[rec_start + 4..rec_start + 8].copy_from_slice(&rec_size.to_le_bytes());
        let tail = chunk.len() - 4;
        chunk[tail..].copy_from_slice(&rec_size.to_le_bytes());

        let free_space = chunk.len() as u32;
        chunk.resize(CHUNK_SIZE, 0);
        chunk[0..8].copy_from_slice(b"ElfChnk\0");
        chunk[0x08..0x10].copy_from_slice(&1u64.to_le_bytes());
        chunk[0x10..0x18].copy_from_slice(&1u64.to_le_bytes());
        chunk[0x18..0x20].copy_from_slice(&1u64.to_le_bytes());
        chunk[0x20..0x28].copy_from_slice(&1u64.to_le_bytes());
        chunk[0x28..0x2C].copy_from_slice(&128u32.to_le_bytes());
        chunk[0x2C..0x30].copy_from_slice(&(rec_start as u32).to_le_bytes());
        chunk[0x30..0x34].copy_from_slice(&free_space.to_le_bytes());
        let rec_crc = crc32_ieee(&chunk[0x200..free_space as usize]);
        chunk[0x34..0x38].copy_from_slice(&rec_crc.to_le_bytes());
        let mut hdr_crc_buf = Vec::with_capacity(120 + (512 - 128));
        hdr_crc_buf.extend_from_slice(&chunk[0..120]);
        hdr_crc_buf.extend_from_slice(&chunk[128..512]);
        chunk[0x7C..0x80].copy_from_slice(&crc32_ieee(&hdr_crc_buf).to_le_bytes());

        let mut hdr = vec![0u8; 4096];
        hdr[0..8].copy_from_slice(b"ElfFile\0");
        hdr[0x18..0x20].copy_from_slice(&2u64.to_le_bytes());
        hdr[0x20..0x24].copy_from_slice(&128u32.to_le_bytes());
        hdr[0x24..0x26].copy_from_slice(&1u16.to_le_bytes());
        hdr[0x26..0x28].copy_from_slice(&3u16.to_le_bytes());
        hdr[0x28..0x2A].copy_from_slice(&4096u16.to_le_bytes());
        hdr[0x2A..0x2C].copy_from_slice(&1u16.to_le_bytes());
        let hcrc = crc32_ieee(&hdr[0..120]);
        hdr[0x7C..0x80].copy_from_slice(&hcrc.to_le_bytes());

        let mut evtx = Vec::with_capacity(4096 + CHUNK_SIZE);
        evtx.extend_from_slice(&hdr);
        evtx.extend_from_slice(&chunk);
        evtx
    }

    fn build_minimal_ese() -> Vec<u8> {
        let ps = 4096usize;
        let mut buf = vec![0u8; ps * 6];
        buf[4..8].copy_from_slice(&0x89AB_CDEFu32.to_le_bytes());
        buf[8..12].copy_from_slice(&0x0000_0620u32.to_le_bytes());
        buf[0x34..0x38].copy_from_slice(&3u32.to_le_bytes());
        buf[0xE8..0xEC].copy_from_slice(&0x17u32.to_le_bytes());
        buf[0xEC..0xF0].copy_from_slice(&(ps as u32).to_le_bytes());
        let cksum = compute_header_xor32_checksum(&buf[0..ps]);
        buf[0..4].copy_from_slice(&cksum.to_le_bytes());
        let (h0, rest) = buf.split_at_mut(ps);
        rest[0..ps].copy_from_slice(h0);

        let space_flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::SPACE_TREE;
        let msys_flags = PageFlags::ROOT | PageFlags::LEAF | PageFlags::NEW_RECORD_FORMAT;
        for (pgno, objid_fdp, flags) in [(2usize, 1u32, space_flags), (3, 1, space_flags), (4, 2, msys_flags)] {
            let start = (pgno + 1) * ps;
            let page = &mut buf[start..start + ps];
            page[24..28].copy_from_slice(&objid_fdp.to_le_bytes());
            page[34..36].copy_from_slice(&1u16.to_le_bytes());
            page[36..40].copy_from_slice(&flags.to_le_bytes());
            let tag_pos = ps - 4;
            page[tag_pos..tag_pos + 2].copy_from_slice(&16u16.to_le_bytes());
            page[28..30].copy_from_slice(&((ps - 4 - 56) as u16).to_le_bytes());
            page[32..34].copy_from_slice(&16u16.to_le_bytes());
        }
        buf
    }

    fn create_synthetic_dir() -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        let p = dir.path();
        fs::write(p.join("Security.evtx"), build_minimal_evtx()).unwrap();
        let hive = RegfBuilder::new("ROOT")
            .add_sz("Software\\Demo", "Mode", "offline")
            .add_dword("Software\\Demo", "Count", 3)
            .build();
        fs::write(p.join("NTUSER.DAT"), hive).unwrap();
        fs::write(
            p.join("watch.reg"),
            "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\Demo]\r\n\"Watch\"=\"1\"\r\n",
        )
        .unwrap();
        fs::write(p.join("SRUDB.dat"), build_minimal_ese()).unwrap();
        fs::write(
            p.join("Report.wer"),
            "Version=1\r\nEventType=APPCRASH\r\nAppName=notepad.exe\r\n",
        )
        .unwrap();
        fs::write(
            p.join("setupapi.dev.log"),
            ">>>  [Device Install (Hardware initiated) - USB\\VID_1234&PID_5678\\SER001]\r\n>>>  Section start 2025/01/15 10:00:00.000\r\n<<<  [Exit status: SUCCESS]\r\n",
        )
        .unwrap();
        fs::write(
            p.join("wua_updates.json"),
            r#"[{"title":"KB5050001","kb_article":"KB5050001","installed_on":"2025-01-15T12:00:00Z","result":"Succeeded"}]"#,
        )
        .unwrap();
        fs::write(
            p.join("CBS.log"),
            "2025-01-15 12:00:00, Info                  CBS    Package Package_for_RollupFix~31bf3856ad364e35~amd64~~22621.4751.1.1 is Installed\r\n",
        )
        .unwrap();
        fs::write(
            p.join("defender_status.json"),
            r#"[{"AntivirusEnabled":true,"RealTimeProtectionEnabled":true,"AMRunningMode":"Normal"}]"#,
        )
        .unwrap();
        fs::write(
            p.join("security_center.json"),
            r#"[{"displayName":"Windows Defender","productType":"AntiVirus","productState":397568}]"#,
        )
        .unwrap();
        dir
    }

    #[test]
    fn iced_skeleton_config_builds_and_runs() {
        IcedArgs::command().debug_assert();
        let cfg = default_suite_config(true);
        assert!(cfg.app_title.contains("45 tools"));
        assert!(cfg.dark_mode);
    }

    #[test]
    fn iced_data_grid_drives_all_45_providers_offline() {
        let dir = create_synthetic_dir();
        let source = ForensicSource::OfflinePath(dir.path().to_path_buf());
        let providers = collect_all_providers(&source);
        assert_eq!(providers.len(), 45);
        let tool_ids: Vec<String> = providers.iter().map(|p| p.tool_id().to_string()).collect();

        let export_dir = dir.path().join("exports");
        let mut grid = IcedDataGrid::new(providers)
            .with_export_dir(export_dir)
            .with_dark_mode(true)
            .with_page_size(200);

        for tid in &tool_ids {
            let _ = grid.update(DataGridMessage::SelectTool(tid.clone()));
            assert_eq!(grid.active_tool_id(), Some(tid.as_str()));
            assert!(!grid.columns().is_empty(), "tool {tid} has empty columns");
            assert!(
                grid.last_error().is_none(),
                "tool {tid} errored: {:?}",
                grid.last_error()
            );
        }

        let _ = grid.update(DataGridMessage::SelectTool("crash.wer".to_string()));
        assert_eq!(grid.total_rows(), 1);
        let _ = grid.update(DataGridMessage::FilterChanged("notepad".to_string()));
        assert_eq!(grid.total_rows(), 1);
        let _ = grid.update(DataGridMessage::ToggleRegex);
        let _ = grid.update(DataGridMessage::FilterChanged("^notepad".to_string()));
        assert!(grid.last_error().is_none());
        let _ = grid.update(DataGridMessage::ToggleRegex);
        let _ = grid.update(DataGridMessage::FilterChanged(String::new()));
        let _ = grid.update(DataGridMessage::SortColumn(0));
        let _ = grid.update(DataGridMessage::SelectRow(0));
        assert!(grid.selected_row().is_some());
        let _ = grid.update(DataGridMessage::SetPage(0));
        let _ = grid.update(DataGridMessage::Export(ExportFormat::Json));
        assert!(grid.last_export_manifest().is_some());
    }
}
