#![forbid(unsafe_code)]

use chrono::{DateTime, TimeZone, Utc};
use forensics2rust_core::{crc32_ieee, rot13, utc_to_filetime};
use forensics2rust_hive::regf::RegfBuilder;

use crate::parsers::lnk::CLSID_SHELL_LINK;

pub fn ts(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(y, mo, d, h, mi, s)
        .single()
        .expect("valid timestamp")
}

pub fn ft(dt: DateTime<Utc>) -> u64 {
    utc_to_filetime(dt).unwrap_or(133_800_000_000_000_000)
}

fn push_utf16_nul(buf: &mut Vec<u8>, s: &str) {
    for u in s.encode_utf16() {
        buf.extend_from_slice(&u.to_le_bytes());
    }
    buf.extend_from_slice(&0u16.to_le_bytes());
}

fn push_utf16_no_nul(buf: &mut Vec<u8>, s: &str) {
    for u in s.encode_utf16() {
        buf.extend_from_slice(&u.to_le_bytes());
    }
}

pub struct SyntheticSccaSpec<'a> {
    pub version: u32,
    pub exe_name: &'a str,
    pub hash: u32,
    pub run_count: u32,
    pub last_runs: &'a [u64],
    pub loaded_files: &'a [&'a str],
    pub volumes: &'a [(&'a str, u32, u64)],
    pub v30_variant2_0x128: bool,
}

/// Builds a synthetic `SCCA` Prefetch `.pf` payload for versions `17`, `23`, `26`, or `30`/`31`.
pub fn build_synthetic_scca(spec: &SyntheticSccaSpec<'_>) -> Vec<u8> {
    let version = spec.version;
    let exe_name = spec.exe_name;
    let hash = spec.hash;
    let run_count = spec.run_count;
    let last_runs = spec.last_runs;
    let loaded_files = spec.loaded_files;
    let volumes = spec.volumes;
    let v30_variant2_0x128 = spec.v30_variant2_0x128;
    let mut data = Vec::new();
    // 84-byte common header
    data.extend_from_slice(&version.to_le_bytes());
    data.extend_from_slice(b"SCCA");
    data.extend_from_slice(&17u32.to_le_bytes()); // 0x08 unknown
    data.extend_from_slice(&0u32.to_le_bytes()); // 0x0C file_size placeholder
    let mut exe_buf = [0u8; 60];
    let mut exe_u16 = Vec::new();
    push_utf16_nul(&mut exe_u16, exe_name);
    let copy_len = exe_u16.len().min(60);
    exe_buf[..copy_len].copy_from_slice(&exe_u16[..copy_len]);
    data.extend_from_slice(&exe_buf);
    data.extend_from_slice(&hash.to_le_bytes()); // 0x4C
    data.extend_from_slice(&0u32.to_le_bytes()); // 0x50 flags

    let metrics_offset: usize = match version {
        17 => 0x98,
        23 => 0xF0,
        26 => 0x130,
        30 | 31 => {
            if v30_variant2_0x128 {
                0x128
            } else {
                0x130
            }
        }
        _ => 0x128,
    };
    data.resize(metrics_offset, 0);

    match version {
        17 => {
            if let Some(&r0) = last_runs.first() {
                data[0x78..0x80].copy_from_slice(&r0.to_le_bytes());
            }
            data[0x90..0x94].copy_from_slice(&run_count.to_le_bytes());
        }
        23 => {
            if let Some(&r0) = last_runs.first() {
                data[0x80..0x88].copy_from_slice(&r0.to_le_bytes());
            }
            data[0x98..0x9C].copy_from_slice(&run_count.to_le_bytes());
        }
        26 => {
            for (i, &r) in last_runs.iter().take(8).enumerate() {
                data[0x80 + i * 8..0x88 + i * 8].copy_from_slice(&r.to_le_bytes());
            }
            data[0xD0..0xD4].copy_from_slice(&run_count.to_le_bytes());
        }
        _ => {
            for (i, &r) in last_runs.iter().take(8).enumerate() {
                data[0x80 + i * 8..0x88 + i * 8].copy_from_slice(&r.to_le_bytes());
            }
            let rc_off = if metrics_offset == 0x130 { 0xD0 } else { 0xC8 };
            data[rc_off..rc_off + 4].copy_from_slice(&run_count.to_le_bytes());
        }
    }

    // Build filename strings blob & track (off, len_chars)
    let mut fn_strings = Vec::new();
    let mut fn_spans = Vec::new();
    for &f in loaded_files {
        let off = fn_strings.len() as u32;
        let len_chars = f.encode_utf16().count() as u32;
        push_utf16_nul(&mut fn_strings, f);
        fn_spans.push((off, len_chars));
    }

    let metric_entry_size = if version == 17 { 20 } else { 32 };
    let metrics_count = loaded_files.len();
    for (i, &(fn_off, fn_len)) in fn_spans.iter().enumerate() {
        if version == 17 {
            data.extend_from_slice(&((i as u32) * 10).to_le_bytes());
            data.extend_from_slice(&5u32.to_le_bytes());
            data.extend_from_slice(&fn_off.to_le_bytes());
            data.extend_from_slice(&fn_len.to_le_bytes());
            data.extend_from_slice(&1u32.to_le_bytes());
        } else {
            data.extend_from_slice(&((i as u32) * 10).to_le_bytes());
            data.extend_from_slice(&5u32.to_le_bytes());
            data.extend_from_slice(&3u32.to_le_bytes());
            data.extend_from_slice(&fn_off.to_le_bytes());
            data.extend_from_slice(&fn_len.to_le_bytes());
            data.extend_from_slice(&1u32.to_le_bytes());
            data.extend_from_slice(&(100u64 + i as u64).to_le_bytes());
        }
    }
    let _ = metric_entry_size;

    let trace_chains_offset = data.len() as u32;
    let filename_strings_offset = data.len() as u32;
    let filename_strings_size = fn_strings.len() as u32;
    data.extend_from_slice(&fn_strings);

    // Volumes section
    let volumes_info_offset = data.len();
    let vol_entry_size = match version {
        17 => 40usize,
        23 | 26 => 104usize,
        _ => 96usize,
    };
    let mut vol_strings = Vec::new();
    let vol_header_bytes = volumes.len() * vol_entry_size;
    let mut vol_entries = vec![0u8; vol_header_bytes];
    for (i, &(dev_path, serial, c_ft)) in volumes.iter().enumerate() {
        let base = i * vol_entry_size;
        let rel_off = (vol_header_bytes + vol_strings.len()) as u32;
        let char_len = dev_path.encode_utf16().count() as u32;
        push_utf16_nul(&mut vol_strings, dev_path);
        vol_entries[base..base + 4].copy_from_slice(&rel_off.to_le_bytes());
        vol_entries[base + 4..base + 8].copy_from_slice(&char_len.to_le_bytes());
        vol_entries[base + 8..base + 16].copy_from_slice(&c_ft.to_le_bytes());
        vol_entries[base + 16..base + 20].copy_from_slice(&serial.to_le_bytes());
    }
    data.extend_from_slice(&vol_entries);
    data.extend_from_slice(&vol_strings);
    let volumes_info_size = (data.len() - volumes_info_offset) as u32;

    // Patch FileInfo header pointers (0x54..0x78)
    data[0x54..0x58].copy_from_slice(&(metrics_offset as u32).to_le_bytes());
    data[0x58..0x5C].copy_from_slice(&(metrics_count as u32).to_le_bytes());
    data[0x5C..0x60].copy_from_slice(&trace_chains_offset.to_le_bytes());
    data[0x60..0x64].copy_from_slice(&0u32.to_le_bytes());
    data[0x64..0x68].copy_from_slice(&filename_strings_offset.to_le_bytes());
    data[0x68..0x6C].copy_from_slice(&filename_strings_size.to_le_bytes());
    data[0x6C..0x70].copy_from_slice(&(volumes_info_offset as u32).to_le_bytes());
    data[0x70..0x74].copy_from_slice(&(volumes.len() as u32).to_le_bytes());
    data[0x74..0x78].copy_from_slice(&volumes_info_size.to_le_bytes());

    let total_len = data.len() as u32;
    data[0x0C..0x10].copy_from_slice(&total_len.to_le_bytes());
    data
}

pub fn build_pidl_item_root_this_pc() -> Vec<u8> {
    let guid_bytes: [u8; 16] = [
        0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10, 0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30, 0x30, 0x9D,
    ];
    let mut body = vec![0x1F, 0x50];
    body.extend_from_slice(&guid_bytes);
    let cb = (body.len() + 2) as u16;
    let mut out = cb.to_le_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

pub fn build_pidl_item_drive(drive: &str) -> Vec<u8> {
    let mut body = vec![0x2F];
    body.extend_from_slice(drive.as_bytes());
    body.push(0);
    while body.len() < 23 {
        body.push(0);
    }
    let cb = (body.len() + 2) as u16;
    let mut out = cb.to_le_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

pub fn build_pidl_item_fs_beef0004(
    is_dir: bool,
    short_name: &str,
    long_name: &str,
    file_size: u32,
    dos_datetime: (u16, u16),
    mft_ref: (u64, u16),
) -> Vec<u8> {
    let (dos_date, dos_time) = dos_datetime;
    let (mft_entry, mft_seq) = mft_ref;
    let type_byte = if is_dir { 0x31u8 } else { 0x32u8 };
    let mut body = Vec::new();
    body.push(type_byte);
    body.push(0x00);
    body.extend_from_slice(&file_size.to_le_bytes());
    body.extend_from_slice(&dos_date.to_le_bytes());
    body.extend_from_slice(&dos_time.to_le_bytes());
    body.extend_from_slice(&(if is_dir { 0x10u16 } else { 0x20u16 }).to_le_bytes());
    body.extend_from_slice(short_name.as_bytes());
    body.push(0);
    if !body.len().is_multiple_of(2) {
        body.push(0);
    }

    // Beef0004 v9 extension block (header up to offset 46)
    let mut ext = Vec::new();
    ext.extend_from_slice(&0u16.to_le_bytes()); // ext_size placeholder
    ext.extend_from_slice(&0x0009u16.to_le_bytes()); // version 9
    ext.extend_from_slice(&0xBEEF_0004u32.to_le_bytes());
    ext.extend_from_slice(&dos_date.to_le_bytes());
    ext.extend_from_slice(&dos_time.to_le_bytes());
    ext.extend_from_slice(&dos_date.to_le_bytes());
    ext.extend_from_slice(&dos_time.to_le_bytes());
    ext.extend_from_slice(&0x002Eu32.to_le_bytes()); // +16..20
    let raw_mft = (mft_entry & 0x0000_FFFF_FFFF_FFFF) | (u64::from(mft_seq) << 48);
    ext.extend_from_slice(&raw_mft.to_le_bytes()); // +20..28
    ext.resize(46, 0);
    push_utf16_nul(&mut ext, long_name);
    let ext_len = ext.len() as u16;
    ext[0..2].copy_from_slice(&ext_len.to_le_bytes());
    body.extend_from_slice(&ext);

    let cb = (body.len() + 2) as u16;
    let mut out = cb.to_le_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

pub fn build_pidl_bytes(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for item in items {
        out.extend_from_slice(item);
    }
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// Builds a valid `[MS-SHLLINK]` `.lnk` file.
#[allow(clippy::too_many_arguments)]
pub fn build_synthetic_lnk(
    target_path: &str,
    name: Option<&str>,
    rel_path: Option<&str>,
    working_dir: Option<&str>,
    args: Option<&str>,
    icon_loc: Option<&str>,
    volume_serial: u32,
    file_size: u32,
    created: u64,
    modified: u64,
    machine_id: Option<&str>,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut flags: u32 = 0x01 | 0x02 | 0x80; // HasIDList | HasLinkInfo | IsUnicode
    if name.is_some() {
        flags |= 0x04;
    }
    if rel_path.is_some() {
        flags |= 0x08;
    }
    if working_dir.is_some() {
        flags |= 0x10;
    }
    if args.is_some() {
        flags |= 0x20;
    }
    if icon_loc.is_some() {
        flags |= 0x40;
    }

    // ShellLinkHeader (76 bytes)
    out.extend_from_slice(&0x0000_004Cu32.to_le_bytes());
    out.extend_from_slice(&CLSID_SHELL_LINK);
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&0x0000_0020u32.to_le_bytes()); // FILE_ATTRIBUTE_ARCHIVE
    out.extend_from_slice(&created.to_le_bytes());
    out.extend_from_slice(&modified.to_le_bytes()); // access
    out.extend_from_slice(&modified.to_le_bytes()); // write
    out.extend_from_slice(&file_size.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes()); // icon index
    out.extend_from_slice(&1u32.to_le_bytes()); // SW_SHOWNORMAL
    out.extend_from_slice(&0u16.to_le_bytes()); // hot key
    out.extend_from_slice(&[0u8; 10]); // reserved

    // LinkTargetIDList
    let fname = target_path.rsplit('\\').next().unwrap_or(target_path);
    let pidl = build_pidl_bytes(&[
        build_pidl_item_root_this_pc(),
        build_pidl_item_drive("C:\\"),
        build_pidl_item_fs_beef0004(false, "FILE~1.TXT", fname, file_size, (0x58A1, 0x7100), (42, 1)),
    ]);
    out.extend_from_slice(&(pidl.len() as u16).to_le_bytes());
    out.extend_from_slice(&pidl);

    // LinkInfo (Unicode-capable, 0x24 header)
    let mut li = Vec::new();
    li.extend_from_slice(&0u32.to_le_bytes()); // size placeholder
    li.extend_from_slice(&0x24u32.to_le_bytes()); // header_size
    li.extend_from_slice(&0x01u32.to_le_bytes()); // VolumeIDAndLocalBasePath
    li.extend_from_slice(&0x24u32.to_le_bytes()); // vol_off
    let vol_id_len = 16 + 4; // header + "OSD\0"
    let local_ansi_off = 0x24 + vol_id_len;
    let mut ansi_bytes = target_path.as_bytes().to_vec();
    ansi_bytes.push(0);
    let suffix_ansi_off = local_ansi_off + ansi_bytes.len();
    let local_u_off = suffix_ansi_off + 1;
    let mut u_bytes = Vec::new();
    push_utf16_nul(&mut u_bytes, target_path);
    let suffix_u_off = local_u_off + u_bytes.len();

    li.extend_from_slice(&(local_ansi_off as u32).to_le_bytes());
    li.extend_from_slice(&0u32.to_le_bytes()); // net_off
    li.extend_from_slice(&(suffix_ansi_off as u32).to_le_bytes());
    li.extend_from_slice(&(local_u_off as u32).to_le_bytes());
    li.extend_from_slice(&(suffix_u_off as u32).to_le_bytes());

    // VolumeID
    li.extend_from_slice(&(vol_id_len as u32).to_le_bytes());
    li.extend_from_slice(&3u32.to_le_bytes()); // DRIVE_FIXED
    li.extend_from_slice(&volume_serial.to_le_bytes());
    li.extend_from_slice(&16u32.to_le_bytes());
    li.extend_from_slice(b"OSD\0");

    li.extend_from_slice(&ansi_bytes);
    li.push(0); // empty suffix ANSI
    li.extend_from_slice(&u_bytes);
    li.extend_from_slice(&[0u8; 2]); // empty suffix UTF-16
    let li_size = li.len() as u32;
    li[0..4].copy_from_slice(&li_size.to_le_bytes());
    out.extend_from_slice(&li);

    // StringData in exact flag order
    for s in [name, rel_path, working_dir, args, icon_loc].into_iter().flatten() {
        let units: Vec<u16> = s.encode_utf16().collect();
        out.extend_from_slice(&(units.len() as u16).to_le_bytes());
        push_utf16_no_nul(&mut out, s);
    }

    // ExtraData: TrackerDataBlock (0xA0000003)
    if let Some(mid) = machine_id {
        let mut tb = vec![0u8; 96];
        tb[0..4].copy_from_slice(&96u32.to_le_bytes());
        tb[4..8].copy_from_slice(&0xA000_0003u32.to_le_bytes());
        tb[8..12].copy_from_slice(&88u32.to_le_bytes());
        tb[12..16].copy_from_slice(&0u32.to_le_bytes());
        let mb = mid.as_bytes();
        let copy_n = mb.len().min(15);
        tb[16..16 + copy_n].copy_from_slice(&mb[..copy_n]);
        tb[32..48].copy_from_slice(&[0x11; 16]);
        tb[48..64].copy_from_slice(&[0x22; 16]);
        tb[64..80].copy_from_slice(&[0x11; 16]);
        tb[80..96].copy_from_slice(&[0x22; 16]);
        out.extend_from_slice(&tb);
    }

    // TerminalBlock
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}

/// Builds a synthetic 512-byte-sector v3 CFBF container supporting both FAT (`>= 4096`B)
/// and MiniStream (`< 4096`B) streams.
pub fn build_synthetic_cfbf(streams: &[(&str, &[u8])]) -> Vec<u8> {
    const SEC_SZ: usize = 512;
    const MINI_SZ: usize = 64;
    const CUTOFF: usize = 4096;

    // Partition streams into mini (<4096) vs regular (>=4096)
    let mut ministream = Vec::new();
    let mut minifat: Vec<u32> = Vec::new();

    struct DirAlloc {
        name: String,
        obj_type: u8,
        start_sec: u32,
        size: u64,
    }
    let mut dir_allocs = Vec::new();

    // Pre-allocate mini streams
    let mut mini_starts = Vec::new();
    for &(_name, data) in streams {
        if !data.is_empty() && data.len() < CUTOFF {
            let start = minifat.len() as u32;
            let num_mini = data.len().div_ceil(MINI_SZ);
            for i in 0..num_mini {
                let next = if i + 1 < num_mini {
                    start + (i as u32) + 1
                } else {
                    0xFFFF_FFFE
                };
                minifat.push(next);
            }
            ministream.extend_from_slice(data);
            let padded = num_mini * MINI_SZ;
            ministream.resize(ministream.len() + (padded - data.len()), 0);
            mini_starts.push(Some(start));
        } else {
            mini_starts.push(None);
        }
    }

    // Allocate regular FAT sectors sequentially starting from sector 0:
    // Order: [MiniStream sectors...] [Regular stream sectors...] [MiniFAT sectors...] [Dir sectors...] [FAT sectors...]
    let mut fat: Vec<u32> = Vec::new();
    let mut sector_blobs: Vec<Vec<u8>> = Vec::new();

    let alloc_blob = |blob: &[u8], fat: &mut Vec<u32>, sector_blobs: &mut Vec<Vec<u8>>| -> u32 {
        if blob.is_empty() {
            return 0xFFFF_FFFE;
        }
        let start = sector_blobs.len() as u32;
        let num_secs = blob.len().div_ceil(SEC_SZ);
        for i in 0..num_secs {
            let off = i * SEC_SZ;
            let end = (off + SEC_SZ).min(blob.len());
            let mut sec = vec![0u8; SEC_SZ];
            sec[..end - off].copy_from_slice(&blob[off..end]);
            sector_blobs.push(sec);
            let next = if i + 1 < num_secs {
                start + (i as u32) + 1
            } else {
                0xFFFF_FFFE
            };
            fat.push(next);
        }
        start
    };

    let ms_start = alloc_blob(&ministream, &mut fat, &mut sector_blobs);
    dir_allocs.push(DirAlloc {
        name: "Root Entry".to_string(),
        obj_type: 5,
        start_sec: ms_start,
        size: ministream.len() as u64,
    });

    for (idx, &(name, data)) in streams.iter().enumerate() {
        if let Some(m_start) = mini_starts[idx] {
            dir_allocs.push(DirAlloc {
                name: name.to_string(),
                obj_type: 2,
                start_sec: m_start,
                size: data.len() as u64,
            });
        } else {
            let f_start = alloc_blob(data, &mut fat, &mut sector_blobs);
            dir_allocs.push(DirAlloc {
                name: name.to_string(),
                obj_type: 2,
                start_sec: f_start,
                size: data.len() as u64,
            });
        }
    }

    let minifat_bytes: Vec<u8> = minifat.iter().flat_map(|v| v.to_le_bytes()).collect();
    let num_minifat_secs = if minifat_bytes.is_empty() {
        0u32
    } else {
        minifat_bytes.len().div_ceil(SEC_SZ) as u32
    };
    let first_minifat_sec = alloc_blob(&minifat_bytes, &mut fat, &mut sector_blobs);

    // Build directory entries (4 per 512B sector)
    let dir_secs_needed = dir_allocs.len().div_ceil(4);
    let mut dir_bytes = vec![0u8; dir_secs_needed * SEC_SZ];
    for (i, d) in dir_allocs.iter().enumerate() {
        let base = i * 128;
        let mut name_u16 = Vec::new();
        push_utf16_nul(&mut name_u16, &d.name);
        let nlen = name_u16.len().min(64);
        dir_bytes[base..base + nlen].copy_from_slice(&name_u16[..nlen]);
        dir_bytes[base + 0x40..base + 0x42].copy_from_slice(&(nlen as u16).to_le_bytes());
        dir_bytes[base + 0x42] = d.obj_type;
        dir_bytes[base + 0x74..base + 0x78].copy_from_slice(&d.start_sec.to_le_bytes());
        dir_bytes[base + 0x78..base + 0x80].copy_from_slice(&d.size.to_le_bytes());
    }
    let first_dir_sec = alloc_blob(&dir_bytes, &mut fat, &mut sector_blobs);

    // Allocate FAT sectors at the end (iterative convergence)
    let mut num_fat_secs = 1usize;
    loop {
        let total_entries = fat.len() + num_fat_secs;
        let needed = total_entries.div_ceil(128);
        if needed <= num_fat_secs {
            break;
        }
        num_fat_secs = needed;
    }

    let mut fat_sids = Vec::new();
    for _ in 0..num_fat_secs {
        let sid = sector_blobs.len() as u32;
        fat_sids.push(sid);
        fat.push(0xFFFF_FFFD); // FATSECT
        sector_blobs.push(vec![0u8; SEC_SZ]);
    }
    while !fat.len().is_multiple_of(128) {
        fat.push(0xFFFF_FFFF); // FREESECT
    }

    for (i, &sid) in fat_sids.iter().enumerate() {
        let slice = &fat[i * 128..(i + 1) * 128];
        let mut sec = Vec::with_capacity(SEC_SZ);
        for v in slice {
            sec.extend_from_slice(&v.to_le_bytes());
        }
        sector_blobs[sid as usize] = sec;
    }

    // Build 512-byte CFBF Header
    let mut hdr = vec![0u8; 512];
    hdr[0..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    hdr[0x18..0x1A].copy_from_slice(&0x003Eu16.to_le_bytes()); // minor version
    hdr[0x1A..0x1C].copy_from_slice(&0x0003u16.to_le_bytes()); // major version v3
    hdr[0x1C..0x1E].copy_from_slice(&0xFFFEu16.to_le_bytes()); // little endian
    hdr[0x1E..0x20].copy_from_slice(&9u16.to_le_bytes()); // sector shift 512
    hdr[0x20..0x22].copy_from_slice(&6u16.to_le_bytes()); // mini sector shift 64
    hdr[0x2C..0x30].copy_from_slice(&(num_fat_secs as u32).to_le_bytes());
    hdr[0x30..0x34].copy_from_slice(&first_dir_sec.to_le_bytes());
    hdr[0x38..0x3C].copy_from_slice(&(CUTOFF as u32).to_le_bytes());
    hdr[0x3C..0x40].copy_from_slice(&first_minifat_sec.to_le_bytes());
    hdr[0x40..0x44].copy_from_slice(&num_minifat_secs.to_le_bytes());
    hdr[0x44..0x48].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes()); // no external DIFAT
    hdr[0x48..0x4C].copy_from_slice(&0u32.to_le_bytes());
    for i in 0..109 {
        let sid = fat_sids.get(i).copied().unwrap_or(0xFFFF_FFFF);
        hdr[0x4C + i * 4..0x50 + i * 4].copy_from_slice(&sid.to_le_bytes());
    }

    let mut out = Vec::with_capacity((1 + sector_blobs.len()) * SEC_SZ);
    out.extend_from_slice(&hdr);
    for sec in sector_blobs {
        out.extend_from_slice(&sec);
    }
    out
}

pub fn build_destlist(version: u32, entries: &[(u64, &str, u32, i32, u64, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    let pinned_cnt = entries.iter().filter(|e| e.3 >= 0).count() as u32;
    out.extend_from_slice(&pinned_cnt.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u64).to_le_bytes());

    for &(entry_id, path, access_count, pin_status, time_ft, netbios) in entries {
        let mut prefix = vec![0u8; if version <= 1 { 114 } else { 130 }];
        let nb = netbios.as_bytes();
        let copy_nb = nb.len().min(15);
        prefix[0x48..0x48 + copy_nb].copy_from_slice(&nb[..copy_nb]);
        prefix[0x58..0x60].copy_from_slice(&entry_id.to_le_bytes());
        prefix[0x60..0x64].copy_from_slice(&(access_count as f32).to_bits().to_le_bytes());
        prefix[0x64..0x6C].copy_from_slice(&time_ft.to_le_bytes());
        prefix[0x6C..0x70].copy_from_slice(&pin_status.to_le_bytes());
        let path_chars = path.encode_utf16().count() as u16;
        if version <= 1 {
            prefix[0x70..0x72].copy_from_slice(&path_chars.to_le_bytes());
            out.extend_from_slice(&prefix);
            push_utf16_no_nul(&mut out, path);
        } else {
            prefix[0x74..0x78].copy_from_slice(&access_count.to_le_bytes());
            prefix[0x80..0x82].copy_from_slice(&path_chars.to_le_bytes());
            out.extend_from_slice(&prefix);
            push_utf16_no_nul(&mut out, path);
            out.extend_from_slice(&0u32.to_le_bytes()); // 4-byte trailer
        }
    }
    out
}

pub fn build_synthetic_custom_destinations(custom_title: &str, custom_lnk: &[u8], task_lnk: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    // 12-byte header: unk0=2, category_count=3 (Custom, Known, Tasks), unk2=0
    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());

    // Category 0: Custom
    out.extend_from_slice(&0u32.to_le_bytes());
    let title_chars = custom_title.encode_utf16().count() as u16;
    out.extend_from_slice(&title_chars.to_le_bytes());
    push_utf16_no_nul(&mut out, custom_title);
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&CLSID_SHELL_LINK);
    out.extend_from_slice(custom_lnk);
    out.extend_from_slice(&0xBABF_FBABu32.to_le_bytes());

    // Category 1: Known (Recent = 2)
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&0xBABF_FBABu32.to_le_bytes());

    // Category 2: Tasks
    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&CLSID_SHELL_LINK);
    out.extend_from_slice(task_lnk);
    out.extend_from_slice(&0xBABF_FBABu32.to_le_bytes());

    out
}

pub fn build_usrclass_hive(when: DateTime<Utc>) -> Vec<u8> {
    let mut b = RegfBuilder::new("USRCLASS").with_header_timestamp(when);
    let item_pc = build_pidl_item_root_this_pc();
    let item_c = build_pidl_item_drive("C:\\");
    let item_docs = build_pidl_item_fs_beef0004(true, "DOCUME~1", "Documents", 0, (0x58A1, 0x7100), (512, 3));

    b.add_key("Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU")
        .set_key_timestamp("Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", when)
        .add_binary(
            "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
            "0",
            item_pc,
        )
        .add_binary(
            "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
            "MRUListEx",
            [0u32.to_le_bytes(), 0xFFFF_FFFFu32.to_le_bytes()].concat(),
        );

    b.add_key("Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU\\0")
        .add_binary(
            "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU\\0",
            "0",
            item_c,
        );

    b.add_key("Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU\\0\\0")
        .add_binary(
            "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU\\0\\0",
            "0",
            item_docs,
        );

    b.add_key("Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU\\0\\0\\0")
        .set_key_timestamp(
            "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU\\0\\0\\0",
            when,
        )
        .add_dword(
            "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU\\0\\0\\0",
            "NodeSlot",
            1,
        );

    b.add_key(
        "Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags\\1\\Shell\\{5C4F28B5-F869-4E84-8E60-F11DB97C5CC7}",
    )
    .add_dword(
        "Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags\\1\\Shell\\{5C4F28B5-F869-4E84-8E60-F11DB97C5CC7}",
        "LogicalViewMode",
        4,
    );

    // MuiCache
    b.add_key("Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache")
        .set_key_timestamp("Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache", when)
        .add_sz(
            "Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
            "LangID",
            "0409",
        )
        .add_sz(
            "Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
            "C:\\Tools\\procmon.exe.FriendlyAppName",
            "Process Monitor",
        )
        .add_sz(
            "Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
            "C:\\Tools\\procmon.exe.ApplicationCompany",
            "Sysinternals - Microsoft",
        );

    b.build()
}

pub fn build_ntuser_hive(when: DateTime<Utc>) -> Vec<u8> {
    let mut b = RegfBuilder::new("NTUSER").with_header_timestamp(when);
    let t_ft = ft(when);

    // UserAssist Win10 72B + WinXP 16B + UEME_CTLSESSION
    let ua_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count";
    let mut bin72 = vec![0u8; 72];
    bin72[0..4].copy_from_slice(&1u32.to_le_bytes()); // session
    bin72[4..8].copy_from_slice(&7u32.to_le_bytes()); // run_count
    bin72[8..12].copy_from_slice(&12u32.to_le_bytes()); // focus_count
    bin72[12..16].copy_from_slice(&45_000u32.to_le_bytes()); // focus_time_ms
    bin72[60..68].copy_from_slice(&t_ft.to_le_bytes());

    let mut bin16 = vec![0u8; 16];
    bin16[0..4].copy_from_slice(&0u32.to_le_bytes());
    bin16[4..8].copy_from_slice(&8u32.to_le_bytes()); // XP raw_count 8 => run_count 3
    bin16[8..16].copy_from_slice(&t_ft.to_le_bytes());

    b.add_key(ua_path)
        .add_binary(ua_path, rot13("C:\\Tools\\procmon.exe"), bin72)
        .add_binary(ua_path, rot13("UEME_RUNPATH:C:\\Windows\\notepad.exe"), bin16)
        .add_binary(ua_path, rot13("UEME_CTLSESSION"), vec![0u8; 72]);

    // OpenSavePidlMRU
    let os_pdf = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU\\pdf";
    let pdf_pidl = build_pidl_bytes(&[
        build_pidl_item_drive("C:\\"),
        build_pidl_item_fs_beef0004(false, "CASE~1.PDF", "case_report.pdf", 4096, (0x58A1, 0x7100), (99, 2)),
    ]);
    b.add_key(os_pdf)
        .set_key_timestamp(os_pdf, when)
        .add_binary(os_pdf, "0", pdf_pidl)
        .add_binary(
            os_pdf,
            "MRUListEx",
            [0u32.to_le_bytes(), 0xFFFF_FFFFu32.to_le_bytes()].concat(),
        );

    // LastVisitedPidlMRU
    let lv_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU";
    let mut lv_bytes = Vec::new();
    push_utf16_nul(&mut lv_bytes, "AcroRd32.exe");
    lv_bytes.extend_from_slice(&build_pidl_bytes(&[
        build_pidl_item_drive("C:\\"),
        build_pidl_item_fs_beef0004(true, "EVIDEN~1", "Evidence", 0, (0x58A1, 0x7100), (77, 1)),
    ]));
    b.add_key(lv_path)
        .set_key_timestamp(lv_path, when)
        .add_binary(lv_path, "0", lv_bytes)
        .add_binary(
            lv_path,
            "MRUListEx",
            [0u32.to_le_bytes(), 0xFFFF_FFFFu32.to_le_bytes()].concat(),
        );

    // RunMRU
    let run_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU";
    b.add_key(run_path)
        .set_key_timestamp(run_path, when)
        .add_sz(run_path, "a", "powershell.exe\\1")
        .add_sz(run_path, "MRUList", "a");

    b.build()
}

pub fn build_software_hive(when: DateTime<Utc>) -> Vec<u8> {
    let mut b = RegfBuilder::new("SOFTWARE").with_header_timestamp(when);
    let load_ft = ft(when);
    let unload_ft = ft(when + chrono::Duration::minutes(30));

    let p1 = "Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-21-1000-2000-3000-1001";
    b.add_key(p1)
        .add_expand_sz(p1, "ProfileImagePath", "C:\\Users\\Alice")
        .add_dword(p1, "Flags", 0)
        .add_dword(p1, "LocalProfileLoadTimeLow", (load_ft & 0xFFFF_FFFF) as u32)
        .add_dword(p1, "LocalProfileLoadTimeHigh", (load_ft >> 32) as u32)
        .add_dword(p1, "LocalProfileUnloadTimeLow", (unload_ft & 0xFFFF_FFFF) as u32)
        .add_dword(p1, "LocalProfileUnloadTimeHigh", (unload_ft >> 32) as u32);

    let p2 = "Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-18";
    b.add_key(p2)
        .add_expand_sz(p2, "ProfileImagePath", "%systemroot%\\system32\\config\\systemprofile")
        .add_dword(p2, "Flags", 12);

    b.build()
}

pub fn build_shimcache_win10(entries: &[(&str, DateTime<Utc>)]) -> Vec<u8> {
    let mut out = vec![0u8; 0x34];
    out[0..4].copy_from_slice(&0x34u32.to_le_bytes());
    for &(path, dt) in entries {
        let mut payload = Vec::new();
        let path_bytes_len = (path.encode_utf16().count() * 2) as u16;
        payload.extend_from_slice(&path_bytes_len.to_le_bytes());
        push_utf16_no_nul(&mut payload, path);
        payload.extend_from_slice(&ft(dt).to_le_bytes());
        payload.extend_from_slice(&4u32.to_le_bytes()); // blob size
        payload.extend_from_slice(&[1, 2, 3, 4]);

        out.extend_from_slice(b"10ts");
        out.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&payload);
    }
    out
}

pub fn build_shimcache_win8(entries: &[(&str, DateTime<Utc>)]) -> Vec<u8> {
    let mut out = vec![0u8; 0x80];
    out[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    for &(path, dt) in entries {
        let mut payload = Vec::new();
        let path_bytes_len = (path.encode_utf16().count() * 2) as u16;
        payload.extend_from_slice(&path_bytes_len.to_le_bytes());
        push_utf16_no_nul(&mut payload, path);
        payload.extend_from_slice(&0u16.to_le_bytes()); // pkg_len
        payload.extend_from_slice(&2u32.to_le_bytes()); // insert_flags (executed bit)
        payload.extend_from_slice(&0u32.to_le_bytes()); // shim_flags
        payload.extend_from_slice(&ft(dt).to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes()); // data_size

        out.extend_from_slice(b"00ts");
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&payload);
    }
    out
}

pub fn build_shimcache_win7(entries: &[(&str, DateTime<Utc>)], is_64bit: bool) -> Vec<u8> {
    let entry_size = if is_64bit { 48 } else { 32 };
    let str_base = 0x80 + entries.len() * entry_size;
    let mut out = vec![0u8; str_base];
    out[0..4].copy_from_slice(&0xBADC_0FEEu32.to_le_bytes());
    out[4..8].copy_from_slice(&(entries.len() as u32).to_le_bytes());

    for (i, &(path, dt)) in entries.iter().enumerate() {
        let path_off = out.len();
        let path_len = (path.encode_utf16().count() * 2) as u16;
        push_utf16_no_nul(&mut out, path);

        let off = 0x80 + i * entry_size;
        out[off..off + 2].copy_from_slice(&path_len.to_le_bytes());
        out[off + 2..off + 4].copy_from_slice(&path_len.to_le_bytes());
        if is_64bit {
            out[off + 8..off + 16].copy_from_slice(&(path_off as u64).to_le_bytes());
            out[off + 16..off + 24].copy_from_slice(&ft(dt).to_le_bytes());
            out[off + 24..off + 28].copy_from_slice(&2u32.to_le_bytes());
        } else {
            out[off + 4..off + 8].copy_from_slice(&(path_off as u32).to_le_bytes());
            out[off + 8..off + 16].copy_from_slice(&ft(dt).to_le_bytes());
            out[off + 16..off + 20].copy_from_slice(&2u32.to_le_bytes());
        }
    }
    out
}

pub fn build_system_hive(when: DateTime<Utc>) -> Vec<u8> {
    let mut b = RegfBuilder::new("SYSTEM").with_header_timestamp(when);
    let ft_bytes = ft(when).to_le_bytes().to_vec();

    b.add_key("Select").add_dword("Select", "Current", 1);

    // USB & USBSTOR + Properties\{83da6326-...} (raw_type = 0xFFFF_0010 DEVPROP_TYPE_FILETIME)
    let usb_inst = "ControlSet001\\Enum\\USB\\VID_0781&PID_5583\\4C530001231122115432";
    b.add_key(usb_inst)
        .set_key_timestamp(usb_inst, when)
        .add_sz(usb_inst, "DeviceDesc", "@usb.inf,%usb\\ms%;USB Mass Storage Device")
        .add_sz(usb_inst, "FriendlyName", "SanDisk Ultra USB");
    let usb_props = format!("{usb_inst}\\Properties\\{{83da6326-97a6-4088-9453-a1923f573b29}}");
    b.add_key(&usb_props)
        .add_raw_value(&usb_props, "0065", 0xFFFF_0010, ft_bytes.clone())
        .add_raw_value(&usb_props, "0066", 0xFFFF_0010, ft_bytes.clone());

    let stor_inst = "ControlSet001\\Enum\\USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\\4C530001231122115432&0";
    b.add_key(stor_inst)
        .set_key_timestamp(stor_inst, when)
        .add_sz(stor_inst, "DeviceDesc", "@disk.inf,%disk_devdesc%;Disk drive")
        .add_sz(stor_inst, "FriendlyName", "SanDisk Ultra USB Device");
    let stor_props = format!("{stor_inst}\\Properties\\{{83da6326-97a6-4088-9453-a1923f573b29}}");
    b.add_key(&stor_props)
        .add_raw_value(&stor_props, "0065", 0xFFFF_0010, ft_bytes.clone())
        .add_raw_value(&stor_props, "0066", 0xFFFF_0010, ft_bytes);

    let mut mounted_bytes = Vec::new();
    push_utf16_nul(
        &mut mounted_bytes,
        "\\??\\USBSTOR#Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00#4C530001231122115432&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
    );
    b.add_key("MountedDevices")
        .add_binary("MountedDevices", "\\DosDevices\\E:", mounted_bytes);

    // BAM
    let bam_key = "ControlSet001\\Services\\bam\\State\\UserSettings\\S-1-5-21-1000-2000-3000-1001";
    let mut bam_val = vec![0u8; 24];
    bam_val[0..8].copy_from_slice(&ft(when).to_le_bytes());
    b.add_key(bam_key)
        .add_binary(bam_key, "\\Device\\HarddiskVolume3\\Tools\\procmon.exe", bam_val);

    // ShimCache
    let shim_bytes = build_shimcache_win10(&[("C:\\Tools\\procmon.exe", when)]);
    b.add_key("ControlSet001\\Control\\Session Manager\\AppCompatCache")
        .add_binary(
            "ControlSet001\\Control\\Session Manager\\AppCompatCache",
            "AppCompatCache",
            shim_bytes,
        );

    b.build()
}

pub fn build_amcache_hive(when: DateTime<Utc>) -> Vec<u8> {
    let mut b = RegfBuilder::new("Amcache").with_header_timestamp(when);
    let k = "Root\\InventoryApplicationFile\\procmon.exe|abc123";
    b.add_key(k)
        .set_key_timestamp(k, when)
        .add_sz(k, "LowerCaseLongPath", "C:\\Tools\\procmon.exe")
        .add_sz(k, "Version", "3.96.0.0")
        .add_sz(k, "Publisher", "Sysinternals - Microsoft")
        .add_sz(k, "ProductName", "Process Monitor")
        .add_sz(k, "FileId", "0000da39a3ee5e6b4b0d3255bfef95601890afd80709");
    b.build()
}

pub fn build_setupapi_dev_log() -> String {
    "\
[Boot Session: 2025/05/10 14:00:00.000]
>>>  [Device Install (Hardware initiated) - USB\\VID_0781&PID_5583\\4C530001231122115432]
>>>  Section start 2025/05/10 14:22:11.123
     dvi: Friendly Name: SanDisk Ultra USB
     dvi: Device Description: USB Mass Storage Device
<<<  [Exit status: SUCCESS]
<<<  Section end 2025/05/10 14:22:12.000

>>>  [Device Install (Hardware initiated) - PCI\\VEN_8086&DEV_1234\\3&11583659&0]
>>>  Section start 2025/05/10 14:23:00.000
     dvi: Device Description: Non-USB PCI Device
<<<  Section end 2025/05/10 14:23:01.000

>>>  [Device Uninstall - USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\\4C530001231122115432&0]
>>>  Section start 2025/05/10 14:45:00.500
     dvi: Friendly Name: SanDisk Ultra USB Device
     dvi: Device Description: Disk drive
<<<  [Exit status: SUCCESS]
<<<  Section end 2025/05/10 14:45:01.000
"
    .to_string()
}

/// Builds a minimal valid `[MS-EVEN6]` EVTX archive with one Security 4688 (Process Created)
/// inline-BinXML event for `artifacts.activity` correlation testing.
pub fn build_minimal_evtx(when: DateTime<Utc>, process_name: &str) -> Vec<u8> {
    const CHUNK_SIZE: usize = 65_536;
    let mut chunk = vec![0u8; 0x200];

    let mut name_cache: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let write_name_ref = |buf: &mut Vec<u8>, cache: &mut std::collections::HashMap<String, u32>, name: &str| {
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
    let open_elem =
        |buf: &mut Vec<u8>, cache: &mut std::collections::HashMap<String, u32>, name: &str, attrs: &[(&str, &str)]| {
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
    let empty_elem =
        |buf: &mut Vec<u8>, cache: &mut std::collections::HashMap<String, u32>, name: &str, attrs: &[(&str, &str)]| {
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
    let text_elem = |buf: &mut Vec<u8>, cache: &mut std::collections::HashMap<String, u32>, name: &str, val: &str| {
        open_elem(buf, cache, name, &[]);
        write_inline_utf16(buf, val);
        buf.push(0x04);
    };

    let rec_start = chunk.len();
    chunk.extend_from_slice(&[0x2A, 0x2A, 0x00, 0x00]);
    chunk.extend_from_slice(&0u32.to_le_bytes());
    chunk.extend_from_slice(&1u64.to_le_bytes());
    chunk.extend_from_slice(&ft(when).to_le_bytes());
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
    let ts_str = when.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
    empty_elem(&mut chunk, &mut name_cache, "TimeCreated", &[("SystemTime", &ts_str)]);
    text_elem(&mut chunk, &mut name_cache, "EventRecordID", "1");
    text_elem(&mut chunk, &mut name_cache, "Channel", "Security");
    text_elem(&mut chunk, &mut name_cache, "Computer", "DFIR-HOST01");
    chunk.push(0x04); // /System

    open_elem(&mut chunk, &mut name_cache, "EventData", &[]);
    text_elem(&mut chunk, &mut name_cache, "Data", ""); // fallback
    open_elem(&mut chunk, &mut name_cache, "Data", &[("Name", "NewProcessName")]);
    write_inline_utf16(&mut chunk, process_name);
    chunk.push(0x04);
    open_elem(&mut chunk, &mut name_cache, "Data", &[("Name", "SubjectUserName")]);
    write_inline_utf16(&mut chunk, "Alice");
    chunk.push(0x04);
    chunk.push(0x04); // /EventData
    chunk.push(0x04); // /Event
    chunk.push(0x00); // EndOfStream

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
    let mut hdr_h = crc32fast::Hasher::new();
    hdr_h.update(&chunk[0..120]);
    hdr_h.update(&chunk[128..512]);
    chunk[0x7C..0x80].copy_from_slice(&hdr_h.finalize().to_le_bytes());

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
