use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use forensics2rust_core::utc_to_filetime;

use super::parser::{HBIN_START, MAX_BIG_DATA_CHUNK, compute_regf_checksum};
use super::{
    KEY_COMP_NAME, KEY_HIVE_ENTRY, REG_BINARY, REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_EXPAND_SZ, REG_LINK, REG_MULTI_SZ,
    REG_NONE, REG_QWORD, REG_SZ, VALUE_COMP_NAME, encode_multi_sz, encode_utf16_le_nul,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubkeyListKind {
    Lf,
    Lh,
    Li,
    Ri,
}

#[derive(Debug, Clone)]
pub struct BuilderValue {
    pub name: String,
    pub raw_type: u32,
    pub raw_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct BuilderKey {
    name: String,
    last_write_filetime: u64,
    list_kind: SubkeyListKind,
    values: Vec<BuilderValue>,
    children: BTreeMap<String, BuilderKey>,
}

#[derive(Debug, Clone)]
struct DeletedKeySpec {
    parent_path: String,
    name: String,
    last_write_filetime: u64,
    values: Vec<BuilderValue>,
}

/// Deterministic synthetic Windows Registry `regf` binary hive builder.
#[derive(Debug, Clone)]
pub struct RegfBuilder {
    root: BuilderKey,
    deleted: Vec<DeletedKeySpec>,
    primary_seq: u32,
    secondary_seq: u32,
    header_filetime: u64,
    minor_version: u32,
    file_name: String,
}

impl RegfBuilder {
    pub fn new(root_name: impl Into<String>) -> Self {
        let default_ft = utc_to_filetime(Utc::now()).unwrap_or(133_800_000_000_000_000);
        Self {
            root: BuilderKey {
                name: root_name.into(),
                last_write_filetime: default_ft,
                list_kind: SubkeyListKind::Lh,
                values: Vec::new(),
                children: BTreeMap::new(),
            },
            deleted: Vec::new(),
            primary_seq: 10,
            secondary_seq: 10,
            header_filetime: default_ft,
            minor_version: 5,
            file_name: "synthetic.dat".to_owned(),
        }
    }

    pub fn with_sequences(mut self, primary: u32, secondary: u32) -> Self {
        self.primary_seq = primary;
        self.secondary_seq = secondary;
        self
    }

    pub fn with_file_name(mut self, file_name: impl Into<String>) -> Self {
        self.file_name = file_name.into();
        self
    }

    pub fn with_header_timestamp(mut self, dt: DateTime<Utc>) -> Self {
        self.header_filetime = utc_to_filetime(dt).unwrap_or(self.header_filetime);
        self
    }

    pub fn set_root_list_kind(&mut self, kind: SubkeyListKind) -> &mut Self {
        self.root.list_kind = kind;
        self
    }

    fn ensure_key_mut(&mut self, path: &str) -> &mut BuilderKey {
        let trimmed = path.trim_matches(|c| c == '\\' || c == '/');
        let mut cur = &mut self.root;
        if trimmed.is_empty() {
            return cur;
        }
        let default_ft = self.header_filetime;
        for seg in trimmed.split(['\\', '/']).filter(|s| !s.is_empty()) {
            let key_ci = seg.to_ascii_lowercase();
            cur = cur.children.entry(key_ci).or_insert_with(|| BuilderKey {
                name: seg.to_owned(),
                last_write_filetime: default_ft,
                list_kind: SubkeyListKind::Lh,
                values: Vec::new(),
                children: BTreeMap::new(),
            });
        }
        cur
    }

    pub fn add_key(&mut self, path: &str) -> &mut Self {
        self.ensure_key_mut(path);
        self
    }

    pub fn set_key_timestamp(&mut self, path: &str, dt: DateTime<Utc>) -> &mut Self {
        let ft = utc_to_filetime(dt).unwrap_or(0);
        self.ensure_key_mut(path).last_write_filetime = ft;
        self
    }

    pub fn set_key_list_kind(&mut self, path: &str, kind: SubkeyListKind) -> &mut Self {
        self.ensure_key_mut(path).list_kind = kind;
        self
    }

    pub fn add_raw_value(
        &mut self,
        key_path: &str,
        value_name: impl Into<String>,
        raw_type: u32,
        raw_bytes: Vec<u8>,
    ) -> &mut Self {
        self.ensure_key_mut(key_path).values.push(BuilderValue {
            name: value_name.into(),
            raw_type,
            raw_bytes,
        });
        self
    }

    pub fn add_sz(&mut self, key_path: &str, value_name: impl Into<String>, val: &str) -> &mut Self {
        self.add_raw_value(key_path, value_name, REG_SZ, encode_utf16_le_nul(val))
    }

    pub fn add_expand_sz(&mut self, key_path: &str, value_name: impl Into<String>, val: &str) -> &mut Self {
        self.add_raw_value(key_path, value_name, REG_EXPAND_SZ, encode_utf16_le_nul(val))
    }

    pub fn add_link(&mut self, key_path: &str, value_name: impl Into<String>, val: &str) -> &mut Self {
        self.add_raw_value(key_path, value_name, REG_LINK, encode_utf16_le_nul(val))
    }

    pub fn add_dword(&mut self, key_path: &str, value_name: impl Into<String>, val: u32) -> &mut Self {
        self.add_raw_value(key_path, value_name, REG_DWORD, val.to_le_bytes().to_vec())
    }

    pub fn add_dword_be(&mut self, key_path: &str, value_name: impl Into<String>, val: u32) -> &mut Self {
        self.add_raw_value(key_path, value_name, REG_DWORD_BIG_ENDIAN, val.to_be_bytes().to_vec())
    }

    pub fn add_qword(&mut self, key_path: &str, value_name: impl Into<String>, val: u64) -> &mut Self {
        self.add_raw_value(key_path, value_name, REG_QWORD, val.to_le_bytes().to_vec())
    }

    pub fn add_binary(&mut self, key_path: &str, value_name: impl Into<String>, data: Vec<u8>) -> &mut Self {
        self.add_raw_value(key_path, value_name, REG_BINARY, data)
    }

    pub fn add_multi_sz(&mut self, key_path: &str, value_name: impl Into<String>, items: &[String]) -> &mut Self {
        self.add_raw_value(key_path, value_name, REG_MULTI_SZ, encode_multi_sz(items))
    }

    pub fn add_none(&mut self, key_path: &str, value_name: impl Into<String>, data: Vec<u8>) -> &mut Self {
        self.add_raw_value(key_path, value_name, REG_NONE, data)
    }

    /// Adds an unallocated (`raw_size > 0`) deleted key + deleted values for carving tests.
    pub fn add_deleted_key(
        &mut self,
        parent_path: impl Into<String>,
        name: impl Into<String>,
        dt: DateTime<Utc>,
        values: Vec<BuilderValue>,
    ) -> &mut Self {
        self.deleted.push(DeletedKeySpec {
            parent_path: parent_path.into(),
            name: name.into(),
            last_write_filetime: utc_to_filetime(dt).unwrap_or(self.header_filetime),
            values,
        });
        self
    }

    /// Serializes the synthetic hive into valid `regf` bytes (`>= 8192` bytes).
    pub fn build(&self) -> Vec<u8> {
        let mut alloc = HbinAllocator::new(self.header_filetime);
        let mut active_offsets: BTreeMap<String, u32> = BTreeMap::new();

        let root_offset = self.emit_key(&mut alloc, &self.root, "", u32::MAX, true, &mut active_offsets);

        for del in &self.deleted {
            let parent_norm = del
                .parent_path
                .trim_matches(|c| c == '\\' || c == '/')
                .to_ascii_lowercase();
            let parent_off = active_offsets.get(&parent_norm).copied().unwrap_or(u32::MAX);
            emit_deleted_nk(&mut alloc, del, parent_off);
        }

        let hbin_buf = alloc.finish();

        let mut base = vec![0u8; HBIN_START];
        base[0..4].copy_from_slice(b"regf");
        base[0x04..0x08].copy_from_slice(&self.primary_seq.to_le_bytes());
        base[0x08..0x0C].copy_from_slice(&self.secondary_seq.to_le_bytes());
        base[0x0C..0x14].copy_from_slice(&self.header_filetime.to_le_bytes());
        base[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        base[0x18..0x1C].copy_from_slice(&self.minor_version.to_le_bytes());
        base[0x1C..0x20].copy_from_slice(&0u32.to_le_bytes());
        base[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
        base[0x24..0x28].copy_from_slice(&root_offset.to_le_bytes());
        base[0x28..0x2C].copy_from_slice(&(hbin_buf.len() as u32).to_le_bytes());
        base[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes());

        let fname_utf16: Vec<u8> = self
            .file_name
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .take(62)
            .collect();
        base[0x30..0x30 + fname_utf16.len()].copy_from_slice(&fname_utf16);

        let checksum = compute_regf_checksum(&base);
        base[0x1FC..0x200].copy_from_slice(&checksum.to_le_bytes());

        let mut out = Vec::with_capacity(HBIN_START + hbin_buf.len());
        out.extend_from_slice(&base);
        out.extend_from_slice(&hbin_buf);
        out
    }

    fn emit_key(
        &self,
        alloc: &mut HbinAllocator,
        key: &BuilderKey,
        norm_path: &str,
        parent_offset: u32,
        is_root: bool,
        active_offsets: &mut BTreeMap<String, u32>,
    ) -> u32 {
        let mut vk_offsets = Vec::with_capacity(key.values.len());
        for val in &key.values {
            vk_offsets.push(emit_vk(alloc, val, true));
        }

        let value_list_offset = if vk_offsets.is_empty() {
            u32::MAX
        } else {
            let mut list_payload = Vec::with_capacity(vk_offsets.len() * 4);
            for off in &vk_offsets {
                list_payload.extend_from_slice(&off.to_le_bytes());
            }
            alloc.alloc_cell(&list_payload, true)
        };

        // Allocate placeholder `nk` first so children have the exact `parent_offset`.
        let (encoded_name, name_compressed) = encode_regf_name(&key.name);
        let mut flags = if is_root { KEY_HIVE_ENTRY } else { 0 };
        if name_compressed {
            flags |= KEY_COMP_NAME;
        }
        let nk_len = 0x4C + encoded_name.len();
        let mut nk_payload = vec![0u8; nk_len];
        nk_payload[0..2].copy_from_slice(b"nk");
        nk_payload[0x02..0x04].copy_from_slice(&flags.to_le_bytes());
        nk_payload[0x04..0x0C].copy_from_slice(&key.last_write_filetime.to_le_bytes());
        nk_payload[0x10..0x14].copy_from_slice(&parent_offset.to_le_bytes());
        nk_payload[0x14..0x18].copy_from_slice(&(key.children.len() as u32).to_le_bytes());
        nk_payload[0x1C..0x20].copy_from_slice(&u32::MAX.to_le_bytes());
        nk_payload[0x24..0x28].copy_from_slice(&(key.values.len() as u32).to_le_bytes());
        nk_payload[0x28..0x2C].copy_from_slice(&value_list_offset.to_le_bytes());
        nk_payload[0x2C..0x30].copy_from_slice(&u32::MAX.to_le_bytes());
        nk_payload[0x30..0x34].copy_from_slice(&u32::MAX.to_le_bytes());
        nk_payload[0x48..0x4A].copy_from_slice(&(encoded_name.len() as u16).to_le_bytes());
        nk_payload[0x4C..0x4C + encoded_name.len()].copy_from_slice(&encoded_name);

        let nk_offset = alloc.alloc_cell(&nk_payload, true);
        active_offsets.insert(norm_path.to_owned(), nk_offset);

        let mut child_entries: Vec<(String, u32)> = Vec::with_capacity(key.children.len());
        for (child_ci, child) in &key.children {
            let child_norm = if norm_path.is_empty() {
                child_ci.clone()
            } else {
                format!("{norm_path}\\{child_ci}")
            };
            let child_off = self.emit_key(alloc, child, &child_norm, nk_offset, false, active_offsets);
            child_entries.push((child.name.clone(), child_off));
        }

        if !child_entries.is_empty() {
            let list_off = emit_subkey_list(alloc, key.list_kind, &child_entries);
            alloc.patch_u32(nk_offset as usize + 4 + 0x1C, list_off);
        }

        nk_offset
    }
}

fn encode_regf_name(name: &str) -> (Vec<u8>, bool) {
    if name.chars().all(|c| u32::from(c) <= 0xFF) {
        (name.chars().map(|c| c as u8).collect(), true)
    } else {
        (name.encode_utf16().flat_map(u16::to_le_bytes).collect(), false)
    }
}

fn lh_hash(name: &str) -> u32 {
    let mut h = 0u32;
    for c in name.chars().flat_map(|ch| ch.to_uppercase()).flat_map(|ch| {
        let mut buf = [0u16; 2];
        ch.encode_utf16(&mut buf).to_vec()
    }) {
        h = h.wrapping_mul(37).wrapping_add(u32::from(c));
    }
    h
}

fn emit_subkey_list(alloc: &mut HbinAllocator, kind: SubkeyListKind, entries: &[(String, u32)]) -> u32 {
    match kind {
        SubkeyListKind::Lf => {
            let mut payload = Vec::with_capacity(4 + entries.len() * 8);
            payload.extend_from_slice(b"lf");
            payload.extend_from_slice(&(entries.len() as u16).to_le_bytes());
            for (name, off) in entries {
                payload.extend_from_slice(&off.to_le_bytes());
                let mut hint = [0u8; 4];
                for (dst, b) in hint.iter_mut().zip(name.as_bytes()) {
                    *dst = *b;
                }
                payload.extend_from_slice(&hint);
            }
            alloc.alloc_cell(&payload, true)
        }
        SubkeyListKind::Lh => {
            let mut payload = Vec::with_capacity(4 + entries.len() * 8);
            payload.extend_from_slice(b"lh");
            payload.extend_from_slice(&(entries.len() as u16).to_le_bytes());
            for (name, off) in entries {
                payload.extend_from_slice(&off.to_le_bytes());
                payload.extend_from_slice(&lh_hash(name).to_le_bytes());
            }
            alloc.alloc_cell(&payload, true)
        }
        SubkeyListKind::Li => emit_li(alloc, entries),
        SubkeyListKind::Ri => {
            let chunk_size = (entries.len() / 2).max(1);
            let mut sub_offsets = Vec::new();
            for chunk in entries.chunks(chunk_size) {
                sub_offsets.push(emit_li(alloc, chunk));
            }
            let mut payload = Vec::with_capacity(4 + sub_offsets.len() * 4);
            payload.extend_from_slice(b"ri");
            payload.extend_from_slice(&(sub_offsets.len() as u16).to_le_bytes());
            for off in sub_offsets {
                payload.extend_from_slice(&off.to_le_bytes());
            }
            alloc.alloc_cell(&payload, true)
        }
    }
}

fn emit_li(alloc: &mut HbinAllocator, entries: &[(String, u32)]) -> u32 {
    let mut payload = Vec::with_capacity(4 + entries.len() * 4);
    payload.extend_from_slice(b"li");
    payload.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    for (_, off) in entries {
        payload.extend_from_slice(&off.to_le_bytes());
    }
    alloc.alloc_cell(&payload, true)
}

fn emit_vk(alloc: &mut HbinAllocator, val: &BuilderValue, allocated: bool) -> u32 {
    let (encoded_name, name_compressed) = encode_regf_name(&val.name);
    let flags = if !val.name.is_empty() && name_compressed {
        VALUE_COMP_NAME
    } else {
        0
    };

    let data_len = val.raw_bytes.len();
    let (raw_data_length, data_offset_or_inline) = if data_len <= 4 {
        let mut inline_bytes = [0u8; 4];
        inline_bytes[..data_len].copy_from_slice(&val.raw_bytes);
        (0x8000_0000u32 | (data_len as u32), u32::from_le_bytes(inline_bytes))
    } else if data_len > MAX_BIG_DATA_CHUNK {
        let mut seg_offsets = Vec::new();
        for chunk in val.raw_bytes.chunks(MAX_BIG_DATA_CHUNK) {
            seg_offsets.push(alloc.alloc_cell(chunk, allocated));
        }
        let mut seg_list = Vec::with_capacity(seg_offsets.len() * 4);
        for off in &seg_offsets {
            seg_list.extend_from_slice(&off.to_le_bytes());
        }
        let seg_list_off = alloc.alloc_cell(&seg_list, allocated);

        let mut db_payload = Vec::with_capacity(8);
        db_payload.extend_from_slice(b"db");
        db_payload.extend_from_slice(&(seg_offsets.len() as u16).to_le_bytes());
        db_payload.extend_from_slice(&seg_list_off.to_le_bytes());
        let db_off = alloc.alloc_cell(&db_payload, allocated);
        (data_len as u32, db_off)
    } else {
        let data_off = alloc.alloc_cell(&val.raw_bytes, allocated);
        (data_len as u32, data_off)
    };

    let mut payload = vec![0u8; 0x14 + encoded_name.len()];
    payload[0..2].copy_from_slice(b"vk");
    payload[0x02..0x04].copy_from_slice(&(encoded_name.len() as u16).to_le_bytes());
    payload[0x04..0x08].copy_from_slice(&raw_data_length.to_le_bytes());
    payload[0x08..0x0C].copy_from_slice(&data_offset_or_inline.to_le_bytes());
    payload[0x0C..0x10].copy_from_slice(&val.raw_type.to_le_bytes());
    payload[0x10..0x12].copy_from_slice(&flags.to_le_bytes());
    payload[0x14..0x14 + encoded_name.len()].copy_from_slice(&encoded_name);

    alloc.alloc_cell(&payload, allocated)
}

fn emit_deleted_nk(alloc: &mut HbinAllocator, spec: &DeletedKeySpec, parent_offset: u32) {
    let mut vk_offsets = Vec::with_capacity(spec.values.len());
    for val in &spec.values {
        vk_offsets.push(emit_vk(alloc, val, false));
    }
    let value_list_offset = if vk_offsets.is_empty() {
        u32::MAX
    } else {
        let mut list_payload = Vec::with_capacity(vk_offsets.len() * 4);
        for off in &vk_offsets {
            list_payload.extend_from_slice(&off.to_le_bytes());
        }
        alloc.alloc_cell(&list_payload, false)
    };

    let (encoded_name, name_compressed) = encode_regf_name(&spec.name);
    let flags = if name_compressed { KEY_COMP_NAME } else { 0 };
    let mut nk_payload = vec![0u8; 0x4C + encoded_name.len()];
    nk_payload[0..2].copy_from_slice(b"nk");
    nk_payload[0x02..0x04].copy_from_slice(&flags.to_le_bytes());
    nk_payload[0x04..0x0C].copy_from_slice(&spec.last_write_filetime.to_le_bytes());
    nk_payload[0x10..0x14].copy_from_slice(&parent_offset.to_le_bytes());
    nk_payload[0x1C..0x20].copy_from_slice(&u32::MAX.to_le_bytes());
    nk_payload[0x24..0x28].copy_from_slice(&(spec.values.len() as u32).to_le_bytes());
    nk_payload[0x28..0x2C].copy_from_slice(&value_list_offset.to_le_bytes());
    nk_payload[0x2C..0x30].copy_from_slice(&u32::MAX.to_le_bytes());
    nk_payload[0x30..0x34].copy_from_slice(&u32::MAX.to_le_bytes());
    nk_payload[0x48..0x4A].copy_from_slice(&(encoded_name.len() as u16).to_le_bytes());
    nk_payload[0x4C..0x4C + encoded_name.len()].copy_from_slice(&encoded_name);

    alloc.alloc_cell(&nk_payload, false);
}

struct HbinAllocator {
    buf: Vec<u8>,
    current_bin_start: usize,
    current_bin_end: usize,
    cursor: usize,
    filetime: u64,
}

impl HbinAllocator {
    fn new(filetime: u64) -> Self {
        let mut alloc = Self {
            buf: Vec::new(),
            current_bin_start: 0,
            current_bin_end: 0,
            cursor: 0,
            filetime,
        };
        alloc.start_bin(4096);
        alloc
    }

    fn start_bin(&mut self, min_size: usize) {
        let aligned_size = ((min_size.max(4096)) + 4095) & !4095;
        let bin_start = self.buf.len();
        self.buf.resize(bin_start + aligned_size, 0);
        self.buf[bin_start..bin_start + 4].copy_from_slice(b"hbin");
        self.buf[bin_start + 4..bin_start + 8].copy_from_slice(&(bin_start as u32).to_le_bytes());
        self.buf[bin_start + 8..bin_start + 12].copy_from_slice(&(aligned_size as u32).to_le_bytes());
        self.buf[bin_start + 0x14..bin_start + 0x1C].copy_from_slice(&self.filetime.to_le_bytes());
        self.current_bin_start = bin_start;
        self.current_bin_end = bin_start + aligned_size;
        self.cursor = bin_start + 0x20;
    }

    fn alloc_cell(&mut self, payload: &[u8], allocated: bool) -> u32 {
        let total = ((4 + payload.len() + 7) & !7).max(8);
        if self.cursor + total > self.current_bin_end {
            let rem = self.current_bin_end - self.cursor;
            if rem >= 8 {
                let free_size = (rem as i32).to_le_bytes();
                self.buf[self.cursor..self.cursor + 4].copy_from_slice(&free_size);
            }
            self.start_bin(0x20 + total);
        }
        let cell_pos = self.cursor;
        let raw_size = if allocated { -(total as i32) } else { total as i32 };
        self.buf[cell_pos..cell_pos + 4].copy_from_slice(&raw_size.to_le_bytes());
        self.buf[cell_pos + 4..cell_pos + 4 + payload.len()].copy_from_slice(payload);
        self.cursor += total;
        cell_pos as u32
    }

    fn patch_u32(&mut self, offset: usize, val: u32) {
        self.buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
    }

    fn finish(mut self) -> Vec<u8> {
        let rem = self.current_bin_end - self.cursor;
        if rem >= 8 {
            let free_size = (rem as i32).to_le_bytes();
            self.buf[self.cursor..self.cursor + 4].copy_from_slice(&free_size);
        }
        self.buf
    }
}
