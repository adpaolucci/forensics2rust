use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use chrono::{DateTime, TimeZone, Utc};
use forensics2rust_core::{
    FORENSIC_TOOL_CATALOG, ForensicError, ForensicSource, QueryHelper, ToolCategory, crc32_ieee, utc_to_filetime,
};
use forensics2rust_evtx::parser::{EvtxArchive, EvtxParseOptions};
use forensics2rust_evtx::providers::{
    ChannelsProvider, FullEventLogProvider, LogonProvider, ProcessProvider, SourcesProvider,
};
use forensics2rust_evtx::{LiveQueryOptions, all_providers, all_providers_with_options};
use guap_table::{CellValue, ColumnType, TableError, TableProvider, TableQuery};

const CHUNK_SIZE: usize = 65_536;
const CHUNK_DATA_OFFSET: usize = 0x200;

/// Spec-compliant `[MS-EVEN6]` binary EVTX builder for offline verification.
struct SyntheticEvtxBuilder {
    chunks: Vec<Vec<u8>>,
    cur_chunk: Vec<u8>,
    name_cache: HashMap<String, u32>,
    template_cache: HashMap<String, u32>,
    next_record_id: u64,
    first_rec_in_chunk: u64,
    last_rec_in_chunk: u64,
    last_rec_offset: u32,
}

#[derive(Clone)]
enum SubVal {
    Null,
    Utf16(String),
    Ansi(String),
    I8(i8),
    U8(u8),
    I16(i16),
    U16(u16),
    I32(i32),
    U32(u32),
    I64(i64),
    U64(u64),
    F32(f32),
    F64(f64),
    Bool(bool),
    Binary(Vec<u8>),
    Guid([u8; 16]),
    FileTime(DateTime<Utc>),
    SysTime(u16, u16, u16, u16, u16, u16, u16),
    Sid(Vec<u8>),
    Hex32(u32),
    Hex64(u64),
    Utf16Array(Vec<String>),
    EventDataBinXml(Vec<(String, String)>),
    DataNodeBinXml(String, String),
    UserDataEventXml(Vec<(String, String)>),
}

impl SubVal {
    fn value_type(&self) -> u8 {
        match self {
            Self::Null => 0x00,
            Self::Utf16(_) => 0x01,
            Self::Ansi(_) => 0x02,
            Self::I8(_) => 0x03,
            Self::U8(_) => 0x04,
            Self::I16(_) => 0x05,
            Self::U16(_) => 0x06,
            Self::I32(_) => 0x07,
            Self::U32(_) => 0x08,
            Self::I64(_) => 0x09,
            Self::U64(_) => 0x0A,
            Self::F32(_) => 0x0B,
            Self::F64(_) => 0x0C,
            Self::Bool(_) => 0x0D,
            Self::Binary(_) => 0x0E,
            Self::Guid(_) => 0x0F,
            Self::FileTime(_) => 0x11,
            Self::SysTime(..) => 0x12,
            Self::Sid(_) => 0x13,
            Self::Hex32(_) => 0x14,
            Self::Hex64(_) => 0x15,
            Self::Utf16Array(_) => 0x81,
            Self::EventDataBinXml(_) | Self::DataNodeBinXml(..) | Self::UserDataEventXml(_) => 0x21,
        }
    }
}

#[derive(Clone)]
struct EventSpec {
    time: DateTime<Utc>,
    provider: String,
    provider_guid: Option<[u8; 16]>,
    event_id: u16,
    qualifiers: Option<u16>,
    version: u8,
    level: u8,
    task: u16,
    opcode: u8,
    keywords: u64,
    process_id: u32,
    thread_id: u32,
    channel: String,
    computer: String,
    user_sid: Option<Vec<u8>>,
    event_data: Vec<(String, String)>,
    user_data: Vec<(String, String)>,
}

impl EventSpec {
    fn new(time: DateTime<Utc>, channel: &str, provider: &str, event_id: u16) -> Self {
        Self {
            time,
            provider: provider.to_string(),
            provider_guid: None,
            event_id,
            qualifiers: None,
            version: 0,
            level: 4,
            task: 0,
            opcode: 0,
            keywords: 0x8020_0000_0000_0000,
            process_id: 4,
            thread_id: 100,
            channel: channel.to_string(),
            computer: "DFIR-HOST01".to_string(),
            user_sid: None,
            event_data: Vec::new(),
            user_data: Vec::new(),
        }
    }

    fn data(mut self, k: &str, v: &str) -> Self {
        self.event_data.push((k.to_string(), v.to_string()));
        self
    }

    fn udata(mut self, k: &str, v: &str) -> Self {
        self.user_data.push((k.to_string(), v.to_string()));
        self
    }

    fn sid(mut self, sid: Vec<u8>) -> Self {
        self.user_sid = Some(sid);
        self
    }

    fn guid(mut self, guid: [u8; 16]) -> Self {
        self.provider_guid = Some(guid);
        self
    }

    fn level(mut self, level: u8) -> Self {
        self.level = level;
        self
    }

    fn keywords(mut self, kw: u64) -> Self {
        self.keywords = kw;
        self
    }

    fn computer(mut self, computer: &str) -> Self {
        self.computer = computer.to_string();
        self
    }
}

impl SyntheticEvtxBuilder {
    fn new() -> Self {
        Self {
            chunks: Vec::new(),
            cur_chunk: vec![0u8; CHUNK_DATA_OFFSET],
            name_cache: HashMap::new(),
            template_cache: HashMap::new(),
            next_record_id: 1,
            first_rec_in_chunk: 0,
            last_rec_in_chunk: 0,
            last_rec_offset: 0,
        }
    }

    fn add_templated_event(&mut self, spec: &EventSpec) {
        let rec_id = self.next_record_id;
        let written_ft = utc_to_filetime(spec.time).unwrap_or(133_000_000_000_000_000);
        let tpl_key = if !spec.user_data.is_empty() {
            "event_userdata_tpl"
        } else {
            "event_eventdata_tpl"
        };

        let mut subs = vec![
            SubVal::Utf16(spec.provider.clone()),
            match spec.provider_guid {
                Some(g) => SubVal::Guid(g),
                None => SubVal::Null,
            },
            SubVal::U16(spec.event_id),
            SubVal::U8(spec.version),
            SubVal::U8(spec.level),
            SubVal::U16(spec.task),
            SubVal::U8(spec.opcode),
            SubVal::Hex64(spec.keywords),
            SubVal::FileTime(spec.time),
            SubVal::U64(rec_id),
            SubVal::U32(spec.process_id),
            SubVal::U32(spec.thread_id),
            SubVal::Utf16(spec.channel.clone()),
            SubVal::Utf16(spec.computer.clone()),
            match &spec.user_sid {
                Some(s) => SubVal::Sid(s.clone()),
                None => SubVal::Null,
            },
        ];

        if !spec.user_data.is_empty() {
            subs.push(SubVal::UserDataEventXml(spec.user_data.clone()));
        } else {
            subs.push(SubVal::EventDataBinXml(spec.event_data.clone()));
        }

        // Snapshot current chunk state in case this record overflows 65,536 bytes.
        let checkpoint_len = self.cur_chunk.len();
        let checkpoint_names = self.name_cache.clone();
        let checkpoint_tpls = self.template_cache.clone();

        if !self.try_append_templated_record(rec_id, written_ft, tpl_key, &subs, spec.qualifiers) {
            self.cur_chunk.truncate(checkpoint_len);
            self.name_cache = checkpoint_names;
            self.template_cache = checkpoint_tpls;
            self.flush_chunk();
            assert!(
                self.try_append_templated_record(rec_id, written_ft, tpl_key, &subs, spec.qualifiers),
                "single synthetic record exceeded 65,536-byte chunk limit"
            );
        }

        self.next_record_id += 1;
    }

    fn add_inline_event(&mut self, spec: &EventSpec, include_cdata_and_entity: bool) {
        let rec_id = self.next_record_id;
        let written_ft = utc_to_filetime(spec.time).unwrap_or(133_000_000_000_000_000);
        let checkpoint_len = self.cur_chunk.len();
        let checkpoint_names = self.name_cache.clone();
        let checkpoint_tpls = self.template_cache.clone();

        if !self.try_append_inline_record(rec_id, written_ft, spec, include_cdata_and_entity) {
            self.cur_chunk.truncate(checkpoint_len);
            self.name_cache = checkpoint_names;
            self.template_cache = checkpoint_tpls;
            self.flush_chunk();
            assert!(
                self.try_append_inline_record(rec_id, written_ft, spec, include_cdata_and_entity),
                "single inline synthetic record exceeded 65,536-byte chunk limit"
            );
        }

        self.next_record_id += 1;
    }

    fn add_custom_template_record(&mut self, time: DateTime<Utc>, tpl_key: &str, subs: Vec<SubVal>) {
        let rec_id = self.next_record_id;
        let written_ft = utc_to_filetime(time).unwrap_or(133_000_000_000_000_000);
        let rec_start = self.cur_chunk.len();
        self.write_record_header(rec_id, written_ft);
        self.cur_chunk.extend_from_slice(&[0x0F, 0x01, 0x01, 0x00]); // FragmentHeader
        self.cur_chunk.push(0x0C); // TemplateInstance
        self.cur_chunk.push(0x01);
        self.cur_chunk.extend_from_slice(&0xAABB_CCDDu32.to_le_bytes());
        let tpl_off_slot = self.cur_chunk.len();
        self.cur_chunk.extend_from_slice(&0u32.to_le_bytes());

        if let Some(&cached_off) = self.template_cache.get(tpl_key) {
            self.cur_chunk[tpl_off_slot..tpl_off_slot + 4].copy_from_slice(&cached_off.to_le_bytes());
        } else {
            let tpl_off = self.cur_chunk.len() as u32;
            self.cur_chunk[tpl_off_slot..tpl_off_slot + 4].copy_from_slice(&tpl_off.to_le_bytes());
            self.template_cache.insert(tpl_key.to_string(), tpl_off);
            self.cur_chunk.extend_from_slice(&0u32.to_le_bytes()); // next_offset
            self.cur_chunk.extend_from_slice(&[0x11; 16]); // template GUID
            let size_slot = self.cur_chunk.len();
            self.cur_chunk.extend_from_slice(&0u32.to_le_bytes());
            let body_start = self.cur_chunk.len();

            self.cur_chunk.extend_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
            self.open_elem("Event", 0xFFFF, &[]);
            self.open_elem("System", 0xFFFF, &[]);
            self.open_elem_sub(
                "Provider",
                0xFFFF,
                &[("Name", 0, 0x01, false), ("Guid", 1, 0x0F, true)],
                None,
            );
            self.open_elem_text_sub("EventID", 0xFFFF, 2, 0x06);
            self.open_elem_text_sub("Level", 0xFFFF, 3, 0x04);
            self.open_elem_sub("TimeCreated", 0xFFFF, &[("SystemTime", 4, 0x11, false)], None);
            self.open_elem_text_sub("EventRecordID", 0xFFFF, 5, 0x0A);
            self.open_elem_text_sub("Channel", 0xFFFF, 6, 0x01);
            self.open_elem_text_sub("Computer", 0xFFFF, 7, 0x01);
            self.open_elem_sub("Security", 8, &[("UserID", 8, 0x13, true)], None);
            self.close_elem(); // System

            self.open_elem("EventData", 0xFFFF, &[]);
            let fields = [
                ("AnsiVal", 9u16, 0x02u8, false),
                ("Int8Val", 10, 0x03, false),
                ("Int16Val", 11, 0x05, false),
                ("Int32Val", 12, 0x07, false),
                ("UInt32Val", 13, 0x08, false),
                ("Int64Val", 14, 0x09, false),
                ("Real32Val", 15, 0x0B, false),
                ("Real64Val", 16, 0x0C, false),
                ("BoolVal", 17, 0x0D, false),
                ("BinaryVal", 18, 0x0E, false),
                ("SysTimeVal", 19, 0x12, false),
                ("Hex32Val", 20, 0x14, false),
                ("Hex64Val", 21, 0x15, false),
                ("ArrayVal", 22, 0x81, false),
                ("OptionalOmitted", 23, 0x01, true),
            ];
            for (fname, sub_id, vtype, opt) in fields {
                let dep = if opt { sub_id } else { 0xFFFF };
                self.open_elem_with_const_attr_and_sub("Data", dep, ("Name", fname), (sub_id, vtype, opt));
            }
            // Sub 24: nested BinXmlType (0x21)
            self.cur_chunk.push(0x0D);
            self.cur_chunk.extend_from_slice(&24u16.to_le_bytes());
            self.cur_chunk.push(0x21);
            self.close_elem(); // EventData
            self.close_elem(); // Event
            self.cur_chunk.push(0x00); // EndOfStream

            let body_size = (self.cur_chunk.len() - body_start) as u32;
            self.cur_chunk[size_slot..size_slot + 4].copy_from_slice(&body_size.to_le_bytes());
        }

        self.write_substitutions(&subs);
        self.finish_record(rec_start, rec_id);
        self.next_record_id += 1;
    }

    fn try_append_templated_record(
        &mut self,
        rec_id: u64,
        written_ft: u64,
        tpl_key: &str,
        subs: &[SubVal],
        qualifiers: Option<u16>,
    ) -> bool {
        let rec_start = self.cur_chunk.len();
        self.write_record_header(rec_id, written_ft);
        self.cur_chunk.extend_from_slice(&[0x0F, 0x01, 0x01, 0x00]); // FragmentHeader
        self.cur_chunk.push(0x0C); // TemplateInstance
        self.cur_chunk.push(0x01);
        let tpl_id: u32 = if tpl_key == "event_userdata_tpl" {
            0x2222_0002
        } else {
            0x1111_0001
        };
        self.cur_chunk.extend_from_slice(&tpl_id.to_le_bytes());
        let tpl_off_slot = self.cur_chunk.len();
        self.cur_chunk.extend_from_slice(&0u32.to_le_bytes());

        let effective_key = if qualifiers.is_some() {
            format!("{tpl_key}_q{}", qualifiers.unwrap_or(0))
        } else {
            tpl_key.to_string()
        };

        if let Some(&cached_off) = self.template_cache.get(&effective_key) {
            self.cur_chunk[tpl_off_slot..tpl_off_slot + 4].copy_from_slice(&cached_off.to_le_bytes());
        } else {
            let tpl_off = self.cur_chunk.len() as u32;
            self.cur_chunk[tpl_off_slot..tpl_off_slot + 4].copy_from_slice(&tpl_off.to_le_bytes());
            self.template_cache.insert(effective_key, tpl_off);
            self.cur_chunk.extend_from_slice(&0u32.to_le_bytes()); // next_offset
            self.cur_chunk.extend_from_slice(&[0x55; 16]);
            let size_slot = self.cur_chunk.len();
            self.cur_chunk.extend_from_slice(&0u32.to_le_bytes());
            let body_start = self.cur_chunk.len();

            self.cur_chunk.extend_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
            self.open_elem("Event", 0xFFFF, &[]);
            self.open_elem("System", 0xFFFF, &[]);
            self.open_elem_sub(
                "Provider",
                0xFFFF,
                &[("Name", 0, 0x01, false), ("Guid", 1, 0x0F, true)],
                None,
            );
            if let Some(q) = qualifiers {
                self.open_elem("EventID", 0xFFFF, &[("Qualifiers", &q.to_string())]);
                self.write_sub_token(2, 0x06, false);
                self.close_elem();
            } else {
                self.open_elem_text_sub("EventID", 0xFFFF, 2, 0x06);
            }
            self.open_elem_text_sub("Version", 0xFFFF, 3, 0x04);
            self.open_elem_text_sub("Level", 0xFFFF, 4, 0x04);
            self.open_elem_text_sub("Task", 0xFFFF, 5, 0x06);
            self.open_elem_text_sub("Opcode", 0xFFFF, 6, 0x04);
            self.open_elem_text_sub("Keywords", 0xFFFF, 7, 0x15);
            self.open_elem_sub("TimeCreated", 0xFFFF, &[("SystemTime", 8, 0x11, false)], None);
            self.open_elem_text_sub("EventRecordID", 0xFFFF, 9, 0x0A);
            self.open_elem_sub(
                "Execution",
                0xFFFF,
                &[("ProcessID", 10, 0x08, false), ("ThreadID", 11, 0x08, false)],
                None,
            );
            self.open_elem_text_sub("Channel", 0xFFFF, 12, 0x01);
            self.open_elem_text_sub("Computer", 0xFFFF, 13, 0x01);
            self.open_elem_sub("Security", 14, &[("UserID", 14, 0x13, true)], None);
            self.close_elem(); // System

            // Sub 15 is BinXmlType (0x21) holding <EventData>...</EventData> or <UserData>...</UserData>
            self.write_sub_token(15, 0x21, false);
            self.close_elem(); // Event
            self.cur_chunk.push(0x00); // EndOfStream

            let body_size = (self.cur_chunk.len() - body_start) as u32;
            self.cur_chunk[size_slot..size_slot + 4].copy_from_slice(&body_size.to_le_bytes());
        }

        self.write_substitutions(subs);
        self.finish_record(rec_start, rec_id);
        self.cur_chunk.len() <= CHUNK_SIZE
    }

    fn try_append_inline_record(
        &mut self,
        rec_id: u64,
        written_ft: u64,
        spec: &EventSpec,
        include_cdata_and_entity: bool,
    ) -> bool {
        let rec_start = self.cur_chunk.len();
        self.write_record_header(rec_id, written_ft);
        self.cur_chunk.extend_from_slice(&[0x0F, 0x01, 0x01, 0x00]); // FragmentHeader

        self.open_elem("Event", 0xFFFF, &[]);
        self.open_elem("System", 0xFFFF, &[]);
        self.empty_elem("Provider", &[("Name", &spec.provider)]);
        self.text_elem("EventID", &spec.event_id.to_string());
        self.text_elem("Level", &spec.level.to_string());
        let ts = spec.time.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
        self.empty_elem("TimeCreated", &[("SystemTime", &ts)]);
        self.text_elem("EventRecordID", &rec_id.to_string());
        self.text_elem("Channel", &spec.channel);
        self.text_elem("Computer", &spec.computer);
        self.close_elem(); // System

        self.open_elem("EventData", 0xFFFF, &[]);
        for (k, v) in &spec.event_data {
            self.open_elem("Data", 0xFFFF, &[("Name", k)]);
            self.write_inline_utf16_val(v);
            self.close_elem();
        }
        if include_cdata_and_entity {
            self.open_elem("Data", 0xFFFF, &[("Name", "SpecialChars")]);
            // Inline UTF-16 value + EntityRef (&amp;) + CDATA
            self.cur_chunk.push(0x45); // Value with more data
            self.cur_chunk.push(0x01);
            let left = "left";
            let units: Vec<u16> = left.encode_utf16().collect();
            self.cur_chunk.extend_from_slice(&(units.len() as u16).to_le_bytes());
            for u in units {
                self.cur_chunk.extend_from_slice(&u.to_le_bytes());
            }
            self.cur_chunk.push(0x09); // EntityRef
            self.write_name_ref("amp");
            self.cur_chunk.push(0x07); // CDATA
            let right = "right";
            let r_units: Vec<u16> = right.encode_utf16().collect();
            self.cur_chunk.extend_from_slice(&(r_units.len() as u16).to_le_bytes());
            for u in r_units {
                self.cur_chunk.extend_from_slice(&u.to_le_bytes());
            }
            self.close_elem();
        }
        self.close_elem(); // EventData
        self.close_elem(); // Event
        self.cur_chunk.push(0x00); // EndOfStream

        self.finish_record(rec_start, rec_id);
        self.cur_chunk.len() <= CHUNK_SIZE
    }

    fn write_record_header(&mut self, rec_id: u64, written_ft: u64) {
        self.cur_chunk.extend_from_slice(&[0x2A, 0x2A, 0x00, 0x00]);
        self.cur_chunk.extend_from_slice(&0u32.to_le_bytes()); // size placeholder
        self.cur_chunk.extend_from_slice(&rec_id.to_le_bytes());
        self.cur_chunk.extend_from_slice(&written_ft.to_le_bytes());
    }

    fn finish_record(&mut self, rec_start: usize, rec_id: u64) {
        self.cur_chunk.extend_from_slice(&0u32.to_le_bytes()); // size copy placeholder
        let rec_size = (self.cur_chunk.len() - rec_start) as u32;
        self.cur_chunk[rec_start + 4..rec_start + 8].copy_from_slice(&rec_size.to_le_bytes());
        let tail = self.cur_chunk.len() - 4;
        self.cur_chunk[tail..].copy_from_slice(&rec_size.to_le_bytes());

        if self.first_rec_in_chunk == 0 {
            self.first_rec_in_chunk = rec_id;
        }
        self.last_rec_in_chunk = rec_id;
        self.last_rec_offset = rec_start as u32;
    }

    fn write_substitutions(&mut self, subs: &[SubVal]) {
        self.cur_chunk.extend_from_slice(&(subs.len() as u32).to_le_bytes());
        let desc_start = self.cur_chunk.len();
        for sub in subs {
            self.cur_chunk.extend_from_slice(&0u16.to_le_bytes());
            self.cur_chunk.push(sub.value_type());
            self.cur_chunk.push(0);
        }

        for (idx, sub) in subs.iter().enumerate() {
            let p_start = self.cur_chunk.len();
            self.encode_sub_payload(sub);
            let p_size = (self.cur_chunk.len() - p_start) as u16;
            let d_off = desc_start + idx * 4;
            self.cur_chunk[d_off..d_off + 2].copy_from_slice(&p_size.to_le_bytes());
        }
    }

    fn encode_sub_payload(&mut self, sub: &SubVal) {
        match sub {
            SubVal::Null => {}
            SubVal::Utf16(s) => {
                for u in s.encode_utf16() {
                    self.cur_chunk.extend_from_slice(&u.to_le_bytes());
                }
            }
            SubVal::Ansi(s) => self.cur_chunk.extend_from_slice(s.as_bytes()),
            SubVal::I8(v) => self.cur_chunk.push(*v as u8),
            SubVal::U8(v) => self.cur_chunk.push(*v),
            SubVal::I16(v) => self.cur_chunk.extend_from_slice(&v.to_le_bytes()),
            SubVal::U16(v) => self.cur_chunk.extend_from_slice(&v.to_le_bytes()),
            SubVal::I32(v) => self.cur_chunk.extend_from_slice(&v.to_le_bytes()),
            SubVal::U32(v) => self.cur_chunk.extend_from_slice(&v.to_le_bytes()),
            SubVal::I64(v) => self.cur_chunk.extend_from_slice(&v.to_le_bytes()),
            SubVal::U64(v) => self.cur_chunk.extend_from_slice(&v.to_le_bytes()),
            SubVal::F32(v) => self.cur_chunk.extend_from_slice(&v.to_le_bytes()),
            SubVal::F64(v) => self.cur_chunk.extend_from_slice(&v.to_le_bytes()),
            SubVal::Bool(b) => self.cur_chunk.extend_from_slice(&u32::from(*b).to_le_bytes()),
            SubVal::Binary(b) | SubVal::Sid(b) => self.cur_chunk.extend_from_slice(b),
            SubVal::Guid(g) => self.cur_chunk.extend_from_slice(g),
            SubVal::FileTime(dt) => {
                let ft = utc_to_filetime(*dt).unwrap_or(0);
                self.cur_chunk.extend_from_slice(&ft.to_le_bytes());
            }
            SubVal::SysTime(y, mo, d, h, mi, s, ms) => {
                for v in [*y, *mo, 0u16, *d, *h, *mi, *s, *ms] {
                    self.cur_chunk.extend_from_slice(&v.to_le_bytes());
                }
            }
            SubVal::Hex32(v) => self.cur_chunk.extend_from_slice(&v.to_le_bytes()),
            SubVal::Hex64(v) => self.cur_chunk.extend_from_slice(&v.to_le_bytes()),
            SubVal::Utf16Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        self.cur_chunk.extend_from_slice(&0u16.to_le_bytes());
                    }
                    for u in item.encode_utf16() {
                        self.cur_chunk.extend_from_slice(&u.to_le_bytes());
                    }
                }
            }
            SubVal::EventDataBinXml(pairs) => {
                self.cur_chunk.extend_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
                self.open_elem("EventData", 0xFFFF, &[]);
                for (k, v) in pairs {
                    self.open_elem("Data", 0xFFFF, &[("Name", k)]);
                    self.write_inline_utf16_val(v);
                    self.close_elem();
                }
                self.close_elem();
                self.cur_chunk.push(0x00);
            }
            SubVal::DataNodeBinXml(k, v) => {
                self.cur_chunk.extend_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
                self.open_elem("Data", 0xFFFF, &[("Name", k)]);
                self.write_inline_utf16_val(v);
                self.close_elem();
                self.cur_chunk.push(0x00);
            }
            SubVal::UserDataEventXml(pairs) => {
                self.cur_chunk.extend_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
                self.open_elem("UserData", 0xFFFF, &[]);
                self.open_elem("EventXML", 0xFFFF, &[]);
                for (k, v) in pairs {
                    self.text_elem(k, v);
                }
                self.close_elem();
                self.close_elem();
                self.cur_chunk.push(0x00);
            }
        }
    }

    fn write_name_ref(&mut self, name: &str) {
        let slot = self.cur_chunk.len();
        self.cur_chunk.extend_from_slice(&0u32.to_le_bytes());
        if let Some(&off) = self.name_cache.get(name) {
            self.cur_chunk[slot..slot + 4].copy_from_slice(&off.to_le_bytes());
            return;
        }
        let off = self.cur_chunk.len() as u32;
        self.cur_chunk[slot..slot + 4].copy_from_slice(&off.to_le_bytes());
        self.name_cache.insert(name.to_string(), off);

        let units: Vec<u16> = name.encode_utf16().collect();
        self.cur_chunk.extend_from_slice(&0u32.to_le_bytes()); // next_offset
        self.cur_chunk.extend_from_slice(&0u16.to_le_bytes()); // hash
        self.cur_chunk.extend_from_slice(&(units.len() as u16).to_le_bytes());
        for u in units {
            self.cur_chunk.extend_from_slice(&u.to_le_bytes());
        }
        self.cur_chunk.extend_from_slice(&0u16.to_le_bytes()); // NUL
    }

    fn open_elem(&mut self, name: &str, dep_id: u16, attrs: &[(&str, &str)]) {
        self.cur_chunk.push(if attrs.is_empty() { 0x01 } else { 0x41 });
        self.cur_chunk.extend_from_slice(&dep_id.to_le_bytes());
        self.cur_chunk.extend_from_slice(&0u32.to_le_bytes()); // data_size (ignored by reader)
        self.write_name_ref(name);
        if !attrs.is_empty() {
            let size_slot = self.cur_chunk.len();
            self.cur_chunk.extend_from_slice(&0u32.to_le_bytes());
            let list_start = self.cur_chunk.len();
            for (i, (k, v)) in attrs.iter().enumerate() {
                self.cur_chunk.push(if i + 1 < attrs.len() { 0x46 } else { 0x06 });
                self.write_name_ref(k);
                self.write_inline_utf16_val(v);
            }
            let list_size = (self.cur_chunk.len() - list_start) as u32;
            self.cur_chunk[size_slot..size_slot + 4].copy_from_slice(&list_size.to_le_bytes());
        }
        self.cur_chunk.push(0x02); // CloseStartElementTag
    }

    fn empty_elem(&mut self, name: &str, attrs: &[(&str, &str)]) {
        self.cur_chunk.push(if attrs.is_empty() { 0x01 } else { 0x41 });
        self.cur_chunk.extend_from_slice(&0xFFFFu16.to_le_bytes());
        self.cur_chunk.extend_from_slice(&0u32.to_le_bytes());
        self.write_name_ref(name);
        if !attrs.is_empty() {
            let size_slot = self.cur_chunk.len();
            self.cur_chunk.extend_from_slice(&0u32.to_le_bytes());
            let list_start = self.cur_chunk.len();
            for (i, (k, v)) in attrs.iter().enumerate() {
                self.cur_chunk.push(if i + 1 < attrs.len() { 0x46 } else { 0x06 });
                self.write_name_ref(k);
                self.write_inline_utf16_val(v);
            }
            let list_size = (self.cur_chunk.len() - list_start) as u32;
            self.cur_chunk[size_slot..size_slot + 4].copy_from_slice(&list_size.to_le_bytes());
        }
        self.cur_chunk.push(0x03); // CloseEmptyElementTag
    }

    fn text_elem(&mut self, name: &str, val: &str) {
        self.open_elem(name, 0xFFFF, &[]);
        self.write_inline_utf16_val(val);
        self.close_elem();
    }

    fn open_elem_sub(
        &mut self,
        name: &str,
        dep_id: u16,
        attrs: &[(&str, u16, u8, bool)],
        children: Option<(u16, u8, bool)>,
    ) {
        self.cur_chunk.push(0x41);
        self.cur_chunk.extend_from_slice(&dep_id.to_le_bytes());
        self.cur_chunk.extend_from_slice(&0u32.to_le_bytes());
        self.write_name_ref(name);
        let size_slot = self.cur_chunk.len();
        self.cur_chunk.extend_from_slice(&0u32.to_le_bytes());
        let list_start = self.cur_chunk.len();
        for (i, (k, sub_id, vtype, opt)) in attrs.iter().enumerate() {
            self.cur_chunk.push(if i + 1 < attrs.len() { 0x46 } else { 0x06 });
            self.write_name_ref(k);
            self.write_sub_token(*sub_id, *vtype, *opt);
        }
        let list_size = (self.cur_chunk.len() - list_start) as u32;
        self.cur_chunk[size_slot..size_slot + 4].copy_from_slice(&list_size.to_le_bytes());

        if let Some((sub_id, vtype, opt)) = children {
            self.cur_chunk.push(0x02);
            self.write_sub_token(sub_id, vtype, opt);
            self.close_elem();
        } else {
            self.cur_chunk.push(0x03);
        }
    }

    fn open_elem_text_sub(&mut self, name: &str, dep_id: u16, sub_id: u16, vtype: u8) {
        self.open_elem(name, dep_id, &[]);
        self.write_sub_token(sub_id, vtype, false);
        self.close_elem();
    }

    fn open_elem_with_const_attr_and_sub(
        &mut self,
        elem_name: &str,
        dep_id: u16,
        attr: (&str, &str),
        sub: (u16, u8, bool),
    ) {
        self.open_elem(elem_name, dep_id, &[attr]);
        self.write_sub_token(sub.0, sub.1, sub.2);
        self.close_elem();
    }

    fn write_sub_token(&mut self, sub_id: u16, vtype: u8, opt: bool) {
        self.cur_chunk.push(if opt { 0x0E } else { 0x0D });
        self.cur_chunk.extend_from_slice(&sub_id.to_le_bytes());
        self.cur_chunk.push(vtype);
    }

    fn write_inline_utf16_val(&mut self, s: &str) {
        self.cur_chunk.push(0x05);
        self.cur_chunk.push(0x01);
        let units: Vec<u16> = s.encode_utf16().collect();
        self.cur_chunk.extend_from_slice(&(units.len() as u16).to_le_bytes());
        for u in units {
            self.cur_chunk.extend_from_slice(&u.to_le_bytes());
        }
    }

    fn close_elem(&mut self) {
        self.cur_chunk.push(0x04);
    }

    fn flush_chunk(&mut self) {
        if self.cur_chunk.len() <= CHUNK_DATA_OFFSET && !self.chunks.is_empty() {
            return;
        }
        let free_space = self.cur_chunk.len() as u32;
        self.cur_chunk.resize(CHUNK_SIZE, 0);

        self.cur_chunk[0..8].copy_from_slice(b"ElfChnk\0");
        self.cur_chunk[0x08..0x10].copy_from_slice(&self.first_rec_in_chunk.to_le_bytes());
        self.cur_chunk[0x10..0x18].copy_from_slice(&self.last_rec_in_chunk.to_le_bytes());
        self.cur_chunk[0x18..0x20].copy_from_slice(&self.first_rec_in_chunk.to_le_bytes());
        self.cur_chunk[0x20..0x28].copy_from_slice(&self.last_rec_in_chunk.to_le_bytes());
        self.cur_chunk[0x28..0x2C].copy_from_slice(&128u32.to_le_bytes());
        self.cur_chunk[0x2C..0x30].copy_from_slice(&self.last_rec_offset.to_le_bytes());
        self.cur_chunk[0x30..0x34].copy_from_slice(&free_space.to_le_bytes());

        let rec_crc = crc32_ieee(&self.cur_chunk[CHUNK_DATA_OFFSET..free_space as usize]);
        self.cur_chunk[0x34..0x38].copy_from_slice(&rec_crc.to_le_bytes());

        let mut hdr_hasher = crc32fast::Hasher::new();
        hdr_hasher.update(&self.cur_chunk[0..120]);
        hdr_hasher.update(&self.cur_chunk[128..512]);
        let hdr_crc = hdr_hasher.finalize();
        self.cur_chunk[0x7C..0x80].copy_from_slice(&hdr_crc.to_le_bytes());

        let finished = std::mem::replace(&mut self.cur_chunk, vec![0u8; CHUNK_DATA_OFFSET]);
        self.chunks.push(finished);
        self.name_cache.clear();
        self.template_cache.clear();
        self.first_rec_in_chunk = 0;
        self.last_rec_in_chunk = 0;
        self.last_rec_offset = 0;
    }

    fn build(mut self) -> Vec<u8> {
        if self.cur_chunk.len() > CHUNK_DATA_OFFSET || self.chunks.is_empty() {
            self.flush_chunk();
        }
        let mut header = vec![0u8; 4096];
        header[0..8].copy_from_slice(b"ElfFile\0");
        header[0x08..0x10].copy_from_slice(&0u64.to_le_bytes()); // oldest_chunk
        let last_chunk_num = (self.chunks.len().saturating_sub(1)) as u64;
        header[0x10..0x18].copy_from_slice(&last_chunk_num.to_le_bytes());
        header[0x18..0x20].copy_from_slice(&self.next_record_id.to_le_bytes());
        header[0x20..0x24].copy_from_slice(&128u32.to_le_bytes());
        header[0x24..0x26].copy_from_slice(&1u16.to_le_bytes()); // minor
        header[0x26..0x28].copy_from_slice(&3u16.to_le_bytes()); // major
        header[0x28..0x2A].copy_from_slice(&4096u16.to_le_bytes());
        header[0x2A..0x2C].copy_from_slice(&(self.chunks.len() as u16).to_le_bytes());
        header[0x78..0x7C].copy_from_slice(&0u32.to_le_bytes()); // flags
        let hdr_crc = crc32_ieee(&header[0..120]);
        header[0x7C..0x80].copy_from_slice(&hdr_crc.to_le_bytes());

        let mut out = Vec::with_capacity(4096 + self.chunks.len() * CHUNK_SIZE);
        out.extend_from_slice(&header);
        for c in self.chunks {
            out.extend_from_slice(&c);
        }
        out
    }
}

fn ts(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(y, mo, d, h, mi, s)
        .single()
        .expect("valid timestamp")
}

fn system_sid_bytes() -> Vec<u8> {
    // S-1-5-18 (LocalSystem)
    vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]
}

fn sample_guid_bytes() -> [u8; 16] {
    [
        0x25, 0x96, 0x84, 0x54, 0x78, 0x54, 0x94, 0x49, 0xa5, 0xba, 0x3e, 0x3b, 0x03, 0x28, 0xc3, 0x0d,
    ]
}

fn build_comprehensive_fixture() -> Vec<u8> {
    let mut b = SyntheticEvtxBuilder::new();
    let sid = system_sid_bytes();
    let sec_guid = sample_guid_bytes();
    let t0 = ts(2026, 11, 20, 8, 0, 0);

    // 1. Security logon/logoff & process creation
    b.add_templated_event(
        &EventSpec::new(t0, "Security", "Microsoft-Windows-Security-Auditing", 4624)
            .guid(sec_guid)
            .sid(sid.clone())
            .keywords(0x0020_0000_0000_0000)
            .data("TargetUserName", "alice")
            .data("TargetDomainName", "CORP")
            .data("TargetLogonId", "0x1001")
            .data("LogonType", "2")
            .data("IpAddress", "192.168.1.10")
            .data("WorkstationName", "WS01"),
    );
    b.add_templated_event(
        &EventSpec::new(
            t0 + chrono::Duration::minutes(15),
            "Security",
            "Microsoft-Windows-Security-Auditing",
            4634,
        )
        .guid(sec_guid)
        .keywords(0x0020_0000_0000_0000)
        .data("TargetUserName", "alice")
        .data("TargetDomainName", "CORP")
        .data("TargetLogonId", "0x1001")
        .data("LogonType", "2"),
    );
    b.add_templated_event(
        &EventSpec::new(
            t0 + chrono::Duration::minutes(20),
            "Security",
            "Microsoft-Windows-Security-Auditing",
            4624,
        )
        .guid(sec_guid)
        .keywords(0x0020_0000_0000_0000)
        .data("TargetUserName", "bob")
        .data("TargetDomainName", "CORP")
        .data("TargetLogonId", "0x1002")
        .data("LogonType", "10")
        .data("IpAddress", "10.0.0.50")
        .data("WorkstationName", "RDP-CLIENT"),
    );
    b.add_templated_event(
        &EventSpec::new(
            t0 + chrono::Duration::minutes(50),
            "Security",
            "Microsoft-Windows-Security-Auditing",
            4647,
        )
        .guid(sec_guid)
        .keywords(0x0020_0000_0000_0000)
        .data("TargetUserName", "bob")
        .data("TargetDomainName", "CORP")
        .data("TargetLogonId", "0x1002"),
    );
    b.add_templated_event(
        &EventSpec::new(
            t0 + chrono::Duration::minutes(25),
            "Security",
            "Microsoft-Windows-Security-Auditing",
            4625,
        )
        .guid(sec_guid)
        .keywords(0x0010_0000_0000_0000)
        .data("TargetUserName", "eve")
        .data("TargetDomainName", "EXT")
        .data("LogonType", "3")
        .data("IpAddress", "203.0.113.9")
        .data("Status", "0xc000006d")
        .data("SubStatus", "0xc000006a"),
    );
    b.add_templated_event(
        &EventSpec::new(
            t0 + chrono::Duration::minutes(30),
            "Security",
            "Microsoft-Windows-Security-Auditing",
            4688,
        )
        .guid(sec_guid)
        .data("NewProcessId", "0x1a40")
        .data("ProcessId", "0x400")
        .data("NewProcessName", r"C:\Windows\System32\cmd.exe")
        .data("ParentProcessName", r"C:\Windows\explorer.exe")
        .data("CommandLine", r"cmd.exe /c whoami")
        .data("SubjectUserName", "alice")
        .data("TokenElevationType", "%%1937"),
    );

    // 2. System boot / shutdown / crash (coalesced boot 1 -> 1074 Restart -> 6006; boot 2 -> 41; boot 3 active)
    b.add_templated_event(&EventSpec::new(t0, "System", "Microsoft-Windows-Kernel-General", 12));
    b.add_templated_event(&EventSpec::new(
        t0 + chrono::Duration::seconds(5),
        "System",
        "EventLog",
        6009,
    ));
    b.add_templated_event(&EventSpec::new(
        t0 + chrono::Duration::seconds(10),
        "System",
        "EventLog",
        6005,
    ));
    b.add_templated_event(
        &EventSpec::new(t0 + chrono::Duration::minutes(119), "System", "User32", 1074)
            .data("param1", r"C:\Windows\System32\svchost.exe")
            .data("param3", "Operating System: Reconfiguration (Planned)")
            .data("param4", "0x80020004")
            .data("param5", "restart"),
    );
    b.add_templated_event(&EventSpec::new(
        t0 + chrono::Duration::hours(2),
        "System",
        "EventLog",
        6006,
    ));
    let t_boot2 = t0 + chrono::Duration::hours(3);
    b.add_templated_event(&EventSpec::new(t_boot2, "System", "EventLog", 6005));
    b.add_templated_event(
        &EventSpec::new(
            t_boot2 + chrono::Duration::minutes(45),
            "System",
            "Microsoft-Windows-Kernel-Power",
            41,
        )
        .level(1)
        .data("BugcheckCode", "0xef"),
    );
    b.add_templated_event(&EventSpec::new(
        t_boot2 + chrono::Duration::hours(1),
        "System",
        "EventLog",
        6005,
    ));

    // 3. Application
    b.add_inline_event(
        &EventSpec::new(t0 + chrono::Duration::minutes(5), "Application", "DemoApp", 1000)
            .level(2)
            .data("Application", "demo.exe"),
        true,
    );

    // 4. Sysmon EID 1
    b.add_templated_event(
        &EventSpec::new(
            t0 + chrono::Duration::minutes(35),
            "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-Sysmon",
            1,
        )
        .data("ProcessId", "8192")
        .data("ParentProcessId", "6720")
        .data("Image", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        .data("ParentImage", r"C:\Windows\System32\cmd.exe")
        .data("CommandLine", "powershell.exe -NoProfile")
        .data("User", r"CORP\alice")
        .data("IntegrityLevel", "High"),
    );

    // 5. WLAN-AutoConfig
    b.add_templated_event(
        &EventSpec::new(
            t0 + chrono::Duration::minutes(40),
            "Microsoft-Windows-WLAN-AutoConfig/Operational",
            "Microsoft-Windows-WLAN-AutoConfig",
            8001,
        )
        .data("SSID", "CorpWiFi")
        .data("BSSID", "AA:BB:CC:DD:EE:FF")
        .data("InterfaceName", "Intel Wi-Fi 6E AX210")
        .data("InterfaceGuid", "{12345678-1234-1234-1234-1234567890ab}")
        .data("ProfileName", "CorpWiFi")
        .data("AuthenticationAlgorithm", "WPA2-Enterprise")
        .data("CipherAlgorithm", "CCMP")
        .data("ReasonCode", "0"),
    );

    // 6. Windows Defender
    b.add_templated_event(
        &EventSpec::new(
            t0 + chrono::Duration::minutes(45),
            "Microsoft-Windows-Windows Defender/Operational",
            "Microsoft-Windows-Windows Defender",
            1116,
        )
        .level(3)
        .data("Threat Name", "Virus:DOS/EICAR_Test_File")
        .data("Severity Name", "Severe")
        .data("Category Name", "Virus")
        .data("Path", r"file:_C:\Temp\eicar.com")
        .data("Process Name", r"C:\Windows\explorer.exe")
        .data("Action Name", "Quarantine")
        .data("Detection User", r"CORP\alice"),
    );

    // 7. RDP (UserData/EventXML + RCM 1149)
    b.add_templated_event(
        &EventSpec::new(
            t0 + chrono::Duration::minutes(50),
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "Microsoft-Windows-TerminalServices-LocalSessionManager",
            21,
        )
        .udata("User", r"CORP\bob")
        .udata("SessionID", "2")
        .udata("Address", "10.0.0.50"),
    );
    b.add_templated_event(
        &EventSpec::new(
            t0 + chrono::Duration::minutes(49),
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
            1149,
        )
        .udata("Param1", "bob")
        .udata("Param3", "10.0.0.50"),
    );

    // 8. PowerShell
    b.add_templated_event(
        &EventSpec::new(
            t0 + chrono::Duration::minutes(55),
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-PowerShell",
            4104,
        )
        .data("ScriptBlockId", "{aaaa1111-bbbb-2222-cccc-3333dddd4444}")
        .data("Path", r"C:\Scripts\audit.ps1")
        .data("ScriptBlockText", "Get-Process | Select-Object -First 5")
        .data("MessageNumber", "1")
        .data("MessageTotal", "1"),
    );

    // 9. Task Scheduler
    b.add_templated_event(
        &EventSpec::new(
            t0 + chrono::Duration::minutes(60),
            "Microsoft-Windows-TaskScheduler/Operational",
            "Microsoft-Windows-TaskScheduler",
            200,
        )
        .data("TaskName", r"\AuditTask")
        .data("ActionName", r"C:\Windows\System32\whoami.exe")
        .data("InstanceId", "{99998888-7777-6666-5555-444433332222}")
        .data("ResultCode", "0")
        .data("UserContext", r"CORP\alice"),
    );

    // 10. USB / PnP
    b.add_templated_event(
        &EventSpec::new(
            t0 + chrono::Duration::minutes(65),
            "Microsoft-Windows-Kernel-PnP/Configuration",
            "Microsoft-Windows-Kernel-PnP",
            410,
        )
        .data("DeviceInstanceId", r"USB\VID_0781&PID_5581\SN987654")
        .data("DriverName", "usbstor.inf"),
    );

    b.build()
}

#[test]
fn all_providers_count_and_catalog_alignment() {
    let providers = all_providers(&ForensicSource::Live);
    let providers_with_opts = all_providers_with_options(&ForensicSource::Live, LiveQueryOptions::default());
    assert_eq!(providers_with_opts.len(), 14);
    let expected: Vec<_> = FORENSIC_TOOL_CATALOG
        .iter()
        .filter(|d| d.category == ToolCategory::Evtx)
        .collect();

    assert_eq!(providers.len(), 14);
    assert_eq!(expected.len(), 14);

    for (provider, desc) in providers.iter().zip(expected.iter()) {
        assert_eq!(provider.tool_id(), desc.tool_id);
        assert_eq!(provider.description(), desc.description);
        assert!(provider.is_read_only(), "{} must be read-only", desc.tool_id);

        let schema = provider.schema();
        assert_eq!(schema.tool_id, desc.tool_id);
        assert!(!schema.columns.is_empty());
        for col in &schema.columns {
            assert!(!col.id.is_empty());
            assert!(
                !col.id.contains(' ')
                    && col
                        .id
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "ColumnDef.id `{}` in {} must be space-free snake_case",
                col.id,
                desc.tool_id
            );
        }
    }
}

#[test]
fn binxml_template_cache_all_value_types_and_nested_binxml() {
    let mut b = SyntheticEvtxBuilder::new();
    let t1 = ts(2026, 11, 22, 14, 0, 0);
    let t2 = ts(2026, 11, 22, 14, 5, 0);
    let sid = system_sid_bytes();
    let guid = sample_guid_bytes();

    let subs1 = vec![
        SubVal::Utf16("CustomProvider".to_string()),
        SubVal::Guid(guid),
        SubVal::U16(9001),
        SubVal::U8(4),
        SubVal::FileTime(t1),
        SubVal::U64(1),
        SubVal::Utf16("Application".to_string()),
        SubVal::Utf16("NODE-A".to_string()),
        SubVal::Sid(sid.clone()),
        SubVal::Ansi("ansi-ok".to_string()),
        SubVal::I8(-12),
        SubVal::I16(-345),
        SubVal::I32(-67890),
        SubVal::U32(123_456),
        SubVal::I64(-9_876_543_210),
        SubVal::F32(1.5),
        SubVal::F64(3.25),
        SubVal::Bool(true),
        SubVal::Binary(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        SubVal::SysTime(2026, 11, 22, 14, 0, 0, 250),
        SubVal::Hex32(0x12AB),
        SubVal::Hex64(0x8020_0000_0000_0001),
        SubVal::Utf16Array(vec!["alpha".to_string(), "beta".to_string()]),
        SubVal::Null,
        SubVal::DataNodeBinXml("NestedKey".to_string(), "NestedVal".to_string()),
    ];

    let subs2 = vec![
        SubVal::Utf16("CustomProvider".to_string()),
        SubVal::Null,
        SubVal::U16(9002),
        SubVal::U8(3),
        SubVal::FileTime(t2),
        SubVal::U64(2),
        SubVal::Utf16("Application".to_string()),
        SubVal::Utf16("NODE-B".to_string()),
        SubVal::Null,
        SubVal::Ansi("second-cached".to_string()),
        SubVal::I8(1),
        SubVal::I16(2),
        SubVal::I32(3),
        SubVal::U32(4),
        SubVal::I64(5),
        SubVal::F32(2.0),
        SubVal::F64(4.0),
        SubVal::Bool(false),
        SubVal::Binary(vec![0x01, 0x02]),
        SubVal::SysTime(2026, 11, 22, 14, 5, 0, 0),
        SubVal::Hex32(0x20),
        SubVal::Hex64(0x40),
        SubVal::Utf16Array(vec!["gamma".to_string()]),
        SubVal::Utf16("PresentOpt".to_string()),
        SubVal::DataNodeBinXml("NestedKey".to_string(), "CachedTplVal".to_string()),
    ];

    b.add_custom_template_record(t1, "all_types", subs1);
    b.add_custom_template_record(t2, "all_types", subs2);

    let bytes = b.build();
    let archive = EvtxArchive::from_bytes_with_options(&bytes, EvtxParseOptions { strict_checksums: true })
        .expect("strict checksums should pass on valid synthetic EVTX");

    assert!(
        archive.warnings().is_empty(),
        "expected zero warnings: {:?}",
        archive.warnings()
    );
    assert!(archive.header().header_checksum_valid);
    assert_eq!(archive.chunks_info().len(), 1);
    assert!(archive.chunks_info()[0].header_checksum_valid);
    assert!(archive.chunks_info()[0].records_checksum_valid);
    assert_eq!(archive.records().len(), 2);

    let r1 = &archive.records()[0];
    assert_eq!(r1.provider, "CustomProvider");
    assert_eq!(
        r1.provider_guid.as_deref(),
        Some("{54849625-5478-4994-a5ba-3e3b0328c30d}")
    );
    assert_eq!(r1.event_id, 9001);
    assert_eq!(r1.user_sid.as_deref(), Some("S-1-5-18"));
    assert_eq!(r1.get_data("AnsiVal"), Some("ansi-ok"));
    assert_eq!(r1.get_data("Int8Val"), Some("-12"));
    assert_eq!(r1.get_data("Int16Val"), Some("-345"));
    assert_eq!(r1.get_data("Int32Val"), Some("-67890"));
    assert_eq!(r1.get_data("UInt32Val"), Some("123456"));
    assert_eq!(r1.get_data("Int64Val"), Some("-9876543210"));
    assert_eq!(r1.get_data("BoolVal"), Some("true"));
    assert_eq!(r1.get_data("BinaryVal"), Some("deadbeef"));
    assert_eq!(r1.get_data("Hex32Val"), Some("0x12ab"));
    assert_eq!(r1.get_data("Hex64Val"), Some("0x8020000000000001"));
    assert_eq!(r1.get_data("ArrayVal"), Some("alpha; beta"));
    assert_eq!(r1.get_data("OptionalOmitted"), None);
    assert_eq!(r1.get_data("NestedKey"), Some("NestedVal"));
    assert!(
        r1.get_data("SysTimeVal")
            .is_some_and(|v| v.starts_with("2026-11-22T14:00:00"))
    );

    // Second record reused cached template offset from record 1
    let r2 = &archive.records()[1];
    assert_eq!(r2.event_id, 9002);
    assert_eq!(r2.user_sid, None);
    assert_eq!(r2.get_data("AnsiVal"), Some("second-cached"));
    assert_eq!(r2.get_data("OptionalOmitted"), Some("PresentOpt"));
    assert_eq!(r2.get_data("NestedKey"), Some("CachedTplVal"));
}

#[test]
fn multi_chunk_evtx_archive_splits_cleanly() {
    let mut b = SyntheticEvtxBuilder::new();
    let payload = "X".repeat(600);
    let base = ts(2026, 11, 21, 0, 0, 0);
    for i in 0..160u32 {
        b.add_templated_event(
            &EventSpec::new(
                base + chrono::Duration::seconds(i64::from(i)),
                "Application",
                "MultiChunk",
                100,
            )
            .data("Payload", &format!("{i}:{payload}")),
        );
    }
    let bytes = b.build();
    let archive = EvtxArchive::from_bytes_with_options(&bytes, EvtxParseOptions { strict_checksums: true })
        .expect("multi-chunk synthetic EVTX must parse strictly");
    assert!(archive.chunks_info().len() >= 2, "expected >= 2 chunks");
    assert_eq!(archive.records().len(), 160);
    assert_eq!(archive.header().chunk_count as usize, archive.chunks_info().len());
}

#[test]
fn all_14_providers_against_comprehensive_synthetic_evtx() {
    let bytes = build_comprehensive_fixture();
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("Comprehensive.evtx");
    std::fs::write(&file_path, &bytes).expect("write fixture");
    let opened = EvtxArchive::open(&file_path).expect("EvtxArchive::open should parse fixture");
    assert!(!opened.records().is_empty());

    for source in [
        ForensicSource::OfflineBytes(bytes),
        ForensicSource::OfflinePath(file_path.clone()),
        ForensicSource::OfflinePath(dir.path().to_path_buf()),
    ] {
        let providers = all_providers(&source);
        assert_eq!(providers.len(), 14);
        for provider in providers {
            let schema = provider.schema();
            let data = provider
                .query(&TableQuery::default())
                .unwrap_or_else(|e| panic!("{} failed for {:?}: {e}", provider.tool_id(), source.label()));
            assert!(
                !data.rows.is_empty(),
                "{} returned 0 rows for {}",
                provider.tool_id(),
                source.label()
            );

            let duration_cols: Vec<usize> = schema
                .columns
                .iter()
                .enumerate()
                .filter(|(_, c)| c.col_type == ColumnType::Duration)
                .map(|(i, _)| i)
                .collect();
            let bytes_cols: Vec<usize> = schema
                .columns
                .iter()
                .enumerate()
                .filter(|(_, c)| c.col_type == ColumnType::BytesSize)
                .map(|(i, _)| i)
                .collect();

            for row in &data.rows {
                assert!(row.detail_json.is_some(), "{} missing detail_json", provider.tool_id());
                assert!(
                    row.raw_bytes.as_ref().is_some_and(|b| !b.is_empty()),
                    "{} missing raw_bytes",
                    provider.tool_id()
                );
                for &idx in &duration_cols {
                    assert!(
                        matches!(row.cells[idx], CellValue::Null | CellValue::Uint(_)),
                        "{} duration cell must be Null or Uint(ms)",
                        provider.tool_id()
                    );
                }
                for &idx in &bytes_cols {
                    assert!(
                        matches!(row.cells[idx], CellValue::Null | CellValue::Bytes(_)),
                        "{} bytes cell must be Null or Bytes(u64)",
                        provider.tool_id()
                    );
                }
            }
        }
    }
}

#[test]
fn logon_and_uptime_session_correlation_details() {
    let bytes = build_comprehensive_fixture();
    let src = ForensicSource::OfflineBytes(bytes);
    let providers = all_providers(&src);

    let logon = providers.iter().find(|p| p.tool_id() == "evtx.logon").unwrap();
    let logon_data = logon.query(&TableQuery::default()).expect("logon query");
    assert_eq!(logon_data.rows.len(), 3, "expected 2 paired sessions + 1 failed logon");

    let by_user: BTreeMap<String, Vec<CellValue>> = logon_data
        .rows
        .iter()
        .map(|r| (r.cells[1].to_string(), r.cells.clone()))
        .collect();
    assert_eq!(by_user["alice"][7], CellValue::Uint(900_000)); // 15 min
    assert_eq!(by_user["bob"][7], CellValue::Uint(1_800_000)); // 30 min
    assert_eq!(by_user["bob"][4].to_string(), "10 (RemoteInteractive)");
    assert_eq!(by_user["eve"][4].to_string(), "Failed: 3 (Network)");
    assert_eq!(by_user["eve"][7], CellValue::Null);

    let uptime = providers.iter().find(|p| p.tool_id() == "evtx.uptime").unwrap();
    let uptime_data = uptime.query(&TableQuery::default()).expect("uptime query");
    assert_eq!(
        uptime_data.rows.len(),
        3,
        "expected 3 boot sessions (12/6009/6005 coalesced)"
    );

    // Default sort is StartupTime Desc: boot 3 (Active), boot 2 (Bugcheck/Unclean), boot 1 (Restart)
    assert_eq!(uptime_data.rows[0].cells[4].to_string(), "Active");
    assert_eq!(uptime_data.rows[0].cells[2], CellValue::Null);

    assert_eq!(uptime_data.rows[1].cells[4].to_string(), "Bugcheck/Unclean");
    assert_eq!(uptime_data.rows[1].cells[5].to_string(), "0xef");

    assert_eq!(uptime_data.rows[2].cells[4].to_string(), "Restart");
    assert_eq!(uptime_data.rows[2].cells[2], CellValue::Uint(7_200_000));
    assert_eq!(
        uptime_data.rows[2].cells[6].to_string(),
        r"C:\Windows\System32\svchost.exe"
    );

    // Case B: real Windows post-boot crash order: boot1 -> boot2 -> 41 (5s after boot2) -> 6008 (10s after boot2)
    let mut b = SyntheticEvtxBuilder::new();
    let t1 = ts(2026, 11, 22, 1, 0, 0);
    let t2 = ts(2026, 11, 22, 2, 0, 0);
    b.add_templated_event(&EventSpec::new(t1, "System", "EventLog", 6005));
    b.add_templated_event(&EventSpec::new(t2, "System", "Microsoft-Windows-Kernel-General", 12));
    b.add_templated_event(&EventSpec::new(
        t2 + chrono::Duration::seconds(5),
        "System",
        "Microsoft-Windows-Kernel-Power",
        41,
    ));
    b.add_templated_event(&EventSpec::new(
        t2 + chrono::Duration::seconds(10),
        "System",
        "EventLog",
        6008,
    ));
    let case_b_src = ForensicSource::OfflineBytes(b.build());
    let case_b_uptime = all_providers(&case_b_src)
        .into_iter()
        .find(|p| p.tool_id() == "evtx.uptime")
        .unwrap();
    let res = case_b_uptime.query(&TableQuery::default()).expect("case B uptime");
    assert_eq!(res.rows.len(), 2);
    assert_eq!(res.rows[0].cells[4].to_string(), "Active");
    assert_eq!(res.rows[1].cells[4].to_string(), "Bugcheck/Unclean");
}

#[test]
fn directory_walk_and_corrupt_sibling_tolerance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sub = dir.path().join("nested");
    std::fs::create_dir_all(&sub).expect("mkdir");

    let mut b1 = SyntheticEvtxBuilder::new();
    b1.add_templated_event(&EventSpec::new(ts(2026, 11, 20, 9, 0, 0), "System", "EventLog", 6005));
    std::fs::write(dir.path().join("System.evtx"), b1.build()).expect("write System.evtx");

    let mut b2 = SyntheticEvtxBuilder::new();
    b2.add_templated_event(
        &EventSpec::new(
            ts(2026, 11, 20, 9, 1, 0),
            "Security",
            "Microsoft-Windows-Security-Auditing",
            4688,
        )
        .data("NewProcessId", "0x200")
        .data("ProcessId", "0x100")
        .data("NewProcessName", r"C:\Windows\notepad.exe"),
    );
    std::fs::write(sub.join("Security.evtx"), b2.build()).expect("write Security.evtx");

    // Non-EVTX file ignored + corrupt EVTX tolerated when valid siblings exist
    std::fs::write(dir.path().join("readme.txt"), b"not evtx").expect("write txt");
    std::fs::write(dir.path().join("corrupt.evtx"), vec![0u8; 4096]).expect("write corrupt");

    let all_prov = FullEventLogProvider::new(ForensicSource::OfflinePath(dir.path().to_path_buf()));
    let data = all_prov
        .query(&TableQuery::default())
        .expect("directory query should succeed");
    assert_eq!(data.rows.len(), 2);

    // Directory with ONLY corrupt .evtx must fail consistently across records, sources, and channels
    let bad_dir = tempfile::tempdir().expect("bad tempdir");
    std::fs::write(bad_dir.path().join("only_bad.evtx"), vec![0u8; 4096]).expect("write only_bad");
    let bad_src = ForensicSource::OfflinePath(bad_dir.path().to_path_buf());
    let bad_prov = FullEventLogProvider::new(bad_src.clone());
    assert!(bad_prov.query(&TableQuery::default()).is_err());
    let bad_channels = ChannelsProvider::new(bad_src.clone());
    assert!(bad_channels.query(&TableQuery::default()).is_err());
    let bad_sources = SourcesProvider::new(bad_src);
    assert!(bad_sources.query(&TableQuery::default()).is_err());
}

#[test]
fn query_helper_filtering_sorting_projection_pagination() {
    let bytes = build_comprehensive_fixture();
    let provider = FullEventLogProvider::new(ForensicSource::OfflineBytes(bytes));

    let data = QueryHelper::query_provider(
        &provider,
        Some(vec![
            "record_id".to_string(),
            "event_id".to_string(),
            "channel".to_string(),
        ]),
        Some("event_id == 4624"),
        Some("record_id:asc"),
        1,
        Some(1),
    )
    .expect("GuapQuery should succeed");

    assert_eq!(data.total_rows, 2);
    assert_eq!(data.rows.len(), 1);
    assert_eq!(data.schema.columns.len(), 3);
    assert_eq!(data.rows[0].cells[1], CellValue::Uint(4624));
    assert_eq!(data.rows[0].cells[2].to_string(), "Security");
}

#[test]
fn negative_and_resilience_tests() {
    // 1. Bad magic
    let mut bad_magic = vec![0u8; 4096];
    bad_magic[0..8].copy_from_slice(b"NOT_EVTX");
    assert!(matches!(
        EvtxArchive::from_bytes(&bad_magic),
        Err(ForensicError::Parse { .. })
    ));

    // 2. Truncated header (< 4096)
    assert!(matches!(
        EvtxArchive::from_bytes(&bad_magic[..512]),
        Err(ForensicError::Parse { .. })
    ));

    // 3. Corrupt CRC32s (file header, chunk header, event records)
    let valid = build_comprehensive_fixture();

    let mut bad_hdr_crc = valid.clone();
    bad_hdr_crc[0x7C] ^= 0xFF;
    assert!(matches!(
        EvtxArchive::from_bytes_with_options(&bad_hdr_crc, EvtxParseOptions { strict_checksums: true }),
        Err(ForensicError::Parse { .. })
    ));
    let tol_hdr = EvtxArchive::from_bytes(&bad_hdr_crc).expect("tolerant header CRC");
    assert!(!tol_hdr.header().header_checksum_valid);
    assert!(!tol_hdr.warnings().is_empty());

    let mut bad_chunk_crc = valid.clone();
    bad_chunk_crc[4096 + 0x7C] ^= 0xFF;
    assert!(matches!(
        EvtxArchive::from_bytes_with_options(&bad_chunk_crc, EvtxParseOptions { strict_checksums: true }),
        Err(ForensicError::Parse { .. })
    ));
    let tol_chunk = EvtxArchive::from_bytes(&bad_chunk_crc).expect("tolerant chunk CRC");
    assert!(!tol_chunk.chunks_info()[0].header_checksum_valid);

    let mut bad_rec_crc = valid.clone();
    bad_rec_crc[4096 + 0x34] ^= 0xFF;
    assert!(matches!(
        EvtxArchive::from_bytes_with_options(&bad_rec_crc, EvtxParseOptions { strict_checksums: true }),
        Err(ForensicError::Parse { .. })
    ));
    let tol_rec = EvtxArchive::from_bytes(&bad_rec_crc).expect("tolerant records CRC");
    assert!(!tol_rec.chunks_info()[0].records_checksum_valid);

    // 4. Mismatched trailing record size_copy
    let mut bad_tail = valid.clone();
    let rec_size = u32::from_le_bytes([
        bad_tail[4096 + 0x204],
        bad_tail[4096 + 0x205],
        bad_tail[4096 + 0x206],
        bad_tail[4096 + 0x207],
    ]) as usize;
    bad_tail[4096 + 0x200 + rec_size - 4] ^= 0x01;
    assert!(matches!(
        EvtxArchive::from_bytes(&bad_tail),
        Err(ForensicError::Parse { .. })
    ));

    // 5. Truncated record / bad free_space_offset
    let mut trunc_rec = valid.clone();
    let bad_free = (0x200 + 16) as u32;
    trunc_rec[4096 + 0x30..4096 + 0x34].copy_from_slice(&bad_free.to_le_bytes());
    assert!(matches!(
        EvtxArchive::from_bytes(&trunc_rec),
        Err(ForensicError::Parse { .. })
    ));

    // 6. Malformed BinXML token inside first record
    let mut bad_binxml = valid;
    bad_binxml[4096 + 0x200 + 24] = 0xFE; // invalid BinXML token
    assert!(matches!(
        EvtxArchive::from_bytes(&bad_binxml),
        Err(ForensicError::Parse { .. })
    ));

    // 7. Missing OfflinePath -> NotFound -> TableError::Provider("forensic artifact not found: ...")
    let missing = Path::new("Z:\\definitely_missing_guap_fixture_12345.evtx").to_path_buf();
    let prov = FullEventLogProvider::new(ForensicSource::OfflinePath(missing));
    let err = prov.query(&TableQuery::default()).expect_err("missing path must fail");
    assert!(
        matches!(err, TableError::Provider(ref msg) if msg.contains("forensic artifact not found")),
        "unexpected error: {err:?}"
    );
}

#[cfg(windows)]
#[test]
fn live_windows_bounded_smoke_and_non_elevated_security() {
    // 1. Bounded live query (max_records = 5) on Application via FullEventLogProvider
    let live_opts = LiveQueryOptions {
        max_records: Some(5),
        xpath_query: Some("*[System[Level<=4]]".to_string()),
        reverse_direction: true,
    };
    let app_prov = FullEventLogProvider::with_options(ForensicSource::Live, live_opts.clone());
    let data = app_prov
        .query(&TableQuery {
            limit: Some(5),
            ..TableQuery::default()
        })
        .expect("live System/Application bounded query should succeed");
    assert!(data.rows.len() <= 5);

    // 2. Live channels & sources metadata smoke check
    let channels_prov = ChannelsProvider::new(ForensicSource::Live);
    let ch_data = channels_prov
        .query(&TableQuery {
            limit: Some(10),
            ..TableQuery::default()
        })
        .expect("live evtx.channels should succeed");
    assert!(ch_data.total_rows > 0);

    let sources_prov = SourcesProvider::new(ForensicSource::Live);
    let src_data = sources_prov
        .query(&TableQuery {
            limit: Some(10),
            ..TableQuery::default()
        })
        .expect("live evtx.sources should succeed");
    assert!(src_data.total_rows > 0);

    // 3. Security logon view & FullEventLogProvider warning diagnostics:
    // Determine genuine Security log accessibility on the host via `wevtutil gli Security`.
    let wevt_out = std::process::Command::new("wevtutil")
        .args(["gli", "Security"])
        .output()
        .expect("wevtutil gli Security should execute on Windows");
    let security_accessible = wevt_out.status.success();

    if security_accessible {
        let logon_prov = LogonProvider::with_options(ForensicSource::Live, live_opts.clone());
        let logon_data = logon_prov
            .query(&TableQuery {
                limit: Some(5),
                ..TableQuery::default()
            })
            .expect("elevated live Security logon query should succeed");
        assert!(logon_data.rows.len() <= 5);

        let full_prov = FullEventLogProvider::with_options(ForensicSource::Live, live_opts);
        let (full_data, warnings) = full_prov
            .query_with_warnings(&TableQuery {
                limit: Some(5),
                ..TableQuery::default()
            })
            .expect("elevated live FullEventLogProvider query should succeed");
        assert!(full_data.rows.len() <= 5);
        assert!(
            !warnings
                .iter()
                .any(|w| w.source.eq_ignore_ascii_case("Security")
                    && w.message.to_ascii_lowercase().contains("permission")),
            "elevated run should not emit Security permission warning: {warnings:?}"
        );
    } else {
        let logon_prov = LogonProvider::new(ForensicSource::Live);
        let err = logon_prov
            .query(&TableQuery::default())
            .expect_err("non-elevated live Security logon query must return PermissionDenied, not Ok(0 rows)");
        match err {
            TableError::Provider(msg) => {
                let lower = msg.to_ascii_lowercase();
                assert!(
                    lower.contains("permission") || lower.contains("denied") || lower.contains("elevated"),
                    "unexpected non-elevated live Security error: {msg}"
                );
            }
            other => panic!("unexpected live Security error variant: {other:?}"),
        }

        let full_prov = FullEventLogProvider::new(ForensicSource::Live);
        let (full_data, warnings) = full_prov
            .query_with_warnings(&TableQuery {
                limit: Some(5),
                ..TableQuery::default()
            })
            .expect("non-elevated FullEventLogProvider should degrade gracefully across System/Application");
        assert!(full_data.rows.len() <= 5);
        assert!(
            warnings
                .iter()
                .any(|w| w.source.contains("Security") || w.message.contains("Security")),
            "non-elevated FullEventLogProvider must emit a DiagnosticWarning mentioning Security; got {warnings:?}"
        );
    }
}

#[cfg(not(windows))]
#[test]
fn non_windows_live_returns_unsupported_platform() {
    let prov = FullEventLogProvider::new(ForensicSource::Live);
    let err = prov
        .query(&TableQuery::default())
        .expect_err("live must fail on non-Windows");
    assert!(matches!(err, TableError::Provider(ref msg) if msg.contains("unsupported platform")));
}

#[test]
fn deep_binxml_element_nesting_returns_parse_error_without_stack_overflow() {
    let mut chunk = vec![0u8; CHUNK_SIZE];
    let rec_start = CHUNK_DATA_OFFSET;
    let mut pos = rec_start;
    // Record header: magic (4) + size (4) + record_id (8) + written_time (8)
    chunk[pos..pos + 4].copy_from_slice(&[0x2A, 0x2A, 0x00, 0x00]);
    pos += 8;
    chunk[pos..pos + 8].copy_from_slice(&1u64.to_le_bytes());
    pos += 8;
    chunk[pos..pos + 8].copy_from_slice(&133_000_000_000_000_000u64.to_le_bytes());
    pos += 8;

    // BinXML FragmentHeader
    chunk[pos..pos + 4].copy_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
    pos += 4;

    // Root element defining inline Name ("E")
    chunk[pos] = 0x01;
    chunk[pos + 1..pos + 3].copy_from_slice(&0xFFFFu16.to_le_bytes());
    chunk[pos + 3..pos + 7].copy_from_slice(&0u32.to_le_bytes());
    let name_off = (pos + 11) as u32;
    chunk[pos + 7..pos + 11].copy_from_slice(&name_off.to_le_bytes());
    pos += 11;
    chunk[pos..pos + 4].copy_from_slice(&0u32.to_le_bytes());
    chunk[pos + 4..pos + 6].copy_from_slice(&0u16.to_le_bytes());
    chunk[pos + 6..pos + 8].copy_from_slice(&1u16.to_le_bytes());
    chunk[pos + 8..pos + 10].copy_from_slice(&u16::from(b'E').to_le_bytes());
    chunk[pos + 10..pos + 12].copy_from_slice(&0u16.to_le_bytes());
    pos += 12;
    chunk[pos] = 0x02;
    pos += 1;

    // 4,500 nested 0x01+0x02 elements reusing cached Name (12 bytes * 4500 = 54,000 bytes)
    let depth = 4_500usize;
    for _ in 0..depth {
        chunk[pos] = 0x01;
        chunk[pos + 1..pos + 3].copy_from_slice(&0xFFFFu16.to_le_bytes());
        chunk[pos + 3..pos + 7].copy_from_slice(&0u32.to_le_bytes());
        chunk[pos + 7..pos + 11].copy_from_slice(&name_off.to_le_bytes());
        chunk[pos + 11] = 0x02;
        pos += 12;
    }
    for _ in 0..=depth {
        chunk[pos] = 0x04;
        pos += 1;
    }
    chunk[pos] = 0x00;
    pos += 1;

    // Trailing record size copy
    let rec_size = (pos + 4 - rec_start) as u32;
    chunk[rec_start + 4..rec_start + 8].copy_from_slice(&rec_size.to_le_bytes());
    chunk[pos..pos + 4].copy_from_slice(&rec_size.to_le_bytes());
    pos += 4;
    let free_space = pos as u32;

    // Valid chunk header + CRC-32s
    chunk[0..8].copy_from_slice(b"ElfChnk\0");
    chunk[0x08..0x10].copy_from_slice(&1u64.to_le_bytes());
    chunk[0x10..0x18].copy_from_slice(&1u64.to_le_bytes());
    chunk[0x18..0x20].copy_from_slice(&1u64.to_le_bytes());
    chunk[0x20..0x28].copy_from_slice(&1u64.to_le_bytes());
    chunk[0x28..0x2C].copy_from_slice(&128u32.to_le_bytes());
    chunk[0x2C..0x30].copy_from_slice(&(rec_start as u32).to_le_bytes());
    chunk[0x30..0x34].copy_from_slice(&free_space.to_le_bytes());
    let rec_crc = crc32_ieee(&chunk[CHUNK_DATA_OFFSET..free_space as usize]);
    chunk[0x34..0x38].copy_from_slice(&rec_crc.to_le_bytes());
    let mut hdr_hasher = crc32fast::Hasher::new();
    hdr_hasher.update(&chunk[0..120]);
    hdr_hasher.update(&chunk[128..512]);
    let hdr_crc = hdr_hasher.finalize();
    chunk[0x7C..0x80].copy_from_slice(&hdr_crc.to_le_bytes());

    let mut header = vec![0u8; 4096];
    header[0..8].copy_from_slice(b"ElfFile\0");
    header[0x18..0x20].copy_from_slice(&2u64.to_le_bytes());
    header[0x20..0x24].copy_from_slice(&128u32.to_le_bytes());
    header[0x24..0x26].copy_from_slice(&1u16.to_le_bytes());
    header[0x26..0x28].copy_from_slice(&3u16.to_le_bytes());
    header[0x28..0x2A].copy_from_slice(&4096u16.to_le_bytes());
    header[0x2A..0x2C].copy_from_slice(&1u16.to_le_bytes());
    let file_crc = crc32_ieee(&header[0..120]);
    header[0x7C..0x80].copy_from_slice(&file_crc.to_le_bytes());

    let mut evtx = Vec::with_capacity(4096 + CHUNK_SIZE);
    evtx.extend_from_slice(&header);
    evtx.extend_from_slice(&chunk);

    let err = EvtxArchive::from_bytes(&evtx).expect_err("deep BinXML element nesting must return Parse error");
    assert!(
        matches!(err, ForensicError::Parse { .. }),
        "expected Parse error, got {err:?}"
    );
}

#[test]
fn cross_channel_event_id_isolation_in_offline_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let t0 = ts(2026, 11, 22, 12, 0, 0);

    let mut ps_builder = SyntheticEvtxBuilder::new();
    ps_builder.add_templated_event(
        &EventSpec::new(t0, "Windows PowerShell", "PowerShell", 400)
            .data("HostApplication", "powershell.exe -NoLogo")
            .data("Payload", "Write-Output ok"),
    );
    std::fs::write(dir.path().join("Windows PowerShell.evtx"), ps_builder.build()).expect("write powershell evtx");

    let mut usb_builder = SyntheticEvtxBuilder::new();
    usb_builder.add_templated_event(
        &EventSpec::new(
            t0 + chrono::Duration::seconds(5),
            "Microsoft-Windows-Kernel-PnP/Configuration",
            "Microsoft-Windows-Kernel-PnP",
            400,
        )
        .data("DeviceInstanceId", r"USB\VID_046D&PID_C52B\7&12345&0&0000")
        .data("DriverName", "hidusb.inf"),
    );
    std::fs::write(dir.path().join("Kernel-PnP.evtx"), usb_builder.build()).expect("write kernel-pnp evtx");

    // Also include an unrelated operational log emitting colliding EIDs 12, 21, 100, 4624, 4688, 1006, 8001,
    // plus EID 1 carrying Sysmon-like <Data Name="Image"> on a non-Sysmon channel.
    let mut other_builder = SyntheticEvtxBuilder::new();
    for eid in [12u16, 21, 100, 4624, 4688, 1006, 8001] {
        other_builder.add_templated_event(&EventSpec::new(
            t0 + chrono::Duration::seconds(10),
            "Custom-Vendor/Operational",
            "Custom-Vendor",
            eid,
        ));
    }
    other_builder.add_templated_event(
        &EventSpec::new(
            t0 + chrono::Duration::seconds(15),
            "Custom/Operational",
            "Custom-Vendor",
            1,
        )
        .data("ProcessId", "4242")
        .data("Image", r"C:\custom\app.exe")
        .data("CommandLine", "app.exe --unrelated"),
    );
    std::fs::write(dir.path().join("CustomVendor.evtx"), other_builder.build()).expect("write custom evtx");

    let src = ForensicSource::OfflinePath(dir.path().to_path_buf());
    let providers = all_providers(&src);
    let query = |id: &str| {
        providers
            .iter()
            .find(|p| p.tool_id() == id)
            .unwrap()
            .query(&TableQuery::default())
            .unwrap()
    };

    let ps_data = query("evtx.powershell");
    assert_eq!(ps_data.rows.len(), 1, "evtx.powershell must exclude Kernel-PnP EID 400");
    assert_eq!(ps_data.rows[0].cells[2].to_string(), "powershell.exe -NoLogo");

    let usb_data = query("evtx.usb");
    assert_eq!(usb_data.rows.len(), 1, "evtx.usb must exclude PowerShell EID 400");
    assert_eq!(usb_data.rows[0].cells[3].to_string(), "VID_046D");
    assert_eq!(usb_data.rows[0].cells[4].to_string(), "PID_C52B");

    assert_eq!(query("evtx.uptime").rows.len(), 0);
    assert_eq!(query("evtx.rdp").rows.len(), 0);
    assert_eq!(query("evtx.tasks").rows.len(), 0);
    assert_eq!(query("evtx.logon").rows.len(), 0);
    assert_eq!(query("evtx.process").rows.len(), 0);
    assert_eq!(query("evtx.defender").rows.len(), 0);
    assert_eq!(query("evtx.wifi").rows.len(), 0);
}

#[test]
fn uptime_slow_boot_75s_post_boot_window_alignment() {
    let mut b = SyntheticEvtxBuilder::new();
    let boot1 = ts(2026, 11, 20, 10, 0, 0);
    let boot2 = ts(2026, 11, 20, 11, 0, 0);

    // Boot 1 (no clean shutdown)
    b.add_templated_event(&EventSpec::new(boot1, "System", "Microsoft-Windows-Kernel-General", 12));
    b.add_templated_event(&EventSpec::new(
        boot1 + chrono::Duration::seconds(5),
        "System",
        "EventLog",
        6005,
    ));

    // Boot 2 taking 80s total, with 6008 logged at +75s
    b.add_templated_event(&EventSpec::new(boot2, "System", "Microsoft-Windows-Kernel-General", 12));
    b.add_templated_event(&EventSpec::new(
        boot2 + chrono::Duration::seconds(2),
        "System",
        "EventLog",
        6009,
    ));
    b.add_templated_event(&EventSpec::new(
        boot2 + chrono::Duration::seconds(75),
        "System",
        "EventLog",
        6008,
    ));
    b.add_templated_event(&EventSpec::new(
        boot2 + chrono::Duration::seconds(80),
        "System",
        "EventLog",
        6005,
    ));

    let src = ForensicSource::OfflineBytes(b.build());
    let uptime = all_providers(&src)
        .into_iter()
        .find(|p| p.tool_id() == "evtx.uptime")
        .unwrap();
    let data = uptime.query(&TableQuery::default()).expect("uptime query");

    assert_eq!(data.rows.len(), 2, "75s slow boot must not split into 3 sessions");
    assert_eq!(data.rows[0].cells[0], CellValue::Timestamp(boot2));
    assert_eq!(data.rows[0].cells[4].to_string(), "Active");
    assert_eq!(data.rows[1].cells[0], CellValue::Timestamp(boot1));
    assert_eq!(data.rows[1].cells[1], CellValue::Null);
    assert_eq!(data.rows[1].cells[3].to_string(), "Unexpected shutdown");
    assert_eq!(data.rows[1].cells[4].to_string(), "Unexpected");

    // Also verify EID 41 at +75s attributes Bugcheck/Unclean to prior session without splitting boot2.
    let mut b41 = SyntheticEvtxBuilder::new();
    b41.add_templated_event(&EventSpec::new(boot1, "System", "Microsoft-Windows-Kernel-General", 12));
    b41.add_templated_event(&EventSpec::new(
        boot1 + chrono::Duration::seconds(5),
        "System",
        "EventLog",
        6005,
    ));
    b41.add_templated_event(&EventSpec::new(boot2, "System", "Microsoft-Windows-Kernel-General", 12));
    b41.add_templated_event(
        &EventSpec::new(
            boot2 + chrono::Duration::seconds(75),
            "System",
            "Microsoft-Windows-Kernel-Power",
            41,
        )
        .data("BugcheckCode", "0x9f"),
    );
    b41.add_templated_event(&EventSpec::new(
        boot2 + chrono::Duration::seconds(80),
        "System",
        "EventLog",
        6005,
    ));

    let src41 = ForensicSource::OfflineBytes(b41.build());
    let uptime41 = all_providers(&src41)
        .into_iter()
        .find(|p| p.tool_id() == "evtx.uptime")
        .unwrap();
    let data41 = uptime41.query(&TableQuery::default()).expect("uptime41 query");
    assert_eq!(data41.rows.len(), 2);
    assert_eq!(data41.rows[0].cells[0], CellValue::Timestamp(boot2));
    assert_eq!(data41.rows[0].cells[4].to_string(), "Active");
    assert_eq!(data41.rows[1].cells[4].to_string(), "Bugcheck/Unclean");
    assert_eq!(data41.rows[1].cells[5].to_string(), "0x9f");
}

#[test]
fn multi_host_logon_id_collision_is_isolated_by_computer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let t0 = ts(2026, 11, 20, 10, 0, 0);

    let mut host_a = SyntheticEvtxBuilder::new();
    host_a.add_templated_event(
        &EventSpec::new(t0, "Security", "Microsoft-Windows-Security-Auditing", 4624)
            .computer("HOST-A")
            .data("TargetUserName", "alice")
            .data("TargetDomainName", "CORP")
            .data("TargetLogonId", "0x1001")
            .data("LogonType", "2"),
    );
    host_a.add_templated_event(
        &EventSpec::new(
            t0 + chrono::Duration::minutes(10),
            "Security",
            "Microsoft-Windows-Security-Auditing",
            4634,
        )
        .computer("host-a")
        .data("TargetUserName", "alice")
        .data("TargetDomainName", "CORP")
        .data("TargetLogonId", "0x00001001")
        .data("LogonType", "2"),
    );
    std::fs::write(dir.path().join("Security_HostA.evtx"), host_a.build()).expect("write host A");

    let mut host_b = SyntheticEvtxBuilder::new();
    host_b.add_templated_event(
        &EventSpec::new(
            t0 + chrono::Duration::minutes(1),
            "Security",
            "Microsoft-Windows-Security-Auditing",
            4624,
        )
        .computer("HOST-B")
        .data("TargetUserName", "bob")
        .data("TargetDomainName", "CORP")
        .data("TargetLogonId", "0x1001")
        .data("LogonType", "10"),
    );
    host_b.add_templated_event(
        &EventSpec::new(
            t0 + chrono::Duration::minutes(6),
            "Security",
            "Microsoft-Windows-Security-Auditing",
            4647,
        )
        .computer("HOST-B")
        .data("TargetUserName", "bob")
        .data("TargetDomainName", "CORP")
        .data("TargetLogonId", "0x1001"),
    );
    std::fs::write(dir.path().join("Security_HostB.evtx"), host_b.build()).expect("write host B");

    let logon = LogonProvider::new(ForensicSource::OfflinePath(dir.path().to_path_buf()));
    let data = logon.query(&TableQuery::default()).expect("multi-host logon query");
    assert_eq!(data.rows.len(), 2, "colliding LUIDs across hosts must pair separately");

    let by_user: BTreeMap<String, Vec<CellValue>> = data
        .rows
        .iter()
        .map(|r| (r.cells[1].to_string(), r.cells.clone()))
        .collect();
    assert_eq!(by_user["alice"][7], CellValue::Uint(600_000));
    assert_eq!(by_user["bob"][7], CellValue::Uint(300_000));
}

#[test]
fn process_provider_isolates_eid_1_to_sysmon_or_empty_channel() {
    let t0 = ts(2026, 11, 22, 15, 0, 0);
    let mut b = SyntheticEvtxBuilder::new();
    // 1. Custom non-Sysmon channel EID 1 with Image -> must be excluded
    b.add_templated_event(
        &EventSpec::new(t0, "Custom/Operational", "CustomVendor", 1)
            .data("ProcessId", "1111")
            .data("Image", r"C:\custom\ignored.exe")
            .data("CommandLine", "ignored.exe"),
    );
    // 2. Sysmon channel EID 1 -> must be included
    b.add_templated_event(
        &EventSpec::new(
            t0 + chrono::Duration::seconds(1),
            "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-Sysmon",
            1,
        )
        .data("ProcessId", "2222")
        .data("Image", r"C:\Windows\System32\whoami.exe")
        .data("CommandLine", "whoami.exe"),
    );
    // 3. Empty channel with non-Sysmon provider EID 1 -> must be included per empty-channel rule
    b.add_templated_event(
        &EventSpec::new(t0 + chrono::Duration::seconds(2), "", "GenericSource", 1)
            .data("ProcessId", "3333")
            .data("Image", r"C:\Windows\System32\hostname.exe")
            .data("CommandLine", "hostname.exe"),
    );

    let proc_prov = ProcessProvider::new(ForensicSource::OfflineBytes(b.build()));
    let data = proc_prov.query(&TableQuery::default()).expect("process query");
    assert_eq!(data.rows.len(), 2, "Custom/Operational EID 1 must be excluded");
    let images: Vec<String> = data.rows.iter().map(|r| r.cells[3].to_string()).collect();
    assert!(images.iter().any(|p| p.ends_with("whoami.exe")));
    assert!(images.iter().any(|p| p.ends_with("hostname.exe")));
    assert!(!images.iter().any(|p| p.contains("ignored.exe")));
}
