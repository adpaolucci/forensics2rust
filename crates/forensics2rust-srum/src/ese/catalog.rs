use std::collections::BTreeMap;

use forensics2rust_core::{DiagnosticWarning, ForensicError, WarningSeverity};

use super::btree::{WalkOptions, walk_btree};
use super::compress::{DecompressOutcome, decompress_ese_value};
use super::header::EseHeader;
use super::record::{FixedColumnLayout, parse_record};
use super::value::{decode_cp1252, decode_ese_text};

pub const MSYS_OBJECTS_PGNO_FDP: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JetColType {
    Nil,
    Bit,
    UnsignedByte,
    Short,
    Long,
    Currency,
    Single,
    Double,
    DateTime,
    Binary,
    Text,
    LongBinary,
    LongText,
    Slv,
    UnsignedLong,
    LongLong,
    Guid,
    UnsignedShort,
    Unknown(u16),
}

impl JetColType {
    pub fn from_u16(val: u16) -> Self {
        match val {
            0 => Self::Nil,
            1 => Self::Bit,
            2 => Self::UnsignedByte,
            3 => Self::Short,
            4 => Self::Long,
            5 => Self::Currency,
            6 => Self::Single,
            7 => Self::Double,
            8 => Self::DateTime,
            9 => Self::Binary,
            10 => Self::Text,
            11 => Self::LongBinary,
            12 => Self::LongText,
            13 => Self::Slv,
            14 => Self::UnsignedLong,
            15 => Self::LongLong,
            16 => Self::Guid,
            17 => Self::UnsignedShort,
            other => Self::Unknown(other),
        }
    }

    pub fn as_u16(self) -> u16 {
        match self {
            Self::Nil => 0,
            Self::Bit => 1,
            Self::UnsignedByte => 2,
            Self::Short => 3,
            Self::Long => 4,
            Self::Currency => 5,
            Self::Single => 6,
            Self::Double => 7,
            Self::DateTime => 8,
            Self::Binary => 9,
            Self::Text => 10,
            Self::LongBinary => 11,
            Self::LongText => 12,
            Self::Slv => 13,
            Self::UnsignedLong => 14,
            Self::LongLong => 15,
            Self::Guid => 16,
            Self::UnsignedShort => 17,
            Self::Unknown(v) => v,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EseColumnSchema {
    pub id: u16,
    pub name: String,
    pub col_type: JetColType,
    pub max_size: u32,
    pub flags: u32,
    pub codepage: u32,
    pub record_offset: Option<u16>,
    pub is_derived: bool,
}

#[derive(Debug, Clone)]
pub struct EseTableSchema {
    pub name: String,
    pub objid_table: u32,
    pub pgno_fdp: u32,
    pub lv_pgno_fdp: Option<u32>,
    pub template_table: Option<String>,
    pub columns: Vec<EseColumnSchema>,
}

impl EseTableSchema {
    pub fn fixed_column_layouts(&self) -> Vec<FixedColumnLayout> {
        self.columns
            .iter()
            .filter(|c| c.id >= 1 && c.id <= 127)
            .map(|c| FixedColumnLayout {
                id: c.id,
                size: c.max_size as usize,
                record_offset: c.record_offset.map(usize::from),
            })
            .collect()
    }
}

fn msys_objects_schema() -> EseTableSchema {
    EseTableSchema {
        name: "MSysObjects".to_string(),
        objid_table: 2,
        pgno_fdp: MSYS_OBJECTS_PGNO_FDP,
        lv_pgno_fdp: None,
        template_table: None,
        columns: vec![
            EseColumnSchema {
                id: 1,
                name: "ObjidTable".to_string(),
                col_type: JetColType::Long,
                max_size: 4,
                flags: 1,
                codepage: 0,
                record_offset: Some(4),
                is_derived: false,
            },
            EseColumnSchema {
                id: 2,
                name: "Type".to_string(),
                col_type: JetColType::Short,
                max_size: 2,
                flags: 1,
                codepage: 0,
                record_offset: Some(8),
                is_derived: false,
            },
            EseColumnSchema {
                id: 3,
                name: "Id".to_string(),
                col_type: JetColType::Long,
                max_size: 4,
                flags: 1,
                codepage: 0,
                record_offset: Some(10),
                is_derived: false,
            },
            EseColumnSchema {
                id: 4,
                name: "ColtypOrPgnoFDP".to_string(),
                col_type: JetColType::Long,
                max_size: 4,
                flags: 1,
                codepage: 0,
                record_offset: Some(14),
                is_derived: false,
            },
            EseColumnSchema {
                id: 5,
                name: "SpaceUsage".to_string(),
                col_type: JetColType::Long,
                max_size: 4,
                flags: 1,
                codepage: 0,
                record_offset: Some(18),
                is_derived: false,
            },
            EseColumnSchema {
                id: 6,
                name: "Flags".to_string(),
                col_type: JetColType::Long,
                max_size: 4,
                flags: 1,
                codepage: 0,
                record_offset: Some(22),
                is_derived: false,
            },
            EseColumnSchema {
                id: 7,
                name: "PagesOrLocale".to_string(),
                col_type: JetColType::Long,
                max_size: 4,
                flags: 1,
                codepage: 0,
                record_offset: Some(26),
                is_derived: false,
            },
            EseColumnSchema {
                id: 8,
                name: "RootFlag".to_string(),
                col_type: JetColType::Bit,
                max_size: 1,
                flags: 1,
                codepage: 0,
                record_offset: Some(30),
                is_derived: false,
            },
            EseColumnSchema {
                id: 9,
                name: "RecordOffset".to_string(),
                col_type: JetColType::Short,
                max_size: 2,
                flags: 1,
                codepage: 0,
                record_offset: Some(31),
                is_derived: false,
            },
            EseColumnSchema {
                id: 10,
                name: "LCMapFlags".to_string(),
                col_type: JetColType::Long,
                max_size: 4,
                flags: 1,
                codepage: 0,
                record_offset: Some(33),
                is_derived: false,
            },
            EseColumnSchema {
                id: 11,
                name: "KeyMost".to_string(),
                col_type: JetColType::UnsignedShort,
                max_size: 2,
                flags: 1,
                codepage: 0,
                record_offset: Some(37),
                is_derived: false,
            },
            EseColumnSchema {
                id: 128,
                name: "Name".to_string(),
                col_type: JetColType::Text,
                max_size: 255,
                flags: 2,
                codepage: 1252,
                record_offset: None,
                is_derived: false,
            },
            EseColumnSchema {
                id: 130,
                name: "TemplateTable".to_string(),
                col_type: JetColType::Text,
                max_size: 255,
                flags: 2,
                codepage: 1252,
                record_offset: None,
                is_derived: false,
            },
            EseColumnSchema {
                id: 257,
                name: "CallbackDependencies".to_string(),
                col_type: JetColType::LongBinary,
                max_size: 0,
                flags: 4,
                codepage: 0,
                record_offset: None,
                is_derived: false,
            },
        ],
    }
}

fn read_i32(bytes: Option<&[u8]>) -> Option<i32> {
    let b = bytes?;
    if b.len() >= 4 {
        Some(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    } else {
        None
    }
}

fn read_i16(bytes: Option<&[u8]>) -> Option<i16> {
    let b = bytes?;
    if b.len() >= 2 {
        Some(i16::from_le_bytes([b[0], b[1]]))
    } else {
        None
    }
}

struct RawTableEntry {
    objid_col: u32,
    id_col: u32,
    pgno_fdp: u32,
    name: String,
    template_table: Option<String>,
}

pub fn parse_catalog(
    data: &[u8],
    header: &EseHeader,
    warnings: &mut Vec<DiagnosticWarning>,
) -> Result<BTreeMap<String, EseTableSchema>, ForensicError> {
    let msys_schema = msys_objects_schema();
    let msys_fixed = msys_schema.fixed_column_layouts();
    let entries = walk_btree(
        data,
        header,
        MSYS_OBJECTS_PGNO_FDP,
        WalkOptions::forensic_default(),
        warnings,
    )?;

    let mut raw_tables: Vec<RawTableEntry> = Vec::new();
    let mut columns_by_objid: BTreeMap<u32, Vec<EseColumnSchema>> = BTreeMap::new();
    let mut lv_by_objid: BTreeMap<u32, u32> = BTreeMap::new();

    for entry in entries {
        if entry.tag_flags.is_versioned() && entry.data == [0x00] {
            continue;
        }
        let rec = match parse_record(&entry.data, entry.page_flags, header.page_format, &msys_fixed) {
            Ok(r) => r,
            Err(err) => {
                warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Warn,
                    tool_id: "srum.db".to_string(),
                    source: "MSysObjects".to_string(),
                    message: format!("skipping malformed catalog row: {err}"),
                });
                continue;
            }
        };

        let Some(objid_table) = read_i32(rec.get_fixed(1)).map(|v| v as u32) else {
            continue;
        };
        let Some(obj_type) = read_i16(rec.get_fixed(2)) else {
            continue;
        };
        let id_val = read_i32(rec.get_fixed(3)).unwrap_or(0) as u32;
        let coltyp_or_pgno = read_i32(rec.get_fixed(4)).unwrap_or(0) as u32;
        let space_usage = read_i32(rec.get_fixed(5)).unwrap_or(0) as u32;
        let flags = read_i32(rec.get_fixed(6)).unwrap_or(0) as u32;
        let locale = read_i32(rec.get_fixed(7)).unwrap_or(1252) as u32;
        let record_offset = read_i16(rec.get_fixed(9)).and_then(|v| u16::try_from(v).ok());
        let name = rec
            .get_variable(128)
            .map(decode_cp1252)
            .map(|s| s.trim_end_matches('\0').to_string())
            .unwrap_or_default();
        let var_template = rec
            .get_variable(130)
            .map(decode_cp1252)
            .map(|s| s.trim_end_matches('\0').to_string())
            .filter(|s| !s.is_empty());
        let template_table = var_template.or_else(|| {
            let tagged = rec.get_tagged(257)?;
            if tagged.is_null {
                return None;
            }
            let text = if tagged.is_compressed && !tagged.data.is_empty() {
                match decompress_ese_value(&tagged.data, warnings) {
                    Ok(DecompressOutcome::Decompressed {
                        bytes,
                        is_utf16_expanded,
                    }) => decode_ese_text(&bytes, 1252, is_utf16_expanded),
                    _ => decode_cp1252(&tagged.data),
                }
            } else {
                decode_cp1252(&tagged.data)
            };
            let trimmed = text.trim_end_matches('\0').to_string();
            if trimmed.is_empty() || !trimmed.bytes().all(|b| (0x20..0x7F).contains(&b)) {
                None
            } else {
                Some(trimmed)
            }
        });

        match obj_type {
            1 => {
                if !name.is_empty() && coltyp_or_pgno != 0 {
                    raw_tables.push(RawTableEntry {
                        objid_col: objid_table,
                        id_col: id_val,
                        pgno_fdp: coltyp_or_pgno,
                        name,
                        template_table,
                    });
                }
            }
            2 => {
                if !name.is_empty()
                    && let Ok(col_id) = u16::try_from(id_val)
                {
                    columns_by_objid.entry(objid_table).or_default().push(EseColumnSchema {
                        id: col_id,
                        name,
                        col_type: JetColType::from_u16(coltyp_or_pgno as u16),
                        max_size: space_usage,
                        flags,
                        codepage: locale,
                        record_offset,
                        is_derived: false,
                    });
                }
            }
            4 if coltyp_or_pgno != 0 => {
                lv_by_objid.insert(objid_table, coltyp_or_pgno);
            }
            _ => {}
        }
    }

    let mut tables = BTreeMap::new();
    for raw in raw_tables {
        // Real ESE Type=1 rows have ObjidTable=1 and Id=<table_objid>.
        // Synthetic builders may place table_objid in ObjidTable directly.
        let effective_objid = if raw.objid_col <= 1 {
            raw.id_col
        } else if columns_by_objid.contains_key(&raw.objid_col) && !columns_by_objid.contains_key(&raw.id_col) {
            raw.objid_col
        } else if raw.id_col != 0 {
            raw.id_col
        } else {
            raw.objid_col
        };

        let mut cols = columns_by_objid.remove(&effective_objid).unwrap_or_default();
        cols.sort_by_key(|c| c.id);

        let lv_pgno_fdp = lv_by_objid.get(&effective_objid).copied();

        tables.insert(
            raw.name.clone(),
            EseTableSchema {
                name: raw.name,
                objid_table: effective_objid,
                pgno_fdp: raw.pgno_fdp,
                lv_pgno_fdp,
                template_table: raw.template_table,
                columns: cols,
            },
        );
    }

    // Apply TemplateTable column inheritance
    let snapshot = tables.clone();
    for table in tables.values_mut() {
        if let Some(ref tmpl_name) = table.template_table
            && let Some(tmpl) = snapshot
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(tmpl_name))
                .map(|(_, v)| v)
        {
            for tcol in &tmpl.columns {
                if tcol.id >= 256 {
                    if !table.columns.iter().any(|c| c.id == tcol.id && c.is_derived) {
                        let mut inherited = tcol.clone();
                        inherited.is_derived = true;
                        table.columns.push(inherited);
                    }
                } else if !table.columns.iter().any(|c| c.id == tcol.id) {
                    let mut inherited = tcol.clone();
                    inherited.is_derived = true;
                    table.columns.push(inherited);
                }
            }
            table.columns.sort_by_key(|c| (c.id, c.is_derived));
        }
    }

    if !tables.keys().any(|k| k.eq_ignore_ascii_case("MSysObjects")) {
        tables.insert("MSysObjects".to_string(), msys_schema);
    }

    Ok(tables)
}
