use forensics2rust_core::ForensicError;
use serde::{Deserialize, Serialize};

use crate::regf::{
    REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_LINK, REG_MULTI_SZ, REG_SZ, RegValueData, RegfHive, encode_multi_sz,
    encode_utf16_le_nul,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum RegExportFormat {
    #[default]
    Regedit5,
    Regedit4,
}

impl RegExportFormat {
    pub fn header_line(self) -> &'static str {
        match self {
            Self::Regedit5 => "Windows Registry Editor Version 5.00",
            Self::Regedit4 => "REGEDIT4",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegExportOptions {
    pub format: RegExportFormat,
    pub root_prefix: String,
    pub include_deleted: bool,
    pub utf8_output: bool,
}

impl Default for RegExportOptions {
    fn default() -> Self {
        Self {
            format: RegExportFormat::Regedit5,
            root_prefix: "HKEY_LOCAL_MACHINE\\OFFLINE".to_owned(),
            include_deleted: true,
            utf8_output: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegExportKeyStats {
    pub key_path: String,
    pub values_exported: u64,
    pub malformed_cells_recovered: u64,
    pub output_bytes: u64,
    pub is_deleted: bool,
    pub snippet: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegExportResult {
    pub text: String,
    pub bytes: Vec<u8>,
    pub keys_exported: usize,
    pub values_exported: usize,
    pub recovered_cells: usize,
    pub per_key: Vec<RegExportKeyStats>,
}

/// Escapes backslash, double-quote, CR, and LF for `.reg` string literals.
pub fn escape_reg_str(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// Unescapes a `.reg` string literal body.
pub fn unescape_reg_str(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('r') => out.push('\r'),
                Some('n') => out.push('\n'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn format_hex_wrapped(prefix: &str, bytes: &[u8]) -> String {
    let mut out = String::with_capacity(prefix.len() + bytes.len() * 3 + 16);
    out.push_str(prefix);
    let mut col = prefix.chars().count();
    for (idx, b) in bytes.iter().enumerate() {
        if idx > 0 {
            out.push(',');
            col += 1;
            if col + 3 > 78 {
                out.push_str("\\\r\n  ");
                col = 2;
            }
        }
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
        col += 2;
    }
    out
}

fn latin1_nul_bytes(s: &str) -> Vec<u8> {
    let mut out: Vec<u8> = s
        .chars()
        .map(|c| {
            let code = u32::from(c);
            if code <= 0xFF { code as u8 } else { b'?' }
        })
        .collect();
    out.push(0);
    out
}

fn latin1_multi_sz_bytes(items: &[String]) -> Vec<u8> {
    if items.is_empty() {
        return vec![0];
    }
    let mut out = Vec::new();
    for item in items {
        out.extend(latin1_nul_bytes(item));
    }
    out.push(0);
    out
}

fn decode_latin1_nul(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    raw[..end].iter().map(|&b| char::from(b)).collect()
}

fn decode_latin1_multi_sz(raw: &[u8]) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = Vec::new();
    for &b in raw {
        if b == 0 {
            if current.is_empty() {
                break;
            }
            items.push(current.iter().map(|&c| char::from(c)).collect());
            current.clear();
        } else {
            current.push(b);
        }
    }
    if !current.is_empty() {
        items.push(current.iter().map(|&c| char::from(c)).collect());
    }
    items
}

/// Formats a single Registry value assignment (`@=...` or `"Name"=...`) in `.reg` syntax.
pub fn format_reg_value_line(
    value_name: &str,
    data: &RegValueData,
    raw_bytes: &[u8],
    format: RegExportFormat,
) -> String {
    let lhs = if value_name.is_empty() {
        "@=".to_owned()
    } else {
        format!("\"{}\"=", escape_reg_str(value_name))
    };

    match data {
        RegValueData::Sz(s) => format!("{lhs}\"{}\"", escape_reg_str(s)),
        RegValueData::Dword(v) => format!("{lhs}dword:{v:08x}"),
        RegValueData::Binary(bytes) => format_hex_wrapped(&format!("{lhs}hex:"), bytes),
        RegValueData::None => format_hex_wrapped(&format!("{lhs}hex(0):"), raw_bytes),
        RegValueData::ExpandSz(s) => {
            let bytes = match format {
                RegExportFormat::Regedit5 => {
                    if raw_bytes.is_empty() {
                        encode_utf16_le_nul(s)
                    } else {
                        raw_bytes.to_vec()
                    }
                }
                RegExportFormat::Regedit4 => latin1_nul_bytes(s),
            };
            format_hex_wrapped(&format!("{lhs}hex(2):"), &bytes)
        }
        RegValueData::DwordBigEndian(v) => format_hex_wrapped(&format!("{lhs}hex(5):"), &v.to_be_bytes()),
        RegValueData::Link(s) => {
            let bytes = match format {
                RegExportFormat::Regedit5 => {
                    if raw_bytes.is_empty() {
                        encode_utf16_le_nul(s)
                    } else {
                        raw_bytes.to_vec()
                    }
                }
                RegExportFormat::Regedit4 => latin1_nul_bytes(s),
            };
            format_hex_wrapped(&format!("{lhs}hex(6):"), &bytes)
        }
        RegValueData::MultiSz(items) => {
            let bytes = match format {
                RegExportFormat::Regedit5 => {
                    if raw_bytes.is_empty() {
                        encode_multi_sz(items)
                    } else {
                        raw_bytes.to_vec()
                    }
                }
                RegExportFormat::Regedit4 => latin1_multi_sz_bytes(items),
            };
            format_hex_wrapped(&format!("{lhs}hex(7):"), &bytes)
        }
        RegValueData::Qword(v) => format_hex_wrapped(&format!("{lhs}hex(b):"), &v.to_le_bytes()),
        RegValueData::Other { raw_type, data } => format_hex_wrapped(&format!("{lhs}hex({raw_type:x}):"), data),
    }
}

/// Encodes `.reg` text according to the chosen format and UTF-8 override.
pub fn encode_reg_text(text: &str, format: RegExportFormat, utf8_output: bool) -> Vec<u8> {
    if utf8_output {
        return text.as_bytes().to_vec();
    }
    match format {
        RegExportFormat::Regedit5 => {
            let mut out = Vec::with_capacity(2 + text.len() * 2);
            out.extend_from_slice(&[0xFF, 0xFE]);
            for unit in text.encode_utf16() {
                out.extend_from_slice(&unit.to_le_bytes());
            }
            out
        }
        RegExportFormat::Regedit4 => text
            .chars()
            .map(|c| {
                let code = u32::from(c);
                if code <= 0xFF { code as u8 } else { b'?' }
            })
            .collect(),
    }
}

fn join_reg_header(root_prefix: &str, sub_path: &str) -> String {
    let prefix = root_prefix.trim_end_matches('\\');
    let sub = sub_path.trim_matches('\\');
    if sub.is_empty() {
        prefix.to_owned()
    } else if prefix.is_empty() {
        sub.to_owned()
    } else {
        format!("{prefix}\\{sub}")
    }
}

/// Exports a parsed [`RegfHive`] (including recovered unallocated/orphaned cells if requested) to `.reg`.
pub fn export_hive(hive: &RegfHive, options: &RegExportOptions) -> RegExportResult {
    let mut text = String::new();
    text.push_str(options.format.header_line());
    text.push_str("\r\n\r\n");

    let mut keys_exported = 0usize;
    let mut values_exported = 0usize;
    let mut recovered_cells = 0usize;
    let mut per_key = Vec::new();

    for key in hive.walk_keys() {
        let full_path = join_reg_header(&options.root_prefix, key.path());
        let mut block = String::new();
        block.push('[');
        block.push_str(&full_path);
        block.push_str("]\r\n");

        let mut val_count = 0u64;
        for val in key.values() {
            let line = format_reg_value_line(&val.name, &val.data, &val.raw_bytes, options.format);
            block.push_str(&line);
            block.push_str("\r\n");
            val_count += 1;
        }
        block.push_str("\r\n");

        let block_bytes = encode_reg_text(&block, options.format, options.utf8_output).len() as u64;
        text.push_str(&block);
        keys_exported += 1;
        values_exported += val_count as usize;
        per_key.push(RegExportKeyStats {
            key_path: full_path,
            values_exported: val_count,
            malformed_cells_recovered: 0,
            output_bytes: block_bytes,
            is_deleted: false,
            snippet: block.trim_end().to_owned(),
        });
    }

    if options.include_deleted {
        for rec in hive.recovered_keys() {
            let rec_prefix = join_reg_header(&options.root_prefix, "_Recovered");
            let clean_rec_path = rec.path.trim_start_matches("[Recovered]\\").trim_matches('\\');
            let full_path = join_reg_header(&rec_prefix, clean_rec_path);
            let mut block = String::new();
            block.push_str(&format!("; [RECOVERED/{}]\r\n", rec.reason));
            block.push('[');
            block.push_str(&full_path);
            block.push_str("]\r\n");

            let mut val_count = 0u64;
            for val in &rec.values {
                let line = format_reg_value_line(&val.name, &val.data, &val.raw_bytes, options.format);
                block.push_str(&line);
                block.push_str("\r\n");
                val_count += 1;
            }
            block.push_str("\r\n");

            let cells_for_key = 1 + val_count;
            let block_bytes = encode_reg_text(&block, options.format, options.utf8_output).len() as u64;
            text.push_str(&block);
            keys_exported += 1;
            values_exported += val_count as usize;
            recovered_cells += cells_for_key as usize;
            per_key.push(RegExportKeyStats {
                key_path: full_path,
                values_exported: val_count,
                malformed_cells_recovered: cells_for_key,
                output_bytes: block_bytes,
                is_deleted: true,
                snippet: block.trim_end().to_owned(),
            });
        }
    }

    let bytes = encode_reg_text(&text, options.format, options.utf8_output);
    RegExportResult {
        text,
        bytes,
        keys_exported,
        values_exported,
        recovered_cells,
        per_key,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegScriptOp {
    CreateKey,
    DeleteKey,
    SetValue,
    DeleteValue,
}

impl RegScriptOp {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CreateKey => "CreateKey",
            Self::DeleteKey => "DeleteKey",
            Self::SetValue => "SetValue",
            Self::DeleteValue => "DeleteValue",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegScriptEntry {
    pub operation: RegScriptOp,
    pub key_path: String,
    pub value_name: Option<String>,
    pub value_type: Option<u32>,
    pub data: Option<RegValueData>,
    pub raw_bytes: Vec<u8>,
    pub reg_dotnet_line: String,
}

/// Decodes UTF-16LE/BE BOM, UTF-8, or Latin-1 `.reg` text into a Rust `String`.
pub fn decode_reg_script_bytes(bytes: &[u8]) -> Result<String, ForensicError> {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let body = &bytes[2..];
        let units: Vec<u16> = body.as_chunks::<2>().0.iter().map(|&c| u16::from_le_bytes(c)).collect();
        let text = String::from_utf16_lossy(&units);
        let trimmed = text.trim_end_matches('\0');
        if trimmed.contains('\0') {
            return Err(ForensicError::parse(
                "reg_script",
                "unexpected NUL byte in UTF-16LE .reg script",
            ));
        }
        Ok(trimmed.to_owned())
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        let body = &bytes[2..];
        let units: Vec<u16> = body.as_chunks::<2>().0.iter().map(|&c| u16::from_be_bytes(c)).collect();
        let text = String::from_utf16_lossy(&units);
        let trimmed = text.trim_end_matches('\0');
        if trimmed.contains('\0') {
            return Err(ForensicError::parse(
                "reg_script",
                "unexpected NUL byte in UTF-16BE .reg script",
            ));
        }
        Ok(trimmed.to_owned())
    } else if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        if rest.contains(&0) {
            return Err(ForensicError::parse(
                "reg_script",
                "unexpected binary NUL byte in .reg script",
            ));
        }
        Ok(match std::str::from_utf8(rest) {
            Ok(s) => s.to_owned(),
            Err(_) => rest.iter().map(|&b| char::from(b)).collect(),
        })
    } else {
        if bytes.contains(&0) {
            return Err(ForensicError::parse(
                "reg_script",
                "unexpected binary NUL byte in .reg script",
            ));
        }
        Ok(match std::str::from_utf8(bytes) {
            Ok(s) => s.to_owned(),
            Err(_) => bytes.iter().map(|&b| char::from(b)).collect(),
        })
    }
}

fn starts_with_registry_root(path: &str) -> bool {
    let upper = path.trim().to_ascii_uppercase();
    upper.starts_with("HKEY_")
        || upper.starts_with("HKLM\\")
        || upper.starts_with("HKCU\\")
        || upper.starts_with("HKU\\")
        || upper.starts_with("HKCR\\")
        || upper.starts_with("HKCC\\")
        || upper.starts_with("\\REGISTRY\\")
}

/// Parses a `Windows Registry Editor Version 5.00` or `REGEDIT4` script into operations.
pub fn parse_reg_script(bytes: &[u8]) -> Result<Vec<RegScriptEntry>, ForensicError> {
    let text = decode_reg_script_bytes(bytes)?;
    let mut logical_lines: Vec<String> = Vec::new();
    let mut current_line = String::new();
    let mut continuing = false;
    let mut detected_format: Option<RegExportFormat> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r');
        if continuing {
            current_line.push_str(line.trim_start());
            if let Some(stripped) = current_line.strip_suffix('\\') {
                current_line = stripped.to_owned();
                continuing = true;
            } else {
                logical_lines.push(std::mem::take(&mut current_line));
                continuing = false;
            }
        } else {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with(';') {
                continue;
            }
            if trimmed.eq_ignore_ascii_case("Windows Registry Editor Version 5.00") {
                detected_format.get_or_insert(RegExportFormat::Regedit5);
                continue;
            }
            if trimmed.eq_ignore_ascii_case("REGEDIT4") {
                detected_format.get_or_insert(RegExportFormat::Regedit4);
                continue;
            }
            if trimmed.contains("hex") && trimmed.ends_with('\\') {
                current_line = trimmed.trim_end_matches('\\').to_owned();
                continuing = true;
            } else {
                logical_lines.push(trimmed.to_owned());
            }
        }
    }
    if !current_line.is_empty() {
        logical_lines.push(current_line);
    }

    if logical_lines.is_empty() {
        if detected_format.is_some() {
            return Ok(Vec::new());
        }
        return Err(ForensicError::parse(
            "reg_script",
            "empty .reg script without recognized header",
        ));
    }

    let format = detected_format.unwrap_or(RegExportFormat::Regedit5);
    let mut entries = Vec::new();
    let mut current_key: Option<String> = None;

    for line in logical_lines {
        if line.starts_with('[') && line.ends_with(']') {
            let inner = &line[1..line.len() - 1];
            let key_candidate = inner.strip_prefix('-').unwrap_or(inner);
            if key_candidate.is_empty()
                || inner.contains('[')
                || inner.contains(']')
                || (detected_format.is_none() && !starts_with_registry_root(key_candidate))
            {
                return Err(ForensicError::parse(
                    "reg_script",
                    format!("invalid registry section header: {line}"),
                ));
            }
            if let Some(del_path) = inner.strip_prefix('-') {
                current_key = None;
                entries.push(RegScriptEntry {
                    operation: RegScriptOp::DeleteKey,
                    key_path: del_path.to_owned(),
                    value_name: None,
                    value_type: None,
                    data: None,
                    raw_bytes: Vec::new(),
                    reg_dotnet_line: line.clone(),
                });
            } else {
                current_key = Some(inner.to_owned());
                entries.push(RegScriptEntry {
                    operation: RegScriptOp::CreateKey,
                    key_path: inner.to_owned(),
                    value_name: None,
                    value_type: None,
                    data: None,
                    raw_bytes: Vec::new(),
                    reg_dotnet_line: line.clone(),
                });
            }
            continue;
        }

        let Some(ref key_path) = current_key else {
            return Err(ForensicError::parse(
                "reg_script",
                format!("unexpected content outside [Key] section: {line}"),
            ));
        };

        let (val_name, rhs) = if let Some(rest) = line.strip_prefix("@=") {
            (String::new(), rest.trim())
        } else if let Some(after_quote) = line.strip_prefix('"') {
            let Some((raw_name, rhs_part)) = split_quoted_assignment(after_quote) else {
                return Err(ForensicError::parse(
                    "reg_script",
                    format!("malformed value assignment: {line}"),
                ));
            };
            (unescape_reg_str(&raw_name), rhs_part.trim())
        } else {
            return Err(ForensicError::parse(
                "reg_script",
                format!("unrecognized .reg line: {line}"),
            ));
        };

        if rhs == "-" {
            entries.push(RegScriptEntry {
                operation: RegScriptOp::DeleteValue,
                key_path: key_path.clone(),
                value_name: Some(val_name),
                value_type: None,
                data: None,
                raw_bytes: Vec::new(),
                reg_dotnet_line: line,
            });
            continue;
        }

        let (raw_type, raw_bytes, data) = if rhs.starts_with('"') && rhs.ends_with('"') && rhs.len() >= 2 {
            let inner = &rhs[1..rhs.len() - 1];
            let s = unescape_reg_str(inner);
            let bytes = encode_utf16_le_nul(&s);
            (REG_SZ, bytes, RegValueData::Sz(s))
        } else if let Some(hex_num) = rhs.strip_prefix("dword:") {
            let val = u32::from_str_radix(hex_num.trim(), 16)
                .map_err(|e| ForensicError::parse("reg_script", format!("invalid dword '{hex_num}': {e}")))?;
            (REG_DWORD, val.to_le_bytes().to_vec(), RegValueData::Dword(val))
        } else if let Some(hex_body) = rhs.strip_prefix("hex:") {
            let bytes = parse_hex_bytes(hex_body)?;
            (REG_BINARY, bytes.clone(), RegValueData::Binary(bytes))
        } else if let Some(rest) = rhs.strip_prefix("hex(") {
            let Some((type_hex, hex_body)) = rest.split_once("):") else {
                return Err(ForensicError::parse(
                    "reg_script",
                    format!("malformed hex(N) value: {rhs}"),
                ));
            };
            let raw_type = u32::from_str_radix(type_hex.trim(), 16)
                .map_err(|e| ForensicError::parse("reg_script", format!("invalid hex type '{type_hex}': {e}")))?;
            let bytes = parse_hex_bytes(hex_body)?;
            let data = match (format, raw_type) {
                (RegExportFormat::Regedit4, REG_EXPAND_SZ) => RegValueData::ExpandSz(decode_latin1_nul(&bytes)),
                (RegExportFormat::Regedit4, REG_LINK) => RegValueData::Link(decode_latin1_nul(&bytes)),
                (RegExportFormat::Regedit4, REG_MULTI_SZ) => RegValueData::MultiSz(decode_latin1_multi_sz(&bytes)),
                _ => RegValueData::from_raw(raw_type, &bytes),
            };
            (raw_type, bytes, data)
        } else {
            return Err(ForensicError::parse(
                "reg_script",
                format!("unrecognized .reg value syntax: {line}"),
            ));
        };

        entries.push(RegScriptEntry {
            operation: RegScriptOp::SetValue,
            key_path: key_path.clone(),
            value_name: Some(val_name),
            value_type: Some(raw_type),
            data: Some(data),
            raw_bytes,
            reg_dotnet_line: line,
        });
    }

    Ok(entries)
}

fn split_quoted_assignment(after_first_quote: &str) -> Option<(String, &str)> {
    let mut name = String::new();
    let mut chars = after_first_quote.char_indices();
    while let Some((idx, ch)) = chars.next() {
        if ch == '\\' {
            name.push('\\');
            if let Some((_, esc)) = chars.next() {
                name.push(esc);
            }
        } else if ch == '"' {
            let rest = &after_first_quote[idx + 1..];
            let rhs = rest.trim_start().strip_prefix('=')?;
            return Some((name, rhs));
        } else {
            name.push(ch);
        }
    }
    None
}

fn parse_hex_bytes(hex_body: &str) -> Result<Vec<u8>, ForensicError> {
    let trimmed = hex_body.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for tok in trimmed.split(',') {
        let t = tok.trim();
        if t.is_empty() {
            continue;
        }
        let b = u8::from_str_radix(t, 16)
            .map_err(|e| ForensicError::parse("reg_script", format!("invalid hex byte '{t}': {e}")))?;
        out.push(b);
    }
    Ok(out)
}
