use forensics2rust_core::{DiagnosticWarning, ForensicError, WarningSeverity};

const MAX_DECOMPRESSED_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecompressOutcome {
    Decompressed { bytes: Vec<u8>, is_utf16_expanded: bool },
    Unsupported { flag: u8 },
}

/// Decodes pure-Rust ESE compressed values:
/// - `0x01`: uncompressed wrapper byte (incompressible payload in compressed column)
/// - `0x08..=0x0F`: 7-bit ASCII
/// - `0x10..=0x17`: 7-bit Unicode (expanded to UTF-16LE `[b, 0x00]`)
/// - `0x18..=0x1F`: `[MS-XCA]` §2.3 Plain LZ77 XPRESS
/// - `0x38..=0x3F`: ESENT LZ4 block (`u16` LE uncompressed length prefix)
pub fn decompress_ese_value(
    data: &[u8],
    warnings: &mut Vec<DiagnosticWarning>,
) -> Result<DecompressOutcome, ForensicError> {
    let Some(&hdr) = data.first() else {
        return Ok(DecompressOutcome::Decompressed {
            bytes: Vec::new(),
            is_utf16_expanded: false,
        });
    };

    if hdr == 0x01 {
        return Ok(DecompressOutcome::Decompressed {
            bytes: data[1..].to_vec(),
            is_utf16_expanded: false,
        });
    }

    match hdr & 0xF8 {
        0x08 => Ok(DecompressOutcome::Decompressed {
            bytes: decompress_7bit_ascii_with_options(&data[1..], (hdr & 0x07) == 7),
            is_utf16_expanded: false,
        }),
        0x10 => {
            let ascii = decompress_7bit_ascii_with_options(&data[1..], (hdr & 0x07) == 7);
            let mut utf16 = Vec::with_capacity(ascii.len() * 2);
            for b in ascii {
                utf16.push(b);
                utf16.push(0x00);
            }
            Ok(DecompressOutcome::Decompressed {
                bytes: utf16,
                is_utf16_expanded: true,
            })
        }
        0x18 => {
            let bytes = decompress_xpress_lz77(&data[1..])?;
            Ok(DecompressOutcome::Decompressed {
                bytes,
                is_utf16_expanded: false,
            })
        }
        0x38 => {
            let bytes = decompress_esent_lz4(&data[1..])?;
            Ok(DecompressOutcome::Decompressed {
                bytes,
                is_utf16_expanded: false,
            })
        }
        _ => {
            warnings.push(DiagnosticWarning {
                severity: WarningSeverity::Warn,
                tool_id: "srum.db".to_string(),
                source: "ESE decompress".to_string(),
                message: format!("unsupported ESE compression flag 0x{hdr:02X}; preserving raw binary"),
            });
            Ok(DecompressOutcome::Unsupported { flag: hdr })
        }
    }
}

/// Returns `true` if `hdr` is a recognized ESENT compression scheme byte (`0x01`, `0x08..=0x1F`, `0x38..=0x3F`).
pub fn is_known_ese_compression_header(hdr: u8) -> bool {
    hdr == 0x01 || matches!(hdr & 0xF8, 0x08 | 0x10 | 0x18 | 0x38)
}

pub fn decompress_7bit_ascii(payload: &[u8]) -> Vec<u8> {
    decompress_7bit_ascii_with_options(payload, false)
}

fn decompress_7bit_ascii_with_options(payload: &[u8], keep_trailing_nul: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity((payload.len() * 8) / 7 + 1);
    let mut bit_buf: u32 = 0;
    let mut bit_len: u8 = 0;
    let last_idx = payload.len().saturating_sub(1);

    for (idx, &byte) in payload.iter().enumerate() {
        bit_buf |= u32::from(byte) << bit_len;
        bit_len += 8;
        let is_last = idx == last_idx;
        while bit_len >= 7 {
            let ch = (bit_buf & 0x7F) as u8;
            bit_buf >>= 7;
            bit_len -= 7;
            if !keep_trailing_nul && is_last && bit_len == 0 && ch == 0 {
                break;
            }
            out.push(ch);
        }
    }
    out
}

/// `[MS-XCA]` §2.3 Plain LZ77 XPRESS decompression (`u16` LE uncompressed length prefix).
pub fn decompress_xpress_lz77(payload: &[u8]) -> Result<Vec<u8>, ForensicError> {
    if payload.len() < 2 {
        return Err(ForensicError::parse(
            "ESE XPRESS",
            "compressed buffer too short for uncompressed size header",
        ));
    }

    let uncompressed_size = u16::from_le_bytes([payload[0], payload[1]]) as usize;
    if uncompressed_size > MAX_DECOMPRESSED_BYTES {
        return Err(ForensicError::parse(
            "ESE XPRESS",
            format!("uncompressed size {uncompressed_size} exceeds safety cap"),
        ));
    }
    let src = &payload[2..];
    if uncompressed_size == 0 {
        if !src.is_empty() {
            return Err(ForensicError::parse(
                "ESE XPRESS",
                "zero uncompressed size with trailing payload bytes",
            ));
        }
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(uncompressed_size);
    let mut pos: usize = 0;
    let mut flags: u32 = 0;
    let mut flag_bits: u8 = 0;
    let mut nibble_pos: Option<usize> = None;

    while out.len() < uncompressed_size {
        if flag_bits == 0 {
            if pos + 4 > src.len() {
                return Err(ForensicError::parse("ESE XPRESS", "truncated XPRESS flag dword"));
            }
            flags = u32::from_le_bytes([src[pos], src[pos + 1], src[pos + 2], src[pos + 3]]);
            pos += 4;
            flag_bits = 32;
        }

        let is_match = (flags & 0x8000_0000) != 0;
        flags <<= 1;
        flag_bits -= 1;

        if !is_match {
            if pos >= src.len() {
                return Err(ForensicError::parse("ESE XPRESS", "truncated literal byte"));
            }
            out.push(src[pos]);
            pos += 1;
        } else {
            if pos + 2 > src.len() {
                return Err(ForensicError::parse("ESE XPRESS", "truncated match token"));
            }
            let tok = u16::from_le_bytes([src[pos], src[pos + 1]]);
            pos += 2;
            let offset = ((tok >> 3) as usize) + 1;
            let mut len = (tok & 0x07) as usize;

            if len == 7 {
                let nibble = if let Some(npos) = nibble_pos.take() {
                    (src[npos] >> 4) & 0x0F
                } else {
                    if pos >= src.len() {
                        return Err(ForensicError::parse("ESE XPRESS", "truncated length nibble"));
                    }
                    let b = src[pos];
                    nibble_pos = Some(pos);
                    pos += 1;
                    b & 0x0F
                };
                len += nibble as usize;

                if nibble == 15 {
                    if pos >= src.len() {
                        return Err(ForensicError::parse("ESE XPRESS", "truncated extended length byte"));
                    }
                    let b = src[pos] as usize;
                    pos += 1;
                    if b == 255 {
                        if pos + 2 > src.len() {
                            return Err(ForensicError::parse("ESE XPRESS", "truncated 16-bit length"));
                        }
                        let ext16 = u16::from_le_bytes([src[pos], src[pos + 1]]) as usize;
                        pos += 2;
                        let ext = if ext16 == 0 {
                            if pos + 4 > src.len() {
                                return Err(ForensicError::parse("ESE XPRESS", "truncated 32-bit length"));
                            }
                            let ext32 =
                                u32::from_le_bytes([src[pos], src[pos + 1], src[pos + 2], src[pos + 3]]) as usize;
                            pos += 4;
                            ext32
                        } else {
                            ext16
                        };
                        if ext < 22 {
                            return Err(ForensicError::parse(
                                "ESE XPRESS",
                                "invalid extended XPRESS match length",
                            ));
                        }
                        len = ext;
                    } else {
                        len += b;
                    }
                }
            }

            len += 3;
            if offset == 0 || offset > out.len() {
                return Err(ForensicError::parse(
                    "ESE XPRESS",
                    format!(
                        "invalid XPRESS back-reference offset {offset} at output len {}",
                        out.len()
                    ),
                ));
            }
            let remaining = uncompressed_size - out.len();
            let copy_len = len.min(remaining);
            for _ in 0..copy_len {
                let b = out[out.len() - offset];
                out.push(b);
            }
        }
    }

    Ok(out)
}

/// ESENT `0x38` LZ4 block decompression (`u16` LE uncompressed length prefix + raw LZ4 block).
pub fn decompress_esent_lz4(payload: &[u8]) -> Result<Vec<u8>, ForensicError> {
    if payload.len() < 2 {
        return Err(ForensicError::parse(
            "ESE LZ4",
            "compressed buffer too short for uncompressed size header",
        ));
    }

    let uncompressed_size = u16::from_le_bytes([payload[0], payload[1]]) as usize;
    if uncompressed_size > MAX_DECOMPRESSED_BYTES {
        return Err(ForensicError::parse(
            "ESE LZ4",
            format!("uncompressed size {uncompressed_size} exceeds safety cap"),
        ));
    }
    let src = &payload[2..];
    if uncompressed_size == 0 {
        if !src.is_empty() {
            return Err(ForensicError::parse(
                "ESE LZ4",
                "zero uncompressed size with trailing payload bytes",
            ));
        }
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(uncompressed_size);
    let mut pos: usize = 0;

    while pos < src.len() && out.len() < uncompressed_size {
        let token = src[pos];
        pos += 1;

        let mut lit_len = (token >> 4) as usize;
        if lit_len == 15 {
            loop {
                if pos >= src.len() {
                    return Err(ForensicError::parse("ESE LZ4", "truncated LZ4 literal length"));
                }
                let extra = src[pos] as usize;
                pos += 1;
                lit_len = lit_len
                    .checked_add(extra)
                    .ok_or_else(|| ForensicError::parse("ESE LZ4", "LZ4 literal length overflow"))?;
                if lit_len > uncompressed_size - out.len() {
                    return Err(ForensicError::parse(
                        "ESE LZ4",
                        "LZ4 literal length exceeds uncompressed size",
                    ));
                }
                if extra != 255 {
                    break;
                }
            }
        }

        if lit_len > uncompressed_size - out.len() {
            return Err(ForensicError::parse(
                "ESE LZ4",
                "LZ4 literal output exceeds uncompressed size",
            ));
        }
        let lit_end = pos
            .checked_add(lit_len)
            .ok_or_else(|| ForensicError::parse("ESE LZ4", "LZ4 literal end overflow"))?;
        if lit_end > src.len() {
            return Err(ForensicError::parse("ESE LZ4", "truncated LZ4 literal bytes"));
        }
        out.extend_from_slice(&src[pos..lit_end]);
        pos = lit_end;

        if pos == src.len() || out.len() == uncompressed_size {
            break;
        }

        if pos + 2 > src.len() {
            return Err(ForensicError::parse("ESE LZ4", "truncated LZ4 match offset"));
        }
        let offset = u16::from_le_bytes([src[pos], src[pos + 1]]) as usize;
        pos += 2;

        if offset == 0 || offset > out.len() {
            return Err(ForensicError::parse(
                "ESE LZ4",
                format!("invalid LZ4 back-reference offset {offset} at output len {}", out.len()),
            ));
        }

        let mut match_len = ((token & 0x0F) as usize) + 4;
        if (token & 0x0F) == 15 {
            loop {
                if pos >= src.len() {
                    return Err(ForensicError::parse("ESE LZ4", "truncated LZ4 match length"));
                }
                let extra = src[pos] as usize;
                pos += 1;
                match_len = match_len
                    .checked_add(extra)
                    .ok_or_else(|| ForensicError::parse("ESE LZ4", "LZ4 match length overflow"))?;
                if match_len > uncompressed_size - out.len() {
                    return Err(ForensicError::parse(
                        "ESE LZ4",
                        "LZ4 match length exceeds uncompressed size",
                    ));
                }
                if extra != 255 {
                    break;
                }
            }
        }

        if match_len > uncompressed_size - out.len() {
            return Err(ForensicError::parse(
                "ESE LZ4",
                "LZ4 match output exceeds uncompressed size",
            ));
        }

        for _ in 0..match_len {
            let b = out[out.len() - offset];
            out.push(b);
        }
    }

    if out.len() != uncompressed_size {
        return Err(ForensicError::parse(
            "ESE LZ4",
            format!(
                "LZ4 decompressed length {} does not match header uncompressed length {uncompressed_size}",
                out.len()
            ),
        ));
    }

    Ok(out)
}
