#![forbid(unsafe_code)]

//! Pure-Rust `[MS-XCA]` LZ77 + Huffman (`MAM\x04` / `MAM\x84`) decompressor
//! used by Windows 10/11 compressed Prefetch (`.pf`) files.

use forensics2rust_core::{ForensicError, crc32_ieee};

/// Upper bound on decompressed Prefetch size (64 MiB) to guard against OOM from corrupt headers.
pub const MAX_PREFETCH_UNCOMPRESSED: usize = 64 * 1024 * 1024;
const MIN_PREFETCH_UNCOMPRESSED: usize = 84;
const CHUNK_SIZE: usize = 65_536;
const NUM_SYMBOLS: usize = 512;
const MAX_BITS: usize = 15;
const TABLE_SIZE: usize = 1 << MAX_BITS;

/// Decompresses a `MAM\x04` or `MAM\x84` `[MS-XCA]` buffer into raw `SCCA` bytes.
pub fn decompress_mam(input: &[u8]) -> Result<Vec<u8>, ForensicError> {
    if input.len() < 8 {
        return Err(ForensicError::parse(
            "XCA",
            format!("MAM buffer too short ({} bytes; expected >= 8)", input.len()),
        ));
    }
    if &input[0..3] != b"MAM" {
        return Err(ForensicError::parse("XCA", "invalid magic; expected MAM"));
    }

    let (expected_crc, mut pos) = match input[3] {
        0x04 => (None, 8usize),
        0x84 => {
            if input.len() < 12 {
                return Err(ForensicError::parse(
                    "XCA",
                    "MAM\\x84 buffer too short for CRC32 header",
                ));
            }
            let crc = u32::from_le_bytes([input[8], input[9], input[10], input[11]]);
            (Some(crc), 12usize)
        }
        other => {
            return Err(ForensicError::parse(
                "XCA",
                format!("unsupported MAM variant byte 0x{other:02X}"),
            ));
        }
    };

    let uncompressed_size = u32::from_le_bytes([input[4], input[5], input[6], input[7]]) as usize;
    if !(MIN_PREFETCH_UNCOMPRESSED..=MAX_PREFETCH_UNCOMPRESSED).contains(&uncompressed_size) {
        return Err(ForensicError::parse(
            "XCA",
            format!(
                "uncompressed size {uncompressed_size} outside valid range [{MIN_PREFETCH_UNCOMPRESSED}, {MAX_PREFETCH_UNCOMPRESSED}]"
            ),
        ));
    }

    let mut out = Vec::with_capacity(uncompressed_size.min(1024 * 1024));

    while out.len() < uncompressed_size {
        if pos + 256 > input.len() {
            return Err(ForensicError::parse(
                "XCA",
                "unexpected EOF reading 256-byte Huffman length table",
            ));
        }

        let mut lengths = [0u8; NUM_SYMBOLS];
        let mut bl_count = [0u32; MAX_BITS + 1];
        for i in 0..256 {
            let b = input[pos + i];
            let l0 = b & 0x0F;
            let l1 = (b >> 4) & 0x0F;
            lengths[2 * i] = l0;
            lengths[2 * i + 1] = l1;
            if l0 > 0 {
                bl_count[usize::from(l0)] += 1;
            }
            if l1 > 0 {
                bl_count[usize::from(l1)] += 1;
            }
        }
        pos += 256;

        let mut kraft_sum: u32 = 0;
        for (bits, &cnt) in bl_count.iter().enumerate().skip(1) {
            kraft_sum = kraft_sum.saturating_add(cnt << (MAX_BITS - bits));
        }
        if kraft_sum > TABLE_SIZE as u32 {
            return Err(ForensicError::parse(
                "XCA",
                format!("invalid Huffman code lengths (Kraft sum {kraft_sum} > {TABLE_SIZE})"),
            ));
        }

        let mut next_code = [0u32; MAX_BITS + 1];
        let mut code = 0u32;
        for bits in 1..=MAX_BITS {
            code = (code + bl_count[bits - 1]) << 1;
            next_code[bits] = code;
        }

        let mut table_sym = vec![0u16; TABLE_SIZE];
        let mut table_len = vec![0u8; TABLE_SIZE];

        for (sym, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let len_usize = usize::from(len);
            let sym_code = next_code[len_usize];
            next_code[len_usize] += 1;

            let shift = MAX_BITS - len_usize;
            let base = (sym_code as usize) << shift;
            let span = 1usize << shift;
            if base + span > TABLE_SIZE {
                return Err(ForensicError::parse("XCA", "Huffman table index overflow"));
            }
            for slot in 0..span {
                table_sym[base + slot] = sym as u16;
                table_len[base + slot] = len;
            }
        }

        if pos + 4 > input.len() {
            return Err(ForensicError::parse("XCA", "unexpected EOF initializing XCA bitstream"));
        }
        let b0 = u16::from_le_bytes([input[pos], input[pos + 1]]);
        let b1 = u16::from_le_bytes([input[pos + 2], input[pos + 3]]);
        pos += 4;
        let mut bits_buf: u32 = (u32::from(b0) << 16) | u32::from(b1);
        let mut bits_avail: i32 = 32;

        let consume = |n: u8, bits_buf: &mut u32, bits_avail: &mut i32, pos: &mut usize| {
            *bits_buf = bits_buf.wrapping_shl(u32::from(n));
            *bits_avail -= i32::from(n);
            if *bits_avail < 16 {
                let w = if *pos + 2 <= input.len() {
                    let v = u16::from_le_bytes([input[*pos], input[*pos + 1]]);
                    *pos += 2;
                    v
                } else {
                    0
                };
                *bits_buf |= u32::from(w) << ((16 - *bits_avail) as u32);
                *bits_avail += 16;
            }
        };

        let block_end = out.len().saturating_add(CHUNK_SIZE).min(uncompressed_size);
        while out.len() < block_end {
            let idx = ((bits_buf >> 17) & 0x7FFF) as usize;
            let len = table_len[idx];
            if len == 0 {
                return Err(ForensicError::parse("XCA", "invalid Huffman code in bitstream"));
            }
            let sym = table_sym[idx];
            consume(len, &mut bits_buf, &mut bits_avail, &mut pos);

            if sym < 256 {
                out.push(sym as u8);
            } else {
                let m = sym - 256;
                let mut match_len = usize::from(m & 0x0F);
                let dist_bits = (m >> 4) as u8;

                if match_len == 15 {
                    if pos >= input.len() {
                        return Err(ForensicError::parse("XCA", "unexpected EOF reading 8-bit match length"));
                    }
                    let ml = input[pos];
                    pos += 1;
                    if ml == 255 {
                        if pos + 2 > input.len() {
                            return Err(ForensicError::parse(
                                "XCA",
                                "unexpected EOF reading 16-bit match length",
                            ));
                        }
                        let ml16 = u16::from_le_bytes([input[pos], input[pos + 1]]);
                        pos += 2;
                        if ml16 == 0 {
                            if pos + 4 > input.len() {
                                return Err(ForensicError::parse(
                                    "XCA",
                                    "unexpected EOF reading 32-bit match length",
                                ));
                            }
                            let ml32 = u32::from_le_bytes([input[pos], input[pos + 1], input[pos + 2], input[pos + 3]]);
                            pos += 4;
                            match_len = ml32 as usize;
                        } else {
                            match_len = usize::from(ml16);
                        }
                    } else {
                        match_len = usize::from(ml) + 15;
                    }
                }
                match_len = match_len
                    .checked_add(3)
                    .ok_or_else(|| ForensicError::parse("XCA", "match length overflow"))?;

                let offset = if dist_bits == 0 {
                    1usize
                } else {
                    let extra = (bits_buf >> (32 - u32::from(dist_bits))) & ((1u32 << dist_bits) - 1);
                    consume(dist_bits, &mut bits_buf, &mut bits_avail, &mut pos);
                    (1usize << dist_bits) + (extra as usize)
                };

                if offset == 0 || offset > out.len() {
                    return Err(ForensicError::parse(
                        "XCA",
                        format!(
                            "invalid LZ77 back-reference offset {offset} at output position {}",
                            out.len()
                        ),
                    ));
                }
                if out.len().saturating_add(match_len) > uncompressed_size {
                    return Err(ForensicError::parse(
                        "XCA",
                        format!(
                            "LZ77 match length {match_len} exceeds uncompressed size {uncompressed_size} at {}",
                            out.len()
                        ),
                    ));
                }

                for _ in 0..match_len {
                    let b = out[out.len() - offset];
                    out.push(b);
                }
            }
        }
    }

    if let Some(expected) = expected_crc
        && expected != 0
    {
        let actual = crc32_ieee(&out);
        if actual != expected {
            return Err(ForensicError::parse(
                "XCA",
                format!("MAM\\x84 CRC32 mismatch: expected 0x{expected:08X}, got 0x{actual:08X}"),
            ));
        }
    }

    Ok(out)
}

#[cfg(test)]
pub(crate) mod test_encoder {
    use forensics2rust_core::crc32_ieee;

    /// Encodes arbitrary bytes into a valid `MAM\x04` `[MS-XCA]` stream using a uniform 9-bit
    /// canonical Huffman tree (`512 * 2^6 = 32768`) and optional greedy RLE/LZ77 matches so
    /// tests can exercise literals, short matches, `ml16`, `ml32`, and multi-chunk boundaries.
    pub fn compress_mam_xca(raw: &[u8], with_crc_variant: bool, enable_matches: bool) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(if with_crc_variant { b"MAM\x84" } else { b"MAM\x04" });
        out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        if with_crc_variant {
            out.extend_from_slice(&crc32_ieee(raw).to_le_bytes());
        }

        let mut offset = 0usize;
        while offset < raw.len() {
            let chunk_end = (offset + 65_536).min(raw.len());
            // Uniform 9-bit code length for all 512 symbols: code(sym) = sym in 9 bits.
            out.extend(std::iter::repeat_n(0x99u8, 256));

            let mut writer = XcaBitWriter::new();
            let mut pos = offset;
            while pos < chunk_end {
                if enable_matches && pos > offset {
                    // Check RLE repeat at offset=1 first (exercises overlapping copy + ml16/ml32!)
                    let prev = raw[pos - 1];
                    let mut rle_len = 0usize;
                    while pos + rle_len < chunk_end && raw[pos + rle_len] == prev {
                        rle_len += 1;
                    }
                    if rle_len >= 3 {
                        let enc_len = rle_len - 3;
                        let len_nibble = enc_len.min(15) as u16;
                        let sym = 256u16 + len_nibble; // dist_bits = 0 => offset = 1
                        writer.write_bits(u32::from(sym), 9);
                        if enc_len >= 15 {
                            if enc_len < 255 + 15 {
                                writer.write_byte((enc_len - 15) as u8);
                            } else if enc_len <= u16::MAX as usize {
                                writer.write_byte(255);
                                writer.write_u16(enc_len as u16);
                            } else {
                                writer.write_byte(255);
                                writer.write_u16(0);
                                writer.write_u32(enc_len as u32);
                            }
                        }
                        pos += rle_len;
                        continue;
                    }
                }
                writer.write_bits(u32::from(raw[pos]), 9);
                pos += 1;
            }
            out.extend_from_slice(&writer.finish());
            offset = chunk_end;
        }

        out
    }

    enum XcaToken {
        Bits(u32, u8),
        Byte(u8),
    }

    struct XcaBitWriter {
        tokens: Vec<XcaToken>,
    }

    impl XcaBitWriter {
        fn new() -> Self {
            Self { tokens: Vec::new() }
        }

        fn write_bits(&mut self, val: u32, nbits: u8) {
            self.tokens.push(XcaToken::Bits(val, nbits));
        }

        fn write_byte(&mut self, b: u8) {
            self.tokens.push(XcaToken::Byte(b));
        }

        fn write_u16(&mut self, v: u16) {
            for b in v.to_le_bytes() {
                self.write_byte(b);
            }
        }

        fn write_u32(&mut self, v: u32) {
            for b in v.to_le_bytes() {
                self.write_byte(b);
            }
        }

        fn finish(self) -> Vec<u8> {
            // Pack all bit tokens into 16-bit LE words first.
            let mut words: Vec<u16> = Vec::new();
            let mut bit_buf: u32 = 0;
            let mut bits_used: u8 = 0;
            for tok in &self.tokens {
                if let XcaToken::Bits(val, nbits) = *tok {
                    let masked = val & ((1u32 << nbits) - 1);
                    bit_buf |= masked << (32 - bits_used - nbits);
                    bits_used += nbits;
                    while bits_used >= 16 {
                        words.push((bit_buf >> 16) as u16);
                        bit_buf <<= 16;
                        bits_used -= 16;
                    }
                }
            }
            if bits_used > 0 {
                words.push((bit_buf >> 16) as u16);
            }
            while words.len() < 2 {
                words.push(0);
            }

            // Replay tokens using the exact decoder refill schedule.
            let mut out = Vec::new();
            out.extend_from_slice(&words[0].to_le_bytes());
            out.extend_from_slice(&words[1].to_le_bytes());
            let mut next_word = 2usize;
            let mut bits_avail: i32 = 32;

            for tok in self.tokens {
                match tok {
                    XcaToken::Bits(_, nbits) => {
                        bits_avail -= i32::from(nbits);
                        if bits_avail < 16 {
                            let w = words.get(next_word).copied().unwrap_or(0);
                            next_word += 1;
                            out.extend_from_slice(&w.to_le_bytes());
                            bits_avail += 16;
                        }
                    }
                    XcaToken::Byte(b) => out.push(b),
                }
            }
            out
        }
    }
}
