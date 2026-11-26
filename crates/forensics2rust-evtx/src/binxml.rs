use std::collections::HashMap;
use std::fmt::Write as _;

use chrono::{DateTime, NaiveDate, Utc};
use forensics2rust_core::{
    ForensicError, bytes_to_hex_lower, filetime_to_utc, parse_guid_le_braced, parse_sid, read_utf16_le,
};

const MAX_BINXML_DEPTH: usize = 32;
const MAX_BINXML_NODES: usize = 65_536;
const MAX_CHUNK_CACHED_NODES: usize = 262_144;
const MAX_BINXML_BYTES: usize = 16 * 1024 * 1024;
const MAX_CHUNK_CACHED_BYTES: usize = 64 * 1024 * 1024;
const CHUNK_HEADER_END: usize = 0x200;

#[derive(Debug, Clone)]
struct CachedTemplate {
    nodes: Vec<AstNode>,
    max_depth: usize,
    node_count: usize,
    byte_size: usize,
}

#[derive(Debug, Clone, Copy)]
struct BinXmlBudget {
    nodes_used: usize,
    node_limit: usize,
    bytes_used: usize,
    byte_limit: usize,
}

impl BinXmlBudget {
    fn new(node_limit: usize, byte_limit: usize) -> Self {
        Self {
            nodes_used: 0,
            node_limit,
            bytes_used: 0,
            byte_limit,
        }
    }

    fn remaining_bytes(&self) -> usize {
        self.byte_limit.saturating_sub(self.bytes_used)
    }

    fn consume_nodes(&mut self, count: usize) -> Result<(), ForensicError> {
        let next = self
            .nodes_used
            .checked_add(count)
            .ok_or_else(|| ForensicError::parse("BinXML", "BinXML node budget overflow"))?;
        if next > self.node_limit {
            return Err(ForensicError::parse(
                "BinXML",
                format!("BinXML node count exceeded {}", self.node_limit),
            ));
        }
        self.nodes_used = next;
        Ok(())
    }

    fn consume_bytes(&mut self, bytes: usize) -> Result<(), ForensicError> {
        let next = self
            .bytes_used
            .checked_add(bytes)
            .ok_or_else(|| ForensicError::parse("BinXML", "BinXML byte budget overflow"))?;
        if next > self.byte_limit {
            return Err(ForensicError::parse(
                "BinXML",
                format!("BinXML byte budget exceeded {}", self.byte_limit),
            ));
        }
        self.bytes_used = next;
        Ok(())
    }

    fn consume(&mut self, nodes: usize, bytes: usize) -> Result<(), ForensicError> {
        let next_nodes = self
            .nodes_used
            .checked_add(nodes)
            .ok_or_else(|| ForensicError::parse("BinXML", "BinXML node budget overflow"))?;
        if next_nodes > self.node_limit {
            return Err(ForensicError::parse(
                "BinXML",
                format!("BinXML node count exceeded {}", self.node_limit),
            ));
        }
        let next_bytes = self
            .bytes_used
            .checked_add(bytes)
            .ok_or_else(|| ForensicError::parse("BinXML", "BinXML byte budget overflow"))?;
        if next_bytes > self.byte_limit {
            return Err(ForensicError::parse(
                "BinXML",
                format!("BinXML byte budget exceeded {}", self.byte_limit),
            ));
        }
        self.nodes_used = next_nodes;
        self.bytes_used = next_bytes;
        Ok(())
    }
}

/// Cached chunk-local `Name` strings and `TemplateDefinition` ASTs.
#[derive(Debug, Default)]
pub(crate) struct ChunkCache {
    names: HashMap<u32, String>,
    templates: HashMap<u32, CachedTemplate>,
    total_cached_nodes: usize,
    total_cached_bytes: usize,
}

#[derive(Debug, Clone)]
enum AstNode {
    Element {
        name: String,
        dependency_id: u16,
        attributes: Vec<(String, Vec<AstFrag>)>,
        children: Vec<AstNode>,
    },
    Frag(AstFrag),
    SubTemplate {
        nodes: Vec<AstNode>,
        subs: Vec<BinXmlValue>,
    },
}

#[derive(Debug, Clone)]
enum AstFrag {
    Text(String),
    CData(String),
    Sub { id: u16, optional: bool },
}

#[derive(Debug, Clone)]
enum BinXmlValue {
    Null,
    Scalar(String),
    Array(Vec<String>),
    XmlNodes(Vec<XmlNode>),
}

impl BinXmlValue {
    fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

#[derive(Debug, Clone)]
enum XmlNode {
    Element {
        name: String,
        attributes: Vec<(String, String)>,
        children: Vec<XmlNode>,
    },
    Text(String),
    CData(String),
}

impl XmlNode {
    fn write_xml(&self, out: &mut String, depth: usize, max_bytes: usize) -> Result<(), ForensicError> {
        if depth >= MAX_BINXML_DEPTH {
            return Err(ForensicError::parse(
                "BinXML",
                format!("BinXML XML serialization depth exceeded {MAX_BINXML_DEPTH}"),
            ));
        }
        match self {
            Self::Text(t) => push_xml_text(out, t, max_bytes)?,
            Self::CData(c) => {
                push_bounded_str(out, "<![CDATA[", max_bytes)?;
                let mut rest = c.as_str();
                while let Some(idx) = rest.find("]]>") {
                    push_bounded_str(out, &rest[..idx], max_bytes)?;
                    push_bounded_str(out, "]]]]><![CDATA[>", max_bytes)?;
                    rest = &rest[idx + 3..];
                }
                push_bounded_str(out, rest, max_bytes)?;
                push_bounded_str(out, "]]>", max_bytes)?;
            }
            Self::Element {
                name,
                attributes,
                children,
            } => {
                push_bounded_str(out, "<", max_bytes)?;
                push_bounded_str(out, name, max_bytes)?;
                for (k, v) in attributes {
                    push_bounded_str(out, " ", max_bytes)?;
                    push_bounded_str(out, k, max_bytes)?;
                    push_bounded_str(out, "=\"", max_bytes)?;
                    push_xml_attr(out, v, max_bytes)?;
                    push_bounded_str(out, "\"", max_bytes)?;
                }
                if children.is_empty() {
                    push_bounded_str(out, "/>", max_bytes)?;
                } else {
                    push_bounded_str(out, ">", max_bytes)?;
                    for child in children {
                        child.write_xml(out, depth + 1, max_bytes)?;
                    }
                    push_bounded_str(out, "</", max_bytes)?;
                    push_bounded_str(out, name, max_bytes)?;
                    push_bounded_str(out, ">", max_bytes)?;
                }
            }
        }
        Ok(())
    }
}

fn push_bounded_str(out: &mut String, s: &str, max_bytes: usize) -> Result<(), ForensicError> {
    let next = out
        .len()
        .checked_add(s.len())
        .ok_or_else(|| ForensicError::parse("BinXML", "BinXML XML output size overflow"))?;
    if next > max_bytes {
        return Err(ForensicError::parse(
            "BinXML",
            format!("BinXML XML output exceeded {max_bytes} bytes"),
        ));
    }
    out.push_str(s);
    Ok(())
}

fn push_xml_text(out: &mut String, s: &str, max_bytes: usize) -> Result<(), ForensicError> {
    for ch in s.chars() {
        match ch {
            '&' => push_bounded_str(out, "&amp;", max_bytes)?,
            '<' => push_bounded_str(out, "&lt;", max_bytes)?,
            '>' => push_bounded_str(out, "&gt;", max_bytes)?,
            _ => {
                let next = out
                    .len()
                    .checked_add(ch.len_utf8())
                    .ok_or_else(|| ForensicError::parse("BinXML", "BinXML XML output size overflow"))?;
                if next > max_bytes {
                    return Err(ForensicError::parse(
                        "BinXML",
                        format!("BinXML XML output exceeded {max_bytes} bytes"),
                    ));
                }
                out.push(ch);
            }
        }
    }
    Ok(())
}

fn push_xml_attr(out: &mut String, s: &str, max_bytes: usize) -> Result<(), ForensicError> {
    for ch in s.chars() {
        match ch {
            '&' => push_bounded_str(out, "&amp;", max_bytes)?,
            '<' => push_bounded_str(out, "&lt;", max_bytes)?,
            '>' => push_bounded_str(out, "&gt;", max_bytes)?,
            '"' => push_bounded_str(out, "&quot;", max_bytes)?,
            '\'' => push_bounded_str(out, "&apos;", max_bytes)?,
            _ => {
                let next = out
                    .len()
                    .checked_add(ch.len_utf8())
                    .ok_or_else(|| ForensicError::parse("BinXML", "BinXML XML output size overflow"))?;
                if next > max_bytes {
                    return Err(ForensicError::parse(
                        "BinXML",
                        format!("BinXML XML output exceeded {max_bytes} bytes"),
                    ));
                }
                out.push(ch);
            }
        }
    }
    Ok(())
}

/// Decodes a BinXML payload at `chunk[start..end]` (chunk-relative offsets) into
/// a well-formed UTF-8 XML string.
pub(crate) fn decode_binxml_to_xml(
    chunk: &[u8],
    start: usize,
    end: usize,
    cache: &mut ChunkCache,
) -> Result<String, ForensicError> {
    let mut parse_budget = BinXmlBudget::new(MAX_BINXML_NODES, MAX_BINXML_BYTES);
    let mut inst_budget = BinXmlBudget::new(MAX_BINXML_NODES, MAX_BINXML_BYTES);
    let (nodes, _) = decode_fragment_nodes(chunk, start, end, cache, 0, &mut parse_budget, &mut inst_budget)?;
    let mut xml = String::with_capacity(512);
    for node in &nodes {
        node.write_xml(&mut xml, 0, MAX_BINXML_BYTES)?;
    }
    Ok(xml)
}

fn decode_fragment_nodes(
    chunk: &[u8],
    start: usize,
    end: usize,
    cache: &mut ChunkCache,
    depth: usize,
    parse_budget: &mut BinXmlBudget,
    inst_budget: &mut BinXmlBudget,
) -> Result<(Vec<XmlNode>, usize), ForensicError> {
    if depth >= MAX_BINXML_DEPTH {
        return Err(ForensicError::parse(
            "BinXML",
            format!("BinXML nesting depth exceeded {MAX_BINXML_DEPTH}"),
        ));
    }
    let mut cursor = start;
    let (ast, max_depth_reached) =
        parse_ast_fragment(chunk, &mut cursor, end, cache, depth, parse_budget, inst_budget)?;
    let nodes = instantiate_ast(&ast, &[], depth, inst_budget)?;
    Ok((nodes, max_depth_reached))
}

#[derive(Debug, Clone, Copy, Default)]
struct AstMeasurement {
    node_count: usize,
    byte_size: usize,
}

impl AstMeasurement {
    fn add(&mut self, other: Self) {
        self.node_count = self.node_count.saturating_add(other.node_count);
        self.byte_size = self.byte_size.saturating_add(other.byte_size);
    }
}

fn array_rendered_len(items: &[String]) -> usize {
    if items.is_empty() {
        0
    } else {
        let sum: usize = items.iter().map(String::len).sum();
        sum.saturating_add(items.len().saturating_sub(1).saturating_mul(2))
    }
}

fn measure_binxml_value(val: &BinXmlValue) -> AstMeasurement {
    match val {
        BinXmlValue::Null => AstMeasurement {
            node_count: 1,
            byte_size: std::mem::size_of::<BinXmlValue>(),
        },
        BinXmlValue::Scalar(s) => AstMeasurement {
            node_count: 1,
            byte_size: s.len(),
        },
        BinXmlValue::Array(items) => {
            let str_bytes: usize = items.iter().map(String::len).sum();
            AstMeasurement {
                node_count: items.len().max(1),
                byte_size: str_bytes.saturating_add(items.len()),
            }
        }
        BinXmlValue::XmlNodes(xml_nodes) => measure_xml_nodes(xml_nodes),
    }
}

fn measure_ast(nodes: &[AstNode]) -> AstMeasurement {
    let mut total = AstMeasurement::default();
    let mut stack: Vec<&AstNode> = nodes.iter().collect();
    while let Some(node) = stack.pop() {
        total.node_count = total.node_count.saturating_add(1);
        match node {
            AstNode::Frag(frag) => match frag {
                AstFrag::Text(s) | AstFrag::CData(s) => {
                    total.byte_size = total.byte_size.saturating_add(s.len());
                }
                AstFrag::Sub { .. } => {}
            },
            AstNode::Element {
                name,
                attributes,
                children,
                ..
            } => {
                total.byte_size = total.byte_size.saturating_add(name.len());
                for (attr_name, frags) in attributes {
                    total.byte_size = total.byte_size.saturating_add(attr_name.len());
                    total.node_count = total.node_count.saturating_add(1 + frags.len());
                    for frag in frags {
                        if let AstFrag::Text(s) | AstFrag::CData(s) = frag {
                            total.byte_size = total.byte_size.saturating_add(s.len());
                        }
                    }
                }
                stack.extend(children.iter());
            }
            AstNode::SubTemplate { nodes: inner, subs } => {
                stack.extend(inner.iter());
                for sub in subs {
                    total.add(measure_binxml_value(sub));
                }
            }
        }
    }
    total
}

fn measure_xml_nodes(nodes: &[XmlNode]) -> AstMeasurement {
    let mut total = AstMeasurement::default();
    let mut stack: Vec<&XmlNode> = nodes.iter().collect();
    while let Some(node) = stack.pop() {
        total.node_count = total.node_count.saturating_add(1);
        match node {
            XmlNode::Text(s) | XmlNode::CData(s) => {
                total.byte_size = total.byte_size.saturating_add(s.len());
            }
            XmlNode::Element {
                name,
                attributes,
                children,
            } => {
                total.byte_size = total.byte_size.saturating_add(name.len());
                for (k, v) in attributes {
                    total.byte_size = total.byte_size.saturating_add(k.len()).saturating_add(v.len());
                }
                stack.extend(children.iter());
            }
        }
    }
    total
}

fn xml_nodes_max_rel_depth(nodes: &[XmlNode]) -> usize {
    let mut max_rel = 0usize;
    let mut stack: Vec<(&XmlNode, usize)> = nodes.iter().map(|n| (n, 0)).collect();
    while let Some((node, rel)) = stack.pop() {
        max_rel = max_rel.max(rel);
        if let XmlNode::Element { children, .. } = node {
            for child in children {
                stack.push((child, rel + 1));
            }
        }
    }
    max_rel
}

fn instantiate_ast(
    ast: &[AstNode],
    subs: &[BinXmlValue],
    depth: usize,
    budget: &mut BinXmlBudget,
) -> Result<Vec<XmlNode>, ForensicError> {
    if depth >= MAX_BINXML_DEPTH {
        return Err(ForensicError::parse(
            "BinXML",
            format!("BinXML template instantiation depth exceeded {MAX_BINXML_DEPTH}"),
        ));
    }
    let mut out = Vec::new();
    for node in ast {
        match node {
            AstNode::Frag(frag) => match frag {
                AstFrag::Text(t) => {
                    budget.consume(1, t.len())?;
                    out.push(XmlNode::Text(t.clone()));
                }
                AstFrag::CData(c) => {
                    budget.consume(1, c.len())?;
                    out.push(XmlNode::CData(c.clone()));
                }
                AstFrag::Sub { id, optional } => {
                    if let Some(val) = subs.get(usize::from(*id)) {
                        match val {
                            BinXmlValue::Null => {
                                if !optional {
                                    // Omitted / empty
                                }
                            }
                            BinXmlValue::XmlNodes(children) => {
                                if !children.is_empty()
                                    && depth.saturating_add(xml_nodes_max_rel_depth(children)) >= MAX_BINXML_DEPTH
                                {
                                    return Err(ForensicError::parse(
                                        "BinXML",
                                        format!("BinXML substituted XML depth exceeded {MAX_BINXML_DEPTH}"),
                                    ));
                                }
                                let meas = measure_xml_nodes(children);
                                budget.consume(meas.node_count, meas.byte_size)?;
                                out.extend(children.iter().cloned());
                            }
                            BinXmlValue::Scalar(s) => {
                                budget.consume(1, s.len())?;
                                out.push(XmlNode::Text(s.clone()));
                            }
                            BinXmlValue::Array(items) => {
                                let rendered_bytes = array_rendered_len(items);
                                budget.consume(items.len().max(1), rendered_bytes)?;
                                out.push(XmlNode::Text(items.join("; ")));
                            }
                        }
                    }
                }
            },
            AstNode::Element {
                name,
                dependency_id,
                attributes,
                children,
            } => {
                if *dependency_id != 0xFFFF
                    && matches!(subs.get(usize::from(*dependency_id)), None | Some(BinXmlValue::Null))
                {
                    continue;
                }
                let mut rendered_attrs = Vec::new();
                for (attr_name, frags) in attributes {
                    budget.consume(1, attr_name.len())?;
                    if let Some(val) = eval_attr_frags(frags, subs, depth, budget)? {
                        rendered_attrs.push((attr_name.clone(), val));
                    }
                }
                let rendered_children = if children.is_empty() {
                    Vec::new()
                } else {
                    instantiate_ast(children, subs, depth + 1, budget)?
                };
                budget.consume(1, name.len())?;
                out.push(XmlNode::Element {
                    name: name.clone(),
                    attributes: rendered_attrs,
                    children: rendered_children,
                });
            }
            AstNode::SubTemplate {
                nodes,
                subs: inner_subs,
            } => {
                if !nodes.is_empty() {
                    out.extend(instantiate_ast(nodes, inner_subs, depth + 1, budget)?);
                }
            }
        }
    }
    Ok(out)
}

fn eval_attr_frags(
    frags: &[AstFrag],
    subs: &[BinXmlValue],
    depth: usize,
    budget: &mut BinXmlBudget,
) -> Result<Option<String>, ForensicError> {
    let mut buf = String::new();
    let mut has_literal_or_present_sub = false;
    let mut had_any_sub = false;

    for frag in frags {
        match frag {
            AstFrag::Text(t) | AstFrag::CData(t) => {
                budget.consume(1, t.len())?;
                buf.push_str(t);
                has_literal_or_present_sub = true;
            }
            AstFrag::Sub { id, optional } => {
                had_any_sub = true;
                match subs.get(usize::from(*id)) {
                    Some(val) if !val.is_null() => match val {
                        BinXmlValue::Null => {}
                        BinXmlValue::Scalar(s) => {
                            budget.consume(1, s.len())?;
                            buf.push_str(s);
                            has_literal_or_present_sub = true;
                        }
                        BinXmlValue::Array(items) => {
                            let rendered_bytes = array_rendered_len(items);
                            budget.consume(items.len().max(1), rendered_bytes)?;
                            for (idx, item) in items.iter().enumerate() {
                                if idx > 0 {
                                    buf.push_str("; ");
                                }
                                buf.push_str(item);
                            }
                            has_literal_or_present_sub = true;
                        }
                        BinXmlValue::XmlNodes(xml_nodes) => {
                            let meas = measure_xml_nodes(xml_nodes);
                            budget.consume_nodes(meas.node_count)?;
                            if meas.byte_size > budget.remaining_bytes() {
                                return Err(ForensicError::parse(
                                    "BinXML",
                                    format!("BinXML byte budget exceeded {}", budget.byte_limit),
                                ));
                            }
                            let start_len = buf.len();
                            let max_out = start_len.saturating_add(budget.remaining_bytes());
                            for n in xml_nodes {
                                n.write_xml(&mut buf, depth, max_out)?;
                            }
                            let written = buf.len().saturating_sub(start_len);
                            budget.consume_bytes(written.max(meas.byte_size))?;
                            has_literal_or_present_sub = true;
                        }
                    },
                    _ if *optional => {}
                    _ => {}
                }
            }
        }
    }

    if had_any_sub && !has_literal_or_present_sub {
        Ok(None)
    } else {
        Ok(Some(buf))
    }
}

struct Cursor<'a> {
    chunk: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> Cursor<'a> {
    fn new(chunk: &'a [u8], pos: usize, end: usize) -> Result<Self, ForensicError> {
        if end > chunk.len() || pos > end {
            return Err(ForensicError::parse(
                "BinXML",
                format!("invalid BinXML bounds [{pos}..{end}] for chunk len {}", chunk.len()),
            ));
        }
        Ok(Self { chunk, pos, end })
    }

    fn remaining(&self) -> usize {
        self.end.saturating_sub(self.pos)
    }

    fn peek_u8(&self) -> Option<u8> {
        if self.pos < self.end {
            Some(self.chunk[self.pos])
        } else {
            None
        }
    }

    fn read_u8(&mut self) -> Result<u8, ForensicError> {
        if self.pos >= self.end {
            return Err(ForensicError::parse(
                "BinXML",
                format!("unexpected EOF reading u8 at offset {}", self.pos),
            ));
        }
        let v = self.chunk[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u16(&mut self) -> Result<u16, ForensicError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, ForensicError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], ForensicError> {
        let next = self
            .pos
            .checked_add(len)
            .ok_or_else(|| ForensicError::parse("BinXML", "cursor integer overflow"))?;
        if next > self.end {
            return Err(ForensicError::parse(
                "BinXML",
                format!(
                    "unexpected EOF at offset {} (needed {len} bytes, {} left)",
                    self.pos,
                    self.remaining()
                ),
            ));
        }
        let slice = &self.chunk[self.pos..next];
        self.pos = next;
        Ok(slice)
    }

    fn read_utf16_chars(&mut self, num_chars: usize) -> Result<String, ForensicError> {
        let byte_len = num_chars
            .checked_mul(2)
            .ok_or_else(|| ForensicError::parse("BinXML", "UTF-16 string length overflow"))?;
        let slice = self.read_bytes(byte_len)?;
        Ok(read_utf16_le(slice))
    }
}

fn parse_ast_fragment(
    chunk: &[u8],
    cursor_pos: &mut usize,
    end: usize,
    cache: &mut ChunkCache,
    depth: usize,
    parse_budget: &mut BinXmlBudget,
    inst_budget: &mut BinXmlBudget,
) -> Result<(Vec<AstNode>, usize), ForensicError> {
    if depth >= MAX_BINXML_DEPTH {
        return Err(ForensicError::parse(
            "BinXML",
            format!("BinXML recursion depth exceeded {MAX_BINXML_DEPTH}"),
        ));
    }
    let mut cur = Cursor::new(chunk, *cursor_pos, end)?;
    if cur.remaining() == 0 {
        return Ok((Vec::new(), depth));
    }

    // Optional FragmentHeader (0x0F)
    if cur.peek_u8() == Some(0x0F) {
        let _tok = cur.read_u8()?;
        let _major = cur.read_u8()?;
        let _minor = cur.read_u8()?;
        let _flags = cur.read_u8()?;
    }

    let mut max_depth_reached = depth;
    let nodes = parse_node_sequence(
        &mut cur,
        cache,
        depth,
        false,
        parse_budget,
        inst_budget,
        &mut max_depth_reached,
    )?;
    *cursor_pos = cur.pos;
    Ok((nodes, max_depth_reached))
}

fn parse_node_sequence(
    cur: &mut Cursor<'_>,
    cache: &mut ChunkCache,
    depth: usize,
    stop_on_close_element: bool,
    parse_budget: &mut BinXmlBudget,
    inst_budget: &mut BinXmlBudget,
    max_depth_reached: &mut usize,
) -> Result<Vec<AstNode>, ForensicError> {
    if depth >= MAX_BINXML_DEPTH {
        return Err(ForensicError::parse(
            "BinXML",
            format!("BinXML element nesting depth exceeded {MAX_BINXML_DEPTH}"),
        ));
    }
    *max_depth_reached = (*max_depth_reached).max(depth);
    let mut nodes = Vec::new();

    while cur.remaining() > 0 {
        let tok = cur.read_u8()?;
        match tok {
            0x00 => {
                // EndOfStream
                break;
            }
            0x04 if stop_on_close_element => {
                // CloseElementTag
                break;
            }
            0x01 | 0x41 => {
                // OpenStartElementTag
                let has_attrs = (tok & 0x40) != 0;
                let dependency_id = cur.read_u16()?;
                let _data_size = cur.read_u32()?;
                let name_offset = cur.read_u32()?;
                let elem_name = resolve_name(cur, name_offset, cache)?;

                let mut attributes = Vec::new();
                if has_attrs {
                    let attr_list_size = cur.read_u32()? as usize;
                    let attr_end = cur
                        .pos
                        .checked_add(attr_list_size)
                        .ok_or_else(|| ForensicError::parse("BinXML", "attribute list overflow"))?;
                    if attr_end > cur.end {
                        return Err(ForensicError::parse("BinXML", "attribute list exceeds bounds"));
                    }
                    let mut attr_cur = Cursor::new(cur.chunk, cur.pos, attr_end)?;
                    while attr_cur.remaining() > 0 {
                        let attr_tok = attr_cur.read_u8()?;
                        if attr_tok != 0x06 && attr_tok != 0x46 {
                            return Err(ForensicError::parse(
                                "BinXML",
                                format!("unexpected attribute token 0x{attr_tok:02x} at {}", attr_cur.pos - 1),
                            ));
                        }
                        let attr_name_off = attr_cur.read_u32()?;
                        let attr_name = resolve_name(&mut attr_cur, attr_name_off, cache)?;
                        parse_budget.consume(1, attr_name.len())?;
                        let frags = parse_attr_value_frags(&mut attr_cur, cache, parse_budget)?;
                        attributes.push((attr_name, frags));
                    }
                    cur.pos = attr_end;
                }

                let next_tok = cur.read_u8()?;
                let children = match next_tok {
                    0x02 => {
                        // CloseStartElementTag -> parse children until 0x04
                        parse_node_sequence(
                            cur,
                            cache,
                            depth + 1,
                            true,
                            parse_budget,
                            inst_budget,
                            max_depth_reached,
                        )?
                    }
                    0x03 => {
                        // CloseEmptyElementTag
                        Vec::new()
                    }
                    other => {
                        return Err(ForensicError::parse(
                            "BinXML",
                            format!("expected CloseStartElementTag (0x02/0x03), got 0x{other:02x}"),
                        ));
                    }
                };

                parse_budget.consume(1, elem_name.len())?;
                nodes.push(AstNode::Element {
                    name: elem_name,
                    dependency_id,
                    attributes,
                    children,
                });
            }
            0x05 | 0x45 => {
                // Value literal
                let s = read_inline_value(cur)?;
                parse_budget.consume(1, s.len())?;
                nodes.push(AstNode::Frag(AstFrag::Text(s)));
            }
            0x07 | 0x47 => {
                // CDATASection
                let num_chars = usize::from(cur.read_u16()?);
                let text = cur.read_utf16_chars(num_chars)?;
                parse_budget.consume(1, text.len())?;
                nodes.push(AstNode::Frag(AstFrag::CData(text)));
            }
            0x08 | 0x48 => {
                // CharRef
                let code = cur.read_u16()?;
                if let Some(ch) = char::from_u32(u32::from(code)) {
                    let s = ch.to_string();
                    parse_budget.consume(1, s.len())?;
                    nodes.push(AstNode::Frag(AstFrag::Text(s)));
                }
            }
            0x09 | 0x49 => {
                // EntityRef
                let name_off = cur.read_u32()?;
                let name = resolve_name(cur, name_off, cache)?;
                let resolved = resolve_entity_name(&name);
                parse_budget.consume(1, resolved.len())?;
                nodes.push(AstNode::Frag(AstFrag::Text(resolved)));
            }
            0x0A => {
                // PITarget
                let name_off = cur.read_u32()?;
                let _ = resolve_name(cur, name_off, cache)?;
            }
            0x0B => {
                // PIData
                let num_chars = usize::from(cur.read_u16()?);
                let _ = cur.read_utf16_chars(num_chars)?;
            }
            0x0C => {
                // TemplateInstance
                let _version = cur.read_u8()?;
                let _template_id = cur.read_u32()?;
                let template_offset = cur.read_u32()?;
                let (tpl_nodes, tpl_max_depth) =
                    resolve_template(cur, template_offset, cache, depth + 1, parse_budget, inst_budget)?;
                *max_depth_reached = (*max_depth_reached).max(tpl_max_depth);
                let num_subs = cur.read_u32()? as usize;
                let desc_bytes = num_subs
                    .checked_mul(4)
                    .ok_or_else(|| ForensicError::parse("BinXML", "substitution count overflow"))?;
                if desc_bytes > cur.remaining() {
                    return Err(ForensicError::parse(
                        "BinXML",
                        format!("substitution array ({num_subs} entries) exceeds remaining bytes"),
                    ));
                }
                let mut specs = Vec::with_capacity(num_subs);
                for _ in 0..num_subs {
                    let size = usize::from(cur.read_u16()?);
                    let value_type = cur.read_u8()?;
                    let _reserved = cur.read_u8()?;
                    specs.push((size, value_type));
                }

                let mut subs = Vec::with_capacity(num_subs);
                for (size, value_type) in specs {
                    let payload_start = cur.pos;
                    let payload_end = payload_start
                        .checked_add(size)
                        .ok_or_else(|| ForensicError::parse("BinXML", "substitution payload overflow"))?;
                    if payload_end > cur.end {
                        return Err(ForensicError::parse(
                            "BinXML",
                            format!("substitution payload ({size} bytes) exceeds bounds"),
                        ));
                    }
                    cur.pos = payload_end;
                    let (val, sub_max_depth) = decode_typed_value(
                        cur.chunk,
                        payload_start,
                        payload_end,
                        value_type,
                        cache,
                        depth + 1,
                        parse_budget,
                        inst_budget,
                    )?;
                    *max_depth_reached = (*max_depth_reached).max(sub_max_depth);
                    subs.push(val);
                }

                parse_budget.consume(1, 0)?;
                nodes.push(AstNode::SubTemplate { nodes: tpl_nodes, subs });
            }
            0x0D => {
                // NormalSubstitution
                let sub_id = cur.read_u16()?;
                let _val_type = cur.read_u8()?;
                parse_budget.consume(1, 0)?;
                nodes.push(AstNode::Frag(AstFrag::Sub {
                    id: sub_id,
                    optional: false,
                }));
            }
            0x0E => {
                // OptionalSubstitution
                let sub_id = cur.read_u16()?;
                let _val_type = cur.read_u8()?;
                parse_budget.consume(1, 0)?;
                nodes.push(AstNode::Frag(AstFrag::Sub {
                    id: sub_id,
                    optional: true,
                }));
            }
            0x0F => {
                // Nested FragmentHeader
                let _major = cur.read_u8()?;
                let _minor = cur.read_u8()?;
                let _flags = cur.read_u8()?;
            }
            other => {
                return Err(ForensicError::parse(
                    "BinXML",
                    format!("unknown BinXML token 0x{other:02x} at chunk offset {}", cur.pos - 1),
                ));
            }
        }
    }

    Ok(nodes)
}

fn parse_attr_value_frags(
    cur: &mut Cursor<'_>,
    cache: &mut ChunkCache,
    parse_budget: &mut BinXmlBudget,
) -> Result<Vec<AstFrag>, ForensicError> {
    let mut frags = Vec::new();
    loop {
        if cur.remaining() == 0 {
            break;
        }
        let tok = cur.read_u8()?;
        let more_data = (tok & 0x40) != 0;
        match tok {
            0x05 | 0x45 => {
                let s = read_inline_value(cur)?;
                parse_budget.consume(1, s.len())?;
                frags.push(AstFrag::Text(s));
            }
            0x07 | 0x47 => {
                let num_chars = usize::from(cur.read_u16()?);
                let s = cur.read_utf16_chars(num_chars)?;
                parse_budget.consume(1, s.len())?;
                frags.push(AstFrag::CData(s));
            }
            0x08 | 0x48 => {
                let code = cur.read_u16()?;
                if let Some(ch) = char::from_u32(u32::from(code)) {
                    let s = ch.to_string();
                    parse_budget.consume(1, s.len())?;
                    frags.push(AstFrag::Text(s));
                }
            }
            0x09 | 0x49 => {
                let name_off = cur.read_u32()?;
                let name = resolve_name(cur, name_off, cache)?;
                let resolved = resolve_entity_name(&name);
                parse_budget.consume(1, resolved.len())?;
                frags.push(AstFrag::Text(resolved));
            }
            0x0D | 0x4D => {
                let id = cur.read_u16()?;
                let _val_type = cur.read_u8()?;
                parse_budget.consume(1, 0)?;
                frags.push(AstFrag::Sub { id, optional: false });
            }
            0x0E | 0x4E => {
                let id = cur.read_u16()?;
                let _val_type = cur.read_u8()?;
                parse_budget.consume(1, 0)?;
                frags.push(AstFrag::Sub { id, optional: true });
            }
            other => {
                return Err(ForensicError::parse(
                    "BinXML",
                    format!("unexpected attribute value token 0x{other:02x} at {}", cur.pos - 1),
                ));
            }
        }
        if !more_data {
            break;
        }
    }
    Ok(frags)
}

fn read_inline_value(cur: &mut Cursor<'_>) -> Result<String, ForensicError> {
    let val_type = cur.read_u8()?;
    match val_type {
        0x00 => Ok(String::new()),
        0x01 => {
            let num_chars = usize::from(cur.read_u16()?);
            cur.read_utf16_chars(num_chars)
        }
        0x02 => {
            let len = usize::from(cur.read_u16()?);
            let bytes = cur.read_bytes(len)?;
            Ok(String::from_utf8_lossy(bytes).trim_end_matches('\0').to_string())
        }
        0x03 => Ok((cur.read_u8()? as i8).to_string()),
        0x04 => Ok(cur.read_u8()?.to_string()),
        0x05 => {
            let b = cur.read_bytes(2)?;
            Ok(i16::from_le_bytes([b[0], b[1]]).to_string())
        }
        0x06 => Ok(cur.read_u16()?.to_string()),
        0x07 => {
            let b = cur.read_bytes(4)?;
            Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]).to_string())
        }
        0x08 => Ok(cur.read_u32()?.to_string()),
        0x09 => {
            let b = cur.read_bytes(8)?;
            Ok(i64::from_le_bytes(b.try_into().unwrap_or([0; 8])).to_string())
        }
        0x0A => {
            let b = cur.read_bytes(8)?;
            Ok(u64::from_le_bytes(b.try_into().unwrap_or([0; 8])).to_string())
        }
        0x0B => {
            let b = cur.read_bytes(4)?;
            Ok(f32::from_le_bytes([b[0], b[1], b[2], b[3]]).to_string())
        }
        0x0C => {
            let b = cur.read_bytes(8)?;
            Ok(f64::from_le_bytes(b.try_into().unwrap_or([0; 8])).to_string())
        }
        0x0D => {
            let b = cur.read_bytes(4)?;
            Ok((u32::from_le_bytes([b[0], b[1], b[2], b[3]]) != 0).to_string())
        }
        0x0E => {
            let len = usize::from(cur.read_u16()?);
            let b = cur.read_bytes(len)?;
            Ok(bytes_to_hex_lower(b))
        }
        0x0F => {
            let b = cur.read_bytes(16)?;
            parse_guid_le_braced(b)
        }
        0x11 => {
            let b = cur.read_bytes(8)?;
            let ft = u64::from_le_bytes(b.try_into().unwrap_or([0; 8]));
            Ok(format_filetime_or_raw(ft))
        }
        0x12 => {
            let b = cur.read_bytes(16)?;
            Ok(format_systemtime(b))
        }
        0x13 => {
            let len = usize::from(cur.read_u16()?);
            let b = cur.read_bytes(len)?;
            parse_sid(b)
        }
        0x14 => Ok(format!("0x{:x}", cur.read_u32()?)),
        0x15 => {
            let b = cur.read_bytes(8)?;
            let v = u64::from_le_bytes(b.try_into().unwrap_or([0; 8]));
            Ok(format!("0x{v:x}"))
        }
        other => Err(ForensicError::parse(
            "BinXML",
            format!("unsupported inline Value type 0x{other:02x}"),
        )),
    }
}

fn cache_parsed_name(cache: &mut ChunkCache, name_offset: u32, text: String) -> Result<String, ForensicError> {
    let prev_bytes = cache.names.get(&name_offset).map_or(0, String::len);
    let next_cached_bytes = cache
        .total_cached_bytes
        .saturating_sub(prev_bytes)
        .checked_add(text.len())
        .ok_or_else(|| ForensicError::parse("BinXML", "chunk name cache byte budget overflow"))?;
    if next_cached_bytes > MAX_CHUNK_CACHED_BYTES {
        return Err(ForensicError::parse(
            "BinXML",
            format!("chunk name cache byte budget exceeded {MAX_CHUNK_CACHED_BYTES}"),
        ));
    }
    cache.total_cached_bytes = next_cached_bytes;
    cache.names.insert(name_offset, text.clone());
    Ok(text)
}

fn resolve_name(cur: &mut Cursor<'_>, name_offset: u32, cache: &mut ChunkCache) -> Result<String, ForensicError> {
    let off = name_offset as usize;
    if off == cur.pos {
        let name = read_name_struct(cur.chunk, off, cur.end)?;
        let total_len = 10 + name.utf16_len * 2;
        cur.pos = off + total_len;
        return cache_parsed_name(cache, name_offset, name.text);
    }

    if let Some(cached) = cache.names.get(&name_offset) {
        return Ok(cached.clone());
    }

    if off < CHUNK_HEADER_END || off >= cur.chunk.len() {
        return Err(ForensicError::parse(
            "BinXML",
            format!("out-of-bounds Name offset 0x{name_offset:x}"),
        ));
    }

    let name = read_name_struct(cur.chunk, off, cur.chunk.len())?;
    cache_parsed_name(cache, name_offset, name.text)
}

struct ParsedName {
    text: String,
    utf16_len: usize,
}

fn read_name_struct(chunk: &[u8], off: usize, limit: usize) -> Result<ParsedName, ForensicError> {
    if off + 10 > limit {
        return Err(ForensicError::parse(
            "BinXML",
            format!("truncated Name header at chunk offset 0x{off:x}"),
        ));
    }
    let num_chars = usize::from(u16::from_le_bytes([chunk[off + 6], chunk[off + 7]]));
    let total_end = off
        .checked_add(10)
        .and_then(|v| v.checked_add(num_chars * 2))
        .ok_or_else(|| ForensicError::parse("BinXML", "Name length overflow"))?;
    if total_end > limit {
        return Err(ForensicError::parse(
            "BinXML",
            format!("truncated Name string ({num_chars} chars) at chunk offset 0x{off:x}"),
        ));
    }
    let text = read_utf16_le(&chunk[off + 8..off + 8 + num_chars * 2]);
    Ok(ParsedName {
        text,
        utf16_len: num_chars,
    })
}

fn cache_parsed_template(
    cache: &mut ChunkCache,
    template_offset: u32,
    nodes: &[AstNode],
    max_depth: usize,
) -> Result<(), ForensicError> {
    let meas = measure_ast(nodes);
    let prev_nodes = cache.templates.get(&template_offset).map_or(0, |t| t.node_count);
    let prev_bytes = cache.templates.get(&template_offset).map_or(0, |t| t.byte_size);

    let next_cached_nodes = cache
        .total_cached_nodes
        .saturating_sub(prev_nodes)
        .checked_add(meas.node_count)
        .ok_or_else(|| ForensicError::parse("BinXML", "chunk template cache node count overflow"))?;
    if next_cached_nodes > MAX_CHUNK_CACHED_NODES {
        return Err(ForensicError::parse(
            "BinXML",
            format!("chunk template cache node budget exceeded {MAX_CHUNK_CACHED_NODES}"),
        ));
    }

    let next_cached_bytes = cache
        .total_cached_bytes
        .saturating_sub(prev_bytes)
        .checked_add(meas.byte_size)
        .ok_or_else(|| ForensicError::parse("BinXML", "chunk template cache byte budget overflow"))?;
    if next_cached_bytes > MAX_CHUNK_CACHED_BYTES {
        return Err(ForensicError::parse(
            "BinXML",
            format!("chunk template cache byte budget exceeded {MAX_CHUNK_CACHED_BYTES}"),
        ));
    }

    cache.templates.insert(
        template_offset,
        CachedTemplate {
            nodes: nodes.to_vec(),
            max_depth,
            node_count: meas.node_count,
            byte_size: meas.byte_size,
        },
    );
    cache.total_cached_nodes = next_cached_nodes;
    cache.total_cached_bytes = next_cached_bytes;
    Ok(())
}

fn resolve_template(
    cur: &mut Cursor<'_>,
    template_offset: u32,
    cache: &mut ChunkCache,
    depth: usize,
    parse_budget: &mut BinXmlBudget,
    inst_budget: &mut BinXmlBudget,
) -> Result<(Vec<AstNode>, usize), ForensicError> {
    if depth >= MAX_BINXML_DEPTH {
        return Err(ForensicError::parse(
            "BinXML",
            format!("template recursion depth exceeded {MAX_BINXML_DEPTH}"),
        ));
    }

    let off = template_offset as usize;
    if off == cur.pos {
        if off + 24 > cur.end {
            return Err(ForensicError::parse(
                "BinXML",
                format!("truncated inline TemplateDefinition at 0x{off:x}"),
            ));
        }
        let data_size = u32::from_le_bytes([
            cur.chunk[off + 20],
            cur.chunk[off + 21],
            cur.chunk[off + 22],
            cur.chunk[off + 23],
        ]) as usize;
        let body_start = off + 24;
        let body_end = body_start
            .checked_add(data_size)
            .ok_or_else(|| ForensicError::parse("BinXML", "template data_size overflow"))?;
        if body_end > cur.end {
            return Err(ForensicError::parse(
                "BinXML",
                format!("inline TemplateDefinition body exceeds bounds at 0x{off:x}"),
            ));
        }
        let mut tpl_pos = body_start;
        let (nodes, max_depth_reached) = parse_ast_fragment(
            cur.chunk,
            &mut tpl_pos,
            body_end,
            cache,
            depth + 1,
            parse_budget,
            inst_budget,
        )?;
        cur.pos = body_end;
        let rel_max_depth = max_depth_reached.saturating_sub(depth);
        cache_parsed_template(cache, template_offset, &nodes, rel_max_depth)?;
        return Ok((nodes, max_depth_reached));
    }

    if let Some(cached) = cache.templates.get(&template_offset) {
        let combined_depth = depth
            .checked_add(cached.max_depth)
            .ok_or_else(|| ForensicError::parse("BinXML", "cached template depth overflow"))?;
        if combined_depth >= MAX_BINXML_DEPTH {
            return Err(ForensicError::parse(
                "BinXML",
                format!("cached template nesting depth exceeded {MAX_BINXML_DEPTH}"),
            ));
        }
        parse_budget.consume(cached.node_count, cached.byte_size)?;
        return Ok((cached.nodes.clone(), combined_depth));
    }

    if off < CHUNK_HEADER_END || off + 24 > cur.chunk.len() {
        return Err(ForensicError::parse(
            "BinXML",
            format!("out-of-bounds TemplateDefinition offset 0x{template_offset:x}"),
        ));
    }

    let data_size = u32::from_le_bytes([
        cur.chunk[off + 20],
        cur.chunk[off + 21],
        cur.chunk[off + 22],
        cur.chunk[off + 23],
    ]) as usize;
    let body_start = off + 24;
    let body_end = body_start
        .checked_add(data_size)
        .ok_or_else(|| ForensicError::parse("BinXML", "template data_size overflow"))?;
    if body_end > cur.chunk.len() {
        return Err(ForensicError::parse(
            "BinXML",
            format!("cached TemplateDefinition body exceeds chunk bounds at 0x{off:x}"),
        ));
    }
    let mut tpl_pos = body_start;
    let (nodes, max_depth_reached) = parse_ast_fragment(
        cur.chunk,
        &mut tpl_pos,
        body_end,
        cache,
        depth + 1,
        parse_budget,
        inst_budget,
    )?;
    let rel_max_depth = max_depth_reached.saturating_sub(depth);
    cache_parsed_template(cache, template_offset, &nodes, rel_max_depth)?;
    Ok((nodes, max_depth_reached))
}

#[allow(clippy::too_many_arguments)]
fn decode_typed_value(
    chunk: &[u8],
    start: usize,
    end: usize,
    value_type: u8,
    cache: &mut ChunkCache,
    depth: usize,
    parse_budget: &mut BinXmlBudget,
    inst_budget: &mut BinXmlBudget,
) -> Result<(BinXmlValue, usize), ForensicError> {
    let payload = &chunk[start..end];
    if value_type == 0x00 || (payload.is_empty() && value_type != 0x01 && value_type != 0x02) {
        parse_budget.consume(1, std::mem::size_of::<BinXmlValue>())?;
        return Ok((BinXmlValue::Null, depth));
    }

    if (value_type & 0x80) != 0 {
        let base = value_type & 0x7F;
        let val = decode_array_value(payload, base)?;
        let meas = measure_binxml_value(&val);
        parse_budget.consume(meas.node_count, meas.byte_size)?;
        return Ok((val, depth));
    }

    let val = match value_type {
        0x01 => BinXmlValue::Scalar(read_utf16_le(payload).trim_end_matches('\0').to_string()),
        0x02 => BinXmlValue::Scalar(String::from_utf8_lossy(payload).trim_end_matches('\0').to_string()),
        0x03 => BinXmlValue::Scalar((payload[0] as i8).to_string()),
        0x04 => BinXmlValue::Scalar(payload[0].to_string()),
        0x05 if payload.len() >= 2 => BinXmlValue::Scalar(i16::from_le_bytes([payload[0], payload[1]]).to_string()),
        0x06 if payload.len() >= 2 => BinXmlValue::Scalar(u16::from_le_bytes([payload[0], payload[1]]).to_string()),
        0x07 if payload.len() >= 4 => {
            BinXmlValue::Scalar(i32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]).to_string())
        }
        0x08 if payload.len() >= 4 => {
            BinXmlValue::Scalar(u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]).to_string())
        }
        0x09 if payload.len() >= 8 => {
            BinXmlValue::Scalar(i64::from_le_bytes(payload[..8].try_into().unwrap_or([0; 8])).to_string())
        }
        0x0A if payload.len() >= 8 => {
            BinXmlValue::Scalar(u64::from_le_bytes(payload[..8].try_into().unwrap_or([0; 8])).to_string())
        }
        0x0B if payload.len() >= 4 => {
            BinXmlValue::Scalar(f32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]).to_string())
        }
        0x0C if payload.len() >= 8 => {
            BinXmlValue::Scalar(f64::from_le_bytes(payload[..8].try_into().unwrap_or([0; 8])).to_string())
        }
        0x0D => {
            let b = if payload.len() >= 4 {
                u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) != 0
            } else {
                payload[0] != 0
            };
            BinXmlValue::Scalar(b.to_string())
        }
        0x0E => BinXmlValue::Scalar(bytes_to_hex_lower(payload)),
        0x0F if payload.len() >= 16 => BinXmlValue::Scalar(parse_guid_le_braced(&payload[..16])?),
        0x10 => {
            if payload.len() >= 8 {
                let v = u64::from_le_bytes(payload[..8].try_into().unwrap_or([0; 8]));
                BinXmlValue::Scalar(v.to_string())
            } else if payload.len() >= 4 {
                let v = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                BinXmlValue::Scalar(v.to_string())
            } else {
                BinXmlValue::Scalar(bytes_to_hex_lower(payload))
            }
        }
        0x11 if payload.len() >= 8 => {
            let ft = u64::from_le_bytes(payload[..8].try_into().unwrap_or([0; 8]));
            BinXmlValue::Scalar(format_filetime_or_raw(ft))
        }
        0x12 if payload.len() >= 16 => BinXmlValue::Scalar(format_systemtime(payload)),
        0x13 => BinXmlValue::Scalar(parse_sid(payload)?),
        0x14 if payload.len() >= 4 => {
            let v = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
            BinXmlValue::Scalar(format!("0x{v:x}"))
        }
        0x15 if payload.len() >= 8 => {
            let v = u64::from_le_bytes(payload[..8].try_into().unwrap_or([0; 8]));
            BinXmlValue::Scalar(format!("0x{v:x}"))
        }
        0x21 => {
            let (nodes, max_depth_reached) =
                decode_fragment_nodes(chunk, start, end, cache, depth + 1, parse_budget, inst_budget)?;
            return Ok((BinXmlValue::XmlNodes(nodes), max_depth_reached));
        }
        _ => BinXmlValue::Scalar(bytes_to_hex_lower(payload)),
    };
    if let BinXmlValue::Scalar(ref s) = val {
        parse_budget.consume(1, s.len())?;
    }
    Ok((val, depth))
}

fn decode_array_value(payload: &[u8], base_type: u8) -> Result<BinXmlValue, ForensicError> {
    if payload.is_empty() {
        return Ok(BinXmlValue::Array(Vec::new()));
    }
    match base_type {
        0x01 => {
            let full = read_utf16_le(payload);
            let items: Vec<String> = full.split('\0').filter(|s| !s.is_empty()).map(str::to_string).collect();
            Ok(BinXmlValue::Array(items))
        }
        0x02 => {
            let full = String::from_utf8_lossy(payload);
            let items: Vec<String> = full.split('\0').filter(|s| !s.is_empty()).map(str::to_string).collect();
            Ok(BinXmlValue::Array(items))
        }
        0x03 => Ok(BinXmlValue::Array(
            payload.iter().map(|&b| (b as i8).to_string()).collect(),
        )),
        0x04 => Ok(BinXmlValue::Array(payload.iter().map(|b| b.to_string()).collect())),
        0x05 => Ok(BinXmlValue::Array(
            payload
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| i16::from_le_bytes(*c).to_string())
                .collect(),
        )),
        0x06 => Ok(BinXmlValue::Array(
            payload
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c).to_string())
                .collect(),
        )),
        0x07 => Ok(BinXmlValue::Array(
            payload
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| i32::from_le_bytes(*c).to_string())
                .collect(),
        )),
        0x08 => Ok(BinXmlValue::Array(
            payload
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| u32::from_le_bytes(*c).to_string())
                .collect(),
        )),
        0x09 => Ok(BinXmlValue::Array(
            payload
                .as_chunks::<8>()
                .0
                .iter()
                .map(|c| i64::from_le_bytes(*c).to_string())
                .collect(),
        )),
        0x0A => Ok(BinXmlValue::Array(
            payload
                .as_chunks::<8>()
                .0
                .iter()
                .map(|c| u64::from_le_bytes(*c).to_string())
                .collect(),
        )),
        0x0F => {
            let mut out = Vec::new();
            for c in payload.as_chunks::<16>().0 {
                out.push(parse_guid_le_braced(c)?);
            }
            Ok(BinXmlValue::Array(out))
        }
        0x11 => Ok(BinXmlValue::Array(
            payload
                .as_chunks::<8>()
                .0
                .iter()
                .map(|c| format_filetime_or_raw(u64::from_le_bytes(*c)))
                .collect(),
        )),
        0x14 => Ok(BinXmlValue::Array(
            payload
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| format!("0x{:x}", u32::from_le_bytes(*c)))
                .collect(),
        )),
        0x15 => Ok(BinXmlValue::Array(
            payload
                .as_chunks::<8>()
                .0
                .iter()
                .map(|c| format!("0x{:x}", u64::from_le_bytes(*c)))
                .collect(),
        )),
        _ => Ok(BinXmlValue::Scalar(bytes_to_hex_lower(payload))),
    }
}

fn format_filetime_or_raw(ft: u64) -> String {
    if let Some(dt) = filetime_to_utc(ft) {
        dt.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
    } else {
        ft.to_string()
    }
}

fn format_systemtime(payload: &[u8]) -> String {
    let year = i32::from(u16::from_le_bytes([payload[0], payload[1]]));
    let month = u32::from(u16::from_le_bytes([payload[2], payload[3]]));
    let day = u32::from(u16::from_le_bytes([payload[6], payload[7]]));
    let hour = u32::from(u16::from_le_bytes([payload[8], payload[9]]));
    let min = u32::from(u16::from_le_bytes([payload[10], payload[11]]));
    let sec = u32::from(u16::from_le_bytes([payload[12], payload[13]]));
    let ms = u32::from(u16::from_le_bytes([payload[14], payload[15]]));

    if let Some(date) = NaiveDate::from_ymd_opt(year, month, day)
        && let Some(ndt) = date.and_hms_milli_opt(hour, min, sec, ms)
    {
        let dt: DateTime<Utc> = ndt.and_utc();
        return dt.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
    }
    let mut s = String::new();
    let _ = write!(s, "{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{ms:03}Z");
    s
}

fn resolve_entity_name(name: &str) -> String {
    match name {
        "amp" => "&".to_string(),
        "lt" => "<".to_string(),
        "gt" => ">".to_string(),
        "quot" => "\"".to_string(),
        "apos" => "'".to_string(),
        other => format!("&{other};"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_name_struct(buf: &mut [u8], pos: usize, name: &str) -> (u32, usize) {
        let name_off = pos as u32;
        let utf16: Vec<u16> = name.encode_utf16().collect();
        buf[pos..pos + 4].copy_from_slice(&0u32.to_le_bytes());
        buf[pos + 4..pos + 6].copy_from_slice(&0u16.to_le_bytes());
        buf[pos + 6..pos + 8].copy_from_slice(&(utf16.len() as u16).to_le_bytes());
        let mut p = pos + 8;
        for ch in utf16 {
            buf[p..p + 2].copy_from_slice(&ch.to_le_bytes());
            p += 2;
        }
        buf[p..p + 2].copy_from_slice(&0u16.to_le_bytes());
        p += 2;
        (name_off, p)
    }

    fn write_open_elem_cached_name(buf: &mut [u8], pos: usize, name_off: u32, close_tok: u8) -> usize {
        buf[pos] = 0x01;
        buf[pos + 1..pos + 3].copy_from_slice(&0xFFFFu16.to_le_bytes());
        buf[pos + 3..pos + 7].copy_from_slice(&0u32.to_le_bytes());
        buf[pos + 7..pos + 11].copy_from_slice(&name_off.to_le_bytes());
        buf[pos + 11] = close_tok;
        pos + 12
    }

    fn write_template_instance_hdr(buf: &mut [u8], pos: usize, tpl_id: u32, tpl_off: u32) -> usize {
        buf[pos] = 0x0C;
        buf[pos + 1] = 0x01;
        buf[pos + 2..pos + 6].copy_from_slice(&tpl_id.to_le_bytes());
        buf[pos + 6..pos + 10].copy_from_slice(&tpl_off.to_le_bytes());
        pos + 10
    }

    fn write_template_def_hdr(buf: &mut [u8], pos: usize) -> (u32, usize, usize) {
        let tpl_off = pos as u32;
        buf[pos..pos + 4].copy_from_slice(&0u32.to_le_bytes()); // next_offset
        buf[pos + 4..pos + 20].copy_from_slice(&[0x22; 16]); // GUID
        let size_slot = pos + 20;
        buf[size_slot..size_slot + 4].copy_from_slice(&0u32.to_le_bytes());
        (tpl_off, size_slot, pos + 24)
    }

    fn write_empty_sub_array(buf: &mut [u8], pos: usize) -> usize {
        buf[pos..pos + 4].copy_from_slice(&0u32.to_le_bytes());
        pos + 4
    }

    #[test]
    fn recursion_depth_guard_rejects_excessive_nesting() {
        let mut cache = ChunkCache::default();
        let mut parse_budget = BinXmlBudget::new(MAX_BINXML_NODES, MAX_BINXML_BYTES);
        let mut inst_budget = BinXmlBudget::new(MAX_BINXML_NODES, MAX_BINXML_BYTES);
        let err = decode_fragment_nodes(
            &[],
            0,
            0,
            &mut cache,
            MAX_BINXML_DEPTH,
            &mut parse_budget,
            &mut inst_budget,
        )
        .expect_err("depth >= MAX_BINXML_DEPTH must error cleanly");
        assert!(matches!(err, ForensicError::Parse { .. }));
    }

    #[test]
    fn deep_element_nesting_in_parse_node_sequence_returns_parse_error() {
        let mut chunk = vec![0u8; 65_536];
        let mut pos = CHUNK_HEADER_END;
        // FragmentHeader
        chunk[pos..pos + 4].copy_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
        pos += 4;

        // First element defines inline Name ("E") at name_off
        chunk[pos] = 0x01; // OpenStartElementTag (no attrs)
        chunk[pos + 1..pos + 3].copy_from_slice(&0xFFFFu16.to_le_bytes()); // dep_id
        chunk[pos + 3..pos + 7].copy_from_slice(&0u32.to_le_bytes()); // data_size
        let name_off = (pos + 11) as u32;
        chunk[pos + 7..pos + 11].copy_from_slice(&name_off.to_le_bytes());
        pos += 11;
        // Name struct: next(4) + hash(2) + num_chars(2) + "E\0"(4) = 12 bytes
        chunk[pos..pos + 4].copy_from_slice(&0u32.to_le_bytes());
        chunk[pos + 4..pos + 6].copy_from_slice(&0u16.to_le_bytes());
        chunk[pos + 6..pos + 8].copy_from_slice(&1u16.to_le_bytes());
        chunk[pos + 8..pos + 10].copy_from_slice(&u16::from(b'E').to_le_bytes());
        chunk[pos + 10..pos + 12].copy_from_slice(&0u16.to_le_bytes());
        pos += 12;
        chunk[pos] = 0x02; // CloseStartElementTag
        pos += 1;

        let depth_count = 4_500usize;
        for _ in 0..depth_count {
            chunk[pos] = 0x01;
            chunk[pos + 1..pos + 3].copy_from_slice(&0xFFFFu16.to_le_bytes());
            chunk[pos + 3..pos + 7].copy_from_slice(&0u32.to_le_bytes());
            chunk[pos + 7..pos + 11].copy_from_slice(&name_off.to_le_bytes());
            chunk[pos + 11] = 0x02;
            pos += 12;
        }
        for _ in 0..=depth_count {
            chunk[pos] = 0x04;
            pos += 1;
        }
        chunk[pos] = 0x00;
        pos += 1;

        let mut cache = ChunkCache::default();
        let err = decode_binxml_to_xml(&chunk, CHUNK_HEADER_END, pos, &mut cache)
            .expect_err("deeply nested 0x01/0x02 elements must return Parse error");
        assert!(matches!(err, ForensicError::Parse { .. }));
    }

    #[test]
    fn chained_cached_templates_exceeding_max_depth_returns_parse_error() {
        let mut chunk = vec![0u8; 65_536];
        let mut pos = CHUNK_HEADER_END;

        // Seed Name "E" in ChunkCache via a simple initial record
        let rec_seed_start = pos;
        chunk[pos..pos + 4].copy_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
        pos += 4;
        chunk[pos] = 0x01;
        chunk[pos + 1..pos + 3].copy_from_slice(&0xFFFFu16.to_le_bytes());
        chunk[pos + 3..pos + 7].copy_from_slice(&0u32.to_le_bytes());
        let name_off_slot = pos + 7;
        pos += 11;
        let (name_off, next_pos) = write_name_struct(&mut chunk, pos, "E");
        chunk[name_off_slot..name_off_slot + 4].copy_from_slice(&name_off.to_le_bytes());
        pos = next_pos;
        chunk[pos] = 0x03; // empty <E/>
        chunk[pos + 1] = 0x00;
        let rec_seed_end = pos + 2;
        pos = rec_seed_end;

        // Build a 3-hop chain T_0 <- T_1 <- T_2 where each link adds 10 nested elements:
        // T_0: depth 11 (at root 0x0C: 1 + 11 = 12 < 32)
        // T_1: 10 elements + 0x0C(T_0) -> depth 22 (at root 0x0C: 1 + 22 = 23 < 32)
        // T_2: 10 elements + 0x0C(T_1) -> combined depth 12 + 22 = 34 >= 32 -> Parse error!
        let mut prev_tpl_off: Option<u32> = None;
        let mut record_ranges = Vec::new();
        for hop in 0..3u32 {
            let rec_start = pos;
            chunk[pos..pos + 4].copy_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
            pos += 4;
            let tpl_off = (pos + 10) as u32;
            pos = write_template_instance_hdr(&mut chunk, pos, 100 + hop, tpl_off);
            let (_, size_slot, body_start) = write_template_def_hdr(&mut chunk, pos);
            pos = body_start;
            chunk[pos..pos + 4].copy_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
            pos += 4;

            for _ in 0..10 {
                pos = write_open_elem_cached_name(&mut chunk, pos, name_off, 0x02);
            }
            if let Some(target_tpl) = prev_tpl_off {
                pos = write_template_instance_hdr(&mut chunk, pos, 99 + hop, target_tpl);
                pos = write_empty_sub_array(&mut chunk, pos);
            } else {
                pos = write_open_elem_cached_name(&mut chunk, pos, name_off, 0x03);
            }
            for _ in 0..10 {
                chunk[pos] = 0x04;
                pos += 1;
            }
            chunk[pos] = 0x00;
            pos += 1;

            let data_size = (pos - body_start) as u32;
            chunk[size_slot..size_slot + 4].copy_from_slice(&data_size.to_le_bytes());
            pos = write_empty_sub_array(&mut chunk, pos);
            chunk[pos] = 0x00;
            pos += 1;

            record_ranges.push((rec_start, pos));
            prev_tpl_off = Some(tpl_off);
        }

        let mut cache = ChunkCache::default();
        assert_eq!(
            decode_binxml_to_xml(&chunk, rec_seed_start, rec_seed_end, &mut cache).unwrap(),
            "<E/>"
        );
        decode_binxml_to_xml(&chunk, record_ranges[0].0, record_ranges[0].1, &mut cache)
            .expect("T_0 within MAX_BINXML_DEPTH must succeed");
        decode_binxml_to_xml(&chunk, record_ranges[1].0, record_ranges[1].1, &mut cache)
            .expect("T_1 <- T_0 within MAX_BINXML_DEPTH must succeed");
        let err = decode_binxml_to_xml(&chunk, record_ranges[2].0, record_ranges[2].1, &mut cache)
            .expect_err("T_2 <- T_1 <- T_0 exceeding MAX_BINXML_DEPTH must return Parse error");
        assert!(matches!(err, ForensicError::Parse { .. }));
    }

    #[test]
    fn branching_cached_template_dag_exceeding_node_budget_returns_parse_error() {
        let mut chunk = vec![0u8; 65_536];
        let mut pos = CHUNK_HEADER_END;

        // Seed Name "E"
        let rec_seed_start = pos;
        chunk[pos..pos + 4].copy_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
        pos += 4;
        chunk[pos] = 0x01;
        chunk[pos + 1..pos + 3].copy_from_slice(&0xFFFFu16.to_le_bytes());
        chunk[pos + 3..pos + 7].copy_from_slice(&0u32.to_le_bytes());
        let name_off_slot = pos + 7;
        pos += 11;
        let (name_off, next_pos) = write_name_struct(&mut chunk, pos, "E");
        chunk[name_off_slot..name_off_slot + 4].copy_from_slice(&name_off.to_le_bytes());
        pos = next_pos;
        chunk[pos] = 0x03;
        chunk[pos + 1] = 0x00;
        let rec_seed_end = pos + 2;
        pos = rec_seed_end;

        // T_0 contains 8 sibling <E/> nodes; each T_k (k = 1..=28) references T_{k-1} twice.
        // Without node-budget enforcement, T_28 would clone 2^28 * 8 (> 2 billion) nodes.
        // With MAX_BINXML_NODES = 65_536, T_13 hits the node budget cleanly while depth (27) < 32.
        let mut record_ranges = Vec::new();
        let mut prev_tpl_off: Option<u32> = None;
        for level in 0..=28u32 {
            let rec_start = pos;
            chunk[pos..pos + 4].copy_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
            pos += 4;
            let tpl_off = (pos + 10) as u32;
            pos = write_template_instance_hdr(&mut chunk, pos, 200 + level, tpl_off);
            let (_, size_slot, body_start) = write_template_def_hdr(&mut chunk, pos);
            pos = body_start;
            chunk[pos..pos + 4].copy_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
            pos += 4;

            if let Some(target_tpl) = prev_tpl_off {
                for branch in 0..2u32 {
                    pos = write_template_instance_hdr(&mut chunk, pos, 300 + level * 2 + branch, target_tpl);
                    pos = write_empty_sub_array(&mut chunk, pos);
                }
            } else {
                for _ in 0..8 {
                    pos = write_open_elem_cached_name(&mut chunk, pos, name_off, 0x03);
                }
            }
            chunk[pos] = 0x00;
            pos += 1;

            let data_size = (pos - body_start) as u32;
            chunk[size_slot..size_slot + 4].copy_from_slice(&data_size.to_le_bytes());
            pos = write_empty_sub_array(&mut chunk, pos);
            chunk[pos] = 0x00;
            pos += 1;

            record_ranges.push((rec_start, pos));
            prev_tpl_off = Some(tpl_off);
        }

        let mut cache = ChunkCache::default();
        decode_binxml_to_xml(&chunk, rec_seed_start, rec_seed_end, &mut cache).unwrap();

        let mut hit_node_budget_err = false;
        for (level, &(start, end)) in record_ranges.iter().enumerate() {
            match decode_binxml_to_xml(&chunk, start, end, &mut cache) {
                Ok(_) => {}
                Err(ForensicError::Parse { message, .. }) => {
                    assert!(
                        message.contains("node count exceeded") || message.contains("node budget"),
                        "expected node budget error at level {level}, got: {message}"
                    );
                    assert!(
                        level < 16,
                        "budget should trip before exponential blowup, tripped at {level}"
                    );
                    hit_node_budget_err = true;
                    break;
                }
                Err(other) => panic!("unexpected error at level {level}: {other:?}"),
            }
        }
        assert!(hit_node_budget_err, "branching template DAG must trip node budget");
    }

    #[test]
    fn legitimate_depth_31_cached_template_succeeds_and_depth_32_fails() {
        let mut chunk = vec![0u8; 65_536];
        let mut pos = CHUNK_HEADER_END;

        // Seed Name "E"
        let rec_seed_start = pos;
        chunk[pos..pos + 4].copy_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
        pos += 4;
        chunk[pos] = 0x01;
        chunk[pos + 1..pos + 3].copy_from_slice(&0xFFFFu16.to_le_bytes());
        chunk[pos + 3..pos + 7].copy_from_slice(&0u32.to_le_bytes());
        let name_off_slot = pos + 7;
        pos += 11;
        let (name_off, next_pos) = write_name_struct(&mut chunk, pos, "E");
        chunk[name_off_slot..name_off_slot + 4].copy_from_slice(&name_off.to_le_bytes());
        pos = next_pos;
        chunk[pos] = 0x03;
        chunk[pos + 1] = 0x00;
        let rec_seed_end = pos + 2;
        pos = rec_seed_end;

        // Template reaching parse_node_sequence depth = 31 (MAX_BINXML_DEPTH - 1):
        // Root 0x0C (depth 0) -> resolve_template (depth 1) -> parse_ast_fragment (depth 2)
        // -> 29 nested 0x01+0x02 elements (depths 2..30, children at 31) -> 1 innermost 0x01+0x03 at depth 31.
        let rec_ok_miss_start = pos;
        chunk[pos..pos + 4].copy_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
        pos += 4;
        let tpl_off = (pos + 10) as u32;
        pos = write_template_instance_hdr(&mut chunk, pos, 500, tpl_off);
        let (_, size_slot, body_start) = write_template_def_hdr(&mut chunk, pos);
        pos = body_start;
        chunk[pos..pos + 4].copy_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
        pos += 4;
        for _ in 0..29 {
            pos = write_open_elem_cached_name(&mut chunk, pos, name_off, 0x02);
        }
        pos = write_open_elem_cached_name(&mut chunk, pos, name_off, 0x03);
        for _ in 0..29 {
            chunk[pos] = 0x04;
            pos += 1;
        }
        chunk[pos] = 0x00;
        pos += 1;
        let data_size = (pos - body_start) as u32;
        chunk[size_slot..size_slot + 4].copy_from_slice(&data_size.to_le_bytes());
        pos = write_empty_sub_array(&mut chunk, pos);
        chunk[pos] = 0x00;
        pos += 1;
        let rec_ok_miss_end = pos;

        // Second record: cache hit at depth 1 (combined depth = 31 < 32 -> succeeds)
        let rec_ok_hit_start = pos;
        chunk[pos..pos + 4].copy_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
        pos += 4;
        pos = write_template_instance_hdr(&mut chunk, pos, 500, tpl_off);
        pos = write_empty_sub_array(&mut chunk, pos);
        chunk[pos] = 0x00;
        pos += 1;
        let rec_ok_hit_end = pos;

        // Third record: wrap cached template inside 1 outer 0x01+0x02 element (combined depth = 32 -> fails)
        let rec_fail_start = pos;
        chunk[pos..pos + 4].copy_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
        pos += 4;
        pos = write_open_elem_cached_name(&mut chunk, pos, name_off, 0x02);
        pos = write_template_instance_hdr(&mut chunk, pos, 500, tpl_off);
        pos = write_empty_sub_array(&mut chunk, pos);
        chunk[pos] = 0x04;
        chunk[pos + 1] = 0x00;
        pos += 2;
        let rec_fail_end = pos;

        let mut cache = ChunkCache::default();
        decode_binxml_to_xml(&chunk, rec_seed_start, rec_seed_end, &mut cache).unwrap();

        let xml_miss = decode_binxml_to_xml(&chunk, rec_ok_miss_start, rec_ok_miss_end, &mut cache)
            .expect("depth-31 template parse must succeed");
        let xml_hit = decode_binxml_to_xml(&chunk, rec_ok_hit_start, rec_ok_hit_end, &mut cache)
            .expect("depth-31 cached template hit must succeed");
        assert_eq!(xml_miss, xml_hit);
        assert!(xml_hit.starts_with("<E>") && xml_hit.ends_with("</E>"));

        let err = decode_binxml_to_xml(&chunk, rec_fail_start, rec_fail_end, &mut cache)
            .expect_err("depth-32 cached template hit must return Parse error");
        assert!(matches!(err, ForensicError::Parse { .. }));
    }

    #[test]
    fn instantiate_ast_and_write_xml_enforce_depth_and_node_bounds() {
        // 33-level AstNode::Element tree exceeds MAX_BINXML_DEPTH = 32
        let mut ast = vec![AstNode::Frag(AstFrag::Text("leaf".to_string()))];
        for _ in 0..33 {
            ast = vec![AstNode::Element {
                name: "E".to_string(),
                dependency_id: 0xFFFF,
                attributes: Vec::new(),
                children: ast,
            }];
        }
        let mut budget = BinXmlBudget::new(MAX_BINXML_NODES, MAX_BINXML_BYTES);
        let inst_err = instantiate_ast(&ast, &[], 0, &mut budget)
            .expect_err("instantiate_ast must reject depth >= MAX_BINXML_DEPTH");
        assert!(matches!(inst_err, ForensicError::Parse { .. }));

        // Tight node budget rejects excessive instantiation (including attribute-embedded XmlNodes)
        let wide_ast = vec![AstNode::Frag(AstFrag::Text("x".to_string())); 5];
        let mut tiny_budget = BinXmlBudget::new(4, MAX_BINXML_BYTES);
        let budget_err = instantiate_ast(&wide_ast, &[], 0, &mut tiny_budget)
            .expect_err("instantiate_ast must enforce BinXmlBudget");
        assert!(matches!(budget_err, ForensicError::Parse { .. }));

        let attr_xml_ast = vec![AstNode::Element {
            name: "E".to_string(),
            dependency_id: 0xFFFF,
            attributes: vec![("a".to_string(), vec![AstFrag::Sub { id: 0, optional: false }])],
            children: Vec::new(),
        }];
        let attr_sub = vec![BinXmlValue::XmlNodes(vec![XmlNode::Text("1".to_string()); 5])];
        let mut attr_budget = BinXmlBudget::new(4, MAX_BINXML_BYTES);
        let attr_budget_err = instantiate_ast(&attr_xml_ast, &attr_sub, 0, &mut attr_budget)
            .expect_err("instantiate_ast must enforce BinXmlBudget on attribute XmlNodes");
        assert!(matches!(attr_budget_err, ForensicError::Parse { .. }));

        // 33-level XmlNode::Element tree exceeds MAX_BINXML_DEPTH = 32 in write_xml
        let mut xml_node = XmlNode::Text("leaf".to_string());
        for _ in 0..33 {
            xml_node = XmlNode::Element {
                name: "E".to_string(),
                attributes: Vec::new(),
                children: vec![xml_node],
            };
        }
        let mut out = String::new();
        let write_err = xml_node
            .write_xml(&mut out, 0, MAX_BINXML_BYTES)
            .expect_err("XmlNode::write_xml must reject depth >= MAX_BINXML_DEPTH");
        assert!(matches!(write_err, ForensicError::Parse { .. }));
    }

    #[test]
    fn branching_cached_template_dag_with_large_array_sub_returns_parse_error() {
        let mut chunk = vec![0u8; 65_536];
        let mut pos = CHUNK_HEADER_END;

        // Leaf template T_leaf (empty body, 0 AST nodes; SubTemplate referencing it is 1 node)
        let rec_leaf_start = pos;
        chunk[pos..pos + 4].copy_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
        pos += 4;
        let leaf_tpl_off = (pos + 10) as u32;
        pos = write_template_instance_hdr(&mut chunk, pos, 10, leaf_tpl_off);
        let (_, leaf_size_slot, leaf_body_start) = write_template_def_hdr(&mut chunk, pos);
        pos = leaf_body_start;
        chunk[pos..pos + 4].copy_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
        chunk[pos + 4] = 0x00;
        pos += 5;
        let leaf_data_size = (pos - leaf_body_start) as u32;
        chunk[leaf_size_slot..leaf_size_slot + 4].copy_from_slice(&leaf_data_size.to_le_bytes());
        pos = write_empty_sub_array(&mut chunk, pos);
        chunk[pos] = 0x00;
        pos += 1;
        let rec_leaf_end = pos;

        // T_0: 1 SubTemplate calling T_leaf with a 30,000-byte 0x84 (u8[]) substitution -> 30,000 Strings.
        // Records 1..=15 each define T_k with two 0x0C calls to T_{k-1}.
        // Without Array item accounting, T_15 stays <= 65,536 nodes while cloning > 983M Strings.
        let mut record_ranges = Vec::new();
        let mut prev_tpl_off: Option<u32> = None;
        for level in 0..=15u32 {
            let rec_start = pos;
            chunk[pos..pos + 4].copy_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
            pos += 4;
            let tpl_off = (pos + 10) as u32;
            pos = write_template_instance_hdr(&mut chunk, pos, 100 + level, tpl_off);
            let (_, size_slot, body_start) = write_template_def_hdr(&mut chunk, pos);
            pos = body_start;
            chunk[pos..pos + 4].copy_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
            pos += 4;

            if let Some(target_tpl) = prev_tpl_off {
                for branch in 0..2u32 {
                    pos = write_template_instance_hdr(&mut chunk, pos, 300 + level * 2 + branch, target_tpl);
                    pos = write_empty_sub_array(&mut chunk, pos);
                }
            } else {
                pos = write_template_instance_hdr(&mut chunk, pos, 11, leaf_tpl_off);
                chunk[pos..pos + 4].copy_from_slice(&1u32.to_le_bytes()); // num_subs = 1
                pos += 4;
                let arr_len = 30_000usize;
                chunk[pos..pos + 2].copy_from_slice(&(arr_len as u16).to_le_bytes());
                chunk[pos + 2] = 0x84; // u8[]
                chunk[pos + 3] = 0x00;
                pos += 4;
                chunk[pos..pos + arr_len].fill(0x41);
                pos += arr_len;
            }
            chunk[pos] = 0x00;
            pos += 1;

            let data_size = (pos - body_start) as u32;
            chunk[size_slot..size_slot + 4].copy_from_slice(&data_size.to_le_bytes());
            pos = write_empty_sub_array(&mut chunk, pos);
            chunk[pos] = 0x00;
            pos += 1;

            record_ranges.push((rec_start, pos));
            prev_tpl_off = Some(tpl_off);
        }

        let mut cache = ChunkCache::default();
        decode_binxml_to_xml(&chunk, rec_leaf_start, rec_leaf_end, &mut cache).unwrap();

        let mut tripped_parse_err = false;
        for (level, &(start, end)) in record_ranges.iter().enumerate() {
            match decode_binxml_to_xml(&chunk, start, end, &mut cache) {
                Ok(_) => {}
                Err(ForensicError::Parse { message, .. }) => {
                    assert!(
                        message.contains("node count exceeded") || message.contains("byte budget exceeded"),
                        "expected node/byte budget error at level {level}, got: {message}"
                    );
                    assert!(
                        level <= 3,
                        "Array DAG should fail cleanly by level 2-3, failed at {level}"
                    );
                    tripped_parse_err = true;
                    break;
                }
                Err(other) => panic!("unexpected error at level {level}: {other:?}"),
            }
        }
        assert!(tripped_parse_err, "15-level Array template DAG must fail cleanly");
    }

    #[test]
    fn fanout_cached_template_dag_exceeding_byte_budget_returns_parse_error() {
        let mut chunk = vec![0u8; 65_536];
        let mut pos = CHUNK_HEADER_END;

        // T_0: 1 inline 0x05 0x0E binary literal of 30,000 bytes -> 60,000-byte hex String (1 node).
        // T_1..T_3: 16-way fanout; T_4: 15-way fanout (15 * 16^3 = 61,440 < MAX_BINXML_NODES, ~3.68 GiB without byte budget).
        let mut record_ranges = Vec::new();
        let mut prev_tpl_off: Option<u32> = None;
        let mut t2_tpl_off = 0u32;
        for level in 0..=4u32 {
            let rec_start = pos;
            chunk[pos..pos + 4].copy_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
            pos += 4;
            let tpl_off = (pos + 10) as u32;
            if level == 2 {
                t2_tpl_off = tpl_off;
            }
            pos = write_template_instance_hdr(&mut chunk, pos, 400 + level, tpl_off);
            let (_, size_slot, body_start) = write_template_def_hdr(&mut chunk, pos);
            pos = body_start;
            chunk[pos..pos + 4].copy_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
            pos += 4;

            if let Some(target_tpl) = prev_tpl_off {
                let fanout = if level == 4 { 15 } else { 16 };
                for branch in 0..fanout {
                    pos = write_template_instance_hdr(&mut chunk, pos, 500 + level * 32 + branch, target_tpl);
                    pos = write_empty_sub_array(&mut chunk, pos);
                }
            } else {
                let bin_len = 30_000usize;
                chunk[pos] = 0x05; // Value literal
                chunk[pos + 1] = 0x0E; // BinaryType -> 60,000 hex chars
                chunk[pos + 2..pos + 4].copy_from_slice(&(bin_len as u16).to_le_bytes());
                pos += 4;
                chunk[pos..pos + bin_len].fill(0xAB);
                pos += bin_len;
            }
            chunk[pos] = 0x00;
            pos += 1;

            let data_size = (pos - body_start) as u32;
            chunk[size_slot..size_slot + 4].copy_from_slice(&data_size.to_le_bytes());
            pos = write_empty_sub_array(&mut chunk, pos);
            chunk[pos] = 0x00;
            pos += 1;

            record_ranges.push((rec_start, pos));
            prev_tpl_off = Some(tpl_off);
        }

        let mut cache = ChunkCache::default();
        let mut hit_byte_budget_err = false;
        for (level, &(start, end)) in record_ranges.iter().enumerate() {
            match decode_binxml_to_xml(&chunk, start, end, &mut cache) {
                Ok(_) => {}
                Err(ForensicError::Parse { message, .. }) => {
                    assert!(
                        message.contains("byte budget exceeded"),
                        "expected byte budget error at level {level}, got: {message}"
                    );
                    assert_eq!(level, 3, "T_0..T_2 fit under 16 MiB; T_3 must trip MAX_BINXML_BYTES");
                    hit_byte_budget_err = true;
                    break;
                }
                Err(other) => panic!("unexpected error at level {level}: {other:?}"),
            }
        }
        assert!(hit_byte_budget_err, "fanout template DAG must trip MAX_BINXML_BYTES");

        // Also verify MAX_CHUNK_CACHED_BYTES (64 MiB) rejects caching > 64 MiB across multiple small templates
        // that each stay individually within MAX_BINXML_BYTES (16 MiB) and MAX_BINXML_NODES (65,536).
        let mut cache_cap_err = false;
        for extra in 0..5u32 {
            let rec_start = pos;
            chunk[pos..pos + 4].copy_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
            pos += 4;
            let tpl_off = (pos + 10) as u32;
            pos = write_template_instance_hdr(&mut chunk, pos, 800 + extra, tpl_off);
            let (_, size_slot, body_start) = write_template_def_hdr(&mut chunk, pos);
            pos = body_start;
            chunk[pos..pos + 4].copy_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
            pos += 4;
            pos = write_template_instance_hdr(&mut chunk, pos, 900 + extra, t2_tpl_off);
            pos = write_empty_sub_array(&mut chunk, pos);
            chunk[pos] = 0x00;
            pos += 1;
            let data_size = (pos - body_start) as u32;
            chunk[size_slot..size_slot + 4].copy_from_slice(&data_size.to_le_bytes());
            pos = write_empty_sub_array(&mut chunk, pos);
            chunk[pos] = 0x00;
            pos += 1;

            if let Err(ForensicError::Parse { message, .. }) = decode_binxml_to_xml(&chunk, rec_start, pos, &mut cache)
            {
                assert!(
                    message.contains("chunk template cache byte budget exceeded"),
                    "expected chunk cache byte budget error, got: {message}"
                );
                cache_cap_err = true;
                break;
            }
        }
        assert!(cache_cap_err, "ChunkCache must enforce MAX_CHUNK_CACHED_BYTES");
    }

    #[test]
    fn eval_attr_frags_and_write_xml_enforce_array_and_byte_bounds() {
        // 1. eval_attr_frags enforces node budget on BinXmlValue::Array
        let attr_arr_ast = vec![AstNode::Element {
            name: "E".to_string(),
            dependency_id: 0xFFFF,
            attributes: vec![("a".to_string(), vec![AstFrag::Sub { id: 0, optional: false }])],
            children: Vec::new(),
        }];
        let arr_sub = vec![BinXmlValue::Array(vec!["x".to_string(); 5])];
        let mut node_budget = BinXmlBudget::new(4, MAX_BINXML_BYTES);
        let err = instantiate_ast(&attr_arr_ast, &arr_sub, 0, &mut node_budget)
            .expect_err("eval_attr_frags must enforce node budget on BinXmlValue::Array");
        assert!(matches!(err, ForensicError::Parse { .. }));

        // 2. eval_attr_frags enforces byte budget on BinXmlValue::Array, Scalar, and Text
        let arr_big_sub = vec![BinXmlValue::Array(vec!["abcdef".to_string(); 3])];
        let mut byte_budget = BinXmlBudget::new(MAX_BINXML_NODES, 20);
        let err = instantiate_ast(&attr_arr_ast, &arr_big_sub, 0, &mut byte_budget)
            .expect_err("eval_attr_frags must enforce byte budget on BinXmlValue::Array");
        assert!(matches!(err, ForensicError::Parse { .. }));

        let scalar_sub = vec![BinXmlValue::Scalar("0123456789".to_string())];
        let mut scalar_budget = BinXmlBudget::new(MAX_BINXML_NODES, 9);
        let err = instantiate_ast(&attr_arr_ast, &scalar_sub, 0, &mut scalar_budget)
            .expect_err("eval_attr_frags must enforce byte budget on BinXmlValue::Scalar");
        assert!(matches!(err, ForensicError::Parse { .. }));

        let attr_text_ast = vec![AstNode::Element {
            name: "E".to_string(),
            dependency_id: 0xFFFF,
            attributes: vec![("a".to_string(), vec![AstFrag::Text("0123456789".to_string())])],
            children: Vec::new(),
        }];
        let mut text_budget = BinXmlBudget::new(MAX_BINXML_NODES, 9);
        let err = instantiate_ast(&attr_text_ast, &[], 0, &mut text_budget)
            .expect_err("eval_attr_frags must enforce byte budget on AstFrag::Text");
        assert!(matches!(err, ForensicError::Parse { .. }));

        // 3. instantiate_ast enforces node & byte budgets on child BinXmlValue::Array
        let child_sub_ast = vec![AstNode::Frag(AstFrag::Sub { id: 0, optional: false })];
        let mut child_node_budget = BinXmlBudget::new(4, MAX_BINXML_BYTES);
        let err = instantiate_ast(&child_sub_ast, &arr_sub, 0, &mut child_node_budget)
            .expect_err("instantiate_ast must enforce node budget on child BinXmlValue::Array");
        assert!(matches!(err, ForensicError::Parse { .. }));

        let mut child_byte_budget = BinXmlBudget::new(MAX_BINXML_NODES, 20);
        let err = instantiate_ast(&child_sub_ast, &arr_big_sub, 0, &mut child_byte_budget)
            .expect_err("instantiate_ast must enforce byte budget on child BinXmlValue::Array");
        assert!(matches!(err, ForensicError::Parse { .. }));

        // 4. XmlNode::write_xml enforces byte cap across Text, escaped '&', CDATA ']]>', and attributes
        let mut out = String::new();
        let err = XmlNode::Text("a".repeat(100))
            .write_xml(&mut out, 0, 50)
            .expect_err("write_xml must enforce max_bytes on Text");
        assert!(matches!(err, ForensicError::Parse { .. }));

        out.clear();
        let err = XmlNode::Text("&".repeat(20))
            .write_xml(&mut out, 0, 50)
            .expect_err("write_xml must enforce max_bytes on escaped Text");
        assert!(matches!(err, ForensicError::Parse { .. }));

        out.clear();
        let err = XmlNode::CData("]]>".repeat(10))
            .write_xml(&mut out, 0, 50)
            .expect_err("write_xml must enforce max_bytes on escaped CData");
        assert!(matches!(err, ForensicError::Parse { .. }));

        out.clear();
        let elem = XmlNode::Element {
            name: "E".to_string(),
            attributes: vec![("k".to_string(), "\"".repeat(20))],
            children: Vec::new(),
        };
        let err = elem
            .write_xml(&mut out, 0, 50)
            .expect_err("write_xml must enforce max_bytes on escaped attributes");
        assert!(matches!(err, ForensicError::Parse { .. }));
    }
}
