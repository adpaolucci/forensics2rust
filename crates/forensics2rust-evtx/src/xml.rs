use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDateTime, Utc};
use forensics2rust_core::ForensicError;
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};

use crate::model::EvtxRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Root,
    Event,
    System,
    EventData,
    UserData,
    RenderingInfo,
}

/// Parses a `<Event>...</Event>` XML document (from live `wevtapi` `EvtRenderEventXml`
/// or decoded BinXML) into a normalized [`EvtxRecord`].
pub fn parse_event_xml(
    xml: &str,
    raw_bytes: Vec<u8>,
    fallback_record_id: u64,
    fallback_written_time: DateTime<Utc>,
    source_file: String,
) -> Result<EvtxRecord, ForensicError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);

    let mut record = EvtxRecord {
        record_id: fallback_record_id,
        event_time: fallback_written_time,
        event_id: 0,
        qualifiers: None,
        version: None,
        level: 0,
        channel: String::new(),
        provider: String::new(),
        provider_guid: None,
        opcode: 0,
        opcode_name: None,
        task: 0,
        task_name: None,
        keywords: 0,
        process_id: None,
        thread_id: None,
        user_sid: None,
        computer: String::new(),
        activity_id: None,
        event_data: BTreeMap::new(),
        user_data: BTreeMap::new(),
        description: String::new(),
        source_file,
        raw_xml: xml.to_string(),
        raw_bytes,
    };

    let mut section = Section::Root;
    let mut stack: Vec<String> = Vec::new();
    let mut current_text = String::new();
    let mut current_data_name: Option<String> = None;
    let mut unnamed_data_idx: usize = 0;
    let mut saw_event_root = false;
    let mut user_data_leaf_has_children = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let name = local_name_string(e.name().as_ref());
                if !stack.is_empty() && section == Section::UserData {
                    // Parent element inside UserData gained a child, so it isn't a leaf.
                    user_data_leaf_has_children = true;
                }
                stack.push(name.clone());
                current_text.clear();

                match (section, stack.len(), name.as_str()) {
                    (Section::Root, 1, "Event") => {
                        saw_event_root = true;
                        section = Section::Event;
                    }
                    (Section::Event, 2, "System") => section = Section::System,
                    (Section::Event, 2, "EventData") => section = Section::EventData,
                    (Section::Event, 2, "UserData") => section = Section::UserData,
                    (Section::Event, 2, "RenderingInfo") => section = Section::RenderingInfo,
                    (Section::System, 3, _) => apply_system_attrs(&reader, e, &name, &mut record)?,
                    (Section::EventData, 3, "Data") => {
                        current_data_name = find_attr(&reader, e, "Name")?;
                    }
                    (Section::UserData, _, _) => {
                        user_data_leaf_has_children = false;
                    }
                    _ => {}
                }
            }
            Ok(Event::Empty(ref e)) => {
                let name = local_name_string(e.name().as_ref());
                if stack.is_empty() && name == "Event" {
                    saw_event_root = true;
                    break;
                }
                match section {
                    Section::System if stack.len() == 2 => {
                        apply_system_attrs(&reader, e, &name, &mut record)?;
                    }
                    Section::EventData if stack.len() == 2 && name == "Data" => {
                        let key = find_attr(&reader, e, "Name")?.unwrap_or_else(|| {
                            let k = format!("Data{unnamed_data_idx}");
                            unnamed_data_idx += 1;
                            k
                        });
                        record.event_data.entry(key).or_default();
                    }
                    Section::UserData if stack.len() >= 2 => {
                        user_data_leaf_has_children = true;
                        record.user_data.entry(name).or_default();
                    }
                    _ => {}
                }
            }
            Ok(Event::End(ref e)) => {
                let name = local_name_string(e.name().as_ref());
                let text = std::mem::take(&mut current_text);
                let trimmed = text.trim();

                match section {
                    Section::System if stack.len() == 3 => match name.as_str() {
                        "EventID" => {
                            if let Some(v) = parse_u16_flex(trimmed) {
                                record.event_id = v;
                            }
                        }
                        "Version" => {
                            record.version = parse_u64_flex(trimmed).and_then(|v| u8::try_from(v).ok());
                        }
                        "Level" => {
                            if let Some(v) = parse_u64_flex(trimmed).and_then(|v| u8::try_from(v).ok()) {
                                record.level = v;
                            }
                        }
                        "Task" => {
                            if let Some(v) = parse_u16_flex(trimmed) {
                                record.task = v;
                            }
                        }
                        "Opcode" => {
                            if let Some(v) = parse_u16_flex(trimmed) {
                                record.opcode = v;
                            }
                        }
                        "Keywords" => {
                            if let Some(v) = parse_u64_flex(trimmed) {
                                record.keywords = v;
                            }
                        }
                        "EventRecordID" => {
                            if let Some(v) = parse_u64_flex(trimmed)
                                && v != 0
                            {
                                record.record_id = v;
                            }
                        }
                        "Channel" => record.channel = trimmed.to_string(),
                        "Computer" => record.computer = trimmed.to_string(),
                        _ => {}
                    },
                    Section::EventData if stack.len() == 3 => {
                        if name == "Data" {
                            let key = current_data_name.take().unwrap_or_else(|| {
                                let k = format!("Data{unnamed_data_idx}");
                                unnamed_data_idx += 1;
                                k
                            });
                            record.event_data.insert(key, text.trim_matches('\0').to_string());
                        } else if name == "Binary" && !trimmed.is_empty() {
                            record.event_data.insert("Binary".to_string(), trimmed.to_string());
                        }
                    }
                    Section::UserData if stack.len() >= 3 => {
                        if !user_data_leaf_has_children && !trimmed.is_empty() {
                            let val = text.trim_matches('\0').to_string();
                            insert_userdata_leaf(&mut record.user_data, &name, val.clone());
                            record.event_data.entry(name).or_insert(val);
                        }
                        // Parent containers should not capture whitespace/child text.
                        user_data_leaf_has_children = true;
                    }
                    Section::RenderingInfo if stack.len() == 3 => match name.as_str() {
                        "Message" => {
                            if !trimmed.is_empty() {
                                record.description = trimmed.to_string();
                            }
                        }
                        "Opcode" => {
                            if !trimmed.is_empty() {
                                record.opcode_name = Some(trimmed.to_string());
                            }
                        }
                        "Task" => {
                            if !trimmed.is_empty() {
                                record.task_name = Some(trimmed.to_string());
                            }
                        }
                        "Channel" if record.channel.is_empty() => {
                            record.channel = trimmed.to_string();
                        }
                        "Provider" if record.provider.is_empty() => {
                            record.provider = trimmed.to_string();
                        }
                        _ => {}
                    },
                    _ => {}
                }

                stack.pop();
                if stack.len() == 1 {
                    section = Section::Event;
                } else if stack.is_empty() {
                    section = Section::Root;
                }
            }
            Ok(Event::Text(e)) => {
                let decoded = e
                    .xml10_content()
                    .map_err(|err| ForensicError::parse("EVTX XML", format!("invalid text node: {err}")))?;
                current_text.push_str(&decoded);
            }
            Ok(Event::CData(e)) => {
                let decoded = e
                    .decode()
                    .map_err(|err| ForensicError::parse("EVTX XML", format!("invalid CDATA node: {err}")))?;
                current_text.push_str(&decoded);
            }
            Ok(Event::GeneralRef(r)) => {
                if let Some(ch) = r
                    .resolve_char_ref()
                    .map_err(|err| ForensicError::parse("EVTX XML", format!("invalid char ref: {err}")))?
                {
                    current_text.push(ch);
                } else {
                    let entity = r
                        .decode()
                        .map_err(|err| ForensicError::parse("EVTX XML", format!("invalid entity ref: {err}")))?;
                    match entity.as_ref() {
                        "amp" => current_text.push('&'),
                        "lt" => current_text.push('<'),
                        "gt" => current_text.push('>'),
                        "quot" => current_text.push('"'),
                        "apos" => current_text.push('\''),
                        other => {
                            current_text.push('&');
                            current_text.push_str(other);
                            current_text.push(';');
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(err) => {
                return Err(ForensicError::parse(
                    "EVTX XML",
                    format!("XML parse error at byte {}: {err}", reader.error_position()),
                ));
            }
        }
    }

    if !saw_event_root {
        return Err(ForensicError::parse("EVTX XML", "missing root <Event> element"));
    }

    if record.description.is_empty() {
        record.description = synthesize_description(&record);
    }

    Ok(record)
}

fn insert_userdata_leaf(map: &mut BTreeMap<String, String>, key: &str, value: String) {
    if !map.contains_key(key) {
        map.insert(key.to_string(), value);
        return;
    }
    let mut idx = 2usize;
    loop {
        let candidate = format!("{key}_{idx}");
        if let std::collections::btree_map::Entry::Vacant(entry) = map.entry(candidate) {
            entry.insert(value);
            return;
        }
        idx += 1;
    }
}

fn apply_system_attrs(
    reader: &Reader<&[u8]>,
    e: &BytesStart<'_>,
    elem_name: &str,
    record: &mut EvtxRecord,
) -> Result<(), ForensicError> {
    match elem_name {
        "Provider" => {
            if let Some(name) = find_attr(reader, e, "Name")? {
                record.provider = name;
            } else if let Some(name) = find_attr(reader, e, "EventSourceName")? {
                record.provider = name;
            }
            if let Some(guid) = find_attr(reader, e, "Guid")?
                && !guid.is_empty()
            {
                record.provider_guid = Some(guid);
            }
        }
        "EventID" => {
            if let Some(q) = find_attr(reader, e, "Qualifiers")? {
                record.qualifiers = parse_u16_flex(q.trim());
            }
        }
        "TimeCreated" => {
            if let Some(sys_time) = find_attr(reader, e, "SystemTime")?
                && let Some(dt) = parse_evtx_timestamp(sys_time.trim())
            {
                record.event_time = dt;
            }
        }
        "Execution" => {
            if let Some(pid) = find_attr(reader, e, "ProcessID")? {
                record.process_id = parse_u64_flex(pid.trim()).and_then(|v| u32::try_from(v).ok());
            }
            if let Some(tid) = find_attr(reader, e, "ThreadID")? {
                record.thread_id = parse_u64_flex(tid.trim()).and_then(|v| u32::try_from(v).ok());
            }
        }
        "Security" => {
            if let Some(sid) = find_attr(reader, e, "UserID")?
                && !sid.is_empty()
            {
                record.user_sid = Some(sid);
            }
        }
        "Correlation" => {
            if let Some(act) = find_attr(reader, e, "ActivityID")?
                && !act.is_empty()
            {
                record.activity_id = Some(act);
            }
        }
        _ => {}
    }
    Ok(())
}

fn find_attr(reader: &Reader<&[u8]>, e: &BytesStart<'_>, attr_name: &str) -> Result<Option<String>, ForensicError> {
    for attr in e.attributes() {
        let attr = attr.map_err(|err| ForensicError::parse("EVTX XML", format!("invalid XML attribute: {err}")))?;
        let key = local_name_string(attr.key.as_ref());
        if key == attr_name {
            let val = attr
                .decoded_and_normalized_value(XmlVersion::Implicit1_0, reader.decoder())
                .map_err(|err| ForensicError::parse("EVTX XML", format!("attribute decode error: {err}")))?;
            return Ok(Some(val.into_owned()));
        }
    }
    Ok(None)
}

fn local_name_string(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    if let Some((_, local)) = s.rsplit_once(':') {
        local.to_string()
    } else {
        s.into_owned()
    }
}

pub(crate) fn parse_u64_flex(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}

pub(crate) fn parse_u16_flex(s: &str) -> Option<u16> {
    parse_u64_flex(s).and_then(|v| u16::try_from(v).ok())
}

pub(crate) fn parse_evtx_timestamp(s: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in [
        "%Y-%m-%dT%H:%M:%S%.fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
    ] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(ndt.and_utc());
        }
    }
    None
}

/// Synthesizes a deterministic human-readable summary for offline EVTX records that
/// lack `<RenderingInfo><Message>` strings.
pub(crate) fn synthesize_description(record: &EvtxRecord) -> String {
    let mut parts: Vec<String> = Vec::new();
    let combined = record
        .user_data
        .iter()
        .chain(record.event_data.iter())
        .filter(|(_, v)| !v.is_empty() && *v != "-");
    for (k, v) in combined.take(6) {
        let compact = v.replace(['\r', '\n'], " ");
        let truncated = if compact.chars().count() > 80 {
            let mut s: String = compact.chars().take(77).collect();
            s.push_str("...");
            s
        } else {
            compact
        };
        parts.push(format!("{k}={truncated}"));
    }

    let provider = if record.provider.is_empty() {
        "Event"
    } else {
        record.provider.as_str()
    };

    if parts.is_empty() {
        format!("{provider} EventID {}", record.event_id)
    } else {
        format!("{provider} EventID {}: {}", record.event_id, parts.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use chrono::Datelike;

    use super::*;

    #[test]
    fn parse_xml_handles_eventdata_entities_cdata_and_hex_fields() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>
    <EventID Qualifiers="16384">4688</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>13312</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-23T12:34:56.1234567Z"/>
    <EventRecordID>42</EventRecordID>
    <Correlation ActivityID="{11111111-2222-3333-4444-555555555555}"/>
    <Execution ProcessID="0x4" ThreadID="88"/>
    <Channel>Security</Channel>
    <Computer>WORKSTATION01</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="CommandLine">cmd.exe /c echo a&amp;b &lt;tag&gt;&#x20;<![CDATA[ok]]></Data>
    <Data Name="EmptyField"/>
    <Data>UnnamedFirst</Data>
    <Binary>DEADBEEF</Binary>
  </EventData>
</Event>"#;

        let rec = EvtxRecord::parse_xml(xml).expect("valid EVTX XML should parse");
        assert_eq!(rec.record_id, 42);
        assert_eq!(rec.event_id, 4688);
        assert_eq!(rec.qualifiers, Some(16384));
        assert_eq!(rec.version, Some(2));
        assert_eq!(rec.keywords, 0x8020_0000_0000_0000);
        assert_eq!(rec.event_time.year(), 2026);
        assert_eq!(rec.process_id, Some(4));
        assert_eq!(rec.thread_id, Some(88));
        assert_eq!(rec.channel, "Security");
        assert_eq!(rec.computer, "WORKSTATION01");
        assert_eq!(rec.user_sid.as_deref(), Some("S-1-5-18"));
        assert_eq!(
            rec.provider_guid.as_deref(),
            Some("{54849625-5478-4994-a5ba-3e3b0328c30d}")
        );
        assert_eq!(
            rec.activity_id.as_deref(),
            Some("{11111111-2222-3333-4444-555555555555}")
        );
        assert_eq!(rec.get_data("CommandLine"), Some("cmd.exe /c echo a&b <tag> ok"));
        assert_eq!(rec.get_data("EmptyField"), Some(""));
        assert_eq!(rec.get_data("Data0"), Some("UnnamedFirst"));
        assert_eq!(rec.get_data("Binary"), Some("DEADBEEF"));
    }

    #[test]
    fn parse_xml_handles_userdata_and_rendering_info() {
        let xml = r#"<Event>
  <System>
    <Provider Name="Microsoft-Windows-TerminalServices-LocalSessionManager"/>
    <EventID>21</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2026-11-23T10:00:00Z"/>
    <EventRecordID>7</EventRecordID>
    <Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel>
    <Computer>SRV01</Computer>
  </System>
  <UserData>
    <EventXML xmlns="Event_NS">
      <User>CORP\alice</User>
      <SessionID>2</SessionID>
      <Address>10.20.30.40</Address>
    </EventXML>
  </UserData>
  <RenderingInfo Culture="en-US">
    <Message>Remote Desktop Services: Session logon succeeded</Message>
    <Opcode>Info</Opcode>
    <Task>Logon</Task>
  </RenderingInfo>
</Event>"#;

        let rec = EvtxRecord::parse_xml(xml).expect("UserData XML should parse");
        assert_eq!(rec.get_data("User"), Some("CORP\\alice"));
        assert_eq!(rec.get_data("SessionID"), Some("2"));
        assert_eq!(rec.get_data("Address"), Some("10.20.30.40"));
        assert_eq!(rec.description, "Remote Desktop Services: Session logon succeeded");
        assert_eq!(rec.opcode_name.as_deref(), Some("Info"));
        assert_eq!(rec.task_name.as_deref(), Some("Logon"));
    }
}
