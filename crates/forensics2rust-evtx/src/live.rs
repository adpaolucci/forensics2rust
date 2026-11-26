use std::collections::{BTreeMap, HashMap};
use std::ffi::c_void;
use std::path::Path;

use chrono::{DateTime, Utc};
use forensics2rust_core::{DiagnosticWarning, ForensicError, WarningSeverity, filetime_to_utc};
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_EVT_CHANNEL_NOT_FOUND, ERROR_EVT_INVALID_CHANNEL_PATH,
    ERROR_EVT_INVALID_OPERATION_OVER_ENABLED_DIRECT_CHANNEL, ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND,
    ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_PATH_NOT_FOUND,
    ERROR_PRIVILEGE_NOT_HELD, ERROR_SUCCESS, FILETIME, WIN32_ERROR,
};
use windows::Win32::System::EventLog::{
    EVT_CHANNEL_CONFIG_PROPERTY_ID, EVT_HANDLE, EVT_LOG_PROPERTY_ID, EVT_PUBLISHER_METADATA_PROPERTY_ID, EVT_VARIANT,
    EVT_VARIANT_TYPE_ARRAY, EVT_VARIANT_TYPE_MASK, EvtChannelConfigAccess, EvtChannelConfigClassicEventlog,
    EvtChannelConfigEnabled, EvtChannelConfigIsolation, EvtChannelConfigOwningPublisher, EvtChannelConfigType,
    EvtChannelIsolationTypeApplication, EvtChannelIsolationTypeCustom, EvtChannelIsolationTypeSystem,
    EvtChannelLoggingConfigLogFilePath, EvtChannelLoggingConfigMaxSize, EvtChannelTypeAdmin, EvtChannelTypeAnalytic,
    EvtChannelTypeDebug, EvtChannelTypeOperational, EvtClose, EvtFormatMessage, EvtFormatMessageEvent,
    EvtGetChannelConfigProperty, EvtGetLogInfo, EvtGetObjectArrayProperty, EvtGetObjectArraySize,
    EvtGetPublisherMetadataProperty, EvtLogCreationTime, EvtLogFileSize, EvtLogFull, EvtLogLastWriteTime,
    EvtLogNumberOfLogRecords, EvtNext, EvtNextChannelPath, EvtNextPublisherId, EvtOpenChannelConfig,
    EvtOpenChannelEnum, EvtOpenLog, EvtOpenPublisherEnum, EvtOpenPublisherMetadata,
    EvtPublisherMetadataChannelReferencePath, EvtPublisherMetadataChannelReferences,
    EvtPublisherMetadataMessageFilePath, EvtPublisherMetadataParameterFilePath, EvtPublisherMetadataPublisherGuid,
    EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection, EvtQueryReverseDirection, EvtRender, EvtRenderEventXml,
    EvtVarTypeBoolean, EvtVarTypeEvtHandle, EvtVarTypeFileTime, EvtVarTypeGuid, EvtVarTypeNull, EvtVarTypeString,
    EvtVarTypeUInt32, EvtVarTypeUInt64,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE, RegCloseKey,
    RegEnumKeyExW, RegOpenKeyExW, RegQueryInfoKeyW, RegQueryValueExW,
};
use windows::core::{GUID, HSTRING, PWSTR};

use crate::model::{ChannelMetadata, EvtxRecord, LiveQueryOptions, SourceMetadata};
use crate::xml::parse_event_xml;

const DEFAULT_MAX_RECORDS: usize = 10_000;

/// RAII wrapper around a Win32 `EVT_HANDLE`.
struct EvtHandle(EVT_HANDLE);

impl EvtHandle {
    fn raw(&self) -> EVT_HANDLE {
        self.0
    }
}

impl Drop for EvtHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: `self.0` is a valid non-null handle acquired from `wevtapi`.
            let _ = unsafe { EvtClose(self.0) };
        }
    }
}

/// RAII wrapper around a Win32 `HKEY`.
struct RegKeyHandle(HKEY);

impl RegKeyHandle {
    fn raw(&self) -> HKEY {
        self.0
    }
}

impl Drop for RegKeyHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: `self.0` is an open registry key handle acquired from `RegOpenKeyExW`.
            let _ = unsafe { RegCloseKey(self.0) };
        }
    }
}

#[derive(Debug, Clone)]
enum EvtVar {
    Bool(bool),
    U32(u32),
    U64(u64),
    FileTime(DateTime<Utc>),
    Guid(String),
    String(String),
    Handle(EVT_HANDLE),
}

fn map_win_error(context: impl Into<String>, err: windows::core::Error) -> ForensicError {
    let ctx = context.into();
    match WIN32_ERROR::from_error(&err) {
        Some(code) if code == ERROR_ACCESS_DENIED || code == ERROR_PRIVILEGE_NOT_HELD => {
            ForensicError::permission_denied(ctx, err.to_string())
        }
        Some(code)
            if code == ERROR_FILE_NOT_FOUND
                || code == ERROR_PATH_NOT_FOUND
                || code == ERROR_EVT_CHANNEL_NOT_FOUND
                || code == ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND
                || code == ERROR_EVT_INVALID_CHANNEL_PATH =>
        {
            ForensicError::NotFound(ctx)
        }
        _ => ForensicError::io(ctx, std::io::Error::from_raw_os_error(err.code().0)),
    }
}

fn is_win_code(err: &windows::core::Error, expected: WIN32_ERROR) -> bool {
    WIN32_ERROR::from_error(err) == Some(expected)
}

fn is_permission_win_err(err: &windows::core::Error) -> bool {
    matches!(
        WIN32_ERROR::from_error(err),
        Some(c) if c == ERROR_ACCESS_DENIED || c == ERROR_PRIVILEGE_NOT_HELD
    )
}

fn is_missing_channel_win_err(err: &windows::core::Error) -> bool {
    matches!(
        WIN32_ERROR::from_error(err),
        Some(c)
            if c == ERROR_FILE_NOT_FOUND
                || c == ERROR_PATH_NOT_FOUND
                || c == ERROR_EVT_CHANNEL_NOT_FOUND
                || c == ERROR_EVT_INVALID_CHANNEL_PATH
                || c == ERROR_EVT_INVALID_OPERATION_OVER_ENABLED_DIRECT_CHANNEL
    )
}

fn format_guid(g: &GUID) -> String {
    format!(
        "{{{0:08x}-{1:04x}-{2:04x}-{3:02x}{4:02x}-{5:02x}{6:02x}{7:02x}{8:02x}{9:02x}{10:02x}}}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7]
    )
}

/// Decodes a populated `EVT_VARIANT` inside an 8-byte-aligned backing buffer.
///
/// # Safety
/// `buf` must hold a valid `EVT_VARIANT` initialized by `wevtapi`, and any embedded
/// pointers (`StringVal`, `GuidVal`) must point within `buf`.
unsafe fn decode_evt_variant(buf: &[u64]) -> Option<EvtVar> {
    let byte_len = std::mem::size_of_val(buf);
    if byte_len < std::mem::size_of::<EVT_VARIANT>() {
        return None;
    }
    // SAFETY: `buf` is 8-byte aligned and at least `size_of::<EVT_VARIANT>()` bytes long.
    let var = unsafe { &*(buf.as_ptr().cast::<EVT_VARIANT>()) };
    if (var.Type & EVT_VARIANT_TYPE_ARRAY) != 0 {
        return None;
    }
    let vtype = var.Type & EVT_VARIANT_TYPE_MASK;
    if vtype == EvtVarTypeNull.0 as u32 {
        return None;
    }
    match vtype {
        x if x == EvtVarTypeBoolean.0 as u32 => {
            // SAFETY: `Type` is `EvtVarTypeBoolean`.
            Some(EvtVar::Bool(unsafe { var.Anonymous.BooleanVal.as_bool() }))
        }
        x if x == EvtVarTypeUInt32.0 as u32 => {
            // SAFETY: `Type` is `EvtVarTypeUInt32`.
            Some(EvtVar::U32(unsafe { var.Anonymous.UInt32Val }))
        }
        x if x == EvtVarTypeUInt64.0 as u32 => {
            // SAFETY: `Type` is `EvtVarTypeUInt64`.
            Some(EvtVar::U64(unsafe { var.Anonymous.UInt64Val }))
        }
        x if x == EvtVarTypeFileTime.0 as u32 => {
            // SAFETY: `Type` is `EvtVarTypeFileTime`.
            let ft = unsafe { var.Anonymous.FileTimeVal };
            filetime_to_utc(ft).map(EvtVar::FileTime)
        }
        x if x == EvtVarTypeGuid.0 as u32 => {
            // SAFETY: `Type` is `EvtVarTypeGuid`.
            let ptr = unsafe { var.Anonymous.GuidVal };
            if ptr.is_null() {
                None
            } else {
                // SAFETY: `GuidVal` points to a valid `GUID` inside `buf`.
                Some(EvtVar::Guid(format_guid(unsafe { &*ptr })))
            }
        }
        x if x == EvtVarTypeString.0 as u32 => {
            // SAFETY: `Type` is `EvtVarTypeString`.
            let pcw = unsafe { var.Anonymous.StringVal };
            if pcw.is_null() {
                None
            } else {
                // SAFETY: `StringVal` is a NUL-terminated UTF-16 string inside `buf`.
                unsafe { pcw.to_string().ok() }.map(EvtVar::String)
            }
        }
        x if x == EvtVarTypeEvtHandle.0 as u32 => {
            // SAFETY: `Type` is `EvtVarTypeEvtHandle`.
            let h = unsafe { var.Anonymous.EvtHandleVal };
            if h.is_invalid() { None } else { Some(EvtVar::Handle(h)) }
        }
        _ => None,
    }
}

fn query_evt_variant<F>(mut call: F) -> Result<Option<EvtVar>, windows::core::Error>
where
    F: FnMut(u32, *mut EVT_VARIANT, *mut u32) -> windows::core::Result<()>,
{
    let mut buf: Vec<u64> = vec![0u64; 64]; // 512 bytes, 8-byte aligned
    let mut used = 0u32;
    let first = call(
        (buf.len() * 8) as u32,
        buf.as_mut_ptr().cast::<EVT_VARIANT>(),
        &mut used,
    );
    if let Err(ref err) = first
        && (is_win_code(err, ERROR_INSUFFICIENT_BUFFER) || is_win_code(err, ERROR_MORE_DATA))
    {
        let needed_u64 = (used as usize).div_ceil(8).max(buf.len() * 2);
        buf.resize(needed_u64, 0);
        call(
            (buf.len() * 8) as u32,
            buf.as_mut_ptr().cast::<EVT_VARIANT>(),
            &mut used,
        )?;
    } else {
        first?;
    }
    // SAFETY: `call` succeeded and initialized `EVT_VARIANT` inside `buf`.
    Ok(unsafe { decode_evt_variant(&buf) })
}

fn get_channel_prop(cfg: EVT_HANDLE, prop: EVT_CHANNEL_CONFIG_PROPERTY_ID) -> Option<EvtVar> {
    query_evt_variant(|bytes, ptr, used| {
        // SAFETY: `cfg` is a valid channel config handle and `ptr` points to `bytes` of aligned memory.
        unsafe { EvtGetChannelConfigProperty(cfg, prop, 0, bytes, Some(ptr), used) }
    })
    .ok()
    .flatten()
}

fn get_log_prop(log: EVT_HANDLE, prop: EVT_LOG_PROPERTY_ID) -> Option<EvtVar> {
    query_evt_variant(|bytes, ptr, used| {
        // SAFETY: `log` is a valid log handle and `ptr` points to `bytes` of aligned memory.
        unsafe { EvtGetLogInfo(log, prop, bytes, Some(ptr), used) }
    })
    .ok()
    .flatten()
}

fn get_publisher_prop(pub_meta: EVT_HANDLE, prop: EVT_PUBLISHER_METADATA_PROPERTY_ID) -> Option<EvtVar> {
    query_evt_variant(|bytes, ptr, used| {
        // SAFETY: `pub_meta` is a valid publisher metadata handle and `ptr` points to aligned memory.
        unsafe { EvtGetPublisherMetadataProperty(pub_meta, prop, 0, bytes, Some(ptr), used) }
    })
    .ok()
    .flatten()
}

/// Queries live Windows Event Log channels via `wevtapi` with bounded `EvtNext` batching
/// and graceful degradation across inaccessible or missing channels.
pub(crate) fn query_channels(
    tool_id: &str,
    channels: &[&str],
    opts: &LiveQueryOptions,
) -> Result<(Vec<EvtxRecord>, Vec<DiagnosticWarning>), ForensicError> {
    let max_records = opts.max_records.unwrap_or(DEFAULT_MAX_RECORDS);
    if max_records == 0 {
        return Ok((Vec::new(), Vec::new()));
    }

    let target_channels: Vec<String> = if channels.is_empty() {
        discover_queryable_channels()?
    } else {
        channels.iter().map(|s| (*s).to_string()).collect()
    };

    if target_channels.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    let mut all_records = Vec::new();
    let mut warnings = Vec::new();
    let mut pub_cache: HashMap<String, Option<EvtHandle>> = HashMap::new();
    let mut render_buf: Vec<u16> = vec![0u16; 8192];
    let mut succeeded_channels = 0usize;
    let mut first_perm_err: Option<ForensicError> = None;
    let mut first_other_err: Option<ForensicError> = None;

    for (idx, channel) in target_channels.iter().enumerate() {
        let remaining = max_records.saturating_sub(all_records.len());
        if remaining == 0 {
            break;
        }
        let remaining_channels = target_channels.len().saturating_sub(idx).max(1);
        let channel_cap = (remaining / remaining_channels).max(1);

        // Fast skip if channel exists and explicitly reports 0 records.
        if let Some(0) = try_log_record_count(channel) {
            succeeded_channels += 1;
            continue;
        }

        match query_single_channel(channel, opts, channel_cap, &mut render_buf, &mut pub_cache) {
            Ok(mut recs) => {
                succeeded_channels += 1;
                all_records.append(&mut recs);
            }
            Err(err) => {
                let is_perm = matches!(err, ForensicError::PermissionDenied { .. });
                let msg = err.to_string();
                tracing::warn!(tool_id, channel = %channel, error = %msg, "live channel query skipped");
                warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Warn,
                    tool_id: tool_id.to_string(),
                    source: channel.clone(),
                    message: msg,
                });
                if is_perm {
                    if first_perm_err.is_none() {
                        first_perm_err = Some(err);
                    }
                } else if first_other_err.is_none() {
                    first_other_err = Some(err);
                }
            }
        }
    }

    if succeeded_channels == 0 {
        if let Some(perm) = first_perm_err {
            return Err(perm);
        }
        if let Some(other) = first_other_err {
            return Err(other);
        }
    }

    Ok((all_records, warnings))
}

fn try_log_record_count(channel: &str) -> Option<u64> {
    let ch_h = HSTRING::from(channel);
    // SAFETY: `ch_h` is a valid NUL-terminated UTF-16 string.
    let log = unsafe { EvtOpenLog(None, &ch_h, windows::Win32::System::EventLog::EvtOpenChannelPath.0) }.ok()?;
    let log_guard = EvtHandle(log);
    match get_log_prop(log_guard.raw(), EvtLogNumberOfLogRecords) {
        Some(EvtVar::U64(n)) => Some(n),
        _ => None,
    }
}

fn query_single_channel(
    channel: &str,
    opts: &LiveQueryOptions,
    max_records: usize,
    render_buf: &mut Vec<u16>,
    pub_cache: &mut HashMap<String, Option<EvtHandle>>,
) -> Result<Vec<EvtxRecord>, ForensicError> {
    let ch_h = HSTRING::from(channel);
    let xpath = opts.xpath_query.as_deref().unwrap_or("*");
    let xpath_h = HSTRING::from(xpath);
    let dir_flag = if opts.reverse_direction {
        EvtQueryReverseDirection.0
    } else {
        EvtQueryForwardDirection.0
    };
    let flags = EvtQueryChannelPath.0 | dir_flag;

    // SAFETY: `ch_h` and `xpath_h` are valid `HSTRING`s; `EvtQuery` returns an owned `EVT_HANDLE`.
    let q_handle = unsafe { EvtQuery(None, &ch_h, &xpath_h, flags) }.map_err(|err| {
        if is_permission_win_err(&err) {
            ForensicError::permission_denied(channel, err.to_string())
        } else if is_missing_channel_win_err(&err) {
            ForensicError::NotFound(channel.to_string())
        } else {
            map_win_error(channel, err)
        }
    })?;
    let q_guard = EvtHandle(q_handle);

    let mut records = Vec::new();
    let mut raw_handles = [0isize; 64];

    while records.len() < max_records {
        let batch_cap = (max_records - records.len()).min(raw_handles.len());
        let mut returned = 0u32;
        // SAFETY: `q_guard` is valid and `raw_handles[..batch_cap]` is writable.
        let next_res = unsafe { EvtNext(q_guard.raw(), &mut raw_handles[..batch_cap], 5_000, 0, &mut returned) };
        if let Err(err) = next_res {
            if is_win_code(&err, ERROR_NO_MORE_ITEMS) {
                break;
            }
            return Err(map_win_error(channel, err));
        }

        let count = returned as usize;
        if count == 0 {
            break;
        }

        // Immediately wrap all returned handles in RAII guards so early returns never leak.
        let evt_guards: Vec<EvtHandle> = raw_handles[..count]
            .iter()
            .map(|&raw| EvtHandle(EVT_HANDLE(raw)))
            .collect();

        for evt in &evt_guards {
            let xml = render_event_xml(evt.raw(), render_buf, channel)?;
            let source_label = format!("live:{channel}");
            let raw_bytes = xml.as_bytes().to_vec();
            let mut rec = parse_event_xml(&xml, raw_bytes, 0, DateTime::<Utc>::UNIX_EPOCH, source_label)?;
            if rec.channel.is_empty() {
                rec.channel = channel.to_string();
            }
            if !rec.provider.is_empty()
                && let Some(msg) = try_format_event_message(evt.raw(), &rec.provider, pub_cache)
                && !msg.is_empty()
            {
                rec.description = msg;
            }
            records.push(rec);
            if records.len() >= max_records {
                break;
            }
        }
    }

    Ok(records)
}

fn render_event_xml(evt: EVT_HANDLE, render_buf: &mut Vec<u16>, channel: &str) -> Result<String, ForensicError> {
    let mut used_bytes = 0u32;
    let mut prop_count = 0u32;
    let buf_bytes = (render_buf.len() * 2) as u32;

    // SAFETY: `evt` is a valid event handle and `render_buf` has `buf_bytes` writable bytes.
    let first = unsafe {
        EvtRender(
            None,
            evt,
            EvtRenderEventXml.0,
            buf_bytes,
            Some(render_buf.as_mut_ptr().cast::<c_void>()),
            &mut used_bytes,
            &mut prop_count,
        )
    };

    if let Err(err) = first {
        if is_win_code(&err, ERROR_INSUFFICIENT_BUFFER) {
            let needed_u16 = (used_bytes as usize).div_ceil(2).max(render_buf.len() * 2);
            render_buf.resize(needed_u16, 0);
            let new_bytes = (render_buf.len() * 2) as u32;
            // SAFETY: `render_buf` was resized to hold `used_bytes`.
            unsafe {
                EvtRender(
                    None,
                    evt,
                    EvtRenderEventXml.0,
                    new_bytes,
                    Some(render_buf.as_mut_ptr().cast::<c_void>()),
                    &mut used_bytes,
                    &mut prop_count,
                )
            }
            .map_err(|e| map_win_error(channel, e))?;
        } else {
            return Err(map_win_error(channel, err));
        }
    }

    let max_u16 = (used_bytes as usize / 2).min(render_buf.len());
    let nul_pos = render_buf[..max_u16].iter().position(|&c| c == 0).unwrap_or(max_u16);
    Ok(String::from_utf16_lossy(&render_buf[..nul_pos]))
}

fn try_format_event_message(
    evt: EVT_HANDLE,
    provider: &str,
    pub_cache: &mut HashMap<String, Option<EvtHandle>>,
) -> Option<String> {
    let meta_opt = pub_cache.entry(provider.to_string()).or_insert_with(|| {
        let p_h = HSTRING::from(provider);
        // SAFETY: `p_h` is a valid `HSTRING`.
        unsafe { EvtOpenPublisherMetadata(None, &p_h, None, 0, 0) }
            .ok()
            .map(EvtHandle)
    });
    let meta = meta_opt.as_ref()?;

    let mut msg_buf: Vec<u16> = vec![0u16; 1024];
    let mut used = 0u32;
    // SAFETY: `meta` and `evt` are valid handles; `msg_buf` has `msg_buf.len()` `u16` elements.
    let res = unsafe {
        EvtFormatMessage(
            Some(meta.raw()),
            Some(evt),
            0,
            None,
            EvtFormatMessageEvent.0,
            Some(&mut msg_buf),
            &mut used,
        )
    };
    if let Err(ref err) = res
        && is_win_code(err, ERROR_INSUFFICIENT_BUFFER)
    {
        msg_buf.resize((used as usize).max(msg_buf.len() * 2), 0);
        // SAFETY: `msg_buf` resized to `used` code units.
        unsafe {
            EvtFormatMessage(
                Some(meta.raw()),
                Some(evt),
                0,
                None,
                EvtFormatMessageEvent.0,
                Some(&mut msg_buf),
                &mut used,
            )
        }
        .ok()?;
    } else {
        res.ok()?;
    }

    let len = (used as usize).min(msg_buf.len());
    let nul = msg_buf[..len].iter().position(|&c| c == 0).unwrap_or(len);
    Some(String::from_utf16_lossy(&msg_buf[..nul]).trim().to_string())
}

fn enumerate_channel_names() -> Result<Vec<String>, ForensicError> {
    // SAFETY: No pointers passed; returns channel enumerator handle.
    let enum_h = unsafe { EvtOpenChannelEnum(None, 0) }.map_err(|e| map_win_error("EvtOpenChannelEnum", e))?;
    let enum_guard = EvtHandle(enum_h);

    let mut channels = Vec::new();
    let mut buf: Vec<u16> = vec![0u16; 260];

    loop {
        let mut used = 0u32;
        // SAFETY: `enum_guard` is valid and `buf` is writable.
        let res = unsafe { EvtNextChannelPath(enum_guard.raw(), Some(&mut buf), &mut used) };
        match res {
            Ok(()) => {
                let len = (used as usize).min(buf.len());
                let nul = buf[..len].iter().position(|&c| c == 0).unwrap_or(len);
                channels.push(String::from_utf16_lossy(&buf[..nul]));
            }
            Err(err) if is_win_code(&err, ERROR_NO_MORE_ITEMS) => break,
            Err(err) if is_win_code(&err, ERROR_INSUFFICIENT_BUFFER) => {
                buf.resize((used as usize).max(buf.len() * 2), 0);
            }
            Err(err) => return Err(map_win_error("EvtNextChannelPath", err)),
        }
    }

    Ok(channels)
}

fn discover_queryable_channels() -> Result<Vec<String>, ForensicError> {
    let all = enumerate_channel_names()?;
    let mut queryable = Vec::new();
    for ch in all {
        let ch_h = HSTRING::from(ch.as_str());
        // SAFETY: `ch_h` is a valid `HSTRING`.
        let Ok(cfg) = (unsafe { EvtOpenChannelConfig(None, &ch_h, 0) }) else {
            continue;
        };
        let cfg_guard = EvtHandle(cfg);
        let enabled = matches!(
            get_channel_prop(cfg_guard.raw(), EvtChannelConfigEnabled),
            Some(EvtVar::Bool(true))
        );
        if !enabled {
            continue;
        }
        let ch_type = match get_channel_prop(cfg_guard.raw(), EvtChannelConfigType) {
            Some(EvtVar::U32(t)) => t,
            _ => 0,
        };
        if ch_type == EvtChannelTypeAnalytic.0 as u32 || ch_type == EvtChannelTypeDebug.0 as u32 {
            continue;
        }
        queryable.push(ch);
    }
    Ok(queryable)
}

/// Enumerates live Windows Event Log channels via `wevtapi` and Registry (`WINEVT\Channels`).
pub(crate) fn enumerate_channels() -> Result<(Vec<ChannelMetadata>, Vec<DiagnosticWarning>), ForensicError> {
    let names = enumerate_channel_names()?;
    let mut out = Vec::with_capacity(names.len());
    let mut warnings = Vec::new();

    for ch_name in names {
        let ch_h = HSTRING::from(ch_name.as_str());
        let cfg_res = unsafe { EvtOpenChannelConfig(None, &ch_h, 0) };
        let mut meta = ChannelMetadata {
            channel_name: ch_name.clone(),
            log_file_path: String::new(),
            enabled: None,
            channel_type: None,
            isolation: None,
            max_size_kb: None,
            event_count: None,
            file_size: None,
            modified_time: None,
            owning_publisher: None,
            classic_eventlog: None,
            raw_bytes: Vec::new(),
        };

        match cfg_res {
            Ok(cfg) => {
                let cfg_guard = EvtHandle(cfg);
                if let Some(EvtVar::Bool(b)) = get_channel_prop(cfg_guard.raw(), EvtChannelConfigEnabled) {
                    meta.enabled = Some(b);
                }
                if let Some(EvtVar::U32(t)) = get_channel_prop(cfg_guard.raw(), EvtChannelConfigType) {
                    meta.channel_type = Some(match t {
                        x if x == EvtChannelTypeAdmin.0 as u32 => "Admin".to_string(),
                        x if x == EvtChannelTypeOperational.0 as u32 => "Operational".to_string(),
                        x if x == EvtChannelTypeAnalytic.0 as u32 => "Analytic".to_string(),
                        x if x == EvtChannelTypeDebug.0 as u32 => "Debug".to_string(),
                        other => format!("Type({other})"),
                    });
                }
                if let Some(EvtVar::U32(iso)) = get_channel_prop(cfg_guard.raw(), EvtChannelConfigIsolation) {
                    meta.isolation = Some(match iso {
                        x if x == EvtChannelIsolationTypeApplication.0 as u32 => "Application".to_string(),
                        x if x == EvtChannelIsolationTypeSystem.0 as u32 => "System".to_string(),
                        x if x == EvtChannelIsolationTypeCustom.0 as u32 => "Custom".to_string(),
                        other => format!("Isolation({other})"),
                    });
                }
                if let Some(EvtVar::String(p)) = get_channel_prop(cfg_guard.raw(), EvtChannelConfigOwningPublisher) {
                    meta.owning_publisher = Some(p);
                }
                if let Some(EvtVar::Bool(c)) = get_channel_prop(cfg_guard.raw(), EvtChannelConfigClassicEventlog) {
                    meta.classic_eventlog = Some(c);
                }
                if let Some(EvtVar::U64(max_bytes)) = get_channel_prop(cfg_guard.raw(), EvtChannelLoggingConfigMaxSize)
                {
                    meta.max_size_kb = Some(max_bytes / 1024);
                }
                if let Some(EvtVar::String(path)) =
                    get_channel_prop(cfg_guard.raw(), EvtChannelLoggingConfigLogFilePath)
                {
                    meta.log_file_path = expand_env_vars(&path);
                }
                let _ = get_channel_prop(cfg_guard.raw(), EvtChannelConfigAccess);
            }
            Err(err) => {
                warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Info,
                    tool_id: "evtx.channels".to_string(),
                    source: ch_name.clone(),
                    message: format!("EvtOpenChannelConfig skipped: {err}"),
                });
            }
        }

        // Best-effort EvtOpenLog stats (may be restricted for Security or enabled Analytic/Debug)
        if let Ok(log) = unsafe { EvtOpenLog(None, &ch_h, windows::Win32::System::EventLog::EvtOpenChannelPath.0) } {
            let log_guard = EvtHandle(log);
            if let Some(EvtVar::U64(cnt)) = get_log_prop(log_guard.raw(), EvtLogNumberOfLogRecords) {
                meta.event_count = Some(cnt);
            }
            if let Some(EvtVar::U64(sz)) = get_log_prop(log_guard.raw(), EvtLogFileSize) {
                meta.file_size = Some(sz);
            }
            if let Some(EvtVar::FileTime(dt)) = get_log_prop(log_guard.raw(), EvtLogLastWriteTime) {
                meta.modified_time = Some(dt);
            } else if let Some(EvtVar::FileTime(dt)) = get_log_prop(log_guard.raw(), EvtLogCreationTime) {
                meta.modified_time = Some(dt);
            }
            let _ = get_log_prop(log_guard.raw(), EvtLogFull);
        }

        // Fallback file size / modified time from filesystem if LogFilePath exists
        if !meta.log_file_path.is_empty()
            && (meta.file_size.is_none() || meta.modified_time.is_none())
            && let Ok(fs_meta) = std::fs::metadata(Path::new(&meta.log_file_path))
        {
            if meta.file_size.is_none() {
                meta.file_size = Some(fs_meta.len());
            }
            if meta.modified_time.is_none()
                && let Ok(mtime) = fs_meta.modified()
            {
                meta.modified_time = Some(DateTime::<Utc>::from(mtime));
            }
        }

        // Fallback modified time from Registry WINEVT\Channels\<channel>
        if meta.modified_time.is_none() {
            let reg_path = format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\{ch_name}");
            meta.modified_time = reg_key_last_write(&reg_path);
        }

        meta.raw_bytes = serde_json::to_vec(&meta).unwrap_or_default();
        out.push(meta);
    }

    Ok((out, warnings))
}

/// Enumerates live Event Log publishers/sources via `wevtapi` and Registry
/// (`WINEVT\Publishers` and `Services\EventLog`).
pub(crate) fn enumerate_sources() -> Result<(Vec<SourceMetadata>, Vec<DiagnosticWarning>), ForensicError> {
    // SAFETY: No pointers passed; opens publisher enumerator.
    let enum_h = unsafe { EvtOpenPublisherEnum(None, 0) }.map_err(|e| map_win_error("EvtOpenPublisherEnum", e))?;
    let enum_guard = EvtHandle(enum_h);

    let mut publisher_ids = Vec::new();
    let mut buf: Vec<u16> = vec![0u16; 260];
    loop {
        let mut used = 0u32;
        // SAFETY: `enum_guard` is valid and `buf` is writable.
        let res = unsafe { EvtNextPublisherId(enum_guard.raw(), Some(&mut buf), &mut used) };
        match res {
            Ok(()) => {
                let len = (used as usize).min(buf.len());
                let nul = buf[..len].iter().position(|&c| c == 0).unwrap_or(len);
                publisher_ids.push(String::from_utf16_lossy(&buf[..nul]));
            }
            Err(err) if is_win_code(&err, ERROR_NO_MORE_ITEMS) => break,
            Err(err) if is_win_code(&err, ERROR_INSUFFICIENT_BUFFER) => {
                buf.resize((used as usize).max(buf.len() * 2), 0);
            }
            Err(err) => return Err(map_win_error("EvtNextPublisherId", err)),
        }
    }

    let mut out = Vec::new();
    let mut warnings = Vec::new();
    let mut seen: BTreeMap<(String, String), usize> = BTreeMap::new();

    for pub_id in publisher_ids {
        let pub_h = HSTRING::from(pub_id.as_str());
        let meta_res = unsafe { EvtOpenPublisherMetadata(None, &pub_h, None, 0, 0) };
        match meta_res {
            Ok(meta_h) => {
                let meta_guard = EvtHandle(meta_h);
                let guid = match get_publisher_prop(meta_guard.raw(), EvtPublisherMetadataPublisherGuid) {
                    Some(EvtVar::Guid(g)) => Some(g),
                    _ => None,
                };
                let msg_dll = match get_publisher_prop(meta_guard.raw(), EvtPublisherMetadataMessageFilePath) {
                    Some(EvtVar::String(s)) if !s.is_empty() => Some(expand_env_vars(&s)),
                    _ => None,
                };
                let param_dll = match get_publisher_prop(meta_guard.raw(), EvtPublisherMetadataParameterFilePath) {
                    Some(EvtVar::String(s)) if !s.is_empty() => Some(expand_env_vars(&s)),
                    _ => None,
                };
                let channels = get_publisher_channel_refs(meta_guard.raw());
                let reg_mod = guid.as_deref().and_then(|g| {
                    reg_key_last_write(&format!(
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{g}"
                    ))
                });
                let dll_exists = msg_dll.as_deref().map(|p| Path::new(p).exists());

                let channel_joined = if channels.is_empty() {
                    "(none)".to_string()
                } else {
                    channels.join(", ")
                };
                let key = (pub_id.clone(), channel_joined.clone());
                if let std::collections::btree_map::Entry::Vacant(entry) = seen.entry(key) {
                    let mut src = SourceMetadata {
                        source_name: pub_id,
                        channel: channel_joined,
                        provider_guid: guid,
                        message_dll: msg_dll,
                        parameter_dll: param_dll,
                        dll_exists,
                        registry_modified: reg_mod,
                        observed_event_count: None,
                        raw_bytes: Vec::new(),
                    };
                    src.raw_bytes = serde_json::to_vec(&src).unwrap_or_default();
                    entry.insert(out.len());
                    out.push(src);
                }
            }
            Err(err) => {
                warnings.push(DiagnosticWarning {
                    severity: WarningSeverity::Info,
                    tool_id: "evtx.sources".to_string(),
                    source: pub_id,
                    message: format!("EvtOpenPublisherMetadata skipped: {err}"),
                });
            }
        }
    }

    // Merge classic Services\EventLog\<Log>\<Source> entries if not already present.
    collect_classic_eventlog_sources(&mut out, &mut seen);

    Ok((out, warnings))
}

fn get_publisher_channel_refs(pub_meta: EVT_HANDLE) -> Vec<String> {
    let Some(EvtVar::Handle(arr_h)) = get_publisher_prop(pub_meta, EvtPublisherMetadataChannelReferences) else {
        return Vec::new();
    };
    let arr_guard = EvtHandle(arr_h);
    let mut size = 0u32;
    // SAFETY: `arr_guard` is an object array handle returned by `EvtGetPublisherMetadataProperty`.
    if unsafe { EvtGetObjectArraySize(arr_guard.raw().0, &mut size) }.is_err() {
        return Vec::new();
    }
    let mut channels = Vec::new();
    for idx in 0..size {
        if let Ok(Some(EvtVar::String(ch))) = query_evt_variant(|bytes, ptr, used| {
            // SAFETY: `arr_guard` is valid and `ptr` points to aligned buffer.
            unsafe {
                EvtGetObjectArrayProperty(
                    arr_guard.raw().0,
                    EvtPublisherMetadataChannelReferencePath.0 as u32,
                    idx,
                    0,
                    bytes,
                    Some(ptr),
                    used,
                )
            }
        }) && !ch.is_empty()
        {
            channels.push(ch);
        }
    }
    channels
}

fn collect_classic_eventlog_sources(out: &mut Vec<SourceMetadata>, seen: &mut BTreeMap<(String, String), usize>) {
    let base_path = r"SYSTEM\CurrentControlSet\Services\EventLog";
    let Some(base_key) = open_reg_key(base_path) else {
        return;
    };
    for log_name in enum_reg_subkeys(base_key.raw()) {
        let log_path = format!(r"{base_path}\{log_name}");
        let Some(log_key) = open_reg_key(&log_path) else {
            continue;
        };
        for src_name in enum_reg_subkeys(log_key.raw()) {
            let key_tuple = (src_name.clone(), log_name.clone());
            if seen.contains_key(&key_tuple) {
                continue;
            }
            let src_path = format!(r"{log_path}\{src_name}");
            let Some(src_key) = open_reg_key(&src_path) else {
                continue;
            };
            let msg_dll = read_reg_string(src_key.raw(), "EventMessageFile").map(|s| expand_env_vars(&s));
            let param_dll = read_reg_string(src_key.raw(), "ParameterMessageFile").map(|s| expand_env_vars(&s));
            let dll_exists = msg_dll
                .as_deref()
                .map(|s| s.split(';').any(|p| Path::new(p.trim()).exists()));
            let reg_mod = reg_handle_last_write(src_key.raw());
            let mut src = SourceMetadata {
                source_name: src_name,
                channel: log_name.clone(),
                provider_guid: None,
                message_dll: msg_dll,
                parameter_dll: param_dll,
                dll_exists,
                registry_modified: reg_mod,
                observed_event_count: None,
                raw_bytes: Vec::new(),
            };
            src.raw_bytes = serde_json::to_vec(&src).unwrap_or_default();
            seen.insert(key_tuple, out.len());
            out.push(src);
        }
    }
}

fn open_reg_key(subkey: &str) -> Option<RegKeyHandle> {
    let sub_h = HSTRING::from(subkey);
    let mut handle = HKEY::default();
    // SAFETY: `sub_h` is valid; `handle` receives the opened key on `ERROR_SUCCESS`.
    let code = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            &sub_h,
            None,
            KEY_READ | KEY_WOW64_64KEY,
            &mut handle,
        )
    };
    if code == ERROR_SUCCESS {
        Some(RegKeyHandle(handle))
    } else {
        None
    }
}

fn reg_key_last_write(subkey: &str) -> Option<DateTime<Utc>> {
    let key = open_reg_key(subkey)?;
    reg_handle_last_write(key.raw())
}

fn reg_handle_last_write(hkey: HKEY) -> Option<DateTime<Utc>> {
    let mut ft = FILETIME::default();
    // SAFETY: `hkey` is a valid open registry key.
    let code = unsafe {
        RegQueryInfoKeyW(
            hkey,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&mut ft),
        )
    };
    if code == ERROR_SUCCESS {
        let combined = (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime);
        filetime_to_utc(combined)
    } else {
        None
    }
}

fn enum_reg_subkeys(hkey: HKEY) -> Vec<String> {
    let mut names = Vec::new();
    let mut idx = 0u32;
    let mut buf = vec![0u16; 260];
    loop {
        let mut len = buf.len() as u32;
        // SAFETY: `hkey` is valid; `buf` holds `len` `u16`s.
        let code = unsafe {
            RegEnumKeyExW(
                hkey,
                idx,
                Some(PWSTR(buf.as_mut_ptr())),
                &mut len,
                None,
                None,
                None,
                None,
            )
        };
        if code == ERROR_NO_MORE_ITEMS {
            break;
        }
        if code == ERROR_MORE_DATA {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if code != ERROR_SUCCESS {
            break;
        }
        names.push(String::from_utf16_lossy(&buf[..len as usize]));
        idx += 1;
    }
    names
}

fn read_reg_string(hkey: HKEY, value_name: &str) -> Option<String> {
    let name_h = HSTRING::from(value_name);
    let mut val_type = REG_VALUE_TYPE::default();
    let mut byte_len = 0u32;
    // SAFETY: Query required byte size first.
    let code = unsafe { RegQueryValueExW(hkey, &name_h, None, Some(&mut val_type), None, Some(&mut byte_len)) };
    if code != ERROR_SUCCESS || byte_len == 0 {
        return None;
    }
    if val_type != REG_SZ && val_type != REG_EXPAND_SZ {
        return None;
    }
    let mut buf = vec![0u8; byte_len as usize];
    // SAFETY: `buf` has `byte_len` writable bytes.
    let code2 = unsafe {
        RegQueryValueExW(
            hkey,
            &name_h,
            None,
            Some(&mut val_type),
            Some(buf.as_mut_ptr()),
            Some(&mut byte_len),
        )
    };
    if code2 != ERROR_SUCCESS {
        return None;
    }
    let units: Vec<u16> = buf[..byte_len as usize]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    Some(String::from_utf16_lossy(&units))
}

fn expand_env_vars(input: &str) -> String {
    expand_env_vars_with(input, |var| std::env::var(var).ok())
}

fn expand_env_vars_with<F>(input: &str, mut lookup: F) -> String
where
    F: FnMut(&str) -> Option<String>,
{
    let mut out = input.to_string();
    for var in ["SystemRoot", "windir", "ProgramFiles", "ProgramData", "SystemDrive"] {
        if let Some(val) = lookup(var) {
            let token_lower = format!("%{}%", var.to_ascii_lowercase());
            let mut cursor = 0;
            while cursor < out.len() {
                let hay_lower = out[cursor..].to_ascii_lowercase();
                let Some(rel_pos) = hay_lower.find(&token_lower) else {
                    break;
                };
                let start = cursor + rel_pos;
                let end = start + token_lower.len();
                out.replace_range(start..end, &val);
                cursor = start + val.len();
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_env_vars_replaces_all_occurrences_without_rescanning() {
        let input = r"%SystemRoot%\System32\a.dll;%systemroot%\System32\b.dll;%SystemRoot%\System32\c.dll";
        let expanded = expand_env_vars_with(input, |var| {
            if var == "SystemRoot" {
                Some(r"C:\Windows".to_string())
            } else {
                None
            }
        });
        assert_eq!(
            expanded,
            r"C:\Windows\System32\a.dll;C:\Windows\System32\b.dll;C:\Windows\System32\c.dll"
        );

        // Ensure substituted value containing the token is not re-expanded.
        let self_ref = expand_env_vars_with(r"%SystemRoot%\a;%SystemRoot%\b", |var| {
            if var == "SystemRoot" {
                Some(r"C:\%SystemRoot%".to_string())
            } else {
                None
            }
        });
        assert_eq!(self_ref, r"C:\%SystemRoot%\a;C:\%SystemRoot%\b");

        // Also exercise real std::env::var-backed expand_env_vars when SystemRoot is present.
        if let Ok(sys_root) = std::env::var("SystemRoot") {
            let real_expanded = expand_env_vars(r"%SystemRoot%\System32\a.dll;%SystemRoot%\System32\b.dll");
            assert_eq!(
                real_expanded,
                format!(r"{sys_root}\System32\a.dll;{sys_root}\System32\b.dll")
            );
        }
    }

    #[test]
    fn decode_evt_variant_rejects_array_variants() {
        let mut var = EVT_VARIANT {
            Type: (EvtVarTypeString.0 as u32) | EVT_VARIANT_TYPE_ARRAY,
            Count: 2,
            ..Default::default()
        };
        // Populate non-null bogus pointer in Anonymous to prove it is never dereferenced.
        var.Anonymous.UInt64Val = 0xDEAD_BEEF_DEAD_BEEFu64;
        let words = std::mem::size_of::<EVT_VARIANT>().div_ceil(8);
        let mut buf = vec![0u64; words];
        // SAFETY: `buf` has enough space and 8-byte alignment for `EVT_VARIANT`.
        unsafe {
            std::ptr::copy_nonoverlapping(
                std::ptr::from_ref(&var).cast::<u8>(),
                buf.as_mut_ptr().cast::<u8>(),
                std::mem::size_of::<EVT_VARIANT>(),
            );
            assert!(decode_evt_variant(&buf).is_none());
        }
    }

    #[test]
    fn win_error_classification_maps_permission_and_missing_channel() {
        let perm_err = windows::core::Error::from_hresult(ERROR_ACCESS_DENIED.to_hresult());
        assert!(is_permission_win_err(&perm_err));
        assert!(!is_missing_channel_win_err(&perm_err));
        assert!(matches!(
            map_win_error("Security", perm_err),
            ForensicError::PermissionDenied { ref context, .. } if context == "Security"
        ));

        let priv_err = windows::core::Error::from_hresult(ERROR_PRIVILEGE_NOT_HELD.to_hresult());
        assert!(is_permission_win_err(&priv_err));
        assert!(matches!(
            map_win_error("Security", priv_err),
            ForensicError::PermissionDenied { ref context, .. } if context == "Security"
        ));

        let missing_err = windows::core::Error::from_hresult(ERROR_EVT_CHANNEL_NOT_FOUND.to_hresult());
        assert!(!is_permission_win_err(&missing_err));
        assert!(is_missing_channel_win_err(&missing_err));
        assert!(matches!(
            map_win_error("Missing/Channel", missing_err),
            ForensicError::NotFound(ref ch) if ch == "Missing/Channel"
        ));
    }
}
