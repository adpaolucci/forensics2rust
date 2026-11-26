use forensics2rust_core::{DiagnosticWarning, ForensicError};

use crate::model::{ChannelMetadata, EvtxRecord, LiveQueryOptions, SourceMetadata};

/// Non-Windows stub for live `wevtapi` event queries.
pub(crate) fn query_channels(
    _tool_id: &str,
    _channels: &[&str],
    _opts: &LiveQueryOptions,
) -> Result<(Vec<EvtxRecord>, Vec<DiagnosticWarning>), ForensicError> {
    Err(ForensicError::unsupported_platform(
        "live Windows Event Log (wevtapi)",
        "live collection requires Windows; supply OfflinePath or OfflineBytes",
    ))
}

/// Non-Windows stub for live `wevtapi` + Registry channel enumeration.
pub(crate) fn enumerate_channels() -> Result<(Vec<ChannelMetadata>, Vec<DiagnosticWarning>), ForensicError> {
    Err(ForensicError::unsupported_platform(
        "live Windows Event Log (wevtapi)",
        "live channel enumeration requires Windows; supply OfflinePath or OfflineBytes",
    ))
}

/// Non-Windows stub for live `wevtapi` + Registry publisher/source enumeration.
pub(crate) fn enumerate_sources() -> Result<(Vec<SourceMetadata>, Vec<DiagnosticWarning>), ForensicError> {
    Err(ForensicError::unsupported_platform(
        "live Windows Event Log (wevtapi)",
        "live source enumeration requires Windows; supply OfflinePath or OfflineBytes",
    ))
}
