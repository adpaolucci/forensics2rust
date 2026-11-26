use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ForensicError;

/// Source of forensic data for a DFIR provider: either live OS/API inspection
/// or deterministic offline analysis of an artifact path or raw byte buffer.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ForensicSource {
    #[default]
    Live,
    OfflinePath(PathBuf),
    OfflineBytes(Vec<u8>),
}

impl ForensicSource {
    /// Builds a `ForensicSource::OfflinePath` when `Some(path)` is supplied,
    /// or `ForensicSource::Live` when `None`.
    pub fn from_optional_path(path: Option<PathBuf>) -> Self {
        match path {
            Some(p) => Self::OfflinePath(p),
            None => Self::Live,
        }
    }

    /// Returns `true` when configured for live Windows OS collection.
    pub fn is_live(&self) -> bool {
        matches!(self, Self::Live)
    }

    /// Returns `true` when backed by an offline file path or raw byte buffer.
    pub fn is_offline(&self) -> bool {
        !self.is_live()
    }

    /// Returns the filesystem path if this source is `OfflinePath`.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::OfflinePath(p) => Some(p.as_path()),
            Self::Live | Self::OfflineBytes(_) => None,
        }
    }

    /// Human-readable diagnostic label describing the source.
    pub fn label(&self) -> String {
        match self {
            Self::Live => "live".to_string(),
            Self::OfflinePath(p) => p.display().to_string(),
            Self::OfflineBytes(bytes) => format!("<memory:{} bytes>", bytes.len()),
        }
    }

    /// Reads raw bytes from an offline path or in-memory buffer.
    ///
    /// Returns `ForensicError::InvalidArgument` for `Live` sources and
    /// classifies filesystem errors into `NotFound`, `PermissionDenied`, or `Io`.
    pub fn read_bytes(&self) -> Result<Vec<u8>, ForensicError> {
        match self {
            Self::Live => Err(ForensicError::InvalidArgument(
                "cannot read raw bytes from Live source; supply an offline artifact path or buffer".to_string(),
            )),
            Self::OfflinePath(path) => {
                std::fs::read(path).map_err(|err| ForensicError::io_classified(path.display().to_string(), err))
            }
            Self::OfflineBytes(bytes) => Ok(bytes.clone()),
        }
    }
}
