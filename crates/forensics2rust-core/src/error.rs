use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Unified error type across all `forensics2rust` domain and surface crates.
#[derive(Debug, Error)]
pub enum ForensicError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("parse error in {context}: {message}")]
    Parse { context: String, message: String },

    #[error("permission denied ({context}): {message}")]
    PermissionDenied { context: String, message: String },

    #[error("unsupported platform for {feature}: {message}")]
    UnsupportedPlatform { feature: String, message: String },

    #[error("artifact not found: {0}")]
    NotFound(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error(transparent)]
    Table(#[from] guap_table::TableError),
}

impl ForensicError {
    pub fn io(path: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    /// Classifies an `std::io::Error` into `NotFound`, `PermissionDenied`, or `Io`.
    pub fn io_classified(path: impl Into<String>, source: std::io::Error) -> Self {
        let path_str = path.into();
        if source.kind() == std::io::ErrorKind::NotFound {
            Self::NotFound(path_str)
        } else if is_elevation_error(&source) {
            Self::PermissionDenied {
                context: path_str,
                message: source.to_string(),
            }
        } else {
            Self::Io { path: path_str, source }
        }
    }

    pub fn parse(context: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Parse {
            context: context.into(),
            message: message.into(),
        }
    }

    pub fn permission_denied(context: impl Into<String>, message: impl Into<String>) -> Self {
        Self::PermissionDenied {
            context: context.into(),
            message: message.into(),
        }
    }

    pub fn unsupported_platform(feature: impl Into<String>, message: impl Into<String>) -> Self {
        Self::UnsupportedPlatform {
            feature: feature.into(),
            message: message.into(),
        }
    }

    /// Maps `&ForensicError` into `guap_table::TableError`, preserving query/param error
    /// classifications and attaching actionable remediation guidance on elevation/missing
    /// artifact conditions.
    pub fn to_table_error(&self) -> guap_table::TableError {
        match self {
            Self::Table(err) => match err {
                guap_table::TableError::InvalidColumn(s) => guap_table::TableError::InvalidColumn(s.clone()),
                guap_table::TableError::InvalidColumnIndex(i) => guap_table::TableError::InvalidColumnIndex(*i),
                guap_table::TableError::InvalidRegex(e) => guap_table::TableError::QueryParse(e.to_string()),
                guap_table::TableError::QueryParse(s) => guap_table::TableError::QueryParse(s.clone()),
                guap_table::TableError::SchemaMismatch(s) => guap_table::TableError::SchemaMismatch(s.clone()),
                guap_table::TableError::InvalidKeyColumns(s) => guap_table::TableError::InvalidKeyColumns(s.clone()),
                guap_table::TableError::Provider(s) => guap_table::TableError::Provider(s.clone()),
            },
            Self::InvalidArgument(msg) => guap_table::TableError::QueryParse(msg.clone()),
            Self::PermissionDenied { context, message } => guap_table::TableError::Provider(format!(
                "permission denied ({context}; run elevated or supply an offline artifact path): {message}"
            )),
            Self::NotFound(path) => guap_table::TableError::Provider(format!("forensic artifact not found: {path}")),
            Self::UnsupportedPlatform { feature, message } => {
                guap_table::TableError::Provider(format!("unsupported platform for {feature}: {message}"))
            }
            Self::Parse { context, message } => {
                guap_table::TableError::Provider(format!("parse error in {context}: {message}"))
            }
            Self::Io { path, source } => guap_table::TableError::Provider(format!("I/O error at {path}: {source}")),
        }
    }
}

impl From<ForensicError> for guap_table::TableError {
    fn from(err: ForensicError) -> Self {
        match err {
            ForensicError::Table(table_err) => table_err,
            other => other.to_table_error(),
        }
    }
}

/// Returns `true` if the OS I/O error represents an access-denied / privilege-not-held condition
/// (Windows `ERROR_ACCESS_DENIED = 5`, `ERROR_PRIVILEGE_NOT_HELD = 1314`, or `PermissionDenied`).
pub fn is_elevation_error(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::PermissionDenied || matches!(err.raw_os_error(), Some(5 | 1314))
}

/// Severity level for non-fatal degraded DFIR collection warnings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WarningSeverity {
    Info,
    Warn,
    Error,
}

/// Structured non-fatal warning emitted during degraded or partial DFIR collection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticWarning {
    pub severity: WarningSeverity,
    pub tool_id: String,
    pub source: String,
    pub message: String,
}
