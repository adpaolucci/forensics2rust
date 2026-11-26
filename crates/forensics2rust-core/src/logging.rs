use std::path::Path;

use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use crate::error::ForensicError;

/// Initializes `tracing_subscriber` writing structured diagnostics to `stderr`
/// (preserving clean `stdout` for CLI output and JSON-RPC `stdio` MCP streams),
/// and optionally appends non-ANSI logs to `log_file`.
///
/// Safe to call multiple times in tests (subsequent initializations are ignored).
pub fn init_logging(log_level: &str, log_file: Option<&Path>) -> Result<(), ForensicError> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    let stderr_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false);

    let registry = tracing_subscriber::registry().with(filter).with(stderr_layer);

    if let Some(file_path) = log_file {
        if let Some(parent) = file_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|err| ForensicError::io_classified(parent.display().to_string(), err))?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path)
            .map_err(|err| ForensicError::io_classified(file_path.display().to_string(), err))?;
        let file_layer = fmt::layer().with_ansi(false).with_writer(file);
        let _ = registry.with(file_layer).try_init();
    } else {
        let _ = registry.try_init();
    }

    Ok(())
}
