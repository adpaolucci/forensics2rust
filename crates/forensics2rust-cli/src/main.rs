#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser;
use forensics2rust_cli::{Cli, run_cli};
use forensics2rust_core::init_logging;

fn init_signal_handler() {
    let _ = ctrlc::set_handler(|| {
        eprintln!("[forensics2rust] interrupt received; exiting cleanly.");
        std::process::exit(130);
    });
}

fn main() -> ExitCode {
    init_signal_handler();
    let cli = Cli::parse();
    if let Err(err) = init_logging(&cli.log_level, cli.log_file.as_deref()) {
        eprintln!("logging initialization error: {err}");
        return ExitCode::FAILURE;
    }

    match run_cli(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
