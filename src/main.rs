//! Warden composition root.
//!
//! This is the only process-level code that resolves `std::env::args()`, selects real
//! descriptors, and maps errors to exit codes. Every other component receives its
//! dependencies explicitly (`docs/architecture.md` section 2; SPEC section 4).

mod cli;

use std::io::{self, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args = std::env::args().skip(1);

    let command = match cli::parse(args) {
        Ok(command) => command,
        Err(error) => {
            // Diagnostics use stderr because stdout is reserved for MCP.
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "warden: {error}");
            return ExitCode::from(cli::EXIT_USAGE);
        }
    };

    let mut stdout = io::stdout().lock();
    match cli::run(command, &mut stdout) {
        Ok(()) => match stdout.flush() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                let mut stderr = io::stderr().lock();
                let _ = writeln!(stderr, "warden: failed to write output: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "warden: {error}");
            ExitCode::FAILURE
        }
    }
}
