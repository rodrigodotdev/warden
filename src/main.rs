//! Warden composition root.
//!
//! This is the only process-level code that resolves `std::env::args()`, selects real
//! descriptors, and maps errors to exit codes. Every other component receives its
//! dependencies explicitly (`docs/architecture.md` section 2; SPEC section 4).

mod audit;
mod cli;
mod startup;

use std::io::{self, Write};
use std::process::ExitCode;

/// The filter used when `RUST_LOG` says nothing.
///
/// Warden's own events at `info`, which is the level `crate::audit` writes every attempt
/// and outcome at, and everything else — `sqlx`, `rmcp`, `hyper` — only when it warns.
/// The prefix `warden` covers both the crate targets (`warden_service::query`) and the
/// dotted ones (`warden.audit`, `warden.mcp`).
const DEFAULT_LOG_FILTER: &str = "warn,warden=info";

fn main() -> ExitCode {
    install_tracing();
    // Not a banner: `docs/mcp.md` section 5.1 forbids printing one, and this is a
    // `debug` event on stderr that the default filter above does not even enable.
    tracing::debug!(
        target: "warden",
        version = env!("CARGO_PKG_VERSION"),
        "warden starting"
    );

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

/// Installs the process's one tracing subscriber, writing to **stderr**.
///
/// This is the first step of `docs/architecture.md` section 12, and the half of
/// "stdout carries MCP and nothing else" that no lint can enforce:
/// `tracing_subscriber::fmt()` defaults to stdout, so naming the writer here is what
/// keeps a log line out of a JSON-RPC stream (`docs/mcp.md` section 5.1). The other
/// half, `clippy::print_stdout = "deny"`, catches a stray `println!` at build time.
///
/// `docs/operations.md` section 10.3 asks for one logging ecosystem, so this is the only
/// subscriber the process installs.
fn install_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(
        |_invalid_or_absent| tracing_subscriber::EnvFilter::new(DEFAULT_LOG_FILTER),
    );
    if let Err(error) = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .try_init()
    {
        // The only way to reach this is a subscriber already installed, which `main`
        // cannot do twice. Reported rather than swallowed, and reported on stderr.
        let mut stderr = io::stderr().lock();
        let _ = writeln!(stderr, "warden: could not install logging: {error}");
    }
}
