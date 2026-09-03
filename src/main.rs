//! Warden composition root.
//!
//! This is the only process-level code that resolves `std::env::args()`, selects real
//! descriptors, and maps errors to exit codes. Every other component receives its
//! dependencies explicitly (`docs/architecture.md` section 2; SPEC section 4).

mod audit;
mod check;
mod cli;
mod startup;

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use tokio_util::sync::CancellationToken;

use crate::cli::{Command, Transport};

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

    match command {
        Command::Serve { config, transport } => report(block_on(run_serve(&config, transport))),
        Command::Check { config } => report(block_on(run_check(&config))),
        immediate => run_immediate(immediate),
    }
}

/// Runs one async subcommand on the process's one runtime.
///
/// `main` stays synchronous rather than wearing `#[tokio::main]`: `version` and `help`
/// answer without a runtime, and a macro on `main` would start a thread pool to print a
/// version string.
fn block_on<F>(command: F) -> Result<ExitCode>
where
    F: Future<Output = Result<ExitCode>>,
{
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("the Tokio runtime could not be started")?
        .block_on(command)
}

/// Serves the MCP tools until the client disconnects or the process is asked to stop.
async fn run_serve(config: &Path, transport: Transport) -> Result<ExitCode> {
    let resolved = warden_config::load_from_path(config)
        .with_context(|| format!("configuration {} could not be used", config.display()))?;

    // Before anything opens a socket, and on stderr: the same sentence `warden check`
    // prints (`docs/mcp.md` section 7).
    for warning in check::stdio_exposure_warnings(&resolved) {
        tracing::warn!(target: "warden.startup", "{warning}");
    }

    // One root token for the process. Every service child token descends from it, so
    // cancelling it here stops an in-flight request too (`docs/architecture.md`
    // section 12).
    let shutdown = CancellationToken::new();
    let deployment = startup::build(resolved, shutdown.clone()).await?;

    let signals = tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_shutdown_signal().await;
            tracing::info!(target: "warden", "a shutdown signal arrived; draining");
            shutdown.cancel();
        }
    });

    let session = match transport {
        Transport::Stdio => warden_mcp::serve_stdio(deployment.server(), shutdown).await,
    };

    // The signal task has nothing left to cancel, and its handle is dropped here rather
    // than left to outlive the runtime it was spawned on.
    signals.abort();
    // `docs/architecture.md` section 13: cancel, then close both pools per connection
    // under a bounded wait. This runs whether the session ended at EOF or in failure.
    deployment.close().await;

    session.context("the MCP session did not complete")?;
    Ok(ExitCode::SUCCESS)
}

/// Validates the configuration and probes every connection it names.
///
/// The report goes to **stderr**. It is a diagnostic, and the one rule this binary cannot
/// bend is that stdout carries MCP and nothing else (`docs/mcp.md` section 5.1): a
/// command whose output habit differs from `serve`'s is a command that eventually prints
/// into a protocol stream. `warden check`'s answer is its exit code; the lines explain it.
async fn run_check(config: &Path) -> Result<ExitCode> {
    let mut stderr = io::stderr().lock();
    let clean = check::run(config, &mut stderr).await?;
    writeln!(
        stderr,
        "{}",
        if clean {
            "warden check: every check passed"
        } else {
            "warden check: every check passed, with warnings"
        }
    )?;
    // A warning describes a deployment an operator may have chosen; only a failed check
    // is a non-zero exit.
    Ok(ExitCode::SUCCESS)
}

/// Waits for `SIGINT` or, on Unix, `SIGTERM`.
#[cfg(unix)]
async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    match signal(SignalKind::terminate()) {
        Ok(mut terminate) => {
            tokio::select! {
                _ = terminate.recv() => {}
                () = interrupt_or_never() => {}
            }
        }
        Err(error) => {
            tracing::warn!(
                target: "warden",
                %error,
                "SIGTERM cannot be handled; only an interrupt will stop this process"
            );
            interrupt_or_never().await;
        }
    }
}

/// Waits for `SIGINT`.
#[cfg(not(unix))]
async fn wait_for_shutdown_signal() {
    interrupt_or_never().await;
}

/// Waits for an interrupt, or forever if the handler cannot be installed.
///
/// Returning on the failure would report a signal nobody sent, and the caller's only
/// reaction to this future completing is to shut the process down.
async fn interrupt_or_never() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(
            target: "warden",
            %error,
            "the interrupt handler is unavailable; this process will not stop on Ctrl-C"
        );
        std::future::pending::<()>().await;
    }
}

/// Runs the subcommands that answer from memory, on stdout.
fn run_immediate(command: Command) -> ExitCode {
    let mut stdout = io::stdout().lock();
    match cli::run(command, &mut stdout).and_then(|()| stdout.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "warden: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Maps a subcommand's outcome to an exit code, reporting a failure on stderr.
///
/// `{error:#}` renders the whole `anyhow` chain through `Display`. `Debug` would print
/// the adapter detail that `ConnectError`'s `Display` deliberately omits, which is where a
/// host and a database user would enter an operator's terminal (`src/startup.rs`).
fn report(outcome: Result<ExitCode>) -> ExitCode {
    match outcome {
        Ok(code) => code,
        Err(error) => {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "warden: {error:#}");
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
