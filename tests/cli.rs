//! Executable E2E tests for exit codes and stdout/stderr separation.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

fn warden(args: &[&str]) -> std::process::Output {
    // `RUST_LOG` inherited from the developer's shell would put log lines on stderr and
    // make the assertions below depend on an environment variable nobody set for them.
    Command::new(env!("CARGO_BIN_EXE_warden"))
        .env_remove("RUST_LOG")
        .args(args)
        .output()
        .expect("failed to execute the warden binary")
}

/// Runs the binary with `RUST_LOG` set, so the tracing subscriber actually emits.
fn warden_logging(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_warden"))
        .env("RUST_LOG", "warden=debug")
        .args(args)
        .output()
        .expect("failed to execute the warden binary")
}

#[test]
fn version_succeeds_and_writes_only_to_stdout() {
    let out = warden(&["version"]);

    assert!(out.status.success(), "status: {:?}", out.status);
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("warden {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(
        out.stderr.is_empty(),
        "stderr should be empty: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn unknown_command_exits_with_usage_code_and_keeps_stdout_clean() {
    // `serv`, not `does-not-exist`, since the subcommand slot now quotes a token back
    // only when it is one edit from a name Warden defines: a bare word in that position
    // is as likely to be a pasted passphrase or token as a typo. The three properties
    // this test was written for are unchanged — usage exit code, silent stdout, and a
    // stderr line that names the mistyped command.
    let out = warden(&["serv"]);

    assert_eq!(out.status.code(), Some(2), "usage-error exit code");
    assert!(
        out.stdout.is_empty(),
        "docs/mcp.md section 5.1 and docs/operations.md section 12.1 reserve \
         stdout for protocol data; stdout contained: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("serv"), "stderr: {stderr}");
}

#[test]
fn a_bare_word_in_the_subcommand_slot_is_refused_without_reaching_stderr() {
    // The other end of the same rule, at the process boundary: a supervisor collecting
    // this binary's stderr must not end up holding a passphrase somebody pasted one
    // argument too early.
    let secret = "correct-horse-battery-staple";
    let out = warden(&[secret]);

    assert_eq!(out.status.code(), Some(2), "usage-error exit code");
    assert!(out.stdout.is_empty(), "stdout: {:?}", out.stdout);
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(!stderr.contains(secret), "stderr: {stderr}");
    assert!(stderr.contains("warden help"), "stderr: {stderr}");
}

#[test]
fn no_argument_exits_with_usage_code() {
    let out = warden(&[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        !stderr.is_empty() && stderr.contains("warden"),
        "stderr: {stderr}"
    );
}

#[test]
fn logging_goes_to_stderr_so_stdout_stays_a_protocol_stream() {
    // `tracing_subscriber::fmt()` writes to stdout unless told otherwise, and no lint
    // catches that: `clippy::print_stdout` sees a library call, not a `println!`. This is
    // the mechanical check that `src/main.rs` named the other writer
    // (`docs/mcp.md` section 5.1).
    let out = warden_logging(&["version"]);

    assert!(out.status.success(), "status: {:?}", out.status);
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("warden {}\n", env!("CARGO_PKG_VERSION")),
        "stdout carried something other than the command's own output"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("warden starting"), "stderr: {stderr}");
}

/// Writes a configuration file to a unique path and returns it.
///
/// The subprocess needs a real path, and the workspace has no temporary-file
/// dependency; a name carrying the process id and a counter keeps concurrent test
/// binaries from colliding. Callers remove the file when the assertion is done.
fn write_temp_config(contents: &str) -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);

    let path = std::env::temp_dir().join(format!(
        "warden-cli-{}-{}.toml",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, contents).expect("failed to write the temporary configuration");
    path
}

#[test]
fn an_unusable_configuration_fails_serve_with_a_diagnostic_and_a_silent_stdout() {
    // stdout is the MCP transport. A startup failure that printed to it would corrupt
    // the stream for a client that had already connected (docs/mcp.md section 5.1).
    let output = warden(&["serve", "--config", "/nonexistent/warden.toml"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout: {:?}", output.stdout);
    assert!(String::from_utf8_lossy(&output.stderr).contains("/nonexistent/warden.toml"));
}

#[test]
fn check_reports_a_configuration_error_and_exits_non_zero() {
    let path = write_temp_config("version = 99\n");
    let output = warden(&["check", "--config", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);

    assert!(!output.status.success());
    // The same discipline the serve test asserts: a diagnostic never reaches stdout,
    // whichever subcommand raised it (docs/mcp.md section 5.1).
    assert!(output.stdout.is_empty(), "stdout: {:?}", output.stdout);
    assert!(String::from_utf8_lossy(&output.stderr).contains("version"));
}

#[test]
fn an_unknown_subcommand_still_exits_with_the_usage_code() {
    assert_eq!(warden(&["serv"]).status.code(), Some(2));
}
