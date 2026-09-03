//! Executable E2E tests for exit codes and stdout/stderr separation.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

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
    let out = warden(&["does-not-exist"]);

    assert_eq!(out.status.code(), Some(2), "usage-error exit code");
    assert!(
        out.stdout.is_empty(),
        "docs/mcp.md section 5.1 and docs/operations.md section 12.1 reserve \
         stdout for protocol data; stdout contained: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("does-not-exist"), "stderr: {stderr}");
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
