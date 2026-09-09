//! Executable E2E tests for exit codes and stdout/stderr separation.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

#[cfg(unix)]
use std::process::Stdio;

fn warden(args: &[&str]) -> std::process::Output {
    // `RUST_LOG` inherited from the developer's shell would put log lines on stderr and
    // make the assertions below depend on an environment variable nobody set for them.
    Command::new(env!("CARGO_BIN_EXE_warden"))
        .env_remove("RUST_LOG")
        .args(args)
        .output()
        .expect("failed to execute the warden binary")
}

/// Runs the binary from `directory`, for the commands whose answer depends on one.
///
/// `mcp-config` resolves a relative `--config` against the working directory, so the
/// only way to assert what it emits is to choose that directory rather than inherit
/// the crate root the test harness happens to run in.
fn warden_in(directory: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_warden"))
        .env_remove("RUST_LOG")
        .current_dir(directory)
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

/// Creates a unique, empty directory under the system temporary directory.
///
/// `init` needs a directory rather than a bare file path so the test can remove
/// everything it created in one call; a name carrying the process id and a counter
/// keeps concurrent test binaries from colliding, the same scheme `write_temp_config`
/// uses for its file names.
fn unique_temp_dir(label: &str) -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);

    let directory = std::env::temp_dir().join(format!(
        "warden-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&directory).expect("failed to create the temporary directory");
    directory
}

/// The `--config` value from a rendered `mcp-config` block.
///
/// The path is positional inside `args`, so reading it by index would pass just as
/// happily if the flag before it changed; this finds the flag and takes what follows.
fn config_argument(parsed: &serde_json::Value) -> &str {
    let args = parsed["mcpServers"]["warden"]["args"]
        .as_array()
        .expect("the block has an args array");
    let flag = args
        .iter()
        .position(|argument| argument == "--config")
        .expect("the block passes --config");
    args.get(flag + 1)
        .and_then(serde_json::Value::as_str)
        .expect("--config is followed by a path")
}

#[test]
fn init_writes_a_configuration_that_does_not_exist_yet() {
    let directory = unique_temp_dir("init");
    let path = directory.join("warden.toml");

    let output = warden(&["init", "--config", path.to_str().unwrap()]);

    assert!(output.status.success(), "{output:?}");
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(written.contains("dsn_env"), "{written}");
    // Diagnostics belong on stderr; stdout stays a protocol stream.
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(!output.stderr.is_empty(), "{output:?}");

    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn init_refuses_to_overwrite_an_existing_configuration() {
    let directory = unique_temp_dir("init-exists");
    let path = directory.join("warden.toml");
    std::fs::write(&path, "version = 1\n").unwrap();

    let output = warden(&["init", "--config", path.to_str().unwrap()]);

    assert!(!output.status.success(), "{output:?}");
    // The operator's file is untouched: refusing is what makes `init` safe to re-run.
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "version = 1\n");

    std::fs::remove_dir_all(&directory).unwrap();
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
fn check_reports_an_audit_destination_that_cannot_be_opened_and_exits_non_zero() {
    let path = write_temp_config("");
    let missing_directory = path.with_file_name(format!(
        "{}-missing-audit-directory",
        path.file_name().unwrap().to_string_lossy()
    ));
    let audit_path = missing_directory.join("audit.jsonl");
    let config = format!(
        r#"version = 1

[[connections]]
name = "db"
dialect = "mysql"
environment = "development"
database = "app"
dsn_env = "WARDEN_TEST_DSN"
policy = "p"

[policies.p]

[audit]
destination = "file"
path = "{}"
"#,
        audit_path.display()
    );
    std::fs::write(&path, config).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_warden"))
        .env_remove("RUST_LOG")
        .env("WARDEN_TEST_DSN", "mysql://warden_ro:pw@127.0.0.1:1/app")
        .args(["check", "--config", path.to_str().unwrap()])
        .output()
        .expect("failed to execute the warden binary");
    let _ = std::fs::remove_file(&path);

    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout: {:?}", output.stdout);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains(&format!(
            "FAIL  the audit trail at {} could not be opened",
            audit_path.display()
        )),
        "stderr: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn check_rejects_the_regular_file_backing_stdout_without_contaminating_it() {
    let path = write_temp_config("");
    let stdout_path = write_temp_config("");
    let config = format!(
        r#"version = 1

[[connections]]
name = "db"
dialect = "mysql"
environment = "development"
database = "app"
dsn_env = "WARDEN_TEST_DSN"
policy = "p"

[policies.p]

[audit]
destination = "file"
path = "{}"
"#,
        stdout_path.display()
    );
    std::fs::write(&path, config).unwrap();
    let stdout = std::fs::File::create(&stdout_path).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_warden"))
        .env_remove("RUST_LOG")
        .env("WARDEN_TEST_DSN", "mysql://warden_ro:pw@127.0.0.1:1/app")
        .args(["check", "--config", path.to_str().unwrap()])
        .stdout(Stdio::from(stdout))
        .output()
        .expect("failed to execute the warden binary");
    let stdout_contents = std::fs::read(&stdout_path).unwrap();
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&stdout_path);

    assert!(!output.status.success());
    assert!(stdout_contents.is_empty(), "stdout: {stdout_contents:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains(&format!(
            "FAIL  the audit trail at {} could not be opened",
            stdout_path.display()
        )),
        "stderr: {stderr}"
    );
}

#[test]
fn an_unknown_subcommand_still_exits_with_the_usage_code() {
    assert_eq!(warden(&["serv"]).status.code(), Some(2));
}

#[test]
fn role_prints_sql_on_stdout_so_it_can_be_piped_into_a_database_console() {
    let output = warden(&[
        "role",
        "--dialect",
        "postgresql",
        "--user",
        "warden_ro",
        "--database",
        "app",
    ]);

    assert!(output.status.success(), "{output:?}");
    let sql = String::from_utf8(output.stdout).unwrap();
    assert!(
        sql.contains("GRANT SELECT ON ALL TABLES IN SCHEMA public TO warden_ro;"),
        "{sql}"
    );
    assert!(output.stderr.is_empty(), "stderr should be silent");
}

#[test]
fn mcp_config_prints_a_block_naming_the_binary_that_printed_it() {
    let directory = unique_temp_dir("mcp-config");
    std::fs::write(directory.join("warden.toml"), "version = 1\n").unwrap();

    let output = warden_in(&directory, &["mcp-config"]);

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let rendered = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    let command = parsed["mcpServers"]["warden"]["command"].as_str().unwrap();

    // The point of the command: an absolute path the client can spawn from any
    // working directory.
    assert!(Path::new(command).is_absolute(), "{rendered}");
    assert!(
        command.ends_with("warden") || command.ends_with("warden.exe"),
        "{rendered}"
    );
    // And the half the command exists for. A client resolves `--config` against a
    // working directory nobody chose, so a relative path here is the failure this
    // block is meant to prevent — asserting only the command path passes in exactly
    // that degraded state.
    assert!(
        Path::new(config_argument(&parsed)).is_absolute(),
        "{rendered}"
    );

    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn mcp_config_is_absolute_even_where_the_configuration_does_not_exist_yet() {
    // An operator who runs this before `init`, or from anywhere but the directory
    // holding the file, still gets a block a client can spawn: `canonicalize` cannot
    // resolve a file that is not there, and the relative default it would fall back to
    // fails at spawn time with nothing to explain it.
    let directory = unique_temp_dir("mcp-config-missing");

    let output = warden_in(&directory, &["mcp-config"]);

    assert!(output.status.success(), "{output:?}");
    let rendered = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    let config = config_argument(&parsed);
    assert!(Path::new(config).is_absolute(), "{rendered}");
    assert!(config.ends_with("warden.toml"), "{rendered}");

    // The missing file is worth a word, and that word belongs on stderr: stdout is the
    // block an operator pipes into a client's configuration.
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("does not exist yet"), "{stderr}");

    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn role_refuses_public_as_a_user_before_it_can_emit_a_grant_to_everyone() {
    // The whole script matters here, not just the exit code: `CREATE ROLE PUBLIC` fails
    // and psql continues without `ON_ERROR_STOP=1`, so a `GRANT … TO PUBLIC` reaching
    // stdout would hand `SELECT` on the whole schema to every role in the database.
    for user in ["public", "PUBLIC"] {
        let output = warden(&[
            "role",
            "--dialect",
            "postgresql",
            "--user",
            user,
            "--database",
            "app",
        ]);

        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
    }
}

#[test]
fn role_refuses_a_hostile_identifier_with_the_usage_code() {
    let output = warden(&[
        "role",
        "--dialect",
        "postgresql",
        "--user",
        "warden_ro; DROP TABLE users --",
        "--database",
        "app",
    ]);

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains("DROP TABLE"), "{stderr}");
}
