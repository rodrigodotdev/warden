//! Argument parsing and subcommand execution.
//!
//! This module receives collected arguments and writes to `&mut dyn Write` rather
//! than accessing process globals. This keeps `clippy::print_stdout = "deny"`
//! effective and makes all CLI output unit-testable.
//!
//! `src/main.rs` alone resolves `std::env::args()` and selects real descriptors,
//! making it the composition root described in `docs/architecture.md` section 2.

use std::fmt;
use std::io::{self, Write};

/// Exit code for command-line usage errors.
///
/// Bash and GNU coreutils conventionally use 2 for incorrect usage. This is not
/// `EX_USAGE` from `sysexits.h`, which is 64; Warden does not claim sysexits
/// compatibility.
///
/// The `u8` type feeds `ExitCode::from` without a cast.
pub(crate) const EXIT_USAGE: u8 = 2;

/// Available subcommands.
///
/// This set is intentionally closed. Adding `Serve` or `Check` in later milestones
/// breaks the exhaustive match in `run` until behavior is implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    Version,
    Help,
}

/// Command-line parsing failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CliError {
    /// No subcommand was provided.
    MissingCommand,
    /// The subcommand does not exist. Contains only its name, never later arguments
    /// that might contain a DSN.
    UnknownCommand(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCommand => {
                write!(f, "no command provided; use `warden help`")
            }
            Self::UnknownCommand(name) => {
                write!(f, "unknown command: `{name}`; use `warden help`")
            }
        }
    }
}

impl std::error::Error for CliError {}

/// Parses arguments supplied **without** `argv[0]`.
pub(crate) fn parse<I>(args: I) -> Result<Command, CliError>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let Some(first) = args.next() else {
        return Err(CliError::MissingCommand);
    };

    match first.as_str() {
        "version" | "--version" | "-V" => Ok(Command::Version),
        "help" | "--help" | "-h" => Ok(Command::Help),
        other => Err(CliError::UnknownCommand(other.to_owned())),
    }
}

/// Executes the subcommand and writes to `out`.
pub(crate) fn run(command: Command, out: &mut dyn Write) -> io::Result<()> {
    match command {
        Command::Version => writeln!(out, "warden {}", env!("CARGO_PKG_VERSION")),
        Command::Help => write!(out, "{HELP}"),
    }
}

const HELP: &str = "\
warden — secure, read-only, auditable query gateway for AI agents

USAGE:
    warden <command>

COMMANDS:
    version    Show the version
    help       Show this message
";

#[cfg(test)]
mod tests {
    // Keeping this exception test-local makes production uses visible in diffs.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parses_the_version_command() {
        assert_eq!(parse(args(&["version"])).unwrap(), Command::Version);
    }

    #[test]
    fn parses_the_help_command_and_its_flags() {
        assert_eq!(parse(args(&["help"])).unwrap(), Command::Help);
        assert_eq!(parse(args(&["--help"])).unwrap(), Command::Help);
        assert_eq!(parse(args(&["-h"])).unwrap(), Command::Help);
    }

    #[test]
    fn no_argument_is_a_missing_command_error() {
        assert_eq!(parse(args(&[])).unwrap_err(), CliError::MissingCommand);
    }

    #[test]
    fn unknown_command_is_reported_with_its_name() {
        assert_eq!(
            parse(args(&["serv"])).unwrap_err(),
            CliError::UnknownCommand("serv".to_owned())
        );
    }

    #[test]
    fn unknown_command_error_does_not_echo_extra_arguments() {
        let err = parse(args(&["serv", "postgres://user:password@host/db"])).unwrap_err();
        let rendered = err.to_string();
        assert!(
            !rendered.contains("password"),
            "error leaked an argument: {rendered}"
        );
        assert!(
            !rendered.contains("postgres://"),
            "error leaked an argument: {rendered}"
        );
    }

    #[test]
    fn version_writes_name_and_version_and_nothing_else() {
        let mut out = Vec::new();
        run(Command::Version, &mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("warden {}\n", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn help_lists_every_command_variant() {
        let mut out = Vec::new();
        run(Command::Help, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        for expected in ["version", "help"] {
            assert!(
                text.contains(expected),
                "help does not mention `{expected}`:\n{text}"
            );
        }
    }
}
