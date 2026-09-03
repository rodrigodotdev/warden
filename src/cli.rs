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
use std::path::PathBuf;

/// Exit code for command-line usage errors.
///
/// Bash and GNU coreutils conventionally use 2 for incorrect usage. This is not
/// `EX_USAGE` from `sysexits.h`, which is 64; Warden does not claim sysexits
/// compatibility.
///
/// The `u8` type feeds `ExitCode::from` without a cast.
pub(crate) const EXIT_USAGE: u8 = 2;

/// The configuration file both `serve` and `check` read when `--config` is absent.
///
/// A relative name, resolved against the working directory: `docs/operations.md`
/// section 11 shows every command without a path, and a deployment that keeps its
/// configuration elsewhere passes `--config`.
pub(crate) const DEFAULT_CONFIG_PATH: &str = "warden.toml";

/// Available subcommands.
///
/// This set is intentionally closed. A new one breaks the exhaustive match in `run`
/// until its behavior is implemented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Command {
    /// Print the version.
    Version,
    /// Print the usage summary.
    Help,
    /// Serve the five MCP tools over the selected transport.
    Serve {
        /// The configuration file to read.
        config: PathBuf,
        /// The transport to serve on.
        transport: Transport,
    },
    /// Validate the configuration and probe every configured connection.
    Check {
        /// The configuration file to read.
        config: PathBuf,
    },
}

/// The transports `warden serve` can carry MCP over.
///
/// One variant today. `docs/operations.md` section 11 documents `--transport http`
/// too, and Milestone 14 is where `rmcp`'s streamable-HTTP server feature and the
/// authorization model that has to come with it are enabled; until then the flag is
/// parsed and refused by name rather than silently ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transport {
    /// The process's own stdin and stdout.
    Stdio,
}

/// Command-line parsing failures.
///
/// Every variant names a flag or a subcommand and never the argument after it, which
/// on this command line is the one place a DSN could appear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CliError {
    /// No subcommand was provided.
    MissingCommand,
    /// The subcommand does not exist. Contains only its name, never later arguments
    /// that might contain a DSN.
    UnknownCommand(String),
    /// A flag this command accepts was the last argument, so its value is missing.
    MissingValue {
        /// The flag left without a value. One of Warden's own literals, never input.
        flag: &'static str,
    },
    /// The subcommand does not accept this flag. Contains the flag, never its value.
    UnknownFlag {
        /// The flag as written.
        flag: String,
    },
    /// `--transport` named a transport this build does not serve.
    UnsupportedTransport {
        /// The transport as written. A transport name is not a secret.
        name: String,
    },
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
            Self::MissingValue { flag } => {
                write!(f, "`{flag}` needs a value; use `warden help`")
            }
            Self::UnknownFlag { flag } => {
                write!(f, "unknown flag: `{flag}`; use `warden help`")
            }
            Self::UnsupportedTransport { name } => {
                write!(
                    f,
                    "unsupported transport: `{name}`; this build serves `stdio` only, \
                     and the HTTP transport arrives in Milestone 14"
                )
            }
        }
    }
}

impl std::error::Error for CliError {}

/// Parses arguments supplied **without** `argv[0]`.
///
/// Hand-written on purpose: `docs/operations.md` section 11 asks for no heavyweight CLI
/// framework until argument complexity justifies one, and four subcommands sharing two
/// flags do not.
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
        "serve" => parse_serve(args),
        "check" => parse_check(args),
        other => Err(CliError::UnknownCommand(other.to_owned())),
    }
}

/// Parses `serve`'s `--config` and `--transport`, in either order.
fn parse_serve<I>(mut args: I) -> Result<Command, CliError>
where
    I: Iterator<Item = String>,
{
    let mut config = None;
    let mut transport = Transport::Stdio;

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--config" => config = Some(PathBuf::from(value_of("--config", &mut args)?)),
            "--transport" => transport = value_of("--transport", &mut args)?.parse()?,
            _ => return Err(CliError::UnknownFlag { flag: argument }),
        }
    }

    Ok(Command::Serve {
        config: config.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH)),
        transport,
    })
}

/// Parses `check`'s `--config`.
fn parse_check<I>(mut args: I) -> Result<Command, CliError>
where
    I: Iterator<Item = String>,
{
    let mut config = None;

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--config" => config = Some(PathBuf::from(value_of("--config", &mut args)?)),
            _ => return Err(CliError::UnknownFlag { flag: argument }),
        }
    }

    Ok(Command::Check {
        config: config.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH)),
    })
}

/// Takes the argument after `flag`, or reports the flag that had none.
///
/// `flag` is the matched literal rather than the string the operator typed, which is
/// what keeps [`CliError::MissingValue`] a `&'static str` and unable to echo input.
fn value_of<I>(flag: &'static str, args: &mut I) -> Result<String, CliError>
where
    I: Iterator<Item = String>,
{
    args.next().ok_or(CliError::MissingValue { flag })
}

impl std::str::FromStr for Transport {
    type Err = CliError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "stdio" => Ok(Self::Stdio),
            other => Err(CliError::UnsupportedTransport {
                name: other.to_owned(),
            }),
        }
    }
}

/// Executes the subcommands that need neither a runtime nor a database, writing to `out`.
///
/// `serve` and `check` are async and are dispatched by `main`, which owns the Tokio
/// runtime and the process's real descriptors; reaching them here means that dispatch is
/// broken, so this reports it rather than succeeding silently.
pub(crate) fn run(command: Command, out: &mut dyn Write) -> io::Result<()> {
    match command {
        Command::Version => writeln!(out, "warden {}", env!("CARGO_PKG_VERSION")),
        Command::Help => write!(out, "{HELP}"),
        Command::Serve { .. } | Command::Check { .. } => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "`serve` and `check` require the runtime that `main` owns",
        )),
    }
}

const HELP: &str = "\
warden — secure, read-only, auditable query gateway for AI agents

USAGE:
    warden <command> [flags]

COMMANDS:
    serve      Serve the MCP tools over the selected transport
    check      Validate the configuration and probe every connection
    version    Show the version
    help       Show this message

FLAGS:
    --config <path>         Configuration file (default: warden.toml)
    --transport <name>      Transport for `serve` (default: stdio)
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
    fn serve_defaults_to_stdio_and_the_documented_config_path() {
        assert_eq!(
            parse(args(&["serve"])).unwrap(),
            Command::Serve {
                config: PathBuf::from(DEFAULT_CONFIG_PATH),
                transport: Transport::Stdio,
            }
        );
    }

    #[test]
    fn both_flags_are_accepted_in_either_order() {
        let expected = Command::Serve {
            config: PathBuf::from("/etc/warden.toml"),
            transport: Transport::Stdio,
        };
        assert_eq!(
            parse(args(&[
                "serve",
                "--config",
                "/etc/warden.toml",
                "--transport",
                "stdio"
            ]))
            .unwrap(),
            expected
        );
        assert_eq!(
            parse(args(&[
                "serve",
                "--transport",
                "stdio",
                "--config",
                "/etc/warden.toml"
            ]))
            .unwrap(),
            expected
        );
    }

    #[test]
    fn check_takes_the_same_configuration_flag() {
        assert_eq!(
            parse(args(&["check"])).unwrap(),
            Command::Check {
                config: PathBuf::from(DEFAULT_CONFIG_PATH)
            }
        );
        assert_eq!(
            parse(args(&["check", "--config", "/etc/warden.toml"])).unwrap(),
            Command::Check {
                config: PathBuf::from("/etc/warden.toml")
            }
        );
    }

    #[test]
    fn the_http_transport_names_the_milestone_that_adds_it() {
        let error = parse(args(&["serve", "--transport", "http"])).unwrap_err();
        assert_eq!(
            error,
            CliError::UnsupportedTransport {
                name: "http".to_owned()
            }
        );
        assert!(error.to_string().contains("stdio"), "{error}");
    }

    #[test]
    fn a_flag_without_its_value_is_a_usage_error_that_echoes_no_argument() {
        let error = parse(args(&["serve", "--config"])).unwrap_err();
        assert_eq!(error, CliError::MissingValue { flag: "--config" });
    }

    #[test]
    fn an_unknown_flag_names_the_flag_and_not_the_value_after_it() {
        let error = parse(args(&["check", "--dsn", "postgres://u:p@h/d"])).unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("--dsn"), "{rendered}");
        assert!(!rendered.contains("postgres://"), "{rendered}");
    }

    #[test]
    fn help_lists_every_command_and_every_flag() {
        let mut out = Vec::new();
        run(Command::Help, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        for expected in [
            "serve",
            "check",
            "version",
            "help",
            "--config",
            "--transport",
        ] {
            assert!(text.contains(expected), "help omits {expected}:\n{text}");
        }
    }

    #[test]
    fn the_asynchronous_commands_refuse_the_synchronous_entry_point() {
        // `main` owns the runtime and dispatches these itself. If that dispatch ever
        // regressed, this arm has to fail loudly rather than exit 0 having done nothing.
        let mut out = Vec::new();
        let error = run(
            Command::Check {
                config: PathBuf::from(DEFAULT_CONFIG_PATH),
            },
            &mut out,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(out.is_empty(), "{out:?}");
    }
}
