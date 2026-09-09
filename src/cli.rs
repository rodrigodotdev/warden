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

use warden_core::dialect::Dialect;

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
    /// Write a starting configuration file.
    Init {
        /// The path to create. Never overwritten.
        config: PathBuf,
    },
    /// Print the SQL that creates Warden's dedicated read-only role.
    Role {
        /// The engine whose grant syntax to render.
        dialect: Dialect,
        /// The role or user to create. A validated bare identifier.
        user: String,
        /// The database or catalog to grant on. A validated bare identifier.
        database: String,
        /// PostgreSQL's schema. Ignored on MySQL, whose schema is the database.
        schema: String,
    },
    /// Print the MCP client configuration block for this installation.
    McpConfig {
        /// The key the client will show for this server.
        name: String,
        /// The configuration file the emitted block will name.
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
/// A message may quote **Warden's own vocabulary and nothing else**, and each position has
/// its own test for what that means. A flag is quoted only when it is written like one —
/// [`is_flag_shaped`], where the leading dash is what an operator writes for a flag and
/// never for a value. A subcommand is quoted only when it is a near miss of a name Warden
/// defines ([`is_near_miss`]), because that slot takes a bare word and a bare word can be
/// a passphrase, a token, a username, or a hostname. A transport name is quoted on that
/// same rule against its own vocabulary ([`TRANSPORTS`]): that slot takes a bare word too,
/// and `warden serve --transport "$DSN"` with a misspelled variable puts a connection
/// string in it. Everything else an operator types is a value — on this command line a DSN
/// is the value that matters — and is refused without being echoed. `--flag=value` is split at the first `=` before any of this, which is what
/// keeps the value half of an unknown `--dsn=<secret>` out of the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CliError {
    /// No subcommand was provided.
    MissingCommand,
    /// The subcommand does not exist, and was close enough to one that does to be named.
    ///
    /// Contains that near miss alone — never a later argument, and never a bare word too
    /// far from Warden's own vocabulary to be a typo of it.
    UnknownCommand(String),
    /// A flag this command accepts was given no value.
    MissingValue {
        /// The flag left without a value. One of Warden's own literals, never input.
        flag: &'static str,
    },
    /// The subcommand does not accept this flag. Contains the flag name, never its value.
    UnknownFlag {
        /// The flag as written, up to but not including any `=`.
        flag: String,
    },
    /// An argument nothing about which can be quoted safely.
    ///
    /// Both `warden serve postgres://user:password@host/db` and
    /// `warden correct-horse-battery-staple` land here: each token is a value, a value on
    /// this command line can be a DSN or a password, and an operator's supervisor collects
    /// stderr.
    UnknownArgument,
    /// `--transport` named a transport this build does not serve, and named it closely
    /// enough to one Warden defines to be quoted back.
    UnsupportedTransport {
        /// The transport as written, and only ever a near miss of [`TRANSPORTS`].
        name: String,
    },
    /// `--transport` was given a value too far from any transport Warden names to echo.
    ///
    /// `warden serve --transport "$DSN"` lands here when the variable holds a connection
    /// string, which is why the value is dropped rather than repeated into whatever
    /// collects stderr.
    UnquotableTransport,
    /// A name that cannot be written into SQL unquoted.
    ///
    /// Carries the flag — Warden's own literal — and never the value, which is the
    /// rule the whole type exists for: an identifier that fails this check is
    /// precisely the kind of string nobody wants echoed into a log.
    InvalidIdentifier {
        /// The flag whose value was refused. One of Warden's own literals.
        flag: &'static str,
    },
    /// `--dialect` named an engine Warden does not implement.
    ///
    /// The value is dropped rather than quoted: this slot takes a bare word, and a
    /// bare word on this command line can be a password.
    UnknownDialect,
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
            Self::UnknownArgument => {
                write!(f, "unknown argument; use `warden help`")
            }
            Self::UnsupportedTransport { name } => {
                write!(
                    f,
                    "unsupported transport: `{name}`; this build serves `stdio` only, \
                     and the HTTP transport arrives in Milestone 14"
                )
            }
            Self::UnquotableTransport => {
                write!(
                    f,
                    "unsupported transport; this build serves `stdio` only, \
                     and the HTTP transport arrives in Milestone 14"
                )
            }
            Self::InvalidIdentifier { flag } => write!(
                f,
                "{flag} must be a plain SQL name: a letter or underscore, then letters, \
                 digits, and underscores, at most 63 characters"
            ),
            Self::UnknownDialect => f.write_str("--dialect must be `mysql` or `postgresql`"),
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
        "init" => parse_init(args),
        "role" => parse_role(args),
        "mcp-config" => parse_mcp_config(args),
        // The subcommand position holds a bare word, and a bare word is as likely to be a
        // pasted secret as a typo. Only a near miss of a name Warden itself defines is
        // quoted back; anything further away is refused without being repeated.
        other if is_near_miss(other, &COMMANDS) => Err(CliError::UnknownCommand(other.to_owned())),
        _unquotable => Err(CliError::UnknownArgument),
    }
}

/// The subcommand names [`parse`] dispatches on, for near-miss reporting.
///
/// The flag spellings (`--version`, `-h`) are deliberately absent: they are flag-shaped,
/// so a typo of one is already quotable through [`is_flag_shaped`] when it reaches a
/// subcommand's flag loop, and a near miss of `-h` is one edit from most short words.
const COMMANDS: [&str; 7] = [
    "serve",
    "check",
    "init",
    "role",
    "mcp-config",
    "version",
    "help",
];

/// The transport names Warden itself defines, for the same near-miss reporting.
///
/// `http` is here although this build refuses it: `docs/operations.md` section 11
/// documents it and Milestone 14 serves it, so quoting it back is what puts the
/// "arrives in Milestone 14" sentence in front of the operator who typed it.
const TRANSPORTS: [&str; 2] = ["stdio", "http"];

/// Parses `serve`'s `--config` and `--transport`, in either order.
fn parse_serve<I>(mut args: I) -> Result<Command, CliError>
where
    I: Iterator<Item = String>,
{
    let mut config = None;
    let mut transport = Transport::Stdio;

    while let Some(argument) = args.next() {
        let (flag, inline) = split_inline_value(&argument);
        match flag {
            "--config" => config = Some(PathBuf::from(value_of("--config", inline, &mut args)?)),
            "--transport" => transport = value_of("--transport", inline, &mut args)?.parse()?,
            unknown => return Err(unknown_argument(unknown)),
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
        let (flag, inline) = split_inline_value(&argument);
        match flag {
            "--config" => config = Some(PathBuf::from(value_of("--config", inline, &mut args)?)),
            unknown => return Err(unknown_argument(unknown)),
        }
    }

    Ok(Command::Check {
        config: config.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH)),
    })
}

/// Parses `init`'s `--config`.
///
/// The same flag `serve` and `check` read, so the three commands name one file the
/// same way: `warden init --config /etc/warden.toml` then
/// `warden check --config /etc/warden.toml`.
fn parse_init<I>(mut args: I) -> Result<Command, CliError>
where
    I: Iterator<Item = String>,
{
    let mut config = None;

    while let Some(argument) = args.next() {
        let (flag, inline) = split_inline_value(&argument);
        match flag {
            "--config" => config = Some(PathBuf::from(value_of("--config", inline, &mut args)?)),
            unknown => return Err(unknown_argument(unknown)),
        }
    }

    Ok(Command::Init {
        config: config.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH)),
    })
}

/// Parses `role`'s four flags.
///
/// `--dialect`, `--user`, and `--database` are required; `--schema` defaults to
/// `public` and is PostgreSQL's alone. The identifier check runs here rather than in
/// `onboarding::role_sql` so an invalid name is a usage error with an exit code,
/// rather than something the rendering has to defend against.
fn parse_role<I>(mut args: I) -> Result<Command, CliError>
where
    I: Iterator<Item = String>,
{
    let mut dialect = None;
    let mut user = None;
    let mut database = None;
    let mut schema = None;

    while let Some(argument) = args.next() {
        let (flag, inline) = split_inline_value(&argument);
        match flag {
            "--dialect" => {
                let value = value_of("--dialect", inline, &mut args)?;
                dialect = Some(value.parse().map_err(|_| CliError::UnknownDialect)?);
            }
            "--user" => user = Some(identifier("--user", inline, &mut args)?),
            "--database" => database = Some(identifier("--database", inline, &mut args)?),
            "--schema" => schema = Some(identifier("--schema", inline, &mut args)?),
            unknown => return Err(unknown_argument(unknown)),
        }
    }

    Ok(Command::Role {
        dialect: dialect.ok_or(CliError::MissingValue { flag: "--dialect" })?,
        user: user.ok_or(CliError::MissingValue { flag: "--user" })?,
        database: database.ok_or(CliError::MissingValue { flag: "--database" })?,
        schema: schema.unwrap_or_else(|| "public".to_owned()),
    })
}

/// Parses `mcp-config`'s `--name` and `--config`.
///
/// `--name` is not run through [`identifier`]: it is a JSON object key that
/// `serde_json` escapes, not SQL, so the identifier rule would reject perfectly good
/// names like `orders-replica` for no benefit.
fn parse_mcp_config<I>(mut args: I) -> Result<Command, CliError>
where
    I: Iterator<Item = String>,
{
    let mut name = None;
    let mut config = None;

    while let Some(argument) = args.next() {
        let (flag, inline) = split_inline_value(&argument);
        match flag {
            "--name" => name = Some(value_of("--name", inline, &mut args)?),
            "--config" => config = Some(PathBuf::from(value_of("--config", inline, &mut args)?)),
            unknown => return Err(unknown_argument(unknown)),
        }
    }

    Ok(Command::McpConfig {
        name: name.unwrap_or_else(|| "warden".to_owned()),
        config: config.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH)),
    })
}

/// Takes a flag's value and requires it to be a plain SQL identifier.
fn identifier<I>(flag: &'static str, inline: Option<&str>, args: &mut I) -> Result<String, CliError>
where
    I: Iterator<Item = String>,
{
    let value = value_of(flag, inline, args)?;
    if crate::onboarding::validate_identifier(&value) {
        Ok(value)
    } else {
        Err(CliError::InvalidIdentifier { flag })
    }
}

/// Takes a flag's value from `--flag=value` or from the argument after it.
///
/// `flag` is the matched literal rather than the string the operator typed, which is
/// what keeps [`CliError::MissingValue`] a `&'static str` and unable to echo input. An
/// empty inline value (`--config=`) is a mistake rather than a path, and is reported as
/// the missing value it is.
fn value_of<I>(flag: &'static str, inline: Option<&str>, args: &mut I) -> Result<String, CliError>
where
    I: Iterator<Item = String>,
{
    match inline {
        Some(value) if !value.is_empty() => Ok(value.to_owned()),
        Some(_empty) => Err(CliError::MissingValue { flag }),
        None => args.next().ok_or(CliError::MissingValue { flag }),
    }
}

/// Splits `--flag=value` into its two halves, leaving a bare `--flag` alone.
///
/// Both forms are accepted, so `--config=/etc/warden.toml` works. This runs before any
/// flag is matched, so the value half of an argument Warden does not recognize is already
/// separated from the name by the time an error is built.
fn split_inline_value(argument: &str) -> (&str, Option<&str>) {
    match argument.split_once('=') {
        Some((flag, value)) => (flag, Some(value)),
        None => (argument, None),
    }
}

/// Reports an argument no subcommand accepts, naming it only when naming it is safe.
///
/// A flag name is Warden's vocabulary and helps an operator find the typo. Anything else
/// is a value the operator supplied, and this command line's values include DSNs, so it
/// is refused without being repeated into whatever collects stderr.
fn unknown_argument(argument: &str) -> CliError {
    if is_flag_shaped(argument) {
        CliError::UnknownFlag {
            flag: argument.to_owned(),
        }
    } else {
        CliError::UnknownArgument
    }
}

/// Whether a token is written the way a flag is: `^--?[A-Za-z][A-Za-z0-9-]*$`.
///
/// The leading dash is required, and that is the whole point. Without it this admits any
/// bare word of letters, digits, and dashes — which is what a dash-separated passphrase, a
/// hex or base36 token, a single-word password, a bare username, and a single-label
/// hostname all are. An operator never has to write a dash to type a secret, and always
/// has to write one to type a flag, so the dash is the only part of the shape that
/// separates Warden's vocabulary from an operator's values.
fn is_flag_shaped(argument: &str) -> bool {
    let Some(name) = argument
        .strip_prefix("--")
        .or_else(|| argument.strip_prefix('-'))
    else {
        return false;
    };
    let mut characters = name.chars();
    matches!(characters.next(), Some(first) if first.is_ascii_alphabetic())
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '-')
}

/// Whether a token is a plausible typo of a name in `vocabulary`, and so safe to quote.
///
/// The subcommand and `--transport` slots both take a bare word, so [`is_flag_shaped`]
/// cannot guard either and a bare word in one is as likely to be a pasted secret as a
/// typo. This is the narrower whitelist that keeps the diagnostic useful anyway: a token
/// is quoted only when a single insertion, deletion, or substitution turns it into one of
/// the names Warden itself defines. `serv` is named; `correct-horse-battery-staple` is
/// not, and neither is the DSN an operator reaches `--transport` with by accident.
fn is_near_miss(argument: &str, vocabulary: &[&str]) -> bool {
    vocabulary
        .iter()
        .any(|name| within_one_edit(argument, name))
}

/// Whether one insertion, deletion, or substitution turns `candidate` into `command`.
///
/// Bytes rather than characters: every name in [`COMMANDS`] is ASCII, so a candidate that
/// is not ASCII cannot be within one edit of any of them and is refused by the length and
/// equality tests without ever being split into characters.
fn within_one_edit(candidate: &str, command: &str) -> bool {
    let (candidate, command) = (candidate.as_bytes(), command.as_bytes());
    match candidate.len().abs_diff(command.len()) {
        // The same length: at most one position may differ.
        0 => {
            candidate
                .iter()
                .zip(command)
                .filter(|(left, right)| left != right)
                .count()
                <= 1
        }
        // One apart: deleting one byte from the longer must yield the shorter.
        1 => {
            let (longer, shorter) = if candidate.len() > command.len() {
                (candidate, command)
            } else {
                (command, candidate)
            };
            let mut matched = 0;
            let mut skipped = false;
            for byte in longer {
                if shorter.get(matched) == Some(byte) {
                    matched += 1;
                } else if skipped {
                    return false;
                } else {
                    skipped = true;
                }
            }
            matched == shorter.len()
        }
        _ => false,
    }
}

impl std::str::FromStr for Transport {
    type Err = CliError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "stdio" => Ok(Self::Stdio),
            other if is_near_miss(other, &TRANSPORTS) => Err(CliError::UnsupportedTransport {
                name: other.to_owned(),
            }),
            _unquotable => Err(CliError::UnquotableTransport),
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
        Command::Role {
            dialect,
            user,
            database,
            schema,
        } => write!(
            out,
            "{}",
            crate::onboarding::role_sql(dialect, &user, &database, &schema)
        ),
        Command::Serve { .. }
        | Command::Check { .. }
        | Command::Init { .. }
        | Command::McpConfig { .. } => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "`serve`, `check`, `init`, and `mcp-config` are executed by `main`",
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
    init       Write a starting configuration file
    role       Print the SQL for Warden's dedicated read-only role
    mcp-config Print the MCP client configuration for this installation
    version    Show the version
    help       Show this message

FLAGS:
    --config <path>         Configuration file (default: warden.toml)
    --transport <name>      Transport for `serve` (default: stdio)
    --dialect <name>        Engine for `role` (mysql or postgresql)
    --user <name>           Role to create, for `role`
    --database <name>       Database to grant on, for `role`
    --schema <name>         PostgreSQL schema for `role` (default: public)
    --name <name>           Server key for `mcp-config` (default: warden)
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
    fn a_near_miss_of_a_transport_is_still_named() {
        // The diagnostic an operator who typed `stdio` wrong has to get back.
        assert_eq!(
            parse(args(&["serve", "--transport", "stdi"])).unwrap_err(),
            CliError::UnsupportedTransport {
                name: "stdi".to_owned()
            }
        );
    }

    #[test]
    fn an_unrecognizable_transport_is_refused_without_being_echoed() {
        // `warden serve --transport "$DSN"` with the wrong variable name. The transport
        // slot takes a bare word, so nothing about the token's shape says "not a secret",
        // and an operator's supervisor collects stderr.
        let error = parse(args(&[
            "serve",
            "--transport",
            "postgres://user:password@host/db",
        ]))
        .unwrap_err();
        assert_eq!(error, CliError::UnquotableTransport);
        let rendered = error.to_string();
        assert!(
            !rendered.contains("password"),
            "error leaked a transport value: {rendered}"
        );
        assert!(
            !rendered.contains("postgres://"),
            "error leaked a transport value: {rendered}"
        );
        // Still a usable diagnostic: it names the transport this build does serve.
        assert!(rendered.contains("stdio"), "{rendered}");
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
    fn an_inline_value_is_accepted_so_the_equals_form_is_not_a_usage_error() {
        assert_eq!(
            parse(args(&["check", "--config=/etc/warden.toml"])).unwrap(),
            Command::Check {
                config: PathBuf::from("/etc/warden.toml")
            }
        );
        assert_eq!(
            parse(args(&[
                "serve",
                "--config=/etc/warden.toml",
                "--transport=stdio"
            ]))
            .unwrap(),
            Command::Serve {
                config: PathBuf::from("/etc/warden.toml"),
                transport: Transport::Stdio,
            }
        );
    }

    #[test]
    fn an_empty_inline_value_is_the_missing_value_it_is() {
        assert_eq!(
            parse(args(&["check", "--config="])).unwrap_err(),
            CliError::MissingValue { flag: "--config" }
        );
    }

    #[test]
    fn an_unknown_flag_written_with_an_inline_secret_echoes_only_the_flag() {
        let error = parse(args(&["check", "--dsn=postgres://u:password@h/d"])).unwrap_err();
        assert_eq!(
            error,
            CliError::UnknownFlag {
                flag: "--dsn".to_owned()
            }
        );
        let rendered = error.to_string();
        assert!(rendered.contains("--dsn"), "{rendered}");
        assert!(!rendered.contains("postgres://"), "{rendered}");
        assert!(!rendered.contains("password"), "{rendered}");
    }

    #[test]
    fn a_bare_argument_is_refused_without_being_repeated() {
        // A positional argument is a value, and a value here can be a DSN. An operator's
        // supervisor collects stderr, so the token is refused rather than quoted.
        for command_line in [
            args(&["serve", "postgres://u:password@h/d"]),
            args(&["check", "postgres://u:password@h/d"]),
            args(&["postgres://u:password@h/d"]),
        ] {
            let error = parse(command_line).unwrap_err();
            assert_eq!(error, CliError::UnknownArgument);
            let rendered = error.to_string();
            assert!(!rendered.contains("postgres://"), "{rendered}");
            assert!(!rendered.contains("password"), "{rendered}");
        }
    }

    #[test]
    fn a_bare_word_secret_is_not_echoed_at_a_flag_or_a_subcommand_position() {
        // Nothing about these needs punctuation to be a secret: a dash-separated
        // passphrase is a password manager's default scheme, and a base36 token is
        // letters and digits. Both would pass a shape test that only asked for a name.
        for secret in ["correct-horse-battery-staple", "hunter2", "k3mz9qx1t7b"] {
            for command_line in [
                args(&["check", secret]),
                args(&["serve", secret]),
                args(&[secret]),
            ] {
                let error = parse(command_line).unwrap_err();
                assert_eq!(error, CliError::UnknownArgument, "{secret}");
                assert!(!error.to_string().contains(secret), "{secret}");
            }
        }
    }

    #[test]
    fn only_a_token_written_like_a_flag_is_quotable_as_one() {
        for flag in ["--config", "-h", "--allow-locking-reads", "-V"] {
            assert!(is_flag_shaped(flag), "{flag}");
        }
        for value in [
            // The dash is the whole test: every one of these is a plausible secret or
            // path, and every one of them is letters, digits, and dashes.
            "correct-horse-battery-staple",
            "hunter2",
            "k3mz9qx1t7b",
            "check",
            "postgres://user:password@host/db",
            "/etc/warden.toml",
            "--",
            "-",
            "",
        ] {
            assert!(!is_flag_shaped(value), "{value}");
        }
    }

    #[test]
    fn a_typo_of_a_subcommand_is_still_named_but_a_distant_word_is_not() {
        // One edit from a name Warden defines, so an operator sees their own typo.
        for typo in ["serv", "serve1", "chek", "checkk", "versio", "helpp"] {
            assert!(is_near_miss(typo, &COMMANDS), "{typo}");
        }
        // Two or more edits away: no longer a plausible typo, and a bare word this far
        // from Warden's vocabulary is the operator's own value. `hepl` is here because a
        // transposition is two substitutions and this deliberately does not measure
        // Damerau distance: the cost of getting a common typo's generic message is one
        // line telling the operator to run `warden help`, and the cost of widening the
        // neighbourhood is more bare words becoming quotable.
        for other in [
            "hepl",
            "does-not-exist",
            "correct-horse-battery-staple",
            "hunter2",
            "",
        ] {
            assert!(!is_near_miss(other, &COMMANDS), "{other}");
        }
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
    fn parses_init_with_and_without_a_config_path() {
        assert_eq!(
            parse(args(&["init"])).unwrap(),
            Command::Init {
                config: PathBuf::from(DEFAULT_CONFIG_PATH)
            }
        );
        assert_eq!(
            parse(args(&["init", "--config", "/etc/warden.toml"])).unwrap(),
            Command::Init {
                config: PathBuf::from("/etc/warden.toml")
            }
        );
    }

    #[test]
    fn init_refuses_a_flag_it_does_not_define() {
        assert_eq!(
            parse(args(&["init", "--transport", "stdio"])),
            Err(CliError::UnknownFlag {
                flag: "--transport".to_owned()
            })
        );
    }

    #[test]
    fn parses_role_with_every_flag_and_the_schema_default() {
        assert_eq!(
            parse(args(&[
                "role",
                "--dialect",
                "postgresql",
                "--user",
                "warden_ro",
                "--database",
                "app"
            ]))
            .unwrap(),
            Command::Role {
                dialect: Dialect::PostgreSql,
                user: "warden_ro".to_owned(),
                database: "app".to_owned(),
                schema: "public".to_owned(),
            }
        );
    }

    #[test]
    fn role_requires_a_user_and_a_database() {
        assert_eq!(
            parse(args(&[
                "role",
                "--dialect",
                "postgresql",
                "--database",
                "app"
            ])),
            Err(CliError::MissingValue { flag: "--user" })
        );
        assert_eq!(
            parse(args(&[
                "role",
                "--dialect",
                "postgresql",
                "--user",
                "warden_ro"
            ])),
            Err(CliError::MissingValue { flag: "--database" })
        );
    }

    #[test]
    fn role_refuses_an_identifier_it_cannot_write_unquoted_without_echoing_it() {
        let refused = parse(args(&[
            "role",
            "--dialect",
            "postgresql",
            "--user",
            "warden_ro; DROP TABLE users --",
            "--database",
            "app",
        ]));
        assert_eq!(refused, Err(CliError::InvalidIdentifier { flag: "--user" }));
        // The rule the whole error type exists for: an operator's value is never
        // repeated into whatever collects stderr.
        let message = format!("{}", refused.unwrap_err());
        assert!(!message.contains("DROP TABLE"), "{message}");
    }

    #[test]
    fn parses_mcp_config_with_its_defaults() {
        assert_eq!(
            parse(args(&["mcp-config"])).unwrap(),
            Command::McpConfig {
                name: "warden".to_owned(),
                config: PathBuf::from(DEFAULT_CONFIG_PATH),
            }
        );
        assert_eq!(
            parse(args(&[
                "mcp-config",
                "--name",
                "orders",
                "--config",
                "/etc/w.toml"
            ]))
            .unwrap(),
            Command::McpConfig {
                name: "orders".to_owned(),
                config: PathBuf::from("/etc/w.toml"),
            }
        );
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
