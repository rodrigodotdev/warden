//! Text the onboarding subcommands render.
//!
//! Every function here is pure: it takes values and returns a `String`. Nothing in
//! this module reads the environment, opens a file, or writes to a descriptor, which
//! is what lets each rendering be asserted exactly rather than through a process.

use std::path::Path;

use warden_core::dialect::Dialect;

/// The configuration `warden init` writes.
///
/// It is deliberately the smallest file Warden accepts rather than a tour of every
/// key: a starting point an operator edits, not a reference. `docs/operations.md`
/// section 3 is the reference. Every value here is a placeholder an operator must
/// change, and none of them is a secret — `dsn_env` names the variable that holds the
/// DSN, because Warden never reads one from this file.
pub(crate) fn config_template() -> String {
    format!(
        "\
# Written by `warden init`. Edit before serving.
#
# Warden never reads a DSN from this file. `dsn_env` names the environment variable
# that holds it; `dsn_file` names a secret file instead, which is stronger — see
# `docs/operations.md` section 3.
version = {version}

[[connections]]
name = \"local\"
dialect = \"postgresql\"
environment = \"development\"
database = \"app\"
dsn_env = \"WARDEN_LOCAL_DSN\"
search_path = [\"public\"]
policy = \"default\"

# TLS is `verify-identity` unless this block says otherwise, which is the mode a
# production deployment must keep. A local server with SSL off refuses that mode, so
# a development machine — and nothing else — may uncomment these two lines:
# [connections.tls]
# mode = \"disabled\"  # development only; never commit this for a real database

[policies.default]
query_timeout = \"5s\"
max_rows = 200

[redaction]
columns = [\"*.password_hash\", \"*.access_token\"]
",
        version = warden_config::SUPPORTED_VERSION
    )
}

/// The longest identifier both engines accept unquoted.
///
/// PostgreSQL truncates at 63 bytes (`NAMEDATALEN - 1`) and MySQL stops at 64. The
/// lower bound is the one that cannot surprise anyone.
const MAX_IDENTIFIER_LENGTH: usize = 63;

/// The words SQL reads as an existing grantee rather than as a new name.
///
/// Every one of them has the shape of a plain identifier, and `PUBLIC` is every role
/// in the database. `warden role --user public` would emit a `CREATE ROLE PUBLIC`
/// that fails and three `GRANT … TO PUBLIC` statements that do not: psql runs on past
/// an error unless `ON_ERROR_STOP=1` is set, so a command whose entire purpose is
/// least privilege would hand `SELECT` on the whole schema to everyone.
const RESERVED_GRANTEES: [&str; 5] = [
    "public",
    "current_user",
    "session_user",
    "current_role",
    "none",
];

/// Whether a name can be written into the rendered SQL unquoted and unescaped.
///
/// This is the strict check, and the one every position but `--schema` takes: a name
/// of the accepted shape that is not one of [`RESERVED_GRANTEES`]. Refusing the
/// reserved words here rather than at the one call site that renders a grantee is
/// deliberate — the default is safe, and a position that may legitimately take
/// `public` has to say so by reaching for [`validate_schema_name`].
pub(crate) fn validate_identifier(candidate: &str) -> bool {
    validate_schema_name(candidate) && !is_reserved_grantee(candidate)
}

/// Whether a name is one of [`RESERVED_GRANTEES`], whatever case it is written in.
///
/// Exposed for the diagnostic alone: [`validate_identifier`] is the refusal, and this
/// only tells `src/cli.rs` which of the two usage messages to print.
pub(crate) fn is_reserved_grantee(candidate: &str) -> bool {
    RESERVED_GRANTEES
        .iter()
        .any(|reserved| candidate.eq_ignore_ascii_case(reserved))
}

/// Whether a name has the shape the rendered SQL can carry unquoted and unescaped.
///
/// The output of `warden role` is copied into a database console by a human with
/// enough privilege to create roles, so a name that can carry punctuation can carry a
/// second statement with it. Rather than quote and escape per dialect — two different
/// rules, both easy to get subtly wrong — the accepted shape is the intersection that
/// needs neither: a leading letter or underscore, then letters, digits, and
/// underscores.
///
/// Shape alone, with no reserved-word check, which is why this is `--schema`'s rule
/// and nothing else's: `public` is PostgreSQL's default schema and the flag's own
/// default, and the `GRANT USAGE ON SCHEMA public` it renders is exactly right. A
/// schema name is never a grantee.
pub(crate) fn validate_schema_name(candidate: &str) -> bool {
    if candidate.is_empty() || candidate.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    let mut characters = candidate.chars();
    matches!(characters.next(), Some(first) if first.is_ascii_alphabetic() || first == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// The `CREATE ROLE` and `GRANT` statements for Warden's dedicated read-only role.
///
/// `docs/security.md` and ADR-0016 make the database role the real write boundary:
/// Warden is defense in depth over it, never a replacement for it. Until now the
/// README said so and left the operator to write the grant, so every deployment
/// improvised its own — which is the one step where improvising is most expensive.
///
/// Every identifier reaching this function has passed [`validate_identifier`], or
/// [`validate_schema_name`] for `schema` alone, so no value here needs quoting or
/// escaping.
///
/// Deviation from the reviewed design (`AGENTS.md` process rule 7): that invariant is
/// enforced at the parse boundary rather than by a validated newtype the way the code
/// rules ask for identifiers. A newtype here would change `Command`, the parser, and
/// this renderer at once for a function whose only callers are two parse helpers, so
/// it is a deliberate deferral, not an oversight — `src/cli.rs::identifier` is the one
/// door, and no other caller constructs these strings.
///
/// The password is a literal placeholder rather than a generated secret. Warden does
/// not invent credentials, and a secret printed to a terminal is a secret in a shell
/// history.
pub(crate) fn role_sql(dialect: Dialect, user: &str, database: &str, schema: &str) -> String {
    match dialect {
        Dialect::PostgreSql => format!(
            "\
-- Warden's dedicated read-only role for PostgreSQL.
-- Replace CHANGE_ME with a real password before running this, and review every line:
-- this grant is the write boundary, not Warden (ADR-0016).
CREATE ROLE {user} LOGIN PASSWORD 'CHANGE_ME';

GRANT CONNECT ON DATABASE {database} TO {user};
GRANT USAGE ON SCHEMA {schema} TO {user};
GRANT SELECT ON ALL TABLES IN SCHEMA {schema} TO {user};

-- Tables created after this runs would otherwise be unreadable — but only tables
-- created by the role that runs this script. Without FOR ROLE, PostgreSQL applies a
-- default privilege to the current role's own future objects and nothing else. Where
-- migrations run as an application or owner role, add FOR ROLE <owner> after
-- ALTER DEFAULT PRIVILEGES, or that role's later tables stay unreadable.
ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} GRANT SELECT ON TABLES TO {user};

-- PostgreSQL 14 and earlier grant CREATE on the public schema to PUBLIC.
REVOKE CREATE ON SCHEMA {schema} FROM PUBLIC;

-- The second barrier: the session refuses a write even with every Warden layer removed.
ALTER ROLE {user} SET default_transaction_read_only = on;
"
        ),
        Dialect::MySql => format!(
            "\
-- Warden's dedicated read-only role for MySQL.
-- Replace CHANGE_ME with a real password before running this, and review every line:
-- this grant is the write boundary, not Warden (ADR-0016).
--
-- '%' is every host. Narrow it to the host Warden runs on before using this in
-- anything but local development.
CREATE USER '{user}'@'%' IDENTIFIED BY 'CHANGE_ME';

GRANT SELECT ON `{database}`.* TO '{user}'@'%';
"
        ),
    }
}

/// The MCP client configuration block for this installation.
///
/// The README's quick start told an operator to write this by hand with two absolute
/// paths in it, which is the most common way an MCP server fails to start: a client
/// spawns its servers with an arbitrary working directory, so Warden's default
/// relative `warden.toml` almost never resolves and the `--config` path has to be
/// absolute. This command resolves both paths from the running process instead.
///
/// `serde_json` does the escaping. A path can contain a quote, and every Windows path
/// contains backslashes.
pub(crate) fn mcp_config_json(name: &str, binary: &Path, config: &Path) -> String {
    let block = serde_json::json!({
        "mcpServers": {
            name: {
                "command": binary.display().to_string(),
                "args": [
                    "serve",
                    "--transport",
                    "stdio",
                    "--config",
                    config.display().to_string(),
                ],
            }
        }
    });

    // `to_string_pretty` cannot fail for a `Value` built from literals, but the
    // fallible API is the only one there is and `expect` is denied. A compact
    // rendering is still valid JSON and still pasteable.
    serde_json::to_string_pretty(&block).unwrap_or_else(|_| block.to_string())
}

#[cfg(test)]
mod tests {
    // Keeping this exception test-local makes production uses visible in diffs.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn the_template_is_a_configuration_warden_can_actually_load() {
        let rendered = config_template();
        let parsed: warden_config::Config = toml::from_str(&rendered).unwrap();
        assert_eq!(parsed.version, warden_config::SUPPORTED_VERSION);
    }

    #[test]
    fn the_template_never_carries_a_dsn() {
        let rendered = config_template();
        assert!(!rendered.contains("://"), "{rendered}");
        assert!(rendered.contains("dsn_env"), "{rendered}");
    }

    #[test]
    fn the_template_points_at_tls_without_recommending_a_weaker_mode() {
        use warden_core::tls::TlsMode;

        let rendered = config_template();
        // The file Warden writes keeps the strict default; the escape hatch is two
        // commented lines an operator has to uncomment on purpose.
        let parsed: warden_config::Config = toml::from_str(&rendered).unwrap();
        assert_eq!(parsed.connections[0].tls.mode, TlsMode::VerifyIdentity);
        assert!(rendered.contains("# [connections.tls]"), "{rendered}");
        assert!(rendered.contains("development only"), "{rendered}");

        // Uncommented, it is still a configuration Warden loads: an operator who
        // follows the hint gets a working file rather than a parse error.
        let uncommented = rendered
            .replace("# [connections.tls]", "[connections.tls]")
            .replace("# mode = \"disabled\"", "mode = \"disabled\"");
        let parsed: warden_config::Config = toml::from_str(&uncommented).unwrap();
        assert_eq!(parsed.connections[0].tls.mode, TlsMode::Disabled);
    }

    #[test]
    fn an_identifier_is_a_plain_unquoted_sql_name_and_nothing_else() {
        assert!(validate_identifier("warden_ro"));
        assert!(validate_identifier("app"));
        assert!(validate_identifier("_private"));
        assert!(validate_identifier("Orders2"));
    }

    #[test]
    fn the_longest_name_both_engines_accept_is_accepted() {
        // The boundary of `candidate.len() > MAX_IDENTIFIER_LENGTH`: 63 is a name, 64
        // is not, and pinning only the rejecting side leaves the comparison free to
        // drift by one.
        assert!(validate_identifier(&"x".repeat(MAX_IDENTIFIER_LENGTH)));
        assert!(!validate_identifier(&"x".repeat(MAX_IDENTIFIER_LENGTH + 1)));
    }

    #[test]
    fn a_word_sql_reads_as_an_existing_grantee_is_not_a_name_warden_will_create() {
        // `CREATE ROLE PUBLIC` fails and the GRANTs after it do not: psql runs past an
        // error unless `ON_ERROR_STOP=1`, so accepting this word would grant SELECT on
        // the whole schema to every role in the database.
        for reserved in RESERVED_GRANTEES {
            assert!(!validate_identifier(reserved), "{reserved}");
            assert!(!validate_identifier(&reserved.to_uppercase()), "{reserved}");
        }
        assert!(!validate_identifier("Public"));
    }

    #[test]
    fn a_schema_may_be_named_public_because_a_schema_is_never_a_grantee() {
        // `public` is PostgreSQL's default schema and this command's own default, and
        // the `GRANT USAGE ON SCHEMA public` it renders is the correct statement.
        assert!(validate_schema_name("public"));
        assert!(validate_schema_name("PUBLIC"));
        assert!(validate_schema_name("reporting"));
        // The shape rule is still the shape rule.
        assert!(!validate_schema_name("public; DROP TABLE users --"));
        assert!(!validate_schema_name(""));
    }

    #[test]
    fn anything_that_could_close_a_quote_or_end_a_statement_is_refused() {
        // The rendered SQL is copied into a database console by a human. A name that
        // can carry punctuation can carry a second statement with it.
        assert!(!validate_identifier("warden_ro; DROP TABLE users --"));
        assert!(!validate_identifier("wa'rden"));
        assert!(!validate_identifier("wa\"rden"));
        assert!(!validate_identifier("wa`rden"));
        assert!(!validate_identifier("wa rden"));
        assert!(!validate_identifier("2fast"));
        assert!(!validate_identifier(""));
        assert!(!validate_identifier(&"x".repeat(64)));
    }

    #[test]
    fn the_postgresql_grant_gives_select_and_takes_everything_else() {
        let sql = role_sql(Dialect::PostgreSql, "warden_ro", "app", "public");
        assert!(
            sql.contains("CREATE ROLE warden_ro LOGIN PASSWORD"),
            "{sql}"
        );
        assert!(
            sql.contains("GRANT CONNECT ON DATABASE app TO warden_ro;"),
            "{sql}"
        );
        assert!(
            sql.contains("GRANT USAGE ON SCHEMA public TO warden_ro;"),
            "{sql}"
        );
        assert!(
            sql.contains("GRANT SELECT ON ALL TABLES IN SCHEMA public TO warden_ro;"),
            "{sql}"
        );
        assert!(
            sql.contains(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO warden_ro;"
            ),
            "{sql}"
        );
        // The second barrier `AGENTS.md` requires: the role cannot write even if every
        // Warden layer is removed.
        assert!(
            sql.contains("ALTER ROLE warden_ro SET default_transaction_read_only = on;"),
            "{sql}"
        );
        assert!(!sql.contains("INSERT"), "{sql}");
        assert!(!sql.contains("ALL PRIVILEGES"), "{sql}");
    }

    #[test]
    fn the_default_privileges_line_says_whose_future_tables_it_covers() {
        // Without FOR ROLE the statement covers the current role's own future objects,
        // so an operator whose migrations run as another role has to be told what to
        // add rather than discovering it as a permission error weeks later.
        let sql = role_sql(Dialect::PostgreSql, "warden_ro", "app", "public");
        assert!(
            sql.contains("created by the role that runs this script"),
            "{sql}"
        );
        assert!(sql.contains("FOR ROLE <owner>"), "{sql}");
    }

    #[test]
    fn the_mysql_grant_gives_select_on_one_schema_only() {
        let sql = role_sql(Dialect::MySql, "warden_ro", "app", "public");
        assert!(
            sql.contains("CREATE USER 'warden_ro'@'%' IDENTIFIED BY"),
            "{sql}"
        );
        assert!(
            sql.contains("GRANT SELECT ON `app`.* TO 'warden_ro'@'%';"),
            "{sql}"
        );
        // `schema` is PostgreSQL's concept; MySQL's schema is the database.
        assert!(!sql.contains("public"), "{sql}");
        assert!(!sql.contains("ALL PRIVILEGES ON"), "{sql}");
    }

    #[test]
    fn the_password_is_a_placeholder_the_operator_must_replace() {
        for dialect in [Dialect::MySql, Dialect::PostgreSql] {
            let sql = role_sql(dialect, "warden_ro", "app", "public");
            assert!(sql.contains("CHANGE_ME"), "{sql}");
            assert!(sql.contains("Replace CHANGE_ME"), "{sql}");
        }
    }

    #[test]
    fn the_client_json_names_absolute_paths_and_the_stdio_transport() {
        let rendered = mcp_config_json(
            "warden",
            Path::new("/usr/local/bin/warden"),
            Path::new("/etc/warden/warden.toml"),
        );
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(
            parsed["mcpServers"]["warden"]["command"],
            "/usr/local/bin/warden"
        );
        assert_eq!(
            parsed["mcpServers"]["warden"]["args"],
            serde_json::json!([
                "serve",
                "--transport",
                "stdio",
                "--config",
                "/etc/warden/warden.toml"
            ])
        );
    }

    #[test]
    fn a_path_that_needs_escaping_is_escaped_rather_than_pasted() {
        // Every Windows path contains backslashes, and a hand-rolled renderer emits
        // invalid JSON for them.
        let rendered = mcp_config_json(
            "warden",
            Path::new(r"C:\Program Files\warden\warden.exe"),
            Path::new(r"C:\ProgramData\warden\warden.toml"),
        );
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(
            parsed["mcpServers"]["warden"]["command"],
            r"C:\Program Files\warden\warden.exe"
        );
    }

    #[test]
    fn the_server_name_is_the_key_the_client_will_show() {
        let rendered = mcp_config_json("orders", Path::new("/bin/warden"), Path::new("/w.toml"));
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert!(parsed["mcpServers"]["orders"].is_object(), "{rendered}");
    }
}
