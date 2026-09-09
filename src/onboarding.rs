//! Text the onboarding subcommands render.
//!
//! Every function here is pure: it takes values and returns a `String`. Nothing in
//! this module reads the environment, opens a file, or writes to a descriptor, which
//! is what lets each rendering be asserted exactly rather than through a process.

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

[policies.default]
query_timeout = \"5s\"
max_rows = 200

[redaction]
columns = [\"*.password_hash\", \"*.access_token\"]
",
        version = warden_config::SUPPORTED_VERSION
    )
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
}
