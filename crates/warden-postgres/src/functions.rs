//! The explicit PostgreSQL function registry.
//!
//! A `SELECT` can still have side effects, so every function a statement invokes is
//! classified and anything unclassified is denied (SPEC section 6, invariant 7;
//! ADR-0011). Two tables carry that decision: a security reviewer must be able to
//! check the denylist against `docs/security.md` section 7.3 and the allowlist
//! against "is any of these able to do something other than compute a value".
//!
//! An **explicit allowlist**, not a category table derived from a reviewed source,
//! is `docs/open-questions.md` section 2 question 3's first option: measure it before
//! scaling it. Question 2 — how broad the allowlist should be — is answered slightly
//! more generously here than in `warden-mysql`, because PostgreSQL routes far more
//! ordinary reading through functions (`generate_series`, `unnest`, the `jsonb_*`
//! family) and a registry too narrow to cover them would deny plain queries.
//!
//! Names arrive already folded. `visit::record_function` calls the shared `folded()`
//! helper — the same one CTE subtraction uses — before consulting this registry: an
//! unquoted identifier is lowercased the way PostgreSQL itself folds it, and a quoted
//! one is compared by its literal, unfolded characters (ASCII-only on purpose: Unicode
//! folding would make a security comparison depend on locale data). Every entry below
//! is lowercase (asserted by `the_two_tables_are_lowercase_sets_that_do_not_overlap`),
//! so a quoted call can only match one that is itself already lowercase —
//! `"count"(1)` matches the `count` entry, `"Count"(1)` does not, exactly as
//! PostgreSQL would resolve the two differently.
//!
//! **This module never sees a schema.** `visit::record_function` decides whether the
//! call's schema is trusted before calling [`classify`], and consults this registry
//! only for an unqualified call or one qualified by `pg_catalog` (ADR-0029). A
//! `public.count(1)` never reaches these tables.
//!
//! **Not in either table, on purpose.**
//!
//! - `version`, `current_setting`, `current_user`, `session_user`, `user`,
//!   `current_database`, `current_schema`, `current_catalog`, `inet_client_addr`,
//!   `inet_server_addr`, `pg_backend_pid`, `txid_current` and the `pg_stat_*` family
//!   read account, connection or server state. `docs/security.md` section 1 names
//!   infrastructure topology a protected asset and section 10 already strips it from
//!   error messages; allowlisting these would hand the same information back on the
//!   result path instead.
//! - `currval` and `lastval` read a sequence rather than advancing it, so
//!   `RiskFlag::SequenceMutation` would be a false statement about them. They stay
//!   unclassified and are denied as `unknown_function`.
//! - `setseed` mutates the session's random-number state, which survives on a pooled
//!   connection.
//! - `dblink`, `dblink_exec`, `dblink_connect`, `query_to_xml`,
//!   `query_to_xml_and_xmlschema` and `database_to_xml` execute SQL that Warden never
//!   parsed, on this server or another one.
//! - `pg_terminate_backend`, `pg_cancel_backend`, `pg_reload_conf`,
//!   `pg_rotate_logfile`, `pg_switch_wal` and `pg_create_restore_point` administer
//!   the server.
//! - `xpath` and `xmlparse` process XML with entity handling Warden does not audit.
//!
//! None of these gets a denylist entry, because no existing `RiskFlag` names what it
//! actually does and inventing one is an ADR-0021 decision, not a table edit. They
//! are denied on the `Unknown` path with an honest code.

use warden_core::analysis::{FunctionClassification, RiskFlag};

/// Functions that do something other than compute a value, and the risk each one is.
///
/// `docs/security.md` section 7.3 names `pg_sleep`, `pg_advisory_lock`,
/// `pg_advisory_xact_lock`, `nextval`, `setval` and `pg_notify`; the rest of each
/// family is here because omitting one spelling would leave an obvious bypass.
///
/// Every entry maps to a flag that names its real effect. A dangerous function whose
/// effect no `RiskFlag` names does not belong here — see the module header.
const DANGEROUS: &[(&str, RiskFlag)] = &[
    // Delay and benchmark: they defeat the deadline controls by consuming it.
    ("pg_sleep", RiskFlag::DelayFunction),
    ("pg_sleep_for", RiskFlag::DelayFunction),
    ("pg_sleep_until", RiskFlag::DelayFunction),
    // Advisory locks: session- or transaction-scoped locks on a pooled connection.
    ("pg_advisory_lock", RiskFlag::AdvisoryLock),
    ("pg_advisory_lock_shared", RiskFlag::AdvisoryLock),
    ("pg_advisory_xact_lock", RiskFlag::AdvisoryLock),
    ("pg_advisory_xact_lock_shared", RiskFlag::AdvisoryLock),
    ("pg_try_advisory_lock", RiskFlag::AdvisoryLock),
    ("pg_try_advisory_lock_shared", RiskFlag::AdvisoryLock),
    ("pg_try_advisory_xact_lock", RiskFlag::AdvisoryLock),
    ("pg_try_advisory_xact_lock_shared", RiskFlag::AdvisoryLock),
    ("pg_advisory_unlock", RiskFlag::AdvisoryLock),
    ("pg_advisory_unlock_shared", RiskFlag::AdvisoryLock),
    ("pg_advisory_unlock_all", RiskFlag::AdvisoryLock),
    // Sequence mutation: SPEC section 6, invariant 10. Only these two advance a
    // sequence; `currval` and `lastval` read one and stay unclassified.
    ("nextval", RiskFlag::SequenceMutation),
    ("setval", RiskFlag::SequenceMutation),
    // Server-side file reads.
    ("pg_read_file", RiskFlag::FileAccess),
    ("pg_read_binary_file", RiskFlag::FileAccess),
    ("pg_ls_dir", RiskFlag::FileAccess),
    ("pg_ls_logdir", RiskFlag::FileAccess),
    ("pg_ls_waldir", RiskFlag::FileAccess),
    ("pg_ls_tmpdir", RiskFlag::FileAccess),
    ("pg_stat_file", RiskFlag::FileAccess),
    ("lo_import", RiskFlag::FileAccess),
    // Server-side file writes.
    ("lo_export", RiskFlag::FileOutput),
    // Session and transaction state that survives on a pooled connection.
    ("set_config", RiskFlag::SessionMutation),
    ("pg_notify", RiskFlag::SessionMutation),
];

/// Functions that only compute a value from their arguments or from the row.
///
/// Grouped by PostgreSQL's own reference-manual chapters so a reviewer can diff this
/// against the documentation. Several entries — `cast`, `extract`, `overlay`,
/// `position`, `substring`, `trim` — usually reach the AST as a dedicated `Expr`
/// variant rather than `Expr::Function` and therefore never reach this table; they
/// are listed anyway so a grammar change cannot turn them into unclassified calls.
///
/// The regular-expression functions are here despite being CPU-expensive: the
/// control for an expensive pattern is the server deadline and the concurrency limit
/// (`docs/security.md` section 3), not classification.
///
/// `gen_random_uuid` is allowed where `warden-mysql` denies `UUID()`. The reason is
/// not inconsistency: MySQL's `UUID()` returns a version-1 value embedding the
/// server host's MAC address, which leaks the topology asset, and PostgreSQL's
/// `gen_random_uuid` returns a version-4 value drawn from the CSPRNG.
const SAFE: &[&str] = &[
    // Aggregate
    "array_agg",
    "avg",
    "bit_and",
    "bit_or",
    "bit_xor",
    "bool_and",
    "bool_or",
    "count",
    "every",
    "json_agg",
    "json_object_agg",
    "jsonb_agg",
    "jsonb_object_agg",
    "max",
    "min",
    "stddev",
    "stddev_pop",
    "stddev_samp",
    "string_agg",
    "sum",
    "var_pop",
    "var_samp",
    "variance",
    // Window
    "cume_dist",
    "dense_rank",
    "first_value",
    "lag",
    "last_value",
    "lead",
    "nth_value",
    "ntile",
    "percent_rank",
    "rank",
    "row_number",
    // String
    "ascii",
    "bit_length",
    "btrim",
    "char_length",
    "character_length",
    "chr",
    "concat",
    "concat_ws",
    "decode",
    "encode",
    "format",
    "initcap",
    "left",
    "length",
    "lower",
    "lpad",
    "ltrim",
    "md5",
    "octet_length",
    "overlay",
    "position",
    "quote_ident",
    "quote_literal",
    "quote_nullable",
    "repeat",
    "replace",
    "reverse",
    "right",
    "rpad",
    "rtrim",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "split_part",
    "starts_with",
    "strpos",
    "substr",
    "substring",
    "to_hex",
    "translate",
    "trim",
    "upper",
    // Regular expressions
    "regexp_match",
    "regexp_matches",
    "regexp_replace",
    "regexp_split_to_array",
    "regexp_split_to_table",
    // Numeric
    "abs",
    "acos",
    "asin",
    "atan",
    "atan2",
    "ceil",
    "ceiling",
    "cos",
    "cot",
    "degrees",
    "div",
    "exp",
    "floor",
    "ln",
    "log",
    "log10",
    "mod",
    "pi",
    "power",
    "radians",
    "random",
    "round",
    "sign",
    "sin",
    "sqrt",
    "tan",
    "trunc",
    "width_bucket",
    // Date and time
    "age",
    "clock_timestamp",
    "current_date",
    "current_time",
    "current_timestamp",
    "date_part",
    "date_trunc",
    "extract",
    "justify_days",
    "justify_hours",
    "justify_interval",
    "localtime",
    "localtimestamp",
    "make_date",
    "make_time",
    "make_timestamp",
    "now",
    "statement_timestamp",
    "to_timestamp",
    "transaction_timestamp",
    // Data-type formatting
    "to_char",
    "to_date",
    "to_number",
    // Comparison, conditional, and cast
    "cast",
    "coalesce",
    "greatest",
    "least",
    "nullif",
    "num_nonnulls",
    "num_nulls",
    // Arrays and set-returning helpers. These are how ordinary PostgreSQL reads
    // expand a value into rows; each computes from its arguments and touches
    // nothing else.
    "array_append",
    "array_cat",
    "array_length",
    "array_lower",
    "array_position",
    "array_positions",
    "array_prepend",
    "array_remove",
    "array_replace",
    "array_to_string",
    "array_upper",
    "cardinality",
    "generate_series",
    "generate_subscripts",
    "string_to_array",
    "string_to_table",
    "unnest",
    // JSON and JSONB, read-only and constructing forms only
    "json_array_elements",
    "json_array_elements_text",
    "json_array_length",
    "json_build_array",
    "json_build_object",
    "json_each",
    "json_each_text",
    "json_extract_path",
    "json_extract_path_text",
    "json_object",
    "json_object_keys",
    "json_strip_nulls",
    "json_typeof",
    "jsonb_array_elements",
    "jsonb_array_elements_text",
    "jsonb_array_length",
    "jsonb_build_array",
    "jsonb_build_object",
    "jsonb_each",
    "jsonb_each_text",
    "jsonb_extract_path",
    "jsonb_extract_path_text",
    "jsonb_insert",
    "jsonb_object",
    "jsonb_object_keys",
    "jsonb_pretty",
    "jsonb_set",
    "jsonb_strip_nulls",
    "jsonb_typeof",
    "row_to_json",
    "to_json",
    "to_jsonb",
    // Network address conversion. These transform a value; the functions that
    // report the connection's own addresses are deliberately absent.
    "abbrev",
    "broadcast",
    "family",
    "host",
    "hostmask",
    "masklen",
    "netmask",
    "network",
    // UUID generation
    "gen_random_uuid",
];

/// Classifies one already-folded function name, and names the risk when there is one.
///
/// This function does no folding of its own: the caller (`visit::record_function`)
/// folds by the identifier's own quoting before calling this, so a name that arrives
/// here already carries PostgreSQL's resolution rule. Passing a name in the wrong case
/// is a caller bug, not something this function should paper over — see the module
/// header.
///
/// The `Option<RiskFlag>` is the evidence half: `FunctionSafetyPolicy` acts on the
/// classification and `RiskEvidencePolicy` acts on the flag, so a dangerous call is
/// denied twice by independent rules and an audit record says *which* danger it was
/// rather than only "dangerous function".
pub(crate) fn classify(name: &str) -> (FunctionClassification, Option<RiskFlag>) {
    if let Some((_, flag)) = DANGEROUS.iter().find(|(known, _)| *known == name) {
        return (FunctionClassification::KnownDangerous, Some(*flag));
    }
    if SAFE.contains(&name) {
        return (FunctionClassification::KnownSafe, None);
    }
    (
        FunctionClassification::Unknown,
        Some(RiskFlag::UserDefinedFunction),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn the_dangerous_functions_named_by_the_security_document_are_all_present() {
        // `docs/security.md` section 7.3 lists these by name; losing one would
        // remove a row from the threat-to-control matrix silently.
        for name in [
            "pg_sleep",
            "pg_advisory_lock",
            "pg_advisory_xact_lock",
            "nextval",
            "setval",
            "pg_notify",
        ] {
            assert_eq!(
                classify(name).0,
                FunctionClassification::KnownDangerous,
                "{name}"
            );
        }
    }

    #[test]
    fn each_dangerous_function_names_the_risk_it_is() {
        assert_eq!(classify("pg_sleep").1, Some(RiskFlag::DelayFunction));
        assert_eq!(classify("pg_advisory_lock").1, Some(RiskFlag::AdvisoryLock));
        assert_eq!(classify("nextval").1, Some(RiskFlag::SequenceMutation));
        assert_eq!(classify("pg_read_file").1, Some(RiskFlag::FileAccess));
        assert_eq!(classify("lo_export").1, Some(RiskFlag::FileOutput));
        assert_eq!(classify("set_config").1, Some(RiskFlag::SessionMutation));
    }

    #[test]
    fn an_unlisted_function_is_unknown_and_carries_evidence() {
        let (classification, risk) = classify("my_udf");
        assert_eq!(classification, FunctionClassification::Unknown);
        assert_eq!(risk, Some(RiskFlag::UserDefinedFunction));
    }

    #[test]
    fn state_reading_and_administrative_functions_are_deliberately_unclassified() {
        // Left out of both tables on purpose; the test exists so that adding one
        // has to be a decision rather than a slip. Each is denied on the `Unknown`
        // path, which is the honest code for it.
        for name in [
            "version",
            "current_setting",
            "current_user",
            "session_user",
            "current_database",
            "inet_client_addr",
            "pg_backend_pid",
            "txid_current",
            "currval",
            "lastval",
            "setseed",
            "dblink",
            "query_to_xml",
            "pg_terminate_backend",
            "pg_reload_conf",
            "xpath",
        ] {
            assert_eq!(classify(name).0, FunctionClassification::Unknown, "{name}");
        }
    }

    #[test]
    fn the_set_returning_functions_ordinary_reads_depend_on_are_safe() {
        // PostgreSQL expands values into rows through functions far more often than
        // MySQL does; denying these would deny plain queries.
        for name in [
            "generate_series",
            "unnest",
            "jsonb_each",
            "jsonb_array_elements",
            "regexp_split_to_table",
            "string_to_table",
        ] {
            assert_eq!(
                classify(name).0,
                FunctionClassification::KnownSafe,
                "{name}"
            );
        }
    }

    #[test]
    fn classify_trusts_the_caller_to_have_already_folded_the_name() {
        // `visit::record_function` folds by the identifier's own quoting before
        // calling `classify`; this function compares only what it is given. A name
        // that differs in case from the registry is a different identifier, not a
        // case-insensitive match — the fix for the laundering ADR-0029 exists to
        // close (a quoted, mixed-case name reaching the registry unfolded).
        assert_eq!(classify("count").0, FunctionClassification::KnownSafe);
        assert_eq!(classify("Count").0, FunctionClassification::Unknown);
        assert_eq!(
            classify("pg_sleep").0,
            FunctionClassification::KnownDangerous
        );
        assert_eq!(classify("PG_SLEEP").0, FunctionClassification::Unknown);
    }

    #[test]
    fn a_safe_function_never_carries_a_risk() {
        assert_eq!(classify("count"), (FunctionClassification::KnownSafe, None));
    }

    #[test]
    fn the_two_tables_are_lowercase_sets_that_do_not_overlap() {
        let safe: BTreeSet<&str> = SAFE.iter().copied().collect();
        assert_eq!(safe.len(), SAFE.len(), "the allowlist has a duplicate");

        let dangerous: BTreeSet<&str> = DANGEROUS.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            dangerous.len(),
            DANGEROUS.len(),
            "the denylist has a duplicate"
        );
        assert!(
            safe.is_disjoint(&dangerous),
            "a function is on both lists: {:?}",
            safe.intersection(&dangerous).collect::<Vec<_>>()
        );

        for name in SAFE.iter().chain(DANGEROUS.iter().map(|(name, _)| name)) {
            assert_eq!(
                *name,
                name.to_ascii_lowercase(),
                "registry entries are compared lowercased"
            );
        }
    }
}
