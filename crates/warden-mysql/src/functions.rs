//! The explicit MySQL function registry.
//!
//! A `SELECT` can still have side effects, so every function a statement invokes is
//! classified and anything unclassified is denied (SPEC section 6, invariant 7;
//! ADR-0011). Two tables carry that decision, and both are deliberately readable in
//! one screen: a security reviewer must be able to check the denylist against
//! `docs/security.md` section 7.2 and the allowlist against "is any of these able to
//! do something other than compute a value".
//!
//! An **explicit allowlist**, not a category table derived from a reviewed source,
//! is `docs/open-questions.md` section 2 question 3's first option: measure it before
//! scaling it. Question 2 — how broad the allowlist should be — is answered
//! conservatively here, and the operator's escape hatch is the `unknown_functions`
//! relaxation, which `warden check` warns about on a production profile.
//!
//! Names are compared ASCII-lowercased. MySQL function names are case-insensitive,
//! and Unicode folding would make a security comparison depend on locale data.
//!
//! **Not in either table, on purpose.** `USER`, `CURRENT_USER`, `SESSION_USER`,
//! `SYSTEM_USER`, `CONNECTION_ID`, `FOUND_ROWS`, and `ROW_COUNT` read account or
//! session state rather than data, and `UUID_SHORT` increments a server-side
//! counter, which is a write. `VERSION` reports server state that
//! `docs/security.md` section 1 names a protected asset ("infrastructure
//! hostnames and topology") and that section 10 already strips from error
//! messages before they reach the model; allowlisting it here would hand the
//! same information back on the result path instead. `UUID` fails the same
//! bar for a different reason: MySQL's `UUID()` returns a version-1 UUID, which
//! embeds the server host's MAC address, so it leaks that asset through a value
//! rather than through a counter, the way `UUID_SHORT` does. All of them land
//! in `Unknown` and are denied.

use warden_core::analysis::{FunctionClassification, RiskFlag};

/// Functions that do something other than compute a value, and the risk each one is.
///
/// `docs/security.md` section 7.2 names the first seven; the wait functions are the
/// same delay primitive under different spellings, and omitting one would leave an
/// obvious bypass of the timeout controls.
const DANGEROUS: &[(&str, RiskFlag)] = &[
    ("sleep", RiskFlag::DelayFunction),
    ("benchmark", RiskFlag::DelayFunction),
    ("master_pos_wait", RiskFlag::DelayFunction),
    ("source_pos_wait", RiskFlag::DelayFunction),
    ("wait_for_executed_gtid_set", RiskFlag::DelayFunction),
    ("wait_until_sql_thread_after_gtids", RiskFlag::DelayFunction),
    ("get_lock", RiskFlag::AdvisoryLock),
    ("release_lock", RiskFlag::AdvisoryLock),
    ("release_all_locks", RiskFlag::AdvisoryLock),
    ("is_free_lock", RiskFlag::AdvisoryLock),
    ("is_used_lock", RiskFlag::AdvisoryLock),
    ("load_file", RiskFlag::FileAccess),
];

/// Functions that only compute a value from their arguments or from the row.
///
/// Grouped by MySQL's own reference-manual sections so a reviewer can diff this
/// against the documentation. Several entries — `CAST`, `CONVERT`, `EXTRACT`,
/// `POSITION`, `SUBSTRING`, `TRIM`, `CEIL`, `FLOOR` — usually reach the AST as a
/// dedicated `Expr` variant rather than `Expr::Function` and therefore never reach
/// this table; they are listed anyway so a grammar change cannot turn them into
/// unclassified calls.
///
/// The regular-expression functions are here despite being CPU-expensive: the
/// control for an expensive pattern is the server deadline and the concurrency limit
/// (`docs/security.md` section 3), not classification.
const SAFE: &[&str] = &[
    // Aggregate
    "avg",
    "bit_and",
    "bit_or",
    "bit_xor",
    "count",
    "group_concat",
    "json_arrayagg",
    "json_objectagg",
    "max",
    "min",
    "std",
    "stddev",
    "stddev_pop",
    "stddev_samp",
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
    "bin",
    "bit_length",
    "char",
    "char_length",
    "character_length",
    "concat",
    "concat_ws",
    "elt",
    "export_set",
    "field",
    "find_in_set",
    "format",
    "from_base64",
    "hex",
    "insert",
    "instr",
    "lcase",
    "left",
    "length",
    "locate",
    "lower",
    "lpad",
    "ltrim",
    "make_set",
    "mid",
    "oct",
    "octet_length",
    "ord",
    "position",
    "quote",
    "repeat",
    "replace",
    "reverse",
    "right",
    "rpad",
    "rtrim",
    "soundex",
    "space",
    "substr",
    "substring",
    "substring_index",
    "to_base64",
    "trim",
    "ucase",
    "unhex",
    "upper",
    "weight_string",
    // Regular expressions
    "regexp_instr",
    "regexp_like",
    "regexp_replace",
    "regexp_substr",
    // Numeric
    "abs",
    "acos",
    "asin",
    "atan",
    "atan2",
    "bit_count",
    "ceil",
    "ceiling",
    "conv",
    "cos",
    "cot",
    "crc32",
    "degrees",
    "exp",
    "floor",
    "ln",
    "log",
    "log10",
    "log2",
    "mod",
    "pi",
    "pow",
    "power",
    "radians",
    "rand",
    "round",
    "sign",
    "sin",
    "sqrt",
    "tan",
    "truncate",
    // Date and time
    "adddate",
    "addtime",
    "convert_tz",
    "curdate",
    "current_date",
    "current_time",
    "current_timestamp",
    "curtime",
    "date",
    "date_add",
    "date_format",
    "date_sub",
    "datediff",
    "day",
    "dayname",
    "dayofmonth",
    "dayofweek",
    "dayofyear",
    "extract",
    "from_days",
    "from_unixtime",
    "get_format",
    "hour",
    "last_day",
    "localtime",
    "localtimestamp",
    "makedate",
    "maketime",
    "microsecond",
    "minute",
    "month",
    "monthname",
    "now",
    "period_add",
    "period_diff",
    "quarter",
    "sec_to_time",
    "second",
    "str_to_date",
    "subdate",
    "subtime",
    "sysdate",
    "time",
    "time_format",
    "time_to_sec",
    "timediff",
    "timestamp",
    "timestampadd",
    "timestampdiff",
    "to_days",
    "to_seconds",
    "unix_timestamp",
    "utc_date",
    "utc_time",
    "utc_timestamp",
    "week",
    "weekday",
    "weekofyear",
    "year",
    "yearweek",
    // Comparison and control flow
    "coalesce",
    "greatest",
    "if",
    "ifnull",
    "interval",
    "isnull",
    "least",
    "nullif",
    "strcmp",
    // Cast
    "binary",
    "cast",
    "convert",
    // JSON, read-only forms only
    "json_array",
    "json_contains",
    "json_contains_path",
    "json_depth",
    "json_extract",
    "json_keys",
    "json_length",
    "json_object",
    "json_overlaps",
    "json_pretty",
    "json_quote",
    "json_search",
    "json_storage_size",
    "json_type",
    "json_unquote",
    "json_valid",
    "json_value",
    // Hashing
    "md5",
    "sha",
    "sha1",
    "sha2",
    // Network address conversion
    "inet_aton",
    "inet_ntoa",
    "inet6_aton",
    "inet6_ntoa",
    "is_ipv4",
    "is_ipv4_compat",
    "is_ipv4_mapped",
    "is_ipv6",
    // Information about the connection's own database, not about the account
    "database",
    "schema",
];

/// Classifies one function name, and names the risk when there is one.
///
/// The `Option<RiskFlag>` is the evidence half: `FunctionSafetyPolicy` acts on the
/// classification and `RiskEvidencePolicy` acts on the flag, so a dangerous call is
/// denied twice by independent rules and an audit record says *which* danger it was
/// rather than only "dangerous function".
pub(crate) fn classify(name: &str) -> (FunctionClassification, Option<RiskFlag>) {
    let lowered = name.to_ascii_lowercase();

    if let Some((_, flag)) = DANGEROUS.iter().find(|(known, _)| *known == lowered) {
        return (FunctionClassification::KnownDangerous, Some(*flag));
    }
    if SAFE.contains(&lowered.as_str()) {
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
        // `docs/security.md` section 7.2 lists these by name; losing one would
        // remove a row from the threat-to-control matrix silently.
        for name in [
            "sleep",
            "benchmark",
            "get_lock",
            "release_lock",
            "load_file",
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
        assert_eq!(classify("SLEEP").1, Some(RiskFlag::DelayFunction));
        assert_eq!(classify("get_lock").1, Some(RiskFlag::AdvisoryLock));
        assert_eq!(classify("LOAD_FILE").1, Some(RiskFlag::FileAccess));
    }

    #[test]
    fn an_unlisted_function_is_unknown_and_carries_evidence() {
        let (classification, risk) = classify("sys_exec");
        assert_eq!(classification, FunctionClassification::Unknown);
        assert_eq!(risk, Some(RiskFlag::UserDefinedFunction));
    }

    #[test]
    fn account_and_counter_functions_are_deliberately_unclassified() {
        // Left out of the allowlist on purpose; the test exists so that adding one
        // has to be a decision rather than a slip.
        for name in [
            "user",
            "current_user",
            "session_user",
            "system_user",
            "connection_id",
            "found_rows",
            "row_count",
            "uuid_short",
            "version",
            "uuid",
        ] {
            assert_eq!(classify(name).0, FunctionClassification::Unknown, "{name}");
        }
    }

    #[test]
    fn classification_ignores_ascii_case() {
        assert_eq!(classify("CoUnT").0, FunctionClassification::KnownSafe);
        assert_eq!(classify("SlEeP").0, FunctionClassification::KnownDangerous);
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
