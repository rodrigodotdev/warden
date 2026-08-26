//! Mechanical guards for rules the Rust compiler cannot express.
//!
//! The MySQL counterpart of this file shipped in Milestone 4 and AGENTS.md recorded
//! that `warden-postgres` owed the same check. This is it. It runs as a separate
//! crate so it sees exactly the surface `warden-service` will see.
//!
//! The scans skip comment lines: the documentation explains why the AST must stay
//! inside, and those explanations must not trip the check that enforces them.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

/// The only files allowed to declare a `pub` item. Everything else is internal.
const PUBLIC_FILES: &[&str] = &[
    "lib.rs",
    "analyzer.rs",
    "connection.rs",
    "error.rs",
    "execute.rs",
];

/// Type names that would carry a parser AST across the crate boundary.
const AST_TYPES: &[&str] = &[
    "sqlparser",
    "Statement",
    "Expr",
    "ObjectName",
    "ObjectNamePart",
    "Ident",
    "TableFactor",
    "SetExpr",
    "UtilityOption",
    "Visitor",
    "VisitorMut",
    "Parser",
    "ParserError",
    "Token",
    "Tokenizer",
];

/// Type names that would carry a driver handle across the crate boundary.
const DRIVER_TYPES: &[&str] = &[
    "sqlx",
    "Postgres",
    "PgPool",
    "PgPoolOptions",
    "PgConnectOptions",
    "PgConnection",
    "PgSslMode",
    "PgRow",
    "PgArguments",
    "Pool",
    "PoolOptions",
    "PoolConnection",
    "Transaction",
    "Executor",
];

fn source_files() -> Vec<PathBuf> {
    fn collect(directory: &Path, found: &mut Vec<PathBuf>) {
        let entries = fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("could not read {}: {error}", directory.display()));
        for entry in entries {
            let path = entry.expect("unreadable directory entry").path();
            if path.is_dir() {
                collect(&path, found);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                found.push(path);
            }
        }
    }

    let mut found = Vec::new();
    collect(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut found,
    );
    assert!(
        !found.is_empty(),
        "no source files found; did the layout change?"
    );
    found.sort();
    found
}

/// Lines of code, with comment lines and an inline `#[cfg(test)]` module removed.
///
/// A test-only field or helper is still production-adjacent code that a mechanical
/// rule must inspect, so only the attribute immediately followed by an inline test
/// module cuts the scan. A substring match would let a doc comment that happens to
/// mention `#[cfg(test)]` earlier in the file silently hide every real line below it
/// — export guard included — while the tests kept passing.
fn code_lines(path: &Path) -> Vec<(usize, String)> {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    let lines: Vec<_> = text
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line.trim().to_owned()))
        .collect();
    let test_module = lines
        .windows(2)
        .position(|window| window[0].1 == "#[cfg(test)]" && window[1].1.starts_with("mod "))
        .unwrap_or(lines.len());
    lines
        .into_iter()
        .take(test_module)
        .filter(|(_, line)| !line.starts_with("//"))
        .collect()
}

/// A `pub` item declaration that is not `pub(crate)` or `pub(super)`.
fn is_exported(line: &str) -> bool {
    line.starts_with("pub ") && !line.starts_with("pub(")
}

/// Whether `line` names `type_name` as an identifier rather than as a substring.
///
/// Without the boundary check, `Statement` would match `StatementKind` and the scan
/// would fire on every classification signature. A scan that cries wolf gets
/// exempted, so it has to be precise enough to stay on.
fn names_type(line: &str, type_name: &str) -> bool {
    line.match_indices(type_name).any(|(start, _)| {
        let before = line[..start].chars().next_back();
        let after = line[start + type_name.len()..].chars().next();
        let boundary = |c: Option<char>| c.is_none_or(|c| !c.is_alphanumeric() && c != '_');
        boundary(before) && boundary(after)
    })
}

/// Complete spans that make up an exported declaration's public surface.
///
/// Headers include multiline parameters, return types, aliases, and `where` clauses.
/// Public structs additionally include public fields; public traits include associated
/// declarations but omit default-method implementation bodies.
fn exported_declaration_spans(lines: &[(usize, String)]) -> Vec<Vec<(usize, String)>> {
    let mut spans = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let (_, line) = &lines[index];
        if !is_exported(line) {
            index += 1;
            continue;
        }
        let header_end = declaration_header_end(lines, index);
        let mut span = lines[index..=header_end].to_vec();
        let starts_struct = line.starts_with("pub struct ") || line.starts_with("pub union ");
        let starts_enum = line.starts_with("pub enum ");
        let starts_trait = is_public_trait(line);
        if lines[header_end].1.contains('{') && (starts_struct || starts_enum || starts_trait) {
            let body_end = declaration_body_end(lines, header_end);
            if starts_struct {
                append_public_struct_fields(&mut span, lines, header_end + 1, body_end);
            } else if starts_trait {
                append_public_trait_declarations(&mut span, lines, header_end + 1, body_end);
            } else {
                span.extend_from_slice(&lines[header_end + 1..body_end]);
            }
            index = body_end + 1;
        } else {
            index = header_end + 1;
        }
        spans.push(span);
    }
    spans
}

fn is_public_trait(line: &str) -> bool {
    line.starts_with("pub ") && line.split_whitespace().any(|word| word == "trait")
}

fn declaration_header_end(lines: &[(usize, String)], start: usize) -> usize {
    let mut index = start;
    while index + 1 < lines.len() && !lines[index].1.contains('{') && !lines[index].1.ends_with(';')
    {
        index += 1;
    }
    index
}

fn declaration_body_end(lines: &[(usize, String)], header_end: usize) -> usize {
    let mut depth = brace_delta(&lines[header_end].1);
    let mut index = header_end;
    while depth > 0 && index + 1 < lines.len() {
        index += 1;
        depth += brace_delta(&lines[index].1);
    }
    index
}

fn append_public_struct_fields(
    span: &mut Vec<(usize, String)>,
    lines: &[(usize, String)],
    start: usize,
    end: usize,
) {
    let mut depth = 1;
    let mut index = start;
    while index < end {
        let (_, line) = &lines[index];
        if depth == 1 && is_exported(line) {
            let field_end = struct_field_end(lines, index, end);
            span.extend_from_slice(&lines[index..=field_end]);
        }
        depth += brace_delta(line);
        index += 1;
    }
}

fn append_public_trait_declarations(
    span: &mut Vec<(usize, String)>,
    lines: &[(usize, String)],
    start: usize,
    end: usize,
) {
    let mut index = start;
    while index < end {
        if !is_trait_item_start(&lines[index].1) {
            index += 1;
            continue;
        }
        let header_end = declaration_header_end(lines, index);
        if lines[header_end].1.contains('{') {
            span.extend_from_slice(&lines[index..header_end]);
            let (number, line) = &lines[header_end];
            let header = line
                .split_once('{')
                .map_or(line.as_str(), |(before, _)| before);
            span.push((*number, header.trim_end().to_owned()));
            index = declaration_body_end(lines, header_end) + 1;
        } else {
            span.extend_from_slice(&lines[index..=header_end]);
            index = header_end + 1;
        }
    }
}

fn is_trait_item_start(line: &str) -> bool {
    let mut words = line.split_whitespace();
    matches!(words.next(), Some("type" | "const" | "fn")) || words.any(|word| word == "fn")
}

fn struct_field_end(lines: &[(usize, String)], start: usize, end: usize) -> usize {
    let mut index = start;
    while index + 1 < end && !lines[index].1.ends_with(',') {
        index += 1;
    }
    index
}

fn brace_delta(line: &str) -> i32 {
    let opens = i32::try_from(line.matches('{').count()).unwrap_or(i32::MAX);
    let closes = i32::try_from(line.matches('}').count()).unwrap_or(i32::MAX);
    opens.saturating_sub(closes)
}

/// Aliases that make a driver type reachable under a different name.
///
/// `use sqlx::postgres::PgPool as Backend;` followed by `pub type Leaked = Backend;`
/// exports a pool under a name no list of driver types contains. Both renaming forms
/// are resolved here — the import rename and the type alias — and type aliases are
/// followed to a fixed point so a chain of them cannot outrun the scan.
fn driver_type_names(lines: &[(usize, String)]) -> Vec<String> {
    let mut names: Vec<String> = DRIVER_TYPES.iter().map(|name| (*name).to_owned()).collect();

    for (_, line) in lines {
        if !line.contains("use ") || !line.contains("sqlx") {
            continue;
        }
        for alias in renamed_imports(line) {
            if !names.contains(&alias) {
                names.push(alias);
            }
        }
    }

    loop {
        let before = names.len();
        for (_, line) in lines {
            let Some((alias, aliased)) = type_alias(line) else {
                continue;
            };
            if names.contains(&alias) {
                continue;
            }
            if names.iter().any(|name| names_type(&aliased, name)) {
                names.push(alias);
            }
        }
        if names.len() == before {
            return names;
        }
    }
}

/// The names introduced by `as` in one `use` declaration.
fn renamed_imports(line: &str) -> Vec<String> {
    let mut aliases = Vec::new();
    let mut renaming = false;
    for token in line
        .split(|character: char| !(character.is_alphanumeric() || character == '_'))
        .filter(|token| !token.is_empty())
    {
        if renaming {
            aliases.push(token.to_owned());
        }
        renaming = token == "as";
    }
    aliases
}

/// The alias and the aliased text of a single-line `type X = Y;` declaration.
fn type_alias(line: &str) -> Option<(String, String)> {
    let (declaration, aliased) = line.split_once('=')?;
    let mut words = declaration.split_whitespace();
    let name = loop {
        match words.next()? {
            "type" => break words.next()?,
            _ => continue,
        }
    };
    let name = name.split(['<', ':']).next()?.trim();
    (!name.is_empty()).then(|| (name.to_owned(), aliased.to_owned()))
}

/// Finds SQLx types, including renamed ones, on exported declaration spans.
fn driver_type_violations(lines: &[(usize, String)]) -> Vec<(usize, String)> {
    let names = driver_type_names(lines);
    let mut violations = Vec::new();
    for span in exported_declaration_spans(lines) {
        for (number, line) in span {
            // One report per offending line: an alias chain can make several names
            // match the same declaration, and a duplicated line reads as two faults.
            if names
                .iter()
                .any(|driver_type| names_type(&line, driver_type))
            {
                violations.push((number, line.clone()));
            }
        }
    }
    violations
}

#[test]
fn only_the_analyzer_and_the_crate_root_export_anything() {
    let mut violations = Vec::new();
    for path in source_files() {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if PUBLIC_FILES.contains(&name) {
            continue;
        }
        for (number, line) in code_lines(&path) {
            if is_exported(&line) {
                violations.push(format!("  {}:{number}: {line}", path.display()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "these internal items are exported:\n{}\n\n\
         Keeping the crate's public surface to the five reviewed files is what \
         makes \"no parser AST and no driver handle leaves the adapter\" checkable \
         at all (ADR-0007, ADR-0005). Use `pub(crate)`.",
        violations.join("\n")
    );
}

#[test]
fn no_public_signature_names_a_parser_type() {
    // Deliberately not filtered by `is_exported`: Rust forbids `pub` inside a
    // trait-impl block, so `impl QueryAnalyzer for PostgreSqlAnalyzer`'s methods —
    // the actual public contract `warden-service` calls — start with `fn`, not
    // `pub fn`, and would be invisible to a `pub`-only scan. The two public
    // files are small and reviewed, so scanning every non-comment line in them
    // is precise enough; `names_type`'s word-boundary check still keeps
    // `StatementKind` from matching `Statement`.
    let mut violations = Vec::new();
    for path in source_files() {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !PUBLIC_FILES.contains(&name) {
            continue;
        }
        for (number, line) in code_lines(&path) {
            for ast_type in AST_TYPES {
                if names_type(&line, ast_type) {
                    violations.push(format!("  {}:{number}: {line}", path.display()));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "a `sqlparser` type appears in the crate's public surface:\n{}\n\n\
         SPEC section 6, invariant 28 and ADR-0007 keep parser ASTs inside adapter \
         crates; that is the seam that lets a future adapter replace `sqlparser` \
         without touching MCP, core, policy, or audit models. This scan covers \
         every line of `lib.rs` and `analyzer.rs`, not only `pub`-prefixed ones, \
         because a trait-impl method such as `QueryAnalyzer::analyze` is public \
         without ever writing the word `pub`.",
        violations.join("\n")
    );
}

#[test]
fn no_public_signature_names_a_driver_type() {
    let mut violations = Vec::new();
    for path in source_files() {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if !PUBLIC_FILES.contains(&name) {
            continue;
        }
        for (number, line) in driver_type_violations(&code_lines(&path)) {
            violations.push(format!("  {}:{number}: {line}", path.display()));
        }
    }
    assert!(
        violations.is_empty(),
        "a SQLx type appears in the crate's public surface:\n{}\n\n\
         ADR-0005 keeps concrete pools inside the adapter. Nothing above this crate \
         needs a `PgPool`: the composition root builds a \
         `PostgreSqlConnectionPools`, hands it to the executor, and never names a \
         driver type. Use `pub(crate)`.",
        violations.join("\n")
    );
}

#[test]
fn driver_surface_scan_catches_a_type_on_a_multiline_public_signature() {
    let fixture = vec![
        (10, "pub fn leaked_pool(".to_owned()),
        (11, "pool: PgPool,".to_owned()),
        (12, ") {}".to_owned()),
        (20, "pub struct PublicConfig<T>".to_owned()),
        (21, "where".to_owned()),
        (22, "T: Executor,".to_owned()),
        (23, "{".to_owned()),
        (24, "pub pool:".to_owned()),
        (25, "PgPool,".to_owned()),
        (26, "private: Transaction,".to_owned()),
        (27, "}".to_owned()),
        (30, "pub enum PublicState {".to_owned()),
        (31, "Connected(PgConnection),".to_owned()),
        (32, "}".to_owned()),
        (40, "pub type DriverAlias<T>".to_owned()),
        (41, "where".to_owned()),
        (42, "T: Pool,".to_owned()),
        (43, "= ();".to_owned()),
        (50, "pub trait DriverPort {".to_owned()),
        (51, "fn pool(".to_owned()),
        (52, "&self,".to_owned()),
        (53, ") -> PgPool".to_owned()),
        (54, "where".to_owned()),
        (55, "Self: Executor;".to_owned()),
        (56, "type ActiveTransaction: Transaction;".to_owned()),
        (57, "fn with_default(&self) {".to_owned()),
        (58, "let local: PgPool;".to_owned()),
        (59, "if true {".to_owned()),
        (60, "let nested: Executor;".to_owned()),
        (61, "}".to_owned()),
        (62, "}".to_owned()),
        (
            63,
            "fn inline_default(&self) { let inline: PgConnection; }".to_owned(),
        ),
        (64, "}".to_owned()),
    ];
    assert_eq!(
        driver_type_violations(&fixture),
        vec![
            (11, "pool: PgPool,".to_owned()),
            (22, "T: Executor,".to_owned()),
            (25, "PgPool,".to_owned()),
            (31, "Connected(PgConnection),".to_owned()),
            (42, "T: Pool,".to_owned()),
            (53, ") -> PgPool".to_owned()),
            (55, "Self: Executor;".to_owned()),
            (56, "type ActiveTransaction: Transaction;".to_owned()),
        ],
        "a driver type on a public declaration continuation must be caught"
    );
}

#[test]
fn driver_surface_scan_follows_a_chain_of_private_type_aliases() {
    let fixture = vec![
        (10, "type Backend = PgPool;".to_owned()),
        (11, "type Inner = Backend;".to_owned()),
        (12, "pub struct Config {".to_owned()),
        (13, "pub pool: Inner,".to_owned()),
        (14, "}".to_owned()),
    ];

    assert_eq!(
        driver_type_violations(&fixture),
        vec![(13, "pub pool: Inner,".to_owned())],
        "a chain of private aliases must stay tainted at the public field"
    );
}

#[test]
fn driver_surface_scan_leaves_an_unrelated_alias_alone() {
    let fixture = vec![
        (10, "type Rows = Vec<String>;".to_owned()),
        (11, "pub fn rows() -> Rows { Vec::new() }".to_owned()),
    ];

    assert!(
        driver_type_violations(&fixture).is_empty(),
        "an alias that names no driver type is not a violation"
    );
}

#[test]
fn driver_surface_scan_resolves_a_renamed_sqlx_import_in_a_public_alias() {
    let fixture = vec![
        (10, "use sqlx::postgres::PgPool as Backend;".to_owned()),
        (11, "pub type Leaked = Backend;".to_owned()),
    ];

    assert_eq!(
        driver_type_violations(&fixture),
        vec![(11, "pub type Leaked = Backend;".to_owned())],
        "a renamed SQLx import must remain tainted through a public alias"
    );
}

/// Whether `current` is a wildcard arm whose *preceding* arm's pattern side names a
/// `warden-core` security enum.
///
/// Only the pattern side of `previous` — the text before its first `=>` — is
/// checked. Scanning the whole line produces a false positive when rustfmt splits a
/// multi-line arm across lines: `visit.rs`'s `Expr::BinaryOp { op:
/// BinaryOperator::PGCustomBinaryOperator(_), .. }` arm closes over several lines, so
/// the line right before the later `_ => {}` (over `Expr`, the deliberate exception
/// documented in `lib.rs`) is `} => self.flag(RiskFlag::UnknownConstruct),` — the bare
/// `}` that closes the multi-line pattern, with `RiskFlag::` appearing only on the
/// right-hand side of that same, unrelated arm.
/// The rule is about what is being *matched*, not what an arm's body does, exactly
/// as the comment on the scan itself says.
///
/// This still catches a real violation: a `StatementKind::Unknown => ...` pattern
/// arm immediately followed by `_ =>` still carries `StatementKind::` in the pattern
/// text of the preceding line, and a multi-line `|`-chained pattern still ends with
/// pattern text (not a call) on the line right before the wildcard.
///
/// Known blind spot, left as a comment rather than fixed: an arm whose *body* is a
/// braced block puts a bare `}` on the line preceding the wildcard, with the guarded
/// enum name several lines further up. Neither this function nor a whole-line scan
/// catches that shape.
fn wildcard_follows_guarded_pattern(previous: &str, current: &str, guarded: &[&str]) -> bool {
    let is_wildcard = current.starts_with("_ =>") || current.starts_with("_ if");
    let pattern = previous.split("=>").next().unwrap_or(previous);
    is_wildcard && guarded.iter().any(|prefix| pattern.contains(prefix))
}

#[test]
fn no_wildcard_arm_matches_a_warden_core_security_enum() {
    // Wildcards over `sqlparser` enums are required (AGENTS.md, "Modeling") and map
    // to Unknown. Wildcards over a `warden-core` security enum are forbidden: a new
    // variant must break this build (ADR-0021). The two are told apart by whether
    // the *pattern side* of the arm preceding the wildcard names a `warden-core`
    // enum — see `wildcard_follows_guarded_pattern`.
    let guarded = [
        "StatementKind::",
        "RiskFlag::",
        "FunctionClassification::",
        "ObjectKind::",
    ];
    let mut violations = Vec::new();

    for path in source_files() {
        let lines = code_lines(&path);
        for window in lines.windows(2) {
            let (previous, current) = (&window[0].1, &window[1]);
            if wildcard_follows_guarded_pattern(previous, &current.1, &guarded) {
                violations.push(format!("  {}:{}: {}", path.display(), current.0, current.1));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "a wildcard arm follows a `warden-core` security enum:\n{}\n\n\
         Adding a variant there must break this crate's build, not slip through a \
         wildcard (ADR-0021).",
        violations.join("\n")
    );
}

#[test]
fn the_scans_are_alive() {
    // A scan that finds nothing because its inputs are empty passes forever.
    assert!(names_type("pub fn f(s: &Statement)", "Statement"));
    assert!(!names_type("pub fn f(k: StatementKind)", "Statement"));
    assert!(!names_type("pub fn f(r: QueryRequest)", "Statement"));
    assert!(is_exported("pub struct PostgreSqlAnalyzer;"));
    assert!(!is_exported("pub(crate) fn kind_of()"));
    assert!(
        source_files().iter().any(|p| p.ends_with("analyzer.rs")),
        "the analyzer module moved; the public-surface scan needs updating"
    );
    assert!(
        source_files().len() >= 14,
        "fewer modules than Milestone 8 shipped; the scans may be reading the wrong \
         directory"
    );

    // The AST-containment scan no longer filters on `is_exported`, because a
    // trait-impl method — `QueryAnalyzer::analyze`'s own signature, for
    // instance — is public without ever writing `pub`. Prove the detection
    // primitive still fires on that shape, so the widened scan would catch it.
    assert!(
        names_type(
            "fn analyze(&self, s: &Statement) -> Result<Foo, Bar> {",
            "Statement"
        ),
        "a parser type in a trait-impl method signature, which never starts \
         with `pub`, must still be caught now that the scan is not gated on \
         `is_exported`"
    );

    // The wildcard scan must fire in both directions, not merely fail to fire.
    let guarded = [
        "StatementKind::",
        "RiskFlag::",
        "FunctionClassification::",
        "ObjectKind::",
    ];
    assert!(
        wildcard_follows_guarded_pattern(
            "StatementKind::Unknown => evidence.flag(RiskFlag::UnknownConstruct),",
            "_ => {}",
            &guarded
        ),
        "a real violation — a wildcard following a pattern arm that names a \
         warden-core enum — must be caught"
    );
    assert!(
        !wildcard_follows_guarded_pattern(
            "} => self.flag(RiskFlag::UnknownConstruct),",
            "_ => {}",
            &guarded
        ),
        "a wildcard over `Expr` must not be flagged merely because the previous \
         arm's body, not its pattern, mentions a warden-core enum \
         (the false positive this scan was narrowed to avoid)"
    );
}

/// Calls that would read a whole result into memory before any bound applied.
const BUFFERING_FETCHES: &[&str] = &["fetch_all(", "fetch_one(", "fetch_optional("];

/// Whether the control-pool cancellation statement binds its backend pid.
///
/// The scan follows the fluent statement through its terminating semicolon, so the
/// SQL literal alone cannot satisfy it: a missing `.bind(backend_pid)` is a failure.
fn cancellation_statement_binds_pid(lines: &[&str]) -> bool {
    let mut cancel_statement = None;

    for line in lines {
        if line.contains("sqlx::query(\"SELECT pg_cancel_backend($1)\")") {
            cancel_statement = Some(line.contains(".bind(backend_pid)"));
            continue;
        }
        let Some(bound) = cancel_statement else {
            continue;
        };
        let bound = bound || line.contains(".bind(backend_pid)");
        if line.ends_with(';') {
            return bound;
        }
        cancel_statement = Some(bound);
    }

    false
}

#[test]
fn cancellation_guard_rejects_a_pidless_statement() {
    let bound = [
        "let statement = sqlx::query(\"SELECT pg_cancel_backend($1)\")",
        ".bind(backend_pid)",
        ".execute(self.pools.control());",
    ];
    let pidless = [
        "let statement = sqlx::query(\"SELECT pg_cancel_backend($1)\")",
        ".execute(self.pools.control());",
    ];

    assert!(cancellation_statement_binds_pid(&bound));
    assert!(!cancellation_statement_binds_pid(&pidless));
}

#[test]
fn agent_sql_is_never_read_into_memory_before_it_is_bounded() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/execute.rs");
    let mut streams = false;
    for (number, line) in code_lines(&path) {
        for buffering in BUFFERING_FETCHES {
            assert!(
                !(line.contains(buffering) && !line.contains("pg_backend_pid")),
                "src/execute.rs:{number} buffers a result with {buffering}"
            );
        }
        streams |= line.contains(".fetch(");
    }
    assert!(
        streams,
        "src/execute.rs never calls `.fetch`, so the ban above passed on an absence"
    );
}

#[test]
fn execute_rs_interpolates_nothing_at_all() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/execute.rs");
    let lines = code_lines(&path);
    for (number, line) in &lines {
        assert!(
            !line.contains("format!"),
            "src/execute.rs:{number} interpolates with format!; PostgreSQL has no \
             audited exception to the bind-only rule"
        );
    }
    let source: Vec<&str> = lines.iter().map(|(_, line)| line.as_str()).collect();
    assert!(
        cancellation_statement_binds_pid(&source),
        "src/execute.rs no longer binds the cancellation pid into \
         `pg_cancel_backend($1)`"
    );
}

#[test]
fn executor_closes_the_named_agent_statement_after_each_request() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/execute.rs");
    let source = code_lines(&path)
        .into_iter()
        .map(|(_, line)| line)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        source.contains("DEALLOCATE ALL"),
        "src/execute.rs does not close the temporary named agent statement"
    );
}
