//! Deterministic column redaction, applied after normalization and before a response
//! leaves this process (`docs/security.md` section 8).
//!
//! # What it is not
//!
//! **Redaction is not authorization.** It matches *output* column names, so
//! `SELECT password AS p` produces `p` and this matcher never sees the rule's name.
//! Aliases and expressions defeat it by construction. It protects against accidental
//! exposure and minimizes output; an agent that must never reach a secret column
//! needs a database `GRANT` or a view that omits it (SPEC section 7).
//!
//! # Matching
//!
//! A rule is `table.column` or `*.column`. Comparison is ASCII case-insensitive.
//! A result column carries no table provenance, so only a wildcard rule can match it.
//! Described columns carry their table, so both forms apply. Plan-document members
//! have no table provenance and their key is matched; free SQL text is never scanned.

use serde_json::Value;
use warden_core::explain::QueryPlan;
use warden_core::result::{ResultSet, ResultValue, row_json_bytes};
use warden_core::schema::SchemaDescription;

/// The fixed text a replaced value becomes.
pub const REDACTED: &str = "[REDACTED]";

/// What happens to a matched value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RedactionStrategy {
    /// Replace it with [`REDACTED`], so the agent can see a value existed.
    #[default]
    Replace,
    /// Drop it, so the response carries no trace of the value.
    Null,
}

/// The redaction rules exactly as configuration supplies them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedactionSettings {
    /// Rules of the form `table.column` or `*.column`.
    pub columns: Vec<String>,
    /// What a match does. Defaults to [`RedactionStrategy::Replace`].
    pub strategy: RedactionStrategy,
}

/// A configured rule that could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RedactionRuleError {
    /// The rule was not `table.column` or `*.column`.
    #[error("redaction rule {rule:?} is not `table.column` or `*.column`")]
    Malformed {
        /// The offending rule, quoted so an empty one is visible.
        rule: String,
    },
    /// One side of the rule was empty.
    #[error("redaction rule {rule:?} has an empty part")]
    EmptyPart {
        /// The offending rule.
        rule: String,
    },
}

/// One parsed rule. `table: None` represents the `*` wildcard.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    table: Option<String>,
    column: String,
}

impl Rule {
    fn parse(rule: &str) -> Result<Self, RedactionRuleError> {
        let malformed = || RedactionRuleError::Malformed {
            rule: rule.to_owned(),
        };
        let mut parts = rule.split('.');
        let (table, column) = match (parts.next(), parts.next(), parts.next()) {
            (Some(table), Some(column), None) => (table, column),
            _ => return Err(malformed()),
        };
        if table.is_empty() || column.is_empty() {
            return Err(RedactionRuleError::EmptyPart {
                rule: rule.to_owned(),
            });
        }
        Ok(Self {
            table: (table != "*").then(|| table.to_ascii_lowercase()),
            column: column.to_ascii_lowercase(),
        })
    }

    fn matches(&self, table: Option<&str>, column: &str) -> bool {
        if !self.column.eq_ignore_ascii_case(column) {
            return false;
        }
        match (&self.table, table) {
            (None, _) => true,
            (Some(expected), Some(actual)) => expected.eq_ignore_ascii_case(actual),
            (Some(_), None) => false,
        }
    }
}

/// The configured column rules, ready to apply to a response.
#[derive(Debug)]
pub struct Redactor {
    rules: Vec<Rule>,
    strategy: RedactionStrategy,
}

impl Redactor {
    /// Parses every configured rule, failing on the first malformed one.
    pub fn new(settings: &RedactionSettings) -> Result<Self, RedactionRuleError> {
        let rules = settings
            .columns
            .iter()
            .map(|rule| Rule::parse(rule))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            rules,
            strategy: settings.strategy,
        })
    }

    /// Whether no rule is configured, in which case every `redact_*` call is a no-op.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    fn matches(&self, table: Option<&str>, column: &str) -> bool {
        self.rules.iter().any(|rule| rule.matches(table, column))
    }

    /// Redacts matching result columns and recomputes their JSON byte count.
    pub fn redact_result(&self, result: &mut ResultSet) {
        if self.is_empty() {
            return;
        }
        let targets: Vec<bool> = result
            .columns
            .iter()
            .map(|column| self.matches(None, &column.name))
            .collect();
        if !targets.iter().any(|matched| *matched) {
            return;
        }
        for row in &mut result.rows {
            for (value, matched) in row.iter_mut().zip(&targets) {
                if *matched {
                    *value = match self.strategy {
                        RedactionStrategy::Replace => ResultValue::String(REDACTED.to_owned()),
                        RedactionStrategy::Null => ResultValue::Null,
                    };
                }
            }
        }
        result.stats.bytes = result.rows.iter().map(|row| row_json_bytes(row)).sum();
    }

    /// Redacts matching described columns' defaults and comments.
    pub fn redact_description(&self, description: &mut SchemaDescription) {
        if self.is_empty() {
            return;
        }
        for schema in &mut description.schemas {
            for table in &mut schema.tables {
                for column in &mut table.columns {
                    if !self.matches(Some(&table.name), &column.name) {
                        continue;
                    }
                    match self.strategy {
                        RedactionStrategy::Replace => {
                            column.default = column.default.as_ref().map(|_| REDACTED.to_owned());
                            column.comment = column.comment.as_ref().map(|_| REDACTED.to_owned());
                        }
                        RedactionStrategy::Null => {
                            column.default = None;
                            column.comment = None;
                        }
                    }
                }
            }
        }
    }

    /// Redacts plan members whose key matches a rule's column part.
    pub fn redact_plan(&self, plan: &mut QueryPlan) {
        if self.is_empty() {
            return;
        }
        let mut stack = vec![&mut plan.plan];
        while let Some(node) = stack.pop() {
            match node {
                Value::Object(members) => {
                    for (key, value) in members.iter_mut() {
                        if self.matches(None, key) {
                            *value = match self.strategy {
                                RedactionStrategy::Replace => Value::String(REDACTED.to_owned()),
                                RedactionStrategy::Null => Value::Null,
                            };
                        } else {
                            stack.push(value);
                        }
                    }
                }
                Value::Array(items) => stack.extend(items.iter_mut()),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use warden_core::dialect::Dialect;
    use warden_core::explain::{PlanSummary, QueryPlan};
    use warden_core::result::{QueryStats, ResultColumn, ResultSet, ResultValue, row_json_bytes};
    use warden_core::schema::{ColumnDescription, Schema, SchemaDescription, Table, TableKind};

    use super::*;

    fn redactor(columns: &[&str], strategy: RedactionStrategy) -> Redactor {
        Redactor::new(&RedactionSettings {
            columns: columns.iter().map(|rule| (*rule).to_owned()).collect(),
            strategy,
        })
        .unwrap()
    }

    fn result() -> ResultSet {
        let rows = vec![vec![
            ResultValue::I64(1),
            ResultValue::String("hunter2".to_owned()),
            ResultValue::String("note: \"quoted\"\n".to_owned()),
        ]];
        ResultSet {
            columns: vec![
                ResultColumn {
                    name: "id".to_owned(),
                    database_type: "BIGINT".to_owned(),
                    nullable: None,
                },
                ResultColumn {
                    name: "Password".to_owned(),
                    database_type: "TEXT".to_owned(),
                    nullable: None,
                },
                ResultColumn {
                    name: "note".to_owned(),
                    database_type: "TEXT".to_owned(),
                    nullable: None,
                },
            ],
            stats: QueryStats {
                rows_returned: rows.len(),
                bytes: rows.iter().map(|row| row_json_bytes(row)).sum(),
                duration: std::time::Duration::from_millis(1),
            },
            rows,
            truncated: false,
        }
    }

    #[test]
    fn a_wildcard_rule_replaces_a_matching_column_ignoring_case() {
        let mut set = result();
        redactor(&["*.password"], RedactionStrategy::Replace).redact_result(&mut set);
        assert_eq!(set.rows[0][0], ResultValue::I64(1));
        assert_eq!(set.rows[0][1], ResultValue::String(REDACTED.to_owned()));
    }

    #[test]
    fn the_null_strategy_removes_the_value_instead_of_replacing_it() {
        let mut set = result();
        redactor(&["*.password"], RedactionStrategy::Null).redact_result(&mut set);
        assert_eq!(set.rows[0][1], ResultValue::Null);
    }

    #[test]
    fn redacting_recomputes_the_byte_figure_the_agent_actually_receives() {
        let mut set = result();
        redactor(&["*.password"], RedactionStrategy::Null).redact_result(&mut set);
        let expected = serde_json::to_string(&set.rows[0]).unwrap().len();
        assert_eq!(set.stats.bytes, expected);
    }

    #[test]
    fn a_qualified_rule_cannot_match_a_result_column() {
        // A result column has no table provenance: duplicate names and expressions
        // make it unknowable, so only `*.column` rules can apply here.
        let mut set = result();
        redactor(&["orders.password"], RedactionStrategy::Replace).redact_result(&mut set);
        assert_eq!(set.rows[0][1], ResultValue::String("hunter2".to_owned()));
    }

    #[test]
    fn a_qualified_rule_matches_the_table_it_names_in_a_description() {
        let mut description = description();
        redactor(&["orders.secret"], RedactionStrategy::Replace)
            .redact_description(&mut description);
        let column = &description.schemas[0].tables[0].columns[1];
        assert_eq!(column.default.as_deref(), Some(REDACTED));
        assert_eq!(column.comment.as_deref(), Some(REDACTED));
    }

    #[test]
    fn a_qualified_rule_leaves_another_table_alone() {
        let mut description = description();
        redactor(&["invoices.secret"], RedactionStrategy::Replace)
            .redact_description(&mut description);
        assert_eq!(
            description.schemas[0].tables[0].columns[1]
                .default
                .as_deref(),
            Some("'s3cr3t'")
        );
    }

    #[test]
    fn the_null_strategy_drops_a_described_default_and_comment() {
        let mut description = description();
        redactor(&["*.secret"], RedactionStrategy::Null).redact_description(&mut description);
        let column = &description.schemas[0].tables[0].columns[1];
        assert_eq!(column.default, None);
        assert_eq!(column.comment, None);
    }

    #[test]
    fn a_plan_member_named_like_a_redacted_column_loses_its_value() {
        let mut plan = QueryPlan {
            dialect: Dialect::PostgreSql,
            summary: PlanSummary::default(),
            plan: serde_json::json!([{ "Plan": { "Node Type": "Seq Scan", "password": "hunter2" } }]),
        };
        redactor(&["*.password"], RedactionStrategy::Replace).redact_plan(&mut plan);
        assert_eq!(
            plan.plan[0]["Plan"]["password"],
            serde_json::json!(REDACTED)
        );
        assert_eq!(
            plan.plan[0]["Plan"]["Node Type"],
            serde_json::json!("Seq Scan")
        );
    }

    #[test]
    fn an_empty_rule_set_changes_nothing() {
        let redactor = redactor(&[], RedactionStrategy::Replace);
        assert!(redactor.is_empty());
        let mut set = result();
        let before = set.clone();
        redactor.redact_result(&mut set);
        assert_eq!(set, before);
    }

    #[test]
    fn a_malformed_rule_names_itself_and_fails_startup() {
        for rule in ["password", "a.b.c", ""] {
            let error = Redactor::new(&RedactionSettings {
                columns: vec![rule.to_owned()],
                strategy: RedactionStrategy::Replace,
            })
            .unwrap_err();
            assert!(error.to_string().contains(rule), "{error}");
        }
        assert_eq!(
            Redactor::new(&RedactionSettings {
                columns: vec![".password".to_owned()],
                strategy: RedactionStrategy::Replace,
            })
            .unwrap_err(),
            RedactionRuleError::EmptyPart {
                rule: ".password".to_owned()
            }
        );
    }

    fn description() -> SchemaDescription {
        SchemaDescription {
            schemas: vec![Schema {
                name: "app".to_owned(),
                tables: vec![Table {
                    schema: "app".to_owned(),
                    name: "orders".to_owned(),
                    kind: TableKind::Table,
                    columns: vec![
                        ColumnDescription {
                            name: "id".to_owned(),
                            database_type: "BIGINT".to_owned(),
                            nullable: false,
                            default: None,
                            comment: None,
                        },
                        ColumnDescription {
                            name: "SECRET".to_owned(),
                            database_type: "TEXT".to_owned(),
                            nullable: true,
                            default: Some("'s3cr3t'".to_owned()),
                            comment: Some("the shared secret".to_owned()),
                        },
                    ],
                    primary_key: vec!["id".to_owned()],
                    foreign_keys: Vec::new(),
                    indexes: Vec::new(),
                    truncated: false,
                }],
            }],
        }
    }
}
