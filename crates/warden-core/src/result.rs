//! The normalized, JSON-safe result model.
//!
//! One JSON object per row is not a suitable canonical model because duplicate
//! column names are legal SQL, so rows are positional and metadata is separate
//! (`docs/data-model.md` section 8).

use std::time::Duration;

use serde::ser::{Serialize, SerializeSeq, Serializer};

use crate::MAX_EXACT_JSON_INTEGER;
use crate::dialect::Dialect;
use crate::error::{PublicError, PublicErrorCode};
use crate::limits::ExecutionLimits;

/// The deepest accepted [`ResultValue::Array`] nesting.
///
/// Without a bound, a deeply nested PostgreSQL array could overflow the stack
/// during normalization or serialization, which would violate SPEC section 6,
/// invariant 31 (`docs/data-model.md` section 8.1, rule 7).
pub const MAX_ARRAY_DEPTH: usize = 8;

/// A value that cannot be represented safely.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NormalizationError {
    /// Nesting exceeded [`MAX_ARRAY_DEPTH`].
    #[error("array nesting exceeds the maximum depth of {max}")]
    ArrayTooDeep {
        /// The configured maximum.
        max: usize,
    },
    /// A floating-point column produced NaN or an infinity.
    ///
    /// JSON has no encoding for these; `serde_json` writes `null`, which would turn
    /// "the value was infinity" into "the value was missing".
    #[error("column {column:?} holds a non-finite floating-point value")]
    NonFiniteFloat {
        /// The offending column.
        column: String,
    },
    /// The value is outside what the normalized model can represent.
    ///
    /// Distinct from [`NormalizationError::UnsupportedType`]: the column's type is
    /// supported, and other rows of the same column normalize without complaint —
    /// this one value does not. PostgreSQL's `infinity` and `-infinity` timestamps,
    /// its dates beyond year 9999, and its `NaN` numerics are the cases this exists
    /// for. Carries the column and the type name and nothing else, exactly as
    /// [`NormalizationError::UnsupportedType`] does
    /// (`docs/data-model.md` section 8.1, rule 4).
    #[error(
        "column {column:?} holds a {database_type} value with no JSON representation; \
         cast it explicitly, for example: {}",
        cast_example(.dialect, .column)
    )]
    UnrepresentableValue {
        /// The offending column.
        column: String,
        /// The dialect that produced the value.
        dialect: Dialect,
        /// The database type name.
        database_type: String,
    },
    /// A row did not match the column metadata.
    #[error("row {row} has {actual} values but the result has {expected} columns")]
    RowWidthMismatch {
        /// Zero-based row index.
        row: usize,
        /// Number of declared columns.
        expected: usize,
        /// Number of values in the row.
        actual: usize,
    },
    /// The database type has no safe JSON representation.
    ///
    /// Carries the type name reported by the driver and nothing else: never driver
    /// internals, memory contents, or the value itself
    /// (`docs/data-model.md` section 8.1, rules 4 and 5).
    #[error(
        "column {column:?} uses unsupported {dialect} type {database_type:?}; \
         cast it explicitly, for example: {}",
        cast_example(.dialect, .column)
    )]
    UnsupportedType {
        /// The offending column.
        column: String,
        /// The dialect that reported the type.
        dialect: Dialect,
        /// The database type name.
        database_type: String,
    },
}

impl PublicError for NormalizationError {
    fn public_code(&self) -> PublicErrorCode {
        PublicErrorCode::QueryNormalizationError
    }
}

/// Indirection for the `#[error]` attribute, which takes field references but is
/// clearer with a named call than with a method chain inside a format argument.
fn cast_example(dialect: &Dialect, column: &str) -> String {
    dialect.text_cast_example(column)
}

/// One column's metadata.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ResultColumn {
    /// The name the database reported, duplicates included.
    pub name: String,
    /// The database type name, preserved so the agent keeps the original meaning.
    pub database_type: String,
    /// Nullability, when the driver reports it.
    pub nullable: Option<bool>,
}

/// Counters for one execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct QueryStats {
    /// Rows returned after any truncation.
    pub rows_returned: usize,
    /// Normalized size of the result in bytes.
    pub bytes: usize,
    /// Wall-clock execution time, serialized as whole milliseconds.
    #[serde(rename = "duration_ms", serialize_with = "serialize_duration_millis")]
    pub duration: std::time::Duration,
}

/// Serializes a duration as whole milliseconds.
///
/// `Duration`'s derived form is a `{secs, nanos}` object, which would leak a Rust
/// representation into a user-facing tool contract.
fn serialize_duration_millis<S: Serializer>(
    duration: &std::time::Duration,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_u64(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
}

/// A bounded, normalized result.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ResultSet {
    /// Column metadata, in positional order.
    pub columns: Vec<ResultColumn>,
    /// Rows, each positionally aligned with `columns`.
    pub rows: Vec<Vec<ResultValue>>,
    /// Whether a limit stopped collection early.
    ///
    /// The documented response to `true` is refining the query, not repeating it
    /// (`docs/mcp.md` section 1.3).
    pub truncated: bool,
    /// Counters for the agent and the audit record.
    pub stats: QueryStats,
}

impl ResultSet {
    /// Checks the invariants an adapter must uphold after normalization.
    ///
    /// Adapters call this before a result leaves the crate. It is defense in depth,
    /// not a type-level guarantee: the fields are public because they are the tool
    /// response shape.
    pub fn validate(&self) -> Result<(), NormalizationError> {
        for (index, row) in self.rows.iter().enumerate() {
            check_row(index, row, &self.columns)?;
        }
        Ok(())
    }
}

/// The three invariants every row must satisfy, wherever it came from.
fn check_row(
    index: usize,
    row: &[ResultValue],
    columns: &[ResultColumn],
) -> Result<(), NormalizationError> {
    if row.len() != columns.len() {
        return Err(NormalizationError::RowWidthMismatch {
            row: index,
            expected: columns.len(),
            actual: row.len(),
        });
    }
    for (value, column) in row.iter().zip(columns) {
        value.validate_depth()?;
        if let ResultValue::F64(number) = value
            && !number.is_finite()
        {
            return Err(NormalizationError::NonFiniteFloat {
                column: column.name.clone(),
            });
        }
    }
    Ok(())
}

/// One normalized cell.
///
/// Deliberately not a universal database type system: the core needs a safe,
/// JSON-compatible representation, and [`ResultColumn::database_type`] preserves
/// the original type name.
#[derive(Debug, Clone, PartialEq)]
pub enum ResultValue {
    /// SQL `NULL`.
    Null,
    /// Boolean.
    Bool(bool),
    /// Signed integer.
    I64(i64),
    /// Unsigned integer.
    U64(u64),
    /// Finite double-precision float.
    F64(f64),
    /// Arbitrary-precision decimal, preserved as text so no digit is lost.
    Decimal(String),
    /// UTF-8 text.
    String(String),
    /// A JSON document.
    Json(serde_json::Value),
    /// Binary data, base64-encoded.
    BytesBase64(String),
    /// A calendar date in a deterministic format.
    Date(String),
    /// A time of day in a deterministic format.
    Time(String),
    /// A timestamp in a deterministic format.
    DateTime(String),
    /// A UUID.
    Uuid(String),
    /// An array, bounded by [`MAX_ARRAY_DEPTH`].
    Array(Vec<ResultValue>),
}

impl ResultValue {
    /// Builds an array, rejecting nesting deeper than [`MAX_ARRAY_DEPTH`].
    pub fn array(values: Vec<ResultValue>) -> Result<Self, NormalizationError> {
        let value = Self::Array(values);
        value.validate_depth()?;
        Ok(value)
    }

    /// Rejects nesting deeper than [`MAX_ARRAY_DEPTH`].
    ///
    /// The walk uses an explicit stack. A recursive check on a hostile value could
    /// overflow the stack, which is the exact failure this bound exists to prevent.
    pub fn validate_depth(&self) -> Result<(), NormalizationError> {
        let mut stack = vec![(self, 1usize)];
        while let Some((value, depth)) = stack.pop() {
            if let Self::Array(items) = value {
                if depth > MAX_ARRAY_DEPTH {
                    return Err(NormalizationError::ArrayTooDeep {
                        max: MAX_ARRAY_DEPTH,
                    });
                }
                stack.extend(items.iter().map(|item| (item, depth + 1)));
            }
        }
        Ok(())
    }

    /// The exact length of this value's JSON encoding, in bytes.
    ///
    /// The byte budgets of `docs/data-model.md` section 7 bound what reaches model
    /// context, which is JSON, so this counts the encoded form rather than the Rust
    /// one. It is computed instead of serialized because measuring a 64 KiB value by
    /// copying it is the allocation the budget exists to avoid, and because an
    /// approximation that ignored escaping would let a value made entirely of quote
    /// characters occupy twice the budget it was checked against.
    ///
    /// The walk is iterative for the same reason [`ResultValue::validate_depth`] is:
    /// recursing over a hostile value is the stack overflow that
    /// SPEC section 6, invariant 31 forbids.
    #[must_use]
    pub fn json_bytes(&self) -> usize {
        let mut total = 0usize;
        let mut stack = vec![self];
        while let Some(value) = stack.pop() {
            total = total.saturating_add(match value {
                Self::Array(items) => {
                    stack.extend(items.iter());
                    // Two brackets and one comma between neighbours.
                    2 + items.len().saturating_sub(1)
                }
                scalar => scalar.scalar_json_bytes(),
            });
        }
        total
    }

    /// The encoded length of everything except an array.
    fn scalar_json_bytes(&self) -> usize {
        match self {
            Self::Null => 4,
            Self::Bool(true) => 4,
            Self::Bool(false) => 5,
            // The same predicate `Serialize` uses, so the count matches the bytes.
            Self::I64(value) => integer_bytes(value.unsigned_abs(), *value < 0),
            Self::U64(value) => integer_bytes(*value, false),
            // `serde_json::Number` formats an f64 with the same `ryu` encoding the
            // serializer uses, so this is exact rather than an upper bound. A
            // non-finite float has no `Number` and serializes as `null`, which
            // `ResultSet::validate` rejects before it can be returned anyway.
            Self::F64(value) => {
                serde_json::Number::from_f64(*value).map_or(4, |number| number.to_string().len())
            }
            Self::Decimal(text)
            | Self::String(text)
            | Self::BytesBase64(text)
            | Self::Date(text)
            | Self::Time(text)
            | Self::DateTime(text)
            | Self::Uuid(text) => json_string_bytes(text),
            Self::Json(document) => json_value_bytes(document),
            // Unreachable from `json_bytes`, which handles arrays on its own stack.
            Self::Array(items) => 2 + items.len().saturating_sub(1),
        }
    }
}

/// Digits in the decimal form of `value`, at least one.
fn decimal_digits(value: u64) -> usize {
    let mut digits = 1;
    let mut remaining = value;
    while remaining >= 10 {
        remaining /= 10;
        digits += 1;
    }
    digits
}

/// The encoded length of an integer, quoted above 2^53.
fn integer_bytes(magnitude: u64, negative: bool) -> usize {
    let digits = decimal_digits(magnitude) + usize::from(negative);
    if magnitude > MAX_EXACT_JSON_INTEGER {
        digits + 2
    } else {
        digits
    }
}

/// The encoded length of a JSON string, including quotes and `serde_json`'s escapes.
fn json_string_bytes(text: &str) -> usize {
    let mut bytes = 2;
    for character in text.chars() {
        bytes += match character {
            '"' | '\\' | '\n' | '\r' | '\t' | '\u{08}' | '\u{0c}' => 2,
            control if control < '\u{20}' => 6,
            other => other.len_utf8(),
        };
    }
    bytes
}

/// The encoded length of a JSON document, walked iteratively.
pub(crate) fn json_value_bytes(document: &serde_json::Value) -> usize {
    let mut total = 0usize;
    let mut stack = vec![document];
    while let Some(value) = stack.pop() {
        total = total.saturating_add(match value {
            serde_json::Value::Null => 4,
            serde_json::Value::Bool(true) => 4,
            serde_json::Value::Bool(false) => 5,
            serde_json::Value::Number(number) => number.to_string().len(),
            serde_json::Value::String(text) => json_string_bytes(text),
            serde_json::Value::Array(items) => {
                stack.extend(items.iter());
                2 + items.len().saturating_sub(1)
            }
            serde_json::Value::Object(entries) => {
                stack.extend(entries.values());
                // Braces, the commas between entries, and each `"key":`.
                2 + entries.len().saturating_sub(1)
                    + entries
                        .keys()
                        .map(|key| json_string_bytes(key) + 1)
                        .sum::<usize>()
            }
        });
    }
    total
}

/// Integers outside ±2^53 serialize as strings.
///
/// Most MCP clients are JavaScript and would silently round a larger integer, and a
/// silently wrong `bigint` is unacceptable in an investigation tool
/// (`docs/data-model.md` section 8.1, rule 6). Milestone 12 must declare the
/// affected fields as `["integer", "string"]` in the tool output schema.
impl Serialize for ResultValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::I64(value) => {
                if value.unsigned_abs() > MAX_EXACT_JSON_INTEGER {
                    serializer.serialize_str(&value.to_string())
                } else {
                    serializer.serialize_i64(*value)
                }
            }
            Self::U64(value) => {
                if *value > MAX_EXACT_JSON_INTEGER {
                    serializer.serialize_str(&value.to_string())
                } else {
                    serializer.serialize_u64(*value)
                }
            }
            Self::F64(value) => serializer.serialize_f64(*value),
            Self::Decimal(text)
            | Self::String(text)
            | Self::BytesBase64(text)
            | Self::Date(text)
            | Self::Time(text)
            | Self::DateTime(text)
            | Self::Uuid(text) => serializer.serialize_str(text),
            Self::Json(document) => document.serialize(serializer),
            Self::Array(items) => {
                let mut sequence = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    sequence.serialize_element(item)?;
                }
                sequence.end()
            }
        }
    }
}

/// A row that could not be added to a result.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResultBuildError {
    /// The row was not a valid normalized row.
    #[error(transparent)]
    Normalization(#[from] NormalizationError),
    /// One value exceeded `max_value_bytes`.
    ///
    /// An error rather than a substitution: [`ResultValue`] has no "omitted"
    /// variant, and inventing one would put a value in the agent's context that the
    /// database never returned (`docs/data-model.md` section 7).
    #[error("value in column {column:?} is {actual} bytes; the maximum is {limit}")]
    ValueTooLarge {
        /// The offending column.
        column: String,
        /// The value's encoded size.
        actual: usize,
        /// The configured per-value budget.
        limit: usize,
    },
    /// The first row alone exceeded `max_result_bytes`, so nothing can be returned.
    #[error("the first row is {actual} bytes; the result budget is {limit}")]
    ResultTooLarge {
        /// The row's encoded size.
        actual: usize,
        /// The configured total budget.
        limit: usize,
    },
}

/// Whether the caller should keep reading rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowOutcome {
    /// The row was stored; keep reading.
    Accepted,
    /// A bound was reached; stop reading and return what is here.
    Truncated,
}

///
/// The exact JSON length of one row: two brackets, one comma between neighbours, and
/// each value's own encoding.
///
/// Public because redaction happens after normalization
/// (`docs/security.md` section 8) and rewrites stored values, so
/// `QueryStats::bytes` has to be recomputed with the same accounting
/// [`ResultBuilder`] used to enforce the budget. One formula in one place: the unit
/// test below pins the builder's incremental accounting against this function.
#[must_use]
pub fn row_json_bytes(row: &[ResultValue]) -> usize {
    row.iter()
        .fold(2 + row.len().saturating_sub(1), |total, value| {
            total.saturating_add(value.json_bytes())
        })
}

/// A result assembled under its row, value, and byte budgets.
///
/// The budgets apply while rows arrive, never afterwards: `docs/operations.md`
/// section 6.6 forbids building an unbounded response and truncating it, because the
/// memory is already spent by then.
#[derive(Debug)]
pub struct ResultBuilder {
    columns: Vec<ResultColumn>,
    rows: Vec<Vec<ResultValue>>,
    limits: ExecutionLimits,
    bytes: usize,
    truncated: bool,
}

impl ResultBuilder {
    /// Starts a result with the given column metadata and bounds.
    #[must_use]
    pub fn new(columns: Vec<ResultColumn>, limits: ExecutionLimits) -> Self {
        Self {
            columns,
            rows: Vec::new(),
            limits,
            bytes: 0,
            truncated: false,
        }
    }

    /// The column metadata every row is checked against.
    #[must_use]
    pub fn columns(&self) -> &[ResultColumn] {
        &self.columns
    }

    /// Decides whether the next fetched row belongs in this result.
    ///
    /// Adapters call this before normalizing the `max_rows + 1` sentinel. That row
    /// exists only to prove truncation, so its values must not turn an otherwise
    /// valid bounded result into a normalization error. [`ResultBuilder::push_row`]
    /// repeats the check defensively, keeping this builder authoritative even when
    /// a caller omits the pre-normalization admission step.
    pub fn admit_row(&mut self) -> RowOutcome {
        if self.rows.len() >= self.limits.max_rows {
            self.truncated = true;
            RowOutcome::Truncated
        } else {
            RowOutcome::Accepted
        }
    }

    /// Adds one row, or reports that a bound stopped the result here.
    pub fn push_row(&mut self, row: Vec<ResultValue>) -> Result<RowOutcome, ResultBuildError> {
        // The `max_rows + 1`-th row is read only to learn that it exists
        // (`docs/operations.md` section 6.5) and is never stored.
        if self.admit_row() == RowOutcome::Truncated {
            return Ok(RowOutcome::Truncated);
        }
        check_row(self.rows.len(), &row, &self.columns)?;

        for (value, column) in row.iter().zip(&self.columns) {
            let value_bytes = value.json_bytes();
            if value_bytes > self.limits.max_value_bytes {
                return Err(ResultBuildError::ValueTooLarge {
                    column: column.name.clone(),
                    actual: value_bytes,
                    limit: self.limits.max_value_bytes,
                });
            }
        }

        let row_bytes = row_json_bytes(&row);

        let total = self.bytes.saturating_add(row_bytes);
        if total > self.limits.max_result_bytes {
            if self.rows.is_empty() {
                // Truncating to zero rows would report success for a result the
                // agent never received any of.
                return Err(ResultBuildError::ResultTooLarge {
                    actual: row_bytes,
                    limit: self.limits.max_result_bytes,
                });
            }
            self.truncated = true;
            return Ok(RowOutcome::Truncated);
        }

        self.bytes = total;
        self.rows.push(row);
        Ok(RowOutcome::Accepted)
    }

    /// Finishes the result and records how long the execution took.
    ///
    /// `stats.bytes` is the sum of the stored rows' encodings; it does not include
    /// the column metadata, which is not part of what the budget bounds.
    #[must_use]
    pub fn finish(self, duration: Duration) -> ResultSet {
        ResultSet {
            stats: QueryStats {
                rows_returned: self.rows.len(),
                bytes: self.bytes,
                duration,
            },
            columns: self.columns,
            rows: self.rows,
            truncated: self.truncated,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    #[test]
    fn an_unrepresentable_value_blames_the_value_and_not_the_type() {
        let rendered = NormalizationError::UnrepresentableValue {
            column: "valid_until".to_owned(),
            dialect: Dialect::PostgreSql,
            database_type: "TIMESTAMPTZ".to_owned(),
        }
        .to_string();
        assert!(rendered.contains("TIMESTAMPTZ"), "{rendered}");
        assert!(rendered.contains("valid_until::text"), "{rendered}");
        assert!(!rendered.contains("unsupported"), "{rendered}");
    }
    use std::time::Duration;

    use super::*;

    fn result_set(rows: Vec<Vec<ResultValue>>) -> ResultSet {
        ResultSet {
            columns: vec![ResultColumn {
                name: "value".to_owned(),
                database_type: "BIGINT".to_owned(),
                nullable: Some(false),
            }],
            rows,
            truncated: false,
            stats: QueryStats {
                rows_returned: 1,
                bytes: 8,
                duration: Duration::from_millis(1234),
            },
        }
    }

    fn columns() -> Vec<ResultColumn> {
        vec![ResultColumn {
            name: "value".to_owned(),
            database_type: "TEXT".to_owned(),
            nullable: Some(false),
        }]
    }

    fn row(n: usize) -> Vec<ResultValue> {
        vec![ResultValue::String("x".repeat(n))]
    }

    #[test]
    fn the_builder_and_shared_accountant_match_escaped_multi_value_json() {
        let columns = vec![
            ResultColumn {
                name: "id".to_owned(),
                database_type: "BIGINT".to_owned(),
                nullable: None,
            },
            ResultColumn {
                name: "note".to_owned(),
                database_type: "TEXT".to_owned(),
                nullable: None,
            },
        ];
        let row = vec![
            ResultValue::I64(-12_345),
            ResultValue::String("quote: \"; tab: \t; newline: \n".to_owned()),
        ];
        let expected = serde_json::to_string(&row).unwrap().len();
        let mut builder = ResultBuilder::new(columns, ExecutionLimits::default());
        builder.push_row(row.clone()).unwrap();
        assert_eq!(row_json_bytes(&row), expected);
        assert_eq!(builder.finish(Duration::ZERO).stats.bytes, expected);
    }

    #[test]
    fn small_integers_stay_numbers_and_large_ones_become_strings() {
        assert_eq!(serde_json::to_string(&ResultValue::I64(42)).unwrap(), "42");
        assert_eq!(
            serde_json::to_string(&ResultValue::I64(9_007_199_254_740_992)).unwrap(),
            "9007199254740992"
        );
        assert_eq!(
            serde_json::to_string(&ResultValue::I64(9_007_199_254_740_993)).unwrap(),
            "\"9007199254740993\""
        );
        assert_eq!(
            serde_json::to_string(&ResultValue::I64(-9_007_199_254_740_993)).unwrap(),
            "\"-9007199254740993\""
        );
        assert_eq!(
            serde_json::to_string(&ResultValue::U64(u64::MAX)).unwrap(),
            "\"18446744073709551615\""
        );
    }

    #[test]
    fn text_shaped_values_serialize_as_strings_and_null_as_null() {
        assert_eq!(serde_json::to_string(&ResultValue::Null).unwrap(), "null");
        assert_eq!(
            serde_json::to_string(&ResultValue::Decimal("0.1000000000000000001".to_owned()))
                .unwrap(),
            "\"0.1000000000000000001\""
        );
        assert_eq!(
            serde_json::to_string(&ResultValue::Uuid(
                "5f0e6a9e-9d1e-4c0a-8d5b-6d3f6c2a1b00".to_owned()
            ))
            .unwrap(),
            "\"5f0e6a9e-9d1e-4c0a-8d5b-6d3f6c2a1b00\""
        );
    }

    #[test]
    fn arrays_are_bounded_at_construction() {
        // Build the maximum depth one level at a time: the innermost scalar sits
        // under MAX_ARRAY_DEPTH arrays, which is still accepted.
        let mut value = ResultValue::I64(1);
        for _ in 0..MAX_ARRAY_DEPTH {
            value = ResultValue::array(vec![value]).unwrap();
        }
        value.validate_depth().unwrap();

        // Do not test with a very deep value: dropping a deeply nested
        // `Vec<ResultValue>` recurses inside `Drop` and would overflow the test
        // harness rather than the code under test.
        let too_deep = ResultValue::Array(vec![value]);
        assert_eq!(
            too_deep.validate_depth(),
            Err(NormalizationError::ArrayTooDeep {
                max: MAX_ARRAY_DEPTH
            })
        );
        assert!(ResultValue::array(vec![too_deep]).is_err());
    }

    #[test]
    fn validation_catches_non_finite_floats_and_ragged_rows() {
        let set = result_set(vec![vec![ResultValue::F64(f64::NAN)]]);
        assert_eq!(
            set.validate(),
            Err(NormalizationError::NonFiniteFloat {
                column: "value".to_owned()
            })
        );
        // Without the check, serde_json would write `null` and turn "infinity" into
        // "no value".
        assert_eq!(
            serde_json::to_string(&ResultValue::F64(f64::NAN)).unwrap(),
            "null"
        );

        let ragged = result_set(vec![vec![ResultValue::I64(1), ResultValue::I64(2)]]);
        assert!(matches!(
            ragged.validate(),
            Err(NormalizationError::RowWidthMismatch {
                row: 0,
                expected: 1,
                actual: 2
            })
        ));

        result_set(vec![vec![ResultValue::I64(1)]])
            .validate()
            .unwrap();
    }

    #[test]
    fn a_result_set_serializes_to_the_documented_shape() {
        let json = serde_json::to_string(&result_set(vec![vec![ResultValue::I64(1)]])).unwrap();
        assert_eq!(
            json,
            r#"{"columns":[{"name":"value","database_type":"BIGINT","nullable":false}],"rows":[[1]],"truncated":false,"stats":{"rows_returned":1,"bytes":8,"duration_ms":1234}}"#
        );
    }

    #[test]
    fn the_unsupported_type_error_names_the_type_and_suggests_a_cast() {
        let error = NormalizationError::UnsupportedType {
            column: "custom_state".to_owned(),
            dialect: Dialect::PostgreSql,
            database_type: "order_state".to_owned(),
        };
        let rendered = error.to_string();
        assert!(rendered.contains("order_state"), "{rendered}");
        assert!(rendered.contains("custom_state::text"), "{rendered}");
        assert_eq!(
            error.public_code(),
            PublicErrorCode::QueryNormalizationError
        );

        let mysql_error = NormalizationError::UnsupportedType {
            column: "custom_state".to_owned(),
            dialect: Dialect::MySql,
            database_type: "order_state".to_owned(),
        };
        let mysql_rendered = mysql_error.to_string();
        assert!(mysql_rendered.contains("order_state"), "{mysql_rendered}");
        assert!(
            mysql_rendered.contains("CAST(custom_state AS CHAR)"),
            "{mysql_rendered}"
        );
    }

    #[test]
    fn the_byte_count_is_the_serializers_own_length() {
        let values = vec![
            ResultValue::Null,
            ResultValue::Bool(true),
            ResultValue::Bool(false),
            ResultValue::I64(0),
            ResultValue::I64(-7),
            ResultValue::I64(9_007_199_254_740_992),
            ResultValue::I64(9_007_199_254_740_993),
            ResultValue::I64(i64::MIN),
            ResultValue::U64(u64::MAX),
            ResultValue::F64(1.5),
            ResultValue::F64(1e30),
            ResultValue::F64(-0.000_001),
            ResultValue::String(String::new()),
            ResultValue::String("plain".to_owned()),
            ResultValue::String("quote\" back\\ tab\t".to_owned()),
            ResultValue::String("control\u{01}".to_owned()),
            ResultValue::String("emoji \u{1f512}".to_owned()),
            ResultValue::Decimal("0.1000000000000000001".to_owned()),
            ResultValue::Json(serde_json::json!({"a": [1, 2.5, null], "b\"": "c"})),
            ResultValue::array(vec![
                ResultValue::I64(1),
                ResultValue::array(vec![ResultValue::String("x".to_owned())]).unwrap(),
            ])
            .unwrap(),
        ];
        for value in values {
            assert_eq!(
                value.json_bytes(),
                serde_json::to_string(&value).unwrap().len(),
                "{value:?}"
            );
        }
    }

    #[test]
    fn rows_stop_at_max_rows_and_the_extra_row_is_not_stored() {
        let limits = ExecutionLimits {
            max_rows: 2,
            ..ExecutionLimits::default()
        };
        let mut builder = ResultBuilder::new(columns(), limits);
        for _ in 0..2 {
            assert_eq!(builder.push_row(row(1)).unwrap(), RowOutcome::Accepted);
        }
        assert_eq!(builder.push_row(row(1)).unwrap(), RowOutcome::Truncated);

        let result = builder.finish(Duration::from_millis(1));
        assert_eq!(result.rows.len(), 2);
        assert!(result.truncated);
        assert_eq!(result.stats.rows_returned, 2);
        result.validate().unwrap();
    }

    #[test]
    fn row_admission_truncates_before_the_sentinel_needs_normalization() {
        let limits = ExecutionLimits {
            max_rows: 1,
            ..ExecutionLimits::default()
        };
        let mut builder = ResultBuilder::new(columns(), limits);

        assert_eq!(builder.admit_row(), RowOutcome::Accepted);
        assert_eq!(builder.push_row(row(1)).unwrap(), RowOutcome::Accepted);
        assert_eq!(builder.admit_row(), RowOutcome::Truncated);

        let result = builder.finish(Duration::ZERO);
        assert_eq!(result.rows, vec![row(1)]);
        assert!(result.truncated);
    }

    #[test]
    fn push_row_defensively_rejects_an_unnormalized_sentinel() {
        let limits = ExecutionLimits {
            max_rows: 1,
            ..ExecutionLimits::default()
        };
        let mut builder = ResultBuilder::new(columns(), limits);
        assert_eq!(builder.push_row(row(1)).unwrap(), RowOutcome::Accepted);

        // This row is deliberately ragged. Row-count truncation takes precedence,
        // so the sentinel is neither validated nor stored.
        assert_eq!(
            builder
                .push_row(vec![
                    ResultValue::String("oversized".to_owned()),
                    ResultValue::Null,
                ])
                .unwrap(),
            RowOutcome::Truncated
        );

        let result = builder.finish(Duration::ZERO);
        assert_eq!(result.rows, vec![row(1)]);
        assert!(result.truncated);
    }

    #[test]
    fn a_value_over_its_budget_is_an_error_and_never_a_substitution() {
        let limits = ExecutionLimits {
            max_value_bytes: 16,
            ..ExecutionLimits::default()
        };
        let mut builder = ResultBuilder::new(columns(), limits);
        let error = builder
            .push_row(vec![ResultValue::String("x".repeat(64))])
            .unwrap_err();
        assert!(
            matches!(error, ResultBuildError::ValueTooLarge { limit: 16, .. }),
            "{error:?}"
        );
    }

    #[test]
    fn the_total_budget_truncates_after_one_row_and_fails_before_any() {
        // A budget that the second row cannot fit into truncates. `max_value_bytes`
        // is set well above any row used here, so only `max_result_bytes` is under
        // test: a 64-character string encodes to 66 JSON bytes (two quotes), which
        // must stay under the per-value budget for the last case to exercise
        // `ResultTooLarge` rather than `ValueTooLarge`.
        let limits = ExecutionLimits {
            max_value_bytes: 128,
            max_result_bytes: 20,
            ..ExecutionLimits::default()
        };
        let mut builder = ResultBuilder::new(columns(), limits);
        assert_eq!(builder.push_row(row(8)).unwrap(), RowOutcome::Accepted);
        assert_eq!(builder.push_row(row(8)).unwrap(), RowOutcome::Truncated);
        assert!(builder.finish(Duration::ZERO).truncated);

        // A budget the first row cannot fit into has nothing to truncate to.
        let mut builder = ResultBuilder::new(columns(), limits);
        let error = builder.push_row(row(64)).unwrap_err();
        assert!(
            matches!(error, ResultBuildError::ResultTooLarge { limit: 20, .. }),
            "{error:?}"
        );
    }
}
