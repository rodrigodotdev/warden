//! The normalized, JSON-safe result model.
//!
//! One JSON object per row is not a suitable canonical model because duplicate
//! column names are legal SQL, so rows are positional and metadata is separate
//! (`docs/data-model.md` section 8).

use serde::ser::{Serialize, SerializeSeq, Serializer};

use crate::MAX_EXACT_JSON_INTEGER;
use crate::dialect::Dialect;
use crate::error::{PublicError, PublicErrorCode};

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
         cast it explicitly, for example: {column}::text"
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
            if row.len() != self.columns.len() {
                return Err(NormalizationError::RowWidthMismatch {
                    row: index,
                    expected: self.columns.len(),
                    actual: row.len(),
                });
            }
            for (value, column) in row.iter().zip(&self.columns) {
                value.validate_depth()?;
                if let ResultValue::F64(number) = value
                    && !number.is_finite()
                {
                    return Err(NormalizationError::NonFiniteFloat {
                        column: column.name.clone(),
                    });
                }
            }
        }
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

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
    }
}
