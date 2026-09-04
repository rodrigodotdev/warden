//! Values bound to placeholders in agent SQL.
//!
//! The set is deliberately small for v0.1 (`docs/data-model.md` section 3).
//! PostgreSQL callers cast explicitly, as in `WHERE id = $1::uuid`. Warden does not
//! infer complex SQL types from arbitrary strings.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer};

use crate::MAX_EXACT_JSON_INTEGER;

/// A supplied value that cannot be bound without losing information.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParameterError {
    /// The number was NaN or an infinity.
    #[error("parameter is not a finite number")]
    NotFinite,
    /// The number reached Warden as a float whose integral value is at least 2^53.
    #[error(
        "parameter is an integer of magnitude 2^53 or greater and cannot be bound \
         exactly; pass it as a string and cast it in SQL"
    )]
    InexactInteger,
}

impl crate::error::PublicError for ParameterError {
    fn public_code(&self) -> crate::error::PublicErrorCode {
        // The request could not be turned into an executable statement. There is no
        // separate parameter code in `docs/security.md` section 10, and inventing
        // one would widen a user-facing contract outside its own milestone.
        crate::error::PublicErrorCode::QueryParseError
    }
}

/// One bound parameter.
///
/// Deliberately does **not** implement `Serialize`. Parameters are not audited or
/// logged by default (SPEC section 6, invariant 23), and the simplest way to keep
/// that true is to make serializing one impossible.
#[derive(Clone, PartialEq)]
pub enum ParameterValue {
    /// SQL `NULL`.
    Null,
    /// Boolean.
    Bool(bool),
    /// Signed 64-bit integer.
    I64(i64),
    /// Unsigned 64-bit integer.
    U64(u64),
    /// Finite double-precision float.
    F64(f64),
    /// UTF-8 text.
    String(String),
}

impl ParameterValue {
    /// Builds a float parameter, rejecting values JSON cannot carry exactly.
    ///
    /// JSON floating-point parameters are bound as `f64`. Rejecting the whole
    /// integral range at or above 2^53 is conservative and keeps the promise in
    /// `docs/data-model.md` section 3.1 that Warden never silently wraps or truncates
    /// a value.
    ///
    /// # Errors
    ///
    /// - [`ParameterError::NotFinite`] for `NaN` or either infinity, none of which
    ///   JSON can represent.
    /// - [`ParameterError::InexactInteger`] for an integral value at or beyond
    ///   2^53, where `f64` can no longer distinguish consecutive integers.
    pub fn float(value: f64) -> Result<Self, ParameterError> {
        if !value.is_finite() {
            return Err(ParameterError::NotFinite);
        }
        if value.fract() == 0.0 && value.abs() >= MAX_EXACT_JSON_INTEGER as f64 {
            return Err(ParameterError::InexactInteger);
        }
        Ok(Self::F64(value))
    }

    /// Classifies a JSON number without rounding integer syntax into a float.
    fn from_json_number(number: serde_json::Number) -> Result<Self, ParameterError> {
        if let Some(value) = number.as_u64() {
            return Ok(Self::U64(value));
        }
        if let Some(value) = number.as_i64() {
            return Ok(Self::I64(value));
        }

        let token = number.to_string();
        if token.contains(['.', 'e', 'E']) {
            let value = number.as_f64().ok_or(ParameterError::NotFinite)?;
            return Self::float(value);
        }

        // With serde_json's arbitrary-precision parsing, reaching this branch means
        // the input used integer syntax but did not fit either i64 or u64. Never
        // round that exact token through f64.
        Err(ParameterError::InexactInteger)
    }
}

/// Prints shape, never content: a parameter can hold an email address, a token, or
/// a private message (`docs/security.md` section 11.3).
impl fmt::Debug for ParameterValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("Null"),
            Self::Bool(_) => f.write_str("Bool(<redacted>)"),
            Self::I64(_) => f.write_str("I64(<redacted>)"),
            Self::U64(_) => f.write_str("U64(<redacted>)"),
            Self::F64(_) => f.write_str("F64(<redacted>)"),
            Self::String(value) => write!(f, "String(<redacted {} bytes>)", value.len()),
        }
    }
}

impl<'de> Deserialize<'de> for ParameterValue {
    /// Deserializes through serde_json's exact number token representation.
    ///
    /// This type is an MCP JSON boundary, so using [`serde_json::Value`] here is
    /// deliberate. With the workspace's arbitrary-precision feature it handles
    /// serde_json's private number protocol internally; Warden then distinguishes
    /// integer syntax from decimal/exponent syntax without depending on that private
    /// token itself.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match serde_json::Value::deserialize(deserializer)? {
            serde_json::Value::Null => Ok(Self::Null),
            serde_json::Value::Bool(value) => Ok(Self::Bool(value)),
            serde_json::Value::Number(number) => {
                Self::from_json_number(number).map_err(de::Error::custom)
            }
            serde_json::Value::String(value) => Ok(Self::String(value)),
            serde_json::Value::Array(_) | serde_json::Value::Object(_) => Err(de::Error::custom(
                "parameter must be null, a boolean, a finite number, or a string",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn accepts_the_v01_value_set() {
        let values: Vec<ParameterValue> =
            serde_json::from_str(r#"[null, true, -7, 42, 1.5, "customer_123"]"#).unwrap();
        assert_eq!(
            values,
            vec![
                ParameterValue::Null,
                ParameterValue::Bool(true),
                ParameterValue::I64(-7),
                ParameterValue::U64(42),
                ParameterValue::F64(1.5),
                ParameterValue::String("customer_123".to_owned()),
            ]
        );
    }

    #[test]
    fn rejects_integers_that_json_cannot_carry_exactly() {
        // The arbitrary-precision parser keeps this exact token. Warden classifies
        // its integer syntax before considering any f64 conversion, closing the
        // silent-rounding path directly.
        let error = serde_json::from_str::<ParameterValue>("18446744073709551616")
            .unwrap_err()
            .to_string();
        assert!(error.contains("2^53"), "{error}");
    }

    #[test]
    fn accepts_the_largest_exact_integers() {
        assert_eq!(
            serde_json::from_str::<ParameterValue>("18446744073709551615").unwrap(),
            ParameterValue::U64(u64::MAX)
        );
        assert_eq!(
            serde_json::from_str::<ParameterValue>("-9223372036854775808").unwrap(),
            ParameterValue::I64(i64::MIN)
        );
    }

    #[test]
    fn a_high_precision_decimal_remains_a_finite_f64_parameter() {
        assert_eq!(
            serde_json::from_str::<ParameterValue>("0.123456789012345678901234567890").unwrap(),
            ParameterValue::F64(0.123_456_789_012_345_68)
        );
    }

    #[test]
    fn rejects_out_of_range_and_non_finite_numbers() {
        // serde_json itself rejects this one before the visitor sees it.
        assert!(serde_json::from_str::<ParameterValue>("1e400").is_err());
        assert_eq!(
            ParameterValue::float(f64::NAN),
            Err(ParameterError::NotFinite)
        );
        assert_eq!(
            ParameterValue::float(f64::INFINITY),
            Err(ParameterError::NotFinite)
        );
        assert_eq!(
            ParameterValue::float(1.5).unwrap(),
            ParameterValue::F64(1.5)
        );
    }

    #[test]
    fn rejects_composite_json() {
        assert!(serde_json::from_str::<ParameterValue>(r#"{"a":1}"#).is_err());
        assert!(serde_json::from_str::<ParameterValue>("[1]").is_err());
    }

    #[test]
    fn debug_never_prints_a_value() {
        let rendered = format!("{:?}", ParameterValue::String("hunter2".to_owned()));
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert_eq!(rendered, "String(<redacted 7 bytes>)");
        assert_eq!(format!("{:?}", ParameterValue::I64(42)), "I64(<redacted>)");
    }
}
