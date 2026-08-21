//! Shared validation for the crate's string newtypes.
//!
//! Four newtypes (`ConnectionName`, `Environment::Other`, `RequestId`, and the
//! externally supplied `PrincipalId`/`ClientName`) need the same two checks with
//! different bounds. Sharing the validator keeps the rejection rules in one
//! reviewable place and guarantees that no error message echoes the whole rejected
//! value: a name that fails validation may still contain something sensitive.

use self::IdentifierViolation::{Empty, TooLong, UnsupportedCharacter};

/// A rejected identifier, naming the field but never quoting the whole value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{field} {violation}")]
pub struct IdentifierError {
    /// Human-readable field name, such as `"connection name"`.
    pub field: &'static str,
    /// What was wrong with it.
    pub violation: IdentifierViolation,
}

/// Why an identifier was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentifierViolation {
    /// The value was empty.
    #[error("is empty")]
    Empty,
    /// The value was longer than its maximum.
    #[error("is {actual} bytes; the maximum is {max}")]
    TooLong {
        /// Length of the rejected value in bytes.
        actual: usize,
        /// Maximum accepted length.
        max: usize,
    },
    /// The value contained a character outside the accepted set.
    #[error("contains the unsupported character {character:?}")]
    UnsupportedCharacter {
        /// The first offending character.
        character: char,
    },
}

/// Accepts a non-empty `[A-Za-z0-9._-]{1,max_len}` value.
///
/// Used for values Warden or its operator controls, which end up in configuration,
/// tool responses, audit records, and metric labels.
pub(crate) fn validate_identifier(
    field: &'static str,
    value: &str,
    max_len: usize,
) -> Result<(), IdentifierError> {
    check_bounds(field, value, max_len)?;
    match value
        .chars()
        .find(|c| !matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-'))
    {
        Some(character) => Err(IdentifierError {
            field,
            violation: UnsupportedCharacter { character },
        }),
        None => Ok(()),
    }
}

/// Accepts non-empty printable ASCII up to `max_len` bytes.
///
/// Used for values supplied by an MCP client, such as a principal subject or a
/// client name. Those legitimately contain spaces, `@`, and `|`, so the identifier
/// charset is too strict — but control characters are rejected because these values
/// reach stderr logs, where a newline is a log-injection primitive.
pub(crate) fn validate_display(
    field: &'static str,
    value: &str,
    max_len: usize,
) -> Result<(), IdentifierError> {
    check_bounds(field, value, max_len)?;
    match value.chars().find(|c| !matches!(c, ' '..='~')) {
        Some(character) => Err(IdentifierError {
            field,
            violation: UnsupportedCharacter { character },
        }),
        None => Ok(()),
    }
}

fn check_bounds(field: &'static str, value: &str, max_len: usize) -> Result<(), IdentifierError> {
    if value.is_empty() {
        return Err(IdentifierError {
            field,
            violation: Empty,
        });
    }
    if value.len() > max_len {
        return Err(IdentifierError {
            field,
            violation: TooLong {
                actual: value.len(),
                max: max_len,
            },
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn identifier_accepts_the_documented_charset() {
        validate_identifier("connection name", "prod-mysql.1_x", 64).unwrap();
    }

    #[test]
    fn identifier_rejects_spaces_and_reports_the_field() {
        let error = validate_identifier("connection name", "bad name", 64).unwrap_err();
        assert_eq!(
            error.to_string(),
            "connection name contains the unsupported character ' '"
        );
    }

    #[test]
    fn display_allows_spaces_but_rejects_control_characters() {
        validate_display("client name", "Claude Code 2.0", 64).unwrap();
        let error = validate_display("client name", "evil\nINFO: fake", 64).unwrap_err();
        assert!(matches!(
            error.violation,
            UnsupportedCharacter { character: '\n' }
        ));
    }

    #[test]
    fn errors_never_echo_the_whole_value() {
        let secret = "s3cr3t token!";
        let error = validate_identifier("connection name", secret, 64).unwrap_err();
        assert!(!error.to_string().contains(secret), "{error}");
    }

    #[test]
    fn bounds_are_inclusive_and_measured_in_bytes() {
        validate_identifier("f", &"a".repeat(64), 64).unwrap();
        assert!(matches!(
            validate_identifier("f", &"a".repeat(65), 64)
                .unwrap_err()
                .violation,
            TooLong {
                actual: 65,
                max: 64
            }
        ));
        // Multi-byte input is bounded by bytes, not characters.
        assert!(validate_identifier("f", "é", 1).is_err());
    }
}
