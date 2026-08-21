//! Versioned query fingerprints.
//!
//! Each adapter computes a fingerprint from a normalized AST with literals
//! replaced, so audits stay comparable without storing SQL
//! (`docs/security.md` section 11.4). Algorithms need not match across dialects,
//! which is why the version prefix is part of the value.
//!
//! Computing a fingerprint belongs to the adapters; this crate owns only its shape.

use std::fmt;
use std::str::FromStr;

/// Length of a SHA-256 digest in lowercase hexadecimal.
const DIGEST_LEN: usize = 64;

/// The value was not a well-formed fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FingerprintError {
    /// The version prefix was missing or unknown.
    #[error("fingerprint must start with the version prefix \"v1:\"")]
    UnknownVersion,
    /// The digest was not 64 lowercase hexadecimal characters.
    #[error("fingerprint digest must be {DIGEST_LEN} lowercase hexadecimal characters")]
    MalformedDigest,
}

/// A stable, versioned identifier for a normalized statement.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String")]
pub struct QueryFingerprint(String);

impl QueryFingerprint {
    /// Builds a `v1` fingerprint from a SHA-256 digest in lowercase hexadecimal.
    pub fn v1(digest: &str) -> Result<Self, FingerprintError> {
        if digest.len() != DIGEST_LEN
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(FingerprintError::MalformedDigest);
        }
        Ok(Self(format!("v1:{digest}")))
    }

    /// Borrows the full `v1:<digest>` value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for QueryFingerprint {
    type Error = FingerprintError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let digest = value
            .strip_prefix("v1:")
            .ok_or(FingerprintError::UnknownVersion)?;
        Self::v1(digest)
    }
}

impl FromStr for QueryFingerprint {
    type Err = FingerprintError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_owned())
    }
}

impl fmt::Display for QueryFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for QueryFingerprint {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn digest() -> String {
        "a".repeat(DIGEST_LEN)
    }

    #[test]
    fn builds_and_renders_a_versioned_value() {
        let fingerprint = QueryFingerprint::v1(&digest()).unwrap();
        assert_eq!(fingerprint.as_str(), format!("v1:{}", digest()));
        assert_eq!(
            fingerprint.to_string().parse::<QueryFingerprint>().unwrap(),
            fingerprint
        );
    }

    #[test]
    fn rejects_malformed_digests_and_versions() {
        assert_eq!(
            QueryFingerprint::v1("abc").unwrap_err(),
            FingerprintError::MalformedDigest
        );
        // Uppercase is rejected so one statement has exactly one fingerprint.
        assert_eq!(
            QueryFingerprint::v1(&"A".repeat(DIGEST_LEN)).unwrap_err(),
            FingerprintError::MalformedDigest
        );
        assert_eq!(
            digest().parse::<QueryFingerprint>().unwrap_err(),
            FingerprintError::UnknownVersion
        );
        assert_eq!(
            format!("v2:{}", digest())
                .parse::<QueryFingerprint>()
                .unwrap_err(),
            FingerprintError::UnknownVersion
        );
    }
}
