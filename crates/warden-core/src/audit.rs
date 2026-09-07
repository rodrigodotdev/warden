//! What an audit record may contain.
//!
//! The mode is a domain value rather than a configuration one: it describes the record
//! a sink writes, and both sinks apply it to the same shape (ADR-0043, ADR-0048).
//! `warden-config` deserializes into it the same way it deserializes
//! [`crate::tls::TlsMode`], and the audit adapter reads it without ever naming the
//! configuration crate.

/// What the audit sink records about a statement.
///
/// Neither mode ever records the statement text or a parameter value. The choice is
/// between recording a fingerprint of the statement and recording nothing about it at
/// all; the attempt and its outcome are written either way, because ADR-0022 denies a
/// query whose attempt cannot be recorded (SPEC section 6, invariants 22–23).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditMode {
    /// Record a fingerprint of the statement, never its literal values.
    #[default]
    Fingerprint,
    /// Record nothing beyond that a request happened.
    #[serde(rename = "none")]
    None_,
}
