//! The raw-size budget a compound PostgreSQL value must fit before it is decoded.
//!
//! `text` and `bytea` are measured before they are copied (`normalize.rs`); `json`,
//! `jsonb` and arrays were not: SQLx builds the whole `serde_json::Value` or
//! `Vec<Option<T>>` first, and only then did the `ResultBuilder` measure the result.
//! This budget is checked against `PgValueRef::as_bytes().len()` first. It is a bound
//! on the *extra* allocation, not on the row the driver already holds
//! (`docs/data-model.md` section 7, ADR-0052).

use warden_core::result::{ResultBuildError, ResultColumn};

/// The most raw bytes any compound value may occupy, whatever `max_value_bytes` says.
const RAW_DECODE_CEILING: usize = 16 * 1024 * 1024;

/// Which compound decoder the budget is protecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompoundKind {
    /// `json` (text on the wire) or `jsonb` (binary).
    Json,
    /// A one-dimensional array of one scalar type.
    Array,
}

impl CompoundKind {
    /// How many raw bytes one normalized byte may have cost on the wire.
    fn expansion(self) -> usize {
        match self {
            // On the wire, `jsonb` is `jsonb_send`: one version byte plus the text
            // form (sqlx strips `buf[0]` and parses the rest), and `json` is already
            // its own text. Raw is therefore never smaller than the normalized text,
            // so the honest expansion is ~1×. 2 is a deliberate margin for whitespace
            // and for numeric literals that normalize shorter (e.g.
            // `1000000000000000000000000` → `1e24`).
            Self::Json => 2,
            // The honest worst case is an `int8[]` of single-digit values: 12 raw
            // bytes per element (4-byte length + 8-byte value) rendering as 2
            // normalized bytes (`1,`) — 6×. 16 is a deliberate margin, not a
            // derivation.
            Self::Array => 16,
        }
    }
}

/// The raw budget derived from `max_value_bytes` for one kind of value.
pub(crate) fn raw_decode_limit(kind: CompoundKind, max_value_bytes: usize) -> usize {
    max_value_bytes
        .saturating_mul(kind.expansion())
        .saturating_add(64)
        .min(RAW_DECODE_CEILING)
}

/// Refuses a value whose raw size cannot normalize under `max_value_bytes`.
///
/// Reports the **raw** budget as `limit`, so a diagnostic distinguishes this refusal
/// from the builder's normalized one. The public code is the same
/// `query_result_too_large` either way (`warden-ports`'s `From<ResultBuildError>`).
pub(crate) fn guard_raw_decode(
    kind: CompoundKind,
    actual: usize,
    column: &ResultColumn,
    max_value_bytes: usize,
) -> Result<(), ResultBuildError> {
    let limit = raw_decode_limit(kind, max_value_bytes);
    if actual > limit {
        return Err(ResultBuildError::ValueTooLarge {
            column: column.name.clone(),
            actual,
            limit,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn the_raw_budget_is_per_kind_and_has_a_hard_ceiling() {
        assert_eq!(raw_decode_limit(CompoundKind::Json, 4), 72);
        assert_eq!(raw_decode_limit(CompoundKind::Array, 4), 128);
        assert_eq!(raw_decode_limit(CompoundKind::Json, 64 * 1024), 131_136);
        assert_eq!(raw_decode_limit(CompoundKind::Array, 64 * 1024), 1_048_640);
        assert_eq!(
            raw_decode_limit(CompoundKind::Array, usize::MAX),
            16 * 1024 * 1024
        );
    }

    #[test]
    fn the_guard_refuses_one_byte_over_and_reports_the_raw_budget() {
        let column = ResultColumn {
            name: "payload".to_owned(),
            database_type: "JSONB".to_owned(),
            nullable: None,
        };
        assert!(guard_raw_decode(CompoundKind::Json, 72, &column, 4).is_ok());
        let error = guard_raw_decode(CompoundKind::Json, 73, &column, 4).unwrap_err();
        assert!(
            matches!(
                error,
                ResultBuildError::ValueTooLarge { ref column, actual: 73, limit: 72 } if column == "payload"
            ),
            "{error:?}"
        );
    }
}
