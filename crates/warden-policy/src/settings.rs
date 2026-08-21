//! The only things about policy an operator may change.
//!
//! ADR-0026 draws the line: if a rule appears in SPEC section 6, it has **no**
//! configuration key. `allow_multiple_statements` does not exist here and never
//! will. What remains are two genuine tradeoffs, and `warden check` warns when a
//! `production` profile enables either (`docs/operations.md` section 3.1).

/// Rules an operator may deliberately relax.
///
/// Named fields rather than positional booleans: `Relaxations::default()` is the
/// hardened configuration, and no call site can swap the two by accident.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Relaxations {
    /// Allow statements that take row locks.
    ///
    /// A locking read on a production replica blocks writers and is denied by
    /// default (SPEC section 6, invariant 6).
    pub locking_reads: bool,
    /// Allow functions the adapter could not classify.
    ///
    /// Default deny is the whole point of function classification: a `SELECT` can
    /// still have side effects (ADR-0011). Enabling this trades that guarantee for
    /// fewer false positives while the safe-function registry is still small
    /// (`docs/open-questions.md` section 2, question 2).
    pub unknown_functions: bool,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn the_default_configuration_is_the_hardened_one() {
        let relaxations = Relaxations::default();
        assert!(!relaxations.locking_reads);
        assert!(!relaxations.unknown_functions);
    }
}
