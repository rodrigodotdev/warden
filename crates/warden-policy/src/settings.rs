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

/// Object rules exactly as configuration supplies them.
///
/// Raw strings, not parsed rules: `warden-config` reads TOML and this crate decides
/// what a rule means, so a malformed entry fails at engine construction with a
/// message naming the entry rather than at the first query that touches it
/// (`docs/operations.md` section 3.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectRules {
    /// Schemas the connection may touch. `None` restricts no schema.
    pub schemas: Option<Vec<String>>,
    /// Tables the connection may touch, as `name` or `schema.name`. `None` restricts
    /// no table.
    pub allow_tables: Option<Vec<String>>,
    /// Tables the connection may never touch. Always applied, and it wins over
    /// `allow_tables`.
    pub deny_tables: Vec<String>,
}

/// Everything an operator configures about policy.
///
/// `Default` is the hardened configuration: nothing relaxed, no object rules. A
/// deployment that restricts no object is still protected by every other policy and
/// by the database role, which is the boundary that matters (ADR-0023).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicySettings {
    /// The two rules an operator may relax.
    pub relaxations: Relaxations,
    /// Which objects the connection may touch.
    pub objects: ObjectRules,
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

    #[test]
    fn default_settings_restrict_nothing_and_relax_nothing() {
        let settings = PolicySettings::default();
        assert_eq!(settings.relaxations, Relaxations::default());
        assert_eq!(settings.objects.schemas, None);
        assert_eq!(settings.objects.allow_tables, None);
        assert!(settings.objects.deny_tables.is_empty());
    }
}
