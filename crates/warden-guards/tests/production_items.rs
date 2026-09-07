//! Negative controls for the one function every other guard is built on.
//!
//! `production_items` decides that a rule does not apply to an item. A mistake here
//! makes every guard quietly narrower than it reads, and that is not hypothetical: the
//! line-scanning predecessor cut each file at the first `#[cfg(test)]` line, which in
//! both adapters was a mid-file `impl` rather than the trailing `mod tests`, leaving the
//! tail of each file outside every scan (ADR-0046).
//!
//! Each case below is a spelling of "test-only" that appears in this workspace, plus
//! the one spelling that must **not** be pruned.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use warden_guards::{exported_names, production_items_of};

/// The names `production_items_of` kept, for a fixture whose items are all named.
fn kept(source: &str) -> Vec<String> {
    exported_names(&production_items_of(source))
        .into_iter()
        .map(|finding| finding.detail)
        .collect()
}

/// The bug this crate was created for.
///
/// A `#[cfg(test)]` item above the trailing `mod tests` used to end every scan at its
/// line, hiding everything below it — including real production code.
#[test]
fn an_item_below_a_mid_file_cfg_test_is_still_production() {
    let kept = kept(
        r#"
        pub fn before() {}

        #[cfg(test)]
        impl Thing {
            pub fn lazy_for_tests() {}
        }

        pub fn after_the_attribute() {}

        #[cfg(test)]
        mod tests {
            pub fn helper() {}
        }
        "#,
    );
    assert_eq!(kept, ["before", "after_the_attribute"]);
}

/// Both adapters gate container work this way.
#[test]
fn a_compound_all_test_gate_is_test_only() {
    let kept = kept(
        r#"
        #[cfg(all(test, feature = "docker"))]
        pub fn container_only() {}

        pub fn ships() {}
        "#,
    );
    assert_eq!(kept, ["ships"]);
}

/// `cfg_attr` makes an attribute conditional, never the item.
///
/// Pruning it would be this crate's founding bug with the opposite sign: a production
/// item that ships in every build and that no guard can see.
#[test]
fn a_cfg_attr_test_item_still_ships() {
    let kept = kept(
        r#"
        #[cfg_attr(test, derive(Debug))]
        pub fn attributed() {}

        pub fn ships() {}
        "#,
    );
    assert_eq!(kept, ["attributed", "ships"]);
}

/// The direction that must not be pruned.
///
/// `any(test, feature = "x")` compiles under `x` with no `test`, so the item ships.
/// Pruning it would be the same blind spot with the opposite sign: a production item a
/// guard cannot see.
#[test]
fn an_any_gate_with_a_non_test_alternative_still_ships() {
    let kept = kept(
        r#"
        #[cfg(any(test, feature = "testing"))]
        pub fn reachable_through_a_feature() {}

        #[cfg(any(test))]
        pub fn only_under_test() {}
        "#,
    );
    assert_eq!(kept, ["reachable_through_a_feature"]);
}

/// Pruning descends: a test module inside a production module is still test-only, and
/// the production module around it survives.
#[test]
fn pruning_reaches_into_nested_modules() {
    let items = production_items_of(
        r#"
        pub mod outer {
            pub fn ships() {}

            #[cfg(test)]
            pub fn does_not_ship() {}

            #[cfg(test)]
            pub mod tests {
                pub fn helper() {}
            }
        }
        "#,
    );
    let syn::Item::Mod(outer) = &items[0] else {
        panic!("expected the module to survive");
    };
    let (_, content) = outer.content.as_ref().unwrap();
    assert_eq!(kept_names(content), ["ships"]);
}

fn kept_names(items: &[syn::Item]) -> Vec<String> {
    exported_names(items)
        .into_iter()
        .map(|finding| finding.detail)
        .collect()
}

/// A `#[cfg(test)]` written inside a string literal or a comment is text, not a gate.
///
/// This is the case the line scanner's own comment worried about, kept as a control
/// now that the answer is structural rather than a cutoff heuristic.
#[test]
fn the_attribute_spelled_inside_a_literal_prunes_nothing() {
    let kept = kept(
        r##"
        /// Mentions #[cfg(test)] in a doc comment.
        pub fn documented() {}

        pub fn quotes() -> &'static str {
            "#[cfg(test)]"
        }
        "##,
    );
    assert_eq!(kept, ["documented", "quotes"]);
}

/// The scan can still fail.
#[test]
fn the_pruning_scan_is_alive() {
    assert!(production_items_of("#[cfg(test)] pub fn only_a_test() {}").is_empty());
    assert_eq!(kept("pub fn ships() {}"), ["ships"]);
}

/// A ban on a type has to cover the names that reach it, or one `use ... as ...`
/// undoes it.
#[test]
fn aliases_follow_renames_and_chains_to_a_fixed_point() {
    let items = production_items_of(
        r#"
        use sqlx::MySqlPool as Handle;
        type Second = Handle;
        type Third = Option<Second>;
        type Unrelated = String;
        "#,
    );
    let known = warden_guards::aliases_of(&items, &["MySqlPool"]);

    assert!(
        known.contains("Handle"),
        "an import rename must be followed"
    );
    assert!(
        known.contains("Second"),
        "an alias of a rename must be followed"
    );
    assert!(
        known.contains("Third"),
        "an alias nested in a generic argument must be followed"
    );
    assert!(
        !known.contains("Unrelated"),
        "an alias of something else must not be dragged in"
    );
}

/// A cycle must terminate rather than loop.
#[test]
fn an_alias_cycle_terminates() {
    let items = production_items_of("type A = B; type B = A;");
    assert!(!warden_guards::aliases_of(&items, &["MySqlPool"]).contains("A"));
}

/// `_ => ...` and a bare binding are the same hole; a named subpattern is not.
#[test]
fn the_wildcard_scan_sees_both_spellings_of_a_catch_all() {
    let items = production_items_of(
        r#"
        fn f(kind: Kind) {
            match kind {
                Kind::One => {}
                _ => {}
            }
            match kind {
                Kind::One => {}
                other => drop(other),
            }
            match kind {
                Kind::One => {}
                Kind::Two => {}
            }
        }
        "#,
    );
    assert_eq!(warden_guards::wildcard_arms(&items).len(), 2);
}
