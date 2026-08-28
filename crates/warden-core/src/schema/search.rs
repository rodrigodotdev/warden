//! The searchable projection of a catalog, and the ranking over it.
//!
//! Both adapters read different catalogs and produce the same shape, so the ranking
//! lives here once. `docs/data-model.md` section 9.1 fixes the order, and
//! [`MatchReason`](super::MatchReason) already encodes it in its declaration order:
//! the derived `Ord` **is** the ranking, so this module sorts rather than scores.
//!
//! Matching is ASCII case-insensitive on both engines. That is a search convenience,
//! not a security comparison — a name that reaches a policy goes through
//! `warden_policy::folding` with its quoting intact (ADR-0027) — and a term an agent
//! typed carries no quoting to fold.

use super::{MatchReason, SchemaMatch, SchemaSearchResult, TableKind};

/// One relation as the search index holds it.
///
/// Column names only: the search ranks, it does not describe. `describe_schema`
/// reads the full definition from the catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedRelation {
    /// The schema holding the relation.
    pub schema: String,
    /// The relation name.
    pub name: String,
    /// What kind of relation it is.
    pub kind: TableKind,
    /// Its column names, bounded by [`super::MAX_INDEXED_COLUMNS`].
    pub columns: Vec<String>,
}

/// A connection's searchable catalog, as one bounded snapshot.
///
/// Built by an adapter from static catalog SQL and cached by
/// [`super::cache::SchemaCache`]. It holds **unfiltered** metadata: the object rules
/// are per-request and are applied by [`CatalogIndex::search`], never baked in
/// (ADR-0036).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogIndex {
    relations: Vec<IndexedRelation>,
    truncated: bool,
}

impl CatalogIndex {
    /// Builds an index. `truncated` says the catalog query hit its own row bound.
    #[must_use]
    pub fn new(relations: Vec<IndexedRelation>, truncated: bool) -> Self {
        Self {
            relations,
            truncated,
        }
    }

    /// The indexed relations, in catalog order.
    #[must_use]
    pub fn relations(&self) -> &[IndexedRelation] {
        &self.relations
    }

    /// Whether the catalog query stopped at [`super::MAX_CATALOG_ROWS`].
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Ranks the relations `permits` accepts against `terms`, keeping at most
    /// `limit`.
    ///
    /// `permits` runs **before** the limit, so a relation the object rules refuse
    /// cannot displace one they allow (ADR-0036). The result is `truncated` when the
    /// limit cut the list or when the index itself was already partial — a partial
    /// catalog must never look complete.
    #[must_use]
    pub fn search(
        &self,
        terms: &[String],
        limit: usize,
        permits: impl Fn(&IndexedRelation) -> bool,
    ) -> SchemaSearchResult {
        let mut ranked: Vec<(MatchReason, &IndexedRelation)> = self
            .relations
            .iter()
            .filter(|relation| permits(relation))
            .filter_map(|relation| best_reason(relation, terms).map(|reason| (reason, relation)))
            .collect();
        ranked.sort_by(|(left_reason, left), (right_reason, right)| {
            left_reason
                .cmp(right_reason)
                .then_with(|| left.schema.cmp(&right.schema))
                .then_with(|| left.name.cmp(&right.name))
        });

        let truncated = self.truncated || ranked.len() > limit;
        let matches = ranked
            .into_iter()
            .take(limit)
            .map(|(reason, relation)| SchemaMatch {
                schema: relation.schema.clone(),
                table: relation.name.clone(),
                kind: relation.kind,
                reason,
            })
            .collect();
        SchemaSearchResult { matches, truncated }
    }
}

/// The strongest reason any term matches this relation.
///
/// `MatchReason::Description` is deliberately unreachable: it ranks a configured
/// human description, and configured descriptions are the schema-intelligence work
/// `docs/open-questions.md` defers past v0.x. The variant stays so that adding them
/// later is an addition rather than a reordering.
fn best_reason(relation: &IndexedRelation, terms: &[String]) -> Option<MatchReason> {
    terms
        .iter()
        .filter_map(|term| term_reason(relation, term))
        .min()
}

fn term_reason(relation: &IndexedRelation, term: &str) -> Option<MatchReason> {
    if relation.name.eq_ignore_ascii_case(term) {
        return Some(MatchReason::ExactTable);
    }
    if starts_with_ignore_ascii_case(&relation.name, term) {
        return Some(MatchReason::TablePrefix);
    }
    if contains_ignore_ascii_case(&relation.name, term) {
        return Some(MatchReason::TableSubstring);
    }
    if relation
        .columns
        .iter()
        .any(|column| contains_ignore_ascii_case(column, term))
    {
        return Some(MatchReason::ColumnMatch);
    }
    if contains_ignore_ascii_case(&relation.schema, term) {
        return Some(MatchReason::SchemaName);
    }
    None
}

fn starts_with_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    haystack
        .get(..needle.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(needle))
}

/// ASCII-only, allocation-free substring search that ignores case.
///
/// `to_lowercase` would allocate per comparison and, worse, apply Unicode folding,
/// which `warden_policy::folding` refuses for the same reason.
fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn relation(schema: &str, name: &str, columns: &[&str]) -> IndexedRelation {
        IndexedRelation {
            schema: schema.to_owned(),
            name: name.to_owned(),
            kind: TableKind::Table,
            columns: columns.iter().map(|c| (*c).to_owned()).collect(),
        }
    }

    fn index() -> CatalogIndex {
        CatalogIndex::new(
            vec![
                relation("app", "orders", &["id", "customer_id"]),
                relation("app", "order_items", &["id", "order_id"]),
                relation("app", "customers", &["id", "order_count"]),
                relation("reporting", "revenue", &["month", "total"]),
            ],
            false,
        )
    }

    fn terms(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn ranking_follows_the_documented_order() {
        let found = index().search(&terms(&["orders", "order"]), 10, |_| true);
        let reasons: Vec<_> = found
            .matches
            .iter()
            .map(|m| (m.table.as_str(), m.reason))
            .collect();
        assert_eq!(
            reasons,
            [
                ("orders", MatchReason::ExactTable),
                ("order_items", MatchReason::TablePrefix),
                ("customers", MatchReason::ColumnMatch),
            ]
        );
        assert!(!found.truncated);
    }

    #[test]
    fn a_relation_keeps_its_best_reason_across_several_terms() {
        let found = index().search(&terms(&["revenue", "reporting"]), 10, |_| true);
        assert_eq!(found.matches.len(), 1);
        assert_eq!(found.matches[0].reason, MatchReason::ExactTable);
    }

    #[test]
    fn matching_ignores_ascii_case_in_both_directions() {
        let found = index().search(&terms(&["ORDERS"]), 10, |_| true);
        assert_eq!(found.matches[0].table, "orders");
    }

    #[test]
    fn a_single_letter_s_is_not_a_match_all_term() {
        let found = index().search(&terms(&["s"]), 10, |_| true);
        let names: Vec<_> = found.matches.iter().map(|m| m.table.as_str()).collect();
        assert_eq!(names, ["customers", "order_items", "orders"]);
    }

    #[test]
    fn input_case_produces_the_same_complete_results() {
        let lower = index().search(&terms(&["orders", "order"]), 10, |_| true);
        let upper = index().search(&terms(&["ORDERS", "ORDER"]), 10, |_| true);
        let lower_pairs: Vec<_> = lower
            .matches
            .iter()
            .map(|m| (m.table.as_str(), m.reason))
            .collect();
        let upper_pairs: Vec<_> = upper
            .matches
            .iter()
            .map(|m| (m.table.as_str(), m.reason))
            .collect();
        assert_eq!(lower_pairs, upper_pairs);
        assert_eq!(lower.truncated, upper.truncated);
    }

    #[test]
    fn a_refused_relation_never_consumes_a_slot() {
        // The property ADR-0036 exists for: the filter runs before the limit, so a
        // denied relation cannot displace an allowed one.
        let found = index().search(&terms(&["order"]), 2, |r| r.name != "orders");
        let names: Vec<_> = found.matches.iter().map(|m| m.table.as_str()).collect();
        assert_eq!(names, ["order_items", "customers"]);
    }

    #[test]
    fn the_limit_bounds_the_response_and_says_so() {
        let found = index().search(&terms(&["order"]), 1, |_| true);
        assert_eq!(found.matches.len(), 1);
        assert!(found.truncated);
    }

    #[test]
    fn a_truncated_index_reports_truncation_even_when_the_limit_fits() {
        let index = CatalogIndex::new(vec![relation("app", "orders", &[])], true);
        let found = index.search(&terms(&["orders"]), 10, |_| true);
        assert_eq!(found.matches.len(), 1);
        assert!(
            found.truncated,
            "a partial catalog cannot claim completeness"
        );
    }

    #[test]
    fn nothing_matches_nothing() {
        let found = index().search(&terms(&["zzz"]), 10, |_| true);
        assert!(found.matches.is_empty());
        assert!(!found.truncated);
    }
}
