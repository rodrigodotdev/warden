//! Which CTE names are visible where, during one walk of a statement.
//!
//! sqlparser's derived visitor reaches every `Query` in document order and calls
//! `pre_visit_query` before its children and `post_visit_query` after them. Inside a
//! `Query`, `with` is visited before `body`, and each `Cte` holds exactly one `Query`,
//! so the first `n` child queries of a query with `n` CTEs are those CTEs' bodies, in
//! declaration order; every later child query belongs to the main body. That is all
//! this stack needs to know to answer "is this unqualified name a CTE *here*?" the way
//! the server answers it (`docs/security.md` section 5.1, ADR-0027).
//!
//! MySQL 8.4's rule: without `RECURSIVE`, a body sees the aliases declared before it
//! and nothing declared at or after it, the same as PostgreSQL; with `RECURSIVE`, a
//! body sees itself and the siblings declared before it, but never one declared
//! after — unlike PostgreSQL, where `RECURSIVE` makes every alias of the `WITH`
//! visible to every body. Either way the main body sees them all, and every query
//! inherits whatever was visible where it appears.

use sqlparser::ast::Query;

/// The walk left the scope stack inconsistent.
///
/// Never expected from the derived visitor, which pairs every `pre_visit_query` with a
/// `post_visit_query`; reported rather than assumed so that a parser upgrade which
/// breaks that pairing denies (`UnknownConstruct`) instead of authorising.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ScopeError {
    /// A query ended that never began.
    #[error("a query scope ended that never began")]
    Underflow,
    /// Scopes were still open when the walk ended.
    #[error("{0} query scope(s) were still open when the walk ended")]
    Unbalanced(usize),
}

/// One query's view of the CTE names around it.
#[derive(Debug)]
struct ScopeFrame {
    /// Aliases visible to relations named directly in this query's main body.
    visible: Vec<String>,
    /// What was visible where this query appeared, before its own `WITH`.
    inherited: Vec<String>,
    /// This query's own `WITH` aliases, in declaration order.
    local: Vec<String>,
    /// How many of `local`'s bodies the walk has entered so far.
    bodies_entered: usize,
    /// Whether the `WITH` was `RECURSIVE`.
    recursive: bool,
}

/// The stack of open query scopes.
#[derive(Debug, Default)]
pub(crate) struct CteScopes {
    frames: Vec<ScopeFrame>,
}

impl CteScopes {
    /// Opens the scope of `query`, deciding from the parent frame whether it is a CTE
    /// body or an ordinary subquery.
    pub(crate) fn enter(&mut self, query: &Query) {
        let inherited = match self.frames.last_mut() {
            None => Vec::new(),
            Some(parent) if parent.bodies_entered < parent.local.len() => {
                let index = parent.bodies_entered;
                parent.bodies_entered += 1;
                body_visibility(parent, index)
            }
            Some(parent) => parent.visible.clone(),
        };
        let (local, recursive) = match &query.with {
            Some(with) => (
                with.cte_tables
                    .iter()
                    .map(|cte| cte.alias.name.value.clone())
                    .collect(),
                with.recursive,
            ),
            None => (Vec::new(), false),
        };
        let mut visible = inherited.clone();
        visible.extend(local.iter().cloned());
        self.frames.push(ScopeFrame {
            visible,
            inherited,
            local,
            bodies_entered: 0,
            recursive,
        });
    }

    /// Closes the innermost scope.
    ///
    /// # Errors
    ///
    /// [`ScopeError::Underflow`] if no scope is open.
    pub(crate) fn leave(&mut self) -> Result<(), ScopeError> {
        self.frames
            .pop()
            .map(|_frame| ())
            .ok_or(ScopeError::Underflow)
    }

    /// Whether an unqualified relation name resolves to a CTE in the current scope.
    ///
    /// MySQL folds unquoted and quoted identifiers alike under the default
    /// `lower_case_table_names`; the visitor already compares case-insensitively.
    pub(crate) fn resolves_cte(&self, name: &str) -> bool {
        self.frames.last().is_some_and(|frame| {
            frame
                .visible
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(name))
        })
    }

    /// Confirms every scope was closed.
    ///
    /// # Errors
    ///
    /// [`ScopeError::Unbalanced`] with the number of scopes still open.
    pub(crate) fn finish(self) -> Result<(), ScopeError> {
        if self.frames.is_empty() {
            Ok(())
        } else {
            Err(ScopeError::Unbalanced(self.frames.len()))
        }
    }
}

/// What the `index`-th CTE body of `parent` can see (MySQL 8.4 rules): earlier
/// siblings, plus itself when the `WITH` is `RECURSIVE`, never a later sibling.
fn body_visibility(parent: &ScopeFrame, index: usize) -> Vec<String> {
    let mut visible = parent.inherited.clone();
    let end = if parent.recursive { index + 1 } else { index };
    visible.extend(parent.local[..end].iter().cloned());
    visible
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use sqlparser::ast::{Statement, Visit, Visitor};
    use sqlparser::dialect::MySqlDialect;
    use sqlparser::parser::Parser;

    use super::*;
    use core::ops::ControlFlow;

    /// Records, for every `Query` the walk enters, whether the name `t` is a CTE there.
    struct Probe {
        scopes: CteScopes,
        seen: Vec<bool>,
    }

    impl Visitor for Probe {
        type Break = ();

        fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
            self.scopes.enter(query);
            self.seen.push(self.scopes.resolves_cte("t"));
            ControlFlow::Continue(())
        }

        fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<()> {
            self.scopes.leave().unwrap();
            ControlFlow::Continue(())
        }
    }

    fn probe(sql: &str) -> Vec<bool> {
        let statements = Parser::parse_sql(&MySqlDialect {}, sql).unwrap();
        let mut probe = Probe {
            scopes: CteScopes::default(),
            seen: Vec::new(),
        };
        for statement in &statements {
            let _ = Statement::visit(statement, &mut probe);
        }
        probe.scopes.finish().unwrap();
        probe.seen
    }

    #[test]
    fn a_non_recursive_body_does_not_see_its_own_alias_but_the_main_body_does() {
        // Queries entered: outer, body of t, subquery in the main body.
        assert_eq!(
            probe("WITH t AS (SELECT * FROM t) SELECT * FROM t WHERE EXISTS (SELECT 1)"),
            vec![true, false, true]
        );
    }

    #[test]
    fn a_non_recursive_body_never_sees_a_later_sibling() {
        // outer, body of a (t is later: invisible), body of t
        assert_eq!(
            probe("WITH a AS (SELECT * FROM t), t AS (SELECT 1) SELECT * FROM a"),
            vec![true, false, false]
        );
    }

    #[test]
    fn a_recursive_body_sees_itself_but_not_a_later_sibling() {
        // outer, body of a (sees a, not t), body of t (sees a and t)
        assert_eq!(
            probe("WITH RECURSIVE a AS (SELECT * FROM t), t AS (SELECT 1) SELECT * FROM a"),
            vec![true, false, true]
        );
    }

    #[test]
    fn an_alias_inside_a_subquery_is_invisible_outside_it() {
        // outer (no WITH), the EXISTS subquery (declares t), its body of t
        assert_eq!(
            probe("SELECT * FROM t WHERE EXISTS (WITH t AS (SELECT 1) SELECT * FROM t)"),
            vec![false, true, false]
        );
    }

    #[test]
    fn nested_queries_inside_a_body_use_the_body_frame_not_the_next_sibling() {
        // outer, body of a, subquery inside a's body (inherits a's view: nothing),
        // body of t (sees a), main-body subquery (sees both)
        assert_eq!(
            probe(
                "WITH a AS (SELECT * FROM (SELECT 1) AS s), t AS (SELECT * FROM a) \
                 SELECT * FROM t WHERE EXISTS (SELECT 1)"
            ),
            vec![true, false, false, false, true]
        );
    }

    #[test]
    fn names_compare_case_insensitively() {
        let mut scopes = CteScopes::default();
        let statements =
            Parser::parse_sql(&MySqlDialect {}, "WITH T AS (SELECT 1) SELECT 1").unwrap();
        let Statement::Query(query) = &statements[0] else {
            panic!("not a query")
        };
        scopes.enter(query);
        assert!(scopes.resolves_cte("t"));
        assert!(scopes.resolves_cte("T"));
    }

    #[test]
    fn leaving_more_than_entering_is_an_error_and_never_a_panic() {
        let mut scopes = CteScopes::default();
        assert_eq!(scopes.leave(), Err(ScopeError::Underflow));
        let statements = Parser::parse_sql(&MySqlDialect {}, "SELECT 1").unwrap();
        let Statement::Query(query) = &statements[0] else {
            panic!("not a query")
        };
        scopes.enter(query);
        assert_eq!(scopes.finish(), Err(ScopeError::Unbalanced(1)));
    }
}
