//! One request's object rules, in a form an adapter can hold.
//!
//! `docs/security.md` section 5.2 requires `search_schema` and `describe_schema` to
//! filter at the source: the inspector receives the rules and never returns the
//! whole catalog for someone else to trim. `docs/open-questions.md` item 13 recorded
//! why the Milestone 3 port could not do that and that Milestone 9 would change the
//! signature. This is the type the signature changes to (ADR-0036).
//!
//! It is a borrowed, `Copy` view rather than an owned object on purpose. The engine
//! is startup state the composition root already owns, the connection metadata and
//! the request identity are per-request values the service already holds, and an
//! adapter that owned any of them would be holding a second copy of a security
//! decision it does not make.

use warden_core::analysis::ObjectRef;
use warden_core::connection::ConnectionMetadata;
use warden_core::dialect::Dialect;

use crate::decision::PolicyRejection;
use crate::engine::PolicyEngine;
use crate::input::PolicyContext;

/// The object rules that apply to one request, ready to be asked about one object.
#[derive(Debug, Clone, Copy)]
pub struct ObjectFilter<'a> {
    engine: &'a PolicyEngine,
    context: PolicyContext<'a>,
}

impl<'a> ObjectFilter<'a> {
    /// Borrows the engine and one request's context.
    #[must_use]
    pub fn new(engine: &'a PolicyEngine, context: PolicyContext<'a>) -> Self {
        Self { engine, context }
    }

    /// Every reason the rules refuse this object, or `Ok` when they do not.
    ///
    /// Used where the agent named the object itself, so that refusing it is an
    /// answer rather than a silence — `describe_schema`.
    ///
    /// # Errors
    ///
    /// [`PolicyRejection`] carrying every object rule that refused `object`, exactly
    /// as [`PolicyEngine::check_object`] returns it.
    pub fn check(&self, object: &ObjectRef) -> Result<(), PolicyRejection> {
        self.engine.check_object(object, &self.context)
    }

    /// Whether the rules permit this object.
    ///
    /// Used where the agent named no object, so that a refusal must not become a
    /// distinguishable response — `search_schema`. A denied relation is dropped
    /// before the response limit is applied, so it cannot consume an allowed
    /// relation's slot.
    #[must_use]
    pub fn permits(&self, object: &ObjectRef) -> bool {
        self.check(object).is_ok()
    }

    /// The connection's dialect, which decides identifier folding.
    #[must_use]
    pub fn dialect(&self) -> Dialect {
        self.context.dialect()
    }

    /// The connection this request runs against.
    #[must_use]
    pub fn connection(&self) -> &'a ConnectionMetadata {
        self.context.connection()
    }
}
