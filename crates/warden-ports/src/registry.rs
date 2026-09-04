//! The connection-lookup port.
//!
//! The concrete implementation is a `HashMap` built at startup and immutable
//! afterwards, and it lives in `warden-service` (Milestone 11). Dynamic
//! configuration reload is future work; nothing here assumes it
//! (`docs/architecture.md` section 6).

use std::sync::Arc;

use warden_core::connection::{ConnectionMetadata, ConnectionName};

use crate::error::ConnectionError;
use crate::runtime::ConnectionRuntime;

/// Resolves a connection name to the runtime that serves it.
pub trait ConnectionRegistry: Send + Sync {
    /// Looks up one connection.
    ///
    /// # Errors
    ///
    /// [`ConnectionError::NotFound`] for an unknown name. The name is untrusted
    /// input, and the caller maps the failure to `connection_not_found`
    /// (`docs/security.md` section 10).
    fn get(&self, name: &ConnectionName) -> Result<Arc<ConnectionRuntime>, ConnectionError>;

    /// Every configured connection's public description.
    ///
    /// This is the entire `list_connections` payload. `ConnectionMetadata` has no
    /// DSN, host, user, or password field, so no serialization path can leak one:
    /// the type cannot hold it (SPEC section 6, invariant 20).
    fn list(&self) -> Vec<ConnectionMetadata>;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use warden_core::dialect::Dialect;

    use super::*;
    use crate::testing;

    #[test]
    fn a_registry_works_behind_a_trait_object() {
        let registry: Arc<dyn ConnectionRegistry> =
            Arc::new(testing::FakeRegistry::new(Dialect::MySql));

        let runtime = registry.get(&"production-db".parse().unwrap()).unwrap();
        assert_eq!(runtime.metadata().dialect, Dialect::MySql);

        let listed = registry.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name.as_str(), "production-db");
    }

    #[test]
    fn an_unknown_name_is_not_found_rather_than_a_panic() {
        let registry = testing::FakeRegistry::new(Dialect::MySql);
        let error = registry.get(&"staging-db".parse().unwrap()).unwrap_err();
        assert_eq!(
            error,
            ConnectionError::NotFound {
                name: "staging-db".parse().unwrap(),
            }
        );
    }
}
