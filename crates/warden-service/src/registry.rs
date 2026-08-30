//! The connection lookup the whole service layer resolves through.
//!
//! A `HashMap` built at startup and immutable afterwards
//! (`docs/architecture.md` section 6). Dynamic configuration reload is future work;
//! nothing here assumes it.
//!
//! [`StaticConnectionRegistry::list`] sorts, because a `HashMap`'s iteration order is
//! randomized per process and this list is the entire `list_connections` payload
//! (`docs/mcp.md` section 2). An agent comparing two calls must not see the same
//! connections in a different order and conclude something changed.

use std::collections::HashMap;
use std::sync::Arc;

use warden_core::connection::{ConnectionMetadata, ConnectionName};
use warden_ports::{ConnectionError, ConnectionRegistry, ConnectionRuntime};

/// Why a registry could not be assembled.
///
/// Operator-facing, raised by the composition root before any transport is serving,
/// so it deliberately does not implement `warden_core::error::PublicError` — the same
/// distinction `warden_ports::RuntimeError` draws.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// No connections were configured.
    ///
    /// A registry that resolves nothing starts cleanly and fails every request, which
    /// is a worse failure than refusing to start.
    #[error("no connections are configured")]
    Empty,
    /// Two runtimes claimed the same name.
    ///
    /// Silently keeping one would make which database an agent reached depend on
    /// insertion order.
    #[error("connection {name} is configured more than once")]
    Duplicate {
        /// The repeated name.
        name: ConnectionName,
    },
}

/// Every configured connection, resolvable by name.
#[derive(Debug)]
pub struct StaticConnectionRegistry {
    connections: HashMap<ConnectionName, Arc<ConnectionRuntime>>,
}

impl StaticConnectionRegistry {
    /// Indexes the runtimes by name, rejecting an empty set and any duplicate.
    pub fn new(runtimes: Vec<Arc<ConnectionRuntime>>) -> Result<Self, RegistryError> {
        if runtimes.is_empty() {
            return Err(RegistryError::Empty);
        }
        let mut connections = HashMap::with_capacity(runtimes.len());
        for runtime in runtimes {
            let name = runtime.metadata().name.clone();
            if connections.insert(name.clone(), runtime).is_some() {
                return Err(RegistryError::Duplicate { name });
            }
        }
        Ok(Self { connections })
    }

    /// How many connections are configured.
    #[must_use]
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Always `false`: [`StaticConnectionRegistry::new`] rejects an empty set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }
}

impl ConnectionRegistry for StaticConnectionRegistry {
    fn get(&self, name: &ConnectionName) -> Result<Arc<ConnectionRuntime>, ConnectionError> {
        self.connections
            .get(name)
            .map(Arc::clone)
            .ok_or_else(|| ConnectionError::NotFound { name: name.clone() })
    }

    fn list(&self) -> Vec<ConnectionMetadata> {
        let mut listed: Vec<ConnectionMetadata> = self
            .connections
            .values()
            .map(|runtime| runtime.metadata().clone())
            .collect();
        listed.sort_by(|left, right| left.name.cmp(&right.name));
        listed
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use warden_core::dialect::Dialect;

    use super::*;
    use crate::testing;

    #[test]
    fn a_configured_name_resolves_to_its_runtime() {
        let registry = testing::registry();
        let name = "production-db".parse().unwrap();
        assert_eq!(registry.get(&name).unwrap().metadata().name, name);
    }

    #[test]
    fn an_unknown_name_is_not_found() {
        let registry = testing::registry();
        let name: ConnectionName = "staging-db".parse().unwrap();
        assert_eq!(
            registry.get(&name).unwrap_err(),
            ConnectionError::NotFound { name }
        );
    }

    #[test]
    fn a_duplicate_name_is_refused_at_startup() {
        let runtime = Arc::new(testing::runtime(Dialect::MySql));
        let error = StaticConnectionRegistry::new(vec![Arc::clone(&runtime), runtime]).unwrap_err();
        assert_eq!(
            error,
            RegistryError::Duplicate {
                name: "production-db".parse().unwrap()
            }
        );
    }

    #[test]
    fn an_empty_registry_is_refused() {
        assert_eq!(
            StaticConnectionRegistry::new(Vec::new()).unwrap_err(),
            RegistryError::Empty
        );
    }

    #[test]
    fn listing_is_sorted_by_name() {
        let runtime = |name: &str| {
            let mut parts = testing::FakeParts::new(Dialect::MySql);
            parts.metadata.name = name.parse().unwrap();
            Arc::new(testing::runtime_from(parts))
        };
        let registry = StaticConnectionRegistry::new(vec![
            runtime("zulu-db"),
            runtime("tango-db"),
            runtime("mike-db"),
            runtime("golf-db"),
            runtime("alpha-db"),
        ])
        .unwrap();
        let listed = registry.list();
        let names: Vec<&str> = listed
            .iter()
            .map(|metadata| metadata.name.as_str())
            .collect();
        assert_eq!(
            names,
            ["alpha-db", "golf-db", "mike-db", "tango-db", "zulu-db"]
        );
        assert_eq!(listed.len(), registry.len());
    }
}
