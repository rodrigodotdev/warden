//! A small, bounded, short-lived cache for catalog metadata.
//!
//! `docs/data-model.md` section 9.2 specifies exactly this shape — an
//! `RwLock<HashMap<..>>` with a five-minute TTL and a key that includes connection
//! identity — and `docs/open-questions.md` item 5 says not to reach for anything
//! larger before profiling says so. There is no Redis, no eviction policy beyond
//! expiry, and no background task.
//!
//! # Two properties this type is built around
//!
//! * **The clock is a parameter.** `warden-core` has no `tokio` dependency and must
//!   keep none, and `tokio::time::pause` does not move `std::time::Instant` anyway.
//!   Passing `now` makes expiry testable without sleeping.
//! * **What it stores is unfiltered.** Object rules are per-request (ADR-0036), so a
//!   cached *filtered* answer would freeze one request's identity into another's.
//!   The adapter filters after every read, hit or miss.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use crate::connection::ConnectionName;

use super::Table;
use super::search::CatalogIndex;

/// How long a cached catalog answer stays usable.
pub const SCHEMA_CACHE_TTL: Duration = Duration::from_secs(300);

/// How many entries one cache holds before it stops accepting new ones.
///
/// A hard ceiling rather than an eviction policy: the cache is an optimization, and
/// a full one that refuses to grow is strictly better than one that quietly becomes
/// the largest allocation in the process.
pub const SCHEMA_CACHE_CAPACITY: usize = 512;

/// What a cache entry is about.
///
/// The connection is part of every key, so one process serving two databases cannot
/// answer for the wrong one (`docs/data-model.md` section 9.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum CacheKey {
    Catalog(ConnectionName),
    Table {
        connection: ConnectionName,
        schema: String,
        table: String,
    },
}

#[derive(Debug, Clone)]
enum CachedValue {
    Catalog(Arc<CatalogIndex>),
    Table(Arc<Table>),
}

#[derive(Debug, Clone)]
struct Expiring {
    value: CachedValue,
    expires_at: Instant,
}

/// Short-lived catalog metadata, keyed by connection.
#[derive(Debug)]
pub struct SchemaCache {
    entries: RwLock<HashMap<CacheKey, Expiring>>,
    ttl: Duration,
    capacity: usize,
}

impl SchemaCache {
    /// Builds a cache with an explicit TTL and entry ceiling.
    #[must_use]
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl,
            capacity,
        }
    }

    /// The cached catalog index for a connection, when one has not expired.
    #[must_use]
    pub fn catalog(&self, connection: &ConnectionName, now: Instant) -> Option<Arc<CatalogIndex>> {
        match self.get(&CacheKey::Catalog(connection.clone()), now)? {
            CachedValue::Catalog(index) => Some(index),
            CachedValue::Table(_) => None,
        }
    }

    /// Stores a catalog index for a connection.
    pub fn store_catalog(
        &self,
        connection: &ConnectionName,
        index: Arc<CatalogIndex>,
        now: Instant,
    ) {
        self.put(
            CacheKey::Catalog(connection.clone()),
            CachedValue::Catalog(index),
            now,
        );
    }

    /// The cached description of one relation, when one has not expired.
    #[must_use]
    pub fn table(
        &self,
        connection: &ConnectionName,
        schema: &str,
        table: &str,
        now: Instant,
    ) -> Option<Arc<Table>> {
        let key = CacheKey::Table {
            connection: connection.clone(),
            schema: schema.to_owned(),
            table: table.to_owned(),
        };
        match self.get(&key, now)? {
            CachedValue::Table(described) => Some(described),
            CachedValue::Catalog(_) => None,
        }
    }

    /// Stores a relation description.
    ///
    /// The key comes from the value's own `schema` and `name`, so a caller cannot
    /// file a table under another table's name.
    pub fn store_table(&self, connection: &ConnectionName, table: Arc<Table>, now: Instant) {
        let key = CacheKey::Table {
            connection: connection.clone(),
            schema: table.schema.clone(),
            table: table.name.clone(),
        };
        self.put(key, CachedValue::Table(table), now);
    }

    /// Drops everything, expired or not.
    pub fn clear(&self) {
        self.write().clear();
    }

    /// How many entries are held, expired ones included. Diagnostics and tests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.read().len()
    }

    /// Whether the cache holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn get(&self, key: &CacheKey, now: Instant) -> Option<CachedValue> {
        let entry = self.read().get(key)?.clone();
        (entry.expires_at > now).then_some(entry.value)
    }

    fn put(&self, key: CacheKey, value: CachedValue, now: Instant) {
        let mut entries = self.write();
        if entries.len() >= self.capacity && !entries.contains_key(&key) {
            entries.retain(|_, entry| entry.expires_at > now);
            if entries.len() >= self.capacity {
                // Full of live entries. Serving from the database is correct, just
                // slower; growing without a bound is neither.
                return;
            }
        }
        entries.insert(
            key,
            Expiring {
                value,
                expires_at: now + self.ttl,
            },
        );
    }

    /// A poisoned lock holds correct data: every writer here inserts or removes a
    /// whole entry, so a panic cannot leave a half-written one. Recovering beats
    /// propagating a panic through a request path that must not panic
    /// (`docs/security.md` section 14).
    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<CacheKey, Expiring>> {
        self.entries.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<CacheKey, Expiring>> {
        self.entries.write().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Default for SchemaCache {
    /// The documented configuration: five minutes, 512 entries.
    fn default() -> Self {
        Self::new(SCHEMA_CACHE_TTL, SCHEMA_CACHE_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::connection::ConnectionName;
    use crate::schema::Table;
    use crate::schema::TableKind;
    use crate::schema::search::IndexedRelation;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn connection(name: &str) -> ConnectionName {
        name.parse().unwrap()
    }

    fn index(name: &str) -> Arc<CatalogIndex> {
        Arc::new(CatalogIndex::new(
            vec![IndexedRelation {
                schema: "app".to_owned(),
                name: name.to_owned(),
                kind: TableKind::Table,
                columns: Vec::new(),
            }],
            false,
        ))
    }

    fn table(schema: &str, name: &str) -> Arc<Table> {
        Arc::new(Table {
            schema: schema.to_owned(),
            name: name.to_owned(),
            kind: TableKind::Table,
            columns: Vec::new(),
            primary_key: Vec::new(),
            foreign_keys: Vec::new(),
            indexes: Vec::new(),
            truncated: false,
        })
    }

    #[test]
    fn a_stored_entry_is_returned_until_the_ttl_elapses() {
        let cache = SchemaCache::new(Duration::from_secs(300), 8);
        let start = Instant::now();
        let name = connection("production-mysql");

        cache.store_catalog(&name, index("orders"), start);
        assert!(
            cache
                .catalog(&name, start + Duration::from_secs(299))
                .is_some()
        );
        assert!(
            cache
                .catalog(&name, start + Duration::from_secs(300))
                .is_none()
        );
        assert!(
            cache
                .catalog(&name, start + Duration::from_secs(301))
                .is_none()
        );
    }

    #[test]
    fn one_connections_metadata_never_answers_for_another() {
        let cache = SchemaCache::default();
        let now = Instant::now();
        let mysql = connection("production-mysql");
        let postgres = connection("production-postgres");

        cache.store_catalog(&mysql, index("orders"), now);
        assert!(cache.catalog(&postgres, now).is_none());
        cache.store_table(&mysql, table("app", "orders"), now);
        assert!(cache.table(&postgres, "app", "orders", now).is_none());
        assert!(cache.table(&mysql, "app", "orders", now).is_some());
        assert!(cache.table(&mysql, "other", "orders", now).is_none());
    }

    #[test]
    fn a_table_is_filed_under_its_own_name() {
        let cache = SchemaCache::default();
        let now = Instant::now();
        let name = connection("production-postgres");
        cache.store_table(&name, table("reporting", "revenue"), now);
        assert!(cache.table(&name, "reporting", "revenue", now).is_some());
    }

    #[test]
    fn a_full_cache_of_live_entries_refuses_to_grow() {
        let cache = SchemaCache::new(Duration::from_secs(300), 2);
        let now = Instant::now();
        for suffix in 0..4 {
            cache.store_table(
                &connection("production-mysql"),
                table("app", &format!("t{suffix}")),
                now,
            );
        }
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn a_full_cache_makes_room_by_dropping_expired_entries() {
        let cache = SchemaCache::new(Duration::from_secs(300), 2);
        let start = Instant::now();
        let name = connection("production-mysql");
        cache.store_table(&name, table("app", "a"), start);
        cache.store_table(&name, table("app", "b"), start);

        let later = start + Duration::from_secs(301);
        cache.store_table(&name, table("app", "c"), later);
        assert_eq!(cache.len(), 1);
        assert!(cache.table(&name, "app", "c", later).is_some());
    }

    #[test]
    fn clearing_empties_the_cache() {
        let cache = SchemaCache::default();
        let now = Instant::now();
        cache.store_catalog(&connection("production-mysql"), index("orders"), now);
        assert!(!cache.is_empty());
        cache.clear();
        assert!(cache.is_empty());
    }
}
