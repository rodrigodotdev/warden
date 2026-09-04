//! The one shape an audit record has, and the one list of fields it may contain.
//!
//! Two sinks write these records — stderr `tracing` and an append-only file — and
//! a field list that lived in each of them separately would drift. The struct is
//! the declaration, `serde` is the encoder, and the constants below are what the
//! tests read back.
//!
//! Nothing here can carry a statement or a parameter, because no field exists that
//! one could occupy (`docs/security.md` section 11.3). `deny_codes` carries
//! `DenyCode` spellings and never `DenyReason::internal_detail`: the detail names
//! the object or function that tripped a rule, and it stays on the auditor's side
//! of `docs/security.md` section 6 — a decision Milestone 13 makes deliberately by
//! keeping the field out of the format rather than by omitting a value.
//!
//! Nothing in this module is called from production code yet: `tracing_sink` reads
//! only the field-name constants, and the structs themselves wait for Task 5's file
//! sink to construct them. Until then this is the declaration and its own tests are
//! the only caller.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the record format's declaration; only its own tests construct one \
                  until Task 5's file sink does too"
    )
)]

use serde::Serialize;
use time::OffsetDateTime;
use warden_config::AuditMode;
use warden_core::analysis::StatementKind;
use warden_core::fingerprint::QueryFingerprint;
use warden_ports::{AuditAttempt, AuditOutcomeEvent};

/// The versioned name every persisted record carries.
///
/// A reader that finds an unknown value here must not guess at the rest: the
/// format is versioned for the same reason the query fingerprint is
/// (`docs/security.md` section 11.4).
pub(crate) const RECORD_SCHEMA: &str = "warden.audit.v1";

/// Every key an attempt record has, in serialization order.
pub(crate) const ATTEMPT_FIELDS: &[&str] = &[
    "schema",
    "event",
    "attempt_id",
    "timestamp",
    "request_id",
    "principal_id",
    "client",
    "connection",
    "dialect",
    "environment",
    "operation",
    "statement_kind",
    "fingerprint",
    "deny_codes",
];

/// Every key an outcome record has, in serialization order.
pub(crate) const OUTCOME_FIELDS: &[&str] = &[
    "schema",
    "event",
    "attempt_id",
    "timestamp",
    "outcome",
    "duration_ms",
    "queue_wait_ms",
    "rows",
    "result_bytes",
    "error_code",
];

/// Names no record may ever carry (`docs/operations.md` section 10.2).
pub(crate) const FORBIDDEN_FIELDS: &[&str] = &[
    "sql",
    "raw_sql",
    "statement",
    "parameters",
    "raw_parameters",
    "password",
    "dsn",
];

/// The two keys the stderr sink does not repeat.
///
/// The subscriber stamps its own time, and the `warden.audit` target already names
/// the stream a `schema` key would identify.
pub(crate) const TRACING_OMITS: &[&str] = &["schema", "timestamp"];

/// One attempt, as it is written.
#[derive(Debug, Serialize)]
pub(crate) struct AttemptRecord<'a> {
    schema: &'static str,
    event: &'static str,
    attempt_id: String,
    #[serde(with = "time::serde::rfc3339")]
    timestamp: OffsetDateTime,
    request_id: &'a str,
    principal_id: &'a str,
    client: &'a str,
    connection: &'a str,
    dialect: &'static str,
    environment: &'a str,
    operation: &'static str,
    statement_kind: Option<&'static str>,
    fingerprint: Option<&'a str>,
    deny_codes: Vec<&'static str>,
}

impl<'a> AttemptRecord<'a> {
    /// Projects an attempt into the record `mode` allows.
    pub(crate) fn new(event: &'a AuditAttempt, mode: AuditMode) -> Self {
        let describes_statement = matches!(mode, AuditMode::Fingerprint);
        Self {
            schema: RECORD_SCHEMA,
            event: "attempt",
            attempt_id: event.id.to_string(),
            timestamp: event.timestamp,
            request_id: event.request_id.as_str(),
            principal_id: event.principal.as_str(),
            client: event.client.as_str(),
            connection: event.connection.as_str(),
            dialect: event.dialect.as_str(),
            // `Environment` has no `as_str`: `AsRef<str>` already borrows the same
            // string `Display` would format, so this is that borrow rather than a
            // new accessor (docs/operations.md section 10.2's field, unchanged).
            environment: event.environment.as_ref(),
            operation: event.operation.as_str(),
            statement_kind: describes_statement
                .then(|| event.statement_kind.map(StatementKind::as_str))
                .flatten(),
            fingerprint: describes_statement
                .then(|| event.fingerprint.as_ref().map(QueryFingerprint::as_str))
                .flatten(),
            deny_codes: event
                .deny_reasons
                .iter()
                .map(|reason| reason.code().as_str())
                .collect(),
        }
    }
}

/// One outcome, as it is written.
///
/// Unlike [`AttemptRecord`], nothing here is gated by `AuditMode`: an outcome
/// describes what happened to Warden's own decision, not to a statement, so
/// `none` has nothing left to drop from it.
#[derive(Debug, Serialize)]
pub(crate) struct OutcomeRecord {
    schema: &'static str,
    event: &'static str,
    attempt_id: String,
    #[serde(with = "time::serde::rfc3339")]
    timestamp: OffsetDateTime,
    outcome: &'static str,
    duration_ms: Option<u64>,
    queue_wait_ms: Option<u64>,
    rows: Option<usize>,
    result_bytes: Option<usize>,
    error_code: Option<&'static str>,
}

impl OutcomeRecord {
    /// Projects an outcome event into its record, stamping the moment it is
    /// written rather than borrowing a timestamp the event does not carry.
    pub(crate) fn new(event: &AuditOutcomeEvent) -> Self {
        Self {
            schema: RECORD_SCHEMA,
            event: "outcome",
            attempt_id: event.attempt_id.to_string(),
            timestamp: OffsetDateTime::now_utc(),
            outcome: event.outcome.as_str(),
            // Saturating rather than truncating: a duration beyond `u64`
            // milliseconds is not reachable under any configured deadline, and
            // reporting the ceiling is still true where wrapping would not be.
            duration_ms: event
                .duration
                .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)),
            // Saturating for the same reason as `duration_ms`: a queue wait beyond
            // `u64` milliseconds is not reachable under any configured
            // `max_queue_wait`.
            queue_wait_ms: event
                .queue_wait
                .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)),
            rows: event.rows_returned,
            result_bytes: event.result_bytes,
            error_code: event.error_code.map(|code| code.as_str()),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::fmt;
    use std::time::Duration;

    use warden_core::analysis::StatementKind;
    use warden_core::connection::Environment;
    use warden_core::dialect::Dialect;
    use warden_core::fingerprint::QueryFingerprint;
    use warden_policy::{DenyCode, DenyReason};
    use warden_ports::{
        AuditAttempt, AuditEventId, AuditOperation, AuditOutcome, AuditOutcomeEvent,
    };

    use super::*;

    #[test]
    fn a_persisted_attempt_carries_exactly_the_documented_keys() {
        let event = attempt();
        let record = AttemptRecord::new(&event, AuditMode::Fingerprint);
        // Not `serde_json::to_value(&record).as_object().keys()`: this workspace does
        // not carry serde_json's `preserve_order` feature, so a `Value`'s `Map` is a
        // `BTreeMap` and would hand back the keys alphabetized rather than in the
        // order the record actually writes them. Reading the key order back out of
        // the record's own JSON text is what actually proves `ATTEMPT_FIELDS` is
        // telling the truth.
        let json = serde_json::to_string(&record).unwrap();
        let RecordKeys(keys) = serde_json::from_str(&json).unwrap();
        let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
        assert_eq!(keys, ATTEMPT_FIELDS);

        let value = serde_json::to_value(&record).unwrap();
        assert_eq!(value["schema"], serde_json::json!(RECORD_SCHEMA));
        assert_eq!(value["event"], serde_json::json!("attempt"));
    }

    #[test]
    fn a_persisted_outcome_carries_exactly_the_documented_keys() {
        // `AttemptRecord`'s wire key order is pinned above against `ATTEMPT_FIELDS`;
        // nothing did the same for `OutcomeRecord` until now, so a field renamed or
        // reordered without updating `OUTCOME_FIELDS` would pass every other test in
        // this module and still lie about the wire format Task 5's file sink writes.
        let record = OutcomeRecord::new(&outcome_event(AuditOutcome::Succeeded));
        let json = serde_json::to_string(&record).unwrap();
        let RecordKeys(keys) = serde_json::from_str(&json).unwrap();
        let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
        assert_eq!(keys, OUTCOME_FIELDS);
    }

    #[test]
    fn no_record_has_a_field_a_statement_or_a_secret_could_occupy() {
        for fields in [ATTEMPT_FIELDS, OUTCOME_FIELDS] {
            for forbidden in FORBIDDEN_FIELDS {
                assert!(!fields.contains(forbidden), "{forbidden}");
            }
        }
    }

    #[test]
    fn the_none_mode_drops_what_describes_the_statement_and_nothing_else() {
        // docs/operations.md section 3: `none` records nothing beyond that a request
        // happened. The record itself is not optional — SPEC section 6, invariant 24
        // has no configuration key (ADR-0026) — so the mode drops the two fields that
        // describe the statement and keeps identity, connection, operation and the
        // denials, which are Warden's own decisions rather than statement content.
        let event = attempt();
        let record = AttemptRecord::new(&event, AuditMode::None_);
        let value = serde_json::to_value(&record).unwrap();
        assert_eq!(value["fingerprint"], serde_json::Value::Null);
        assert_eq!(value["statement_kind"], serde_json::Value::Null);
        assert_eq!(value["deny_codes"], serde_json::json!(["write_statement"]));
        assert_eq!(value["connection"], serde_json::json!("production-db"));
    }

    #[test]
    fn a_record_line_is_one_line() {
        // The file sink writes one record per line; a value carrying a newline would
        // split one record into two and make the trail unparseable.
        let json =
            serde_json::to_string(&AttemptRecord::new(&attempt(), AuditMode::Fingerprint)).unwrap();
        assert!(!json.contains('\n'));
    }

    #[test]
    fn every_outcome_and_operation_reaches_a_record_spelling() {
        for outcome in AuditOutcome::ALL {
            let value = serde_json::to_value(OutcomeRecord::new(&outcome_event(outcome))).unwrap();
            assert_eq!(value["outcome"], serde_json::json!(outcome.as_str()));
        }
        for operation in AuditOperation::ALL {
            let mut event = attempt();
            event.operation = operation;
            let value =
                serde_json::to_value(AttemptRecord::new(&event, AuditMode::Fingerprint)).unwrap();
            assert_eq!(value["operation"], serde_json::json!(operation.as_str()));
        }
    }

    /// One representative attempt: production, MySQL, a select, denied for writing.
    fn attempt() -> AuditAttempt {
        AuditAttempt {
            id: AuditEventId::generate(),
            timestamp: time::OffsetDateTime::UNIX_EPOCH,
            request_id: "request-1".parse().unwrap(),
            principal: "local-stdio".parse().unwrap(),
            client: "example-client".parse().unwrap(),
            connection: "production-db".parse().unwrap(),
            dialect: Dialect::MySql,
            environment: Environment::Production,
            operation: AuditOperation::Query,
            fingerprint: Some(QueryFingerprint::v1(&"a".repeat(64)).unwrap()),
            statement_kind: Some(StatementKind::Select),
            deny_reasons: vec![DenyReason::new(DenyCode::WriteStatement)],
        }
    }

    /// One representative outcome, correlated with nothing in particular: every test
    /// here reads `outcome`, not `attempt_id`.
    fn outcome_event(outcome: AuditOutcome) -> AuditOutcomeEvent {
        AuditOutcomeEvent {
            attempt_id: AuditEventId::generate(),
            outcome,
            duration: Some(Duration::from_millis(3)),
            queue_wait: Some(Duration::from_millis(1)),
            rows_returned: Some(2),
            result_bytes: Some(64),
            error_code: None,
        }
    }

    /// The keys a JSON object's own text names, in the order they appear.
    ///
    /// A hand-rolled `Visitor` rather than `serde_json::Value`: `Value`'s `Map` is a
    /// `BTreeMap` unless the crate carries `preserve_order`, which this workspace
    /// does not, so parsing into one would alphabetize the very thing this test
    /// exists to check. `MapAccess` has no such feature gate — it yields entries in
    /// the order the deserializer reads them off the wire, because it is a cursor
    /// over the input, not a container someone could reorder.
    struct RecordKeys(Vec<String>);

    impl<'de> serde::Deserialize<'de> for RecordKeys {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct KeyOrderVisitor;

            impl<'de> serde::de::Visitor<'de> for KeyOrderVisitor {
                type Value = RecordKeys;

                fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str("a JSON object")
                }

                fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                where
                    A: serde::de::MapAccess<'de>,
                {
                    let mut keys = Vec::new();
                    while let Some(key) = map.next_key::<String>()? {
                        let _: serde::de::IgnoredAny = map.next_value()?;
                        keys.push(key);
                    }
                    Ok(RecordKeys(keys))
                }
            }

            deserializer.deserialize_map(KeyOrderVisitor)
        }
    }
}
