//! One PostgreSQL row, turned into the core result model.
//!
//! # The table is closed
//!
//! [`kind_of`] matches the exact strings `sqlx_postgres`'s `PgTypeInfo::name`
//! produces — display names such as `INT4` and `TIMESTAMPTZ`, not the catalog names
//! `int4` and `timestamptz`. Anything it does not name is [`ValueKind::Unsupported`],
//! which becomes a `NormalizationError::UnsupportedType` carrying the type name and a
//! cast example — ADR-0011's default deny applied to types rather than to SQL. A
//! wildcard that guessed would be the one place a value of unknown shape entered
//! model context.
//!
//! # A supported type can still hold an unrepresentable value
//!
//! This is where PostgreSQL differs from MySQL, and it is not a corner case: `date`
//! reaches year 5874897, `timestamp` reaches year 294276, both accept `'infinity'`
//! and `'-infinity'`, and `numeric` accepts `'NaN'`. `time::Date` holds ±9999 years
//! and its `Add` **panics** on overflow rather than returning an error, so handing
//! any of those to `sqlx`'s own date decoder would abort the request task —
//! precisely what SPEC section 6, invariant 31 forbids. [`date_from_days`] and
//! [`timestamp_from_micros`] therefore decode the wire integer, which is total, and
//! convert with `checked_add`; `None` becomes
//! `NormalizationError::UnrepresentableValue`, which blames the value rather than
//! the column's type.
//!
//! # A decode failure says the same thing every time
//!
//! `sqlx`'s `Decode` errors quote the value they could not read.
//! `docs/data-model.md` section 8.1, rule 4 allows the **type name** and nothing
//! else, so every failure here collapses into `UnsupportedType`, and the driver's
//! message is dropped rather than wrapped. `NUMERIC` is the one exception: its only
//! reachable decode failures are `NaN` and `±Infinity`, both of which are values
//! rather than types, so it reports `UnrepresentableValue` instead.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sqlx::postgres::{PgRow, PgValueFormat, PgValueRef, Postgres};
use sqlx::types::{BigDecimal, Uuid};
use sqlx::{Column, Decode, Row, Type, TypeInfo, ValueRef};
use warden_core::dialect::Dialect;
use warden_core::result::{NormalizationError, ResultBuildError, ResultColumn, ResultValue};

/// The origin every PostgreSQL `date`, `timestamp` and `timestamptz` counts from.
const PG_EPOCH: time::Date = time::macros::date!(2000 - 01 - 01);

/// One PostgreSQL scalar type, in the form the core model can carry.
///
/// `Float32` and `Float64` are separate because `sqlx`'s `f32` decoder reads the
/// first four bytes of whatever it is given: handed an eight-byte `float8` it
/// returns a wrong number rather than an error. Integers need no such split —
/// `int_decode` reads any one-to-eight-byte big-endian integer into an `i64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scalar {
    /// `bool`.
    Bool,
    /// `int2`, `int4` or `int8`.
    Signed,
    /// `float4`.
    Float32,
    /// `float8`.
    Float64,
    /// `numeric`, preserved as text so no digit is lost.
    Numeric,
    /// Character data.
    Text,
    /// `bytea`, which leaves as base64.
    Bytes,
    /// `date`.
    Date,
    /// `time`.
    Time,
    /// `timestamp`, which carries no zone.
    Timestamp,
    /// `timestamptz`, which PostgreSQL stores in UTC.
    TimestampTz,
    /// `uuid`.
    Uuid,
    /// `json` or `jsonb`.
    Json,
}

/// What one column's declared type becomes in the core model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueKind {
    /// A single value.
    Scalar(Scalar),
    /// A one-dimensional array of one scalar type.
    Array(Scalar),
    /// Everything else, which fails safely with a cast example.
    Unsupported,
}

/// Maps a PostgreSQL scalar type name to the core representation.
///
/// `CHAR` is `bpchar`. The one-byte internal `"char"` type displays as `"CHAR"`
/// **with** quotes and is deliberately absent: it is a catalog implementation type,
/// not something an investigation query should be reading unquoted.
fn scalar_of(database_type: &str) -> Option<Scalar> {
    Some(match database_type {
        "BOOL" => Scalar::Bool,
        "INT2" | "INT4" | "INT8" => Scalar::Signed,
        "FLOAT4" => Scalar::Float32,
        "FLOAT8" => Scalar::Float64,
        "NUMERIC" => Scalar::Numeric,
        "TEXT" | "VARCHAR" | "CHAR" | "NAME" => Scalar::Text,
        "BYTEA" => Scalar::Bytes,
        "DATE" => Scalar::Date,
        "TIME" => Scalar::Time,
        "TIMESTAMP" => Scalar::Timestamp,
        "TIMESTAMPTZ" => Scalar::TimestampTz,
        "UUID" => Scalar::Uuid,
        "JSON" | "JSONB" => Scalar::Json,
        // `INTERVAL`, `TIMETZ`, `MONEY`, every range and geometry type, every
        // extension type, and every user-defined enum or composite land here. So
        // does `OID` and the rest of the catalog's own types: schema introspection
        // is Warden's static SQL on `control_pool` (Milestone 9), never a value an
        // agent query normalizes.
        _ => return None,
    })
}

/// Maps a PostgreSQL column type name to the core representation.
///
/// An array is recognised by the `[]` suffix `PgTypeInfo::name` appends, and its
/// element must itself be a scalar this table names: `INT4[][]` cannot occur —
/// PostgreSQL's multi-dimensional `int4[][]` is still the `_int4` type, so its name
/// still ends in exactly one `[]` — and if it ever did, the inner lookup would fail
/// and the column would be denied rather than guessed.
///
/// `DATE[]`, `TIMESTAMP[]` and `TIMESTAMPTZ[]` are refused on purpose. `sqlx`
/// decodes array elements internally, so the overflow guard the scalar path applies
/// cannot reach them, and an `infinity` element would panic inside the driver. A
/// `::text` cast renders those arrays correctly and is what the error suggests.
pub(crate) fn kind_of(database_type: &str) -> ValueKind {
    let Some(element) = database_type.strip_suffix("[]") else {
        return scalar_of(database_type).map_or(ValueKind::Unsupported, ValueKind::Scalar);
    };
    match scalar_of(element) {
        Some(Scalar::Date | Scalar::Timestamp | Scalar::TimestampTz) | None => {
            ValueKind::Unsupported
        }
        Some(scalar) => ValueKind::Array(scalar),
    }
}
/// The column metadata for one row.
///
/// `nullable` is always `None`: neither driver reports nullability through a row —
/// only through `describe` — and `docs/architecture.md` section 11 forbids inventing
/// a value the engine did not give.
pub(crate) fn columns(row: &PgRow) -> Vec<ResultColumn> {
    row.columns()
        .iter()
        .map(|column| ResultColumn {
            name: column.name().to_owned(),
            database_type: column.type_info().name().to_owned(),
            nullable: None,
        })
        .collect()
}

/// One row's values, positionally aligned with `columns`.
pub(crate) fn row(
    row: &PgRow,
    columns: &[ResultColumn],
    max_value_bytes: usize,
) -> Result<Vec<ResultValue>, ResultBuildError> {
    columns
        .iter()
        .enumerate()
        .map(|(index, column)| value(row, index, column, max_value_bytes))
        .collect()
}

/// One value.
///
/// `max_value_bytes` is checked here against the value's **raw** size as well as by
/// `ResultBuilder` against its encoded size. The early check is not a duplicate: a
/// 500 MB `bytea` would otherwise be copied into a 666 MB base64 string purely to be
/// rejected. The builder remains the authority.
fn value(
    row: &PgRow,
    index: usize,
    column: &ResultColumn,
    max_value_bytes: usize,
) -> Result<ResultValue, ResultBuildError> {
    let raw = row.try_get_raw(index).map_err(|_| unsupported(column))?;
    if raw.is_null() {
        return Ok(ResultValue::Null);
    }

    match kind_of(&column.database_type) {
        ValueKind::Scalar(scalar) => scalar_value(scalar, raw, column, max_value_bytes),
        ValueKind::Array(element) => array_value(element, raw, column, max_value_bytes),
        ValueKind::Unsupported => Err(unsupported(column).into()),
    }
}

/// One non-null scalar.
fn scalar_value(
    scalar: Scalar,
    raw: PgValueRef<'_>,
    column: &ResultColumn,
    max_value_bytes: usize,
) -> Result<ResultValue, ResultBuildError> {
    let value = match scalar {
        Scalar::Bool => ResultValue::Bool(decode::<bool>(raw, column)?),
        Scalar::Signed => ResultValue::I64(decode::<i64>(raw, column)?),
        Scalar::Float32 => finite(f64::from(decode::<f32>(raw, column)?), column)?,
        Scalar::Float64 => finite(decode::<f64>(raw, column)?, column)?,
        Scalar::Numeric => {
            // `to_plain_string`, never `to_string`: `BigDecimal`'s `Display`
            // switches to exponential notation past its own thresholds, and
            // `1E+10` is not what `docs/data-model.md` section 8.1, rule 1 means by
            // preserving the server's digits. The decode failure is reported as an
            // unrepresentable *value* because `NaN` and `±Infinity` are its only
            // reachable causes.
            let number = decode_value::<BigDecimal>(raw, column)?;
            ResultValue::Decimal(number.to_plain_string())
        }
        Scalar::Text => text_value(decode::<&str>(raw, column)?, column, max_value_bytes)?,
        Scalar::Bytes => bytes_value(decode::<&[u8]>(raw, column)?, column, max_value_bytes)?,
        Scalar::Date => {
            let days = wire_integer::<i32>(raw, column)?;
            ResultValue::Date(format_date(
                date_from_days(days).ok_or_else(|| unrepresentable(column))?,
            ))
        }
        Scalar::Time => ResultValue::Time(format_time(decode::<time::Time>(raw, column)?)),
        Scalar::Timestamp => {
            let micros = wire_integer::<i64>(raw, column)?;
            ResultValue::DateTime(format_timestamp(
                timestamp_from_micros(micros).ok_or_else(|| unrepresentable(column))?,
            ))
        }
        Scalar::TimestampTz => {
            let micros = wire_integer::<i64>(raw, column)?;
            ResultValue::DateTime(format_timestamptz(
                timestamp_from_micros(micros).ok_or_else(|| unrepresentable(column))?,
            ))
        }
        Scalar::Uuid => ResultValue::Uuid(decode::<Uuid>(raw, column)?.to_string()),
        Scalar::Json => ResultValue::Json(decode::<serde_json::Value>(raw, column)?),
    };
    Ok(value)
}

/// One non-null array, element by element.
///
/// Exhaustive on `Scalar` on purpose: adding a scalar type must break this build
/// rather than silently produce an array the table cannot describe. `Date`,
/// `Timestamp` and `TimestampTz` cannot appear — [`kind_of`] never builds
/// `ValueKind::Array` for them — but they still need arms, and refusing them here as
/// well keeps the reason next to the code rather than only in `kind_of`'s comment.
fn array_value(
    element: Scalar,
    raw: PgValueRef<'_>,
    column: &ResultColumn,
    max_value_bytes: usize,
) -> Result<ResultValue, ResultBuildError> {
    match element {
        Scalar::Bool => array_of::<bool, _>(raw, column, |value| Ok(ResultValue::Bool(value))),
        Scalar::Signed => array_of::<i64, _>(raw, column, |value| Ok(ResultValue::I64(value))),
        Scalar::Float32 => {
            array_of::<f32, _>(raw, column, |value| finite(f64::from(value), column))
        }
        Scalar::Float64 => array_of::<f64, _>(raw, column, |value| finite(value, column)),
        Scalar::Numeric => array_of::<BigDecimal, _>(raw, column, |value| {
            Ok(ResultValue::Decimal(value.to_plain_string()))
        }),
        Scalar::Text => array_of::<String, _>(raw, column, |value| {
            text_value(&value, column, max_value_bytes)
        }),
        Scalar::Bytes => array_of::<Vec<u8>, _>(raw, column, |value| {
            bytes_value(&value, column, max_value_bytes)
        }),
        Scalar::Time => array_of::<time::Time, _>(raw, column, |value| {
            Ok(ResultValue::Time(format_time(value)))
        }),
        Scalar::Uuid => array_of::<Uuid, _>(raw, column, |value| {
            Ok(ResultValue::Uuid(value.to_string()))
        }),
        Scalar::Json => {
            array_of::<serde_json::Value, _>(raw, column, |value| Ok(ResultValue::Json(value)))
        }
        Scalar::Date | Scalar::Timestamp | Scalar::TimestampTz => Err(unsupported(column).into()),
    }
}

/// Decodes a one-dimensional array and converts each element.
///
/// The elements are owned rather than borrowed because `sqlx`'s array decoder
/// requires `T: for<'a> Decode<'a, Postgres>`, a higher-ranked bound `&str` and
/// `&[u8]` cannot satisfy. One consequence is honest and worth stating: an array
/// element is copied before it is measured against `max_value_bytes`, unlike a
/// scalar. As `docs/data-model.md` section 7 already records, that budget bounds
/// what **leaves** Warden; the driver has materialized the row either way.
///
/// One asymmetry with the scalar path is accepted rather than engineered around: a
/// `NaN` inside a `numeric[]` fails through `decode` and is reported as
/// `UnsupportedType`, where the same value in a scalar `numeric` column reports
/// `UnrepresentableValue`. Distinguishing them would mean a second generic parameter
/// carrying the error constructor, for an element case no measurement has asked for.
/// Both are safe errors naming only the type, and both suggest the `::text` cast.
///
/// The depth bound is `ResultValue::array`'s, not this function's:
/// `MAX_ARRAY_DEPTH` is a `warden-core` rule and stays enforced in one place. PostgreSQL
/// can only reach depth 1 through `sqlx`, so the check is defense in depth here.
fn array_of<'r, T, F>(
    raw: PgValueRef<'r>,
    column: &ResultColumn,
    convert: F,
) -> Result<ResultValue, ResultBuildError>
where
    T: for<'a> Decode<'a, Postgres> + Type<Postgres>,
    F: Fn(T) -> Result<ResultValue, ResultBuildError>,
{
    let decoded = decode::<Vec<Option<T>>>(raw, column)?;
    let mut values = Vec::with_capacity(decoded.len());
    for element in decoded {
        values.push(match element {
            Some(value) => convert(value)?,
            None => ResultValue::Null,
        });
    }
    Ok(ResultValue::array(values)?)
}

/// Decodes one value, discarding the driver's message.
fn decode<'r, T: Decode<'r, Postgres>>(
    raw: PgValueRef<'r>,
    column: &ResultColumn,
) -> Result<T, NormalizationError> {
    T::decode(raw).map_err(|_| unsupported(column))
}

/// Decodes one value whose only reachable failures are unrepresentable *values*.
///
/// `NUMERIC` is the case: `sqlx` reports `'NaN'` as "BigDecimal does not support NaN
/// values" and `'Infinity'` as an invalid sign word, and there is no third way for a
/// `numeric` the server sent to fail. Reporting those as `UnsupportedType` would tell
/// the agent that `numeric` itself is unsupported.
fn decode_value<'r, T: Decode<'r, Postgres>>(
    raw: PgValueRef<'r>,
    column: &ResultColumn,
) -> Result<T, NormalizationError> {
    T::decode(raw).map_err(|_| unrepresentable(column))
}

/// Reads the integer a `date` or a `timestamp` arrives as.
///
/// Deliberately not `T::decode` on the calendar type: `sqlx` adds that integer to
/// its epoch with `time`'s panicking `Add`, and PostgreSQL's own range is wider than
/// `time`'s. The integer decoders are total for any one-to-eight-byte value, so
/// reading the number first and converting with `checked_add` is what keeps an
/// `'infinity'::timestamptz` an error instead of an aborted request task.
///
/// The text arm cannot be reached: `sqlx-postgres` asks for binary results on every
/// prepared statement, and the simple-query protocol is banned by `clippy.toml`. It
/// refuses rather than guesses, so an upstream change makes a wrong value impossible
/// rather than merely unlikely.
fn wire_integer<'r, T: Decode<'r, Postgres>>(
    raw: PgValueRef<'r>,
    column: &ResultColumn,
) -> Result<T, NormalizationError> {
    if raw.format() != PgValueFormat::Binary {
        return Err(unsupported(column));
    }
    decode::<T>(raw, column)
}

/// The date `days` days after the PostgreSQL epoch, if `time` can hold it.
fn date_from_days(days: i32) -> Option<time::Date> {
    PG_EPOCH.checked_add(time::Duration::days(i64::from(days)))
}

/// The timestamp `micros` microseconds after the PostgreSQL epoch, if `time` can
/// hold it.
fn timestamp_from_micros(micros: i64) -> Option<time::PrimitiveDateTime> {
    PG_EPOCH
        .midnight()
        .checked_add(time::Duration::microseconds(micros))
}

/// Refuses a float JSON cannot carry.
///
/// PostgreSQL genuinely stores `'NaN'`, `'Infinity'` and `'-Infinity'` in `float4`
/// and `float8`, so this arm is reachable in ordinary data rather than only in
/// theory. `serde_json` would write `null`, turning "the value was infinity" into
/// "the value was missing".
fn finite(number: f64, column: &ResultColumn) -> Result<ResultValue, ResultBuildError> {
    if !number.is_finite() {
        return Err(NormalizationError::NonFiniteFloat {
            column: column.name.clone(),
        }
        .into());
    }
    Ok(ResultValue::F64(number))
}

/// Text, refused before it is copied if it is already over budget.
fn text_value(
    value: &str,
    column: &ResultColumn,
    max_value_bytes: usize,
) -> Result<ResultValue, ResultBuildError> {
    guard(value.len(), column, max_value_bytes)?;
    Ok(ResultValue::String(value.to_owned()))
}

/// Bytes, refused before they are base64-encoded if the encoding would be over
/// budget.
fn bytes_value(
    value: &[u8],
    column: &ResultColumn,
    max_value_bytes: usize,
) -> Result<ResultValue, ResultBuildError> {
    guard(base64_len(value.len()), column, max_value_bytes)?;
    Ok(ResultValue::BytesBase64(BASE64.encode(value)))
}

/// Rejects a value whose raw size already exceeds the per-value budget.
fn guard(
    actual: usize,
    column: &ResultColumn,
    max_value_bytes: usize,
) -> Result<(), ResultBuildError> {
    if actual > max_value_bytes {
        return Err(ResultBuildError::ValueTooLarge {
            column: column.name.clone(),
            actual,
            limit: max_value_bytes,
        });
    }
    Ok(())
}

/// The length base64 turns `raw` into: four characters per three bytes, padded.
fn base64_len(raw: usize) -> usize {
    raw.div_ceil(3).saturating_mul(4)
}

/// The column's type has no safe representation.
fn unsupported(column: &ResultColumn) -> NormalizationError {
    NormalizationError::UnsupportedType {
        column: column.name.clone(),
        dialect: Dialect::PostgreSql,
        database_type: column.database_type.clone(),
    }
}

/// The column's type is fine; this value is not.
fn unrepresentable(column: &ResultColumn) -> NormalizationError {
    NormalizationError::UnrepresentableValue {
        column: column.name.clone(),
        dialect: Dialect::PostgreSql,
        database_type: column.database_type.clone(),
    }
}
/// `YYYY-MM-DD`.
fn format_date(date: time::Date) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

/// `HH:MM:SS[.ffffff]`.
///
/// The fractional part is written from the decoded microseconds, so it is omitted
/// entirely at zero and always six digits otherwise. A `time(3)` column's declared
/// precision is not preserved — every digit shown is a true stored microsecond, but
/// the column's own width is lost, exactly as on MySQL
/// (`docs/open-questions.md` section 2).
fn format_time(value: time::Time) -> String {
    let mut rendered = format!(
        "{:02}:{:02}:{:02}",
        value.hour(),
        value.minute(),
        value.second()
    );
    let microseconds = value.microsecond();
    if microseconds != 0 {
        rendered.push_str(&format!(".{microseconds:06}"));
    }
    rendered
}

/// `YYYY-MM-DD HH:MM:SS[.ffffff]`, with no offset appended.
///
/// A `timestamp` carries no zone, and none is invented
/// (`docs/architecture.md` section 11).
fn format_timestamp(stamp: time::PrimitiveDateTime) -> String {
    format!(
        "{} {}",
        format_date(stamp.date()),
        format_time(stamp.time())
    )
}

/// `YYYY-MM-DD HH:MM:SS[.ffffff]+00:00`.
///
/// The offset is stated rather than invented: PostgreSQL stores `timestamptz` in
/// UTC, and this module decodes the same UTC microsecond count `sqlx` would have
/// called `assume_utc` on. This is the one place PostgreSQL is *less* ambiguous
/// than MySQL, whose `TIMESTAMP` is emitted in the session's unpinned zone
/// (`docs/open-questions.md` section 2, item 15).
fn format_timestamptz(stamp: time::PrimitiveDateTime) -> String {
    format!("{}+00:00", format_timestamp(stamp))
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn every_documented_postgresql_type_has_a_representation() {
        // `docs/data-model.md` section 8.2's PostgreSQL list, by the names the
        // driver reports. A type missing here is a type that would reach an agent
        // as an unsupported-type error in production.
        let cases: &[(&str, ValueKind)] = &[
            ("BOOL", ValueKind::Scalar(Scalar::Bool)),
            ("INT2", ValueKind::Scalar(Scalar::Signed)),
            ("INT4", ValueKind::Scalar(Scalar::Signed)),
            ("INT8", ValueKind::Scalar(Scalar::Signed)),
            ("FLOAT4", ValueKind::Scalar(Scalar::Float32)),
            ("FLOAT8", ValueKind::Scalar(Scalar::Float64)),
            ("NUMERIC", ValueKind::Scalar(Scalar::Numeric)),
            ("TEXT", ValueKind::Scalar(Scalar::Text)),
            ("VARCHAR", ValueKind::Scalar(Scalar::Text)),
            ("CHAR", ValueKind::Scalar(Scalar::Text)),
            ("NAME", ValueKind::Scalar(Scalar::Text)),
            ("BYTEA", ValueKind::Scalar(Scalar::Bytes)),
            ("DATE", ValueKind::Scalar(Scalar::Date)),
            ("TIME", ValueKind::Scalar(Scalar::Time)),
            ("TIMESTAMP", ValueKind::Scalar(Scalar::Timestamp)),
            ("TIMESTAMPTZ", ValueKind::Scalar(Scalar::TimestampTz)),
            ("UUID", ValueKind::Scalar(Scalar::Uuid)),
            ("JSON", ValueKind::Scalar(Scalar::Json)),
            ("JSONB", ValueKind::Scalar(Scalar::Json)),
            ("INT4[]", ValueKind::Array(Scalar::Signed)),
            ("TEXT[]", ValueKind::Array(Scalar::Text)),
            ("NUMERIC[]", ValueKind::Array(Scalar::Numeric)),
            ("UUID[]", ValueKind::Array(Scalar::Uuid)),
            ("JSONB[]", ValueKind::Array(Scalar::Json)),
            ("BYTEA[]", ValueKind::Array(Scalar::Bytes)),
            ("TIME[]", ValueKind::Array(Scalar::Time)),
        ];
        for (name, expected) in cases {
            assert_eq!(kind_of(name), *expected, "{name}");
        }
    }

    #[test]
    fn an_unnamed_type_is_denied_rather_than_guessed() {
        for name in [
            "INTERVAL",
            "TIMETZ",
            "MONEY",
            "INT4RANGE",
            "POINT",
            "OID",
            "order_state",
            "\"CHAR\"",
            "",
            "int4",
        ] {
            assert_eq!(kind_of(name), ValueKind::Unsupported, "{name}");
        }
    }

    #[test]
    fn calendar_arrays_are_refused_because_their_elements_cannot_be_guarded() {
        // Design decision 7: `sqlx` decodes array elements internally, so the
        // overflow guard `scalar_value` applies cannot reach them, and an
        // `infinity` element would panic inside the driver rather than fail.
        for name in ["DATE[]", "TIMESTAMP[]", "TIMESTAMPTZ[]"] {
            assert_eq!(kind_of(name), ValueKind::Unsupported, "{name}");
        }
        // The refusal is specific to those three, not to arrays in general.
        assert_eq!(kind_of("TIME[]"), ValueKind::Array(Scalar::Time));
    }

    #[test]
    fn an_array_of_an_unnamed_type_is_denied() {
        for name in ["INTERVAL[]", "order_state[]", "[]", "\"CHAR\"[]"] {
            assert_eq!(kind_of(name), ValueKind::Unsupported, "{name}");
        }
    }

    #[test]
    fn the_unsupported_error_names_the_type_and_a_postgresql_cast() {
        let column = ResultColumn {
            name: "custom_state".to_owned(),
            database_type: "order_state".to_owned(),
            nullable: None,
        };
        let rendered = unsupported(&column).to_string();
        assert!(rendered.contains("order_state"), "{rendered}");
        assert!(rendered.contains("custom_state::text"), "{rendered}");
        assert!(!rendered.contains("CAST("), "{rendered}");
    }

    #[test]
    fn the_calendar_guard_refuses_exactly_what_time_cannot_hold() {
        // `time::Date` holds ±9999 years; PostgreSQL's `date` reaches 5874897 AD
        // and reserves both extremes for the infinities. `sqlx`'s own decoder adds
        // the number to its epoch with a panicking `Add`, which is what this
        // conversion exists to avoid (SPEC section 6, invariant 31).
        assert!(date_from_days(0).is_some());
        assert!(date_from_days(i32::MAX).is_none());
        assert!(date_from_days(i32::MIN).is_none());
        assert!(timestamp_from_micros(0).is_some());
        assert!(timestamp_from_micros(i64::MAX).is_none());
        assert!(timestamp_from_micros(i64::MIN).is_none());

        // The epoch itself, so a wrong constant fails here rather than by one day
        // in a container test.
        assert_eq!(format_date(date_from_days(0).unwrap()), "2000-01-01");
        assert_eq!(format_date(date_from_days(1).unwrap()), "2000-01-02");
        assert_eq!(format_date(date_from_days(-1).unwrap()), "1999-12-31");
    }

    #[test]
    fn base64_length_matches_the_real_encoder() {
        // Exact equality, not merely an upper bound: `bytes_value` calls
        // `base64_len` to guard the per-value budget *before* encoding,
        // specifically so a huge `bytea` is never copied into a huge base64
        // `String` purely to be rejected. An upper bound alone would let a value
        // pass this check and then encode larger than `max_value_bytes` allows.
        for raw in [0usize, 1, 2, 3, 4, 100, 65_536] {
            let encoded = BASE64.encode(vec![0u8; raw]);
            assert_eq!(base64_len(raw), encoded.len(), "{raw}");
        }
    }

    #[test]
    fn dates_and_times_render_deterministically() {
        let date = time::Date::from_calendar_date(2026, time::Month::January, 5).unwrap();
        assert_eq!(format_date(date), "2026-01-05");

        assert_eq!(
            format_time(time::Time::from_hms_micro(9, 7, 3, 0).unwrap()),
            "09:07:03"
        );
        assert_eq!(
            format_time(time::Time::from_hms_micro(9, 7, 3, 250_000).unwrap()),
            "09:07:03.250000"
        );

        let stamp =
            time::PrimitiveDateTime::new(date, time::Time::from_hms_micro(9, 7, 3, 0).unwrap());
        assert_eq!(format_timestamp(stamp), "2026-01-05 09:07:03");
        // A `timestamptz` states its offset because PostgreSQL stores it in UTC; a
        // `timestamp` states none because it has none.
        assert_eq!(format_timestamptz(stamp), "2026-01-05 09:07:03+00:00");
    }

    #[test]
    fn json_numbers_remain_exact_through_normalized_result_serialization() {
        for document in [
            r#"{"value":18446744073709551616}"#,
            r#"{"value":0.123456789012345678901234567890}"#,
        ] {
            let decoded = serde_json::from_str::<serde_json::Value>(document).unwrap();
            let normalized = ResultValue::Json(decoded);

            assert_eq!(serde_json::to_string(&normalized).unwrap(), document);
        }
    }
}
