//! One MySQL row, turned into the core result model.
//!
//! # The table is closed
//!
//! `kind_of` matches the exact strings `sqlx_mysql`'s `ColumnType::name` produces.
//! Anything it does not name is [`ValueKind::Unsupported`], which becomes a
//! `NormalizationError::UnsupportedType` carrying the type name and a cast example —
//! ADR-0011's default deny applied to types rather than to SQL. A wildcard that
//! guessed would be the one place a value of unknown shape entered model context.
//!
//! # A decode failure says the same thing every time
//!
//! `sqlx`'s `Decode` errors quote the value they could not read.
//! `docs/data-model.md` section 8.1, rule 4 allows the **type name** and nothing
//! else, so every failure here collapses into the same `UnsupportedType`, and the
//! driver's message is dropped rather than wrapped.

// `dead_code` is not a workspace lint (`Cargo.toml` `[workspace.lints]` lists
// neither it nor an equivalent), so this is not silencing one. `columns` and `row`
// are the interface `execute.rs` calls in the next task; until that module exists,
// nothing outside this file's own tests reaches this module, and the plain (no
// `cfg(test)`) build would otherwise call every item here dead.
#![allow(dead_code)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sqlx::mysql::types::MySqlTime;
use sqlx::mysql::{MySql, MySqlRow, MySqlValueRef};
use sqlx::{Column, Decode, Row, TypeInfo, ValueRef};
use warden_core::dialect::Dialect;
use warden_core::result::{NormalizationError, ResultBuildError, ResultColumn, ResultValue};

/// What one MySQL column's declared type becomes in the core model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueKind {
    /// The column has no type at all, as in `SELECT NULL`.
    Null,
    /// `BOOLEAN`, which MySQL spells `TINYINT(1)`.
    Bool,
    /// A signed integer, or `YEAR`.
    Signed,
    /// An unsigned integer, or `BIT`.
    Unsigned,
    /// `FLOAT` or `DOUBLE`.
    Float,
    /// `DECIMAL`, preserved as text so no digit is lost.
    Decimal,
    /// Character data, including `ENUM` and `SET`.
    Text,
    /// Binary data, which leaves as base64.
    Bytes,
    /// `DATE`.
    Date,
    /// `TIME`, which is a signed duration rather than a time of day.
    Time,
    /// `DATETIME` or `TIMESTAMP`.
    DateTime,
    /// `JSON`.
    Json,
    /// Everything else, which fails safely with a cast example.
    Unsupported,
}

/// Maps a MySQL type name to the core representation.
///
/// The names are `sqlx_mysql`'s, not the ones in `information_schema`: they are what
/// `MySqlTypeInfo::name` returns, and they already fold `TINYINT(1)` into `BOOLEAN`
/// and append ` UNSIGNED` where the column flag says so.
pub(crate) fn kind_of(database_type: &str) -> ValueKind {
    match database_type {
        "NULL" => ValueKind::Null,
        "BOOLEAN" => ValueKind::Bool,
        "TINYINT" | "SMALLINT" | "MEDIUMINT" | "INT" | "BIGINT" | "YEAR" => ValueKind::Signed,
        "TINYINT UNSIGNED" | "SMALLINT UNSIGNED" | "MEDIUMINT UNSIGNED" | "INT UNSIGNED"
        | "BIGINT UNSIGNED" | "BIT" => ValueKind::Unsigned,
        "FLOAT" | "DOUBLE" => ValueKind::Float,
        "DECIMAL" => ValueKind::Decimal,
        "CHAR" | "VARCHAR" | "TINYTEXT" | "TEXT" | "MEDIUMTEXT" | "LONGTEXT" | "ENUM" | "SET" => {
            ValueKind::Text
        }
        "BINARY" | "VARBINARY" | "TINYBLOB" | "BLOB" | "MEDIUMBLOB" | "LONGBLOB" => {
            ValueKind::Bytes
        }
        "DATE" => ValueKind::Date,
        "TIME" => ValueKind::Time,
        "DATETIME" | "TIMESTAMP" => ValueKind::DateTime,
        "JSON" => ValueKind::Json,
        // `GEOMETRY` lands here deliberately: its wire form is WKB, which base64
        // would carry without making it readable. `ST_AsText(column)` is the answer,
        // and the cast example says so.
        _ => ValueKind::Unsupported,
    }
}

/// The column metadata for one row.
///
/// `nullable` is always `None`: the MySQL driver reports nullability through
/// `describe`, never through a row, and `docs/architecture.md` section 11 forbids
/// inventing a value the engine did not give.
pub(crate) fn columns(row: &MySqlRow) -> Vec<ResultColumn> {
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
    row: &MySqlRow,
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
/// 500 MB `BLOB` would otherwise be copied into a 666 MB base64 string purely to be
/// rejected. The builder remains the authority.
fn value(
    row: &MySqlRow,
    index: usize,
    column: &ResultColumn,
    max_value_bytes: usize,
) -> Result<ResultValue, ResultBuildError> {
    let raw = row.try_get_raw(index).map_err(|_| unsupported(column))?;
    if raw.is_null() {
        return Ok(ResultValue::Null);
    }

    let value = match kind_of(&column.database_type) {
        ValueKind::Null => ResultValue::Null,
        ValueKind::Bool => ResultValue::Bool(decode::<bool>(raw, column)?),
        ValueKind::Signed => ResultValue::I64(decode::<i64>(raw, column)?),
        ValueKind::Unsigned => ResultValue::U64(decode::<u64>(raw, column)?),
        ValueKind::Float => {
            let number = decode::<f64>(raw, column)?;
            if !number.is_finite() {
                return Err(NormalizationError::NonFiniteFloat {
                    column: column.name.clone(),
                }
                .into());
            }
            ResultValue::F64(number)
        }
        ValueKind::Decimal => {
            // MySQL sends DECIMAL as ASCII text in both protocols, so the server's
            // own digits survive without a BigDecimal round trip
            // (`docs/data-model.md` section 8.1, rule 1).
            ResultValue::Decimal(text(raw, column, max_value_bytes)?.to_owned())
        }
        ValueKind::Text => ResultValue::String(text(raw, column, max_value_bytes)?.to_owned()),
        ValueKind::Bytes => {
            let bytes = decode::<&[u8]>(raw, column)?;
            guard(base64_len(bytes.len()), column, max_value_bytes)?;
            ResultValue::BytesBase64(BASE64.encode(bytes))
        }
        ValueKind::Date => ResultValue::Date(format_date(decode::<time::Date>(raw, column)?)),
        ValueKind::Time => ResultValue::Time(format_time(&decode::<MySqlTime>(raw, column)?)),
        ValueKind::DateTime => ResultValue::DateTime(format_timestamp(decode::<
            time::PrimitiveDateTime,
        >(raw, column)?)),
        ValueKind::Json => {
            let document = text(raw, column, max_value_bytes)?;
            ResultValue::Json(serde_json::from_str(document).map_err(|_| unsupported(column))?)
        }
        ValueKind::Unsupported => return Err(unsupported(column).into()),
    };
    Ok(value)
}

/// Decodes one value, discarding the driver's message.
fn decode<'r, T: Decode<'r, MySql>>(
    raw: MySqlValueRef<'r>,
    column: &ResultColumn,
) -> Result<T, NormalizationError> {
    T::decode(raw).map_err(|_| unsupported(column))
}

/// Decodes text and refuses it before it is copied if it is already over budget.
fn text<'r>(
    raw: MySqlValueRef<'r>,
    column: &ResultColumn,
    max_value_bytes: usize,
) -> Result<&'r str, ResultBuildError> {
    let value = decode::<&str>(raw, column)?;
    guard(value.len(), column, max_value_bytes)?;
    Ok(value)
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

/// The one failure this module reports, carrying only the type name.
fn unsupported(column: &ResultColumn) -> NormalizationError {
    NormalizationError::UnsupportedType {
        column: column.name.clone(),
        dialect: Dialect::MySql,
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

/// `YYYY-MM-DD HH:MM:SS[.ffffff]`.
///
/// A `TIMESTAMP` arrives in the server session's time zone and is emitted exactly as
/// the server produced it, with no offset appended: inventing `Z` for a value whose
/// zone Warden does not pin would be worse than emitting none
/// (`docs/architecture.md` section 11).
fn format_timestamp(stamp: time::PrimitiveDateTime) -> String {
    let mut rendered = format!(
        "{} {:02}:{:02}:{:02}",
        format_date(stamp.date()),
        stamp.hour(),
        stamp.minute(),
        stamp.second()
    );
    let microseconds = stamp.microsecond();
    if microseconds != 0 {
        rendered.push_str(&format!(".{microseconds:06}"));
    }
    rendered
}

/// `[-]HH:MM:SS[.ffffff]`.
///
/// MySQL's `TIME` is a signed duration of up to 838 hours, not a time of day, so it
/// is neither an ISO-8601 time nor pretended to be one. `MySqlTime`'s own `Display`
/// is not used because it does not zero-pad the hours.
fn format_time(value: &MySqlTime) -> String {
    let mut rendered = String::new();
    // `MySqlTime::is_negative` is inverted in sqlx-mysql 0.9.0 — it returns
    // `self.sign.is_positive()` — so the sign is read through `sign()`, which is
    // correct.
    if value.sign().is_negative() {
        rendered.push('-');
    }
    rendered.push_str(&format!(
        "{:02}:{:02}:{:02}",
        value.hours(),
        value.minutes(),
        value.seconds()
    ));
    let microseconds = value.microseconds();
    if microseconds != 0 {
        rendered.push_str(&format!(".{microseconds:06}"));
    }
    rendered
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn every_documented_mysql_type_has_a_representation() {
        // `docs/data-model.md` section 8.2's MySQL list, by the names the driver
        // reports. A type missing here is a type that would reach an agent as an
        // unsupported-type error in production.
        let cases: &[(&str, ValueKind)] = &[
            ("NULL", ValueKind::Null),
            ("BOOLEAN", ValueKind::Bool),
            ("TINYINT", ValueKind::Signed),
            ("BIGINT", ValueKind::Signed),
            ("YEAR", ValueKind::Signed),
            ("BIGINT UNSIGNED", ValueKind::Unsigned),
            ("BIT", ValueKind::Unsigned),
            ("DOUBLE", ValueKind::Float),
            ("DECIMAL", ValueKind::Decimal),
            ("VARCHAR", ValueKind::Text),
            ("LONGTEXT", ValueKind::Text),
            ("ENUM", ValueKind::Text),
            ("SET", ValueKind::Text),
            ("VARBINARY", ValueKind::Bytes),
            ("LONGBLOB", ValueKind::Bytes),
            ("DATE", ValueKind::Date),
            ("TIME", ValueKind::Time),
            ("DATETIME", ValueKind::DateTime),
            ("TIMESTAMP", ValueKind::DateTime),
            ("JSON", ValueKind::Json),
        ];
        for (name, expected) in cases {
            assert_eq!(kind_of(name), *expected, "{name}");
        }
    }

    #[test]
    fn an_unnamed_type_is_denied_rather_than_guessed() {
        for name in ["GEOMETRY", "VECTOR", "", "varchar"] {
            assert_eq!(kind_of(name), ValueKind::Unsupported, "{name}");
        }
    }

    #[test]
    fn the_unsupported_error_names_the_type_and_a_mysql_cast() {
        let column = ResultColumn {
            name: "shape".to_owned(),
            database_type: "GEOMETRY".to_owned(),
            nullable: None,
        };
        let rendered = unsupported(&column).to_string();
        assert!(rendered.contains("GEOMETRY"), "{rendered}");
        assert!(rendered.contains("CAST(shape AS CHAR)"), "{rendered}");
        assert!(!rendered.contains("::text"), "{rendered}");
    }

    #[test]
    fn base64_length_is_an_upper_bound_on_the_encoder() {
        for raw in [0usize, 1, 2, 3, 4, 100, 65_536] {
            let encoded = BASE64.encode(vec![0u8; raw]);
            assert_eq!(base64_len(raw), encoded.len(), "{raw}");
        }
    }

    #[test]
    fn dates_and_times_use_mysqls_own_canonical_text() {
        let date = time::Date::from_calendar_date(2026, time::Month::January, 5).unwrap();
        assert_eq!(format_date(date), "2026-01-05");

        let stamp =
            time::PrimitiveDateTime::new(date, time::Time::from_hms_micro(9, 7, 3, 0).unwrap());
        assert_eq!(format_timestamp(stamp), "2026-01-05 09:07:03");

        let precise = time::PrimitiveDateTime::new(
            date,
            time::Time::from_hms_micro(9, 7, 3, 250_000).unwrap(),
        );
        assert_eq!(format_timestamp(precise), "2026-01-05 09:07:03.250000");
    }

    #[test]
    fn a_negative_and_an_over_long_time_both_survive() {
        let long =
            MySqlTime::new(sqlx::mysql::types::MySqlTimeSign::Positive, 838, 59, 59, 0).unwrap();
        assert_eq!(format_time(&long), "838:59:59");

        let negative = MySqlTime::new(
            sqlx::mysql::types::MySqlTimeSign::Negative,
            1,
            2,
            3,
            400_000,
        )
        .unwrap();
        assert_eq!(format_time(&negative), "-01:02:03.400000");
    }
}
