//! Durations as an operator writes them.
//!
//! `toml` deserializes an integer into `Duration` as seconds and a table into its parts;
//! neither is what `docs/operations.md` section 3's `"5s"` means. This newtype accepts
//! exactly `<positive integer><ms|s|m>` and rejects everything else, so a typo is a startup
//! error naming the value rather than a silently different deadline.
//!
//! It is a validated newtype and follows the rule for one (`AGENTS.md`): `TryFrom<String>`,
//! `FromStr`, `Display`, `AsRef` where meaningful, never `Deref`, and deserialization
//! through `try_from`.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use crate::error::ConfigError;

/// A duration written as `250ms`, `5s`, or `2m`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(try_from = "String")]
pub struct HumanDuration(Duration);

impl HumanDuration {
    /// Borrows the validated duration.
    #[must_use]
    pub fn get(&self) -> Duration {
        self.0
    }

    /// Wraps an already-valid duration, for `model.rs`'s defaults that mirror a
    /// `warden-core` constant rather than operator-written text. Infallible because those
    /// constants are never negative or unparsable; the validation this newtype exists for
    /// applies only to text an operator wrote.
    pub(crate) const fn from_duration(duration: Duration) -> Self {
        Self(duration)
    }
}

impl TryFrom<String> for HumanDuration {
    type Error = ConfigError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let malformed = || ConfigError::MalformedDuration {
            value: value.clone(),
        };
        let split = value
            .find(|character: char| !character.is_ascii_digit())
            .ok_or_else(malformed)?;
        let (digits, unit) = value.split_at(split);
        let amount: u64 = digits.parse().map_err(|_| malformed())?;
        let millis = match unit {
            "ms" => Some(amount),
            "s" => amount.checked_mul(1_000),
            "m" => amount.checked_mul(60_000),
            _ => return Err(malformed()),
        }
        .ok_or_else(malformed)?;
        Ok(Self(Duration::from_millis(millis)))
    }
}

impl FromStr for HumanDuration {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_owned())
    }
}

impl fmt::Display for HumanDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}ms", self.0.as_millis())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn every_documented_spelling_parses() {
        for (text, expected) in [
            ("5s", Duration::from_secs(5)),
            ("250ms", Duration::from_millis(250)),
            ("2m", Duration::from_secs(120)),
        ] {
            assert_eq!(text.parse::<HumanDuration>().unwrap().get(), expected);
        }
    }

    #[test]
    fn a_bare_number_or_an_unknown_unit_is_refused() {
        for text in ["5", "5 s", "5sec", "s", "", "-5s", "9999999999999999999s"] {
            assert!(
                text.parse::<HumanDuration>().is_err(),
                "{text:?} was accepted"
            );
        }
    }

    #[test]
    fn a_duration_round_trips_through_toml() {
        #[derive(serde::Deserialize)]
        struct Wrapper {
            value: HumanDuration,
        }
        let parsed: Wrapper = toml::from_str("value = \"3s\"").unwrap();
        assert_eq!(parsed.value.get(), Duration::from_secs(3));
        assert!(toml::from_str::<Wrapper>("value = 3").is_err());
    }
}
