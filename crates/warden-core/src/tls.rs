//! What a database connection must prove before Warden sends credentials.
//!
//! # Why there is no `Preferred`
//!
//! `MySqlSslMode` defaults to `Preferred` and `PgSslMode` defaults to `Prefer`. Both
//! attempt TLS and **fall back to cleartext** when the server declines, which is the
//! failure nobody notices: the connection works, the dashboard is green, and the
//! password crossed the network in the open. [`TlsMode`] offers no such variant, and
//! the adapters always call the driver's `ssl_mode` explicitly, so the driver default
//! is never the value in effect.
//!
//! [`TlsMode::Disabled`] exists because Testcontainers' PostgreSQL image serves no
//! TLS and local development against a loopback socket does not need it. It is not a
//! bypass flag under SPEC section 9: [`TlsSettings::validate`] refuses it for every
//! environment except [`Environment::Development`], and no configuration key relaxes
//! that. [`TlsMode::Required`] likewise encrypts without authenticating the server,
//! so it is legal only in development; every other environment must verify the
//! certificate chain (ADR-0030).

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use crate::connection::Environment;

/// The value did not name a supported TLS mode.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "unsupported TLS mode {value:?}; expected \"disabled\", \"required\", \
     \"verify-ca\", or \"verify-identity\""
)]
pub struct TlsModeError {
    /// The rejected value. This is a configuration keyword, never a secret.
    pub value: String,
}

/// A TLS configuration a connection may not use.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TlsError {
    /// Cleartext was requested outside development.
    #[error("connections in the {environment} environment must use TLS")]
    CleartextOutsideDevelopment {
        /// The environment that rejected it.
        environment: Environment,
    },
    /// TLS without certificate verification was requested outside development.
    #[error("connections in the {environment} environment must verify TLS certificates")]
    CertificateVerificationRequired {
        /// The environment that rejected the mode.
        environment: Environment,
    },
    /// A root certificate was configured for a connection that will not use TLS.
    ///
    /// Always an operator mistake, and the kind that reads as hardened: the
    /// certificate is present, the mode is not.
    #[error("a root certificate is configured but TLS is disabled")]
    RootCertificateWithoutTls,
}

/// How much the driver must prove before it sends credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum TlsMode {
    /// No TLS. Legal only in [`Environment::Development`].
    Disabled,
    /// TLS is mandatory without certificate verification. Legal only in development.
    Required,
    /// TLS is mandatory and the chain must reach a trusted authority.
    VerifyCa,
    /// TLS is mandatory, the chain must verify, and the hostname must match.
    VerifyIdentity,
}

impl TryFrom<String> for TlsMode {
    type Error = TlsModeError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "disabled" => Ok(Self::Disabled),
            "required" => Ok(Self::Required),
            "verify-ca" => Ok(Self::VerifyCa),
            "verify-identity" => Ok(Self::VerifyIdentity),
            _ => Err(TlsModeError { value }),
        }
    }
}

impl FromStr for TlsMode {
    type Err = TlsModeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_owned())
    }
}

impl From<TlsMode> for String {
    fn from(value: TlsMode) -> Self {
        value.to_string()
    }
}

impl fmt::Display for TlsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl AsRef<str> for TlsMode {
    fn as_ref(&self) -> &str {
        match self {
            Self::Disabled => "disabled",
            Self::Required => "required",
            Self::VerifyCa => "verify-ca",
            Self::VerifyIdentity => "verify-identity",
        }
    }
}

/// One connection's transport security.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSettings {
    /// What the driver must prove.
    pub mode: TlsMode,
    /// A private certificate authority, for deployments whose server certificate
    /// does not chain to a public root (`docs/operations.md` section 8).
    ///
    /// `None` means the embedded Mozilla root store, which is what
    /// `tls-rustls-ring-webpki` provides and what a distroless image needs.
    pub root_certificate: Option<PathBuf>,
}

impl Default for TlsSettings {
    /// Authenticated TLS with no private authority — the setting a production
    /// deployment wants and the one an operator gets by not choosing.
    fn default() -> Self {
        Self {
            mode: TlsMode::VerifyIdentity,
            root_certificate: None,
        }
    }
}

impl TlsSettings {
    /// Rejects a configuration this environment may not use.
    pub fn validate(&self, environment: &Environment) -> Result<(), TlsError> {
        match self.mode {
            TlsMode::Disabled => {
                if self.root_certificate.is_some() {
                    return Err(TlsError::RootCertificateWithoutTls);
                }
                // Default deny: only the one environment that is definitionally local may
                // run in cleartext. `Other("canary")` is not development.
                if matches!(environment, Environment::Development) {
                    Ok(())
                } else {
                    Err(TlsError::CleartextOutsideDevelopment {
                        environment: environment.clone(),
                    })
                }
            }
            // `Required` encrypts without authenticating the peer, which is useful for
            // local test containers but violates operations section 8 elsewhere.
            TlsMode::Required if !matches!(environment, Environment::Development) => {
                Err(TlsError::CertificateVerificationRequired {
                    environment: environment.clone(),
                })
            }
            TlsMode::Required | TlsMode::VerifyCa | TlsMode::VerifyIdentity => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn the_default_is_tls() {
        assert_eq!(TlsSettings::default().mode, TlsMode::VerifyIdentity);
        assert!(TlsSettings::default().root_certificate.is_none());
    }

    #[test]
    fn cleartext_is_confined_to_development() {
        let cleartext = TlsSettings {
            mode: TlsMode::Disabled,
            root_certificate: None,
        };
        cleartext.validate(&Environment::Development).unwrap();

        for environment in [
            Environment::Staging,
            Environment::Production,
            Environment::Other("canary".to_owned()),
        ] {
            assert_eq!(
                cleartext.validate(&environment),
                Err(TlsError::CleartextOutsideDevelopment {
                    environment: environment.clone()
                }),
                "{environment} accepted cleartext"
            );
        }
    }

    #[test]
    fn a_root_certificate_without_tls_is_a_contradiction() {
        let contradictory = TlsSettings {
            mode: TlsMode::Disabled,
            root_certificate: Some(PathBuf::from("/run/secrets/ca.pem")),
        };
        // Rejected even in development: the shape reads as hardened and is not.
        assert_eq!(
            contradictory.validate(&Environment::Development),
            Err(TlsError::RootCertificateWithoutTls)
        );
    }

    #[test]
    fn every_verifying_mode_is_accepted_everywhere() {
        for mode in [TlsMode::VerifyCa, TlsMode::VerifyIdentity] {
            let settings = TlsSettings {
                mode,
                root_certificate: Some(PathBuf::from("/run/secrets/ca.pem")),
            };
            settings.validate(&Environment::Production).unwrap();
        }
    }

    #[test]
    fn non_verifying_tls_is_confined_to_development() {
        let required = TlsSettings {
            mode: TlsMode::Required,
            root_certificate: None,
        };
        required.validate(&Environment::Development).unwrap();

        for environment in [
            Environment::Staging,
            Environment::Production,
            Environment::Other("canary".to_owned()),
        ] {
            assert_eq!(
                required.validate(&environment),
                Err(TlsError::CertificateVerificationRequired {
                    environment: environment.clone(),
                }),
                "{environment} accepted TLS without certificate verification"
            );
        }
    }

    #[test]
    fn the_mode_round_trips_through_its_configuration_spelling() {
        for mode in [
            TlsMode::Disabled,
            TlsMode::Required,
            TlsMode::VerifyCa,
            TlsMode::VerifyIdentity,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            assert_eq!(serde_json::from_str::<TlsMode>(&json).unwrap(), mode);
            assert_eq!(mode.as_ref().parse::<TlsMode>().unwrap(), mode);
        }
        // There is no spelling for a preferring mode, in configuration or in code.
        assert!("preferred".parse::<TlsMode>().is_err());
        assert!("prefer".parse::<TlsMode>().is_err());
    }
}
