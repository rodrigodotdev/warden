//! Per-request identity.
//!
//! `PolicyEngine::authorize` takes a `&RequestContext`
//! (`docs/architecture.md` section 4.1), and every audit record carries the same
//! three identifiers (`docs/security.md` section 11.2). They are newtypes rather
//! than `String` so that swapping two of them in an audit event does not compile.

use std::fmt;
use std::str::FromStr;

use crate::identifier::{IdentifierError, validate_display, validate_identifier};

/// Longest accepted request identifier.
pub const MAX_REQUEST_ID_LEN: usize = 64;

/// Longest accepted principal identifier.
pub const MAX_PRINCIPAL_ID_LEN: usize = 128;

/// Longest accepted client name.
pub const MAX_CLIENT_NAME_LEN: usize = 64;

macro_rules! string_newtype {
    (
        $(#[$meta:meta])*
        $name:ident, $field:literal, $max:expr, $validate:path
    ) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize,
            serde::Deserialize,
        )]
        #[serde(try_from = "String")]
        pub struct $name(String);

        impl $name {
            /// Borrows the validated value.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdentifierError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                $validate($field, &value, $max)?;
                Ok(Self(value))
            }
        }

        impl FromStr for $name {
            type Err = IdentifierError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::try_from(value.to_owned())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

string_newtype!(
    /// Correlates every span, audit record, and error for one tool call.
    ///
    /// Warden generates this value, so it uses the strict identifier charset.
    RequestId,
    "request id",
    MAX_REQUEST_ID_LEN,
    validate_identifier
);

string_newtype!(
    /// Identifies the authenticated caller.
    ///
    /// Supplied by the transport, so it accepts printable ASCII: real subjects
    /// contain `@`, `|`, and `:`.
    PrincipalId,
    "principal id",
    MAX_PRINCIPAL_ID_LEN,
    validate_display
);

string_newtype!(
    /// The MCP client's self-reported name, recorded for auditing.
    ///
    /// This value is untrusted. Printable ASCII only, so it cannot inject a line
    /// break into stderr logs.
    ClientName,
    "client name",
    MAX_CLIENT_NAME_LEN,
    validate_display
);

/// Who is asking, and under which request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
    request_id: RequestId,
    principal: PrincipalId,
    client: ClientName,
}

impl RequestContext {
    /// Builds a context. Named types make the argument order unswappable.
    #[must_use]
    pub fn new(request_id: RequestId, principal: PrincipalId, client: ClientName) -> Self {
        Self {
            request_id,
            principal,
            client,
        }
    }

    /// The correlation identifier for this call.
    #[must_use]
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// The authenticated caller.
    #[must_use]
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// The client that opened the session.
    #[must_use]
    pub fn client(&self) -> &ClientName {
        &self.client
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn request_ids_use_the_strict_charset() {
        assert!("01J8Z3-abcdef".parse::<RequestId>().is_ok());
        assert!("has space".parse::<RequestId>().is_err());
    }

    #[test]
    fn principals_and_clients_accept_real_world_values() {
        assert!(
            "auth0|507f1f77bcf86cd799439011"
                .parse::<PrincipalId>()
                .is_ok()
        );
        assert!("alice@example.com".parse::<PrincipalId>().is_ok());
        assert!("Claude Code 2.0".parse::<ClientName>().is_ok());
    }

    #[test]
    fn untrusted_names_cannot_inject_log_lines() {
        let error = "warden\nERROR fake entry"
            .parse::<ClientName>()
            .unwrap_err();
        assert!(
            error.to_string().contains("unsupported character"),
            "{error}"
        );
    }

    #[test]
    fn context_exposes_read_only_accessors() {
        let context = RequestContext::new(
            "req-1".parse().unwrap(),
            "alice@example.com".parse().unwrap(),
            "Claude Code".parse().unwrap(),
        );
        assert_eq!(context.request_id().as_str(), "req-1");
        assert_eq!(context.principal().as_str(), "alice@example.com");
        assert_eq!(context.client().as_str(), "Claude Code");
    }
}
