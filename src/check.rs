//! `warden check`: everything `warden serve` would do, minus serving.
//!
//! `docs/operations.md` section 11 gives this command four jobs — configuration, secret
//! references, connectivity, and server settings — and one prohibition: it **never
//! executes arbitrary user SQL**. It therefore takes no [`warden_ports::QueryPermit`]
//! and dispatches no query. The only statements it causes are the two fixed ones each
//! adapter already owns: the readiness probe `docs/operations.md` section 10.4 requires to
//! run on `control_pool`, and the session-setting read-back of section 5.1.
//!
//! ```text
//! load and resolve configuration   ← every static rule, from warden-config
//!     ↓ open every connection      ← the same eager connect `serve` performs
//!     ↓ health_check               ← control_pool, fixed statement, bounded
//!     ↓ verify_session_settings    ← detects a proxy that discarded startup options
//!     ↓ warn about production over stdio
//!     ↓ warn about a relaxed profile in production
//! ```
//!
//! # What a line may say
//!
//! Failures reach the report through `anyhow`'s [`Display`](std::fmt::Display) chain and
//! never through `Debug`. `ConnectError::Driver` keeps `sqlx`'s own text — which routinely
//! names a host and a database user — in a field only `Debug` reveals, so a `{:?}` here
//! would print a DSN's host into an operator's terminal and, worse, into whatever collects
//! it. `src/startup.rs`'s header states the rule; this module is its most exposed caller.
//!
//! # Warnings are not failures
//!
//! A production connection served over stdio is a deployment an operator may have chosen
//! deliberately (`docs/mcp.md` section 7). It is reported and the exit code stays 0.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use warden_config::{ResolvedConfig, ResolvedPolicy};
use warden_core::connection::{ConnectionName, Environment};
use warden_core::pool::POOL_ACQUIRE_TIMEOUT;

use crate::startup::{self, Deployment};

/// The bound on one probe.
///
/// A probe is at most two pooled acquisitions and two fixed statements —
/// `verify_session_settings` reads both pools back — so this is twice the pool's own
/// [`POOL_ACQUIRE_TIMEOUT`] plus a round trip's slack. A probe that cannot obtain a
/// connection within the pool's acquire timeout has already failed, and nothing here
/// waits indefinitely (`docs/architecture.md` section 13).
const PROBE_TIMEOUT: Duration = Duration::from_secs(2 * POOL_ACQUIRE_TIMEOUT.as_secs() + 2);

/// Runs every check, writing one line per step to `out`.
///
/// Returns `true` when every check passed and nothing was flagged, and `false` when the
/// checks passed but a warning was raised. `main` maps both to exit code 0, because a
/// warning describes a deployment choice rather than a broken one.
///
/// # Errors
///
/// Returns an operator-facing error when the configuration cannot be used, a connection
/// cannot be opened, or a probe fails. No message carries a DSN, a password, a host, or a
/// user.
pub(crate) async fn run(config: &Path, out: &mut dyn Write) -> Result<bool> {
    let resolved = warden_config::load_from_path(config)
        .with_context(|| format!("configuration {} could not be used", config.display()))?;
    writeln!(out, "ok    configuration {} is valid", config.display())?;

    // Collected before `build` consumes the configuration, reported after the probes so
    // the report reads in the order `docs/operations.md` section 11 lists the jobs.
    let warnings = startup_warnings(&resolved);

    let deployment = startup::build(resolved, CancellationToken::new()).await?;
    writeln!(
        out,
        "ok    {} connection(s) opened",
        deployment.pools().len()
    )?;

    // The probes run against a fully built deployment, so every pool this opened is
    // closed even when a probe fails or the report cannot be written. A connection that
    // refuses to open never reaches this point: `build` aborts, closing whatever it had
    // already opened, and the error propagates from the line above.
    let probed = probe(&deployment, out).await;
    deployment.close().await;
    let failures = probed?;

    for warning in &warnings {
        writeln!(out, "warn  {warning}")?;
    }

    anyhow::ensure!(
        failures == 0,
        "{failures} of this deployment's connection checks failed"
    );
    Ok(warnings.is_empty())
}

/// Probes every connection, reporting each result and returning how many failed.
///
/// One failing connection does not stop the others: this is a diagnostic, and an operator
/// fixing a deployment wants every broken connection named in one run rather than the
/// first one repeatedly.
///
/// # Errors
///
/// Returns an error only when the report itself cannot be written. A failing probe is a
/// counted line, not an early return.
async fn probe(deployment: &Deployment, out: &mut dyn Write) -> Result<usize> {
    let mut failures = 0;

    for pool in deployment.pools() {
        let name = pool.name();

        match pool.health_check(Instant::now() + PROBE_TIMEOUT).await {
            Ok(()) => writeln!(out, "ok    connection {name} answered a health check")?,
            Err(error) => {
                failures += 1;
                writeln!(out, "FAIL  {error:#}")?;
            }
        }

        match pool
            .verify_session_settings(Instant::now() + PROBE_TIMEOUT)
            .await
        {
            Ok(()) => writeln!(
                out,
                "ok    connection {name} kept the session settings it connected with"
            )?,
            Err(error) => {
                failures += 1;
                writeln!(out, "FAIL  {error:#}")?;
            }
        }
    }

    Ok(failures)
}

/// Every warning a deployment raises before it serves anything.
///
/// `serve` writes these to stderr at startup and `check` writes them into its report, so
/// both commands say the same sentences about the same deployment. It is one function
/// rather than one call each because the two commands drifted apart once already: `serve`
/// emitted the stdio exposure warnings and not the relaxation ones, so the process that
/// actually hands an agent a production database stayed quiet about the pair
/// `docs/operations.md` section 3.1 exists to flag. A caller that can only ask for *all*
/// of them cannot reintroduce that gap.
pub(crate) fn startup_warnings(config: &ResolvedConfig) -> Vec<String> {
    let production = production_connections(config);
    let mut warnings: Vec<String> = production.iter().map(exposure_warning).collect();
    warnings.extend(relaxation_warnings(&production, &config.policy));
    warnings
}

/// The connections whose `environment` is `production`, in configuration order.
fn production_connections(config: &ResolvedConfig) -> Vec<ConnectionName> {
    config
        .connections
        .iter()
        .filter(|connection| connection.metadata.environment == Environment::Production)
        .map(|connection| connection.metadata.name.clone())
        .collect()
}

/// What `docs/mcp.md` section 7 says about a production connection reached over stdio.
fn exposure_warning(name: &ConnectionName) -> String {
    format!(
        "connection {name} is a production connection served over stdio: a local agent \
         with shell access can read the environment and the files its own process can \
         read, so stdio alone does not protect a production DSN (docs/mcp.md section 7)"
    )
}

/// What a relaxed profile adds to that exposure (`docs/operations.md` section 3.1).
///
/// The profile is process-wide (ADR-0039), so a relaxation is reported once and names the
/// production connections it reaches rather than repeating itself per connection.
fn relaxation_warnings(production: &[ConnectionName], policy: &ResolvedPolicy) -> Vec<String> {
    if production.is_empty() {
        return Vec::new();
    }

    let names = production
        .iter()
        .map(ConnectionName::to_string)
        .collect::<Vec<_>>()
        .join(", ");

    [
        (policy.allow_locking_reads, "allow_locking_reads"),
        (policy.allow_unknown_functions, "allow_unknown_functions"),
    ]
    .into_iter()
    .filter(|(relaxed, _)| *relaxed)
    .map(|(_, rule)| {
        format!(
            "the policy profile sets {rule} while serving production connection(s) \
             {names} (docs/operations.md section 3.1)"
        )
    })
    .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn name(text: &str) -> ConnectionName {
        ConnectionName::try_from(text.to_owned()).unwrap()
    }

    fn hardened() -> ResolvedPolicy {
        ResolvedPolicy {
            allow_locking_reads: false,
            allow_unknown_functions: false,
            schemas: None,
            allow_tables: None,
            deny_tables: Vec::new(),
        }
    }

    #[tokio::test]
    async fn an_unreadable_configuration_fails_before_any_connection_is_opened() {
        let mut report = Vec::new();
        let error = run(Path::new("/nonexistent/warden.toml"), &mut report)
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("/nonexistent/warden.toml"));
        assert!(report.is_empty(), "{report:?}");
    }

    #[test]
    fn the_stdio_warning_names_the_connection_and_the_document_that_explains_it() {
        let warning = exposure_warning(&name("orders"));
        assert!(warning.contains("orders"), "{warning}");
        assert!(warning.contains("docs/mcp.md section 7"), "{warning}");
    }

    #[test]
    fn a_hardened_profile_raises_no_relaxation_warning() {
        assert!(relaxation_warnings(&[name("orders")], &hardened()).is_empty());
    }

    #[test]
    fn each_relaxation_is_reported_once_and_names_every_production_connection() {
        let warnings = relaxation_warnings(
            &[name("orders"), name("billing")],
            &ResolvedPolicy {
                allow_locking_reads: true,
                allow_unknown_functions: true,
                ..hardened()
            },
        );

        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].contains("allow_locking_reads"), "{warnings:?}");
        assert!(
            warnings[1].contains("allow_unknown_functions"),
            "{warnings:?}"
        );
        for warning in &warnings {
            assert!(warning.contains("orders"), "{warning}");
            assert!(warning.contains("billing"), "{warning}");
        }
    }

    #[test]
    fn a_relaxation_outside_production_is_not_warned_about() {
        // The relaxation is a deliberate development convenience until a production
        // connection is served under it; warning about every development profile would
        // train an operator to ignore the line that matters.
        let warnings = relaxation_warnings(
            &[],
            &ResolvedPolicy {
                allow_locking_reads: true,
                ..hardened()
            },
        );
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn one_probe_can_never_outlast_the_pool_it_borrows_from() {
        // `docs/architecture.md` section 13: nothing waits indefinitely. A probe budget
        // below the pool's own acquire timeout would report a healthy database as failed.
        assert!(PROBE_TIMEOUT > POOL_ACQUIRE_TIMEOUT);
    }
}
