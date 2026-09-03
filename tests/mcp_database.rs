//! Warden's own binary, over stdio, against real MySQL and PostgreSQL.
//!
//! `docs/testing.md` section 6 asks for exactly this: start Warden over stdio and test
//! initialization, tool discovery, all five tools, denied queries, sanitized errors,
//! protocol-only stdout, and the agent workflow that motivates the product. What
//! `crates/warden-mcp/tests/protocol.rs` proves about the protocol with fake ports, this
//! proves about the whole program with real drivers, real roles, and real catalogs.
//!
//! Connections declare `environment = "development"` because a container speaks cleartext
//! and ADR-0030 permits that in development only. Testing against a production profile
//! would mean provisioning TLS for the container, which proves nothing this suite is for;
//! `crates/warden-mysql`'s own tests already cover a validated handshake.
//!
//! # Two barriers, both measured here
//!
//! `AGENTS.md` requires an integration test to prove that the **database role** refuses a
//! write, not only that policy does. Every fixture below therefore provisions the same
//! least-privileged role `crates/warden-mysql/src/container_tests/privileges.rs` and its
//! PostgreSQL counterpart use, and hands Warden that role's DSN.
//! [`a_write_is_denied_before_the_database_is_asked`] measures the upper barrier through
//! the MCP wire; [`the_database_role_refuses_the_same_write_with_warden_removed`] sends
//! the identical statements to the same server as the same role with every Warden layer
//! taken away. Either test can fail without the other, which is what makes them two
//! barriers rather than one assertion written twice.

#![cfg(feature = "docker")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::{ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use sqlx::mysql::MySqlDatabaseError;
use sqlx::{AssertSqlSafe, MySqlPool, PgPool};
use testcontainers_modules::mysql::Mysql;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

// ---------------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------------

/// The one connection name every configuration below declares.
const NAME: &str = "orders-db";

/// The least-privileged account Warden connects as, matching the adapters' own
/// privilege fixtures.
const ROLE: &str = "warden_ro";

/// Its password. A container-local literal; no production value is involved. It is also
/// the string the assertions search the wire for: a DSN password must never cross.
const ROLE_PASSWORD: &str = "warden-ro-password";

/// A password the role does not have, for the startup-failure test.
const WRONG_PASSWORD: &str = "not-the-password";

/// The environment variable each configuration names as its DSN source.
const DSN_VARIABLE: &str = "WARDEN_E2E_DSN";

/// The newest protocol version Warden implements (ADR-0041).
const PROTOCOL_VERSION: &str = "2026-07-28";

/// `docs/testing.md` section 4 requires MySQL 8.4; the module defaults to 8.1.
const MYSQL_TAG: &str = "8.4";

/// The module defaults to an end-of-life release; testing needs a supported one.
const PG_TAG: &str = "17-alpine";

/// The value in the seeded `password` column, distinctive enough that finding it
/// anywhere on the wire is proof the redaction rule did not run.
const SECRET: &str = "hunter2";

/// The bound on one child process, from spawn to exit.
///
/// Generous because it covers opening both pools against a cold container, not because
/// anything here may wait: `tokio::time::timeout` turns a hang into a failure, and a test
/// that can hang blocks CI forever rather than failing it.
const PROCESS_TIMEOUT: Duration = Duration::from_secs(60);

/// The log filter every child runs with.
///
/// Set rather than inherited, exactly as `tests/cli.rs` does: `RUST_LOG` from a
/// developer's shell would decide whether the stderr assertions hold. `warden` is a
/// prefix, so it covers the crate targets and the dotted ones alike and nothing else —
/// `sqlx::query` stays off, which is what keeps SQL out of this process's stderr.
const LOG_FILTER: &str = "warden=debug";

// ---------------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------------

/// Which engine one fixture runs against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Engine {
    /// MySQL 8.4, reached over TLS without certificate verification.
    MySql,
    /// PostgreSQL 17, reached in cleartext because the image serves no TLS.
    PostgreSql,
}

impl Engine {
    /// The dialect spelling `warden-mcp` puts on the wire.
    fn dialect_name(self) -> &'static str {
        match self {
            Self::MySql => "mysql",
            Self::PostgreSql => "postgresql",
        }
    }
}

/// The running container, held for the fixture's lifetime so the server stays up.
///
/// Nothing reads the payload — dropping it is the whole contract, and the leading
/// underscore says so to the dead-code lint rather than to a reader alone.
#[derive(Debug)]
enum Server {
    /// A MySQL container.
    MySql {
        /// Held until the fixture is dropped.
        _container: ContainerAsync<Mysql>,
    },
    /// A PostgreSQL container.
    PostgreSql {
        /// Held until the fixture is dropped.
        _container: ContainerAsync<Postgres>,
    },
}

/// A configuration file removed on both the success and the panic path.
#[derive(Debug)]
struct TemporaryConfig {
    /// Where it was written.
    path: PathBuf,
}

impl TemporaryConfig {
    /// Writes one configuration to a path unique to this process and test.
    fn write(contents: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);

        let path = std::env::temp_dir().join(format!(
            "warden-e2e-{}-{}.toml",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).expect("failed to write the temporary configuration");
        Self { path }
    }
}

impl Drop for TemporaryConfig {
    fn drop(&mut self) {
        // Drop runs during unwinding too, so a failing assertion leaves nothing behind.
        let _ignored = std::fs::remove_file(&self.path);
    }
}

/// One container, one provisioned fixture, one configuration file, one role DSN.
#[derive(Debug)]
struct Fixture {
    /// Which engine this fixture speaks.
    engine: Engine,
    /// The container. Dropping it stops the server, so the fixture owns it.
    _server: Server,
    /// The configuration `warden serve` and `warden check` read.
    config: TemporaryConfig,
    /// The DSN, handed to the child through the environment and never on its argv.
    dsn: String,
    /// The host the container is reachable at, for the leak assertions.
    host: String,
    /// The mapped port, for the leak assertions.
    port: u16,
}

impl Fixture {
    /// Starts a container, seeds it, creates the least-privileged role, and writes the
    /// configuration that points Warden at that role.
    async fn start(engine: Engine) -> Self {
        match engine {
            Engine::MySql => Self::start_mysql().await,
            Engine::PostgreSql => Self::start_postgres().await,
        }
    }

    /// MySQL 8.4, seeded as root and then handed over to `warden_ro`.
    async fn start_mysql() -> Self {
        let container = Mysql::default()
            .with_tag(MYSQL_TAG)
            .start()
            .await
            .expect("failed to start the MySQL container");
        let host = container.get_host().await.unwrap().to_string();
        let port = container.get_host_port_ipv4(3306).await.unwrap();

        let admin = MySqlPool::connect(&format!("mysql://root@{host}:{port}/test"))
            .await
            .expect("failed to connect to the MySQL container as root");
        for statement in [
            "CREATE TABLE orders (id BIGINT PRIMARY KEY, status VARCHAR(32) NOT NULL, \
             password VARCHAR(64) NOT NULL)"
                .to_owned(),
            // `SECRET` is interpolated rather than written twice: a constant the seed did
            // not actually store would turn every `!contains(SECRET)` assertion in this
            // file into a guard on a string no database ever held.
            format!(
                "INSERT INTO orders (id, status, password) VALUES \
                 (1, 'shipped', '{SECRET}'), (2, 'pending', '{SECRET}'), \
                 (3, 'shipped', '{SECRET}')"
            ),
        ] {
            sqlx::query(AssertSqlSafe(statement))
                .execute(&admin)
                .await
                .unwrap();
        }
        // The grant is the shape `docs/security.md` section 4 recommends: `SELECT` on the
        // one table the agent needs and nothing else — no write privilege at all.
        for statement in [
            format!("CREATE USER '{ROLE}'@'%' IDENTIFIED BY '{ROLE_PASSWORD}'"),
            format!("GRANT SELECT ON test.orders TO '{ROLE}'@'%'"),
        ] {
            sqlx::query(AssertSqlSafe(statement))
                .execute(&admin)
                .await
                .unwrap();
        }
        admin.close().await;

        let dsn = format!("mysql://{ROLE}:{ROLE_PASSWORD}@{host}:{port}/test");
        let config = TemporaryConfig::write(&format!(
            "version = 1\n\
             \n\
             [[connections]]\n\
             name = \"{NAME}\"\n\
             dialect = \"mysql\"\n\
             environment = \"development\"\n\
             database = \"test\"\n\
             dsn_env = \"{DSN_VARIABLE}\"\n\
             policy = \"e2e\"\n\
             tls = {{ mode = \"required\" }}\n\
             \n\
             [policies.e2e]\n\
             \n\
             [redaction]\n\
             columns = [\"*.password\"]\n"
        ));

        Self {
            engine: Engine::MySql,
            _server: Server::MySql {
                _container: container,
            },
            config,
            dsn,
            host,
            port,
        }
    }

    /// PostgreSQL 17, seeded as the superuser and then handed over to `warden_ro`.
    async fn start_postgres() -> Self {
        let container = Postgres::default()
            .with_tag(PG_TAG)
            .start()
            .await
            .expect("failed to start the PostgreSQL container");
        let host = container.get_host().await.unwrap().to_string();
        let port = container.get_host_port_ipv4(5432).await.unwrap();

        let admin = PgPool::connect(&format!(
            "postgres://postgres:postgres@{host}:{port}/postgres"
        ))
        .await
        .expect("failed to connect to the PostgreSQL container as the superuser");
        for statement in [
            "CREATE TABLE orders (id bigint PRIMARY KEY, status text NOT NULL, \
             password text NOT NULL)"
                .to_owned(),
            // Interpolated for the reason the MySQL seed above gives.
            format!(
                "INSERT INTO orders (id, status, password) VALUES \
                 (1, 'shipped', '{SECRET}'), (2, 'pending', '{SECRET}'), \
                 (3, 'shipped', '{SECRET}')"
            ),
        ] {
            sqlx::query(AssertSqlSafe(statement))
                .execute(&admin)
                .await
                .unwrap();
        }
        // The grant is the shape `docs/security.md` section 4.2 recommends: `CONNECT` on
        // the database, `USAGE` on the schema, `SELECT` on the one approved table, and no
        // table write, no schema `CREATE`, and no sequence privilege.
        for statement in [
            format!(
                "CREATE ROLE {ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE \
                 NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD '{ROLE_PASSWORD}'"
            ),
            format!("GRANT CONNECT ON DATABASE postgres TO {ROLE}"),
            format!("GRANT USAGE ON SCHEMA public TO {ROLE}"),
            format!("GRANT SELECT ON orders TO {ROLE}"),
        ] {
            sqlx::query(AssertSqlSafe(statement))
                .execute(&admin)
                .await
                .unwrap();
        }
        admin.close().await;

        let dsn = format!("postgres://{ROLE}:{ROLE_PASSWORD}@{host}:{port}/postgres");
        let config = TemporaryConfig::write(&format!(
            "version = 1\n\
             \n\
             [[connections]]\n\
             name = \"{NAME}\"\n\
             dialect = \"postgresql\"\n\
             environment = \"development\"\n\
             database = \"postgres\"\n\
             dsn_env = \"{DSN_VARIABLE}\"\n\
             policy = \"e2e\"\n\
             search_path = [\"public\"]\n\
             tls = {{ mode = \"disabled\" }}\n\
             \n\
             [policies.e2e]\n\
             \n\
             [redaction]\n\
             columns = [\"*.password\"]\n"
        ));

        Self {
            engine: Engine::PostgreSql,
            _server: Server::PostgreSql {
                _container: container,
            },
            config,
            dsn,
            host,
            port,
        }
    }

    /// The seeded relation, qualified the way this engine names it.
    fn table(&self) -> &'static str {
        match self.engine {
            Engine::MySql => "test.orders",
            Engine::PostgreSql => "public.orders",
        }
    }

    /// A bound `SELECT` in this connection's own placeholder syntax.
    fn select_with_placeholder(&self) -> &'static str {
        match self.engine {
            Engine::MySql => "SELECT id, status FROM orders WHERE status = ? ORDER BY id",
            Engine::PostgreSql => "SELECT id, status FROM orders WHERE status = $1 ORDER BY id",
        }
    }

    /// The same statement without a placeholder, for `explain`.
    fn select(&self) -> &'static str {
        "SELECT id, status FROM orders ORDER BY id"
    }

    /// Spawns `warden serve --transport stdio`, writes every request, and collects the
    /// process's output after stdin closes.
    ///
    /// The DSN goes to the child through [`Command::env`] and never onto its command
    /// line, because `/proc/<pid>/cmdline` is world-readable and this test is also the
    /// documentation of how to pass one.
    async fn run_to_completion(&self, requests: &[Value]) -> (String, String, ExitStatus) {
        let mut child = self
            .command(["serve", "--transport", "stdio"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Reap the process if the timeout below drops the consuming future.
            .kill_on_drop(true)
            .spawn()
            .expect("failed to start warden serve");

        let mut stdin = child.stdin.take().expect("stdin unavailable");
        for request in requests {
            let line = format!("{}\n", serde_json::to_string(request).unwrap());
            stdin.write_all(line.as_bytes()).await.unwrap();
        }
        stdin.flush().await.unwrap();
        drop(stdin); // The server exits on EOF.

        let output = tokio::time::timeout(PROCESS_TIMEOUT, child.wait_with_output())
            .await
            .expect("warden did not exit within the process timeout after stdin EOF")
            .expect("failed to collect warden's output");

        (
            String::from_utf8(output.stdout).expect("stdout is not UTF-8"),
            String::from_utf8_lossy(&output.stderr).into_owned(),
            output.status,
        )
    }

    /// Sends one exchange and returns the response to each request that expects one, in
    /// request order.
    ///
    /// Responses are correlated by JSON-RPC id rather than by position, so a server that
    /// answered out of order would still be read correctly — and one that dropped an
    /// answer fails here instead of shifting every later assertion onto the wrong reply.
    async fn exchange(&self, requests: &[Value]) -> Vec<Value> {
        let prepared = with_ids(requests);
        let (stdout, stderr, status) = self.run_to_completion(&prepared).await;
        assert!(
            status.success(),
            "warden exited with {status:?}; stderr={stderr}"
        );

        let messages = parse_protocol(&stdout);
        prepared
            .iter()
            .filter_map(|request| request.get("id"))
            .map(|id| {
                messages
                    .iter()
                    .find(|message| message.get("id") == Some(id))
                    .unwrap_or_else(|| {
                        panic!("no response for id {id}; stdout={stdout:?} stderr={stderr:?}")
                    })
                    .clone()
            })
            .collect()
    }

    /// Initializes, then calls `query` once, and returns that call's response.
    async fn call_query(&self, sql: &str) -> Value {
        let responses = self
            .exchange(&[
                initialize(),
                initialized(),
                call("query", json!({ "connection": NAME, "sql": sql })),
            ])
            .await;
        responses
            .last()
            .expect("the exchange produced no response")
            .clone()
    }

    /// Runs `warden check` against this fixture's configuration.
    async fn run_check(&self) -> Output {
        self.run(&["check"]).await
    }

    /// Runs one subcommand to completion with no stdin, and returns its output.
    ///
    /// `Command::output` supplies a null stdin, which is what a startup-failure test
    /// needs: a process that dies while resolving its configuration never reads the
    /// descriptor, and writing to it would race a broken pipe against the assertion.
    async fn run(&self, arguments: &[&str]) -> Output {
        let mut command = self.command(arguments.iter().copied());
        tokio::time::timeout(PROCESS_TIMEOUT, command.kill_on_drop(true).output())
            .await
            .unwrap_or_else(|_elapsed| {
                panic!("warden {arguments:?} did not finish within the process timeout")
            })
            .expect("failed to execute warden")
    }

    /// The same fixture with a DSN whose password is wrong.
    ///
    /// Only the DSN changes: the configuration file names an environment variable, so
    /// nothing about the deployment differs except the secret behind it.
    fn with_wrong_password(mut self) -> Self {
        self.dsn = self.dsn.replace(ROLE_PASSWORD, WRONG_PASSWORD);
        self
    }

    /// Every string a leaked DSN would put on the wire or in a diagnostic.
    ///
    /// Shared by the two tests that search for them so neither can drift from the other.
    /// Which of them are *live* depends on the failure being provoked, and each caller
    /// says which: only a connection-time failure has the role, the password, the host
    /// and the port inside the error value at all.
    fn dsn_tokens(&self) -> Vec<String> {
        vec![
            ROLE.to_owned(),
            ROLE_PASSWORD.to_owned(),
            self.host.clone(),
            self.port.to_string(),
        ]
    }

    /// Builds a child command for one subcommand, with the DSN and log filter in its
    /// environment and the configuration path on its command line.
    fn command<I, S>(&self, arguments: I) -> Command
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = Command::new(env!("CARGO_BIN_EXE_warden"));
        command
            .args(arguments)
            .arg("--config")
            .arg(&self.config.path)
            .env(DSN_VARIABLE, &self.dsn)
            .env("RUST_LOG", LOG_FILTER);
        command
    }

    /// Sends one statement to the same server as the same role, with every Warden layer
    /// removed, and returns the driver's own failure.
    ///
    /// This is the barrier `AGENTS.md` requires an integration test to measure directly:
    /// no analyzer, no policy engine, no read-only session, no Warden pool settings —
    /// just the `GRANT`.
    async fn refused_by_the_role(&self, sql: &str) -> sqlx::Error {
        match self.engine {
            Engine::MySql => {
                let pool = MySqlPool::connect(&self.dsn).await.unwrap();
                let error = sqlx::query(AssertSqlSafe(sql.to_owned()))
                    .execute(&pool)
                    .await
                    .expect_err("the MySQL role accepted a statement it must refuse");
                pool.close().await;
                error
            }
            Engine::PostgreSql => {
                let pool = PgPool::connect(&self.dsn).await.unwrap();
                let error = sqlx::query(AssertSqlSafe(sql.to_owned()))
                    .execute(&pool)
                    .await
                    .expect_err("the PostgreSQL role accepted a statement it must refuse");
                pool.close().await;
                error
            }
        }
    }

    /// Counts the seeded rows as the same role, proving a refusal above is about
    /// privileges rather than about an unusable connection.
    async fn rows_the_role_can_still_read(&self) -> i64 {
        match self.engine {
            Engine::MySql => {
                let pool = MySqlPool::connect(&self.dsn).await.unwrap();
                let count = sqlx::query_scalar("SELECT COUNT(*) FROM orders")
                    .fetch_one(&pool)
                    .await
                    .unwrap();
                pool.close().await;
                count
            }
            Engine::PostgreSql => {
                let pool = PgPool::connect(&self.dsn).await.unwrap();
                let count = sqlx::query_scalar("SELECT count(*) FROM orders")
                    .fetch_one(&pool)
                    .await
                    .unwrap();
                pool.close().await;
                count
            }
        }
    }
}

// ---------------------------------------------------------------------------------
// Protocol helpers
// ---------------------------------------------------------------------------------

/// The `initialize` request, at the newest version Warden advertises.
fn initialize() -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "warden-e2e-test", "version": "0.0.0" }
        }
    })
}

/// The notification that completes initialization. It carries no id and expects no
/// answer.
fn initialized() -> Value {
    json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })
}

/// One `tools/call` request.
fn call(tool: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": { "name": tool, "arguments": arguments }
    })
}

/// The `tools/list` request.
fn list_tools() -> Value {
    json!({ "jsonrpc": "2.0", "method": "tools/list", "params": {} })
}

/// Stamps a unique id on every request that is not a notification.
///
/// Written here rather than in each helper so a test never has to keep two id spaces in
/// its head, and so a notification cannot accidentally acquire one.
fn with_ids(requests: &[Value]) -> Vec<Value> {
    requests
        .iter()
        .enumerate()
        .map(|(index, request)| {
            let mut request = request.clone();
            let is_notification = request
                .get("method")
                .and_then(Value::as_str)
                .is_some_and(|method| method.starts_with("notifications/"));
            if let Some(object) = request.as_object_mut()
                && !is_notification
            {
                object.insert("id".to_owned(), json!(index + 1));
            }
            request
        })
        .collect()
}

/// Parses stdout while enforcing the protocol-only invariant on every line.
///
/// `docs/mcp.md` section 5.1 reserves stdout for MCP. `clippy::print_stdout` is the
/// mechanical half of that rule; this is the observed half, and it runs on every exchange
/// in this file rather than only in the test named for it.
fn parse_protocol(stdout: &str) -> Vec<Value> {
    stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let value: Value = serde_json::from_str(line).unwrap_or_else(|error| {
                panic!("stdout carried a non-protocol line ({error}): {line:?}")
            });
            assert_eq!(
                value["jsonrpc"], "2.0",
                "stdout line is not JSON-RPC: {line:?}"
            );
            value
        })
        .collect()
}

/// The MySQL error number behind a driver failure, when there is one.
///
/// The number, not the SQLSTATE: `ER_TABLEACCESS_DENIED_ERROR` shares `42000` with
/// unrelated failures, and a test that accepted the SQLSTATE would pass on the wrong
/// refusal (ADR-0033).
fn mysql_error_number(error: &sqlx::Error) -> Option<u16> {
    error
        .as_database_error()
        .and_then(|database| database.try_downcast_ref::<MySqlDatabaseError>())
        .map(MySqlDatabaseError::number)
}

/// The SQLSTATE behind a driver failure, when there is one.
fn sqlstate(error: &sqlx::Error) -> Option<String> {
    error
        .as_database_error()
        .and_then(|database| database.code())
        .map(|code| code.into_owned())
}

// ---------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn an_agent_can_find_a_table_describe_it_query_it_and_plan_it() {
    // The workflow SPEC section 2 promises, on both engines, without the agent ever
    // receiving a password.
    for engine in [Engine::MySql, Engine::PostgreSql] {
        let fixture = Fixture::start(engine).await;
        let responses = fixture
            .exchange(&[
                initialize(),
                initialized(),
                list_tools(),
                call("list_connections", json!({})),
                call(
                    "search_schema",
                    json!({ "connection": NAME, "query": "orders" }),
                ),
                call(
                    "describe_schema",
                    json!({ "connection": NAME, "tables": [fixture.table()] }),
                ),
                call(
                    "query",
                    json!({
                        "connection": NAME,
                        "sql": fixture.select_with_placeholder(),
                        "parameters": ["shipped"],
                    }),
                ),
                call(
                    "explain",
                    json!({ "connection": NAME, "sql": fixture.select() }),
                ),
            ])
            .await;

        // `responses[0]` answers `initialize` and `responses[1]` answers `tools/list`:
        // neither is a tool call, so neither carries `result.isError`.
        assert!(
            responses[0]["error"].is_null(),
            "{engine:?}: {}",
            responses[0]
        );
        assert_eq!(
            responses[0]["result"]["protocolVersion"],
            json!(PROTOCOL_VERSION),
            "{engine:?}: {}",
            responses[0]
        );

        let mut discovered: Vec<&str> = responses[1]["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("{engine:?}: no tools array: {}", responses[1]))
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        discovered.sort_unstable();
        assert_eq!(
            discovered,
            [
                "describe_schema",
                "explain",
                "list_connections",
                "query",
                "search_schema"
            ],
            "{engine:?}: unexpected tool set"
        );

        let tools = &responses[2..];
        for response in tools {
            assert!(response["error"].is_null(), "{engine:?}: {response}");
            assert_eq!(
                response["result"]["isError"],
                json!(false),
                "{engine:?}: {response}"
            );
        }

        // Every tool answered; each one also has to have answered with something.
        let connections = &tools[0]["result"]["structuredContent"]["connections"];
        assert_eq!(connections[0]["name"], json!(NAME), "{connections}");
        assert_eq!(
            connections[0]["dialect"],
            json!(engine.dialect_name()),
            "{connections}"
        );

        let matches = &tools[1]["result"]["structuredContent"]["matches"];
        assert!(
            matches
                .as_array()
                .is_some_and(|matches| matches.iter().any(|hit| hit["table"] == json!("orders"))),
            "{engine:?}: search found no orders table: {matches}"
        );

        let described = &tools[2]["result"]["structuredContent"]["schemas"][0]["tables"][0];
        assert_eq!(described["name"], json!("orders"), "{described}");
        let columns: Vec<&str> = described["columns"]
            .as_array()
            .unwrap_or_else(|| panic!("{engine:?}: no columns: {described}"))
            .iter()
            .filter_map(|column| column["name"].as_str())
            .collect();
        assert_eq!(columns, ["id", "status", "password"], "{described}");

        let rows = &tools[3]["result"]["structuredContent"]["rows"];
        assert!(
            rows.as_array().is_some_and(|rows| !rows.is_empty()),
            "{rows}"
        );
        // The bound parameter reached the server: only the two shipped rows come back.
        assert_eq!(rows.as_array().map(Vec::len), Some(2), "{rows}");
        assert_eq!(rows[0][1], json!("shipped"), "{rows}");

        assert_eq!(
            tools[4]["result"]["structuredContent"]["dialect"],
            json!(engine.dialect_name())
        );

        // Nothing in this whole exchange may carry the DSN's password.
        let transcript = serde_json::to_string(&responses).unwrap();
        assert!(
            !transcript.contains(ROLE_PASSWORD),
            "{engine:?}: the DSN password reached the agent: {transcript}"
        );
    }
}

#[tokio::test]
async fn a_write_is_denied_before_the_database_is_asked() {
    // `query_rejected` is the observable difference: a statement the database refused
    // would arrive as `query_execution_error` instead, so this code is the evidence that
    // policy stopped it rather than the server.
    for engine in [Engine::MySql, Engine::PostgreSql] {
        let fixture = Fixture::start(engine).await;
        for statement in [
            "DELETE FROM orders",
            "UPDATE orders SET status = 'x'",
            "SELECT 1; SELECT 2",
            "SELECT * FROM orders FOR UPDATE",
        ] {
            let response = fixture.call_query(statement).await;
            assert_eq!(
                response["result"]["structuredContent"]["error"]["code"],
                json!("query_rejected"),
                "{engine:?} accepted {statement}"
            );
        }
    }
}

#[tokio::test]
async fn the_database_role_refuses_the_same_write_with_warden_removed() {
    // AGENTS.md: "Integration tests verify that the database role rejects writes, not
    // only that policy rejects them." The two statements below are the two the test above
    // watched policy deny; here they are sent to the same server, as the same role, with
    // the analyzer, the policy engine, the read-only session and Warden's own pool
    // settings all removed. The read-only guarantee has to survive a bug in the layer
    // above, and this is where that is measured.
    for engine in [Engine::MySql, Engine::PostgreSql] {
        let fixture = Fixture::start(engine).await;
        for statement in ["DELETE FROM orders", "UPDATE orders SET status = 'x'"] {
            let error = fixture.refused_by_the_role(statement).await;
            match engine {
                // ER_TABLEACCESS_DENIED_ERROR or ER_DBACCESS_DENIED_ERROR.
                Engine::MySql => assert!(
                    matches!(mysql_error_number(&error), Some(1142 | 1044)),
                    "{statement} was not refused by the role: {error:?}"
                ),
                // 42501 insufficient_privilege.
                Engine::PostgreSql => assert_eq!(
                    sqlstate(&error).as_deref(),
                    Some("42501"),
                    "{statement} was not refused by the role: {error:?}"
                ),
            }
        }

        // The same account still reads what it was granted, so the refusals above are
        // about privileges and not about an unusable connection.
        assert_eq!(
            fixture.rows_the_role_can_still_read().await,
            3,
            "{engine:?}"
        );
    }
}

#[tokio::test]
async fn a_driver_error_reaches_the_agent_as_a_code_and_nothing_else() {
    // The invariant the whole error boundary exists for: a real SQLx error naming a real
    // host, user, and relation must not cross (docs/security.md section 10).
    let fixture = Fixture::start(Engine::PostgreSql).await;

    // First, the same statement without the boundary, so the assertions below are known
    // to be guarding a string that genuinely exists one layer down rather than one that
    // could never have appeared.
    let driver = fixture
        .refused_by_the_role("SELECT * FROM no_such_relation")
        .await;
    assert!(
        driver.to_string().contains("no_such_relation"),
        "the driver's own message no longer names the relation: {driver}"
    );
    assert_eq!(sqlstate(&driver).as_deref(), Some("42P01"), "{driver:?}");

    let response = fixture.call_query("SELECT * FROM no_such_relation").await;
    let rendered = serde_json::to_string(&response).unwrap();
    assert!(rendered.contains("query_execution_error"), "{rendered}");

    // The two tokens this failure actually carries: `ExecuteError::Database`'s only field
    // is the driver's `Display`, asserted above to name the relation, and the SQLSTATE
    // this server reports for it.
    for leaked in ["no_such_relation", "42P01"] {
        assert!(!rendered.contains(leaked), "{leaked} leaked: {rendered}");
    }
    // The DSN tokens are checked here as a standing guard, not as a measurement: no
    // `ExecuteError` variant carries a connection string, so a statement error could not
    // leak one however badly this boundary broke.
    // `a_startup_failure_leaks_no_dsn_and_leaves_stdout_untouched` is where the same list
    // is live, because there the strings are inside the error value.
    for leaked in fixture.dsn_tokens() {
        assert!(!rendered.contains(&leaked), "{leaked} leaked: {rendered}");
    }
}

#[tokio::test]
async fn a_startup_failure_leaks_no_dsn_and_leaves_stdout_untouched() {
    // The hardest leak class in this suite, and the only place it is reachable.
    //
    // `ConnectionError::Unavailable` — the wire's `connection_unavailable` — carries a
    // `ConnectionName` and nothing else (`warden-ports/src/error.rs`), and pools connect
    // eagerly so a misconfiguration fails at startup (`crates/warden-mysql/src/pool.rs`).
    // A DSN that cannot authenticate therefore never reaches an MCP session at all: it
    // surfaces as `ConnectError`, which is deliberately not a `PublicError` and whose
    // `Driver` variant keeps sqlx's own text — the text that names the role Warden
    // connected as. `src/main.rs`'s `report` and `src/check.rs`'s module header both
    // state that rendering it with `Debug` instead of `Display` is what would put that
    // into an operator's terminal and into whatever collects it. This is that assertion.
    let fixture = Fixture::start(Engine::MySql).await.with_wrong_password();

    // The driver's own message does name the role, so the assertions below guard strings
    // that genuinely exist one layer down rather than strings that could never appear.
    let driver = MySqlPool::connect(&fixture.dsn)
        .await
        .expect_err("the server accepted a wrong password");
    assert!(
        driver.to_string().contains(ROLE),
        "the driver's own message no longer names the role: {driver}"
    );

    for arguments in [&["serve", "--transport", "stdio"][..], &["check"][..]] {
        let output = fixture.run(arguments).await;
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

        assert!(
            !output.status.success(),
            "warden {arguments:?} succeeded against an unusable DSN; stderr={stderr}"
        );
        // A startup failure must not corrupt the stream a client may already be reading
        // (docs/mcp.md section 5.1).
        assert!(
            output.stdout.is_empty(),
            "warden {arguments:?} wrote to stdout: {:?}",
            output.stdout
        );
        // Checked before the shape assertions below, so a leak is reported as a leak
        // rather than as a missing sentence.
        for leaked in fixture.dsn_tokens() {
            assert!(
                !stderr.contains(&leaked),
                "warden {arguments:?} leaked {leaked}: {stderr}"
            );
        }
        // The operator still gets a usable diagnostic: it names the connection that
        // could not be opened, which is public metadata `list_connections` already
        // returns, and it is `ConnectError`'s `Display` — the rendering that omits the
        // driver detail — rather than its `Debug`.
        assert!(
            stderr.contains(NAME),
            "warden {arguments:?} named no connection: {stderr}"
        );
        assert!(
            stderr.contains("the database connection could not be established"),
            "warden {arguments:?} did not report the sanitized connect failure: {stderr}"
        );
    }
}

#[tokio::test]
async fn a_redacted_column_is_redacted_on_the_wire() {
    let fixture = Fixture::start(Engine::MySql).await;
    let response = fixture.call_query("SELECT id, password FROM orders").await;
    let rendered = serde_json::to_string(&response).unwrap();
    assert!(rendered.contains("[REDACTED]"), "{rendered}");
    assert!(!rendered.contains(SECRET), "{rendered}");
}

#[tokio::test]
async fn stdout_carries_protocol_only_and_the_process_exits_on_eof() {
    // `clippy::print_stdout` is the mechanical half of docs/mcp.md section 5.1; this is
    // the observed half, including the startup path where a banner would be tempting.
    let fixture = Fixture::start(Engine::MySql).await;
    let (stdout, stderr, status) = fixture
        .run_to_completion(&with_ids(&[initialize(), initialized()]))
        .await;
    // The same check every other exchange in this file runs, rather than a weaker
    // re-implementation of it: a line like `{"foo":1}` is not protocol either.
    let messages = parse_protocol(&stdout);
    assert!(!messages.is_empty(), "stdout carried no response at all");
    assert!(status.success(), "exit status {status:?}; stderr={stderr}");
    // The startup log lines exist — they just go to the other descriptor. Naming one
    // rather than counting bytes: a panic message is also a non-empty stderr.
    assert!(
        stderr.contains("warden starting"),
        "the startup log line is missing from stderr: {stderr}"
    );
}

#[tokio::test]
async fn check_passes_against_a_reachable_database_and_warns_about_nothing_here() {
    let fixture = Fixture::start(Engine::PostgreSql).await;
    let output = fixture.run_check().await;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "stderr={stderr}");
    // The report is a diagnostic, so it goes to stderr and stdout stays a protocol
    // stream even for a command that never serves one (docs/mcp.md section 5.1).
    assert!(output.stdout.is_empty(), "stdout: {:?}", output.stdout);
    // A development connection over stdio raises none of `docs/mcp.md` section 7's
    // warnings, so the clean sentence is the one that must appear.
    assert!(
        stderr.contains("warden check: every check passed"),
        "stderr={stderr}"
    );
    assert!(
        !stderr.contains("with warnings"),
        "an unexpected warning was raised: {stderr}"
    );
    assert!(!stderr.contains(ROLE_PASSWORD), "stderr={stderr}");
}
