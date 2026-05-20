use super::*;
use crate::config::Config;
use crate::metrics::Metrics;
use crate::types::{BpfEvent, EventMeta};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering;

fn temp_db_path(name: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("peekd-{name}-{}-{nanos}.db", std::process::id()))
}

fn cleanup_db(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    let _ = std::fs::remove_file(format!("{}-shm", path.display()));
}

fn open_test_writer(path: &std::path::Path, metrics: Arc<Metrics>) -> DbWriter {
    open_test_writer_with_privacy(path, metrics, PrivacyMask::default())
}

fn open_test_writer_with_privacy(
    path: &std::path::Path,
    metrics: Arc<Metrics>,
    privacy: PrivacyMask,
) -> DbWriter {
    cleanup_db(path);
    let db = Connection::open(path).unwrap();
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
        .unwrap();
    _init_schema(&db).unwrap();
    DbWriter::new(db, 30, metrics, privacy)
}

fn event(lport: u16, cmdline: &str, sha256: &str, laddr: [u8; 4], send: u32) -> BpfEvent {
    BpfEvent {
        pid: 100,
        ppid: 1,
        uid: 1000,
        name: "curl".to_string(),
        pname: "bash".to_string(),
        exe: "/usr/bin/curl".to_string(),
        pexe: "/usr/bin/bash".to_string(),
        cmdline: cmdline.to_string(),
        pcmdline: "bash".to_string(),
        fd_path: String::new(),
        pfd_path: String::new(),
        dev: 1,
        ino: 2,
        pdev: 3,
        pino: 4,
        send,
        recv: 7,
        lport,
        rport: 443,
        laddr: IpAddr::V4(Ipv4Addr::from(laddr)),
        raddr: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        domain: "example.com".to_string(),
        domain_source: "unknown".to_string(),
        domain_confidence: "none".to_string(),
        domain_status: "unknown".to_string(),
        sha256: sha256.to_string(),
        psha256: "parent-sha".to_string(),
        meta: EventMeta::default(),
    }
}

#[test]
fn init_schema_migrates_domain_metadata_columns() {
    let path = temp_db_path("domain-migration");
    cleanup_db(&path);
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TABLE executables (
            id INTEGER PRIMARY KEY,
            exe TEXT NOT NULL,
            name TEXT NOT NULL,
            cmdline TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            UNIQUE(exe, name, cmdline, sha256)
        );
        CREATE TABLE connections (
            contime INTEGER NOT NULL,
            send INTEGER NOT NULL,
            recv INTEGER NOT NULL,
            exe_id INTEGER NOT NULL REFERENCES executables(id),
            pexe_id INTEGER NOT NULL REFERENCES executables(id),
            uid INTEGER NOT NULL,
            lport INTEGER NOT NULL,
            rport INTEGER NOT NULL,
            laddr TEXT NOT NULL,
            raddr TEXT NOT NULL,
            domain TEXT NOT NULL
        );",
    )
    .unwrap();

    _init_schema(&db).unwrap();
    db.execute(
        "INSERT INTO executables (id, exe, name, cmdline, sha256)
         VALUES (1, '/bin/a', 'a', '', ''), (2, '/bin/b', 'b', '', '')",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO connections
            (contime, send, recv, exe_id, pexe_id, uid, lport, rport, laddr, raddr, domain)
         VALUES (0, 0, 0, 1, 2, 0, 0, 0, '', '', '')",
        [],
    )
    .unwrap();

    let row: (String, String, String) = db
        .query_row(
            "SELECT domain_source, domain_confidence, domain_status FROM connections",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        row,
        (
            "unknown".to_string(),
            "none".to_string(),
            "unknown".to_string()
        )
    );

    cleanup_db(&path);
}

#[test]
fn fresh_schema_sets_current_user_version() {
    let path = temp_db_path("fresh-schema-version");
    cleanup_db(&path);
    let db = Connection::open(&path).unwrap();

    _init_schema(&db).unwrap();

    let version: i64 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, CURRENT_SCHEMA_VERSION);
    cleanup_db(&path);
}

#[test]
fn schema_init_rejects_newer_database_version() {
    let path = temp_db_path("future-schema-version");
    cleanup_db(&path);
    let db = Connection::open(&path).unwrap();
    db.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION + 1)
        .unwrap();

    let err = _init_schema(&db).unwrap_err();

    assert!(err.to_string().contains("newer than this binary"));
    cleanup_db(&path);
}

#[tokio::test]
async fn start_rejects_newer_schema_version() {
    let path = temp_db_path("start-newer-schema");
    cleanup_db(&path);
    let db = Connection::open(&path).unwrap();
    db.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION + 1)
        .unwrap();
    drop(db);

    let metrics = Arc::new(Metrics::default());
    let config = Arc::new(Config::default());
    let (_tx, rx) = tokio::sync::broadcast::channel(16);
    let err = match super::lifecycle::start_with_db_path(rx, config, metrics, path.clone()) {
        Ok(handle) => {
            handle.shutdown().await;
            panic!("storage start unexpectedly accepted a newer schema")
        }
        Err(e) => e,
    };

    assert!(err.to_string().contains("newer than this binary"));
    cleanup_db(&path);
}

#[test]
fn legacy_schema_migrates_domain_columns_alerts_and_version() {
    let path = temp_db_path("legacy-schema-version");
    cleanup_db(&path);
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TABLE executables (
            id INTEGER PRIMARY KEY,
            exe TEXT NOT NULL,
            name TEXT NOT NULL,
            cmdline TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            UNIQUE(exe, name, cmdline, sha256)
        );
        CREATE TABLE connections (
            contime INTEGER NOT NULL,
            send INTEGER NOT NULL,
            recv INTEGER NOT NULL,
            exe_id INTEGER NOT NULL REFERENCES executables(id),
            pexe_id INTEGER NOT NULL REFERENCES executables(id),
            uid INTEGER NOT NULL,
            lport INTEGER NOT NULL,
            rport INTEGER NOT NULL,
            laddr TEXT NOT NULL,
            raddr TEXT NOT NULL,
            domain TEXT NOT NULL
        );",
    )
    .unwrap();

    _init_schema(&db).unwrap();

    let version: i64 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    let alert_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='alert_events'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let domain_source_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('connections') WHERE name='domain_source'",
            [],
            |r| r.get(0),
        )
        .unwrap();

    assert_eq!(version, CURRENT_SCHEMA_VERSION);
    assert_eq!(alert_count, 1);
    assert_eq!(domain_source_count, 1);
    cleanup_db(&path);
}

#[test]
fn flush_persists_local_endpoint_and_distinct_executable_metadata() {
    let path = temp_db_path("row-truth");
    let metrics = Arc::new(Metrics::default());
    let mut writer = open_test_writer(&path, metrics);

    writer.accumulate(vec![
        event(
            40001,
            "curl https://example.com/a",
            "sha-a",
            [127, 0, 0, 1],
            11,
        ),
        event(
            40002,
            "curl https://example.com/b",
            "sha-b",
            [127, 0, 0, 2],
            13,
        ),
    ]);
    writer.flush().unwrap();

    let mut stmt = writer
        .db
        .prepare(
            "SELECT c.laddr, c.lport, e.cmdline, e.sha256, c.send
             FROM connections c JOIN executables e ON c.exe_id = e.id
             ORDER BY c.lport",
        )
        .unwrap();
    let rows: Vec<(String, u16, String, String, u32)> = stmt
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect();

    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0],
        (
            "127.0.0.1".to_string(),
            40001,
            "curl https://example.com/a".to_string(),
            "sha-a".to_string(),
            11,
        )
    );
    assert_eq!(
        rows[1],
        (
            "127.0.0.2".to_string(),
            40002,
            "curl https://example.com/b".to_string(),
            "sha-b".to_string(),
            13,
        )
    );

    cleanup_db(&path);
}

#[test]
fn failed_flush_retains_buffer_and_counts_error() {
    let path = temp_db_path("flush-failure");
    let metrics = Arc::new(Metrics::default());
    let mut writer = open_test_writer(&path, metrics.clone());

    writer.accumulate(vec![event(
        40001,
        "curl https://example.com",
        "sha-a",
        [127, 0, 0, 1],
        11,
    )]);
    writer.db.execute("DROP TABLE connections", []).unwrap();

    assert!(writer.flush().is_err());
    assert_eq!(writer.traffic.len(), 1);
    assert_eq!(metrics.sqlite_write_errors.load(Ordering::Relaxed), 1);
    let health = storage_health_probe(&writer.db).unwrap();
    assert_eq!(health.checkpoint.busy, 0);
    assert_eq!(health.quick_check, "ok");

    _init_schema(&writer.db).unwrap();
    writer.flush().unwrap();

    let count: i64 = writer
        .db
        .query_row("SELECT COUNT(*) FROM connections", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(writer.traffic.len(), 0);
    assert_eq!(metrics.sqlite_writes.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.sqlite_rows_written.load(Ordering::Relaxed), 1);

    cleanup_db(&path);
}

#[test]
fn query_open_retry_policy_includes_wal_io_errors() {
    let cannot_open = rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error {
            code: ErrorCode::CannotOpen,
            extended_code: rusqlite::ffi::SQLITE_CANTOPEN,
        },
        Some("unable to open database file".to_string()),
    );
    let io_error = rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error {
            code: ErrorCode::SystemIoFailure,
            extended_code: rusqlite::ffi::SQLITE_IOERR,
        },
        Some("disk I/O error".to_string()),
    );
    let readonly = rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error {
            code: ErrorCode::ReadOnly,
            extended_code: rusqlite::ffi::SQLITE_READONLY,
        },
        Some("attempt to write a readonly database".to_string()),
    );

    assert!(should_retry_query_open_readwrite(&cannot_open));
    assert!(should_retry_query_open_readwrite(&io_error));
    assert!(!should_retry_query_open_readwrite(&readonly));
}

#[test]
fn lifecycle_metadata_is_written_by_storage_writer() {
    let path = temp_db_path("lifecycle-storage-writer");
    let metrics = Arc::new(Metrics::default());
    let writer = open_test_writer(&path, metrics);
    let record = crate::connection_lifecycle::LifecycleRecord {
        exe: "/usr/bin/curl".to_string(),
        laddr: "127.0.0.1".parse().unwrap(),
        lport: 40000,
        raddr: "1.2.3.4".parse().unwrap(),
        rport: 443,
        connect_t: 10,
        close_t: Some(20),
        direction: crate::connection_lifecycle::Direction::Outbound,
    };

    writer.write_lifecycle_record(&record).unwrap();

    let row: (String, String, u16, String, u16, i64, Option<i64>, String) = writer
        .db
        .query_row(
            "SELECT exe, laddr, lport, raddr, rport, connect_t, close_t, direction
             FROM connections_meta",
            [],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(row.0, "/usr/bin/curl");
    assert_eq!(row.1, "127.0.0.1");
    assert_eq!(row.2, 40000);
    assert_eq!(row.3, "1.2.3.4");
    assert_eq!(row.4, 443);
    assert_eq!(row.5, 10);
    assert_eq!(row.6, Some(20));
    assert_eq!(row.7, "outbound");
    cleanup_db(&path);
}

#[test]
fn privacy_flags_redact_before_sqlite_write() {
    let path = temp_db_path("privacy-redaction");
    let metrics = Arc::new(Metrics::default());
    let privacy = PrivacyMask {
        addresses: false,
        commands: false,
        ports: false,
    };
    let mut writer = open_test_writer_with_privacy(&path, metrics, privacy);

    writer.accumulate(vec![event(
        40001,
        "curl https://example.com/private",
        "sha-private",
        [127, 0, 0, 1],
        11,
    )]);
    writer.flush().unwrap();

    let row: (String, String, u16, u16, String, String, String) = writer
        .db
        .query_row(
            "SELECT c.laddr, c.raddr, c.lport, c.rport, e.exe, e.cmdline, pe.cmdline
             FROM connections c
             JOIN executables e ON c.exe_id = e.id
             JOIN executables pe ON c.pexe_id = pe.id",
            [],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            },
        )
        .unwrap();

    assert_eq!(row.0, "");
    assert_eq!(row.1, "");
    assert_eq!(row.2, 0);
    assert_eq!(row.3, 0);
    assert_eq!(row.4, "/usr/bin/curl");
    assert_eq!(row.5, "");
    assert_eq!(row.6, "");

    cleanup_db(&path);
}

#[test]
fn flush_persists_domain_metadata() {
    let path = temp_db_path("domain-metadata");
    let metrics = Arc::new(Metrics::default());
    let mut writer = open_test_writer(&path, metrics);
    let mut event = event(
        40001,
        "curl https://example.com",
        "sha-domain",
        [127, 0, 0, 1],
        11,
    );
    event.domain = "com.example.www".to_string();
    event.domain_source = "getaddrinfo".to_string();
    event.domain_confidence = "high".to_string();
    event.domain_status = "direct_dns_seen".to_string();

    writer.accumulate(vec![event]);
    writer.flush().unwrap();

    let row: (String, String, String, String) = writer
        .db
        .query_row(
            "SELECT domain, domain_source, domain_confidence, domain_status FROM connections",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        row,
        (
            "com.example.www".to_string(),
            "getaddrinfo".to_string(),
            "high".to_string(),
            "direct_dns_seen".to_string(),
        )
    );

    cleanup_db(&path);
}

#[test]
fn flush_message_does_not_consume_pending_events() {
    let path = temp_db_path("flush-message");
    let metrics = Arc::new(Metrics::default());
    let writer = open_test_writer(&path, metrics);
    let (tx, rx) = std::sync::mpsc::channel();

    tx.send(WriterMsg::Flush).unwrap();
    tx.send(WriterMsg::Events(vec![event(
        40001,
        "curl https://example.com",
        "sha-a",
        [127, 0, 0, 1],
        11,
    )]))
    .unwrap();
    tx.send(WriterMsg::Shutdown).unwrap();
    drop(tx);

    writer.run(rx);

    let db = Connection::open(&path).unwrap();
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM connections", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);

    cleanup_db(&path);
}

#[tokio::test]
async fn start_returns_handle_and_shutdown_drains_final_batch() {
    let path = temp_db_path("storage-handle");
    cleanup_db(&path);
    let metrics = Arc::new(Metrics::default());
    let mut config = Config::default();
    config.database.write_limit_seconds = 60;
    let (tx, rx) = tokio::sync::broadcast::channel(16);
    let handle =
        super::lifecycle::start_with_db_path(rx, Arc::new(config), metrics, path.clone()).unwrap();

    tx.send(event(
        40003,
        "curl https://example.com/late",
        "sha-late",
        [127, 0, 0, 3],
        17,
    ))
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    tokio::time::timeout(std::time::Duration::from_secs(2), handle.shutdown())
        .await
        .unwrap();

    let db = Connection::open(&path).unwrap();
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM connections", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
    cleanup_db(&path);
}

#[tokio::test]
async fn database_disabled_start_does_not_create_db() {
    let path = temp_db_path("storage-disabled");
    cleanup_db(&path);
    let metrics = Arc::new(Metrics::default());
    let mut config = Config::default();
    config.database.enabled = false;
    let (_tx, rx) = tokio::sync::broadcast::channel(16);
    let handle =
        super::lifecycle::start_with_db_path(rx, Arc::new(config), metrics, path.clone()).unwrap();

    handle.alert_sender().send(WriterMsg::Flush).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), handle.shutdown())
        .await
        .unwrap();
    assert!(!path.exists());
}

#[test]
fn readonly_connection_rejects_writes() {
    let path = temp_db_path("readonly");
    let metrics = Arc::new(Metrics::default());
    let mut writer = open_test_writer(&path, metrics);
    writer.accumulate(vec![event(
        40004,
        "curl https://example.com/read",
        "sha-read",
        [127, 0, 0, 4],
        19,
    )]);
    writer.flush().unwrap();
    drop(writer);

    let ro = open_query_path(&path).unwrap();
    let query_only: i64 = ro.query_row("PRAGMA query_only", [], |r| r.get(0)).unwrap();
    assert_eq!(query_only, 1);
    let err = ro
        .execute("INSERT INTO connections (contime, send, recv, exe_id, pexe_id, uid, lport, rport, laddr, raddr, domain) VALUES (0,0,0,0,0,0,0,0,'','','')", [])
        .unwrap_err();
    assert!(err.to_string().contains("readonly"));
    cleanup_db(&path);
}

#[test]
fn query_only_readwrite_connection_rejects_writes() {
    let path = temp_db_path("query-only-rw");
    let metrics = Arc::new(Metrics::default());
    let mut writer = open_test_writer(&path, metrics);
    writer.accumulate(vec![event(
        40005,
        "curl https://example.com/rw",
        "sha-readwrite",
        [127, 0, 0, 5],
        23,
    )]);
    writer.flush().unwrap();
    drop(writer);

    let conn = open_query_only_path(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    let query_only: i64 = conn
        .query_row("PRAGMA query_only", [], |r| r.get(0))
        .unwrap();
    assert_eq!(query_only, 1);
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM connections", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
    let err = conn.execute("DELETE FROM connections", []).unwrap_err();
    assert!(err.to_string().contains("readonly"));
    cleanup_db(&path);
}

#[test]
fn query_connection_enables_query_only_and_busy_timeout() {
    let path = temp_db_path("query-contract");
    let metrics = Arc::new(Metrics::default());
    let mut writer = open_test_writer(&path, metrics);
    writer.accumulate(vec![event(
        40010,
        "curl https://example.com/query-contract",
        "sha-query-contract",
        [127, 0, 0, 10],
        31,
    )]);
    writer.flush().unwrap();
    drop(writer);

    let conn = open_query_path(&path).unwrap();
    let query_only: i64 = conn
        .query_row("PRAGMA query_only", [], |r| r.get(0))
        .unwrap();
    let busy_timeout: i64 = conn
        .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
        .unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM connections", [], |r| r.get(0))
        .unwrap();

    assert_eq!(query_only, 1);
    assert_eq!(busy_timeout, DB_BUSY_TIMEOUT_MS);
    assert_eq!(count, 1);
    let err = conn.execute("DELETE FROM connections", []).unwrap_err();
    assert!(err.to_string().contains("readonly"));
    cleanup_db(&path);
}

#[test]
fn integrity_check_reports_ok_for_valid_database() {
    let path = temp_db_path("integrity-ok");
    let metrics = Arc::new(Metrics::default());
    let mut writer = open_test_writer(&path, metrics);
    writer.accumulate(vec![event(
        40020,
        "curl https://example.com/integrity",
        "sha-integrity",
        [127, 0, 0, 20],
        41,
    )]);
    writer.flush().unwrap();
    drop(writer);

    let result = integrity_check_path(&path).unwrap();

    assert_eq!(result, "ok");
    cleanup_db(&path);
}

#[test]
fn checkpoint_truncate_returns_sqlite_status() {
    let path = temp_db_path("checkpoint-truncate");
    let metrics = Arc::new(Metrics::default());
    let mut writer = open_test_writer(&path, metrics);
    writer.accumulate(vec![event(
        40021,
        "curl https://example.com/checkpoint",
        "sha-checkpoint",
        [127, 0, 0, 21],
        43,
    )]);
    writer.flush().unwrap();
    drop(writer);

    let status = checkpoint_truncate_path(&path).unwrap();

    assert_eq!(status.busy, 0);
    cleanup_db(&path);
}
