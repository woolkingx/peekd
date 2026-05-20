#![allow(dead_code, unused_imports)]

//! storage.rs: Event persistence to SQLite.
//!
//! Architecture: one writer thread owns the Connection (no Mutex contention),
//! one read-only connection per CLI query (WAL allows unlimited concurrent readers).
//!
//! Writer thread receives WriterMsg via mpsc, batches traffic, flushes on interval.
//! CLI query path opens a fresh read-only connection — never blocks the writer.

use crate::types::{BpfEvent, Sink};
use rusqlite::{params, Connection, ErrorCode, OpenFlags};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, warn};

type ExeKey = (String, String, String, String);
// (exe, name, cmdline, sha256) — matches UNIQUE constraint in executables table

type TrafficKey = (
    ExeKey,
    ExeKey,
    u32,
    u16,
    u16,
    String,
    String,
    String,
    String,
    String,
    String,
);
// (exe_key, pexe_key, uid, lport, rport, laddr, raddr, domain, source, confidence, status)

const CURRENT_SCHEMA_VERSION: i64 = 3;
const DB_BUSY_TIMEOUT_MS: i64 = 5_000;

#[derive(Clone, Copy)]
struct PrivacyMask {
    addresses: bool,
    commands: bool,
    ports: bool,
}

impl PrivacyMask {
    fn from_config(config: &crate::config::LogConfig) -> Self {
        Self {
            addresses: config.addresses,
            commands: config.commands,
            ports: config.ports,
        }
    }
}

impl Default for PrivacyMask {
    fn default() -> Self {
        Self {
            addresses: true,
            commands: true,
            ports: true,
        }
    }
}

// ============================================================================
// Writer thread message
// ============================================================================

pub enum WriterMsg {
    Events(Vec<BpfEvent>),
    LifecycleRecord(crate::connection_lifecycle::LifecycleRecord),
    AlertEvent {
        ts: i64,
        rule: String,
        exe: String,
        raddr: String,
        domain: String,
        action: String,
    },
    Flush,
    Shutdown,
}

// ============================================================================
// Writer thread: owns Connection, no Mutex needed
// ============================================================================

struct DbWriter {
    db: Connection,
    traffic: HashMap<TrafficKey, (u32, u32)>,
    exe_id_cache: HashMap<ExeKey, i64>,
    retention_days: u32,
    event_count: u64,
    metrics: Arc<crate::metrics::Metrics>,
    privacy: PrivacyMask,
}

impl DbWriter {
    fn new(
        db: Connection,
        retention_days: u32,
        metrics: Arc<crate::metrics::Metrics>,
        privacy: PrivacyMask,
    ) -> Self {
        Self {
            db,
            traffic: HashMap::new(),
            exe_id_cache: HashMap::new(),
            retention_days,
            event_count: 0,
            metrics,
            privacy,
        }
    }

    fn accumulate(&mut self, events: Vec<BpfEvent>) {
        for event in events {
            let exe_key = if event.exe.is_empty() {
                event.name.clone()
            } else {
                event.exe.clone()
            };
            let pexe_key = if event.pexe.is_empty() {
                event.pname.clone()
            } else {
                event.pexe.clone()
            };
            let cmdline = if self.privacy.commands {
                event.cmdline.clone()
            } else {
                String::new()
            };
            let pcmdline = if self.privacy.commands {
                event.pcmdline.clone()
            } else {
                String::new()
            };
            let (lport, rport) = if self.privacy.ports {
                (event.lport, event.rport)
            } else {
                (0, 0)
            };
            let (laddr, raddr) = if self.privacy.addresses {
                (event.laddr.to_string(), event.raddr.to_string())
            } else {
                (String::new(), String::new())
            };
            let exe_id_key = (exe_key, event.name.clone(), cmdline, event.sha256.clone());
            let pexe_id_key = (
                pexe_key,
                event.pname.clone(),
                pcmdline,
                event.psha256.clone(),
            );
            let traffic_key = (
                exe_id_key,
                pexe_id_key,
                event.uid,
                lport,
                rport,
                laddr,
                raddr,
                event.domain.clone(),
                non_empty_or(&event.domain_source, "unknown"),
                non_empty_or(&event.domain_confidence, "none"),
                non_empty_or(&event.domain_status, "unknown"),
            );
            let (send, recv) = self.traffic.entry(traffic_key).or_insert((0, 0));
            *send += event.send;
            *recv += event.recv;

            self.event_count += 1;
        }
    }

    fn flush(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match self.flush_inner() {
            Ok(()) => Ok(()),
            Err(e) => {
                self.record_storage_write_error("flush_error");
                Err(e)
            }
        }
    }

    fn flush_inner(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        _ensure_wal_mode(&self.db)?;
        if self.traffic.is_empty() {
            return Ok(());
        }
        let mut next_exe_id_cache = self.exe_id_cache.clone();
        match _flush_to_db(&mut self.db, &self.traffic, &mut next_exe_id_cache) {
            Ok(rows_written) => {
                self.exe_id_cache = next_exe_id_cache;
                self.traffic.clear();
                self.metrics.sqlite_writes.fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .sqlite_rows_written
                    .fetch_add(rows_written as u64, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn write_lifecycle_record(
        &self,
        record: &crate::connection_lifecycle::LifecycleRecord,
    ) -> rusqlite::Result<usize> {
        self.db.execute(
            "INSERT INTO connections_meta (exe, laddr, lport, raddr, rport, connect_t, close_t, direction)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                &record.exe,
                record.laddr.to_string(),
                record.lport,
                record.raddr.to_string(),
                record.rport,
                record.connect_t,
                record.close_t,
                record.direction.as_str(),
            ],
        )
    }

    fn record_storage_write_error(&self, reason: &str) {
        self.metrics
            .sqlite_write_errors
            .fetch_add(1, Ordering::Relaxed);
        match storage_health_probe(&self.db) {
            Ok(status) => warn!(
                reason,
                checkpoint_busy = status.checkpoint.busy,
                checkpoint_log_frames = status.checkpoint.log_frames,
                checkpointed_frames = status.checkpoint.checkpointed_frames,
                quick_check = %status.quick_check,
                "sqlite health probe after storage error"
            ),
            Err(e) => warn!(reason, error = %e, "sqlite health probe failed"),
        }
    }

    fn cleanup_retention(&mut self) {
        if let Err(e) = _cleanup_retention(&self.db, self.retention_days) {
            warn!("retention cleanup failed: {}", e);
        }
    }

    fn run(mut self, rx: std::sync::mpsc::Receiver<WriterMsg>) {
        let flush_secs = 5u64; // flush every 5s regardless of event volume
        let mut last_flush = std::time::Instant::now();
        let cleanup_interval =
            std::time::Duration::from_secs(((self.retention_days as u64) * 86400 / 2).max(3600));
        let mut last_cleanup = std::time::Instant::now();

        loop {
            // Blocking recv with timeout so we can flush on interval even with no messages
            match rx.recv_timeout(std::time::Duration::from_millis(500)) {
                Ok(WriterMsg::Events(events)) => {
                    self.accumulate(events);
                }
                Ok(WriterMsg::LifecycleRecord(record)) => {
                    if let Err(e) = self.write_lifecycle_record(&record) {
                        self.record_storage_write_error("lifecycle_insert_failed");
                        error!("lifecycle insert failed: {}", e);
                    }
                }
                Ok(WriterMsg::AlertEvent { ts, rule, exe, raddr, domain, action }) => {
                    if let Err(e) = self.db.execute(
                        "INSERT INTO alert_events (ts, rule, exe, raddr, domain, action) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![ts, rule, exe, raddr, domain, action],
                    ) {
                        self.record_storage_write_error("alert_insert_failed");
                        error!("alert event insert failed: {}", e);
                    }
                }
                Ok(WriterMsg::Flush) => {
                    if let Err(e) = self.flush() {
                        error!("storage flush failed: {}", e);
                    }
                    last_flush = std::time::Instant::now();
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if last_flush.elapsed().as_secs() >= flush_secs {
                        if let Err(e) = self.flush() {
                            error!("storage flush failed: {}", e);
                        }
                        last_flush = std::time::Instant::now();
                    }
                }
                Ok(WriterMsg::Shutdown) => {
                    if let Err(e) = self.flush() {
                        error!("storage final flush failed: {}", e);
                    }
                    break;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    if let Err(e) = self.flush() {
                        error!("storage final flush failed after disconnect: {}", e);
                    }
                    break;
                }
            }

            if last_cleanup.elapsed() >= cleanup_interval {
                self.cleanup_retention();
                last_cleanup = std::time::Instant::now();
            }
        }
    }
}

pub type AlertEventSender = std::sync::mpsc::Sender<WriterMsg>;

mod lifecycle;
pub use lifecycle::*;

// ============================================================================
// Schema and helpers
// ============================================================================

fn _init_schema(db: &Connection) -> Result<(), Box<dyn std::error::Error>> {
    db.execute_batch("PRAGMA foreign_keys = ON;")?;
    let version = schema_version(db)?;
    if version > CURRENT_SCHEMA_VERSION {
        return Err(format!(
            "database schema version {version} is newer than this binary supports ({CURRENT_SCHEMA_VERSION})"
        )
        .into());
    }
    create_current_tables(db)?;
    migrate_schema(db, version)?;
    set_schema_version(db, CURRENT_SCHEMA_VERSION)?;
    Ok(())
}

fn schema_version(db: &Connection) -> rusqlite::Result<i64> {
    db.query_row("PRAGMA user_version", [], |r| r.get(0))
}

fn set_schema_version(db: &Connection, version: i64) -> rusqlite::Result<()> {
    db.pragma_update(None, "user_version", version)
}

fn create_current_tables(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS executables (
            id      INTEGER PRIMARY KEY,
            exe     TEXT NOT NULL,
            name    TEXT NOT NULL,
            cmdline TEXT NOT NULL,
            sha256  TEXT NOT NULL,
            UNIQUE(exe, name, cmdline, sha256)
        );
        CREATE TABLE IF NOT EXISTS connections (
            contime INTEGER NOT NULL,
            send    INTEGER NOT NULL,
            recv    INTEGER NOT NULL,
            exe_id  INTEGER NOT NULL REFERENCES executables(id),
            pexe_id INTEGER NOT NULL REFERENCES executables(id),
            uid     INTEGER NOT NULL,
            lport   INTEGER NOT NULL,
            rport   INTEGER NOT NULL,
            laddr   TEXT NOT NULL,
            raddr   TEXT NOT NULL,
            domain  TEXT NOT NULL,
            domain_source TEXT NOT NULL DEFAULT 'unknown',
            domain_confidence TEXT NOT NULL DEFAULT 'none',
            domain_status TEXT NOT NULL DEFAULT 'unknown'
        );
        CREATE INDEX IF NOT EXISTS idx_contime ON connections(contime);
        CREATE INDEX IF NOT EXISTS idx_exe_id_contime ON connections(exe_id, contime);
        CREATE TABLE IF NOT EXISTS connections_meta (
            id         INTEGER PRIMARY KEY,
            exe        TEXT NOT NULL,
            laddr      TEXT NOT NULL,
            lport      INTEGER NOT NULL,
            raddr      TEXT NOT NULL,
            rport      INTEGER NOT NULL,
            connect_t  INTEGER NOT NULL,
            close_t    INTEGER,
            direction  TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_meta_connect_t ON connections_meta(connect_t);
        CREATE INDEX IF NOT EXISTS idx_meta_raddr ON connections_meta(raddr);
        CREATE TABLE IF NOT EXISTS alert_events (
            id      INTEGER PRIMARY KEY,
            ts      INTEGER NOT NULL,
            rule    TEXT NOT NULL,
            exe     TEXT NOT NULL,
            raddr   TEXT NOT NULL,
            domain  TEXT NOT NULL DEFAULT '',
            action  TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_alert_ts ON alert_events(ts);",
    )
}

fn migrate_schema(db: &Connection, _from_version: i64) -> Result<(), Box<dyn std::error::Error>> {
    _ensure_column(
        db,
        "connections",
        "domain_source",
        "TEXT NOT NULL DEFAULT 'unknown'",
    )?;
    _ensure_column(
        db,
        "connections",
        "domain_confidence",
        "TEXT NOT NULL DEFAULT 'none'",
    )?;
    _ensure_column(
        db,
        "connections",
        "domain_status",
        "TEXT NOT NULL DEFAULT 'unknown'",
    )?;
    Ok(())
}

fn _ensure_column(
    db: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut stmt = db.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for row in rows {
        if row? == column {
            return Ok(());
        }
    }
    db.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
        [],
    )?;
    Ok(())
}

pub fn open_readonly_db() -> Result<Connection, Box<dyn std::error::Error>> {
    open_query_db()
}

pub fn open_query_db() -> Result<Connection, Box<dyn std::error::Error>> {
    let db_path = crate::config::db_path();
    open_query_path(&db_path)
}

fn open_query_path(db_path: &Path) -> Result<Connection, Box<dyn std::error::Error>> {
    if !db_path.exists() {
        return Err(format!("database not found: {:?}", db_path).into());
    }
    let readonly_flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    match open_query_only_path(db_path, readonly_flags) {
        Ok(conn) => Ok(conn),
        Err(read_err) if should_retry_query_open_readwrite(&read_err) => {
            warn!(
                "readonly sqlite open failed for {}: {}; retrying query-only read-write open",
                db_path.display(),
                read_err
            );
            let readwrite_flags =
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
            Ok(open_query_only_path(db_path, readwrite_flags)?)
        }
        Err(read_err) => Err(read_err.into()),
    }
}

fn open_query_only_path(db_path: &Path, flags: OpenFlags) -> rusqlite::Result<Connection> {
    let conn = Connection::open_with_flags(db_path, flags)?;
    configure_query_connection(&conn)?;
    Ok(conn)
}

fn configure_query_connection(conn: &Connection) -> rusqlite::Result<()> {
    conn.busy_timeout(Duration::from_millis(DB_BUSY_TIMEOUT_MS as u64))?;
    conn.pragma_update(None, "query_only", true)?;
    Ok(())
}

fn should_retry_query_open_readwrite(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(sqlite_err, _)
            if matches!(sqlite_err.code, ErrorCode::CannotOpen | ErrorCode::SystemIoFailure)
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalCheckpointStatus {
    pub busy: i64,
    pub log_frames: i64,
    pub checkpointed_frames: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageHealthStatus {
    pub checkpoint: WalCheckpointStatus,
    pub quick_check: String,
}

pub fn integrity_check() -> Result<String, Box<dyn std::error::Error>> {
    integrity_check_path(&crate::config::db_path())
}

fn integrity_check_path(db_path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let conn = open_query_path(db_path)?;
    Ok(conn.query_row("PRAGMA integrity_check", [], |r| r.get(0))?)
}

pub fn checkpoint_truncate() -> Result<WalCheckpointStatus, Box<dyn std::error::Error>> {
    checkpoint_truncate_path(&crate::config::db_path())
}

fn checkpoint_truncate_path(
    db_path: &Path,
) -> Result<WalCheckpointStatus, Box<dyn std::error::Error>> {
    if !db_path.exists() {
        return Err(format!("database not found: {:?}", db_path).into());
    }
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(Duration::from_millis(DB_BUSY_TIMEOUT_MS as u64))?;
    Ok(conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
        Ok(WalCheckpointStatus {
            busy: r.get(0)?,
            log_frames: r.get(1)?,
            checkpointed_frames: r.get(2)?,
        })
    })?)
}

fn storage_health_probe(
    conn: &Connection,
) -> Result<StorageHealthStatus, Box<dyn std::error::Error>> {
    let checkpoint = wal_checkpoint_passive(conn)?;
    let quick_check: String = conn.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
    Ok(StorageHealthStatus {
        checkpoint,
        quick_check,
    })
}

fn wal_checkpoint_passive(conn: &Connection) -> rusqlite::Result<WalCheckpointStatus> {
    conn.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |r| {
        Ok(WalCheckpointStatus {
            busy: r.get(0)?,
            log_frames: r.get(1)?,
            checkpointed_frames: r.get(2)?,
        })
    })
}

fn _ensure_wal_mode(db: &Connection) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mode: String = db.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(format!("sqlite journal_mode is {mode}, expected wal").into());
    }
    db.execute_batch("PRAGMA synchronous=NORMAL;")?;
    Ok(())
}

fn _cleanup_retention(
    db: &Connection,
    retention_days: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let cutoff = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64)
        - (retention_days as i64 * 86400);
    db.execute(
        "DELETE FROM connections WHERE contime < ?1",
        params![cutoff],
    )?;
    Ok(())
}

fn _get_or_insert_exe(
    db: &Connection,
    cache: &mut HashMap<ExeKey, i64>,
    exe: &str,
    name: &str,
    cmdline: &str,
    sha256: &str,
) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
    let key = (
        exe.to_string(),
        name.to_string(),
        cmdline.to_string(),
        sha256.to_string(),
    );
    if let Some(&id) = cache.get(&key) {
        if id > 0 {
            return Ok(id);
        }
    }
    db.execute(
        "INSERT OR IGNORE INTO executables (exe, name, cmdline, sha256) VALUES (?1, ?2, ?3, ?4)",
        params![exe, name, cmdline, sha256],
    )?;
    let id: i64 = db.query_row(
        "SELECT id FROM executables WHERE exe = ?1 AND name = ?2 AND cmdline = ?3 AND sha256 = ?4",
        params![exe, name, cmdline, sha256],
        |row| row.get(0),
    )?;
    cache.insert(key, id);
    Ok(id)
}

fn _flush_to_db(
    db: &mut Connection,
    traffic: &HashMap<TrafficKey, (u32, u32)>,
    exe_cache: &mut HashMap<ExeKey, i64>,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let tx = db.transaction()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    for (
        (
            exe_key,
            pexe_key,
            uid,
            lport,
            rport,
            laddr,
            raddr,
            domain,
            domain_source,
            domain_confidence,
            domain_status,
        ),
        (send, recv),
    ) in traffic.iter()
    {
        let exe_id = _get_or_insert_exe(
            &tx, exe_cache, &exe_key.0, &exe_key.1, &exe_key.2, &exe_key.3,
        )?;
        let pexe_id = _get_or_insert_exe(
            &tx,
            exe_cache,
            &pexe_key.0,
            &pexe_key.1,
            &pexe_key.2,
            &pexe_key.3,
        )?;

        tx.execute(
            "INSERT INTO connections
                (contime, send, recv, exe_id, pexe_id, uid, lport, rport, laddr, raddr, domain, domain_source, domain_confidence, domain_status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                now,
                send,
                recv,
                exe_id,
                pexe_id,
                uid,
                lport,
                rport,
                laddr,
                raddr,
                domain,
                domain_source,
                domain_confidence,
                domain_status,
            ],
        )?;
    }

    tx.commit()?;
    Ok(traffic.len())
}

fn non_empty_or(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests_storage;

mod remote;
pub use remote::*;
