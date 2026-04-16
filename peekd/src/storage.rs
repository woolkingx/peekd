#![allow(dead_code, unused_imports)]

//! storage.rs: Event persistence to SQLite.
//!
//! Architecture: one writer thread owns the Connection (no Mutex contention),
//! one read-only connection per CLI query (WAL allows unlimited concurrent readers).
//!
//! Writer thread receives WriterMsg via mpsc, batches traffic, flushes on interval.
//! CLI query path opens a fresh read-only connection — never blocks the writer.

use crate::types::{BpfEvent, Sink};
use crate::config::Config;
use tracing::{info, warn, error};
use std::collections::HashMap;
use std::sync::Arc;
use std::thread;
use tokio::time::{interval, Duration};
use tokio::sync::{broadcast, mpsc};
use rusqlite::{Connection, OpenFlags, params};

type TrafficKey = (String, String, String, u32, u16, String, String);
// (exe, pexe, cmdline, uid, rport, raddr, domain)
// lport excluded: ephemeral port changes per-session, preventing same-day aggregation

type ExeKey = (String, String, String, String);
// (exe, name, cmdline, sha256) — matches UNIQUE constraint in executables table

#[derive(Clone)]
struct ExeMetadata {
    name: String,
    cmdline: String,
    sha256: String,
    pname: String,
    pcmdline: String,
    psha256: String,
}

// ============================================================================
// Writer thread message
// ============================================================================

pub enum WriterMsg {
    Events(Vec<BpfEvent>),
    AlertEvent { ts: i64, rule: String, exe: String, raddr: String, domain: String, action: String },
    Flush,
    Shutdown,
}

// ============================================================================
// Writer thread: owns Connection, no Mutex needed
// ============================================================================

struct DbWriter {
    db: Connection,
    traffic: HashMap<TrafficKey, (u32, u32)>,
    exe_metadata: HashMap<String, ExeMetadata>,
    exe_id_cache: HashMap<ExeKey, i64>,
    retention_days: u32,
    event_count: u64,
}

impl DbWriter {
    fn new(db: Connection, retention_days: u32) -> Self {
        Self {
            db,
            traffic: HashMap::new(),
            exe_metadata: HashMap::new(),
            exe_id_cache: HashMap::new(),
            retention_days,
            event_count: 0,
        }
    }

    fn accumulate(&mut self, events: Vec<BpfEvent>) {
        for event in events {
            let exe_key = if event.exe.is_empty() { event.name.clone() } else { event.exe.clone() };
            let pexe_key = if event.pexe.is_empty() { event.pname.clone() } else { event.pexe.clone() };
            let traffic_key = (
                exe_key,
                pexe_key,
                event.cmdline.clone(),
                event.uid,
                event.rport,
                event.raddr.to_string(),
                event.domain.clone(),
            );
            let (send, recv) = self.traffic.entry(traffic_key).or_insert((0, 0));
            *send += event.send;
            *recv += event.recv;

            self.exe_metadata.entry(event.exe.clone()).or_insert_with(|| ExeMetadata {
                name: event.name.clone(),
                cmdline: event.cmdline.clone(),
                sha256: event.sha256.clone(),
                pname: event.pname.clone(),
                pcmdline: event.pcmdline.clone(),
                psha256: event.psha256.clone(),
            });
            self.exe_metadata.entry(event.pexe.clone()).or_insert_with(|| ExeMetadata {
                name: event.pname.clone(),
                cmdline: event.pcmdline.clone(),
                sha256: event.psha256.clone(),
                pname: String::new(),
                pcmdline: String::new(),
                psha256: String::new(),
            });

            self.event_count += 1;
        }
    }

    fn flush(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.traffic.is_empty() {
            return Ok(());
        }
        let traffic = std::mem::take(&mut self.traffic);
        let exe_metadata = std::mem::take(&mut self.exe_metadata);
        // exe_id_cache is NOT taken — it persists across flushes so DB lookups
        // are skipped for exe rows already inserted in previous flush cycles.
        _flush_to_db(&mut self.db, &traffic, &mut self.exe_id_cache, &exe_metadata)?;
        Ok(())
    }

    fn cleanup_retention(&mut self) {
        if let Err(e) = _cleanup_retention(&self.db, self.retention_days) {
            warn!("retention cleanup failed: {}", e);
        }
    }

    fn run(mut self, rx: std::sync::mpsc::Receiver<WriterMsg>) {
        let flush_secs = 5u64; // flush every 5s regardless of event volume
        let mut last_flush = std::time::Instant::now();
        let cleanup_interval = std::time::Duration::from_secs(
            ((self.retention_days as u64) * 86400 / 2).max(3600)
        );
        let mut last_cleanup = std::time::Instant::now();

        loop {
            // Blocking recv with timeout so we can flush on interval even with no messages
            match rx.recv_timeout(std::time::Duration::from_millis(500)) {
                Ok(WriterMsg::Events(events)) => {
                    self.accumulate(events);
                }
                Ok(WriterMsg::AlertEvent { ts, rule, exe, raddr, domain, action }) => {
                    if let Err(e) = self.db.execute(
                        "INSERT INTO alert_events (ts, rule, exe, raddr, domain, action) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![ts, rule, exe, raddr, domain, action],
                    ) {
                        error!("alert event insert failed: {}", e);
                    }
                }
                Ok(WriterMsg::Flush) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if last_flush.elapsed().as_secs() >= flush_secs || matches!(rx.try_recv(), Err(_)) {
                        if let Err(e) = self.flush() {
                            error!("storage flush failed: {}", e);
                        }
                        last_flush = std::time::Instant::now();
                    }
                }
                Ok(WriterMsg::Shutdown) => {
                    let _ = self.flush();
                    break;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    let _ = self.flush();
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

// ============================================================================
// Public run() function
// ============================================================================

pub type AlertEventSender = std::sync::mpsc::Sender<WriterMsg>;

/// Run the storage task.
///
/// Spawns a dedicated writer thread that owns the SQLite Connection.
/// Receives BpfEvent from broadcast, relays batches to writer via std::sync::mpsc.
/// Writer thread flushes on interval — no Mutex, no spawn_blocking per flush.
/// Returns the writer channel sender for alert events.
pub async fn run(
    mut rx: broadcast::Receiver<BpfEvent>,
    config: Arc<Config>,
    metrics: Arc<crate::metrics::Metrics>,
) -> Result<AlertEventSender, Box<dyn std::error::Error>> {
    let db_path = crate::config::db_path();
    info!("opening db: {}", db_path.display());
    // Ensure parent directory exists
    if let Some(parent) = db_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let db = Connection::open(&db_path)?;
    if let Err(e) = db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;") {
        warn!("WAL pragma failed (ignored): {}", e);
    }
    if let Err(e) = _init_schema(&db) {
        warn!("schema init failed: {}", e);
    }
    if let Err(e) = _cleanup_retention(&db, config.database.retention_days) {
        warn!("retention cleanup failed (ignored): {}", e);
    }

    // Writer thread: owns Connection, receives via std::sync::mpsc (not tokio)
    let (writer_tx, writer_rx) = std::sync::mpsc::channel::<WriterMsg>();
    let writer = DbWriter::new(db, config.database.retention_days);
    let writer_handle = thread::Builder::new()
        .name("peekd-db-writer".into())
        .spawn(move || writer.run(writer_rx))?;

    // Async relay: receive from broadcast, send batches to writer thread
    let mut batch: Vec<BpfEvent> = Vec::with_capacity(256);
    let mut flush_interval = interval(Duration::from_secs(config.database.write_limit_seconds));

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(event) => {
                        batch.push(event);
                        // Send batch when it reaches 256 events to bound memory
                        if batch.len() >= 256 {
                            let _ = writer_tx.send(WriterMsg::Events(std::mem::take(&mut batch)));
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("storage sink lagged, dropping {} events", n);
                        metrics.events_dropped.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
            _ = flush_interval.tick() => {
                if !batch.is_empty() {
                    let _ = writer_tx.send(WriterMsg::Events(std::mem::take(&mut batch)));
                }
                let _ = writer_tx.send(WriterMsg::Flush);
            }
        }
    }

    // Clone writer_tx before we move it into the shutdown task
    let writer_tx_ret = writer_tx.clone();

    // Final flush on shutdown: send remaining batch + Shutdown, then wait for writer thread
    if !batch.is_empty() {
        let _ = writer_tx.send(WriterMsg::Events(batch));
    }
    let _ = writer_tx.send(WriterMsg::Shutdown);
    // Block until writer thread finishes its final flush to avoid data loss on shutdown
    tokio::task::spawn_blocking(move || {
        if let Err(e) = writer_handle.join() {
            error!("storage writer thread panicked: {:?}", e);
        }
    }).await.ok();
    Ok(writer_tx_ret)
}

// ============================================================================
// Schema and helpers
// ============================================================================

fn _init_schema(db: &Connection) -> Result<(), Box<dyn std::error::Error>> {
    db.execute_batch(
        "PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS executables (
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
            domain  TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_contime ON connections(contime);
        CREATE INDEX IF NOT EXISTS idx_exe_id_contime ON connections(exe_id, contime);
        CREATE TABLE IF NOT EXISTS alert_events (
            id      INTEGER PRIMARY KEY,
            ts      INTEGER NOT NULL,
            rule    TEXT NOT NULL,
            exe     TEXT NOT NULL,
            raddr   TEXT NOT NULL,
            domain  TEXT NOT NULL DEFAULT '',
            action  TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_alert_ts ON alert_events(ts);"
    )?;
    Ok(())
}

fn _cleanup_retention(db: &Connection, retention_days: u32) -> Result<(), Box<dyn std::error::Error>> {
    let cutoff = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64) - (retention_days as i64 * 86400);
    db.execute("DELETE FROM connections WHERE contime < ?1", params![cutoff])?;
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
    let key = (exe.to_string(), name.to_string(), cmdline.to_string(), sha256.to_string());
    if let Some(&id) = cache.get(&key) {
        if id > 0 { return Ok(id); }
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
    exe_metadata: &HashMap<String, ExeMetadata>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tx = db.transaction()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    for ((exe, pexe, _cmdline, uid, rport, raddr, domain), (send, recv)) in traffic.iter() {
        let (exe_name, exe_cmdline, exe_sha256) = exe_metadata
            .get(exe)
            .map(|m| (m.name.as_str(), m.cmdline.as_str(), m.sha256.as_str()))
            .unwrap_or(("", "", ""));
        let (pexe_name, pexe_cmdline, pexe_sha256) = exe_metadata
            .get(pexe)
            .map(|m| (m.name.as_str(), m.cmdline.as_str(), m.sha256.as_str()))
            .unwrap_or(("", "", ""));

        let exe_id = _get_or_insert_exe(&tx, exe_cache, exe, exe_name, exe_cmdline, exe_sha256)?;
        let pexe_id = _get_or_insert_exe(&tx, exe_cache, pexe, pexe_name, pexe_cmdline, pexe_sha256)?;

        tx.execute(
            "INSERT INTO connections (contime, send, recv, exe_id, pexe_id, uid, lport, rport, laddr, raddr, domain)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, '', ?8, ?9)",
            params![now, send, recv, exe_id, pexe_id, uid, rport, raddr, domain],
        )?;
    }

    tx.commit()?;
    Ok(())
}

// ============================================================================
// v2: RemoteStorage implementations (unchanged)
// ============================================================================

#[cfg(feature = "remote-clickhouse")]
pub struct ClickHouseSink {
    url: String,
    client: reqwest::Client,
    batch: Vec<crate::types::ConnectionRow>,
    batch_size: usize,
}

#[cfg(feature = "remote-clickhouse")]
impl ClickHouseSink {
    pub fn new(url: &str, batch_size: usize) -> Self {
        Self {
            url: url.to_string(),
            client: reqwest::Client::new(),
            batch: Vec::with_capacity(batch_size),
            batch_size,
        }
    }
}

#[cfg(feature = "remote-clickhouse")]
impl crate::types::RemoteStorage for ClickHouseSink {
    async fn write_batch(
        &mut self,
        rows: &[crate::types::ConnectionRow],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(rows)?;
        self.client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .body(json)
            .send()
            .await?;
        Ok(())
    }
}

pub struct JsonFileSink {
    path: std::path::PathBuf,
}

impl JsonFileSink {
    pub fn new(path: &std::path::Path) -> Self {
        Self { path: path.to_path_buf() }
    }
}

impl crate::types::RemoteStorage for JsonFileSink {
    async fn write_batch(
        &mut self,
        rows: &[crate::types::ConnectionRow],
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write;
        let path = self.path.clone();
        let rows = rows.to_vec();
        let result = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)?;
            for row in &rows {
                let line = serde_json::to_string(row)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                writeln!(file, "{}", line)?;
            }
            Ok(())
        })
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        result.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }
}
