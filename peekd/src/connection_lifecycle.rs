#![allow(dead_code, unused_imports)]

//! connection_lifecycle.rs: TCP connect/disconnect tracking (v2).
//!
//! Tracks when TCP connections are established and closed via BPF hooks:
//! - kretprobe/tcp_v4_connect (outbound)
//! - kretprobe/inet_csk_accept (inbound)
//! - kprobe/tcp_close (both directions)
//!
//! Populates connections_meta table with connect_t, close_t, direction.

use std::collections::HashMap;
use std::sync::Arc;
use std::net::IpAddr;
use tokio::sync::{Mutex, broadcast};
use crate::config::Config;
use crate::metrics::Metrics;

/// Direction of a TCP connection.
#[derive(Clone, Debug, PartialEq)]
pub enum Direction {
    Outbound,
    Inbound,
}

impl Direction {
    pub fn as_str(&self) -> &str {
        match self {
            Direction::Outbound => "outbound",
            Direction::Inbound => "inbound",
        }
    }
}

/// A TCP connection lifecycle event (connect or close).
#[derive(Clone, Debug)]
pub struct ConnectEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub exe: String,
    pub laddr: IpAddr,
    pub lport: u16,
    pub raddr: IpAddr,
    pub rport: u16,
    pub direction: Direction,
    pub event_type: ConnectEventType,
    pub timestamp: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ConnectEventType {
    Connect,
    Close,
}

/// Connection key for correlating connect/close events.
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct ConnKey {
    laddr: String,
    lport: u16,
    raddr: String,
    rport: u16,
}

const MAX_ACTIVE_CONNECTIONS: usize = 65536;

/// Active connection tracker.
///
/// Correlates connect and close events by socket address tuple.
/// When a close event arrives, computes duration and emits a complete
/// lifecycle record for storage. Evicts oldest entries when exceeding MAX_ACTIVE_CONNECTIONS.
pub struct ConnectionTracker {
    active: HashMap<ConnKey, ConnectEvent>,
    metrics: Arc<Metrics>,
}

impl ConnectionTracker {
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            active: HashMap::with_capacity(4096),
            metrics,
        }
    }

    /// Handle a connect event. Returns None (stored for later correlation).
    /// Evicts oldest entry if at capacity.
    pub fn on_connect(&mut self, event: ConnectEvent) -> Option<LifecycleRecord> {
        if self.active.len() >= MAX_ACTIVE_CONNECTIONS {
            // Evict oldest by timestamp
            if let Some(oldest_key) = self.active.iter()
                .min_by_key(|(_, v)| v.timestamp)
                .map(|(k, _)| k.clone())
            {
                self.active.remove(&oldest_key);
            }
        }
        let key = ConnKey {
            laddr: event.laddr.to_string(),
            lport: event.lport,
            raddr: event.raddr.to_string(),
            rport: event.rport,
        };
        self.active.insert(key, event);
        None
    }

    /// Handle a close event. Returns Some(record) if matching connect found.
    pub fn on_close(&mut self, event: ConnectEvent) -> Option<LifecycleRecord> {
        let key = ConnKey {
            laddr: event.laddr.to_string(),
            lport: event.lport,
            raddr: event.raddr.to_string(),
            rport: event.rport,
        };
        if let Some(connect) = self.active.remove(&key) {
            Some(LifecycleRecord {
                exe: connect.exe,
                laddr: connect.laddr,
                lport: connect.lport,
                raddr: connect.raddr,
                rport: connect.rport,
                connect_t: connect.timestamp,
                close_t: Some(event.timestamp),
                direction: connect.direction,
            })
        } else {
            // Close without matching connect (connection predates daemon start)
            Some(LifecycleRecord {
                exe: event.exe,
                laddr: event.laddr,
                lport: event.lport,
                raddr: event.raddr,
                rport: event.rport,
                connect_t: 0, // unknown
                close_t: Some(event.timestamp),
                direction: event.direction,
            })
        }
    }

    /// Get count of currently tracked active connections.
    pub fn active_count(&self) -> usize {
        self.active.len()
    }
}

/// Complete lifecycle record for a TCP connection (ready for storage).
#[derive(Clone, Debug)]
pub struct LifecycleRecord {
    pub exe: String,
    pub laddr: IpAddr,
    pub lport: u16,
    pub raddr: IpAddr,
    pub rport: u16,
    pub connect_t: i64,
    pub close_t: Option<i64>,
    pub direction: Direction,
}

/// Write lifecycle records to SQLite connections_meta table.
pub async fn write_meta(
    mut rx: tokio::sync::mpsc::Receiver<LifecycleRecord>,
    db: Arc<Mutex<rusqlite::Connection>>,
) {
    while let Some(record) = rx.recv().await {
        let db = db.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let conn = db.blocking_lock();
            conn.execute(
                "INSERT INTO connections_meta (exe, laddr, lport, raddr, rport, connect_t, close_t, direction)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    record.exe,
                    record.laddr.to_string(),
                    record.lport,
                    record.raddr.to_string(),
                    record.rport,
                    record.connect_t,
                    record.close_t,
                    record.direction.as_str(),
                ],
            )
        })
        .await;
    }
}

/// Create the connections_meta table if it doesn't exist.
pub fn create_table(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS connections_meta (
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
        CREATE INDEX IF NOT EXISTS idx_meta_raddr ON connections_meta(raddr);"
    )
}
