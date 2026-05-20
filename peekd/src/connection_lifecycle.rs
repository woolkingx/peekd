#![allow(dead_code, unused_imports)]

//! connection_lifecycle.rs: TCP connect/disconnect tracking (v2).
//!
//! Tracks when TCP connections are established and closed via BPF hooks:
//! - kretprobe/tcp_v4_connect (outbound)
//! - kretprobe/inet_csk_accept (inbound)
//! - kprobe/tcp_close (both directions)
//!
//! Populates connections_meta table with connect_t, close_t, direction.

use crate::config::Config;
use crate::metrics::Metrics;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::broadcast;

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
            if let Some(oldest_key) = self
                .active
                .iter()
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

#[cfg(test)]
mod tests_connection_lifecycle {
    use super::*;

    fn event(event_type: ConnectEventType, timestamp: i64) -> ConnectEvent {
        ConnectEvent {
            pid: 100,
            ppid: 1,
            uid: 1000,
            exe: "/usr/bin/curl".to_string(),
            laddr: "127.0.0.1".parse().unwrap(),
            lport: 40000,
            raddr: "1.2.3.4".parse().unwrap(),
            rport: 443,
            direction: Direction::Outbound,
            event_type,
            timestamp,
        }
    }

    #[test]
    fn close_event_emits_lifecycle_record() {
        let metrics = Arc::new(Metrics::default());
        let mut tracker = ConnectionTracker::new(metrics);

        assert!(tracker
            .on_connect(event(ConnectEventType::Connect, 10))
            .is_none());
        let record = tracker
            .on_close(event(ConnectEventType::Close, 20))
            .unwrap();

        assert_eq!(record.exe, "/usr/bin/curl");
        assert_eq!(record.connect_t, 10);
        assert_eq!(record.close_t, Some(20));
        assert_eq!(record.direction, Direction::Outbound);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn close_without_connect_emits_unknown_connect_time() {
        let metrics = Arc::new(Metrics::default());
        let mut tracker = ConnectionTracker::new(metrics);

        let record = tracker
            .on_close(event(ConnectEventType::Close, 20))
            .unwrap();

        assert_eq!(record.connect_t, 0);
        assert_eq!(record.close_t, Some(20));
    }
}
