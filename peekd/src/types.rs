#![allow(dead_code, unused_imports)]

//! types.rs: Shared type definitions and extension traits.
//!
//! Defines:
//! - RawEvent: kernel event types from perf buffers
//! - BpfEvent: fully resolved event (main pipeline currency)
//! - ConnectionRow: storage-ready event for SQLite
//! - Extension traits: Sink, EventFilter, RemoteStorage
//! - NotifyMsg: inter-module communication for state + notify

use anyhow::Result;
use peekd_common::{
    BpfStatEvent, ConnectEventRaw, DnsEvent, DnsEvent6, ExecEvent, SendRecv6Event, SendRecvEvent,
};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::net::IpAddr;

/// RawEvent: Direct kernel output from perf buffers.
///
/// Variants map to perf map types:
/// - SendV4 / RecvV4: IPv4 send/recv events
/// - SendV6 / RecvV6: IPv6 send/recv events
/// - Exec: process execution
/// - Dns: DNS query events
#[derive(Clone, Debug)]
pub enum RawEvent {
    SendV4(SendRecvEvent),
    RecvV4(SendRecvEvent),
    SendV6(SendRecv6Event),
    RecvV6(SendRecv6Event),
    Exec(ExecEvent),
    Dns(DnsEvent),
    Dns6(DnsEvent6),
    Connect(ConnectEventRaw),
    BpfStat(BpfStatEvent),
}

/// EventMeta: Bit-mask encoding discovery flags for a BpfEvent.
///
/// NEW_EXE  (bit 0): exe path seen for the first time (normal — software install)
/// NEW_HASH (bit 1): new sha256 for an already-known exe (suspicious — possible tampering)
///
/// Using a u8 bit-mask keeps BpfEvent at 1 extra byte and allows future flags
/// (e.g., WHITELISTED, NEW_PEXE) without changing the wire format.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventMeta(pub u8);

impl EventMeta {
    pub const NEW_EXE: u8 = 1 << 0;
    pub const NEW_HASH: u8 = 1 << 1;

    #[inline(always)]
    pub fn is_new_exe(self) -> bool {
        self.0 & Self::NEW_EXE != 0
    }
    #[inline(always)]
    pub fn is_new_hash(self) -> bool {
        self.0 & Self::NEW_HASH != 0
    }
    #[inline(always)]
    pub fn set_new_exe(&mut self) {
        self.0 |= Self::NEW_EXE;
    }
    #[inline(always)]
    pub fn set_new_hash(&mut self) {
        self.0 |= Self::NEW_HASH;
    }
}

/// BpfEvent: Fully resolved event ready for storage/filtering/alerts.
///
/// Populated by resolver from RawEvent + /proc + fd_cache + DNS map.
/// Main currency of the processing pipeline.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BpfEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub name: String,
    pub pname: String,
    pub exe: String,
    pub pexe: String,
    pub cmdline: String,
    pub pcmdline: String,
    pub fd_path: String,
    pub pfd_path: String,
    pub dev: u64,
    pub ino: u64,
    pub pdev: u64,
    pub pino: u64,
    pub send: u32,
    pub recv: u32,
    pub lport: u16,
    pub rport: u16,
    pub laddr: IpAddr,
    pub raddr: IpAddr,
    pub domain: String,
    #[serde(default = "default_domain_source")]
    pub domain_source: String,
    #[serde(default = "default_domain_confidence")]
    pub domain_confidence: String,
    #[serde(default = "default_domain_status")]
    pub domain_status: String,
    pub sha256: String, // resolved by hasher before broadcast
    pub psha256: String,
    #[serde(default)]
    pub meta: EventMeta, // NEW_EXE | NEW_HASH discovery flags
}

fn default_domain_source() -> String {
    "unknown".to_string()
}

fn default_domain_confidence() -> String {
    "none".to_string()
}

fn default_domain_status() -> String {
    "unknown".to_string()
}

#[cfg(test)]
mod tests_event_meta {
    use super::*;

    #[test]
    fn default_is_zero() {
        let m = EventMeta::default();
        assert!(!m.is_new_exe());
        assert!(!m.is_new_hash());
        assert_eq!(m.0, 0);
    }

    #[test]
    fn bits_are_independent() {
        let mut m = EventMeta::default();
        m.set_new_exe();
        assert!(m.is_new_exe());
        assert!(!m.is_new_hash());

        m.set_new_hash();
        assert!(m.is_new_exe());
        assert!(m.is_new_hash());
        assert_eq!(m.0, EventMeta::NEW_EXE | EventMeta::NEW_HASH);
    }

    #[test]
    fn set_new_exe_is_idempotent() {
        let mut m = EventMeta::default();
        m.set_new_exe();
        m.set_new_exe();
        assert_eq!(m.0, EventMeta::NEW_EXE);
    }

    #[test]
    fn new_hash_does_not_set_new_exe() {
        let mut m = EventMeta::default();
        m.set_new_hash();
        assert!(!m.is_new_exe());
        assert!(m.is_new_hash());
    }
}

/// ConnectionRow: Storage-ready representation for SQLite.
///
/// Denormalized from BpfEvent for efficient write batching.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionRow {
    pub contime: i64,
    pub send: u32,
    pub recv: u32,
    pub exe: String,
    pub name: String,
    pub cmdline: String,
    pub sha256: String,
    pub pexe: String,
    pub pname: String,
    pub pcmdline: String,
    pub psha256: String,
    pub uid: u32,
    pub lport: u16,
    pub rport: u16,
    pub laddr: String,
    pub raddr: String,
    pub domain: String,
}

/// NotifyMsg: Messages from state or other modules to notify task.
///
/// Triggers D-Bus notifications and event logs.
#[derive(Clone, Debug)]
pub enum NotifyMsg {
    NewExe {
        pid: u32,
        exe: String,
        cmdline: String,
    },
    NewHash {
        exe: String,
        sha256: String,
    },
    Error {
        msg: String,
    },
}

/// Sink: Extension trait for event consumers.
///
/// Any module that writes events somewhere implements this.
/// Registered in main.rs, called by broadcast fan-out.
pub trait Sink: Send + 'static {
    fn write(
        &mut self,
        batch: &[BpfEvent],
    ) -> impl Future<Output = Result<(), Box<dyn std::error::Error>>> + Send;

    fn flush(&mut self) -> impl Future<Output = Result<(), Box<dyn std::error::Error>>> + Send {
        async { Ok(()) }
    }
}

/// EventFilter: Extension trait for filtering decisions.
///
/// Matches BpfEvent against rules (config, Lua, WASM, etc).
/// All filters must match for event to be broadcast.
pub trait EventFilter: Send + Sync + 'static {
    fn matches(&self, event: &BpfEvent) -> bool;
}

/// RemoteStorage: Extension trait for remote storage backends.
///
/// Future trait for ClickHouse, TimescaleDB, etc.
/// v1 uses local SQLite (Sink), v2 adds RemoteStorage sink.
pub trait RemoteStorage: Send + 'static {
    fn write_batch(
        &mut self,
        rows: &[ConnectionRow],
    ) -> impl Future<Output = Result<(), Box<dyn std::error::Error>>> + Send;
}
