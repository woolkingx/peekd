#![allow(dead_code, unused_imports)]

//! resolver.rs: RawEvent → BpfEvent pipeline.
//!
//! Converts kernel events into fully resolved events by reading /proc,
//! consulting fd_cache, DNS map, and config.
//!
//! Responsibility: Given a RawEvent, populate all missing fields (exe, cmdline,
//! domain, etc) from various sources, returning a complete BpfEvent.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::sync::{Mutex, broadcast};
use lru::LruCache;

use peekd_common::{SendRecvEvent, SendRecv6Event, ExecEvent};
use crate::types::{RawEvent, BpfEvent};
use crate::config::Config;
use crate::fd_cache::FdCache;
use crate::dns::DnsMap;
use crate::metrics::Metrics;

/// PID_CACHE: LRU cache size for cmdline lookups (default 1024)
const PID_CACHE: usize = 1024;

/// Resolver: Convert RawEvent → BpfEvent with process/domain enrichment.
///
/// Owns fd_cache and cmdline_cache. Resolves exe paths, process names,
/// and domain info for each event.
pub struct Resolver {
    fd_cache: Arc<Mutex<FdCache>>,
    /// Cache key is (pid, starttime) to handle PID reuse correctly.
    /// starttime is read from /proc/{pid}/stat field 22 (in clock ticks).
    cmdline_cache: LruCache<(u32, u64), String>,
    config: Arc<Config>,
}

impl Resolver {
    /// Create a new Resolver with the given fd_cache and config.
    pub fn new(fd_cache: Arc<Mutex<FdCache>>, config: Arc<Config>) -> Self {
        Self {
            fd_cache,
            cmdline_cache: LruCache::new(std::num::NonZeroUsize::new(PID_CACHE).unwrap()),
            config,
        }
    }

    /// Resolve a single RawEvent into a complete BpfEvent.
    ///
    /// Returns None if event should be dropped (e.g., exec event when every_exe=false).
    pub async fn resolve(&mut self, raw: RawEvent, dns: &DnsMap) -> Option<BpfEvent> {
        match raw {
            RawEvent::SendV4(e) | RawEvent::RecvV4(e) => Some(self._resolve_sendrecv_v4(e, dns).await),
            RawEvent::SendV6(e) | RawEvent::RecvV6(e) => Some(self._resolve_sendrecv_v6(e, dns).await),
            RawEvent::Exec(e) => self._resolve_exec(e).await,
            RawEvent::Dns(_) | RawEvent::Dns6(_) => None, // DNS events consumed by dns module
            RawEvent::Connect(_) => None, // Connection lifecycle handled by connection_lifecycle module
        }
    }

    // Resolve IPv4 send/recv event
    async fn _resolve_sendrecv_v4(&mut self, raw: SendRecvEvent, dns: &DnsMap) -> BpfEvent {
        let (name, exe, fd_path) = self._resolve_process(raw.pid, raw.dev, raw.ino, &raw.comm).await;
        let (pname, pexe, pfd_path) = self._resolve_process(raw.ppid, raw.pdev, raw.pino, &raw.pcomm).await;
        let cmdline = self._get_cmdline(raw.pid).await;
        let pcmdline = self._get_cmdline(raw.ppid).await;

        let laddr = IpAddr::V4(Ipv4Addr::from(raw.saddr.swap_bytes()));
        let raddr = IpAddr::V4(Ipv4Addr::from(raw.daddr.swap_bytes()));
        let domain = crate::dns::lookup(dns, raddr).await;

        BpfEvent {
            pid: raw.pid,
            ppid: raw.ppid,
            uid: raw.uid,
            name,
            pname,
            exe,
            pexe,
            cmdline,
            pcmdline,
            fd_path,
            pfd_path,
            dev: raw.dev,
            ino: raw.ino,
            pdev: raw.pdev,
            pino: raw.pino,
            send: if raw.direction == 0 { raw.bytes as u32 } else { 0 },
            recv: if raw.direction == 1 { raw.bytes as u32 } else { 0 },
            lport: raw.sport,
            rport: raw.dport,
            laddr,
            raddr,
            domain,
            sha256: String::new(),
            psha256: String::new(),
            meta: crate::types::EventMeta::default(),
        }
    }

    // Resolve IPv6 send/recv event
    async fn _resolve_sendrecv_v6(&mut self, raw: SendRecv6Event, dns: &DnsMap) -> BpfEvent {
        let (name, exe, fd_path) = self._resolve_process(raw.pid, raw.dev, raw.ino, &raw.comm).await;
        let (pname, pexe, pfd_path) = self._resolve_process(raw.ppid, raw.pdev, raw.pino, &raw.pcomm).await;
        let cmdline = self._get_cmdline(raw.pid).await;
        let pcmdline = self._get_cmdline(raw.ppid).await;

        let laddr = IpAddr::V6(Ipv6Addr::from(raw.saddr));
        let raddr = IpAddr::V6(Ipv6Addr::from(raw.daddr));
        let domain = crate::dns::lookup(dns, raddr).await;

        BpfEvent {
            pid: raw.pid,
            ppid: raw.ppid,
            uid: raw.uid,
            name,
            pname,
            exe,
            pexe,
            cmdline,
            pcmdline,
            fd_path,
            pfd_path,
            dev: raw.dev,
            ino: raw.ino,
            pdev: raw.pdev,
            pino: raw.pino,
            send: if raw.direction == 0 { raw.bytes as u32 } else { 0 },
            recv: if raw.direction == 1 { raw.bytes as u32 } else { 0 },
            lport: raw.sport,
            rport: raw.dport,
            laddr,
            raddr,
            domain,
            sha256: String::new(),
            psha256: String::new(),
            meta: crate::types::EventMeta::default(),
        }
    }

    // Resolve exec events (subject to config.monitoring.every_exe filter)
    async fn _resolve_exec(&mut self, raw: ExecEvent) -> Option<BpfEvent> {
        if !self.config.monitoring.every_exe {
            return None;
        }

        let (name, exe, fd_path) = self._resolve_process(raw.pid, raw.dev, raw.ino, &raw.comm).await;
        let (pname, pexe, pfd_path) = self._resolve_process(raw.ppid, raw.pdev, raw.pino, &raw.pcomm).await;
        let cmdline = self._get_cmdline(raw.pid).await;
        let pcmdline = self._get_cmdline(raw.ppid).await;

        Some(BpfEvent {
            pid: raw.pid,
            ppid: raw.ppid,
            uid: raw.uid,
            name,
            pname,
            exe,
            pexe,
            cmdline,
            pcmdline,
            fd_path,
            pfd_path,
            dev: raw.dev,
            ino: raw.ino,
            pdev: raw.pdev,
            pino: raw.pino,
            send: 0,
            recv: 0,
            lport: u16::MAX,
            rport: u16::MAX,
            laddr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            raddr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            domain: String::new(),
            sha256: String::new(),
            psha256: String::new(),
            meta: crate::types::EventMeta::default(),
        })
    }

    // Resolve exe path, process name, and fd_path for a single process
    async fn _resolve_process(&mut self, pid: u32, dev: u64, ino: u64, comm: &[u8]) -> (String, String, String) {
        let comm_str = String::from_utf8_lossy(comm).trim_end_matches('\0').to_string();

        let (exe, _mod_cnt) = {
            let mut cache = self.fd_cache.lock().await;
            cache.get(dev, ino).unwrap_or((String::new(), 0))
        };

        // Fallback: read /proc/{pid}/exe when fd_cache misses
        let exe = if exe.is_empty() && pid > 0 {
            tokio::fs::read_link(format!("/proc/{}/exe", pid)).await
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default()
        } else {
            exe
        };

        // fd_path: the absolute exe path from fd_cache (for hasher fallback 1 inode verification).
        // Only set when we have a real cached path; empty triggers hasher fallback 2 (/proc/pid/exe).
        // Do NOT set to /proc/{pid}/exe here — that is hasher fallback 2's job.
        let fd_path = exe.clone();

        let name = if exe.is_empty() {
            comm_str
        } else {
            exe.split('/').last().unwrap_or(&comm_str).to_string()
        };

        (name, exe, fd_path)
    }

    // Get cmdline for a pid, using LRU cache with (pid, starttime) key to handle PID reuse.
    async fn _get_cmdline(&mut self, pid: u32) -> String {
        let starttime = _read_starttime(pid);
        let key = (pid, starttime);
        if let Some(cached) = self.cmdline_cache.get(&key) {
            return cached.clone();
        }

        let cmdline = self._read_cmdline(pid).await;
        self.cmdline_cache.put(key, cmdline.clone());
        cmdline
    }

    // Read /proc/{pid}/cmdline, null-separated args → space-joined
    async fn _read_cmdline(&self, pid: u32) -> String {
        let path = format!("/proc/{}/cmdline", pid);
        let data = tokio::fs::read(&path).await.unwrap_or_default();

        if data.is_empty() {
            return String::new();
        }

        let s = String::from_utf8_lossy(&data);
        s.split('\0')
            .filter(|arg| !arg.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    }

}

/// Read process starttime from /proc/{pid}/stat field 22 (clock ticks since boot).
/// Returns 0 on failure. Used as part of cache key to detect PID reuse.
fn _read_starttime(pid: u32) -> u64 {
    let path = format!("/proc/{}/stat", pid);
    let Ok(content) = std::fs::read_to_string(&path) else { return 0 };
    // stat format: "pid (comm) state ppid pgroup session tty_nr tpgid flags ... starttime"
    // starttime is field 22 (1-indexed). comm may contain spaces/parens, so find closing ')' first.
    let after_comm = content.rfind(')').map(|i| &content[i + 2..]).unwrap_or("");
    after_comm.split_whitespace().nth(19).and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// Run the resolver pipeline: subscribe to RawEvent broadcast, resolve, publish BpfEvent.
///
/// Receives RawEvent from broadcast, resolves each into BpfEvent, and broadcasts results.
/// Filters out exec events when config.monitoring.every_exe=false.
pub async fn run(
    mut rx: broadcast::Receiver<RawEvent>,
    tx: broadcast::Sender<BpfEvent>,
    fd_cache: Arc<Mutex<FdCache>>,
    dns: Arc<DnsMap>,
    config: Arc<Config>,
    metrics: Arc<Metrics>,
) {
    let mut resolver = Resolver::new(fd_cache, config);

    loop {
        match rx.recv().await {
            Ok(raw_event) => {
                if let Some(event) = resolver.resolve(raw_event, &dns).await {
                    if tx.send(event).is_err() {
                        // All receivers dropped, exit
                        break;
                    }
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!("resolver lagged, dropping {} events", n);
                metrics.events_dropped.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
            }
            Err(broadcast::error::RecvError::Closed) => {
                // Channel closed, exit
                break;
            }
        }
    }
}
