#![allow(dead_code, unused_imports)]

//! dns.rs: IP → domain name mapping cache.
//!
//! Maintains a map of IP addresses to resolved domain names in normal format.
//! Populated by uprobe/getaddrinfo interception in BPF.
//! Consulted by resolver when building BpfEvent domain field.
//! Falls back to reverse DNS lookup when uprobe data is unavailable.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use lru::LruCache;
use crate::types::RawEvent;
use crate::metrics::Metrics;
use peekd_common::{DnsEvent, DnsEvent6};

/// DnsMap: IP → domain name cache with LRU eviction.
///
/// Thread-safe cache wrapping LruCache in Arc<RwLock<>>.
/// Stores domains in normal format (e.g., "www.example.com").
pub type DnsMap = Arc<RwLock<LruCache<IpAddr, String>>>;

/// Create new DnsMap with given capacity.
pub fn new_dns_map(capacity: usize) -> DnsMap {
    let capacity = std::num::NonZeroUsize::new(capacity).unwrap_or_else(|| {
        std::num::NonZeroUsize::new(10_000).unwrap()
    });
    Arc::new(RwLock::new(LruCache::new(capacity)))
}


/// Lookup domain for IP address, returns empty string if not found.
/// Uses read lock + peek() — does not update LRU order on read.
/// Tradeoff: hot entries may be evicted slightly sooner, but concurrent
/// lookups don't block each other or block inserts.
pub async fn lookup(dns: &DnsMap, addr: IpAddr) -> String {
    dns.read().await.peek(&addr).cloned().unwrap_or_default()
}

/// Insert DNS event mapping.
pub async fn insert(dns: &DnsMap, addr: IpAddr, domain: &str) {
    let domain = domain.trim_end_matches('.');
    if !domain.is_empty() {
        dns.write().await.put(addr, domain.to_string());
    }
}

/// Background task: listen for DNS BPF events, update DnsMap.
///
/// Subscribes to broadcast receiver for RawEvent::Dns variants.
/// Extracts query name and response IP, converts to TLD-first, inserts into DnsMap.
pub async fn run(
    mut rx: broadcast::Receiver<RawEvent>,
    dns: DnsMap,
    metrics: Arc<Metrics>,
) {
    loop {
        match rx.recv().await {
            Ok(RawEvent::Dns(event)) => {
                _handle_dns_event(&event, &dns).await;
            }
            Ok(RawEvent::Dns6(event)) => {
                _handle_dns6_event(&event, &dns).await;
            }
            Ok(_) => {}
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!("dns task lagged, dropping {} events", n);
                metrics.events_dropped.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
            }
            Err(broadcast::error::RecvError::Closed) => {
                // Channel closed, exit task
                break;
            }
        }
    }
}

/// Handle a single DNS event: extract IP and domain, insert into cache.
async fn _handle_dns_event(event: &DnsEvent, dns: &DnsMap) {
    let name_cstr = &event.name;
    let name_str = match std::ffi::CStr::from_bytes_until_nul(name_cstr) {
        Ok(cstr) => match cstr.to_str() {
            Ok(s) => s,
            Err(_) => return,
        },
        Err(_) => return,
    };

    // Skip if result is an IP address
    if IpAddr::from_str(name_str).is_ok() {
        return;
    }

    // Insert IPv4 mapping
    if event.daddr != 0 {
        let ip = IpAddr::V4(std::net::Ipv4Addr::from(event.daddr));
        insert(dns, ip, name_str).await;
    }

}

/// Handle a single DNS6 event: extract IPv6 address and domain, insert into cache.
async fn _handle_dns6_event(event: &DnsEvent6, dns: &DnsMap) {
    let name_cstr = &event.name;
    let name_str = match std::ffi::CStr::from_bytes_until_nul(name_cstr) {
        Ok(cstr) => match cstr.to_str() {
            Ok(s) => s,
            Err(_) => return,
        },
        Err(_) => return,
    };

    if IpAddr::from_str(name_str).is_ok() {
        return;
    }

    if event.daddr != 0 {
        let ip = IpAddr::V6(std::net::Ipv6Addr::from(event.daddr));
        insert(dns, ip, name_str).await;
    }
}

