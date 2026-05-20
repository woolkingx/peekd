#![allow(dead_code, unused_imports)]

//! dns.rs: IP → domain name mapping cache.
//!
//! Maintains a map of IP addresses to canonical TLD-first domain names.
//! Populated by uprobe/getaddrinfo interception in BPF.
//! Consulted by resolver when building BpfEvent domain field.
//! Falls back to reverse DNS lookup when uprobe data is unavailable.

use crate::domain::{
    insert_evidence, DomainConfidence, DomainEvidence, DomainEvidenceStore, DomainSource,
};
use crate::metrics::Metrics;
use crate::types::RawEvent;
use lru::LruCache;
use peekd_common::{DnsEvent, DnsEvent6};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

/// DnsMap: IP → domain name cache with LRU eviction.
///
/// Thread-safe cache wrapping LruCache in Arc<RwLock<>>.
/// Stores domains in canonical TLD-first format (e.g., "com.example.www").
pub type DnsMap = Arc<RwLock<LruCache<IpAddr, String>>>;

/// Create new DnsMap with given capacity.
pub fn new_dns_map(capacity: usize) -> DnsMap {
    let capacity = std::num::NonZeroUsize::new(capacity)
        .unwrap_or_else(|| std::num::NonZeroUsize::new(10_000).unwrap());
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
    let domain = canonical_domain(domain);
    if !domain.is_empty() {
        dns.write().await.put(addr, domain);
    }
}

/// Insert high-confidence getaddrinfo evidence into the domain owner store.
pub async fn insert_getaddrinfo_evidence(
    store: &DomainEvidenceStore,
    addr: IpAddr,
    domain: &str,
    pid: Option<u32>,
) {
    let domain = canonical_domain(domain);
    if domain.is_empty() {
        return;
    }
    insert_evidence(
        store,
        DomainEvidence {
            addr,
            domain,
            source: DomainSource::GetAddrInfo,
            confidence: DomainConfidence::High,
            observed_at: unix_now(),
            expires_at: None,
            pid,
            process: None,
            ambiguous: false,
        },
    )
    .await;
}

/// Ingest a raw DNS response packet from a packet observer.
///
/// Returns the number of address evidences inserted. Query-only and malformed
/// packets are ignored.
pub async fn ingest_dns_response_packet(
    store: &DomainEvidenceStore,
    packet: &[u8],
    observed_at: i64,
) -> usize {
    let records = parse_dns_response(packet);
    let inserted = records.len();
    for record in records {
        let domain = canonical_domain(&record.domain);
        if domain.is_empty() {
            continue;
        }
        insert_evidence(
            store,
            DomainEvidence {
                addr: record.addr,
                domain,
                source: DomainSource::DnsAnswer,
                confidence: DomainConfidence::High,
                observed_at,
                expires_at: Some(observed_at + record.ttl as i64),
                pid: None,
                process: None,
                ambiguous: false,
            },
        )
        .await;
    }
    inserted
}

/// Convert raw IPv4 event addresses into the userspace IpAddr key format.
pub fn ipv4_event_addr(raw: u32) -> Ipv4Addr {
    Ipv4Addr::from(raw.swap_bytes())
}

/// Normalize hostnames to the storage/filter contract: lowercase TLD-first.
pub fn canonical_domain(domain: &str) -> String {
    let host = domain.trim().trim_end_matches('.');
    if host.is_empty() || IpAddr::from_str(host).is_ok() {
        return String::new();
    }

    let lower = host.to_ascii_lowercase();
    let labels: Vec<&str> = lower.split('.').filter(|label| !label.is_empty()).collect();
    if labels.is_empty() {
        return String::new();
    }
    if labels.len() == 1 {
        return labels[0].to_string();
    }

    labels.into_iter().rev().collect::<Vec<_>>().join(".")
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DnsAddressRecord {
    addr: IpAddr,
    domain: String,
    ttl: u32,
}

fn parse_dns_response(packet: &[u8]) -> Vec<DnsAddressRecord> {
    if packet.len() < 12 {
        return Vec::new();
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 == 0 {
        return Vec::new();
    }

    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut offset = 12;
    for _ in 0..qdcount {
        if read_dns_name(packet, &mut offset).is_none() || offset + 4 > packet.len() {
            return Vec::new();
        }
        offset += 4;
    }

    let mut records = Vec::new();
    let mut cname_aliases: HashMap<String, String> = HashMap::new();
    for _ in 0..ancount {
        let Some(name) = read_dns_name(packet, &mut offset) else {
            return Vec::new();
        };
        if offset + 10 > packet.len() {
            return Vec::new();
        }
        let rr_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let rr_class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let ttl = u32::from_be_bytes([
            packet[offset + 4],
            packet[offset + 5],
            packet[offset + 6],
            packet[offset + 7],
        ]);
        let rdlen = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > packet.len() {
            return Vec::new();
        }
        let rdata_offset = offset;
        offset += rdlen;

        if rr_class != 1 {
            continue;
        }
        match rr_type {
            1 if rdlen == 4 => {
                let domain = cname_aliases.get(&name).unwrap_or(&name).clone();
                records.push(DnsAddressRecord {
                    addr: IpAddr::V4(Ipv4Addr::new(
                        packet[rdata_offset],
                        packet[rdata_offset + 1],
                        packet[rdata_offset + 2],
                        packet[rdata_offset + 3],
                    )),
                    domain,
                    ttl,
                });
            }
            28 if rdlen == 16 => {
                let mut bytes = [0_u8; 16];
                bytes.copy_from_slice(&packet[rdata_offset..rdata_offset + 16]);
                let domain = cname_aliases.get(&name).unwrap_or(&name).clone();
                records.push(DnsAddressRecord {
                    addr: IpAddr::V6(Ipv6Addr::from(bytes)),
                    domain,
                    ttl,
                });
            }
            5 => {
                let mut rdata_name_offset = rdata_offset;
                if let Some(target) = read_dns_name(packet, &mut rdata_name_offset) {
                    cname_aliases.insert(target, name);
                }
            }
            _ => {}
        }
    }
    records
}

fn read_dns_name(packet: &[u8], offset: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut cursor = *offset;
    let mut jumped = false;
    let mut jumps = 0;

    loop {
        let len = *packet.get(cursor)?;
        if len & 0xc0 == 0xc0 {
            let next = *packet.get(cursor + 1)? as usize;
            let pointer = (((len & 0x3f) as usize) << 8) | next;
            if pointer >= packet.len() {
                return None;
            }
            if !jumped {
                *offset = cursor + 2;
            }
            cursor = pointer;
            jumped = true;
            jumps += 1;
            if jumps > 8 {
                return None;
            }
            continue;
        }
        if len == 0 {
            if !jumped {
                *offset = cursor + 1;
            }
            break;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        cursor += 1;
        let end = cursor + len as usize;
        if end > packet.len() {
            return None;
        }
        labels.push(std::str::from_utf8(&packet[cursor..end]).ok()?.to_string());
        cursor = end;
    }

    Some(labels.join("."))
}

/// Background task: listen for DNS BPF events, update DnsMap.
///
/// Subscribes to broadcast receiver for RawEvent::Dns variants.
/// Extracts query name and response IP, converts to TLD-first, inserts into DnsMap.
pub async fn run(
    mut rx: broadcast::Receiver<RawEvent>,
    dns: DnsMap,
    evidence_store: DomainEvidenceStore,
    metrics: Arc<Metrics>,
) {
    loop {
        match rx.recv().await {
            Ok(RawEvent::Dns(event)) => {
                _handle_dns_event(&event, &dns, &evidence_store).await;
            }
            Ok(RawEvent::Dns6(event)) => {
                _handle_dns6_event(&event, &dns, &evidence_store).await;
            }
            Ok(_) => {}
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!("dns task lagged, dropping {} events", n);
                metrics.record_broadcast_lag("dns", n);
            }
            Err(broadcast::error::RecvError::Closed) => {
                // Channel closed, exit task
                break;
            }
        }
    }
}

/// Handle a single DNS event: extract IP and domain, insert into cache.
async fn _handle_dns_event(event: &DnsEvent, dns: &DnsMap, evidence_store: &DomainEvidenceStore) {
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
        let ip = IpAddr::V4(ipv4_event_addr(event.daddr));
        insert(dns, ip, name_str).await;
        insert_getaddrinfo_evidence(evidence_store, ip, name_str, Some(event.pid)).await;
    }
}

/// Handle a single DNS6 event: extract IPv6 address and domain, insert into cache.
async fn _handle_dns6_event(event: &DnsEvent6, dns: &DnsMap, evidence_store: &DomainEvidenceStore) {
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

    if event.daddr.iter().any(|byte| *byte != 0) {
        let ip = IpAddr::V6(std::net::Ipv6Addr::from(event.daddr));
        insert(dns, ip, name_str).await;
        insert_getaddrinfo_evidence(evidence_store, ip, name_str, Some(event.pid)).await;
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests_dns;
