#![allow(dead_code, unused_imports)]

//! domain.rs: Domain evidence owner and routing policy.
//!
//! Collectors insert `DomainEvidence`; resolver asks `DomainRouter` for the
//! per-connection `DomainResolution`.

use lru::LruCache;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::RwLock;

mod mihomo;
mod ptr;
mod sni;

pub use mihomo::*;
pub use ptr::*;
pub use sni::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DomainSource {
    DnsAnswer,
    GetAddrInfo,
    MihomoApi,
    Sni,
    Ptr,
    Unknown,
}

impl DomainSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            DomainSource::DnsAnswer => "dns_answer",
            DomainSource::GetAddrInfo => "getaddrinfo",
            DomainSource::MihomoApi => "mihomo_api",
            DomainSource::Sni => "sni",
            DomainSource::Ptr => "ptr",
            DomainSource::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DomainConfidence {
    High,
    Medium,
    Low,
    None,
}

impl DomainConfidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            DomainConfidence::High => "high",
            DomainConfidence::Medium => "medium",
            DomainConfidence::Low => "low",
            DomainConfidence::None => "none",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DomainStatus {
    DirectDnsSeen,
    ProxyIngress,
    ProxyEgress,
    SniSeen,
    PtrOnly,
    Unknown,
}

impl DomainStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            DomainStatus::DirectDnsSeen => "direct_dns_seen",
            DomainStatus::ProxyIngress => "proxy_ingress",
            DomainStatus::ProxyEgress => "proxy_egress",
            DomainStatus::SniSeen => "sni_seen",
            DomainStatus::PtrOnly => "ptr_only",
            DomainStatus::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainEvidence {
    pub addr: IpAddr,
    pub domain: String,
    pub source: DomainSource,
    pub confidence: DomainConfidence,
    pub observed_at: i64,
    pub expires_at: Option<i64>,
    pub pid: Option<u32>,
    pub process: Option<String>,
    pub ambiguous: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainContext {
    pub pid: u32,
    pub name: String,
    pub exe: String,
    pub raddr: IpAddr,
    pub rport: u16,
    pub now: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainResolution {
    pub domain: String,
    pub source: DomainSource,
    pub confidence: DomainConfidence,
    pub status: DomainStatus,
    pub ambiguous: bool,
}

impl Default for DomainResolution {
    fn default() -> Self {
        Self {
            domain: String::new(),
            source: DomainSource::Unknown,
            confidence: DomainConfidence::None,
            status: DomainStatus::Unknown,
            ambiguous: false,
        }
    }
}

pub type DomainEvidenceStore = Arc<RwLock<LruCache<IpAddr, Vec<DomainEvidence>>>>;

const MAX_EVIDENCE_PER_ADDR: usize = 16;

pub fn new_domain_store(capacity: usize) -> DomainEvidenceStore {
    let capacity = std::num::NonZeroUsize::new(capacity)
        .unwrap_or_else(|| std::num::NonZeroUsize::new(10_000).unwrap());
    Arc::new(RwLock::new(LruCache::new(capacity)))
}

pub async fn insert_evidence(store: &DomainEvidenceStore, evidence: DomainEvidence) {
    let mut guard = store.write().await;
    let list = guard.get_or_insert_mut(evidence.addr, Vec::new);
    list.retain(|existing| !is_expired(existing, evidence.observed_at));
    if let Some(existing) = list.iter_mut().find(|existing| {
        existing.source == evidence.source
            && existing.domain == evidence.domain
            && existing.pid == evidence.pid
    }) {
        *existing = evidence;
        return;
    }
    list.push(evidence);
    list.sort_by(|left, right| {
        source_rank(&left.source)
            .cmp(&source_rank(&right.source))
            .then_with(|| right.observed_at.cmp(&left.observed_at))
    });
    list.truncate(MAX_EVIDENCE_PER_ADDR);
}

pub async fn insert_mihomo_evidence(
    store: &DomainEvidenceStore,
    addr: IpAddr,
    domain: &str,
    observed_at: i64,
    expires_at: Option<i64>,
) {
    insert_domain_evidence(
        store,
        addr,
        domain,
        DomainSource::MihomoApi,
        DomainConfidence::High,
        observed_at,
        expires_at,
    )
    .await;
}

pub async fn insert_ptr_evidence(
    store: &DomainEvidenceStore,
    addr: IpAddr,
    ptr_name: &str,
    observed_at: i64,
) -> bool {
    let domain = canonical_domain(ptr_name);
    if domain.is_empty() {
        return false;
    }
    insert_evidence(
        store,
        DomainEvidence {
            addr,
            domain,
            source: DomainSource::Ptr,
            confidence: DomainConfidence::Low,
            observed_at,
            expires_at: Some(observed_at + 3600),
            pid: None,
            process: None,
            ambiguous: false,
        },
    )
    .await;
    true
}

async fn insert_domain_evidence(
    store: &DomainEvidenceStore,
    addr: IpAddr,
    domain: &str,
    source: DomainSource,
    confidence: DomainConfidence,
    observed_at: i64,
    expires_at: Option<i64>,
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
            source,
            confidence,
            observed_at,
            expires_at,
            pid: None,
            process: None,
            ambiguous: false,
        },
    )
    .await;
}

#[derive(Clone)]
pub struct DomainRouter {
    store: DomainEvidenceStore,
    proxy_endpoints: Vec<(IpAddr, u16)>,
}

impl DomainRouter {
    pub fn new(store: DomainEvidenceStore) -> Self {
        Self {
            store,
            proxy_endpoints: vec![(IpAddr::V4(Ipv4Addr::LOCALHOST), 7890)],
        }
    }

    pub async fn resolve(&self, context: &DomainContext) -> DomainResolution {
        if self.is_proxy_ingress(context.raddr, context.rport) {
            return DomainResolution {
                status: DomainStatus::ProxyIngress,
                ..DomainResolution::default()
            };
        }

        let Some(evidence) = self.best_evidence(context).await else {
            return DomainResolution::default();
        };

        DomainResolution {
            domain: evidence.domain.clone(),
            source: evidence.source.clone(),
            confidence: evidence.confidence.clone(),
            status: status_for_source(&evidence.source),
            ambiguous: evidence.ambiguous,
        }
    }

    pub async fn resolve_with_ptr_fallback(&self, context: &DomainContext) -> DomainResolution {
        let resolved = self.resolve(context).await;
        if resolved.status != DomainStatus::Unknown {
            return resolved;
        }

        let addr = context.raddr;
        let Ok(Some(ptr_name)) = tokio::task::spawn_blocking(move || reverse_ptr_name(addr)).await
        else {
            return resolved;
        };
        if !insert_ptr_evidence(&self.store, addr, &ptr_name, context.now).await {
            return resolved;
        }
        self.resolve(context).await
    }

    fn is_proxy_ingress(&self, addr: IpAddr, port: u16) -> bool {
        self.proxy_endpoints.contains(&(addr, port))
    }

    async fn best_evidence(&self, context: &DomainContext) -> Option<DomainEvidence> {
        let guard = self.store.read().await;
        guard
            .peek(&context.raddr)?
            .iter()
            .filter(|evidence| !is_expired(evidence, context.now))
            .min_by_key(|evidence| source_rank(&evidence.source))
            .cloned()
    }
}

fn is_expired(evidence: &DomainEvidence, now: i64) -> bool {
    evidence
        .expires_at
        .is_some_and(|expires_at| expires_at <= now)
}

fn source_rank(source: &DomainSource) -> u8 {
    match source {
        DomainSource::DnsAnswer => 0,
        DomainSource::MihomoApi => 1,
        DomainSource::GetAddrInfo => 2,
        DomainSource::Sni => 3,
        DomainSource::Ptr => 4,
        DomainSource::Unknown => 5,
    }
}

fn status_for_source(source: &DomainSource) -> DomainStatus {
    match source {
        DomainSource::DnsAnswer | DomainSource::GetAddrInfo => DomainStatus::DirectDnsSeen,
        DomainSource::MihomoApi => DomainStatus::ProxyEgress,
        DomainSource::Sni => DomainStatus::SniSeen,
        DomainSource::Ptr => DomainStatus::PtrOnly,
        DomainSource::Unknown => DomainStatus::Unknown,
    }
}

pub fn canonical_domain(domain: &str) -> String {
    let host = domain.trim().trim_end_matches('.');
    if host.is_empty() || host.parse::<IpAddr>().is_ok() {
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

#[cfg(test)]
mod tests_domain;
