use super::*;
use crate::domain::{
    insert_evidence, DomainConfidence, DomainEvidence, DomainEvidenceStore, DomainSource,
};
use crate::fd_cache::{FdCache, FdEntry};
use peekd_common::{DIRECTION_RECV, DIRECTION_SEND};

fn comm(name: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let bytes = name.as_bytes();
    let len = bytes.len().min(out.len());
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

fn raw_ipv4(addr: Ipv4Addr) -> u32 {
    u32::from(addr).swap_bytes()
}

async fn resolver_with_fd(dev: u64, ino: u64, exe: &str, store: DomainEvidenceStore) -> Resolver {
    let metrics = Arc::new(Metrics::default());
    let fd_cache = Arc::new(Mutex::new(FdCache::new(None, 16, metrics)));
    {
        let mut cache = fd_cache.lock().await;
        cache.insert(
            dev,
            ino,
            FdEntry {
                fd: None,
                fd_path: exe.to_string(),
                exe: exe.to_string(),
                mod_cnt: 0,
            },
        );
    }
    Resolver::new(
        fd_cache,
        Arc::new(Config::default()),
        DomainRouter::new(store),
    )
}

async fn insert_domain(store: &DomainEvidenceStore, addr: IpAddr, domain: &str) {
    insert_evidence(
        store,
        DomainEvidence {
            addr,
            domain: domain.to_string(),
            source: DomainSource::GetAddrInfo,
            confidence: DomainConfidence::High,
            observed_at: 1,
            expires_at: None,
            pid: None,
            process: None,
            ambiguous: false,
        },
    )
    .await;
}

#[tokio::test]
async fn sendrecv_v4_resolves_fd_cache_dns_and_direction() {
    let dns = crate::dns::new_dns_map(16);
    let store = crate::domain::new_domain_store(16);
    insert_domain(
        &store,
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        "com.example.www",
    )
    .await;
    let mut resolver = resolver_with_fd(7, 11, "/usr/bin/curl", store).await;

    let event = resolver
        .resolve(
            RawEvent::SendV4(SendRecvEvent {
                pid: 0,
                ppid: 0,
                uid: 1000,
                dev: 7,
                ino: 11,
                pdev: 0,
                pino: 0,
                comm: comm("curl"),
                pcomm: comm("parent"),
                saddr: raw_ipv4(Ipv4Addr::new(10, 0, 0, 2)),
                daddr: raw_ipv4(Ipv4Addr::new(93, 184, 216, 34)),
                sport: 40000,
                dport: 443,
                bytes: 1234,
                direction: DIRECTION_SEND,
                _pad: [0; 7],
            }),
            &dns,
        )
        .await
        .unwrap();

    assert_eq!(event.exe, "/usr/bin/curl");
    assert_eq!(event.name, "curl");
    assert_eq!(event.fd_path, "/usr/bin/curl");
    assert_eq!(event.laddr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    assert_eq!(event.raddr, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
    assert_eq!(event.domain, "com.example.www");
    assert_eq!(event.domain_source, "getaddrinfo");
    assert_eq!(event.domain_confidence, "high");
    assert_eq!(event.domain_status, "direct_dns_seen");
    assert_eq!(event.send, 1234);
    assert_eq!(event.recv, 0);
}

#[tokio::test]
async fn sendrecv_v4_recv_direction_moves_bytes_to_recv() {
    let dns = crate::dns::new_dns_map(16);
    let store = crate::domain::new_domain_store(16);
    let mut resolver = resolver_with_fd(3, 5, "/usr/bin/server", store).await;

    let event = resolver
        .resolve(
            RawEvent::RecvV4(SendRecvEvent {
                pid: 0,
                ppid: 0,
                uid: 1000,
                dev: 3,
                ino: 5,
                pdev: 0,
                pino: 0,
                comm: comm("server"),
                pcomm: comm("parent"),
                saddr: raw_ipv4(Ipv4Addr::new(10, 0, 0, 2)),
                daddr: raw_ipv4(Ipv4Addr::new(198, 51, 100, 3)),
                sport: 8080,
                dport: 50100,
                bytes: 777,
                direction: DIRECTION_RECV,
                _pad: [0; 7],
            }),
            &dns,
        )
        .await
        .unwrap();

    assert_eq!(event.send, 0);
    assert_eq!(event.recv, 777);
    assert_eq!(event.domain, "");
    assert_eq!(event.domain_status, "unknown");
}

#[tokio::test]
async fn proxy_ingress_is_marked_without_destination_domain() {
    let dns = crate::dns::new_dns_map(16);
    let store = crate::domain::new_domain_store(16);
    insert_domain(&store, IpAddr::V4(Ipv4Addr::LOCALHOST), "com.wrong").await;
    let mut resolver = resolver_with_fd(3, 5, "/usr/bin/curl", store).await;

    let event = resolver
        .resolve(
            RawEvent::SendV4(SendRecvEvent {
                pid: 0,
                ppid: 0,
                uid: 1000,
                dev: 3,
                ino: 5,
                pdev: 0,
                pino: 0,
                comm: comm("curl"),
                pcomm: comm("parent"),
                saddr: raw_ipv4(Ipv4Addr::new(127, 0, 0, 1)),
                daddr: raw_ipv4(Ipv4Addr::LOCALHOST),
                sport: 50100,
                dport: 7890,
                bytes: 100,
                direction: DIRECTION_SEND,
                _pad: [0; 7],
            }),
            &dns,
        )
        .await
        .unwrap();

    assert_eq!(event.domain, "");
    assert_eq!(event.domain_source, "unknown");
    assert_eq!(event.domain_confidence, "none");
    assert_eq!(event.domain_status, "proxy_ingress");
}

#[tokio::test]
async fn exec_event_is_dropped_when_every_exe_is_disabled() {
    let dns = crate::dns::new_dns_map(16);
    let store = crate::domain::new_domain_store(16);
    let mut resolver = resolver_with_fd(1, 2, "/usr/bin/true", store).await;

    let event = resolver
        .resolve(
            RawEvent::Exec(ExecEvent {
                pid: 0,
                ppid: 0,
                uid: 0,
                dev: 1,
                ino: 2,
                pdev: 0,
                pino: 0,
                comm: comm("true"),
                pcomm: comm("parent"),
                filename: [0; 256],
                _pad: [0; 16],
            }),
            &dns,
        )
        .await;

    assert!(event.is_none());
}
