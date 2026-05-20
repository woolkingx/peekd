use super::*;

fn evidence(addr: IpAddr, domain: &str, source: DomainSource) -> DomainEvidence {
    DomainEvidence {
        addr,
        domain: domain.to_string(),
        source,
        confidence: DomainConfidence::High,
        observed_at: 10,
        expires_at: Some(100),
        pid: None,
        process: None,
        ambiguous: false,
    }
}

fn context(addr: IpAddr, port: u16) -> DomainContext {
    DomainContext {
        pid: 42,
        name: "curl".to_string(),
        exe: "/usr/bin/curl".to_string(),
        raddr: addr,
        rport: port,
        now: 50,
    }
}

#[tokio::test]
async fn source_priority_prefers_dns_answer_over_getaddrinfo_sni_ptr() {
    let addr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    let store = new_domain_store(16);
    insert_evidence(&store, evidence(addr, "ptr.example", DomainSource::Ptr)).await;
    insert_evidence(&store, evidence(addr, "sni.example", DomainSource::Sni)).await;
    insert_evidence(
        &store,
        evidence(addr, "ga.example", DomainSource::GetAddrInfo),
    )
    .await;
    insert_evidence(
        &store,
        evidence(addr, "dns.example", DomainSource::DnsAnswer),
    )
    .await;

    let router = DomainRouter::new(store);
    let resolved = router.resolve(&context(addr, 443)).await;

    assert_eq!(resolved.domain, "dns.example");
    assert_eq!(resolved.source, DomainSource::DnsAnswer);
    assert_eq!(resolved.status, DomainStatus::DirectDnsSeen);
}

#[tokio::test]
async fn source_priority_prefers_mihomo_before_getaddrinfo() {
    let addr = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 10));
    let store = new_domain_store(16);
    insert_evidence(
        &store,
        evidence(addr, "ga.example", DomainSource::GetAddrInfo),
    )
    .await;
    insert_mihomo_evidence(&store, addr, "proxy.example", 10, Some(90)).await;

    let router = DomainRouter::new(store);
    let resolved = router.resolve(&context(addr, 443)).await;

    assert_eq!(resolved.domain, "example.proxy");
    assert_eq!(resolved.source, DomainSource::MihomoApi);
    assert_eq!(resolved.status, DomainStatus::ProxyEgress);
}

#[tokio::test]
async fn source_priority_uses_sni_before_ptr() {
    let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    let store = new_domain_store(16);
    insert_evidence(&store, evidence(addr, "ptr.example", DomainSource::Ptr)).await;
    insert_evidence(&store, evidence(addr, "sni.example", DomainSource::Sni)).await;

    let router = DomainRouter::new(store);
    let resolved = router.resolve(&context(addr, 443)).await;

    assert_eq!(resolved.domain, "sni.example");
    assert_eq!(resolved.status, DomainStatus::SniSeen);
}

#[tokio::test]
async fn ptr_evidence_is_low_confidence_fallback() {
    let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20));
    let store = new_domain_store(16);
    assert!(insert_ptr_evidence(&store, addr, "PTR.Example.COM.", 10).await);

    let router = DomainRouter::new(store);
    let resolved = router.resolve(&context(addr, 443)).await;

    assert_eq!(resolved.domain, "com.example.ptr");
    assert_eq!(resolved.source, DomainSource::Ptr);
    assert_eq!(resolved.confidence, DomainConfidence::Low);
    assert_eq!(resolved.status, DomainStatus::PtrOnly);
}

#[tokio::test]
async fn mihomo_dns_json_ingest_accepts_map_and_array_shapes() {
    let store = new_domain_store(16);
    let body = r#"{
        "fakeip": {"198.18.0.1": "alpha.example.com"},
        "entries": [
            {"fake_ip": "198.18.0.2", "domain": "beta.example.com"}
        ]
    }"#;

    assert_eq!(ingest_mihomo_dns_json(&store, body, 10, 60).await, 2);

    let router = DomainRouter::new(store);
    let first = router
        .resolve(&context(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)), 443))
        .await;
    let second = router
        .resolve(&context(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)), 443))
        .await;
    assert_eq!(first.domain, "com.example.alpha");
    assert_eq!(first.source, DomainSource::MihomoApi);
    assert_eq!(second.domain, "com.example.beta");
    assert_eq!(second.status, DomainStatus::ProxyEgress);
}

#[tokio::test]
async fn mihomo_dns_json_ingest_rejects_oversized_body() {
    let store = new_domain_store(16);
    let body = " ".repeat(256 * 1024 + 1);

    assert_eq!(ingest_mihomo_dns_json(&store, &body, 10, 60).await, 0);
}

#[test]
fn tls_sni_parser_extracts_bounded_client_hello_host() {
    let hello = tls_client_hello("www.example.com", false);

    assert_eq!(parse_tls_sni(&hello), Some("www.example.com".to_string()));
}

#[test]
fn tls_sni_parser_rejects_ech_and_oversized_input() {
    let hello = tls_client_hello("www.example.com", true);
    let oversized = vec![0_u8; 4097];

    assert_eq!(parse_tls_sni(&hello), None);
    assert_eq!(parse_tls_sni(&oversized), None);
}

#[tokio::test]
async fn proxy_ingress_does_not_inherit_destination_domain() {
    let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let store = new_domain_store(16);
    insert_evidence(
        &store,
        evidence(addr, "com.example.www", DomainSource::DnsAnswer),
    )
    .await;

    let router = DomainRouter::new(store);
    let resolved = router.resolve(&context(addr, 7890)).await;

    assert_eq!(resolved.domain, "");
    assert_eq!(resolved.source, DomainSource::Unknown);
    assert_eq!(resolved.confidence, DomainConfidence::None);
    assert_eq!(resolved.status, DomainStatus::ProxyIngress);
}

#[tokio::test]
async fn expired_evidence_falls_back_to_unknown() {
    let addr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3));
    let store = new_domain_store(16);
    insert_evidence(
        &store,
        evidence(addr, "old.example", DomainSource::DnsAnswer),
    )
    .await;

    let router = DomainRouter::new(store);
    let resolved = router
        .resolve(&DomainContext {
            now: 100,
            ..context(addr, 443)
        })
        .await;

    assert_eq!(resolved, DomainResolution::default());
}

#[tokio::test]
async fn evidence_store_dedupes_same_source_domain_and_pid() {
    let addr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4));
    let store = new_domain_store(16);
    let mut first = evidence(addr, "dns.example", DomainSource::DnsAnswer);
    first.pid = Some(42);
    first.observed_at = 10;
    let mut second = first.clone();
    second.observed_at = 20;

    insert_evidence(&store, first).await;
    insert_evidence(&store, second).await;

    let guard = store.read().await;
    let list = guard.peek(&addr).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].observed_at, 20);
}

#[tokio::test]
async fn evidence_store_caps_entries_per_addr_and_keeps_best_sources() {
    let addr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5));
    let store = new_domain_store(16);
    for idx in 0..20 {
        let mut item = evidence(addr, &format!("ptr{idx}.example"), DomainSource::Ptr);
        item.observed_at = idx;
        insert_evidence(&store, item).await;
    }
    insert_evidence(
        &store,
        evidence(addr, "dns.example", DomainSource::DnsAnswer),
    )
    .await;

    let guard = store.read().await;
    let list = guard.peek(&addr).unwrap();
    assert_eq!(list.len(), MAX_EVIDENCE_PER_ADDR);
    assert_eq!(list[0].domain, "dns.example");
    assert_eq!(list[0].source, DomainSource::DnsAnswer);
}

fn tls_client_hello(host: &str, ech: bool) -> Vec<u8> {
    let host_bytes = host.as_bytes();
    let mut sni_body = Vec::new();
    sni_body.extend_from_slice(&((host_bytes.len() + 3) as u16).to_be_bytes());
    sni_body.push(0);
    sni_body.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    sni_body.extend_from_slice(host_bytes);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0_u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_body);
    if ech {
        extensions.extend_from_slice(&0xfe0d_u16.to_be_bytes());
        extensions.extend_from_slice(&0_u16.to_be_bytes());
    }

    let mut body = Vec::new();
    body.extend_from_slice(&0x0303_u16.to_be_bytes());
    body.extend_from_slice(&[0x11; 32]);
    body.push(0);
    body.extend_from_slice(&2_u16.to_be_bytes());
    body.extend_from_slice(&0x1301_u16.to_be_bytes());
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut packet = Vec::new();
    packet.push(0x16);
    packet.extend_from_slice(&0x0301_u16.to_be_bytes());
    packet.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    packet.push(0x01);
    packet.push(((body.len() >> 16) & 0xff) as u8);
    packet.push(((body.len() >> 8) & 0xff) as u8);
    packet.push((body.len() & 0xff) as u8);
    packet.extend_from_slice(&body);
    packet
}
