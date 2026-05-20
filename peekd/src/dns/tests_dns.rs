use super::*;
use peekd_common::{DnsEvent, DnsEvent6};

fn name_bytes(name: &str) -> [u8; 256] {
    let mut buf = [0_u8; 256];
    let bytes = name.as_bytes();
    buf[..bytes.len()].copy_from_slice(bytes);
    buf
}

fn raw_ipv4(ip: Ipv4Addr) -> u32 {
    u32::from(ip).swap_bytes()
}

fn dns_response_header(answer_count: u16) -> Vec<u8> {
    let mut packet = vec![
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    packet[6..8].copy_from_slice(&answer_count.to_be_bytes());
    packet.extend_from_slice(&[
        0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o',
        b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ]);
    packet
}

#[test]
fn canonical_domain_uses_tld_first_lowercase_format() {
    assert_eq!(canonical_domain("WWW.Example.COM."), "com.example.www");
    assert_eq!(canonical_domain("localhost."), "localhost");
    assert_eq!(canonical_domain("93.184.216.34"), "");
}

#[tokio::test]
async fn ipv4_dns_event_key_matches_sendrecv_key() {
    let ip = Ipv4Addr::new(93, 184, 216, 34);
    let raw = raw_ipv4(ip);
    let dns = new_dns_map(8);
    let evidence_store = crate::domain::new_domain_store(8);
    let event = DnsEvent {
        pid: 1,
        saddr: 0,
        daddr: raw,
        sport: 0,
        dport: 0,
        name: name_bytes("WWW.Example.COM."),
    };

    assert_eq!(ipv4_event_addr(raw), ip);
    _handle_dns_event(&event, &dns, &evidence_store).await;

    let domain = lookup(&dns, IpAddr::V4(ip)).await;
    assert_eq!(domain, "com.example.www");
    let router = crate::domain::DomainRouter::new(evidence_store);
    let resolved = router
        .resolve(&crate::domain::DomainContext {
            pid: 1,
            name: "curl".to_string(),
            exe: "/usr/bin/curl".to_string(),
            raddr: IpAddr::V4(ip),
            rport: 443,
            now: unix_now(),
        })
        .await;
    assert_eq!(resolved.domain, "com.example.www");
    assert_eq!(resolved.source, crate::domain::DomainSource::GetAddrInfo);
}

#[tokio::test]
async fn ipv6_dns_event_key_matches_sendrecv_key() {
    let ip: Ipv6Addr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
    let dns = new_dns_map(8);
    let evidence_store = crate::domain::new_domain_store(8);
    let event = DnsEvent6 {
        pid: 1,
        saddr: [0; 16],
        daddr: ip.octets(),
        sport: 0,
        dport: 0,
        name: name_bytes("api.Example.COM."),
    };

    _handle_dns6_event(&event, &dns, &evidence_store).await;

    let domain = lookup(&dns, IpAddr::V6(ip)).await;
    assert_eq!(domain, "com.example.api");
    let router = crate::domain::DomainRouter::new(evidence_store);
    let resolved = router
        .resolve(&crate::domain::DomainContext {
            pid: 1,
            name: "curl".to_string(),
            exe: "/usr/bin/curl".to_string(),
            raddr: IpAddr::V6(ip),
            rport: 443,
            now: unix_now(),
        })
        .await;
    assert_eq!(resolved.domain, "com.example.api");
    assert_eq!(resolved.source, crate::domain::DomainSource::GetAddrInfo);
}

#[tokio::test]
async fn dns_response_ingest_extracts_a_record_evidence() {
    let mut packet = dns_response_header(1);
    packet.extend_from_slice(&[
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 93, 184, 216, 34,
    ]);
    let store = crate::domain::new_domain_store(8);

    assert_eq!(ingest_dns_response_packet(&store, &packet, 100).await, 1);

    let router = crate::domain::DomainRouter::new(store);
    let resolved = router
        .resolve(&crate::domain::DomainContext {
            pid: 1,
            name: "curl".to_string(),
            exe: "/usr/bin/curl".to_string(),
            raddr: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            rport: 443,
            now: 120,
        })
        .await;
    assert_eq!(resolved.domain, "com.example.www");
    assert_eq!(resolved.source, crate::domain::DomainSource::DnsAnswer);
}

#[tokio::test]
async fn dns_response_ingest_extracts_aaaa_record_evidence() {
    let mut packet = dns_response_header(1);
    packet.extend_from_slice(&[
        0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x10, 0x26, 0x06, 0x28,
        0x00, 0x02, 0x20, 0x00, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46,
    ]);
    let addr: Ipv6Addr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
    let store = crate::domain::new_domain_store(8);

    assert_eq!(ingest_dns_response_packet(&store, &packet, 100).await, 1);

    let router = crate::domain::DomainRouter::new(store);
    let resolved = router
        .resolve(&crate::domain::DomainContext {
            pid: 1,
            name: "curl".to_string(),
            exe: "/usr/bin/curl".to_string(),
            raddr: IpAddr::V6(addr),
            rport: 443,
            now: 120,
        })
        .await;
    assert_eq!(resolved.domain, "com.example.www");
    assert_eq!(resolved.source, crate::domain::DomainSource::DnsAnswer);
}

#[test]
fn dns_response_parser_uses_cname_alias_for_address_record() {
    let mut packet = dns_response_header(2);
    packet.extend_from_slice(&[
        0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x06, 0x03, b'a', b'p',
        b'i', 0xc0, 0x10,
    ]);
    packet.extend_from_slice(&[
        0x03, b'a', b'p', b'i', 0xc0, 0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00,
        0x04, 203, 0, 113, 9,
    ]);

    let records = parse_dns_response(&packet);

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].addr, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)));
    assert_eq!(records[0].domain, "www.example.com");
}

#[test]
fn dns_response_parser_rejects_query_only_packet() {
    let mut packet = dns_response_header(0);
    packet[2] = 0x01;
    packet[3] = 0x00;

    assert!(parse_dns_response(&packet).is_empty());
}
