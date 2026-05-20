use std::net::IpAddr;

use serde_json::Value;

use super::{canonical_domain, insert_mihomo_evidence, DomainEvidenceStore};

pub async fn ingest_mihomo_dns_json(
    store: &DomainEvidenceStore,
    body: &str,
    observed_at: i64,
    ttl_seconds: i64,
) -> usize {
    const MAX_MIHOMO_DNS_JSON: usize = 256 * 1024;
    if body.len() > MAX_MIHOMO_DNS_JSON {
        return 0;
    }
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return 0;
    };
    let mut pairs = Vec::new();
    collect_mihomo_pairs(&value, &mut pairs);
    let mut inserted = 0;
    for (addr, domain) in pairs {
        if canonical_domain(&domain).is_empty() {
            continue;
        }
        insert_mihomo_evidence(
            store,
            addr,
            &domain,
            observed_at,
            Some(observed_at + ttl_seconds.max(1)),
        )
        .await;
        inserted += 1;
    }
    inserted
}

fn collect_mihomo_pairs(value: &Value, out: &mut Vec<(IpAddr, String)>) {
    match value {
        Value::Object(map) => {
            if let (Some(addr), Some(domain)) = (
                string_field(map, &["ip", "fake_ip", "fake-ip", "addr", "address"]),
                string_field(map, &["domain", "host", "hostname", "name"]),
            ) {
                if let Ok(addr) = addr.parse::<IpAddr>() {
                    out.push((addr, domain.to_string()));
                }
            }
            for (key, child) in map {
                if let Ok(addr) = key.parse::<IpAddr>() {
                    if let Some(domain) = child.as_str() {
                        out.push((addr, domain.to_string()));
                    }
                }
                collect_mihomo_pairs(child, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_mihomo_pairs(item, out);
            }
        }
        _ => {}
    }
}

fn string_field<'a>(map: &'a serde_json::Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| map.get(*key).and_then(Value::as_str))
}
