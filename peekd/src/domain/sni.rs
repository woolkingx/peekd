use std::net::IpAddr;

use super::{insert_domain_evidence, DomainConfidence, DomainEvidenceStore, DomainSource};

pub async fn insert_sni_evidence(
    store: &DomainEvidenceStore,
    addr: IpAddr,
    client_hello: &[u8],
    observed_at: i64,
) -> bool {
    let Some(sni) = parse_tls_sni(client_hello) else {
        return false;
    };
    insert_domain_evidence(
        store,
        addr,
        &sni,
        DomainSource::Sni,
        DomainConfidence::Medium,
        observed_at,
        Some(observed_at + 300),
    )
    .await;
    true
}

pub fn parse_tls_sni(buf: &[u8]) -> Option<String> {
    const MAX_CLIENT_HELLO: usize = 4096;
    const MAX_EXTENSIONS: usize = 2048;
    const MAX_HOST_LEN: usize = 253;
    const EXT_SERVER_NAME: u16 = 0x0000;
    const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

    if buf.len() < 9 || buf.len() > MAX_CLIENT_HELLO {
        return None;
    }
    if buf[0] != 0x16 || buf[5] != 0x01 {
        return None;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if record_len + 5 > buf.len() {
        return None;
    }
    let handshake_len = ((buf[6] as usize) << 16) | ((buf[7] as usize) << 8) | buf[8] as usize;
    if handshake_len + 9 > record_len + 5 {
        return None;
    }

    let mut pos = 9 + 2 + 32;
    if pos >= buf.len() {
        return None;
    }
    let session_len = *buf.get(pos)? as usize;
    pos += 1 + session_len;
    if pos + 2 > buf.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2 + cipher_len;
    if pos >= buf.len() {
        return None;
    }
    let compression_len = *buf.get(pos)? as usize;
    pos += 1 + compression_len;
    if pos + 2 > buf.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    if ext_len > MAX_EXTENSIONS || pos + ext_len > buf.len() {
        return None;
    }

    let end = pos + ext_len;
    let mut sni = None;
    while pos + 4 <= end {
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if pos + len > end {
            return None;
        }
        if ext_type == EXT_ENCRYPTED_CLIENT_HELLO {
            return None;
        }
        if ext_type == EXT_SERVER_NAME {
            sni = parse_sni_extension(&buf[pos..pos + len], MAX_HOST_LEN);
        }
        pos += len;
    }
    sni
}

fn parse_sni_extension(buf: &[u8], max_host_len: usize) -> Option<String> {
    if buf.len() < 5 {
        return None;
    }
    let list_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if list_len + 2 > buf.len() {
        return None;
    }
    let name_type = buf[2];
    let host_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if name_type != 0 || host_len == 0 || host_len > max_host_len || 5 + host_len > buf.len() {
        return None;
    }
    let host = std::str::from_utf8(&buf[5..5 + host_len]).ok()?;
    if host.bytes().any(|b| b == 0 || b == b'/' || b == b' ') {
        return None;
    }
    Some(host.to_string())
}
