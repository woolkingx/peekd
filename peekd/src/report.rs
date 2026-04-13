#![allow(dead_code, unused_imports)]

//! report.rs: Daily/periodic network traffic report.
//!
//! Reads SQLite directly (read-only connection, WAL-safe).
//! Resolves hostnames via PTR (system resolver) and org via whois.
//! Output is plain text matching the netwatch report format.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Local, TimeZone, Timelike};
use rusqlite::{Connection, params};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// Public entry point
// ============================================================================

#[derive(Debug, Clone)]
pub struct ReportArgs {
    pub since: String,   // "1h", "24h", "7d", "30d"
    pub top: Option<usize>, // top N destinations, None = all
    pub json: bool,
}

impl Default for ReportArgs {
    fn default() -> Self {
        Self { since: "24h".to_string(), top: None, json: false }
    }
}

pub fn run_report(args: &ReportArgs, _config: &crate::config::Config) -> Result<()> {
    let db_path = crate::config::db_path();
    if !db_path.exists() {
        return Err(anyhow!("database not found: {:?}", db_path));
    }
    let conn = Connection::open_with_flags(&db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let _ = conn.execute_batch("PRAGMA journal_mode=WAL;");

    let since_secs: i64 = match args.since.as_str() {
        "1h"  => 3600,
        "24h" => 86400,
        "7d"  => 604800,
        "30d" => 2592000,
        other => return Err(anyhow!("invalid duration: {}", other)),
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let cutoff = now - since_secs;

    // Collect all unique remote IPs for batch PTR+whois resolution
    let all_ips = _query_unique_ips(&conn, cutoff)?;
    eprintln!("resolving {} remote IPs (PTR + whois)...", all_ips.len());
    let resolved = _resolve_all(&all_ips);

    let hostname = gethostname();
    let date_str = Local::now().format("%Y-%m-%d").to_string();
    let generated = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let sep = "=".repeat(76);
    println!("{sep}");
    println!("  peekd Report - {hostname}");
    println!("  Date: {date_str}");
    println!("  Generated: {generated}");
    println!("{sep}");
    println!();

    _print_summary(&conn, cutoff)?;
    _print_hourly(&conn, cutoff)?;
    _print_top_destinations(&conn, cutoff, args.top, &resolved)?;
    _print_top_ports(&conn, cutoff)?;
    _print_anomalies(&conn, cutoff)?;
    _print_new_ips(&conn, cutoff, &resolved)?;

    println!("{sep}");
    Ok(())
}

// ============================================================================
// DNS / whois resolution
// ============================================================================

fn gethostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// PTR reverse lookup via system resolver (uses local unbound/resolv.conf).
fn lookup_ptr(ip: &str) -> Option<String> {
    // Parse as IpAddr then use DNS reverse lookup
    let addr: IpAddr = ip.parse().ok()?;
    // Build reverse lookup hostname
    let reverse = match addr {
        IpAddr::V4(a) => {
            let oct = a.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", oct[3], oct[2], oct[1], oct[0])
        }
        IpAddr::V6(a) => {
            let hex: String = a.octets().iter().rev()
                .flat_map(|b| vec![char::from_digit((b & 0xf) as u32, 16).unwrap_or('0'),
                                   char::from_digit((b >> 4) as u32, 16).unwrap_or('0')])
                .collect::<Vec<char>>()
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(".");
            format!("{}.ip6.arpa", hex)
        }
    };
    // Use getaddrinfo via dig for reliability (handles ndots, search domains)
    let out = std::process::Command::new("dig")
        .args(["+short", "+time=2", "+tries=1", "PTR", &reverse])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let hostname = s.lines()
        .find(|l| !l.starts_with(';') && !l.contains(".arpa") && !l.is_empty())?
        .trim_end_matches('.')
        .to_string();
    if hostname.is_empty() { None } else { Some(hostname) }
}

/// whois org lookup — parses OrgName / org-name / netname fields.
/// Only called for public IPs (non-RFC1918).
fn lookup_whois_org(ip: &str) -> Option<String> {
    let addr: IpAddr = ip.parse().ok()?;
    if is_private(&addr) {
        return None;
    }
    let out = std::process::Command::new("whois")
        .arg(ip)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // Try fields in preference order
    for field in &["OrgName", "org-name", "netname", "Organization", "owner"] {
        for line in text.lines() {
            let lower = line.to_lowercase();
            let field_lower = field.to_lowercase();
            if lower.starts_with(&field_lower) {
                if let Some(val) = line.splitn(2, ':').nth(1) {
                    let v = val.trim().to_string();
                    if !v.is_empty() {
                        return Some(v);
                    }
                }
            }
        }
    }
    None
}

fn is_private(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => {
            let o = a.octets();
            o[0] == 10
                || (o[0] == 172 && o[1] >= 16 && o[1] <= 31)
                || (o[0] == 192 && o[1] == 168)
                || o[0] == 127
                || o[0] == 0
        }
        IpAddr::V6(a) => a.is_loopback() || {
            let s = a.segments();
            s[0] == 0xfe80  // link-local
        },
    }
}

/// Resolve all IPs in parallel using rayon-style threads.
/// Returns HashMap<ip_string, (ptr_hostname, org)>
fn _resolve_all(ips: &[String]) -> HashMap<String, (Option<String>, Option<String>)> {
    use std::sync::{Arc, Mutex};
    let results: Arc<Mutex<HashMap<String, (Option<String>, Option<String>)>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let handles: Vec<_> = ips.iter().map(|ip| {
        let ip = ip.clone();
        let results = results.clone();
        std::thread::spawn(move || {
            let ptr = lookup_ptr(&ip);
            let org = lookup_whois_org(&ip);
            results.lock().unwrap().insert(ip, (ptr, org));
        })
    }).collect();

    for h in handles { let _ = h.join(); }
    Arc::try_unwrap(results).unwrap().into_inner().unwrap()
}

fn _query_unique_ips(conn: &Connection, cutoff: i64) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT raddr FROM connections WHERE contime >= ?1"
    )?;
    let ips: Vec<String> = stmt.query_map(params![cutoff], |r| r.get(0))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(ips)
}

fn format_bytes(b: i64) -> String {
    if b >= 1_000_000_000 { format!("{:.1}G", b as f64 / 1e9) }
    else if b >= 1_000_000 { format!("{:.1}M", b as f64 / 1e6) }
    else if b >= 1_000     { format!("{:.1}K", b as f64 / 1e3) }
    else                   { format!("{}B", b) }
}

fn display_addr(ip: &str, resolved: &HashMap<String, (Option<String>, Option<String>)>) -> String {
    let (ptr, org) = resolved.get(ip).cloned().unwrap_or((None, None));
    let label = ptr.as_deref().or(org.as_deref());
    match label {
        Some(l) => format!("{:<15}  ({})", ip, l),
        None    => format!("{:<15}", ip),
    }
}

fn org_label(ip: &str, resolved: &HashMap<String, (Option<String>, Option<String>)>) -> String {
    let (ptr, org) = resolved.get(ip).cloned().unwrap_or((None, None));
    // Show ptr hostname; show org in parens if different
    match (ptr, org) {
        (Some(p), Some(o)) if o != p => format!("{}  ({})", p, o),
        (Some(p), _) => p,
        (None, Some(o)) => o,
        (None, None) => String::new(),
    }
}

// ============================================================================
// Report sections
// ============================================================================

fn _print_summary(conn: &Connection, cutoff: i64) -> Result<()> {
    let (total_flows, total_send, total_recv): (i64, i64, i64) = conn.query_row(
        "SELECT COUNT(*), COALESCE(SUM(send),0), COALESCE(SUM(recv),0) FROM connections WHERE contime >= ?1",
        params![cutoff], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))
    )?;
    let unique_ips: i64 = conn.query_row(
        "SELECT COUNT(DISTINCT raddr) FROM connections WHERE contime >= ?1",
        params![cutoff], |r| r.get(0)
    )?;

    println!("--- Summary ---");
    println!("Total flows       : {}", total_flows);
    println!("Total bytes       : {}  (out: {}, in: {})",
        format_bytes(total_send + total_recv),
        format_bytes(total_send),
        format_bytes(total_recv));
    println!("Unique remote IPs : {}", unique_ips);
    println!();
    Ok(())
}

fn _print_hourly(conn: &Connection, cutoff: i64) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT strftime('%H', datetime(contime, 'unixepoch', 'localtime')) AS hr,
                COUNT(*) AS flows,
                COALESCE(SUM(send + recv), 0) AS bytes
         FROM connections
         WHERE contime >= ?1
         GROUP BY hr
         ORDER BY hr"
    )?;
    let rows: Vec<(String, i64, i64)> = stmt.query_map(params![cutoff], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
    })?.filter_map(|r| r.ok()).collect();

    if rows.is_empty() { return Ok(()); }

    let max_bytes = rows.iter().map(|(_, _, b)| *b).max().unwrap_or(1).max(1);
    let bar_width = 40usize;

    println!("--- Hourly Distribution ---");
    println!(" {:>4}  {:>7}  {:>10}  Graph", "Hour", "Flows", "Bytes");
    for (hr, flows, bytes) in &rows {
        let bar_len = ((*bytes as f64 / max_bytes as f64) * bar_width as f64) as usize;
        let bar = "#".repeat(bar_len);
        println!("  {:>3}h  {:>7}  {:>10}  {}", hr, flows, format_bytes(*bytes), bar);
    }
    println!();
    Ok(())
}

fn _print_top_destinations(
    conn: &Connection,
    cutoff: i64,
    top: Option<usize>,
    resolved: &HashMap<String, (Option<String>, Option<String>)>,
) -> Result<()> {
    // Top IPs by total bytes
    let sql = match top {
        Some(n) => format!(
            "SELECT raddr, COUNT(*) AS flows, COALESCE(SUM(send+recv),0) AS bytes
             FROM connections WHERE contime >= ?1 GROUP BY raddr ORDER BY bytes DESC LIMIT {}",
            n
        ),
        None => "SELECT raddr, COUNT(*) AS flows, COALESCE(SUM(send+recv),0) AS bytes
                 FROM connections WHERE contime >= ?1 GROUP BY raddr ORDER BY bytes DESC".to_string(),
    };
    let mut stmt = conn.prepare(&sql)?;
    let rows: Vec<(String, i64, i64)> = stmt.query_map(params![cutoff], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
    })?.filter_map(|r| r.ok()).collect();

    if rows.is_empty() { return Ok(()); }

    println!("--- Top Destinations ---");
    for (i, (raddr, flows, bytes)) in rows.iter().enumerate() {
        let label = org_label(raddr, resolved);
        let label_part = if label.is_empty() { String::new() } else { format!("  ({})", label) };
        println!("  {:>3}. {:<15}{}  {} flows  {}",
            i + 1, raddr, label_part, flows, format_bytes(*bytes));

        // Per-exe breakdown (top 5 per IP)
        let mut stmt2 = conn.prepare(
            "SELECT e.name, c.uid, COUNT(*) AS flows, COALESCE(SUM(c.send + c.recv), 0) AS bytes
             FROM connections c JOIN executables e ON c.exe_id = e.id
             WHERE c.contime >= ?1 AND c.raddr = ?2
             GROUP BY e.name, c.uid
             ORDER BY bytes DESC
             LIMIT 5"
        )?;
        let sub: Vec<(String, i64, i64, i64)> = stmt2.query_map(params![cutoff, raddr], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?.filter_map(|r| r.ok()).collect();

        // Only show breakdown if more than 1 process or interesting
        if sub.len() > 1 || (sub.len() == 1 && flows > &1) {
            for (name, uid, sub_flows, sub_bytes) in &sub {
                println!("       {}(uid={})  {} flows  {}",
                    if name.is_empty() { "?".to_string() } else { name.clone() },
                    uid, sub_flows, format_bytes(*sub_bytes));
            }
        }
    }
    println!();
    Ok(())
}

fn _print_top_ports(conn: &Connection, cutoff: i64) -> Result<()> {
    // Well-known port → service name table
    fn port_service(port: i64) -> &'static str {
        match port {
            20 | 21 => "FTP",
            22      => "SSH",
            23      => "Telnet",
            25      => "SMTP",
            43      => "WHOIS",
            53      => "DNS",
            67 | 68 => "DHCP",
            80      => "HTTP",
            110     => "POP3",
            123     => "NTP",
            143     => "IMAP",
            443     => "HTTPS",
            465     => "SMTPS",
            587     => "SMTP-sub",
            853     => "DNS-TLS",
            993     => "IMAPS",
            995     => "POP3S",
            1194    => "OpenVPN",
            3306    => "MySQL",
            5432    => "PostgreSQL",
            6379    => "Redis",
            8080    => "HTTP-alt",
            8000    => "HTTP-alt",
            8443    => "HTTPS-alt",
            8529    => "ArangoDB",
            51820   => "WireGuard",
            _       => "",
        }
    }

    let mut stmt = conn.prepare(
        "SELECT rport, COUNT(*) AS flows, COALESCE(SUM(send + recv), 0) AS bytes
         FROM connections
         WHERE contime >= ?1 AND rport > 0
         GROUP BY rport
         ORDER BY flows DESC
         LIMIT 20"
    )?;
    let rows: Vec<(i64, i64, i64)> = stmt.query_map(params![cutoff], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
    })?.filter_map(|r| r.ok()).collect();

    if rows.is_empty() { return Ok(()); }

    println!("--- Top 20 Destination Ports ---");
    println!("   {:>5}  {:>9}  {:>10}  Service", "Port", "Flows", "Bytes");
    for (port, flows, bytes) in &rows {
        let svc = port_service(*port);
        println!("   {:>5}  {:>9}  {:>10}  {}", port, flows, format_bytes(*bytes), svc);
    }
    println!();
    Ok(())
}

fn _print_anomalies(conn: &Connection, cutoff: i64) -> Result<()> {
    // Detect per-minute flow bursts: > 30 flows/min to same IP
    let burst_threshold = 30i64;
    let mut stmt = conn.prepare(
        "SELECT (contime / 60) * 60 AS minute, raddr, COUNT(*) AS flows
         FROM connections
         WHERE contime >= ?1
         GROUP BY minute, raddr
         HAVING flows >= ?2
         ORDER BY minute ASC"
    )?;
    let rows: Vec<(i64, String, i64)> = stmt.query_map(params![cutoff, burst_threshold], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
    })?.filter_map(|r| r.ok()).collect();

    if rows.is_empty() { return Ok(()); }

    println!("--- Anomalies ({}) ---", rows.len());
    for (minute, raddr, flows) in &rows {
        let dt = Local.timestamp_opt(*minute, 0).single()
            .map(|t| t.format("%H:%M:%S").to_string())
            .unwrap_or_else(|| minute.to_string());
        println!("  [WARN] {} rate_burst   {:<15}",  dt, raddr);
        println!("    {{\"minute\": {}, \"flows\": {}}}", minute, flows);
    }
    println!();
    Ok(())
}

fn _print_new_ips(
    conn: &Connection,
    cutoff: i64,
    resolved: &HashMap<String, (Option<String>, Option<String>)>,
) -> Result<()> {
    // IPs first seen within the report window
    let mut stmt = conn.prepare(
        "SELECT raddr, MIN(contime) AS first_seen
         FROM connections
         WHERE contime >= ?1
         GROUP BY raddr
         ORDER BY first_seen ASC"
    )?;
    let rows: Vec<(String, i64)> = stmt.query_map(params![cutoff], |r| {
        Ok((r.get(0)?, r.get(1)?))
    })?.filter_map(|r| r.ok()).collect();

    if rows.is_empty() { return Ok(()); }

    let total = rows.len();
    let show = rows.iter().take(50);

    println!("--- New Remote IPs ({}) ---", total);
    for (raddr, first_seen) in show {
        let dt = Local.timestamp_opt(*first_seen, 0).single()
            .map(|t| t.format("%H:%M:%S").to_string())
            .unwrap_or_default();
        let label = org_label(raddr, resolved);
        let label_part = if label.is_empty() { String::new() } else { format!("  ({})", label) };
        println!("  {}  {:<15}{}", dt, raddr, label_part);
    }
    if total > 50 {
        println!("  ... {} more", total - 50);
    }
    println!();
    Ok(())
}
