//! web.rs: Minimal web UI for peekd.
//!
//! `peekd web [--port 5100]`
//! Serves a single-page dashboard backed by the SQLite DB.
//! Two endpoints:
//!   GET /           → embedded HTML (vanilla JS + Chart.js CDN)
//!   GET /api/data   → JSON: {dim, since, rows: [{label, send, recv, flows}]}
//!   GET /api/top    → JSON: top destinations with per-exe breakdown

use anyhow::Result;
use axum::{Router, extract::{Query, State}, response::{Html, Json}, routing::{get, post}};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use lru::LruCache;

#[derive(Clone)]
struct AppState {
    top_limit:       u32,
    refresh_seconds: u64,
    default_since:   String,
}

// PTR lookup cache: ip string → hostname (empty = no record), max 10k entries
static PTR_CACHE: OnceLock<Mutex<LruCache<String, String>>> = OnceLock::new();
static PTR_SEMAPHORE: OnceLock<tokio::sync::Semaphore> = OnceLock::new();

fn ptr_cache() -> &'static Mutex<LruCache<String, String>> {
    PTR_CACHE.get_or_init(|| Mutex::new(LruCache::new(std::num::NonZeroUsize::new(10000).unwrap())))
}

fn ptr_semaphore() -> &'static tokio::sync::Semaphore {
    PTR_SEMAPHORE.get_or_init(|| tokio::sync::Semaphore::new(20))
}

async fn lookup_ptr(ip: &str) -> String {
    // Check cache first
    if let Ok(mut cache) = ptr_cache().lock() {
        if let Some(v) = cache.get(ip) {
            return v.clone();
        }
    }

    // Acquire semaphore permit before doing DNS/whois work
    if let Ok(_permit) = ptr_semaphore().acquire().await {
        let mut result = _do_ptr_lookup(ip).await;

        // PTR failed — try whois org for public IPs
        if result.is_empty() && !_is_private(ip) {
            result = _do_whois_lookup(ip).await;
        }

        if let Ok(mut cache) = ptr_cache().lock() {
            cache.put(ip.to_string(), result.clone());
        }
        result
    } else {
        String::new()
    }
}

fn _is_private(ip: &str) -> bool {
    let Ok(addr) = IpAddr::from_str(ip) else { return false };
    match addr {
        IpAddr::V4(a) => {
            let o = a.octets();
            matches!(o, [10, ..] | [172, 16..=31, ..] | [192, 168, ..] | [127, ..])
        }
        IpAddr::V6(a) => a.is_loopback(),
    }
}

async fn _do_whois_lookup(ip: &str) -> String {
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::process::Command::new("whois")
            .arg(ip)
            .output()
    ).await;
    let Ok(Ok(out)) = out else { return String::new() };
    let text = String::from_utf8_lossy(&out.stdout);
    for field in &["OrgName", "org-name", "netname", "Organization", "owner"] {
        for line in text.lines() {
            if line.to_lowercase().starts_with(&field.to_lowercase()) {
                if let Some(val) = line.splitn(2, ':').nth(1) {
                    let v = val.trim().to_string();
                    if !v.is_empty() { return v; }
                }
            }
        }
    }
    String::new()
}

async fn _do_ptr_lookup(ip: &str) -> String {
    let Ok(addr) = IpAddr::from_str(ip) else { return String::new() };
    tokio::task::spawn_blocking(move || _getnameinfo(&addr))
        .await
        .unwrap_or_default()
}

fn _getnameinfo(addr: &IpAddr) -> String {
    let mut host = [0u8; 1025];
    let ret = match addr {
        IpAddr::V4(v4) => {
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(v4.octets()) },
                sin_zero: [0; 8],
            };
            unsafe {
                libc::getnameinfo(
                    &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host.as_mut_ptr() as *mut libc::c_char,
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(), 0,
                    libc::NI_NAMEREQD,
                )
            }
        }
        IpAddr::V6(v6) => {
            let sa = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr { s6_addr: v6.octets() },
                sin6_scope_id: 0,
            };
            unsafe {
                libc::getnameinfo(
                    &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host.as_mut_ptr() as *mut libc::c_char,
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(), 0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };
    if ret != 0 { return String::new(); }
    let end = host.iter().position(|&b| b == 0).unwrap_or(host.len());
    String::from_utf8_lossy(&host[..end]).into_owned()
}

static HTML: &str = include_str!("web.html");

#[derive(Deserialize)]
struct DataParams {
    since: Option<String>,
    dim:   Option<String>,
    from:  Option<i64>,
    to:    Option<i64>,
}

#[derive(Serialize)]
struct DataRow {
    label: String,
    send:  i64,
    recv:  i64,
    flows: i64,
}

#[derive(Serialize)]
struct DataResp {
    dim:   String,
    since: String,
    rows:  Vec<DataRow>,
}

#[derive(Serialize, Clone)]
struct DestSub {
    name:   String,
    uid:    i64,
    rport:  i64,
    domain: String,
    flows:  i64,
    send:   i64,
    recv:   i64,
}

#[derive(Serialize)]
struct Dest {
    label:    String,
    domain:   String,
    hostname: String,
    flows:    i64,
    send:     i64,
    recv:     i64,
    subs:     Vec<DestSub>,
}

#[derive(Serialize)]
struct TopResp {
    since: String,
    dests: Vec<Dest>,
}

#[derive(Serialize)]
struct HourRow {
    hour:  String,
    flows: i64,
    bytes: i64,
}

#[derive(Serialize)]
struct SummaryResp {
    since:      String,
    flows:      i64,
    send:       i64,
    recv:       i64,
    unique_ips: i64,
    hours:      Vec<HourRow>,
}

fn db() -> Result<Connection> {
    let path = crate::config::db_path();
    let conn = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let _ = conn.execute_batch("PRAGMA journal_mode=WAL;");
    Ok(conn)
}

fn get_from_to(since: Option<&str>, from: Option<i64>, to: Option<i64>) -> (i64, i64) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let to_ts = to.unwrap_or(now);

    let from_ts = if let Some(f) = from {
        f
    } else {
        let since_str = since.unwrap_or("24h");
        let secs: i64 = match since_str {
            "1h"  => 3600,
            "6h"  => 21600,
            "7d"  => 604800,
            "30d" => 2592000,
            _     => 86400,
        };
        to_ts - secs
    };

    (from_ts, to_ts)
}

fn dim_sql(dim: &str) -> &'static str {
    match dim {
        "name"    => "e.name",
        "cmdline" => "e.cmdline",
        "raddr"   => "c.raddr",
        "domain"  => "c.domain",
        "rport"   => "CAST(c.rport AS TEXT)",
        "uid"     => "CAST(c.uid AS TEXT)",
        _         => "e.exe",
    }
}

async fn api_data(Query(p): Query<DataParams>) -> Json<DataResp> {
    let (from_ts, _to_ts) = get_from_to(p.since.as_deref(), p.from, p.to);
    let since = p.since.unwrap_or_else(|| "24h".into());
    let dim   = p.dim.unwrap_or_else(|| "exe".into());
    let col   = dim_sql(&dim).to_string();

    let rows = tokio::task::spawn_blocking(move || {
        (|| -> Result<Vec<DataRow>> {
            let conn = db()?;
            let sql = format!(
                "SELECT {col} AS label, COALESCE(SUM(c.send),0), COALESCE(SUM(c.recv),0), COUNT(*)
                 FROM connections c JOIN executables e ON c.exe_id = e.id
                 WHERE c.contime >= ?1
                 GROUP BY label ORDER BY SUM(c.send+c.recv) DESC LIMIT 50"
            );
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(params![from_ts], |r| {
                Ok(DataRow { label: r.get::<_,String>(0).unwrap_or_default(), send: r.get(1)?, recv: r.get(2)?, flows: r.get(3)? })
            })?.filter_map(|r| r.ok()).collect();
            Ok(rows)
        })()
    })
    .await
    .unwrap_or(Err(anyhow::anyhow!("spawn_blocking failed")))
    .unwrap_or_default();

    Json(DataResp { dim, since, rows })
}

async fn api_top(State(state): State<AppState>, Query(p): Query<DataParams>) -> Json<TopResp> {
    let (from_ts, _to_ts) = get_from_to(p.since.as_deref(), p.from, p.to);
    let since  = p.since.unwrap_or_else(|| "24h".into());
    let dim    = p.dim.unwrap_or_else(|| "raddr".into());
    let col    = dim_sql(&dim).to_string();
    let by_raddr = dim == "raddr";
    let limit  = state.top_limit;

    type RawDest = (String, String, i64, i64, i64, Vec<DestSub>);
    let raw: Vec<RawDest> = tokio::task::spawn_blocking(move || {
        (|| -> Result<Vec<RawDest>> {
            let conn = db()?;
            let domain_col = if by_raddr { "COALESCE(c.domain,'')" } else { "''" };
            let sql = format!(
                "SELECT {col} AS label, {domain_col}, COUNT(*), COALESCE(SUM(c.send),0), COALESCE(SUM(c.recv),0)
                 FROM connections c JOIN executables e ON c.exe_id = e.id
                 WHERE c.contime >= ?1
                 GROUP BY label ORDER BY SUM(c.send+c.recv) DESC LIMIT {limit}"
            );
            let mut stmt = conn.prepare(&sql)?;
            let dests_raw: Vec<(String, String, i64, i64, i64)> = stmt.query_map(params![from_ts], |r| {
                Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?, r.get::<_,i64>(2)?, r.get::<_,i64>(3)?, r.get::<_,i64>(4)?))
            })?.filter_map(|r| r.ok()).collect();

            if by_raddr {
                // Single JOIN query for all raddr subs, group in Rust
                let mut sub_stmt = conn.prepare(
                    "SELECT c.raddr, e.name, c.uid, c.rport, COUNT(*), COALESCE(SUM(c.send),0), COALESCE(SUM(c.recv),0)
                     FROM connections c JOIN executables e ON c.exe_id = e.id
                     WHERE c.contime >= ?1
                     GROUP BY c.raddr, e.name, c.uid, c.rport"
                )?;
                let mut subs_by_raddr: std::collections::HashMap<String, Vec<DestSub>> = HashMap::new();
                sub_stmt.query_map(params![from_ts], |r| {
                    let raddr = r.get::<_,String>(0)?;
                    let sub = DestSub {
                        name: r.get(1)?,
                        uid: r.get(2)?,
                        rport: r.get(3)?,
                        domain: String::new(),
                        flows: r.get(4)?,
                        send: r.get(5)?,
                        recv: r.get(6)?,
                    };
                    subs_by_raddr.entry(raddr).or_insert_with(Vec::new).push(sub);
                    Ok(())
                })?.for_each(|_| ());

                // Sort each vec by send+recv DESC
                for subs in subs_by_raddr.values_mut() {
                    subs.sort_by(|a, b| (b.send + b.recv).cmp(&(a.send + a.recv)));
                }

                let rows: Vec<RawDest> = dests_raw.into_iter().map(|(label, domain, flows, send, recv)| {
                    let subs = subs_by_raddr.get(&label).cloned().unwrap_or_default();
                    (label, domain, flows, send, recv, subs)
                }).collect();
                Ok(rows)
            } else {
                // Non-raddr path: keep the original per-destination queries
                let rows: Vec<RawDest> = dests_raw.into_iter().map(|(label, domain, flows, send, recv)| {
                    let sub_sql = format!(
                        "SELECT c.raddr, COALESCE(c.domain,''), COUNT(*), COALESCE(SUM(c.send),0), COALESCE(SUM(c.recv),0)
                         FROM connections c JOIN executables e ON c.exe_id = e.id
                         WHERE c.contime >= ?1 AND {col} = ?2
                         GROUP BY c.raddr ORDER BY SUM(c.send+c.recv) DESC LIMIT 10"
                    );
                    let subs: Vec<DestSub> = if let Ok(mut s) = conn.prepare(&sub_sql) {
                        s.query_map(params![from_ts, &label], |r| {
                            Ok(DestSub { name: r.get(0)?, uid: 0, rport: 0, domain: r.get(1)?, flows: r.get(2)?, send: r.get(3)?, recv: r.get(4)? })
                        }).ok().map(|it| it.filter_map(|r| r.ok()).collect()).unwrap_or_default()
                    } else {
                        Vec::new()
                    };
                    (label, domain, flows, send, recv, subs)
                }).collect();
                Ok(rows)
            }
        })()
    })
    .await
    .unwrap_or(Err(anyhow::anyhow!("spawn_blocking failed")))
    .unwrap_or_default();

    let mut dests = Vec::with_capacity(raw.len());
    if by_raddr {
        let hostnames = futures::future::join_all(
            raw.iter().map(|(label, ..)| lookup_ptr(label))
        ).await;
        for ((label, domain, flows, send, recv, subs), hostname) in raw.into_iter().zip(hostnames) {
            dests.push(Dest { label, domain, hostname, flows, send, recv, subs });
        }
    } else {
        for (label, domain, flows, send, recv, subs) in raw {
            dests.push(Dest { label, domain, hostname: String::new(), flows, send, recv, subs });
        }
    }

    Json(TopResp { since, dests })
}

async fn api_summary(Query(p): Query<DataParams>) -> Json<SummaryResp> {
    let (from_ts, to_ts) = get_from_to(p.since.as_deref(), p.from, p.to);
    let since = p.since.unwrap_or_else(|| "24h".into());
    let span = to_ts - from_ts;
    let since_clone = since.clone();

    let result = tokio::task::spawn_blocking(move || {
        (|| -> Result<SummaryResp> {
            let conn = db()?;
            let (flows, send, recv): (i64, i64, i64) = conn.query_row(
                "SELECT COUNT(*), COALESCE(SUM(send),0), COALESCE(SUM(recv),0) FROM connections WHERE contime >= ?1",
                params![from_ts], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            )?;
            let unique_ips: i64 = conn.query_row(
                "SELECT COUNT(DISTINCT raddr) FROM connections WHERE contime >= ?1",
                params![from_ts], |r| r.get(0)
            )?;
            // Auto-detect bucket granularity based on span
            let time_sql = if span < 7200 {
                // < 2 hours: 5-min buckets
                "strftime('%H:%M', datetime((contime/300)*300,'unixepoch','localtime'))"
            } else if span < 1_209_600 {
                // < 14 days: 1-hour buckets
                "strftime('%m-%d %Hh', datetime(contime,'unixepoch','localtime'))"
            } else {
                // >= 14 days: 1-day buckets
                "strftime('%m-%d', datetime(contime,'unixepoch','localtime'))"
            };
            let sql = format!(
                "SELECT {time_sql} AS bucket, COUNT(*), COALESCE(SUM(send+recv),0)
                 FROM connections WHERE contime >= ?1 GROUP BY bucket ORDER BY bucket"
            );
            let mut stmt = conn.prepare(&sql)?;
            let hours: Vec<HourRow> = stmt.query_map(params![from_ts], |r| {
                Ok(HourRow { hour: r.get(0)?, flows: r.get(1)?, bytes: r.get(2)? })
            })?.filter_map(|r| r.ok()).collect();
            Ok(SummaryResp { since: since.clone(), flows, send, recv, unique_ips, hours })
        })()
    })
    .await
    .unwrap_or(Err(anyhow::anyhow!("spawn_blocking failed")))
    .unwrap_or(SummaryResp { since: since_clone, flows: 0, send: 0, recv: 0, unique_ips: 0, hours: vec![] });

    Json(result)
}

async fn api_alerts(Query(p): Query<DataParams>) -> Json<serde_json::Value> {
    let (from_ts, to_ts) = get_from_to(p.since.as_deref(), p.from, p.to);
    let rows = tokio::task::spawn_blocking(move || {
        (|| -> Result<Vec<serde_json::Value>> {
            let conn = db()?;
            let mut stmt = conn.prepare(
                "SELECT ts, rule, exe, raddr, domain, action FROM alert_events WHERE ts >= ?1 AND ts <= ?2 ORDER BY ts DESC LIMIT 500"
            )?;
            let rows = stmt.query_map(params![from_ts, to_ts], |r| {
                Ok(serde_json::json!({
                    "ts": r.get::<_,i64>(0)?,
                    "rule": r.get::<_,String>(1)?,
                    "exe": r.get::<_,String>(2)?,
                    "raddr": r.get::<_,String>(3)?,
                    "domain": r.get::<_,String>(4)?,
                    "action": r.get::<_,String>(5)?,
                }))
            })?.filter_map(|r| r.ok()).collect();
            Ok(rows)
        })()
    }).await.unwrap_or(Ok(vec![])).unwrap_or_default();
    Json(serde_json::json!({"events": rows}))
}

#[derive(Deserialize)]
struct ConnParams {
    exe:   Option<String>,
    raddr: Option<String>,
    from:  Option<i64>,
    to:    Option<i64>,
    since: Option<String>,
    limit: Option<u32>,
}

async fn api_connections(Query(p): Query<ConnParams>) -> Json<serde_json::Value> {
    let (from_ts, to_ts) = get_from_to(p.since.as_deref(), p.from, p.to);
    let limit = p.limit.unwrap_or(200);
    let exe   = p.exe.clone();
    let raddr = p.raddr.clone();

    let rows = tokio::task::spawn_blocking(move || {
        (|| -> Result<Vec<serde_json::Value>> {
            let conn = db()?;
            // Build WHERE conditions
            let (where_clause, bind_count) = match (&exe, &raddr) {
                (Some(_), Some(_)) => (
                    "WHERE c.contime >= ?1 AND c.contime <= ?2 AND e.exe LIKE ?3 AND c.raddr = ?4".to_string(),
                    4
                ),
                (Some(_), None) => (
                    "WHERE c.contime >= ?1 AND c.contime <= ?2 AND e.exe LIKE ?3".to_string(),
                    3
                ),
                (None, Some(_)) => (
                    "WHERE c.contime >= ?1 AND c.contime <= ?2 AND c.raddr = ?3".to_string(),
                    3
                ),
                (None, None) => (
                    "WHERE c.contime >= ?1 AND c.contime <= ?2".to_string(),
                    2
                ),
            };

            let sql = format!(
                "SELECT c.contime, e.exe, e.name, c.raddr, COALESCE(c.domain,''), c.rport, c.lport, c.uid, COALESCE(c.send,0), COALESCE(c.recv,0), COALESCE(e.exe,'')
                 FROM connections c JOIN executables e ON c.exe_id = e.id
                 {} ORDER BY c.contime DESC LIMIT {}", where_clause, limit
            );

            let mut stmt = conn.prepare(&sql)?;
            let rows = match bind_count {
                4 => {
                    let exe_pat = format!("%{}%", exe.as_ref().unwrap());
                    stmt.query_map(params![from_ts, to_ts, exe_pat, raddr.as_ref().unwrap()], |r| {
                        Ok(serde_json::json!({
                            "ts":     r.get::<_,i64>(0)?,
                            "exe":    r.get::<_,String>(1)?,
                            "name":   r.get::<_,String>(2)?,
                            "raddr":  r.get::<_,String>(3)?,
                            "domain": r.get::<_,String>(4)?,
                            "rport":  r.get::<_,i64>(5)?,
                            "lport":  r.get::<_,i64>(6)?,
                            "uid":    r.get::<_,i64>(7)?,
                            "send":   r.get::<_,i64>(8)?,
                            "recv":   r.get::<_,i64>(9)?,
                            "pexe":   r.get::<_,String>(10)?,
                        }))
                    })?.filter_map(|r| r.ok()).collect()
                },
                3 => {
                    if exe.is_some() {
                        let exe_pat = format!("%{}%", exe.as_ref().unwrap());
                        stmt.query_map(params![from_ts, to_ts, exe_pat], |r| {
                            Ok(serde_json::json!({
                                "ts":     r.get::<_,i64>(0)?,
                                "exe":    r.get::<_,String>(1)?,
                                "name":   r.get::<_,String>(2)?,
                                "raddr":  r.get::<_,String>(3)?,
                                "domain": r.get::<_,String>(4)?,
                                "rport":  r.get::<_,i64>(5)?,
                                "lport":  r.get::<_,i64>(6)?,
                                "uid":    r.get::<_,i64>(7)?,
                                "send":   r.get::<_,i64>(8)?,
                                "recv":   r.get::<_,i64>(9)?,
                                "pexe":   r.get::<_,String>(10)?,
                            }))
                        })?.filter_map(|r| r.ok()).collect()
                    } else {
                        stmt.query_map(params![from_ts, to_ts, raddr.as_ref().unwrap()], |r| {
                            Ok(serde_json::json!({
                                "ts":     r.get::<_,i64>(0)?,
                                "exe":    r.get::<_,String>(1)?,
                                "name":   r.get::<_,String>(2)?,
                                "raddr":  r.get::<_,String>(3)?,
                                "domain": r.get::<_,String>(4)?,
                                "rport":  r.get::<_,i64>(5)?,
                                "lport":  r.get::<_,i64>(6)?,
                                "uid":    r.get::<_,i64>(7)?,
                                "send":   r.get::<_,i64>(8)?,
                                "recv":   r.get::<_,i64>(9)?,
                                "pexe":   r.get::<_,String>(10)?,
                            }))
                        })?.filter_map(|r| r.ok()).collect()
                    }
                },
                _ => {
                    stmt.query_map(params![from_ts, to_ts], |r| {
                        Ok(serde_json::json!({
                            "ts":     r.get::<_,i64>(0)?,
                            "exe":    r.get::<_,String>(1)?,
                            "name":   r.get::<_,String>(2)?,
                            "raddr":  r.get::<_,String>(3)?,
                            "domain": r.get::<_,String>(4)?,
                            "rport":  r.get::<_,i64>(5)?,
                            "lport":  r.get::<_,i64>(6)?,
                            "uid":    r.get::<_,i64>(7)?,
                            "send":   r.get::<_,i64>(8)?,
                            "recv":   r.get::<_,i64>(9)?,
                            "pexe":   r.get::<_,String>(10)?,
                        }))
                    })?.filter_map(|r| r.ok()).collect()
                },
            };
            Ok(rows)
        })()
    }).await.unwrap_or(Ok(vec![])).unwrap_or_default();

    Json(serde_json::json!({"connections": rows}))
}

async fn api_timeseries(State(state): State<AppState>, Query(p): Query<DataParams>) -> Json<serde_json::Value> {
    let (from_ts, to_ts) = get_from_to(p.since.as_deref(), p.from, p.to);
    let dim = p.dim.unwrap_or_else(|| "exe".into());
    let col = dim_sql(&dim).to_string();
    let span = to_ts - from_ts;
    let _limit = state.top_limit;

    let result = tokio::task::spawn_blocking(move || {
        (|| -> Result<serde_json::Value> {
            let conn = db()?;
            // Auto-detect bucket granularity
            let time_sql = if span < 7200 {
                "strftime('%H:%M', datetime((contime/300)*300,'unixepoch','localtime'))"
            } else if span < 1_209_600 {
                "strftime('%m-%d %Hh', datetime(contime,'unixepoch','localtime'))"
            } else {
                "strftime('%m-%d', datetime(contime,'unixepoch','localtime'))"
            };

            // Get top N labels by total bytes
            let top_sql = format!(
                "SELECT {col} AS label, SUM(c.send+c.recv) AS total
                 FROM connections c JOIN executables e ON c.exe_id = e.id
                 WHERE c.contime >= ?1 AND c.contime <= ?2
                 GROUP BY label ORDER BY total DESC LIMIT 8"
            );
            let mut stmt = conn.prepare(&top_sql)?;
            let top_labels: Vec<String> = stmt.query_map(params![from_ts, to_ts], |r| {
                r.get::<_,String>(0)
            })?.filter_map(|r| r.ok()).collect();

            // Get all buckets
            let bucket_sql = format!(
                "SELECT DISTINCT {time_sql} AS bucket FROM connections WHERE contime >= ?1 AND contime <= ?2 ORDER BY bucket"
            );
            let mut stmt2 = conn.prepare(&bucket_sql)?;
            let buckets: Vec<String> = stmt2.query_map(params![from_ts, to_ts], |r| {
                r.get::<_,String>(0)
            })?.filter_map(|r| r.ok()).collect();

            // For each top label, get bytes per bucket
            let mut series = vec![];
            for label in &top_labels {
                let data_sql = format!(
                    "SELECT {time_sql} AS bucket, COALESCE(SUM(c.send+c.recv),0)
                     FROM connections c JOIN executables e ON c.exe_id = e.id
                     WHERE c.contime >= ?1 AND c.contime <= ?2 AND {col} = ?3
                     GROUP BY bucket"
                );
                let mut data_stmt = conn.prepare(&data_sql)?;
                let data_map: std::collections::HashMap<String,i64> = data_stmt.query_map(params![from_ts, to_ts, label], |r| {
                    Ok((r.get::<_,String>(0)?, r.get::<_,i64>(1)?))
                })?.filter_map(|r| r.ok()).collect();
                let data: Vec<i64> = buckets.iter().map(|b| data_map.get(b).copied().unwrap_or(0)).collect();
                series.push(serde_json::json!({"label": label, "data": data}));
            }

            Ok(serde_json::json!({"buckets": buckets, "series": series}))
        })()
    }).await.unwrap_or(Ok(serde_json::json!({"buckets":[],"series":[]}))).unwrap_or(serde_json::json!({"buckets":[],"series":[]}));

    Json(result)
}

#[derive(Deserialize)]
struct IgnoreReq { kind: String, value: String }

async fn api_ignore(axum::Json(body): axum::Json<IgnoreReq>) -> Json<serde_json::Value> {
    let kind = body.kind.clone();
    let value = body.value.clone();
    // Validate kind
    if !["exe", "domain", "raddr"].contains(&kind.as_str()) {
        return Json(serde_json::json!({"ok": false, "error": "invalid kind"}));
    }
    let config_dir = crate::config::config_dir();
    match crate::filter::save_extra_ignore(&config_dir, &kind, &value) {
        Ok(_) => Json(serde_json::json!({"ok": true})),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e.to_string()})),
    }
}

async fn api_export(Query(p): Query<DataParams>) -> impl axum::response::IntoResponse {
    let (from_ts, _to_ts) = get_from_to(p.since.as_deref(), p.from, p.to);
    let dim = p.dim.unwrap_or_else(|| "exe".into());
    let col = dim_sql(&dim).to_string();

    let csv = tokio::task::spawn_blocking(move || {
        (|| -> Result<String> {
            let conn = db()?;
            let sql = format!(
                "SELECT {col} AS label, COALESCE(SUM(c.send),0), COALESCE(SUM(c.recv),0), COUNT(*)
                 FROM connections c JOIN executables e ON c.exe_id = e.id
                 WHERE c.contime >= ?1
                 GROUP BY label ORDER BY SUM(c.send+c.recv) DESC"
            );
            let mut stmt = conn.prepare(&sql)?;
            let mut out = String::from("label,send,recv,flows\n");
            stmt.query_map(params![from_ts], |r| {
                Ok(format!("{},{},{},{}\n",
                    r.get::<_,String>(0).unwrap_or_default(),
                    r.get::<_,i64>(1).unwrap_or(0),
                    r.get::<_,i64>(2).unwrap_or(0),
                    r.get::<_,i64>(3).unwrap_or(0),
                ))
            })?.filter_map(|r| r.ok()).for_each(|line| out.push_str(&line));
            Ok(out)
        })()
    }).await.unwrap_or(Ok(String::new())).unwrap_or_default();

    (
        [
            ("Content-Type", "text/csv"),
            ("Content-Disposition", "attachment; filename=\"peekd-export.csv\""),
        ],
        csv,
    )
}

async fn api_config(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "refresh_seconds": state.refresh_seconds,
        "default_since":   state.default_since,
    }))
}

pub async fn serve(cfg: crate::config::WebConfig) -> Result<()> {
    let state = AppState {
        top_limit:       cfg.top_limit,
        refresh_seconds: cfg.refresh_seconds,
        default_since:   cfg.default_since.clone(),
    };

    let api = Router::new()
        .route("/config",      get(api_config))
        .route("/data",        get(api_data))
        .route("/top",         get(api_top))
        .route("/summary",     get(api_summary))
        .route("/alerts",      get(api_alerts))
        .route("/connections", get(api_connections))
        .route("/timeseries",  get(api_timeseries))
        .route("/ignore",      post(api_ignore))
        .route("/export",      get(api_export))
        .with_state(state);

    // Check if static_dir should be used
    let app: Router;
    if !cfg.static_dir.is_empty() && std::path::Path::new(&cfg.static_dir).exists() {
        use tower_http::services::ServeDir;
        app = Router::new()
            .nest("/api", api)
            .fallback_service(ServeDir::new(&cfg.static_dir));
    } else {
        app = Router::new()
            .route("/", get(|| async { Html(HTML) }))
            .nest("/api", api);
    }

    let addr = format!("{}:{}", cfg.bind, cfg.port);
    println!("peekd web UI at http://localhost:{}", cfg.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
