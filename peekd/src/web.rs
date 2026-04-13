//! web.rs: Minimal web UI for peekd.
//!
//! `peekd web [--port 5100]`
//! Serves a single-page dashboard backed by the SQLite DB.
//! Two endpoints:
//!   GET /           → embedded HTML (vanilla JS + Chart.js CDN)
//!   GET /api/data   → JSON: {dim, since, rows: [{label, send, recv, flows}]}
//!   GET /api/top    → JSON: top destinations with per-exe breakdown

use anyhow::Result;
use axum::{Router, extract::Query, response::{Html, Json}, routing::get};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

// PTR lookup cache: ip string → hostname (empty = no record)
static PTR_CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn ptr_cache() -> &'static Mutex<HashMap<String, String>> {
    PTR_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

async fn lookup_ptr(ip: &str) -> String {
    // Check cache first
    if let Ok(cache) = ptr_cache().lock() {
        if let Some(v) = cache.get(ip) {
            return v.clone();
        }
    }

    let mut result = _do_ptr_lookup(ip).await;

    // PTR failed — try whois org for public IPs
    if result.is_empty() && !_is_private(ip) {
        result = _do_whois_lookup(ip).await;
    }

    if let Ok(mut cache) = ptr_cache().lock() {
        cache.insert(ip.to_string(), result.clone());
    }
    result
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
    let out = tokio::process::Command::new("whois")
        .arg(ip)
        .output()
        .await;
    let Ok(out) = out else { return String::new() };
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
    let ip = ip.to_string();
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

#[derive(Serialize)]
struct DestSub {
    name:  String,
    uid:   i64,
    rport: i64,
    flows: i64,
    send:  i64,
    recv:  i64,
}

#[derive(Serialize)]
struct Dest {
    raddr:    String,
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

fn cutoff(since: &str) -> i64 {
    let secs: i64 = match since {
        "1h"  => 3600,
        "7d"  => 604800,
        "30d" => 2592000,
        _     => 86400,
    };
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 - secs
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
    let since = p.since.unwrap_or_else(|| "24h".into());
    let dim   = p.dim.unwrap_or_else(|| "exe".into());
    let col   = dim_sql(&dim);
    let ts    = cutoff(&since);

    let rows = (|| -> Result<Vec<DataRow>> {
        let conn = db()?;
        let sql = format!(
            "SELECT {col} AS label, COALESCE(SUM(c.send),0), COALESCE(SUM(c.recv),0), COUNT(*)
             FROM connections c JOIN executables e ON c.exe_id = e.id
             WHERE c.contime >= ?1
             GROUP BY label ORDER BY SUM(c.send+c.recv) DESC LIMIT 50"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![ts], |r| {
            Ok(DataRow { label: r.get::<_,String>(0).unwrap_or_default(), send: r.get(1)?, recv: r.get(2)?, flows: r.get(3)? })
        })?.filter_map(|r| r.ok()).collect();
        Ok(rows)
    })().unwrap_or_default();

    Json(DataResp { dim, since, rows })
}

async fn api_top(Query(p): Query<DataParams>) -> Json<TopResp> {
    let since = p.since.unwrap_or_else(|| "24h".into());
    let ts    = cutoff(&since);

    // Collect raw rows synchronously
    type RawDest = (String, String, i64, i64, i64, Vec<DestSub>);
    let raw: Vec<RawDest> = (|| -> Result<Vec<RawDest>> {
        let conn = db()?;
        let mut stmt = conn.prepare(
            "SELECT c.raddr, COALESCE(c.domain,''), COUNT(*), COALESCE(SUM(c.send),0), COALESCE(SUM(c.recv),0)
             FROM connections c JOIN executables e ON c.exe_id = e.id
             WHERE c.contime >= ?1
             GROUP BY c.raddr ORDER BY SUM(c.send+c.recv) DESC"
        )?;
        let rows: Vec<RawDest> = stmt.query_map(params![ts], |r| {
            Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?, r.get::<_,i64>(2)?, r.get::<_,i64>(3)?, r.get::<_,i64>(4)?))
        })?.filter_map(|r| r.ok()).map(|(raddr, domain, flows, send, recv)| {
            let mut stmt2 = conn.prepare(
                "SELECT e.name, c.uid, c.rport, COUNT(*), COALESCE(SUM(c.send),0), COALESCE(SUM(c.recv),0)
                 FROM connections c JOIN executables e ON c.exe_id = e.id
                 WHERE c.contime >= ?1 AND c.raddr = ?2
                 GROUP BY e.name, c.uid, c.rport ORDER BY SUM(c.send+c.recv) DESC"
            ).unwrap();
            let subs: Vec<DestSub> = stmt2.query_map(params![ts, &raddr], |r| {
                Ok(DestSub { name: r.get(0)?, uid: r.get(1)?, rport: r.get(2)?, flows: r.get(3)?, send: r.get(4)?, recv: r.get(5)? })
            }).unwrap().filter_map(|r| r.ok()).collect();
            (raddr, domain, flows, send, recv, subs)
        }).collect();
        Ok(rows)
    })().unwrap_or_default();

    // Async PTR resolve all IPs in parallel
    let mut dests = Vec::with_capacity(raw.len());
    let hostnames = futures::future::join_all(
        raw.iter().map(|(raddr, ..)| lookup_ptr(raddr))
    ).await;
    for ((raddr, domain, flows, send, recv, subs), hostname) in raw.into_iter().zip(hostnames) {
        dests.push(Dest { raddr, domain, hostname, flows, send, recv, subs });
    }

    Json(TopResp { since, dests })
}

async fn api_summary(Query(p): Query<DataParams>) -> Json<SummaryResp> {
    let since = p.since.unwrap_or_else(|| "24h".into());
    let ts    = cutoff(&since);

    let result = (|| -> Result<SummaryResp> {
        let conn = db()?;
        let (flows, send, recv): (i64, i64, i64) = conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(send),0), COALESCE(SUM(recv),0) FROM connections WHERE contime >= ?1",
            params![ts], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        )?;
        let unique_ips: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT raddr) FROM connections WHERE contime >= ?1",
            params![ts], |r| r.get(0)
        )?;
        let time_sql = match since.as_str() {
            "1h"  => "strftime('%H:%M', datetime((contime/300)*300,'unixepoch','localtime'))",
            "7d"  => "strftime('%m-%d %Hh', datetime(contime,'unixepoch','localtime'))",
            "30d" => "strftime('%m-%d', datetime(contime,'unixepoch','localtime'))",
            _     => "strftime('%H:00', datetime(contime,'unixepoch','localtime'))",
        };
        let sql = format!(
            "SELECT {time_sql} AS bucket, COUNT(*), COALESCE(SUM(send+recv),0)
             FROM connections WHERE contime >= ?1 GROUP BY bucket ORDER BY bucket"
        );
        let mut stmt = conn.prepare(&sql)?;
        let hours: Vec<HourRow> = stmt.query_map(params![ts], |r| {
            Ok(HourRow { hour: r.get(0)?, flows: r.get(1)?, bytes: r.get(2)? })
        })?.filter_map(|r| r.ok()).collect();
        Ok(SummaryResp { since: since.clone(), flows, send, recv, unique_ips, hours })
    })().unwrap_or(SummaryResp { since, flows: 0, send: 0, recv: 0, unique_ips: 0, hours: vec![] });

    Json(result)
}

pub async fn serve(port: u16) -> Result<()> {
    let app = Router::new()
        .route("/", get(|| async { Html(HTML) }))
        .route("/api/data",    get(api_data))
        .route("/api/top",     get(api_top))
        .route("/api/summary", get(api_summary));

    let addr = format!("0.0.0.0:{port}");
    println!("peekd web UI at http://localhost:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
