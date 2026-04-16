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
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use lru::LruCache;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;

const PTR_CACHE_CAP: usize = 10_000;
const PTR_SEMAPHORE_LIMIT: usize = 64;
const WHOIS_TIMEOUT_SECS: u64 = 3;

// PTR lookup cache: ip string → hostname (empty = no record). LRU-bounded.
static PTR_CACHE: OnceLock<Mutex<LruCache<String, String>>> = OnceLock::new();

fn ptr_cache() -> &'static Mutex<LruCache<String, String>> {
    PTR_CACHE.get_or_init(|| {
        Mutex::new(LruCache::new(NonZeroUsize::new(PTR_CACHE_CAP).unwrap()))
    })
}

async fn lookup_ptr(ip: &str) -> String {
    // Check cache first
    if let Ok(mut cache) = ptr_cache().lock() {
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
        cache.put(ip.to_string(), result.clone());
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
    let fut = tokio::process::Command::new("whois").arg(ip).output();
    let Ok(Ok(out)) = tokio::time::timeout(Duration::from_secs(WHOIS_TIMEOUT_SECS), fut).await
    else { return String::new() };
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

static EMBEDDED_HTML: &str = include_str!("web.html");

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

#[derive(Deserialize)]
struct DataParams {
    from: Option<i64>,
    to:   Option<i64>,
    dim:  Option<String>,
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
    dim:  String,
    from: i64,
    to:   i64,
    rows: Vec<DataRow>,
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
    from:  i64,
    to:    i64,
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
    from:       i64,
    to:         i64,
    flows:      i64,
    send:       i64,
    recv:       i64,
    unique_ips: i64,
    hours:      Vec<HourRow>,
}

#[derive(Serialize)]
struct ConfigResp {
    refresh_seconds: u64,
    default_since:   String,
    top_limit:       u32,
}

async fn api_config() -> Json<ConfigResp> {
    let cfg = crate::config::load().unwrap_or_default();
    Json(ConfigResp {
        refresh_seconds: cfg.web.refresh_seconds,
        default_since:   cfg.web.default_since,
        top_limit:       cfg.web.top_limit,
    })
}

fn db() -> Result<Connection> {
    let path = crate::config::db_path();
    let conn = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let _ = conn.execute_batch("PRAGMA journal_mode=WAL;");
    Ok(conn)
}

fn bucket_sql(span: i64) -> &'static str {
    if span <= 7_200 {
        "strftime('%H:%M', datetime((contime/300)*300,'unixepoch','localtime'))"
    } else if span <= 1_209_600 {
        "strftime('%H:00', datetime(contime,'unixepoch','localtime'))"
    } else {
        "strftime('%m-%d', datetime(contime,'unixepoch','localtime'))"
    }
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
    let now  = now_unix();
    let to   = p.to.unwrap_or(now);
    let from = p.from.unwrap_or(to - 86400);
    let dim  = p.dim.unwrap_or_else(|| "exe".into());
    let col  = dim_sql(&dim);

    let rows = tokio::task::spawn_blocking(move || -> Vec<DataRow> {
        (|| -> Result<Vec<DataRow>> {
            let conn = db()?;
            let sql = format!(
                "SELECT {col} AS label, COALESCE(SUM(c.send),0), COALESCE(SUM(c.recv),0), COUNT(*)
                 FROM connections c JOIN executables e ON c.exe_id = e.id
                 WHERE c.contime >= ?1 AND c.contime <= ?2
                 GROUP BY label ORDER BY SUM(c.send+c.recv) DESC LIMIT 50"
            );
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(params![from, to], |r| {
                Ok(DataRow { label: r.get::<_,String>(0).unwrap_or_default(), send: r.get(1)?, recv: r.get(2)?, flows: r.get(3)? })
            })?.filter_map(|r| r.ok()).collect();
            Ok(rows)
        })().unwrap_or_default()
    }).await.unwrap_or_default();

    Json(DataResp { dim, from, to, rows })
}

async fn api_top(Query(p): Query<DataParams>) -> Json<TopResp> {
    let now       = now_unix();
    let to        = p.to.unwrap_or(now);
    let from      = p.from.unwrap_or(to - 86400);
    let top_limit = crate::config::load().map(|c| c.web.top_limit).unwrap_or(200);

    // Single JOIN query — collect dest aggregates + per-exe subs in one pass
    type RawDest = (String, String, i64, i64, i64, Vec<DestSub>);
    let raw: Vec<RawDest> = tokio::task::spawn_blocking(move || -> Vec<RawDest> {
        (|| -> Result<Vec<RawDest>> {
            let conn = db()?;

            // Step 1: top destinations (bounded by top_limit)
            let mut dest_stmt = conn.prepare(
                "SELECT c.raddr, COALESCE(c.domain,''), COUNT(*), COALESCE(SUM(c.send),0), COALESCE(SUM(c.recv),0)
                 FROM connections c JOIN executables e ON c.exe_id = e.id
                 WHERE c.contime >= ?1 AND c.contime <= ?2
                 GROUP BY c.raddr ORDER BY SUM(c.send+c.recv) DESC LIMIT ?3"
            )?;
            let dest_rows: Vec<(String, String, i64, i64, i64)> = dest_stmt
                .query_map(params![from, to, top_limit], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })?.filter_map(|r| r.ok()).collect();

            // Step 2: single JOIN for all subs of the top destinations
            let raddrs: Vec<String> = dest_rows.iter().map(|(r, ..)| r.clone()).collect();
            if raddrs.is_empty() {
                return Ok(vec![]);
            }
            let placeholders = raddrs.iter().enumerate()
                .map(|(i, _)| format!("?{}", i + 3))
                .collect::<Vec<_>>().join(",");
            let sub_sql = format!(
                "SELECT c.raddr, e.name, c.uid, c.rport, COUNT(*), COALESCE(SUM(c.send),0), COALESCE(SUM(c.recv),0)
                 FROM connections c JOIN executables e ON c.exe_id = e.id
                 WHERE c.contime >= ?1 AND c.contime <= ?2 AND c.raddr IN ({placeholders})
                 GROUP BY c.raddr, e.name, c.uid, c.rport"
            );
            let mut sub_stmt = conn.prepare(&sub_sql)?;
            let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(from), Box::new(to)];
            for r in &raddrs { params_vec.push(Box::new(r.clone())); }
            let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

            let mut subs_map: HashMap<String, Vec<DestSub>> = HashMap::new();
            sub_stmt.query_map(params_refs.as_slice(), |r| {
                Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?, r.get::<_,i64>(2)?,
                    r.get::<_,i64>(3)?, r.get::<_,i64>(4)?, r.get::<_,i64>(5)?, r.get::<_,i64>(6)?))
            })?.filter_map(|r| r.ok()).for_each(|(raddr, name, uid, rport, flows, send, recv)| {
                subs_map.entry(raddr).or_default().push(DestSub { name, uid, rport, flows, send, recv });
            });

            // Sort subs by send+recv DESC (HashMap insertion is unordered)
            for subs in subs_map.values_mut() {
                subs.sort_unstable_by(|a, b| (b.send + b.recv).cmp(&(a.send + a.recv)));
            }

            let rows = dest_rows.into_iter().map(|(raddr, domain, flows, send, recv)| {
                let subs = subs_map.remove(&raddr).unwrap_or_default();
                (raddr, domain, flows, send, recv, subs)
            }).collect();
            Ok(rows)
        })().unwrap_or_default()
    }).await.unwrap_or_default();

    // PTR resolve with concurrency cap to prevent unbounded subprocess spawning
    let sem = std::sync::Arc::new(Semaphore::new(PTR_SEMAPHORE_LIMIT));
    let mut dests = Vec::with_capacity(raw.len());
    let hostnames = futures::future::join_all(raw.iter().map(|(raddr, ..)| {
        let sem = sem.clone();
        let raddr = raddr.clone();
        async move {
            let _permit = sem.acquire().await;
            lookup_ptr(&raddr).await
        }
    })).await;
    for ((raddr, domain, flows, send, recv, subs), hostname) in raw.into_iter().zip(hostnames) {
        dests.push(Dest { raddr, domain, hostname, flows, send, recv, subs });
    }

    Json(TopResp { from, to, dests })
}

async fn api_summary(Query(p): Query<DataParams>) -> Json<SummaryResp> {
    let now  = now_unix();
    let to   = p.to.unwrap_or(now);
    let from = p.from.unwrap_or(to - 86400);
    let span = to - from;

    let result = tokio::task::spawn_blocking(move || -> SummaryResp {
        let zero = || SummaryResp { from, to, flows: 0, send: 0, recv: 0, unique_ips: 0, hours: vec![] };
        (|| -> Result<SummaryResp> {
            let conn = db()?;
            let (flows, send, recv): (i64, i64, i64) = conn.query_row(
                "SELECT COUNT(*), COALESCE(SUM(send),0), COALESCE(SUM(recv),0)
                 FROM connections WHERE contime >= ?1 AND contime <= ?2",
                params![from, to], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            )?;
            let unique_ips: i64 = conn.query_row(
                "SELECT COUNT(DISTINCT raddr) FROM connections WHERE contime >= ?1 AND contime <= ?2",
                params![from, to], |r| r.get(0)
            )?;
            let time_sql = bucket_sql(span);
            let sql = format!(
                "SELECT {time_sql} AS bucket, COUNT(*), COALESCE(SUM(send+recv),0)
                 FROM connections WHERE contime >= ?1 AND contime <= ?2
                 GROUP BY bucket ORDER BY bucket"
            );
            let mut stmt = conn.prepare(&sql)?;
            let hours: Vec<HourRow> = stmt.query_map(params![from, to], |r| {
                Ok(HourRow { hour: r.get(0)?, flows: r.get(1)?, bytes: r.get(2)? })
            })?.filter_map(|r| r.ok()).collect();
            Ok(SummaryResp { from, to, flows, send, recv, unique_ips, hours })
        })().unwrap_or_else(|_| zero())
    }).await.unwrap_or_else(|_| SummaryResp { from, to, flows: 0, send: 0, recv: 0, unique_ips: 0, hours: vec![] });

    Json(result)
}

async fn serve_static(
    axum::extract::Path(path): axum::extract::Path<String>,
    axum::extract::State(static_dir): axum::extract::State<PathBuf>,
) -> impl IntoResponse {
    let file_path = static_dir.join(&path);
    // Prevent directory traversal: resolved path must stay under static_dir
    let Ok(canonical_dir)  = static_dir.canonicalize() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, [(header::CONTENT_TYPE, "text/plain")], vec![]).into_response();
    };
    let Ok(canonical_file) = file_path.canonicalize() else {
        return (StatusCode::NOT_FOUND, [(header::CONTENT_TYPE, "text/plain")], vec![]).into_response();
    };
    if !canonical_file.starts_with(&canonical_dir) {
        return (StatusCode::FORBIDDEN, [(header::CONTENT_TYPE, "text/plain")], vec![]).into_response();
    }
    let mime = mime_from_path(&path);
    match tokio::fs::read(&canonical_file).await {
        Ok(bytes) => (StatusCode::OK, [(header::CONTENT_TYPE, mime)], bytes).into_response(),
        Err(_)    => (StatusCode::NOT_FOUND, [(header::CONTENT_TYPE, "text/plain")], vec![]).into_response(),
    }
}

fn mime_from_path(path: &str) -> &'static str {
    if path.ends_with(".js")   { "application/javascript; charset=utf-8" }
    else if path.ends_with(".css")  { "text/css; charset=utf-8" }
    else if path.ends_with(".html") { "text/html; charset=utf-8" }
    else if path.ends_with(".json") { "application/json" }
    else if path.ends_with(".svg")  { "image/svg+xml" }
    else { "application/octet-stream" }
}

pub async fn serve(port: u16, bind: &str, static_dir: &str) -> Result<()> {
    let use_disk = !static_dir.is_empty();
    let sdir     = PathBuf::from(static_dir);

    let app = if use_disk {
        let index_path = sdir.join("index.html");
        let sdir_clone = sdir.clone();
        Router::new()
            .route("/", get(move || {
                let p = index_path.clone();
                async move {
                    match tokio::fs::read_to_string(&p).await {
                        Ok(html) => Html(html).into_response(),
                        Err(_)   => (StatusCode::NOT_FOUND, "index.html not found").into_response(),
                    }
                }
            }))
            .route("/*path", get(serve_static))
            .with_state(sdir_clone)
    } else {
        Router::new()
            .route("/", get(|| async { Html(EMBEDDED_HTML) }))
            .with_state(PathBuf::new())
    }
    .route("/api/data",    get(api_data))
    .route("/api/top",     get(api_top))
    .route("/api/summary", get(api_summary))
    .route("/api/config",  get(api_config));

    let addr = format!("{bind}:{port}");
    println!("peekd web UI at http://localhost:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
