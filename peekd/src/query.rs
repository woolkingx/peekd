#![allow(dead_code, unused_imports)]

//! query.rs: CLI query and Unix socket RPC interface.
//!
//! v1: CLI query reads SQLite directly via rusqlite.
//! v1.5: Unix socket RPC at /run/peekd/peekd.sock, newline-delimited JSON.

use crate::config::Config;
use crate::metrics::Metrics;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Semaphore;
use rusqlite::{Connection, params_from_iter};
use rusqlite::types::ToSql;
use std::time::{SystemTime, UNIX_EPOCH};
use serde_json::{json, Value};
use anyhow::{anyhow, Result};
use std::io::Write;

/// CLI query arguments for peekd query subcommand.
#[derive(Debug, Clone, Default)]
pub struct QueryArgs {
    pub exe: Option<String>,
    pub name: Option<String>,
    pub domain: Option<String>,
    pub raddr: Option<String>,
    pub rport: Option<u16>,
    pub lport: Option<u16>,
    pub uid: Option<u32>,
    pub sha256: Option<String>,
    pub since: String,
    pub limit: usize,
    pub json: bool,
    pub count: bool,
    pub sum_bytes: bool,
}

const SELECT_COLS: &str = "SELECT c.contime, e.exe, e.name, c.raddr, c.rport, c.domain, c.send, c.recv, c.uid FROM connections c JOIN executables e ON c.exe_id = e.id";
const COUNT_PREFIX: &str = "SELECT COUNT(*) FROM connections c JOIN executables e ON c.exe_id = e.id";

/// Build WHERE clause and params dynamically using sequential ? placeholders.
fn _build_where(cutoff: i64, args: &QueryArgs) -> (String, Vec<Box<dyn ToSql>>) {
    let mut clauses = vec!["c.contime >= ?".to_string()];
    let mut p: Vec<Box<dyn ToSql>> = vec![Box::new(cutoff)];

    if let Some(exe) = &args.exe {
        clauses.push("e.exe LIKE ?".to_string());
        p.push(Box::new(format!("%{}%", exe)));
    }
    if let Some(name) = &args.name {
        clauses.push("e.name = ?".to_string());
        p.push(Box::new(name.clone()));
    }
    if let Some(domain) = &args.domain {
        clauses.push("c.domain LIKE ?".to_string());
        p.push(Box::new(format!("{}%", domain)));
    }
    if let Some(raddr) = &args.raddr {
        clauses.push("c.raddr = ?".to_string());
        p.push(Box::new(raddr.clone()));
    }
    if let Some(rport) = args.rport {
        clauses.push("c.rport = ?".to_string());
        p.push(Box::new(rport as i64));
    }
    if let Some(lport) = args.lport {
        clauses.push("c.lport = ?".to_string());
        p.push(Box::new(lport as i64));
    }
    if let Some(uid) = args.uid {
        clauses.push("c.uid = ?".to_string());
        p.push(Box::new(uid as i64));
    }
    if let Some(sha256) = &args.sha256 {
        clauses.push("e.sha256 = ?".to_string());
        p.push(Box::new(sha256.clone()));
    }

    let where_clause = format!(" WHERE {}", clauses.join(" AND "));
    (where_clause, p)
}

/// Build WHERE clause from JSON params (RPC path).
fn _build_where_rpc(cutoff: i64, params: &Value) -> (String, Vec<Box<dyn ToSql>>) {
    let mut clauses = vec!["c.contime >= ?".to_string()];
    let mut p: Vec<Box<dyn ToSql>> = vec![Box::new(cutoff)];

    if let Some(exe) = params.get("exe").and_then(|x| x.as_str()) {
        clauses.push("e.exe LIKE ?".to_string());
        p.push(Box::new(format!("%{}%", exe)));
    }
    if let Some(name) = params.get("name").and_then(|x| x.as_str()) {
        clauses.push("e.name = ?".to_string());
        p.push(Box::new(name.to_string()));
    }
    if let Some(domain) = params.get("domain").and_then(|x| x.as_str()) {
        clauses.push("c.domain LIKE ?".to_string());
        p.push(Box::new(format!("{}%", domain)));
    }
    if let Some(raddr) = params.get("raddr").and_then(|x| x.as_str()) {
        clauses.push("c.raddr = ?".to_string());
        p.push(Box::new(raddr.to_string()));
    }
    if let Some(rport) = params.get("rport").and_then(|v| v.as_u64()) {
        clauses.push("c.rport = ?".to_string());
        p.push(Box::new(rport as i64));
    }
    if let Some(lport) = params.get("lport").and_then(|v| v.as_u64()) {
        clauses.push("c.lport = ?".to_string());
        p.push(Box::new(lport as i64));
    }
    if let Some(uid) = params.get("uid").and_then(|v| v.as_u64()) {
        clauses.push("c.uid = ?".to_string());
        p.push(Box::new(uid as i64));
    }
    if let Some(sha256) = params.get("sha256").and_then(|v| v.as_str()) {
        clauses.push("e.sha256 = ?".to_string());
        p.push(Box::new(sha256.to_string()));
    }

    let where_clause = format!(" WHERE {}", clauses.join(" AND "));
    (where_clause, p)
}

/// Execute CLI query.
pub fn query_cli(args: &QueryArgs, _config: &Config) -> Result<()> {
    let db_path = crate::config::db_path();
    if !db_path.exists() {
        return Err(anyhow!("database not found: {:?}", db_path));
    }

    let conn = Connection::open(&db_path)?;
    let since_secs = match args.since.as_str() {
        "1h" => 3600,
        "24h" => 86400,
        "7d" => 604800,
        "30d" => 2592000,
        _ => return Err(anyhow!("invalid duration: {}", args.since)),
    };
    let cutoff = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs() as i64 - since_secs;

    if args.sum_bytes {
        _output_sum_bytes(&conn, cutoff, args)?;
    } else if args.count {
        _output_count(&conn, cutoff, args)?;
    } else if args.json {
        _output_json(&conn, cutoff, args)?;
    } else {
        _output_table(&conn, cutoff, args)?;
    }

    Ok(())
}

/// Serve RPC over Unix socket.
pub async fn serve(config: Arc<Config>, metrics: Arc<Metrics>) -> Result<()> {
    let sock_path = crate::config::run_dir().join("peekd.sock");
    let _ = std::fs::remove_file(&sock_path);

    let listener = UnixListener::bind(&sock_path)?;
    tracing::info!("listening on {:?}", sock_path);

    // Limit concurrent RPC connections to prevent resource exhaustion.
    // 16 is generous for a local CLI tool; excess connections are dropped.
    let sem = Arc::new(Semaphore::new(16));

    loop {
        if let Ok((stream, _)) = listener.accept().await {
            match sem.clone().try_acquire_owned() {
                Ok(permit) => {
                    let config = config.clone();
                    let metrics = metrics.clone();
                    tokio::spawn(async move {
                        let _permit = permit; // dropped when handler exits
                        if let Err(e) = _handle_rpc_conn(stream, &config, &metrics).await {
                            tracing::error!("rpc handler error: {}", e);
                        }
                    });
                }
                Err(_) => {
                    tracing::warn!("rpc connection limit reached, dropping connection");
                }
            }
        }
    }
}

async fn _handle_rpc_conn(socket: tokio::net::UnixStream, config: &Config, metrics: &Metrics) -> Result<()> {
    let (reader, mut writer) = socket.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let req: Value = serde_json::from_str(&line)?;
        let resp = _dispatch_rpc(&req, config, metrics)?;
        writer.write_all(serde_json::to_string(&resp)?.as_bytes()).await?;
        writer.write_u8(b'\n').await?;
    }
    Ok(())
}

fn _dispatch_rpc(req: &Value, _config: &Config, metrics: &Metrics) -> Result<Value> {
    let cmd = req.get("cmd").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("missing cmd field"))?;

    match cmd {
        "reload_config" => Ok(json!({"ok": true})),
        "status" => {
            use std::sync::atomic::Ordering;
            Ok(json!({"ok": true, "pid": std::process::id(), "events_total": metrics.events_total.load(Ordering::Relaxed)}))
        }
        "query" => _query_rpc(req.get("params").ok_or_else(|| anyhow!("missing params"))?),
        _ => Err(anyhow!("unknown cmd: {}", cmd))
    }
}

fn _query_rpc(rpc_params: &Value) -> Result<Value> {
    let db_path = crate::config::db_path();
    if !db_path.exists() {
        return Err(anyhow!("database not found"));
    }

    let conn = Connection::open(&db_path)?;
    // M-1: clamp since to [1, 365 days] to prevent full-table-scan DoS via negative/huge values
    let since = rpc_params.get("since").and_then(|v| v.as_u64()).unwrap_or(86400)
        .clamp(1, 365 * 86400) as i64;
    let cutoff = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64 - since;
    let limit = rpc_params.get("limit").and_then(|v| v.as_u64()).unwrap_or(100)
        .clamp(1, 10_000) as i64;

    let (where_clause, mut p) = _build_where_rpc(cutoff, rpc_params);
    let sql = format!("{}{} ORDER BY c.contime DESC LIMIT ?", SELECT_COLS, where_clause);
    p.push(Box::new(limit));

    let p_refs: Vec<&dyn ToSql> = p.iter().map(|b| b.as_ref()).collect();
    let mut stmt = conn.prepare(&sql)?;
    let mut results = Vec::new();
    for row in stmt.query_map(p_refs.as_slice(), |row| {
        Ok(json!({
            "time": _fmt_time(row.get::<_, i64>(0)?),
            "exe": row.get::<_, String>(1)?,
            "name": row.get::<_, String>(2)?,
            "raddr": row.get::<_, String>(3)?,
            "rport": row.get::<_, u16>(4)?,
            "domain": row.get::<_, String>(5)?,
            "send": row.get::<_, u32>(6)?,
            "recv": row.get::<_, u32>(7)?,
            "uid": row.get::<_, u32>(8)?
        }))
    })? {
        results.push(row?);
    }
    Ok(json!({"ok": true, "rows": results}))
}

fn _output_table(conn: &Connection, cutoff: i64, args: &QueryArgs) -> Result<()> {
    let (where_clause, mut p) = _build_where(cutoff, args);
    let sql = format!("{}{} ORDER BY c.contime DESC LIMIT ?", SELECT_COLS, where_clause);
    p.push(Box::new(args.limit as i64));

    let p_refs: Vec<&dyn ToSql> = p.iter().map(|b| b.as_ref()).collect();
    let mut stmt = conn.prepare(&sql)?;
    let mut tw = tabwriter::TabWriter::new(std::io::stdout());
    writeln!(tw, "TIME\tEXE\tNAME\tRADDR\tRPORT\tDOMAIN\tSEND\tRECV")?;
    for row in stmt.query_map(p_refs.as_slice(), |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, u16>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, u32>(6)?,
            row.get::<_, u32>(7)?,
        ))
    })? {
        let (time, exe, name, raddr, rport, domain, send, recv) = row?;
        writeln!(tw, "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            _fmt_time(time), exe, name, raddr, rport, domain,
            _fmt_bytes(send as u64), _fmt_bytes(recv as u64))?;
    }
    tw.flush()?;
    Ok(())
}

fn _output_json(conn: &Connection, cutoff: i64, args: &QueryArgs) -> Result<()> {
    let (where_clause, mut p) = _build_where(cutoff, args);
    let sql = format!("{}{} ORDER BY c.contime DESC LIMIT ?", SELECT_COLS, where_clause);
    p.push(Box::new(args.limit as i64));

    let p_refs: Vec<&dyn ToSql> = p.iter().map(|b| b.as_ref()).collect();
    let mut stmt = conn.prepare(&sql)?;
    for row in stmt.query_map(p_refs.as_slice(), |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, u16>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, u32>(6)?,
            row.get::<_, u32>(7)?,
            row.get::<_, u32>(8)?,
        ))
    })? {
        let (time, exe, name, raddr, rport, domain, send, recv, uid) = row?;
        println!("{}", serde_json::to_string(&json!({
            "time": _fmt_time(time), "exe": exe, "name": name,
            "raddr": raddr, "rport": rport, "domain": domain,
            "send": send, "recv": recv, "uid": uid
        }))?);
    }
    Ok(())
}

fn _output_count(conn: &Connection, cutoff: i64, args: &QueryArgs) -> Result<()> {
    let (where_clause, p) = _build_where(cutoff, args);
    let sql = format!("{}{}", COUNT_PREFIX, where_clause);

    let p_refs: Vec<&dyn ToSql> = p.iter().map(|b| b.as_ref()).collect();
    let count: i64 = conn.query_row(&sql, p_refs.as_slice(), |row| row.get(0))?;
    println!("{}", count);
    Ok(())
}

fn _output_sum_bytes(conn: &Connection, cutoff: i64, args: &QueryArgs) -> Result<()> {
    let (where_clause, p) = _build_where(cutoff, args);
    let sql = format!(
        "SELECT e.exe, SUM(c.send), SUM(c.recv) \
         FROM connections c JOIN executables e ON c.exe_id = e.id\
         {} GROUP BY e.exe ORDER BY SUM(c.send) + SUM(c.recv) DESC",
        where_clause
    );
    let p_refs: Vec<&dyn ToSql> = p.iter().map(|b| b.as_ref()).collect();
    let mut stmt = conn.prepare(&sql)?;
    let mut tw = tabwriter::TabWriter::new(std::io::stdout());
    writeln!(tw, "EXE\tSEND_TOTAL\tRECV_TOTAL")?;
    for row in stmt.query_map(p_refs.as_slice(), |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?, row.get::<_, u64>(2)?)))? {
        let (exe, send, recv) = row?;
        writeln!(tw, "{}\t{}\t{}", exe, _fmt_bytes(send), _fmt_bytes(recv))?;
    }
    tw.flush()?;
    Ok(())
}

fn _fmt_time(ts: i64) -> String {
    use chrono::{Local, TimeZone};
    match Local.timestamp_opt(ts, 0) {
        chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        _ => format!("{}", ts),
    }
}

fn _fmt_bytes(b: u64) -> String {
    let u = ["B", "KB", "MB", "GB", "TB"];
    let mut s = b as f64;
    let mut i = 0;
    while s >= 1024.0 && i < u.len() - 1 { s /= 1024.0; i += 1; }
    if i == 0 { format!("{}{}", b, u[0]) } else { format!("{:.1}{}", s, u[i]) }
}
