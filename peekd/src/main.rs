#![allow(dead_code, unused_imports)]

//! peekd: Per-process network attribution daemon via eBPF.
//!
//! Usage:
//!   peekd daemon              — run the monitoring daemon (requires root)
//!   peekd report [OPTIONS]    — generate a traffic report
//!   peekd web [--port 5100]   — serve the web dashboard
//!   peekd query [OPTIONS]     — query the local database
//!
//! Async daemon that wires all modules into a streaming pipeline:
//! BPF → resolver → filter → hasher → broadcast → [storage, alerts, state]

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;
use tokio::sync::{Mutex, broadcast};
use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{info, warn, error};

mod bpf;
mod report;
mod web;
mod resolver;
mod fd_cache;
mod dns;
mod hasher;
mod filter;
mod storage;
mod state;
mod notify;
mod query;
mod alerts;
mod metrics;
mod fuse;
mod types;
mod config;
mod connection_lifecycle;

#[derive(Parser)]
#[command(name = "peekd", about = "Per-process network attribution daemon")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the monitoring daemon (requires root)
    Daemon {
        /// Enable web dashboard on this port (overrides config [web])
        #[arg(long)]
        web_port: Option<u16>,
    },
    /// Generate a traffic report
    Report {
        /// Time window: 1h, 24h, 7d, 30d
        #[arg(long, default_value = "24h")]
        since: String,
        /// Top N destinations to show (omit for all)
        #[arg(long)]
        top: Option<usize>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Serve web dashboard
    Web {
        /// Port to listen on
        #[arg(long, default_value = "5100")]
        port: u16,
    },
    /// Query the local database
    Query {
        /// Filter by executable path (substring match)
        #[arg(long)]
        exe: Option<String>,
        /// Filter by process name
        #[arg(long)]
        name: Option<String>,
        /// Filter by domain prefix
        #[arg(long)]
        domain: Option<String>,
        /// Filter by remote address
        #[arg(long)]
        raddr: Option<String>,
        /// Filter by remote port
        #[arg(long)]
        rport: Option<u16>,
        /// Filter by local port
        #[arg(long)]
        lport: Option<u16>,
        /// Filter by UID
        #[arg(long)]
        uid: Option<u32>,
        /// Filter by SHA256
        #[arg(long)]
        sha256: Option<String>,
        /// Time window: 1h, 24h, 7d, 30d
        #[arg(long, default_value = "24h")]
        since: String,
        /// Max rows
        #[arg(long, default_value = "100")]
        limit: usize,
        /// Output as JSON lines
        #[arg(long)]
        json: bool,
        /// Output count only
        #[arg(long)]
        count: bool,
        /// Output total bytes per exe
        #[arg(long)]
        sum_bytes: bool,
    },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Web { port }) => {
            let mut cfg = config::load().map_err(|e| anyhow::anyhow!("{}", e))
                .map(|c| c.web)
                .unwrap_or_default();
            cfg.port = port;
            return web::serve(cfg).await;
        }
        Some(Commands::Report { since, top, json }) => {
            let config = config::load().map_err(|e| anyhow::anyhow!("{}", e))?;
            let args = report::ReportArgs { since, top, json };
            return report::run_report(&args, &config);
        }
        Some(Commands::Query { exe, name, domain, raddr, rport, lport, uid, sha256, since, limit, json, count, sum_bytes }) => {
            let config = config::load().map_err(|e| anyhow::anyhow!("{}", e))?;
            let args = query::QueryArgs {
                exe, name, domain, raddr, rport, lport, uid, sha256,
                since, limit, json, count, sum_bytes,
            };
            return query::query_cli(&args, &config);
        }
        Some(Commands::Daemon { .. }) | None => {
            // Fall through to daemon mode
        }
    }

    let web_port = match cli.command {
        Some(Commands::Daemon { web_port }) => web_port,
        _ => None,
    };

    info!("starting peekd daemon");

    let config = Arc::new(config::load().map_err(|e| anyhow::anyhow!("{}", e))?);
    let metrics = Arc::new(metrics::Metrics::default());
    let start_time = Instant::now();

    // Initialize directories
    let _ = std::fs::create_dir_all(config::run_dir());
    let _ = std::fs::create_dir_all(config::data_dir());
    let _ = std::fs::create_dir_all(config::log_dir());

    // Initialize structured logging → /var/log/peekd/peekd.YYYY-MM-DD.log
    let file_appender = tracing_appender::rolling::daily(config::log_dir(), "peekd.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(non_blocking)
        .init();

    // DNS map: shared LRU cache for IP → domain resolution
    let dns_map_inner = dns::new_dns_map(10_000);
    let dns_map = Arc::new(dns_map_inner.clone());

    // fanotify for executable modification tracking
    let fan_fd = match bpf::init_fanotify() {
        Ok(fd) => Some(fd),
        Err(e) => {
            warn!("fanotify init failed: {}", e);
            None
        }
    };

    // fd_cache with fanotify integration
    let fd_cache = Arc::new(Mutex::new(fd_cache::FdCache::new(
        fan_fd,
        config.monitoring.fd_cache_size,
        metrics.clone(),
    )));

    // Application state for tracking known exes/hashes
    // seen_set is a lightweight RwLock<HashSet> for the filter hot path.
    // It avoids locking the full AppState Mutex on every filtered event.
    let loaded_state = state::AppState::load(&config);
    let seen_set = loaded_state.build_seen_set();
    let exe_seen_set = loaded_state.build_exe_seen_set();
    let app_state = Arc::new(Mutex::new(loaded_state));

    // Signal handling flag for graceful shutdown
    let shutdown = Arc::new(AtomicBool::new(false));

    // 1. fanotify watcher task
    let fd_cache_clone = fd_cache.clone();
    let metrics_clone = metrics.clone();
    tokio::spawn(async move {
        fd_cache::fanotify_watcher(fd_cache_clone, metrics_clone).await;
    });

    // 2. metrics writer task
    let metrics_clone = metrics.clone();
    let config_clone = config.clone();
    tokio::spawn(async move {
        metrics::writer(metrics_clone, config_clone, start_time).await;
    });

    // 2b. Pipeline stats logger (debug: periodic counters to log)
    let metrics_clone = metrics.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
        loop {
            interval.tick().await;
            let total = metrics_clone.events_total.load(std::sync::atomic::Ordering::Relaxed);
            let dropped = metrics_clone.events_dropped.load(std::sync::atomic::Ordering::Relaxed);
            let filtered = metrics_clone.events_filtered.load(std::sync::atomic::Ordering::Relaxed);
            let sendv4 = metrics_clone.events_sendv4.load(std::sync::atomic::Ordering::Relaxed);
            let recvv4 = metrics_clone.events_recvv4.load(std::sync::atomic::Ordering::Relaxed);
            let exec = metrics_clone.events_exec.load(std::sync::atomic::Ordering::Relaxed);
            let dns = metrics_clone.events_dns.load(std::sync::atomic::Ordering::Relaxed);
            let alerts = metrics_clone.alerts_fired.load(std::sync::atomic::Ordering::Relaxed);
            let writes = metrics_clone.sqlite_writes.load(std::sync::atomic::Ordering::Relaxed);
            info!(
                "pipeline: total={} sendv4={} recvv4={} exec={} dns={} filtered={} dropped={} alerts={} writes={}",
                total, sendv4, recvv4, exec, dns, filtered, dropped, alerts, writes
            );
        }
    });

    // 3. query serve (Unix socket RPC)
    let config_clone = config.clone();
    let metrics_clone = metrics.clone();
    tokio::spawn(async move {
        if let Err(e) = query::serve(config_clone, metrics_clone).await {
            error!("query serve error: {}", e);
        }
    });

    // 3b. Web dashboard (optional)
    {
        let mut web_cfg = config.web.clone();
        if let Some(p) = web_port { web_cfg.port = p; web_cfg.enabled = true; }
        if web_cfg.enabled && web_cfg.port > 0 {
            tokio::spawn(async move {
                if let Err(e) = web::serve(web_cfg).await {
                    error!("web serve error: {}", e);
                }
            });
        }
    }

    // 4. BPF event source
    let raw_tx = bpf::events(metrics.clone()).await?;

    // 4b. Connection lifecycle tracker (v2)
    {
        let db_path = config::db_path();
        let lifecycle_db = rusqlite::Connection::open(&db_path)
            .map_err(|e| anyhow::anyhow!("failed to open db for connection_lifecycle: {}", e))?;
        lifecycle_db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(|e| anyhow::anyhow!("failed to set WAL mode for lifecycle db: {}", e))?;
        connection_lifecycle::create_table(&lifecycle_db)
            .map_err(|e| anyhow::anyhow!("failed to create connections_meta table: {}", e))?;
        let lifecycle_db = Arc::new(Mutex::new(lifecycle_db));

        let (lifecycle_tx, lifecycle_rx) = tokio::sync::mpsc::channel(1024);
        let lifecycle_db_clone = lifecycle_db.clone();
        tokio::spawn(async move {
            connection_lifecycle::write_meta(lifecycle_rx, lifecycle_db_clone).await;
        });

        let raw_rx_lifecycle = raw_tx.subscribe();
        let metrics_clone = metrics.clone();
        let metrics_lifecycle = metrics.clone();
        tokio::spawn(async move {
            let mut rx = raw_rx_lifecycle;
            let mut tracker = connection_lifecycle::ConnectionTracker::new(metrics_clone);
            loop {
                match rx.recv().await {
                    Ok(types::RawEvent::Connect(raw)) => {
                        use std::net::{IpAddr, Ipv4Addr};
                        let event = connection_lifecycle::ConnectEvent {
                            pid: raw.pid,
                            ppid: raw.ppid,
                            uid: raw.uid,
                            exe: String::from_utf8_lossy(&raw.comm).trim_end_matches('\0').to_string(),
                            laddr: IpAddr::V4(Ipv4Addr::from(raw.saddr.swap_bytes())),
                            lport: raw.sport,
                            raddr: IpAddr::V4(Ipv4Addr::from(raw.daddr.swap_bytes())),
                            rport: raw.dport,
                            direction: if raw.direction == 0 {
                                connection_lifecycle::Direction::Outbound
                            } else {
                                connection_lifecycle::Direction::Inbound
                            },
                            event_type: if raw.event_type == 0 {
                                connection_lifecycle::ConnectEventType::Connect
                            } else {
                                connection_lifecycle::ConnectEventType::Close
                            },
                            timestamp: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs() as i64,
                        };
                        let record = match event.event_type {
                            connection_lifecycle::ConnectEventType::Connect => tracker.on_connect(event),
                            connection_lifecycle::ConnectEventType::Close => tracker.on_close(event),
                        };
                        if let Some(record) = record {
                            let _ = lifecycle_tx.send(record).await;
                        }
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("lifecycle task lagged, dropping {} events", n);
                        metrics_lifecycle.events_dropped.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    // 5. DNS update task (consumes RawEvent::Dns variants)
    let raw_rx_dns = raw_tx.subscribe();
    let dns_map_inner_clone = dns_map_inner.clone();
    let metrics_clone = metrics.clone();
    tokio::spawn(async move {
        dns::run(raw_rx_dns, dns_map_inner_clone, metrics_clone).await;
    });

    // 6. Resolver task (RawEvent → BpfEvent)
    let raw_rx_resolver = raw_tx.subscribe();
    let (resolved_tx, _) = broadcast::channel(config.broadcast.channel_capacity);
    let fd_cache_clone = fd_cache.clone();
    let dns_map_clone = dns_map.clone();
    let config_clone = config.clone();
    let metrics_clone = metrics.clone();
    let resolved_tx_clone = resolved_tx.clone();
    tokio::spawn(async move {
        resolver::run(
            raw_rx_resolver,
            resolved_tx_clone,
            fd_cache_clone,
            dns_map_clone,
            config_clone,
            metrics_clone,
        )
        .await;
    });

    // 6b. Fuse worker (non-root hash for FUSE executables)
    let (fuse_tx, fuse_rx) = tokio::sync::mpsc::channel(64);
    let fuse_user = config.desktop.user.clone();
    tokio::spawn(async move {
        fuse::worker(fuse_rx, fuse_user, 5000).await;
    });

    // 6c. Notify channel (desktop notifications)
    let (notify_tx, notify_rx) = tokio::sync::mpsc::channel(64);
    let config_clone = config.clone();
    tokio::spawn(async move {
        notify::run(notify_rx, config_clone).await;
    });

    // 7. Hasher task (populate sha256 fields)
    let (hashed_tx, _) = broadcast::channel(config.broadcast.channel_capacity);
    let resolved_rx_hasher = resolved_tx.subscribe();
    let config_clone = config.clone();
    let hashed_tx_clone = hashed_tx.clone();
    let fd_cache_clone = fd_cache.clone();
    let _metrics_clone = metrics.clone();
    tokio::spawn(async move {
        hasher::run(
            resolved_rx_hasher,
            hashed_tx_clone,
            config_clone,
            Some(fuse_tx),
            fd_cache_clone,
        )
        .await;
    });

    // 8. Filter+Enrich task (filter → state enrichment → broadcast)
    //
    // State enrichment (is_new_hash) is performed HERE, before the broadcast,
    // so all downstream consumers (alerts, storage) see the correct flag.
    // This avoids the race where state task sets is_new_hash on a local copy
    // while alerts/storage have already received the original with is_new_hash=false.
    let (filtered_tx, _) = broadcast::channel(config.broadcast.channel_capacity);
    let hashed_rx_filter = hashed_tx.subscribe();
    let filter_chain = filter::new_chain(&config);
    let filter_chain_reload = filter_chain.clone();
    let filtered_tx_clone = filtered_tx.clone();
    let metrics_enrich = metrics.clone();

    // State mpsc: filter task sends events to background state task which runs handle_event.
    // This decouples the AppState Mutex from the filter hot path.
    let (state_event_tx, mut state_event_rx) = tokio::sync::mpsc::channel::<types::BpfEvent>(4096);
    let seen_set_enrich = seen_set.clone();
    let exe_seen_set_enrich = exe_seen_set.clone();

    // 8a. Background state task: full AppState update (exe.log, dirty tracking, flush)
    let app_state_state = app_state.clone();
    let seen_set_state = seen_set.clone();
    let exe_seen_set_state = exe_seen_set.clone();
    let _metrics_state = metrics.clone();
    tokio::spawn(async move {
        while let Some(event) = state_event_rx.recv().await {
            let mut guard = app_state_state.lock().await;
            guard.handle_event(&event, &seen_set_state, &exe_seen_set_state);
        }
    });

    // 8b. Filter+Enrich task: SeenSet read check (no AppState lock), then broadcast.
    tokio::spawn(async move {
        let mut rx = hashed_rx_filter;
        loop {
            match rx.recv().await {
                Ok(mut event) => {
                    let pass = {
                        let chain = filter_chain.read().unwrap();
                        filter::apply(&chain, &event)
                    };
                    if pass {
                        // Fast meta flag enrichment via SeenSets (read lock only, no AppState Mutex).
                        // NEW_EXE: exe path never seen before (normal — software install/first run)
                        // NEW_HASH: new sha256 for known exe (suspicious — possible tampering)
                        if !event.exe.is_empty() {
                            let is_new_exe = exe_seen_set_enrich.read()
                                .map(|s| !s.contains(&event.exe))
                                .unwrap_or(false);
                            if is_new_exe {
                                event.meta.set_new_exe();
                            }
                            if !event.sha256.is_empty() && !event.sha256.starts_with("!!!") {
                                let key = (event.exe.clone(), event.sha256.clone());
                                let is_new_hash = seen_set_enrich.read()
                                    .map(|s| !s.contains(&key))
                                    .unwrap_or(false);
                                if is_new_hash {
                                    event.meta.set_new_hash();
                                    metrics_enrich.alerts_fired.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    info!("new hash: {} for {}", event.sha256, event.exe);
                                    let _ = notify_tx.send(types::NotifyMsg::NewHash {
                                        exe: event.exe.clone(),
                                        sha256: event.sha256.clone(),
                                    }).await;
                                }
                            }
                        }
                        let _ = filtered_tx_clone.send(event.clone());
                        // Forward to state task for full AppState update (non-blocking).
                        // try_send drops when channel full (state task lagged); log and count.
                        if state_event_tx.try_send(event).is_err() {
                            metrics_enrich.events_dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            warn!("state channel full, exe tracking dropped for one event");
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("filter lagged, dropping {} events", n);
                    metrics_enrich.events_dropped.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // 9. Storage sink (SQLite)
    let filtered_rx_storage = filtered_tx.subscribe();
    let config_clone = config.clone();
    let metrics_storage = metrics.clone();
    let writer_tx_storage = tokio::spawn(async move {
        match storage::run(filtered_rx_storage, config_clone, metrics_storage).await {
            Ok(tx) => Some(tx),
            Err(e) => {
                error!("storage error: {}", e);
                None
            }
        }
    });
    let writer_tx = writer_tx_storage.await.ok().flatten().unwrap();

    // 10. Alerts task (hot-reloadable via Arc<RwLock<>>)
    let filtered_rx_alerts = filtered_tx.subscribe();
    let config_clone = config.clone();
    let alerts_rules = alerts::load_shared_rules(&config_clone);
    let alerts_rules_reload = alerts_rules.clone();
    let metrics_alerts = metrics.clone();
    let writer_tx_alerts = writer_tx.clone();
    tokio::spawn(async move {
        alerts::run(filtered_rx_alerts, config_clone, alerts_rules, metrics_alerts, writer_tx_alerts).await;
    });

    // 12. State flush task (periodic flush every 30s)
    // shutdown_flush_tx is sent on SIGINT to stop the loop before final flush.
    let (shutdown_flush_tx, shutdown_flush_rx) = tokio::sync::oneshot::channel::<()>();
    let app_state_clone = app_state.clone();
    let config_clone = config.clone();
    tokio::spawn(async move {
        state::flush_loop(app_state_clone, config_clone, shutdown_flush_rx).await;
    });

    // 13. SIGHUP handler (hot reload config, filters, and alert rules)
    let filter_chain_sighup = filter_chain_reload.clone();
    tokio::spawn(async move {
        let mut sighup = match tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::hangup(),
        ) {
            Ok(s) => s,
            Err(e) => { error!("failed to register SIGHUP handler: {}", e); return; }
        };
        loop {
            sighup.recv().await;
            info!("SIGHUP received, reloading config");
            match config::load() {
                Ok(new_config) => {
                    let new_filters = filter::build(&new_config);
                    *filter_chain_sighup.write().unwrap() = new_filters;
                    info!("config reloaded, {} filters active",
                        filter_chain_sighup.read().unwrap().len());
                }
                Err(e) => error!("config reload failed: {}", e),
            }
            // Also reload alert rules (G-4 fix)
            alerts::reload_shared_rules(&alerts_rules_reload).await;
        }
    });

    // 14. Signal handling (SIGTERM/SIGINT for graceful shutdown)
    let shutdown_clone = shutdown.clone();
    let app_state_clone = app_state.clone();
    let config_clone = config.clone();
    tokio::spawn(async move {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                info!("SIGTERM/SIGINT received, initiating graceful shutdown");
                shutdown_clone.store(true, std::sync::atomic::Ordering::SeqCst);
                // Stop flush_loop first (G-3: prevent concurrent flush race)
                let _ = shutdown_flush_tx.send(());
                let mut state = app_state_clone.lock().await;
                if let Err(e) = state.flush(&config_clone) {
                    error!("error flushing state: {}", e);
                }
            }
            Err(e) => error!("signal error: {}", e),
        }
    });

    // Wait indefinitely — daemon runs until signal
    loop {
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            info!("shutdown flag set, exiting");
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    Ok(())
}
