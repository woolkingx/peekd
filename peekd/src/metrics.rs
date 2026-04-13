#![allow(dead_code, unused_imports)]

//! metrics.rs: Runtime counters and periodic JSON export.
//!
//! Collects event counters across all pipeline stages.
//! Periodically writes metrics.json to /run/peekd/metrics.json.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use serde_json::json;
use chrono::Utc;
use crate::config::Config;

/// Metrics: Event counters with atomic access for low-latency instrumentation.
#[derive(Default, Debug)]
pub struct Metrics {
    // BPF layer: event sources
    pub events_total: AtomicU64,
    pub events_sendv4: AtomicU64,
    pub events_recvv4: AtomicU64,
    pub events_sendv6: AtomicU64,
    pub events_recvv6: AtomicU64,
    pub events_exec: AtomicU64,
    pub events_dns: AtomicU64,
    pub perf_buffer_loss: AtomicU64,

    // Resolver layer: fd and cmdline caching
    pub fd_cache_hits: AtomicU64,
    pub fd_cache_misses: AtomicU64,
    pub fd_open_failures: AtomicU64,
    pub cmdline_cache_hits: AtomicU64,

    // Hasher layer: hash computation paths
    pub hash_cache_hits: AtomicU64,
    pub hash_fd_success: AtomicU64,
    pub hash_pid_fallback: AtomicU64,
    pub hash_fuse_fallback: AtomicU64,
    pub hash_failures: AtomicU64,

    // Storage layer: SQLite writes
    pub sqlite_writes: AtomicU64,
    pub sqlite_rows_written: AtomicU64,
    pub sqlite_write_errors: AtomicU64,
    pub events_filtered: AtomicU64,

    // Alerts
    pub alerts_fired: AtomicU64,

    // Pipeline: dropped events due to broadcast lag
    pub events_dropped: AtomicU64,
}

/// Run metrics writer task.
///
/// Periodically exports metrics.json containing current counter values
/// and computed statistics (cache hit rates, uptime, etc).
/// Writes atomically via temp file + rename to /run/peekd/metrics.json.
pub async fn writer(
    metrics: Arc<Metrics>,
    config: Arc<Config>,
    start_time: std::time::Instant,
) {
    let mut interval = tokio::time::interval(
        std::time::Duration::from_secs(config.metrics.interval_seconds)
    );

    loop {
        interval.tick().await;
        if let Err(e) = _write_metrics(&metrics, &start_time) {
            tracing::warn!("failed to write metrics: {}", e);
        }
    }
}

/// Write metrics snapshot to /run/peekd/metrics.json (atomically).
fn _write_metrics(metrics: &Metrics, start_time: &std::time::Instant) -> std::io::Result<()> {
    let uptime_secs = start_time.elapsed().as_secs();

    // ISO8601 timestamp
    let timestamp = Utc::now().to_rfc3339();

    // Read all counters with Relaxed ordering (approximate values OK)
    let events_total = metrics.events_total.load(Ordering::Relaxed);
    let events_sendv4 = metrics.events_sendv4.load(Ordering::Relaxed);
    let events_recvv4 = metrics.events_recvv4.load(Ordering::Relaxed);
    let events_sendv6 = metrics.events_sendv6.load(Ordering::Relaxed);
    let events_recvv6 = metrics.events_recvv6.load(Ordering::Relaxed);
    let events_exec = metrics.events_exec.load(Ordering::Relaxed);
    let events_dns = metrics.events_dns.load(Ordering::Relaxed);
    let perf_buffer_loss = metrics.perf_buffer_loss.load(Ordering::Relaxed);

    let fd_cache_hits = metrics.fd_cache_hits.load(Ordering::Relaxed);
    let fd_cache_misses = metrics.fd_cache_misses.load(Ordering::Relaxed);
    let fd_open_failures = metrics.fd_open_failures.load(Ordering::Relaxed);
    let cmdline_cache_hits = metrics.cmdline_cache_hits.load(Ordering::Relaxed);

    let hash_cache_hits = metrics.hash_cache_hits.load(Ordering::Relaxed);
    let hash_fd_success = metrics.hash_fd_success.load(Ordering::Relaxed);
    let hash_pid_fallback = metrics.hash_pid_fallback.load(Ordering::Relaxed);
    let hash_fuse_fallback = metrics.hash_fuse_fallback.load(Ordering::Relaxed);
    let hash_failures = metrics.hash_failures.load(Ordering::Relaxed);

    let sqlite_writes = metrics.sqlite_writes.load(Ordering::Relaxed);
    let sqlite_rows_written = metrics.sqlite_rows_written.load(Ordering::Relaxed);
    let sqlite_write_errors = metrics.sqlite_write_errors.load(Ordering::Relaxed);
    let events_filtered = metrics.events_filtered.load(Ordering::Relaxed);

    let alerts_fired = metrics.alerts_fired.load(Ordering::Relaxed);
    let events_dropped = metrics.events_dropped.load(Ordering::Relaxed);

    // Compute hit rates
    let fd_cache_total = fd_cache_hits.saturating_add(fd_cache_misses);
    let fd_hit_rate = if fd_cache_total > 0 {
        (fd_cache_hits as f64) / (fd_cache_total as f64)
    } else {
        0.0
    };

    let hash_cache_total = hash_cache_hits.saturating_add(
        hash_fd_success.saturating_add(hash_pid_fallback.saturating_add(hash_fuse_fallback))
    );
    let hash_hit_rate = if hash_cache_total > 0 {
        (hash_cache_hits as f64) / (hash_cache_total as f64)
    } else {
        0.0
    };

    // Build JSON output
    let output = json!({
        "timestamp": timestamp,
        "uptime_seconds": uptime_secs,
        "events": {
            "total": events_total,
            "sendv4": events_sendv4,
            "recvv4": events_recvv4,
            "sendv6": events_sendv6,
            "recvv6": events_recvv6,
            "exec": events_exec,
            "dns": events_dns,
            "perf_buffer_loss": perf_buffer_loss,
        },
        "resolver": {
            "fd_cache_hit_rate": (fd_hit_rate * 100.0).round() / 100.0,
            "fd_open_failures": fd_open_failures,
            "cmdline_cache_hits": cmdline_cache_hits,
        },
        "hasher": {
            "cache_hit_rate": (hash_hit_rate * 100.0).round() / 100.0,
            "fd_success": hash_fd_success,
            "pid_fallback": hash_pid_fallback,
            "fuse_fallback": hash_fuse_fallback,
            "failures": hash_failures,
        },
        "storage": {
            "writes": sqlite_writes,
            "rows_written": sqlite_rows_written,
            "write_errors": sqlite_write_errors,
            "events_filtered": events_filtered,
        },
        "alerts": {
            "fired": alerts_fired,
        },
        "pipeline": {
            "events_dropped": events_dropped,
        },
    });

    // Write to temp file then rename (atomic)
    let run_dir = crate::config::run_dir();
    let metrics_path = run_dir.join("metrics.json");
    let temp_path = run_dir.join("metrics.json.tmp");

    let json_str = serde_json::to_string_pretty(&output)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    std::fs::write(&temp_path, json_str)?;
    std::fs::rename(&temp_path, &metrics_path)?;

    Ok(())
}
