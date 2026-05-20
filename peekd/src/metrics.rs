#![allow(dead_code, unused_imports)]

//! metrics.rs: Runtime counters and periodic JSON export.
//!
//! Collects event counters across all pipeline stages.
//! Periodically writes metrics.json to /run/peekd/metrics.json.

use crate::config::Config;
use anyhow::{anyhow, Result};
use chrono::Utc;
use peekd_common::{
    BPF_STAT_DNS_ARGS_INSERT_FAILED, BPF_STAT_DNS_ARGS_REMOVE_FAILED, BPF_STAT_DNS_ENTRY_SEEN,
    BPF_STAT_DNS_RETURN_SEEN, BPF_STAT_LIFECYCLE_IPV6_SKIPPED,
};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

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
    pub events_connect: AtomicU64,
    pub perf_buffer_loss: AtomicU64,
    pub perf_loss_sendv4: AtomicU64,
    pub perf_loss_recvv4: AtomicU64,
    pub perf_loss_sendv6: AtomicU64,
    pub perf_loss_recvv6: AtomicU64,
    pub perf_loss_exec: AtomicU64,
    pub perf_loss_dns: AtomicU64,
    pub perf_loss_dns6: AtomicU64,
    pub perf_loss_connect: AtomicU64,
    pub decoder_failures: AtomicU64,
    pub dns_args_insert_failures: AtomicU64,
    pub dns_args_remove_failures: AtomicU64,
    pub dns_entry_seen: AtomicU64,
    pub dns_return_seen: AtomicU64,
    pub lifecycle_ipv6_skips: AtomicU64,

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
    pub new_hash_detected: AtomicU64,
    pub alerts_fired: AtomicU64,

    // Pipeline pressure
    pub events_dropped: AtomicU64,
    pub broadcast_lag_dns: AtomicU64,
    pub broadcast_lag_resolver: AtomicU64,
    pub broadcast_lag_hasher: AtomicU64,
    pub broadcast_lag_filter: AtomicU64,
    pub broadcast_lag_storage: AtomicU64,
    pub broadcast_lag_alerts: AtomicU64,
    pub broadcast_lag_lifecycle: AtomicU64,
    pub state_queue_drops: AtomicU64,
    pub lifecycle_queue_drops: AtomicU64,
}

impl Metrics {
    pub fn record_perf_loss(&self, source: &str, n: u64) {
        self.perf_buffer_loss.fetch_add(n, Ordering::Relaxed);
        match source {
            "SENDMSG_EVENTS" => &self.perf_loss_sendv4,
            "RECVMSG_EVENTS" => &self.perf_loss_recvv4,
            "SENDMSG6_EVENTS" => &self.perf_loss_sendv6,
            "RECVMSG6_EVENTS" => &self.perf_loss_recvv6,
            "EXEC_EVENTS" => &self.perf_loss_exec,
            "DNS_EVENTS" => &self.perf_loss_dns,
            "DNS6_EVENTS" => &self.perf_loss_dns6,
            "CONNECT_EVENTS" => &self.perf_loss_connect,
            _ => return,
        }
        .fetch_add(n, Ordering::Relaxed);
    }

    pub fn record_broadcast_lag(&self, consumer: &str, n: u64) {
        self.events_dropped.fetch_add(n, Ordering::Relaxed);
        match consumer {
            "dns" => &self.broadcast_lag_dns,
            "resolver" => &self.broadcast_lag_resolver,
            "hasher" => &self.broadcast_lag_hasher,
            "filter" => &self.broadcast_lag_filter,
            "storage" => &self.broadcast_lag_storage,
            "alerts" => &self.broadcast_lag_alerts,
            "lifecycle" => &self.broadcast_lag_lifecycle,
            _ => return,
        }
        .fetch_add(n, Ordering::Relaxed);
    }

    pub fn record_bpf_stat(&self, kind: u32) {
        match kind {
            BPF_STAT_DNS_ARGS_INSERT_FAILED => &self.dns_args_insert_failures,
            BPF_STAT_DNS_ARGS_REMOVE_FAILED => &self.dns_args_remove_failures,
            BPF_STAT_DNS_ENTRY_SEEN => &self.dns_entry_seen,
            BPF_STAT_DNS_RETURN_SEEN => &self.dns_return_seen,
            BPF_STAT_LIFECYCLE_IPV6_SKIPPED => &self.lifecycle_ipv6_skips,
            _ => return,
        }
        .fetch_add(1, Ordering::Relaxed);
    }
}

/// Run metrics writer task.
///
/// Periodically exports metrics.json containing current counter values
/// and computed statistics (cache hit rates, uptime, etc).
/// Writes atomically via temp file + rename to /run/peekd/metrics.json.
pub async fn writer(metrics: Arc<Metrics>, config: Arc<Config>, start_time: std::time::Instant) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(
        config.metrics.interval_seconds,
    ));

    loop {
        interval.tick().await;
        if let Err(e) = _write_metrics(&metrics, &start_time) {
            tracing::warn!("failed to write metrics: {}", e);
        }
    }
}

pub fn status_cli() -> Result<()> {
    let path = crate::config::run_dir().join("metrics.json");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| anyhow!("failed to read {}: {}", path.display(), e))?;
    let json: Value = serde_json::from_str(&text)
        .map_err(|e| anyhow!("failed to parse {}: {}", path.display(), e))?;
    println!("{}", status_text(&json)?);
    Ok(())
}

fn status_text(json: &Value) -> Result<String> {
    let uptime = json
        .get("uptime_seconds")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing uptime_seconds"))?;
    let events_total = json
        .pointer("/events/total")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let buffer_loss = json
        .pointer("/events/perf_buffer_loss")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let hash_hit_rate = json
        .pointer("/hasher/cache_hit_rate")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let sqlite_writes = json
        .pointer("/storage/writes")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let sqlite_rows = json
        .pointer("/storage/rows_written")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let alerts = json
        .pointer("/alerts/fired")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    Ok(format!(
        "peekd status\n  uptime:        {}\n  events total:  {}\n  buffer loss:   {}\n  hash hit rate: {:.0}%\n  sqlite writes: {} ({} rows)\n  alerts fired:  {}",
        format_duration(uptime),
        events_total,
        buffer_loss,
        hash_hit_rate * 100.0,
        sqlite_writes,
        sqlite_rows,
        alerts,
    ))
}

fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;
    if hours > 0 {
        format!("{}h {}m", hours, minutes)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, secs)
    } else {
        format!("{}s", secs)
    }
}

/// Write metrics snapshot to /run/peekd/metrics.json (atomically).
fn _write_metrics(metrics: &Metrics, start_time: &std::time::Instant) -> std::io::Result<()> {
    let uptime_secs = start_time.elapsed().as_secs();

    let output = _snapshot(metrics, uptime_secs, Utc::now().to_rfc3339());
    let run_dir = crate::config::run_dir();
    let metrics_path = run_dir.join("metrics.json");
    let temp_path = run_dir.join("metrics.json.tmp");
    let json_str = serde_json::to_string_pretty(&output).map_err(std::io::Error::other)?;

    std::fs::write(&temp_path, json_str)?;
    std::fs::rename(&temp_path, &metrics_path)?;

    Ok(())
}

fn _snapshot(metrics: &Metrics, uptime_secs: u64, timestamp: String) -> Value {
    let events_total = metrics.events_total.load(Ordering::Relaxed);
    let events_sendv4 = metrics.events_sendv4.load(Ordering::Relaxed);
    let events_recvv4 = metrics.events_recvv4.load(Ordering::Relaxed);
    let events_sendv6 = metrics.events_sendv6.load(Ordering::Relaxed);
    let events_recvv6 = metrics.events_recvv6.load(Ordering::Relaxed);
    let events_exec = metrics.events_exec.load(Ordering::Relaxed);
    let events_dns = metrics.events_dns.load(Ordering::Relaxed);
    let events_connect = metrics.events_connect.load(Ordering::Relaxed);
    let perf_buffer_loss = metrics.perf_buffer_loss.load(Ordering::Relaxed);
    let decoder_failures = metrics.decoder_failures.load(Ordering::Relaxed);

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

    let new_hash_detected = metrics.new_hash_detected.load(Ordering::Relaxed);

    // Compute hit rates
    let fd_cache_total = fd_cache_hits.saturating_add(fd_cache_misses);
    let fd_hit_rate = if fd_cache_total > 0 {
        (fd_cache_hits as f64) / (fd_cache_total as f64)
    } else {
        0.0
    };

    let hash_cache_total = hash_cache_hits.saturating_add(
        hash_fd_success.saturating_add(hash_pid_fallback.saturating_add(hash_fuse_fallback)),
    );
    let hash_hit_rate = if hash_cache_total > 0 {
        (hash_cache_hits as f64) / (hash_cache_total as f64)
    } else {
        0.0
    };

    json!({
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
            "connect": events_connect,
            "perf_buffer_loss": perf_buffer_loss,
            "perf_loss": {
                "sendv4": metrics.perf_loss_sendv4.load(Ordering::Relaxed),
                "recvv4": metrics.perf_loss_recvv4.load(Ordering::Relaxed),
                "sendv6": metrics.perf_loss_sendv6.load(Ordering::Relaxed),
                "recvv6": metrics.perf_loss_recvv6.load(Ordering::Relaxed),
                "exec": metrics.perf_loss_exec.load(Ordering::Relaxed),
                "dns": metrics.perf_loss_dns.load(Ordering::Relaxed),
                "dns6": metrics.perf_loss_dns6.load(Ordering::Relaxed),
                "connect": metrics.perf_loss_connect.load(Ordering::Relaxed),
            },
            "decoder_failures": decoder_failures,
            "bpf_stats": {
                "dns_args_insert_failures": metrics.dns_args_insert_failures.load(Ordering::Relaxed),
                "dns_args_remove_failures": metrics.dns_args_remove_failures.load(Ordering::Relaxed),
                "dns_entry_seen": metrics.dns_entry_seen.load(Ordering::Relaxed),
                "dns_return_seen": metrics.dns_return_seen.load(Ordering::Relaxed),
                "lifecycle_ipv6_skips": metrics.lifecycle_ipv6_skips.load(Ordering::Relaxed),
            },
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
            "new_hash_detected": new_hash_detected,
            "fired": metrics.alerts_fired.load(Ordering::Relaxed),
        },
        "pipeline": {
            "events_dropped": metrics.events_dropped.load(Ordering::Relaxed),
            "broadcast_lag": {
                "dns": metrics.broadcast_lag_dns.load(Ordering::Relaxed),
                "resolver": metrics.broadcast_lag_resolver.load(Ordering::Relaxed),
                "hasher": metrics.broadcast_lag_hasher.load(Ordering::Relaxed),
                "filter": metrics.broadcast_lag_filter.load(Ordering::Relaxed),
                "storage": metrics.broadcast_lag_storage.load(Ordering::Relaxed),
                "alerts": metrics.broadcast_lag_alerts.load(Ordering::Relaxed),
                "lifecycle": metrics.broadcast_lag_lifecycle.load(Ordering::Relaxed),
            },
            "state_queue_drops": metrics.state_queue_drops.load(Ordering::Relaxed),
            "lifecycle_queue_drops": metrics.lifecycle_queue_drops.load(Ordering::Relaxed),
        },
    })
}

#[cfg(test)]
mod tests_metrics {
    use super::*;

    #[test]
    fn snapshot_separates_alerts_from_new_hash_detection() {
        let metrics = Metrics::default();
        metrics.new_hash_detected.fetch_add(2, Ordering::Relaxed);
        metrics.alerts_fired.fetch_add(1, Ordering::Relaxed);

        let json = _snapshot(&metrics, 7, "ts".to_string());
        assert_eq!(json["alerts"]["new_hash_detected"], 2);
        assert_eq!(json["alerts"]["fired"], 1);
    }

    #[test]
    fn records_source_specific_pressure() {
        let metrics = Metrics::default();
        metrics.record_perf_loss("SENDMSG6_EVENTS", 3);
        metrics.record_broadcast_lag("storage", 5);
        metrics.state_queue_drops.fetch_add(4, Ordering::Relaxed);
        metrics
            .lifecycle_queue_drops
            .fetch_add(2, Ordering::Relaxed);
        metrics.record_bpf_stat(BPF_STAT_DNS_ARGS_INSERT_FAILED);
        metrics.record_bpf_stat(BPF_STAT_DNS_ARGS_REMOVE_FAILED);
        metrics.record_bpf_stat(BPF_STAT_DNS_ENTRY_SEEN);
        metrics.record_bpf_stat(BPF_STAT_DNS_RETURN_SEEN);
        metrics.record_bpf_stat(BPF_STAT_LIFECYCLE_IPV6_SKIPPED);
        metrics.decoder_failures.fetch_add(2, Ordering::Relaxed);

        let json = _snapshot(&metrics, 1, "ts".to_string());
        assert_eq!(json["events"]["perf_buffer_loss"], 3);
        assert_eq!(json["events"]["perf_loss"]["sendv6"], 3);
        assert_eq!(json["events"]["decoder_failures"], 2);
        assert_eq!(json["events"]["bpf_stats"]["dns_args_insert_failures"], 1);
        assert_eq!(json["events"]["bpf_stats"]["dns_args_remove_failures"], 1);
        assert_eq!(json["events"]["bpf_stats"]["dns_entry_seen"], 1);
        assert_eq!(json["events"]["bpf_stats"]["dns_return_seen"], 1);
        assert_eq!(json["events"]["bpf_stats"]["lifecycle_ipv6_skips"], 1);
        assert_eq!(json["pipeline"]["broadcast_lag"]["storage"], 5);
        assert_eq!(json["pipeline"]["events_dropped"], 5);
        assert_eq!(json["pipeline"]["state_queue_drops"], 4);
        assert_eq!(json["pipeline"]["lifecycle_queue_drops"], 2);
    }

    #[test]
    fn status_text_requires_metrics_snapshot_and_formats_summary() {
        let json = json!({
            "uptime_seconds": 3661,
            "events": {"total": 450000, "perf_buffer_loss": 2},
            "hasher": {"cache_hit_rate": 0.97},
            "storage": {"writes": 360, "rows_written": 44800},
            "alerts": {"fired": 2}
        });

        let text = status_text(&json).unwrap();
        assert!(text.contains("uptime:        1h 1m"));
        assert!(text.contains("events total:  450000"));
        assert!(text.contains("hash hit rate: 97%"));
        assert!(status_text(&json!({})).is_err());
    }
}
