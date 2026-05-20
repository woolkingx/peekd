#![allow(dead_code, unused_imports)]

//! config.rs: Configuration loading and validation.
//!
//! Loads config.toml and provides typed Config struct to all modules.
//! Handles directory paths, serde deserialization, and defaults.
//!
//! File paths:
//! - /etc/peekd/config.toml or $XDG_CONFIG_HOME/peekd/config.toml
//! - /var/lib/peekd/ (SQLite database, state.json)
//! - /var/log/peekd/ (peekd.log, exe.log, error.log)
//! - /run/peekd/ (Unix sockets, metrics.json)

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Top-level config struct with all subsystem configs.
#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct Config {
    pub database: DatabaseConfig,
    pub log: LogConfig,
    pub desktop: DesktopConfig,
    pub monitoring: MonitoringConfig,
    pub broadcast: BroadcastConfig,
    pub metrics: MetricsConfig,
    pub web: WebConfig,
}

/// WebConfig: embedded web dashboard settings.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default)]
pub struct WebConfig {
    pub enabled: bool,
    pub port: u16,
    /// Bind address. Default 127.0.0.1. Set "0.0.0.0" to expose on LAN (no auth).
    pub bind: String,
    /// "" = serve embedded HTML (production). Path = serve from disk (dev/custom).
    pub static_dir: String,
    /// Auto-refresh interval seconds. 0 = disabled.
    pub refresh_seconds: u64,
    /// Default time window shown on load: 1h / 6h / 24h / 7d / 30d.
    pub default_since: String,
    /// Maximum rows returned by /api/top.
    pub top_limit: u32,
}

/// DatabaseConfig: SQLite storage settings.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default)]
pub struct DatabaseConfig {
    pub enabled: bool,
    pub retention_days: u32,
    pub write_limit_seconds: u64,
    pub text_log: bool,
}

/// LogConfig: Filtering and ignore lists.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default)]
pub struct LogConfig {
    pub addresses: bool,
    pub commands: bool,
    pub ports: bool,
    pub ignore_ports: Vec<u16>,
    pub ignore_domains: Vec<String>,
    #[serde(default)]
    pub ignore_ips: Vec<String>,
    #[serde(skip)]
    pub ignore_networks: Vec<ipnet::IpNet>,
    pub ignore_sha256: Vec<String>,
}

/// DesktopConfig: User-facing features (notifications, fuse worker user).
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default)]
pub struct DesktopConfig {
    pub user: String,
    pub notifications: bool,
}

/// MonitoringConfig: BPF and perf buffer tuning.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default)]
pub struct MonitoringConfig {
    pub every_exe: bool,
    pub perf_ring_buffer_pages: u32,
    pub st_dev_mask: Option<u64>,
    pub fd_cache_size: usize,
}

/// BroadcastConfig: Channel capacity and timing.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default)]
pub struct BroadcastConfig {
    pub channel_capacity: usize,
}

/// MetricsConfig: Metrics export settings.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default)]
pub struct MetricsConfig {
    pub interval_seconds: u64,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: 30,
            write_limit_seconds: 10,
            text_log: false,
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            addresses: true,
            commands: true,
            ports: true,
            ignore_ports: Vec::new(),
            ignore_domains: Vec::new(),
            ignore_ips: Vec::new(),
            ignore_networks: Vec::new(),
            ignore_sha256: Vec::new(),
        }
    }
}

impl Default for DesktopConfig {
    fn default() -> Self {
        Self {
            user: String::from("root"),
            notifications: true,
        }
    }
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            every_exe: false,
            perf_ring_buffer_pages: 256,
            st_dev_mask: Some(0xfffff),
            fd_cache_size: 10_000,
        }
    }
}

impl Default for BroadcastConfig {
    fn default() -> Self {
        Self {
            channel_capacity: 10_000,
        }
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            interval_seconds: 30,
        }
    }
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 5100,
            bind: "127.0.0.1".into(),
            static_dir: String::new(),
            refresh_seconds: 30,
            default_since: "24h".into(),
            top_limit: 200,
        }
    }
}

/// Load config from disk or return defaults.
pub fn load() -> Result<Config, Box<dyn std::error::Error>> {
    let path = config_dir().join("config.toml");
    if !path.exists() {
        return Ok(Config::default());
    }
    let text = std::fs::read_to_string(&path)?;
    let mut config: Config = toml::from_str(&text)?;
    _parse_ignore_networks(&mut config.log)?;
    _validate(&config)?;
    Ok(config)
}

fn _validate(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    if config.database.retention_days == 0 {
        return Err("database.retention_days must be >= 1 (0 would delete all data)".into());
    }
    if config.database.write_limit_seconds == 0 {
        return Err("database.write_limit_seconds must be >= 1 (0 causes CPU spin)".into());
    }
    if config.monitoring.perf_ring_buffer_pages == 0
        || !config.monitoring.perf_ring_buffer_pages.is_power_of_two()
    {
        return Err("monitoring.perf_ring_buffer_pages must be a power of two >= 1".into());
    }
    Ok(())
}

/// Write default config to path.
pub fn write_default(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::default();
    let toml_str = toml::to_string_pretty(&config)?;
    std::fs::write(path, toml_str)?;
    Ok(())
}

/// Parse ignore_ips strings into IpNet objects. Logs warnings on parse errors.
fn _parse_ignore_networks(log_config: &mut LogConfig) -> Result<(), Box<dyn std::error::Error>> {
    log_config.ignore_networks.clear();
    for ip_str in &log_config.ignore_ips {
        match ipnet::IpNet::from_str(ip_str) {
            Ok(net) => log_config.ignore_networks.push(net),
            Err(e) => tracing::warn!("failed to parse ignore_ips '{}': {}", ip_str, e),
        }
    }
    Ok(())
}

/// Get config directory: /etc/peekd or $XDG_CONFIG_HOME/peekd
pub fn config_dir() -> PathBuf {
    if let Ok(xdg_home) = std::env::var("XDG_CONFIG_HOME") {
        PathBuf::from(xdg_home).join("peekd")
    } else {
        PathBuf::from("/etc/peekd")
    }
}

/// Get data directory: /var/lib/peekd
pub fn data_dir() -> PathBuf {
    PathBuf::from("/var/lib/peekd")
}

/// Get log directory: /var/log/peekd
pub fn log_dir() -> PathBuf {
    PathBuf::from("/var/log/peekd")
}

/// Get runtime directory: /run/peekd
pub fn run_dir() -> PathBuf {
    PathBuf::from("/run/peekd")
}

/// Get database path: data_dir/peekd.db
pub fn db_path() -> PathBuf {
    data_dir().join("peekd.db")
}

#[cfg(test)]
mod tests_config {
    use super::*;

    #[test]
    fn validate_rejects_invalid_perf_ring_pages() {
        let mut config = Config::default();
        config.monitoring.perf_ring_buffer_pages = 3;

        let err = _validate(&config).unwrap_err();
        assert!(err.to_string().contains("perf_ring_buffer_pages"));
    }
}
