#![allow(dead_code, unused_imports)]
#![cfg_attr(not(feature = "lua-filters"), allow(unused))]

//! filter.rs: Event filtering logic.
//!
//! Implements EventFilter trait. v1 uses config-based filtering
//! (ignore lists for ports, domains, IPs, SHA256s).
//! Future versions: Lua, WASM, SQL filters.

use crate::config::Config;
use crate::types::{BpfEvent, EventFilter};
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

pub type FilterChain = Arc<RwLock<Vec<Box<dyn EventFilter>>>>;

struct PortFilter {
    ignore_ports: HashSet<u16>,
}

impl EventFilter for PortFilter {
    fn matches(&self, event: &BpfEvent) -> bool {
        !self.ignore_ports.contains(&event.rport)
    }
}

struct DomainFilter {
    ignore_prefixes: Vec<String>,
}

impl EventFilter for DomainFilter {
    fn matches(&self, event: &BpfEvent) -> bool {
        !self
            .ignore_prefixes
            .iter()
            .any(|p| event.domain.starts_with(p))
    }
}

struct IpFilter {
    ignore_networks: Vec<ipnet::IpNet>,
}

impl EventFilter for IpFilter {
    fn matches(&self, event: &BpfEvent) -> bool {
        !self
            .ignore_networks
            .iter()
            .any(|net| net.contains(&event.raddr) || net.contains(&event.laddr))
    }
}

struct Sha256Filter {
    ignore_hashes: HashSet<String>,
}

impl EventFilter for Sha256Filter {
    fn matches(&self, event: &BpfEvent) -> bool {
        !self.ignore_hashes.contains(&event.sha256)
    }
}

struct ExeFilter {
    every_exe: bool,
}

impl EventFilter for ExeFilter {
    fn matches(&self, event: &BpfEvent) -> bool {
        if self.every_exe {
            true
        } else {
            event.send > 0 || event.recv > 0
        }
    }
}

struct ExtraIgnoreFilter {
    exe: HashSet<String>,
    domain: Vec<String>,
    raddr: HashSet<String>,
}

impl EventFilter for ExtraIgnoreFilter {
    fn matches(&self, event: &BpfEvent) -> bool {
        !self.exe.contains(&event.exe)
            && !self.domain.iter().any(|p| event.domain.starts_with(p))
            && !self.raddr.contains(&event.raddr.to_string())
    }
}

/// Build filter chain from config.
///
/// Returns filters in order: Port → Domain → IP → SHA256 → Exe.
/// First false short-circuits (AND logic).
pub fn build(config: &Config) -> Vec<Box<dyn EventFilter>> {
    vec![
        Box::new(PortFilter {
            ignore_ports: config.log.ignore_ports.iter().copied().collect(),
        }),
        Box::new(DomainFilter {
            ignore_prefixes: config.log.ignore_domains.clone(),
        }),
        Box::new(IpFilter {
            ignore_networks: config.log.ignore_networks.clone(),
        }),
        Box::new(Sha256Filter {
            ignore_hashes: config.log.ignore_sha256.iter().cloned().collect(),
        }),
        Box::new(ExeFilter {
            every_exe: config.monitoring.every_exe,
        }),
    ]
}

pub fn build_with_extra(config: &Config, config_dir: &Path) -> Vec<Box<dyn EventFilter>> {
    let mut chain = build(config);
    let extra = load_extra_ignores(config_dir);
    if !extra.exe.is_empty() || !extra.domain.is_empty() || !extra.raddr.is_empty() {
        chain.push(Box::new(ExtraIgnoreFilter {
            exe: extra.exe.into_iter().collect(),
            domain: extra.domain,
            raddr: extra.raddr.into_iter().collect(),
        }));
    }
    chain
}

/// Apply all filters to event. Returns true if event should be processed.
///
/// AND logic: all filters must match. First false short-circuits.
pub fn apply(filters: &[Box<dyn EventFilter>], event: &BpfEvent) -> bool {
    filters.iter().all(|f| f.matches(event))
}

/// Create hot-reloadable filter chain.
pub fn new_chain(config: &Config) -> FilterChain {
    Arc::new(RwLock::new(build(config)))
}

pub fn new_chain_with_extra(config: &Config, config_dir: &Path) -> FilterChain {
    Arc::new(RwLock::new(build_with_extra(config, config_dir)))
}

// --- v2: Lua pluggable filters ---

/// Lua script filter (feature-gated: `lua-filters`).
///
/// Loads a Lua script and calls a named function with event data.
/// Function must return bool: true = pass, false = drop.
#[cfg(feature = "lua-filters")]
pub struct LuaFilter {
    lua: mlua::Lua,
    fn_name: String,
    name: String,
}

#[cfg(feature = "lua-filters")]
impl LuaFilter {
    /// Create a new Lua filter from a script file.
    pub fn from_file(path: &str, fn_name: &str, name: &str) -> Result<Self, mlua::Error> {
        let lua = mlua::Lua::new();
        let script =
            std::fs::read_to_string(path).map_err(|e| mlua::Error::ExternalError(Arc::new(e)))?;
        lua.load(&script).exec()?;
        Ok(Self {
            lua,
            fn_name: fn_name.to_string(),
            name: name.to_string(),
        })
    }

    fn _event_to_table(&self, event: &BpfEvent) -> Result<mlua::Table, mlua::Error> {
        let tbl = self.lua.create_table()?;
        tbl.set("pid", event.pid)?;
        tbl.set("uid", event.uid)?;
        tbl.set("exe", event.exe.as_str())?;
        tbl.set("name", event.name.as_str())?;
        tbl.set("domain", event.domain.as_str())?;
        tbl.set("raddr", event.raddr.to_string())?;
        tbl.set("rport", event.rport)?;
        tbl.set("lport", event.lport)?;
        tbl.set("sha256", event.sha256.as_str())?;
        tbl.set("send", event.send)?;
        tbl.set("recv", event.recv)?;
        Ok(tbl)
    }
}

#[cfg(feature = "lua-filters")]
impl EventFilter for LuaFilter {
    fn matches(&self, event: &BpfEvent) -> bool {
        let result: Result<bool, _> = (|| {
            let func: mlua::Function = self.lua.globals().get(self.fn_name.as_str())?;
            let tbl = self._event_to_table(event)?;
            func.call::<bool>(tbl)
        })();
        result.unwrap_or(true) // on error, pass through
    }
}

/// Load Lua filters from config directory.
///
/// Scans /etc/peekd/filters/*.lua, loads each with its declared function name.
#[cfg(feature = "lua-filters")]
pub fn load_lua_filters(config_dir: &std::path::Path) -> Vec<Box<dyn EventFilter>> {
    let filter_dir = config_dir.join("filters");
    let mut filters: Vec<Box<dyn EventFilter>> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&filter_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "lua") {
                let name = path
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                match LuaFilter::from_file(&path.to_string_lossy(), "should_log", &name) {
                    Ok(f) => {
                        tracing::info!("loaded Lua filter: {}", name);
                        filters.push(Box::new(f));
                    }
                    Err(e) => tracing::error!("failed to load Lua filter {}: {}", name, e),
                }
            }
        }
    }
    filters
}

/// Extended build that includes Lua filters (v2).
#[cfg(feature = "lua-filters")]
pub fn build_with_lua(config: &Config) -> Vec<Box<dyn EventFilter>> {
    let mut chain = build(config);
    chain.extend(load_lua_filters(&crate::config::config_dir()));
    chain
}

// ============================================================================
// Extra ignores: runtime-managed ignore lists loaded from ignore_extra.toml
// ============================================================================

use std::path::Path;

#[derive(Default, Clone)]
pub struct ExtraIgnores {
    pub exe: Vec<String>,
    pub domain: Vec<String>,
    pub raddr: Vec<String>,
}

pub fn load_extra_ignores(config_dir: &Path) -> ExtraIgnores {
    let path = config_dir.join("ignore_extra.toml");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return ExtraIgnores::default();
    };
    let Ok(val) = toml::from_str::<toml::Value>(&text) else {
        return ExtraIgnores::default();
    };
    fn get_list(val: &toml::Value, key: &str) -> Vec<String> {
        val.get(key)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default()
    }
    ExtraIgnores {
        exe: get_list(&val, "exe"),
        domain: get_list(&val, "domain"),
        raddr: get_list(&val, "raddr"),
    }
}

pub fn save_extra_ignore(config_dir: &Path, kind: &str, value: &str) -> anyhow::Result<()> {
    std::fs::create_dir_all(config_dir)?;
    let path = config_dir.join("ignore_extra.toml");
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let mut val: toml::Value = if text.is_empty() {
        toml::Value::Table(toml::map::Map::new())
    } else {
        toml::from_str(&text)?
    };
    let table = val
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("invalid toml"))?;
    let arr = table
        .entry(kind)
        .or_insert_with(|| toml::Value::Array(vec![]));
    if let Some(list) = arr.as_array_mut() {
        let v = toml::Value::String(value.to_string());
        if !list.contains(&v) {
            list.push(v);
        }
    }
    std::fs::write(&path, toml::to_string_pretty(&val)?)?;
    Ok(())
}

#[cfg(test)]
mod tests_filter {
    use super::*;
    use crate::types::EventMeta;
    use std::net::{IpAddr, Ipv4Addr};

    fn event_with_fields(exe: &str, domain: &str, raddr: IpAddr) -> BpfEvent {
        BpfEvent {
            pid: 1,
            ppid: 0,
            uid: 1000,
            name: "curl".to_string(),
            pname: String::new(),
            exe: exe.to_string(),
            pexe: String::new(),
            cmdline: String::new(),
            pcmdline: String::new(),
            fd_path: String::new(),
            pfd_path: String::new(),
            dev: 1,
            ino: 1,
            pdev: 0,
            pino: 0,
            send: 1,
            recv: 0,
            lport: 40000,
            rport: 443,
            laddr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            raddr,
            domain: domain.to_string(),
            domain_source: "unknown".to_string(),
            domain_confidence: "none".to_string(),
            domain_status: "unknown".to_string(),
            sha256: String::new(),
            psha256: String::new(),
            meta: EventMeta::default(),
        }
    }

    #[test]
    fn domain_filter_matches_canonical_tld_first_prefix() {
        let mut config = Config::default();
        config.log.ignore_domains = vec!["com.example".to_string()];
        let filters = build(&config);

        assert!(!apply(
            &filters,
            &event_with_fields(
                "/usr/bin/curl",
                "com.example.www",
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
            )
        ));
        assert!(apply(
            &filters,
            &event_with_fields(
                "/usr/bin/curl",
                "org.example.www",
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
            )
        ));
    }

    #[test]
    fn build_with_extra_applies_runtime_ignores() {
        let dir = std::env::temp_dir().join(format!("peekd-filter-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        save_extra_ignore(&dir, "exe", "/usr/bin/curl").unwrap();
        save_extra_ignore(&dir, "domain", "com.example").unwrap();
        save_extra_ignore(&dir, "raddr", "93.184.216.34").unwrap();

        let filters = build_with_extra(&Config::default(), &dir);
        assert!(!apply(
            &filters,
            &event_with_fields(
                "/usr/bin/curl",
                "org.example.www",
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))
            )
        ));
        assert!(!apply(
            &filters,
            &event_with_fields(
                "/usr/bin/wget",
                "com.example.www",
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))
            )
        ));
        assert!(!apply(
            &filters,
            &event_with_fields(
                "/usr/bin/wget",
                "org.example.www",
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
            )
        ));
        assert!(apply(
            &filters,
            &event_with_fields(
                "/usr/bin/wget",
                "org.example.www",
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))
            )
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
