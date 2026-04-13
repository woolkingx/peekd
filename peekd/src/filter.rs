#![allow(dead_code, unused_imports)]
#![cfg_attr(not(feature = "lua-filters"), allow(unused))]

//! filter.rs: Event filtering logic.
//!
//! Implements EventFilter trait. v1 uses config-based filtering
//! (ignore lists for ports, domains, IPs, SHA256s).
//! Future versions: Lua, WASM, SQL filters.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use crate::types::{BpfEvent, EventFilter};
use crate::config::Config;

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
        !self.ignore_prefixes.iter().any(|p| event.domain.starts_with(p))
    }
}

struct IpFilter {
    ignore_networks: Vec<ipnet::IpNet>,
}

impl EventFilter for IpFilter {
    fn matches(&self, event: &BpfEvent) -> bool {
        !self.ignore_networks.iter().any(|net| net.contains(&event.raddr) || net.contains(&event.laddr))
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
        let script = std::fs::read_to_string(path)
            .map_err(|e| mlua::Error::ExternalError(Arc::new(e)))?;
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
                let name = path.file_stem().unwrap_or_default().to_string_lossy().to_string();
                match LuaFilter::from_file(
                    &path.to_string_lossy(),
                    "should_log",
                    &name,
                ) {
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
