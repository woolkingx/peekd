//! state.rs: Application state tracking for known executables, names, and hashes.
//!
//! Implements picosnitch-compatible state.json format with full tracking:
//! - executables: exe → [name, ...]
//! - names: name → [exe, ...]
//! - parent_executables: pexe → [pname, ...]
//! - parent_names: pname → [pexe, ...]
//! - sha256: exe → { hash → vt_result }
//!
//! Writes exe.log and error.log on new discoveries.
//! Flushes state.json every 30s when dirty.

use crate::config::Config;
use crate::types::BpfEvent;
use anyhow::Result;
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};

/// SeenSet: fast read-only check for known (exe, sha256) pairs.
///
/// Used in the filter+enrich hot path to set NEW_HASH without holding
/// the full AppState lock. Writes happen only on first discovery, so it is
/// read-heavy and cheap under std::sync::RwLock.
pub type SeenSet = Arc<RwLock<HashSet<(String, String)>>>;

/// ExeSeenSet: fast read-only check for known exe paths.
///
/// Used in the filter+enrich hot path to set NEW_EXE flag.
/// Distinct from SeenSet: tracks exe paths only, not (exe, sha256) pairs.
pub type ExeSeenSet = Arc<RwLock<HashSet<String>>>;

// ============================================================================
// State JSON (picosnitch-compatible schema)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StateJson {
    #[serde(rename = "Executables")]
    pub executables: HashMap<String, Vec<String>>,

    #[serde(rename = "Names")]
    pub names: HashMap<String, Vec<String>>,

    #[serde(rename = "Parent Executables")]
    pub parent_executables: HashMap<String, Vec<String>>,

    #[serde(rename = "Parent Names")]
    pub parent_names: HashMap<String, Vec<String>>,

    #[serde(rename = "SHA256")]
    pub sha256: HashMap<String, HashMap<String, String>>,
}

// ============================================================================
// AppState
// ============================================================================

pub struct AppState {
    pub executables: HashMap<String, Vec<String>>,
    pub names: HashMap<String, Vec<String>>,
    pub parent_executables: HashMap<String, Vec<String>>,
    pub parent_names: HashMap<String, Vec<String>>,
    pub sha256: HashMap<String, HashMap<String, String>>,
    pub dirty: bool,
}

impl AppState {
    pub fn load(_config: &Config) -> Self {
        let path = _state_path();
        match fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<StateJson>(&content) {
                Ok(s) => Self {
                    executables: s.executables,
                    names: s.names,
                    parent_executables: s.parent_executables,
                    parent_names: s.parent_names,
                    sha256: s.sha256,
                    dirty: false,
                },
                Err(_) => Self::new(),
            },
            Err(_) => Self::new(),
        }
    }

    fn new() -> Self {
        Self {
            executables: HashMap::new(),
            names: HashMap::new(),
            parent_executables: HashMap::new(),
            parent_names: HashMap::new(),
            sha256: HashMap::new(),
            dirty: false,
        }
    }

    /// Build a SeenSet pre-populated from the current sha256 map.
    /// Call once after load() to initialise the hot-path enrichment check.
    pub fn build_seen_set(&self) -> SeenSet {
        let mut set = HashSet::new();
        for (exe, hashes) in &self.sha256 {
            for hash in hashes.keys() {
                set.insert((exe.clone(), hash.clone()));
            }
        }
        Arc::new(RwLock::new(set))
    }

    /// Build an ExeSeenSet pre-populated from the known executables map.
    /// Used in hot-path to detect first-seen exe paths (NEW_EXE flag).
    pub fn build_exe_seen_set(&self) -> ExeSeenSet {
        let set: HashSet<String> = self.executables.keys().cloned().collect();
        Arc::new(RwLock::new(set))
    }

    /// Handle event: update all tracking maps for exe and parent.
    /// Also inserts into `seen`/`exe_seen` so hot-path enrichment checks stay current.
    ///
    /// Returns true if this event represents a new exe or new sha256.
    pub fn handle_event(
        &mut self,
        event: &BpfEvent,
        seen: &SeenSet,
        exe_seen: &ExeSeenSet,
    ) -> bool {
        let mut is_new = false;

        // Child exe/name tracking
        if !event.exe.is_empty() && !event.name.is_empty() {
            // names[name] → append exe if not present
            if _insert_unique(&mut self.names, &event.name, &event.exe) {
                self.dirty = true;
            }
            // executables[exe] → append name if not present; first insert = new exe
            if _insert_unique(&mut self.executables, &event.exe, &event.name) {
                self.dirty = true;
                is_new = true;
                _append_exe_log(event, "exe");
                // Update ExeSeenSet so hot-path NEW_EXE check stays current
                if let Ok(mut set) = exe_seen.write() {
                    set.insert(event.exe.clone());
                }
            }
        }

        // Parent exe/name tracking
        if !event.pexe.is_empty() && !event.pname.is_empty() {
            if _insert_unique(&mut self.parent_names, &event.pname, &event.pexe) {
                self.dirty = true;
            }
            if _insert_unique(&mut self.parent_executables, &event.pexe, &event.pname) {
                self.dirty = true;
            }
        }

        // SHA256 tracking: exe → { hash → "" }
        if !event.exe.is_empty() && !event.sha256.is_empty() && !event.sha256.starts_with("!!!") {
            let hashes = self.sha256.entry(event.exe.clone()).or_default();
            if !hashes.contains_key(&event.sha256) {
                hashes.insert(event.sha256.clone(), String::new());
                self.dirty = true;
                is_new = true;
                _append_exe_log(event, "hash");
                // Update SeenSet so hot-path enrichment check stays current
                if let Ok(mut set) = seen.write() {
                    set.insert((event.exe.clone(), event.sha256.clone()));
                }
            }
        }

        is_new
    }

    /// Flush state.json atomically. No-op if not dirty.
    pub fn flush(&mut self, _config: &Config) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }

        let data_dir = crate::config::data_dir();
        fs::create_dir_all(&data_dir)?;

        let state_json = StateJson {
            executables: self.executables.clone(),
            names: self.names.clone(),
            parent_executables: self.parent_executables.clone(),
            parent_names: self.parent_names.clone(),
            sha256: self.sha256.clone(),
        };

        let json_str = serde_json::to_string_pretty(&state_json)?;
        let path = _state_path();
        let temp = _state_temp_path();

        fs::write(&temp, json_str)?;
        fs::rename(&temp, &path)?;

        self.dirty = false;
        Ok(())
    }
}

// ============================================================================
// Background flush task
// ============================================================================

/// Background flush task. Accepts a shutdown receiver so SIGINT handler can
/// stop this loop before attempting its own final flush, preventing concurrent writes.
pub async fn flush_loop(
    state: Arc<Mutex<AppState>>,
    config: Arc<Config>,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) {
    let mut ticker = interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let mut guard = state.lock().await;
                if guard.dirty {
                    if let Err(e) = guard.flush(&config) {
                        // M-3: log with context; dirty remains true so next tick retries.
                        // Common causes: disk full, permissions. Daemon continues running.
                        tracing::warn!("state flush failed (will retry in 30s): {}", e);
                    }
                }
            }
            _ = &mut shutdown_rx => {
                // SIGINT handler will perform final flush; exit loop to release the lock.
                break;
            }
        }
    }
}

// ============================================================================
// Log helpers
// ============================================================================

fn _append_exe_log(event: &BpfEvent, reason: &str) {
    let log_dir = crate::config::log_dir();
    if fs::create_dir_all(&log_dir).is_err() {
        return;
    }
    let path = _exe_log_path();
    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let line = format!("{} {:<16} {} (new {})\n", ts, event.name, event.exe, reason);
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = f.write_all(line.as_bytes());
    }
}

pub fn log_error(msg: &str) {
    let log_dir = crate::config::log_dir();
    if fs::create_dir_all(&log_dir).is_err() {
        return;
    }
    let path = _error_log_path();
    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let line = format!("{} {}\n", ts, msg);
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = f.write_all(line.as_bytes());
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn _state_path() -> PathBuf {
    crate::config::data_dir().join("state.json")
}

fn _state_temp_path() -> PathBuf {
    crate::config::data_dir().join("state.json.tmp")
}

fn _exe_log_path() -> PathBuf {
    crate::config::log_dir().join("exe.log")
}

fn _error_log_path() -> PathBuf {
    crate::config::log_dir().join("error.log")
}

/// Insert value into map[key] if not already present. Returns true if inserted.
fn _insert_unique(map: &mut HashMap<String, Vec<String>>, key: &str, value: &str) -> bool {
    let vec = map.entry(key.to_string()).or_default();
    if !vec.iter().any(|v| v == value) {
        vec.push(value.to_string());
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests_state {
    use super::*;
    use crate::types::{BpfEvent, EventMeta};
    use std::net::{IpAddr, Ipv4Addr};

    fn make_event(exe: &str, name: &str, sha256: &str) -> BpfEvent {
        BpfEvent {
            pid: 1,
            ppid: 0,
            uid: 1000,
            name: name.to_string(),
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
            send: 0,
            recv: 0,
            lport: 0,
            rport: 80,
            laddr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            raddr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            domain: String::new(),
            domain_source: "unknown".to_string(),
            domain_confidence: "none".to_string(),
            domain_status: "unknown".to_string(),
            sha256: sha256.to_string(),
            psha256: String::new(),
            meta: EventMeta::default(),
        }
    }

    #[test]
    fn first_exe_is_new() {
        let mut state = AppState::new();
        let seen = state.build_seen_set();
        let exe_seen = state.build_exe_seen_set();
        let ev = make_event("/usr/bin/curl", "curl", "abc123");
        assert!(state.handle_event(&ev, &seen, &exe_seen));
    }

    #[test]
    fn same_exe_same_hash_not_new() {
        let mut state = AppState::new();
        let seen = state.build_seen_set();
        let exe_seen = state.build_exe_seen_set();
        let ev = make_event("/usr/bin/curl", "curl", "abc123");
        state.handle_event(&ev, &seen, &exe_seen);
        // Second call: same exe + same hash → not new
        assert!(!state.handle_event(&ev, &seen, &exe_seen));
    }

    #[test]
    fn same_exe_new_hash_is_new() {
        let mut state = AppState::new();
        let seen = state.build_seen_set();
        let exe_seen = state.build_exe_seen_set();
        let ev1 = make_event("/usr/bin/curl", "curl", "abc123");
        state.handle_event(&ev1, &seen, &exe_seen);
        // Same exe, different hash → new (possible tampering)
        let ev2 = make_event("/usr/bin/curl", "curl", "deadbeef");
        assert!(state.handle_event(&ev2, &seen, &exe_seen));
    }

    #[test]
    fn handle_event_updates_seen_set() {
        let mut state = AppState::new();
        let seen = state.build_seen_set();
        let exe_seen = state.build_exe_seen_set();
        let ev = make_event("/usr/bin/curl", "curl", "abc123");
        state.handle_event(&ev, &seen, &exe_seen);
        // SeenSet must contain the pair after handle_event
        let key = ("/usr/bin/curl".to_string(), "abc123".to_string());
        assert!(seen.read().unwrap().contains(&key));
    }

    #[test]
    fn handle_event_updates_exe_seen_set() {
        let mut state = AppState::new();
        let seen = state.build_seen_set();
        let exe_seen = state.build_exe_seen_set();
        let ev = make_event("/usr/bin/curl", "curl", "abc123");
        state.handle_event(&ev, &seen, &exe_seen);
        assert!(exe_seen.read().unwrap().contains("/usr/bin/curl"));
    }

    #[test]
    fn dirty_flag_set_on_new_exe() {
        let mut state = AppState::new();
        let seen = state.build_seen_set();
        let exe_seen = state.build_exe_seen_set();
        assert!(!state.dirty);
        let ev = make_event("/usr/bin/curl", "curl", "abc123");
        state.handle_event(&ev, &seen, &exe_seen);
        assert!(state.dirty);
    }

    #[test]
    fn no_dirty_on_repeated_event() {
        let mut state = AppState::new();
        let seen = state.build_seen_set();
        let exe_seen = state.build_exe_seen_set();
        let ev = make_event("/usr/bin/curl", "curl", "abc123");
        state.handle_event(&ev, &seen, &exe_seen);
        state.dirty = false; // reset
        state.handle_event(&ev, &seen, &exe_seen);
        assert!(!state.dirty);
    }

    #[test]
    fn state_and_log_paths_match_config_owners() {
        assert_eq!(_state_path(), crate::config::data_dir().join("state.json"));
        assert_eq!(
            _state_temp_path(),
            crate::config::data_dir().join("state.json.tmp")
        );
        assert_eq!(_exe_log_path(), crate::config::log_dir().join("exe.log"));
        assert_eq!(
            _error_log_path(),
            crate::config::log_dir().join("error.log")
        );
    }
}
