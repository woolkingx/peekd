#![allow(dead_code, unused_imports)]
use crate::types::BpfEvent;
use crate::config::Config;
use tracing::{info, warn, error};
use std::path::Path;
use std::collections::HashMap;
use std::time::{Instant, Duration};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlertRule {
    pub name: String,
    pub exe: Option<String>,
    #[serde(skip)]
    pub exe_glob: Option<glob::Pattern>,
    pub domain: Option<String>,
    pub rport: Option<u16>,
    pub rport_not: Vec<u16>,
    pub sha256: Option<String>,
    pub on_new_hash: bool,
    pub action: AlertAction,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum AlertAction {
    #[serde(rename = "exec")]
    Exec(String),
    #[serde(rename = "webhook")]
    Webhook {
        #[serde(rename = "webhook_url")]
        url: String,
        #[serde(rename = "webhook_method")]
        method: String,
    },
}

pub fn load_rules(path: &Path) -> anyhow::Result<Vec<AlertRule>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path)?;
    let raw: RawAlertsToml = toml::from_str(&text)?;
    raw.alerts.into_iter().map(_parse_raw_rule).collect()
}

#[derive(Deserialize)]
struct RawAlertsToml {
    #[serde(default)]
    alerts: Vec<RawAlertRule>,
}

#[derive(Deserialize)]
struct RawAlertRule {
    name: String,
    #[serde(default)]
    exe: Option<String>,
    #[serde(default)]
    exe_glob: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    rport: Option<u16>,
    #[serde(default)]
    rport_not: Vec<u16>,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    on_new_hash: bool,
    action: String,
    #[serde(default)]
    exec: Option<String>,
    #[serde(default)]
    webhook_url: Option<String>,
    #[serde(default)]
    webhook_method: Option<String>,
}

fn _parse_raw_rule(raw: RawAlertRule) -> anyhow::Result<AlertRule> {
    // Parse exe_glob pattern if provided
    let exe_glob = if let Some(pattern_str) = raw.exe_glob {
        if pattern_str.is_empty() {
            None
        } else {
            Some(glob::Pattern::new(&pattern_str)?)
        }
    } else {
        None
    };

    // Clear empty strings to None for string options
    let exe = raw.exe.filter(|s| !s.is_empty());
    let domain = raw.domain.filter(|s| !s.is_empty());
    let sha256 = raw.sha256.filter(|s| !s.is_empty());

    // Parse action based on action field
    let action = match raw.action.as_str() {
        "exec" => {
            let exec_cmd = raw
                .exec
                .ok_or_else(|| anyhow::anyhow!("exec action requires 'exec' field"))?;
            AlertAction::Exec(exec_cmd)
        }
        "webhook" => {
            let url = raw
                .webhook_url
                .ok_or_else(|| anyhow::anyhow!("webhook action requires 'webhook_url' field"))?;
            let method = raw
                .webhook_method
                .unwrap_or_else(|| "POST".to_string());
            AlertAction::Webhook { url, method }
        }
        _ => anyhow::bail!("unknown action: {}", raw.action),
    };

    Ok(AlertRule {
        name: raw.name,
        exe,
        exe_glob,
        domain,
        rport: if raw.rport == Some(0) { None } else { raw.rport },
        rport_not: raw.rport_not,
        sha256,
        on_new_hash: raw.on_new_hash,
        action,
    })
}

fn _matches(rule: &AlertRule, event: &BpfEvent) -> bool {
    rule.exe.as_deref().map_or(true, |e| event.exe == e)
        && rule.exe_glob.as_ref().map_or(true, |g| g.matches(&event.exe))
        && rule.domain.as_ref().map_or(true, |d| event.domain.starts_with(d))
        && rule.rport.map_or(true, |p| event.rport == p)
        && (rule.rport_not.is_empty() || !rule.rport_not.contains(&event.rport))
        && rule.sha256.as_deref().map_or(true, |s| event.sha256 == s)
        && (!rule.on_new_hash || event.meta.is_new_hash())
}

fn _expand_template(template: &str, event: &BpfEvent) -> String {
    template
        .replace("{exe}", &event.exe)
        .replace("{raddr}", &event.raddr.to_string())
        .replace("{rport}", &event.rport.to_string())
        .replace("{domain}", &event.domain)
        .replace("{name}", &event.name)
        .replace("{sha256}", &event.sha256)
}

async fn _exec_action(cmd: &str) {
    match tokio::process::Command::new("sh").arg("-c").arg(cmd).spawn() {
        Ok(mut child) => {
            tokio::spawn(async move {
                let _ = child.wait().await;
            });
        }
        Err(e) => error!("alert exec spawn failed: {}", e),
    }
}

#[cfg(feature = "alerts-webhook")]
async fn _webhook_action(url: &str, method: &str, event: &BpfEvent) {
    let client = reqwest::Client::new();
    let json_body = match serde_json::to_value(event) {
        Ok(v) => v,
        Err(e) => {
            error!("alert webhook JSON encode failed: {}", e);
            return;
        }
    };
    let request = match method.to_uppercase().as_str() {
        "POST" => client.post(url).json(&json_body),
        "PUT" => client.put(url).json(&json_body),
        "PATCH" => client.patch(url).json(&json_body),
        _ => {
            error!("alert unknown HTTP method: {}", method);
            return;
        }
    };
    if let Err(e) = request.send().await {
        error!("alert webhook request failed: {}", e);
    }
}

#[cfg(not(feature = "alerts-webhook"))]
async fn _webhook_action(_url: &str, _method: &str, _event: &BpfEvent) {
    warn!("alert webhook feature not enabled");
}

/// Shared alert rules handle for hot-reload via SIGHUP.
pub type SharedRules = Arc<RwLock<Vec<AlertRule>>>;

/// Load alert rules into a shared handle (called at startup and on SIGHUP).
pub fn load_shared_rules(config: &Config) -> SharedRules {
    let _ = config;
    let rules_path = crate::config::config_dir().join("alerts.toml");
    let rules = match load_rules(&rules_path) {
        Ok(r) => r,
        Err(e) => {
            error!("failed to load alerts.toml: {}", e);
            Vec::new()
        }
    };
    Arc::new(RwLock::new(rules))
}

/// Reload alert rules into an existing shared handle (called on SIGHUP).
pub async fn reload_shared_rules(shared: &SharedRules) {
    let rules_path = crate::config::config_dir().join("alerts.toml");
    match load_rules(&rules_path) {
        Ok(rules) => {
            *shared.write().await = rules;
            info!("alert rules reloaded");
        }
        Err(e) => error!("alert rules reload failed: {}", e),
    }
}

/// Run alert processor task.
///
/// Consumes BpfEvent from broadcast channel, evaluates against alert rules,
/// and executes scripts or webhooks for matching rules with deduplication.
/// Rules are hot-reloadable via `shared_rules` handle (updated on SIGHUP).
pub async fn run(
    mut rx: tokio::sync::broadcast::Receiver<BpfEvent>,
    _config: Arc<Config>,
    shared_rules: SharedRules,
    metrics: Arc<crate::metrics::Metrics>,
) {
    // Deduplication window: (rule_name, exe, raddr_string, rport, uid) -> last_fired
    // uid included to prevent privilege-escalation bypass (different uid = different dedup slot)
    let mut dedup_window: HashMap<(String, String, String, u16, u32), Instant> = HashMap::new();
    let dedup_secs = 60u64;
    let prune_interval = Duration::from_secs(dedup_secs * 2);
    let mut last_prune = Instant::now();

    loop {
        match rx.recv().await {
            Ok(event) => {
                // Periodically prune expired dedup entries to prevent unbounded growth.
                // Time-based (not event-count-based) so it works at both high and low throughput.
                if last_prune.elapsed() >= prune_interval {
                    dedup_window.retain(|_, last_fired| last_fired.elapsed() < prune_interval);
                    last_prune = Instant::now();
                }

                let rules = shared_rules.read().await;
                for rule in rules.iter() {
                    if !_matches(rule, &event) {
                        continue;
                    }

                    let dedup_key = (
                        rule.name.clone(),
                        event.exe.clone(),
                        event.raddr.to_string(),
                        event.rport,
                        event.uid,
                    );

                    let should_fire = if let Some(&last_fired) = dedup_window.get(&dedup_key) {
                        last_fired.elapsed() >= Duration::from_secs(dedup_secs)
                    } else {
                        true
                    };

                    if !should_fire {
                        continue;
                    }

                    dedup_window.insert(dedup_key, Instant::now());
                    metrics.alerts_fired.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    // Fire action in a separate task — never blocks the event loop.
                    // Matching + dedup stay in the main loop (need mutable dedup_window).
                    let action = rule.action.clone();
                    let event_clone = event.clone();
                    tokio::spawn(async move {
                        match &action {
                            AlertAction::Exec(template) => {
                                let cmd = _expand_template(template, &event_clone);
                                _exec_action(&cmd).await;
                            }
                            AlertAction::Webhook { url, method } => {
                                _webhook_action(url, method, &event_clone).await;
                            }
                        }
                    });
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                warn!("alert broadcast channel lagged, dropped {} events", n);
                metrics.events_dropped.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                info!("alert broadcast channel closed, exiting");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests_alerts {
    use super::*;
    use crate::types::{BpfEvent, EventMeta};
    use std::net::{IpAddr, Ipv4Addr};

    fn make_event(exe: &str, rport: u16, domain: &str, sha256: &str, meta: EventMeta) -> BpfEvent {
        BpfEvent {
            pid: 1, ppid: 0, uid: 1000,
            name: "test".to_string(), pname: String::new(),
            exe: exe.to_string(), pexe: String::new(),
            cmdline: String::new(), pcmdline: String::new(),
            fd_path: String::new(), pfd_path: String::new(),
            dev: 1, ino: 1, pdev: 0, pino: 0,
            send: 100, recv: 0,
            lport: 0, rport,
            laddr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            raddr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            domain: domain.to_string(),
            sha256: sha256.to_string(), psha256: String::new(),
            meta,
        }
    }

    fn make_rule(on_new_hash: bool, rport: Option<u16>, exe: Option<&str>) -> AlertRule {
        AlertRule {
            name: "test-rule".to_string(),
            exe: exe.map(|s| s.to_string()),
            exe_glob: None,
            domain: None,
            rport,
            rport_not: vec![],
            sha256: None,
            on_new_hash,
            action: AlertAction::Exec("echo {exe}".to_string()),
        }
    }

    #[test]
    fn rule_matches_any_event_when_no_conditions() {
        let rule = make_rule(false, None, None);
        let ev = make_event("/usr/bin/curl", 443, "example.com", "abc", EventMeta::default());
        assert!(_matches(&rule, &ev));
    }

    #[test]
    fn rule_on_new_hash_requires_meta_flag() {
        let rule = make_rule(true, None, None);
        let ev_no_flag = make_event("/usr/bin/curl", 443, "", "abc", EventMeta::default());
        assert!(!_matches(&rule, &ev_no_flag));

        let mut meta = EventMeta::default();
        meta.set_new_hash();
        let ev_flagged = make_event("/usr/bin/curl", 443, "", "abc", meta);
        assert!(_matches(&rule, &ev_flagged));
    }

    #[test]
    fn rule_on_new_hash_does_not_fire_on_new_exe_only() {
        // NEW_EXE alone must NOT trigger on_new_hash rule (semantics: new exe is normal)
        let rule = make_rule(true, None, None);
        let mut meta = EventMeta::default();
        meta.set_new_exe();
        let ev = make_event("/usr/bin/curl", 443, "", "abc", meta);
        assert!(!_matches(&rule, &ev));
    }

    #[test]
    fn rport_filter_exact_match() {
        let rule = make_rule(false, Some(443), None);
        let ev_match = make_event("/usr/bin/curl", 443, "", "abc", EventMeta::default());
        let ev_miss  = make_event("/usr/bin/curl", 80,  "", "abc", EventMeta::default());
        assert!(_matches(&rule, &ev_match));
        assert!(!_matches(&rule, &ev_miss));
    }

    #[test]
    fn exe_filter_exact_match() {
        let rule = make_rule(false, None, Some("/usr/bin/curl"));
        let ev_match = make_event("/usr/bin/curl", 443, "", "abc", EventMeta::default());
        let ev_miss  = make_event("/usr/bin/wget", 443, "", "abc", EventMeta::default());
        assert!(_matches(&rule, &ev_match));
        assert!(!_matches(&rule, &ev_miss));
    }

    #[test]
    fn rport_not_excludes_event() {
        let mut rule = make_rule(false, None, None);
        rule.rport_not = vec![443];
        let ev = make_event("/usr/bin/curl", 443, "", "abc", EventMeta::default());
        assert!(!_matches(&rule, &ev));
    }
}
