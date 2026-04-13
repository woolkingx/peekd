#![allow(dead_code, unused_imports)]

//! notify.rs: Desktop notification via D-Bus (optional feature).
//!
//! Consumes NotifyMsg from state/other modules, sends D-Bus notifications.
//! Feature-gated: compile with `--features notifications` to enable.
//! When disabled, run() drains the channel (no-op).

use std::sync::Arc;
use crate::config::Config;
use crate::types::NotifyMsg;

/// Drop root privileges permanently to the specified user.
///
/// Required before accessing D-Bus session bus (user-owned socket).
/// SAFETY: nix::unistd::setuid calls libc::setuid (not raw syscall).
/// glibc implements process-wide via SIGRT synchronization.
/// WARNING: musl uses raw SYS_setuid (thread-local only) — not safe under musl/Alpine.
#[cfg(feature = "notifications")]
fn _drop_root(user: &str) {
    use nix::unistd::{Uid, User as NixUser};

    let nix_user = match NixUser::from_name(user) {
        Ok(Some(u)) => u,
        _ => {
            tracing::warn!("user '{}' not found, cannot drop root", user);
            return;
        }
    };

    let uid = nix_user.uid;
    let gid = nix_user.gid;

    let _ = nix::unistd::setgroups(&[]);
    if let Err(e) = nix::unistd::setgid(gid) {
        tracing::error!("setgid failed: {}", e);
        return;
    }
    if let Err(e) = nix::unistd::setuid(uid) {
        tracing::error!("setuid failed: {}", e);
        return;
    }
    // Verify cannot regain root
    if nix::unistd::setuid(Uid::from_raw(0)).is_ok() {
        tracing::error!("CRITICAL: able to regain root after drop");
        std::process::exit(1);
    }
    tracing::info!("dropped root to user '{}'", user);
}

/// Run notification task (feature-enabled version).
///
/// Drops root, then listens for NotifyMsg and sends D-Bus notifications.
/// Dedup: skip if identical to last message sent.
#[cfg(feature = "notifications")]
pub async fn run(
    mut notify_rx: tokio::sync::mpsc::Receiver<NotifyMsg>,
    config: Arc<Config>,
) {
    if !config.desktop.user.is_empty() {
        _drop_root(&config.desktop.user);
    }

    let mut last_sent = String::new();

    while let Some(msg) = notify_rx.recv().await {
        let (summary, body) = match &msg {
            NotifyMsg::NewExe { pid, exe, cmdline } => {
                ("peekd: New executable".into(), format!("[pid {}] {} ({})", pid, exe, cmdline))
            }
            NotifyMsg::NewHash { exe, sha256 } => {
                ("peekd: Hash changed".into(), format!("Binary modified: {} ({})", exe, sha256))
            }
            NotifyMsg::Error { msg } => {
                ("peekd: Error".into(), msg.clone())
            }
        };

        let key = format!("{}:{}", summary, body);
        if key == last_sent {
            continue;
        }
        last_sent = key;

        if config.desktop.notifications {
            match notify_rust::Notification::new()
                .summary(&summary)
                .body(&body)
                .appname("peekd")
                .timeout(5000)
                .show()
            {
                Ok(_) => tracing::info!("notification sent: {}", summary),
                Err(e) => tracing::error!("D-Bus error: {}", e),
            }
        }
    }
}

/// No-op stub when notifications feature is disabled.
/// Drains channel to prevent backpressure.
#[cfg(not(feature = "notifications"))]
pub async fn run(
    mut notify_rx: tokio::sync::mpsc::Receiver<NotifyMsg>,
    _config: Arc<Config>,
) {
    while let Some(_msg) = notify_rx.recv().await {}
}
