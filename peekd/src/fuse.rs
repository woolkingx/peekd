#![allow(dead_code, unused_imports)]

//! fuse.rs: Non-root hash worker for AppImage/FUSE executables.
//!
//! When peekd (root) encounters a FUSE-mounted executable (e.g. AppImage),
//! it cannot directly read the file. This module spawns a non-root child
//! process that permanently drops privileges and computes SHA256 hashes
//! on behalf of the main daemon.
//!
//! Communication: parent sends HashRequest via mpsc, child replies via oneshot.

use sha2::{Digest, Sha256};
use std::io::Read;
use tokio::sync::{mpsc, oneshot};

/// Request to compute SHA256 of a file.
#[derive(Debug)]
pub struct FuseRequest {
    pub path: String,
    pub pid: u32,
    pub dev: u64,
    pub ino: u64,
    pub reply_tx: oneshot::Sender<Option<String>>,
}

/// Drop root privileges permanently to the specified user.
/// SAFETY: nix::unistd::setuid calls libc::setuid (not raw syscall).
/// glibc implements process-wide via SIGRT synchronization.
/// WARNING: musl uses raw SYS_setuid (thread-local only) — not safe under musl/Alpine.
fn _drop_root(user: &str) -> bool {
    use nix::unistd::{Uid, User as NixUser};

    let nix_user = match NixUser::from_name(user) {
        Ok(Some(u)) => u,
        _ => {
            tracing::warn!("user '{}' not found", user);
            return false;
        }
    };

    let uid = nix_user.uid;
    let gid = nix_user.gid;

    let _ = nix::unistd::setgroups(&[]);
    if nix::unistd::setgid(gid).is_err() || nix::unistd::setuid(uid).is_err() {
        tracing::error!("privilege drop failed");
        return false;
    }
    // Verify cannot regain root
    if nix::unistd::setuid(Uid::from_raw(0)).is_ok() {
        tracing::error!("CRITICAL: able to regain root");
        std::process::exit(1);
    }
    tracing::info!("dropped root to '{}'", user);
    true
}

/// Compute SHA256 of file at path, returns hex string or None.
fn _hash_file(path: &str) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let result = hasher.finalize();
    Some(result.iter().map(|b| format!("{:02x}", b)).collect())
}

/// Run the fuse hash worker.
///
/// Drops privileges immediately, then processes hash requests from mpsc channel.
/// Each request gets a SHA256 hex string or None on failure.
pub async fn worker(mut rx: mpsc::Receiver<FuseRequest>, user: String, timeout_ms: u64) {
    // Drop root first — worker can only compute hashes after this
    if !user.is_empty() && !_drop_root(&user) {
        tracing::error!("cannot operate without privilege drop, exiting worker");
        return;
    }

    while let Some(req) = rx.recv().await {
        let path = req.path.clone();
        let timeout = tokio::time::Duration::from_millis(timeout_ms);

        // Hash in spawn_blocking with timeout
        let result = tokio::time::timeout(
            timeout,
            tokio::task::spawn_blocking(move || _hash_file(&path)),
        )
        .await;

        let hash = match result {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                tracing::error!("spawn_blocking error: {}", e);
                None
            }
            Err(_) => {
                tracing::warn!("timeout hashing {}", req.path);
                None
            }
        };

        let _ = req.reply_tx.send(hash);
    }
}
