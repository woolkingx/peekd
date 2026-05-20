//! hasher.rs: SHA256 hash computation for executables.
//!
//! Computes SHA256 for exe paths via three-tier fallback:
//! 1. Direct fd read from /proc/{pid}/fd/{n}
//! 2. Fallback: read /proc/{pid}/exe
//! 3. Fallback: FUSE worker (AppImage/unionfs cases)
//!
//! Caches results by (dev, ino, mod_cnt) to avoid rehashing.
//! mod_cnt from fanotify invalidation counter forces cache miss on file modification.

use crate::config::Config;
use crate::fuse::FuseRequest;
use crate::types::BpfEvent;
use lru::LruCache;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, oneshot};

/// Hasher: SHA256 computation with LRU cache and fallback chain.
pub struct Hasher {
    cache: LruCache<(u64, u64, u64), String>,
    fuse_tx: Option<mpsc::Sender<FuseRequest>>,
    config: Arc<Config>,
}

impl Hasher {
    /// Create new Hasher with config and optional fuse channel.
    pub fn new(config: Arc<Config>, fuse_tx: Option<mpsc::Sender<FuseRequest>>) -> Self {
        let capacity = NonZeroUsize::new(1024).unwrap();
        Self {
            cache: LruCache::new(capacity),
            fuse_tx,
            config,
        }
    }

    /// Compute SHA256 for executable, using cache + fallback chain.
    /// Returns hex string on success, error string starting with "!!!" on failure.
    pub async fn hash(&mut self, event: &BpfEvent, mod_cnt: u64) -> String {
        let key = (event.dev, event.ino, mod_cnt);

        // Cache hit: return immediately
        if let Some(hash) = self.cache.get(&key) {
            return hash.clone();
        }

        let fd_path = event.fd_path.clone();
        let pid = event.pid;
        let dev = event.dev;
        let ino = event.ino;
        if let Ok(Some(hash)) =
            tokio::task::spawn_blocking(move || _get_sha256_local(&fd_path, pid, dev, ino)).await
        {
            self.cache.put(key, hash.clone());
            return hash;
        }

        // Fallback 3: Try fuse worker
        if let Some(hash) = self._get_sha256_fuse(event, mod_cnt).await {
            self.cache.put(key, hash.clone());
            return hash;
        }

        // All fallbacks exhausted
        let error = "!!! All hash methods failed".to_string();
        self.cache.put(key, error.clone());
        error
    }

    /// Try fuse worker for AppImage or unionfs mounts.
    async fn _get_sha256_fuse(&self, event: &BpfEvent, _mod_cnt: u64) -> Option<String> {
        let tx = self.fuse_tx.as_ref()?;
        let (reply_tx, reply_rx) = oneshot::channel();

        let req = FuseRequest {
            path: event.exe.clone(),
            pid: event.pid,
            dev: event.dev,
            ino: event.ino,
            reply_tx,
        };

        if tx.send(req).await.is_err() {
            return None;
        }

        match reply_rx.await {
            Ok(Some(hash)) => Some(hash),
            _ => None,
        }
    }
}

fn _get_sha256_local(fd_path: &str, pid: u32, dev: u64, ino: u64) -> Option<String> {
    if !fd_path.is_empty() {
        if let Some(hash) = _get_sha256_fd(fd_path, dev, ino) {
            return Some(hash);
        }
    }
    if pid > 0 {
        return _get_sha256_pid(pid, dev, ino);
    }
    None
}

/// Try read via /proc/{pid}/fd/{n}, verify inode matches.
fn _get_sha256_fd(fd_path: &str, dev: u64, ino: u64) -> Option<String> {
    let file = File::open(fd_path).ok()?;

    // Verify inode to prevent swap
    let metadata = file.metadata().ok()?;
    if _stat_dev(&metadata) != dev || _stat_ino(&metadata) != ino {
        return None;
    }

    _sha256_file(file)
}

/// Try read via /proc/{pid}/exe, verify inode matches.
fn _get_sha256_pid(pid: u32, dev: u64, ino: u64) -> Option<String> {
    let exe_path = format!("/proc/{}/exe", pid);
    let file = File::open(exe_path).ok()?;

    // Verify inode
    let metadata = file.metadata().ok()?;
    if _stat_dev(&metadata) != dev || _stat_ino(&metadata) != ino {
        return None;
    }

    _sha256_file(file)
}

/// Compute SHA256 of file by streaming read.
fn _sha256_file(mut file: File) -> Option<String> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];

    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return None,
        }
    }

    let hash_bytes = hasher.finalize();
    let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    Some(hex)
}

/// Extract dev from file metadata (platform-specific).
#[cfg(unix)]
fn _stat_dev(metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.dev()
}

#[cfg(not(unix))]
fn _stat_dev(_metadata: &std::fs::Metadata) -> u64 {
    0
}

/// Extract ino from file metadata (platform-specific).
#[cfg(unix)]
fn _stat_ino(metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.ino()
}

#[cfg(not(unix))]
fn _stat_ino(_metadata: &std::fs::Metadata) -> u64 {
    0
}

/// Run hasher task: read BpfEvent from rx, populate sha256 field, broadcast.
pub async fn run(
    mut rx: broadcast::Receiver<BpfEvent>,
    tx: broadcast::Sender<BpfEvent>,
    config: Arc<Config>,
    fuse_tx: Option<mpsc::Sender<FuseRequest>>,
    fd_cache: Arc<tokio::sync::Mutex<crate::fd_cache::FdCache>>,
    metrics: Arc<crate::metrics::Metrics>,
) {
    let mut hasher = Hasher::new(config, fuse_tx);

    loop {
        match rx.recv().await {
            Ok(mut event) => {
                let mod_cnt = {
                    let mut cache = fd_cache.lock().await;
                    cache
                        .get(event.dev, event.ino)
                        .map(|(_, cnt)| cnt)
                        .unwrap_or(0)
                };

                event.sha256 = hasher.hash(&event, mod_cnt).await;
                event.psha256 = hasher.hash_parent(&event, &fd_cache).await;

                if let Err(e) = tx.send(event) {
                    tracing::error!("hasher broadcast failed: {}", e);
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!("hasher lagged, dropping {} events", n);
                metrics.record_broadcast_lag("hasher", n);
            }
            Err(broadcast::error::RecvError::Closed) => {
                break;
            }
        }
    }
}

/// Helper: hash parent process exe using parent's own mod_cnt from fd_cache.
impl Hasher {
    async fn hash_parent(
        &mut self,
        event: &BpfEvent,
        fd_cache: &Arc<tokio::sync::Mutex<crate::fd_cache::FdCache>>,
    ) -> String {
        // G-5: zero pdev/pino means parent info unavailable — all such events would share
        // cache key (0,0,0) and return the same wrong hash. Return empty string instead.
        if event.pdev == 0 && event.pino == 0 {
            return String::new();
        }

        let parent_mod_cnt = {
            let mut cache = fd_cache.lock().await;
            cache
                .get(event.pdev, event.pino)
                .map(|(_, cnt)| cnt)
                .unwrap_or(0)
        };

        let mut parent_event = event.clone();
        parent_event.dev = event.pdev;
        parent_event.ino = event.pino;
        parent_event.exe = event.pexe.clone();
        parent_event.fd_path = event.pfd_path.clone();
        parent_event.pid = event.ppid;

        self.hash(&parent_event, parent_mod_cnt).await
    }
}

#[cfg(test)]
mod tests_hasher {
    use super::*;

    #[test]
    fn local_hash_reads_matching_fd() {
        let path = std::env::temp_dir().join(format!("peekd-hasher-{}", std::process::id()));
        std::fs::write(&path, b"abc").unwrap();
        let file = File::open(&path).unwrap();
        let metadata = file.metadata().unwrap();
        let hash = _get_sha256_local(
            path.to_str().unwrap(),
            0,
            _stat_dev(&metadata),
            _stat_ino(&metadata),
        )
        .unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(
            hash,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
