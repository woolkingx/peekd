#![allow(dead_code, unused_imports)]

//! fd_cache.rs: File descriptor → path caching with fanotify invalidation.
//!
//! Maintains an LRU cache of (dev, ino) → FdEntry mappings.
//! Listens to fanotify FAN_MODIFY events to track file modifications.
//! fd_path is cached for stable hashing in later stages.

use std::sync::Arc;
use std::os::unix::io::RawFd;
use lru::LruCache;
use tokio::sync::Mutex;
use crate::metrics::Metrics;

const FAN_MODIFY: u32 = 0x0002;
const FAN_MARK_ADD: u32 = 0x0000001;
const FAN_MARK_REMOVE: u32 = 0x0000002;

/// FdEntry: Cached file descriptor metadata.
///
/// Keeps fd open for stable hashing. mod_cnt tracks fanotify modifications.
#[derive(Clone, Debug)]
pub struct FdEntry {
    pub fd: Option<RawFd>,
    pub fd_path: String,
    pub exe: String,
    pub mod_cnt: u64,
}

/// FdCache: LRU cache for (dev, ino) → exe path resolution.
///
/// Capacity-bounded cache with fanotify integration.
/// Evicted entries unmark fd and close.
pub struct FdCache {
    cache: LruCache<(u64, u64), FdEntry>,
    fan_fd: Option<RawFd>,
    metrics: Arc<Metrics>,
}

impl FdCache {
    /// Create new FdCache with optional fanotify fd.
    pub fn new(fan_fd: Option<RawFd>, capacity: usize, metrics: Arc<Metrics>) -> Self {
        let cap = std::num::NonZeroUsize::new(capacity)
            .unwrap_or(std::num::NonZeroUsize::new(8192).unwrap());
        Self {
            cache: LruCache::new(cap),
            fan_fd,
            metrics,
        }
    }

    /// Resolve (dev, ino) → (exe, mod_cnt).
    ///
    /// Returns cached exe path and current mod_cnt, or None if resolution fails.
    /// Triggers LRU eviction if cache full.
    pub fn get(&mut self, dev: u64, ino: u64) -> Option<(String, u64)> {
        let entry = self.cache.get(&(dev, ino))?;
        Some((entry.exe.clone(), entry.mod_cnt))
    }

    /// Insert a new cache entry.
    ///
    /// Marks fd with fanotify if available.
    /// On eviction, removes fanotify mark and closes fd.
    pub fn insert(&mut self, dev: u64, ino: u64, entry: FdEntry) {
        self._mark_fanotify(entry.fd, true);

        if let Some((_, evicted)) = self.cache.push((dev, ino), entry) {
            self._mark_fanotify(evicted.fd, false);
            // G-7: explicitly close evicted fd to prevent fd leak
            if let Some(fd) = evicted.fd {
                unsafe { libc::close(fd); }
            }
        }
    }

    /// Increment mod_cnt for (dev, ino) on fanotify FAN_MODIFY event.
    pub fn invalidate(&mut self, dev: u64, ino: u64) {
        if let Some(entry) = self.cache.get_mut(&(dev, ino)) {
            entry.mod_cnt += 1;
        }
    }

    /// Process all pending fanotify events.
    ///
    /// Reads event metadata and calls invalidate() for each FAN_MODIFY.
    pub fn handle_fanotify_events(&mut self) {
        let Some(fan_fd) = self.fan_fd else {
            return;
        };

        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe {
                libc::read(fan_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
            };

            if n <= 0 {
                break;
            }

            self._process_fan_events(&buf[..n as usize]);
        }
    }

    fn _mark_fanotify(&self, fd: Option<RawFd>, add: bool) {
        let Some(fan_fd) = self.fan_fd else {
            return;
        };
        let Some(fd) = fd else {
            return;
        };

        let flags = if add { FAN_MARK_ADD as u32 } else { FAN_MARK_REMOVE as u32 };
        unsafe {
            let _ = libc::fanotify_mark(fan_fd, flags, FAN_MODIFY as u64, fd, std::ptr::null());
        }
    }

    fn _process_fan_events(&mut self, buf: &[u8]) {
        let mut offset = 0;
        while offset + 16 <= buf.len() {
            let event_ptr = &buf[offset] as *const u8 as *const libc::fanotify_event_metadata;
            let event = unsafe { &*event_ptr };

            if (event.mask as u32) & FAN_MODIFY != 0 {
                if let Ok(stat) = nix::sys::stat::fstat(event.fd) {
                    self.invalidate(stat.st_dev, stat.st_ino);
                }
            }

            unsafe { let _ = libc::close(event.fd); }

            offset += event.event_len as usize;
            if event.event_len == 0 {
                break;
            }
        }
    }
}

/// Background task: read fanotify events and update cache.
///
/// Uses AsyncFd for event-driven wakeup instead of polling.
/// Falls back to 100ms polling if AsyncFd is unavailable.
pub async fn fanotify_watcher(
    cache: Arc<Mutex<FdCache>>,
    _metrics: Arc<Metrics>,
) {
    use std::os::unix::io::RawFd;
    use tokio::io::unix::AsyncFd;
    use tokio::io::Interest;

    // Try to get fan_fd from cache for event-driven mode
    let fan_fd: Option<RawFd> = {
        let c = cache.lock().await;
        c.fan_fd
    };

    if let Some(fd) = fan_fd {
        // fan_fd is a valid fanotify file descriptor opened by init_fanotify()
        // and kept alive for the daemon's lifetime. AsyncFd does not take ownership.
        match AsyncFd::new(fd) {
            Ok(async_fd) => {
                loop {
                    match async_fd.readable().await {
                        Ok(mut guard) => {
                            {
                                let mut c = cache.lock().await;
                                c.handle_fanotify_events();
                            }
                            guard.clear_ready();
                        }
                        Err(e) => {
                            tracing::error!("AsyncFd readable error: {}", e);
                            break;
                        }
                    }
                }
                return;
            }
            Err(e) => {
                tracing::warn!("AsyncFd init failed, falling back to polling: {}", e);
            }
        }
    }

    // Fallback: polling mode
    loop {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let mut c = cache.lock().await;
        c.handle_fanotify_events();
    }
}
