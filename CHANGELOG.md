# Changelog

All notable changes to peekd are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.1.0] - 2026-04-01

### Added
- Initial eBPF network monitoring daemon
- IPv4/IPv6 send/recv tracking via kprobe
- DNS domain resolution via uprobe on `getaddrinfo`
- Process exe path resolution via fanotify + fd_cache
- SHA256 hashing with three fallback paths (fd, /proc/pid/exe, FUSE)
- SQLite storage with WAL mode, retention cleanup, indexed queries
- Alert system with exec/webhook actions, glob patterns, dedup window
- CLI query interface: table, JSON, count, sum-bytes modes
- Unix socket RPC at `/run/peekd/peekd.sock`
- picosnitch-compatible `state.json` format
- Runtime metrics export to `/run/peekd/metrics.json`
- SIGHUP hot-reload of alert rules
- SIGINT graceful shutdown with final state flush
