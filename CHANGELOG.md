# Changelog

All notable changes to peekd are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.1.2] - 2026-05-20

### Added
- libbpf-rs/libbpf-cargo CO-RE eBPF adapter with generated skeleton loading
- DNS evidence pipeline with source, confidence, status, and per-IP deduplication
- SQLite WAL health checks, checkpoint command, integrity command, and startup recovery handling
- Storage module integration tests for schema, WAL behavior, query safety, ignore rules, and alert persistence
- Web API fail-closed row decoding and improved HTTP error statuses for ignore-rule updates

### Changed
- Replaced the Aya eBPF worktree with the libbpf skeleton path as the mainline adapter
- Switched send-byte capture to kernel paths that work on Debian 12 kernel 6.1 target hosts
- Enforced a single SQLite writer boundary for lifecycle and connection persistence
- Hardened notify and alert paths so slow consumers do not block hot event processing
- Updated release metadata, repository topics, and public positioning around per-process network attribution

### Fixed
- BPF verifier rejection from misaligned stack access in the send/recv event layout
- Kernel 6.1 incompatibility with multi-uprobe attach by falling back to single uprobe/uretprobe attach
- Web dashboard 500 responses caused by SQLite `SQLITE_IOERR` reader-open failures after WAL state changes
- Frontend data failure when API error payloads did not include expected `rows`
- Domain evidence over-growth by capping and deduplicating evidence per IP

---

## [0.1.1] - 2026-04-16

### Added
- Web dashboard Phase 0-3 overhaul: time range picker, date pickers, auto-refresh, group-by, column filter, URL hash permalink
- Alert log panel (`alert_events` DB table)
- Connection timeline slide-in panel (`/api/connections`)
- Process tree view panel
- Ignore UI + `ignore_extra.toml` (`/api/ignore`)
- Bytes over time stacked bar chart (`/api/timeseries`)
- CSV export (`/api/export`)
- Connection detail drill-down panel
- Chart.js v4 inline embed (CDN removed)
- Error banner and loading indicators
- `/api/config` endpoint; frontend reads config on startup
- `WebConfig`: `bind`, `static_dir`, `refresh_seconds`, `default_since`, `top_limit` fields
- `DatabaseConfig`: `text_log` field
- `LogConfig`: `addresses`, `commands`, `ports`, `ignore_ips`, `ignore_sha256` fields
- `BroadcastConfig` and `DesktopConfig` sections in config
- `filter.rs`: inline ignore filtering

### Changed
- `ignore_networks` renamed to `ignore_ips` in config
- Web dashboard default bind changed to `127.0.0.1`
- Bucket granularity auto-detects from time span
- N+1 query replaced with single JOIN + HashMap sort for raddr sub-rows

### Fixed
- XSS prevention: `escapeHtml()` on all dynamic HTML
- PTR cache: LRU eviction (10k entries), semaphore cap (20), whois 3s timeout
- All SQLite handlers moved to `spawn_blocking`
- Hour label concatenation bug in chart
- Routing fix for web dashboard SPA

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
