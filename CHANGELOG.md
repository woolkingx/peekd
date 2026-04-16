# Changelog

All notable changes to peekd are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
