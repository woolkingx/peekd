# peekd

Linux eBPF/libbpf CO-RE daemon for per-process network attribution: domains,
bytes, executable hashes, alerts, SQLite WAL storage, and a live web UI.

peekd answers the operator question: which executable talked to which domain or
IP, how much traffic moved, and did the binary change? It observes kernel
send/recv paths and DNS evidence, enriches each flow with process identity and
hashes, stores history in SQLite, and exposes CLI, report, metrics, alerts, and
dashboard views.

Rewritten from [picosnitch](https://github.com/elesiuta/picosnitch) in Rust with
a libbpf CO-RE eBPF adapter and a single-writer SQLite architecture.

## At a glance

| Layer | What peekd owns |
|---|---|
| Kernel capture | libbpf CO-RE probes for send/recv, lifecycle, exec, and resolver evidence |
| Attribution | Process, parent process, domain source/confidence/status, bytes, ports, exe hashes |
| Storage | SQLite WAL with one writer, query-only readers, retention, checkpoint and integrity commands |
| Operator surface | Web dashboard, CLI query/report, metrics JSON, alerts, desktop notifications |

## What it does

- Attributes AF_INET/AF_INET6 send/recv bytes to executable path, process name, parent process, UID, endpoint, and domain evidence
- Captures traffic via libbpf CO-RE probes on kernel send/recv paths
- Tracks TCP connection lifecycle (connect, accept, close), exec, and process metadata
- Resolves domains from DNS answers, resolver evidence, SNI/PTR hints, and proxy hints with source/confidence/status
- Resolves exe paths, cmdlines, sha256 hashes per process
- Stores connections in SQLite WAL with one writer, query-only readers, retention, checkpoint, and integrity commands
- Fires alerts (exec script or webhook) on configurable rules
- Detects binary tampering: `NEW_HASH` flag when a known exe gets a new sha256
- Exports runtime metrics to `/run/peekd/metrics.json`
- Serves a web dashboard with live traffic charts and per-process breakdown

## Architecture

```
kernel BPF (kprobe/kretprobe/uprobe)
    │
    ▼
bpf.rs (perf buffer poll)
    │  RawEvent broadcast
    ├──► dns.rs         (IP→domain cache)
    ├──► resolver.rs    (RawEvent→BpfEvent, /proc enrichment)
    │        │  BpfEvent broadcast
    │        ▼
    │    hasher.rs      (sha256 via fanotify fd / /proc/pid/exe)
    │        │  hashed BpfEvent broadcast
    │        ▼
    │    filter.rs + enrich  (EventMeta: NEW_EXE | NEW_HASH flags)
    │        │  filtered BpfEvent broadcast
    │        ├──► storage.rs   (SQLite writer thread)
    │        ├──► alerts.rs    (rule matching, exec/webhook actions)
    │        ├──► state.rs     (exe/hash tracking, state.json)
    │        └──► notify.rs    (desktop notifications)
    │
    ├──► query.rs  (Unix socket RPC + CLI)
    └──► web.rs    (HTTP dashboard, optional)
```

## Requirements

- Linux kernel >= 5.8, BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`)
- Build tools: Rust stable, clang, libelf headers, pkg-config
- Root or `CAP_BPF` + `CAP_NET_ADMIN`

## Build

```bash
# Build daemon and generate the libbpf BPF object
cargo build --release -p peekd

# Full release gate: object sanity, userspace build, startup smoke
scripts/verify_release.sh
```

## Install

```bash
sudo install -m 755 target/release/peekd /usr/local/sbin/
sudo mkdir -p /etc/peekd /var/lib/peekd /var/log/peekd /run/peekd
sudo install -m 640 config/config.toml /etc/peekd/
```

## Usage

```bash
# Run daemon (foreground)
sudo peekd daemon

# Run daemon with web dashboard on custom port
sudo peekd daemon --web-port 5100

# Serve web dashboard standalone (requires daemon running)
sudo peekd web --port 5100

# Traffic report (last 24h)
peekd report

# Report for specific time window, no row limit
peekd report --since 7d

# Report with row limit
peekd report --since 24h --top 20

# JSON output
peekd report --since 1h --json

# Live query via Unix socket RPC
peekd query --since 1h
peekd query --name curl --since 24h
peekd query --sum-bytes --since 7d

# Daemon status
peekd status
```

## Web Dashboard

Open `http://localhost:5100` after starting with `--web-port` or `peekd web`.

Features:
- Time range picker with date pickers, auto-refresh, group-by toggle
- Hourly/daily traffic charts (send + recv) with auto bucket granularity
- Top destinations by remote port (bar chart)
- Full destination table with hostname resolution and per-process breakdown
- Connection timeline slide-in panel, process tree view, connection detail drill-down
- Alert log panel, bytes over time stacked bar chart
- Inline column filter, URL hash permalink
- Ignore UI (`ignore_extra.toml` hot-reload)
- CSV export (`/api/export`)

Hostname resolution order: system PTR lookup (`/etc/resolv.conf`) → whois org lookup for public IPs.

## Configuration

`/etc/peekd/config.toml`:

```toml
[database]
enabled             = true
retention_days      = 30
write_limit_seconds = 5
text_log            = false  # also write new-exe events to /var/log/peekd/exe.log

[monitoring]
every_exe = false  # track exec events even without network activity

[log]
ignore_ports   = [53]
ignore_domains = ["localhost"]
ignore_ips     = ["127.0.0.0/8", "::1/128"]  # replaces ignore_networks
ignore_sha256  = []

[metrics]
interval_seconds = 30

[broadcast]
channel_capacity = 10000

[desktop]
user          = "root"
notifications = true

[web]
enabled         = false
port            = 5100
bind            = "127.0.0.1"  # "0.0.0.0" exposes on LAN (no auth)
refresh_seconds = 30
default_since   = "24h"
top_limit       = 200
```

Alert rules at `/etc/peekd/alerts.toml`:

```toml
[[alerts]]
name = "curl-outbound"
exe = "/usr/bin/curl"
rport = 443
action = "exec"
exec = "logger 'peekd: {exe} → {raddr}:{rport} ({domain})'"

[[alerts]]
name = "binary-tampered"
on_new_hash = true         # fires only on NEW_HASH (known exe, new sha256)
action = "exec"
exec = "logger 'peekd: binary tampered: {exe} sha256={sha256}'"
```

## Runtime files

| Path | Contents |
|------|----------|
| `/var/lib/peekd/peekd.db` | SQLite connections database |
| `/var/lib/peekd/state.json` | Known executables and hashes |
| `/var/log/peekd/peekd.log` | Structured daemon log (daily rolling) |
| `/run/peekd/metrics.json` | Runtime metrics snapshot |
| `/run/peekd/peekd.sock` | Unix socket for RPC queries |

## Signals

| Signal | Effect |
|--------|--------|
| `SIGINT` / `SIGTERM` | Graceful shutdown, final state flush |
| `SIGHUP` | Reload alert rules from `alerts.toml` |

## EventMeta flags

`NEW_EXE` (bit 0): exe path seen for the first time — normal (software install).  
`NEW_HASH` (bit 1): new sha256 for a known exe — suspicious (possible binary tampering).

Alert rules with `on_new_hash = true` trigger only on `NEW_HASH`, not `NEW_EXE`.

## eBPF hook points

| Hook | Kernel function | Captures |
|------|----------------|----------|
| `kprobe/inet_sendmsg` | `inet_sendmsg` | IP send bytes |
| `kretprobe/inet_sendmsg` | `inet_sendmsg` | IP send completion |
| `kprobe/inet_recvmsg` | `inet_recvmsg` | IP recv entry |
| `kretprobe/inet_recvmsg` | `inet_recvmsg` | IP recv bytes |
| `kprobe/tcp_v4_connect` | `tcp_v4_connect` | TCP connect entry (stash sock ptr) |
| `kretprobe/tcp_v4_connect` | `tcp_v4_connect` | TCP connect completion |
| `kretprobe/inet_csk_accept` | `inet_csk_accept` | TCP accept |
| `kprobe/tcp_close` | `tcp_close` | TCP close |
| `kretprobe/__x64_sys_execve` | `__x64_sys_execve` | Process execution |
| `uprobe/getaddrinfo` | libc `getaddrinfo` | DNS query hostname |
| `uretprobe/getaddrinfo` | libc `getaddrinfo` | DNS resolved addresses |
