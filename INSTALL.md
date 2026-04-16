# Installation Guide

## Requirements

- Linux kernel >= 5.8 with BTF (`CONFIG_DEBUG_INFO_BTF=y`)
- Root access
- Debian/Ubuntu recommended (paths assume `/usr/local/sbin`)

## Build from source

```bash
# Install Rust nightly + BPF target
rustup toolchain install nightly
rustup target add --toolchain nightly bpfel-unknown-none

# Build eBPF bytecode
cargo xtask build-ebpf --release

# Build userspace daemon
CARGO_BUILD_JOBS=1 cargo build --release -p peekd
```

## Install

```bash
# Binary
sudo install -m 755 target/release/peekd /usr/local/sbin/

# Directories
sudo mkdir -p /etc/peekd /var/lib/peekd /var/log/peekd

# Config files
sudo install -m 640 config/config.toml /etc/peekd/
sudo install -m 640 config/alerts.toml /etc/peekd/

# systemd service
sudo install -m 644 config/peekd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now peekd
```

## Verify

```bash
sudo systemctl status peekd
journalctl -u peekd -f
```

## Configuration

| File | Purpose |
|------|---------|
| `/etc/peekd/config.toml` | Main config (database, log filters, web) |
| `/etc/peekd/alerts.toml` | Alert rules |

Edit then reload alerts without restart:

```bash
sudo kill -HUP $(pidof peekd)
```

## Uninstall

```bash
sudo systemctl disable --now peekd
sudo rm /etc/systemd/system/peekd.service
sudo rm /usr/local/sbin/peekd
sudo rm -rf /etc/peekd /var/lib/peekd /var/log/peekd
sudo systemctl daemon-reload
```

## Runtime files

| Path | Contents |
|------|----------|
| `/var/lib/peekd/peekd.db` | SQLite traffic database |
| `/var/lib/peekd/state.json` | Known exe/hash state |
| `/var/log/peekd/peekd.log` | Daemon log (daily rolling) |
| `/run/peekd/metrics.json` | Runtime metrics |
| `/run/peekd/peekd.sock` | Unix socket RPC |
