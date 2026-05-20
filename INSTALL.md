# Installation Guide

## Requirements

- Linux kernel >= 5.8 with BTF (`CONFIG_DEBUG_INFO_BTF=y`)
- Root access
- Rust stable toolchain
- `clang`, `pkg-config`, and `libelf-dev` for libbpf CO-RE object generation
- `sqlite3` CLI for DB backup, schema readback, and upgrade verification
- Debian/Ubuntu recommended (paths assume `/usr/local/sbin`)

## Build from source

```bash
# Install build dependencies
sudo apt-get install -y clang pkg-config libelf-dev sqlite3

# Recommended release build gate:
# 1. generate the libbpf eBPF object through peekd/build.rs
# 2. verify the object has BTF
# 3. build userspace daemon with the generated skeleton embedded
# 4. smoke daemon startup
scripts/verify_release.sh
```

The release binary embeds the libbpf skeleton generated from
`peekd/src/bpf/peekd.bpf.c`. Install `target/release/peekd`; keep
`target/bpf/peekd.bpf.o` only for audit or
debugging.

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

## Upgrade Existing Host

Use this flow when `/usr/local/sbin/peekd` is already installed and a live
SQLite database exists under `/var/lib/peekd`.

### 1. Build and verify locally

From the source worktree:

```bash
cargo test -p peekd
scripts/verify_release.sh
sha256sum target/release/peekd target/bpf/peekd.bpf.o
```

Expected:

- tests pass
- `scripts/verify_release.sh` prints `ok`
- `target/release/peekd` exists and is executable

### 2. Inspect the running service

On the target host:

```bash
systemctl status peekd --no-pager
systemctl cat peekd
sha256sum /usr/local/sbin/peekd
```

The packaged service expects:

```text
ExecStart=/usr/local/sbin/peekd daemon
User=root
```

### 3. Create a rollback backup

```bash
ts="$(date +%Y%m%d-%H%M%S)"
sudo mkdir -p /var/backups/peekd/"$ts"

sudo cp -a /usr/local/sbin/peekd /var/backups/peekd/"$ts"/peekd.old
sudo cp -a /etc/peekd /var/backups/peekd/"$ts"/etc.peekd
sudo cp -a /var/lib/peekd/state.json /var/backups/peekd/"$ts"/state.json 2>/dev/null || true
```

Back up SQLite while the daemon is stopped in the next step. Do not copy only
`peekd.db` while the daemon is running; WAL state may be split across
`peekd.db`, `peekd.db-wal`, and `peekd.db-shm`.

### 4. Stop service, check SQLite, and back up

```bash
sudo systemctl stop peekd

sudo /usr/local/sbin/peekd db check
sudo /usr/local/sbin/peekd db checkpoint

sudo sqlite3 /var/lib/peekd/peekd.db \
  "VACUUM INTO '/var/backups/peekd/$ts/peekd.db';"

sudo cp -a /var/lib/peekd/peekd.db /var/backups/peekd/"$ts"/peekd.db.raw
sudo cp -a /var/lib/peekd/peekd.db-wal /var/backups/peekd/"$ts"/peekd.db-wal.raw 2>/dev/null || true
sudo cp -a /var/lib/peekd/peekd.db-shm /var/backups/peekd/"$ts"/peekd.db-shm.raw 2>/dev/null || true
```

### 5. Install the new binary

From the source worktree, or after copying the built binary to the host:

```bash
sudo install -m 755 target/release/peekd /usr/local/sbin/peekd
sha256sum /usr/local/sbin/peekd
```

No separate eBPF object install is required for the standard build. The
userspace binary already embeds the eBPF object.

### 6. Start service and confirm migration

```bash
sudo systemctl start peekd
sudo systemctl status peekd --no-pager

sqlite3 /var/lib/peekd/peekd.db ".schema connections"
sqlite3 /var/lib/peekd/peekd.db "PRAGMA user_version;"
sqlite3 /var/lib/peekd/peekd.db "PRAGMA quick_check;"
```

For the DomainEvidence upgrade, the `connections` table must contain:

```sql
domain_source TEXT NOT NULL DEFAULT 'unknown'
domain_confidence TEXT NOT NULL DEFAULT 'none'
domain_status TEXT NOT NULL DEFAULT 'unknown'
```

The daemon applies this migration automatically on startup. If these columns
are missing after restart, the running service is still using an old binary or
failed before opening storage.

### 7. Run live verification

Run the live domain evidence gate from the source worktree:

```bash
scripts/verify_db_runtime.sh
PEEKD_LIVE_FLUSH_WAIT=10 scripts/verify_domain_live.sh
```

The verifier:

- uses the existing daemon if one is running
- verifies SQLite quick_check, schema version, and Web JSON envelope shape
- triggers direct HTTPS traffic
- triggers mihomo proxy traffic through `127.0.0.1:7890`
- checks that the DB has domain metadata columns
- requires at least one direct evidence row
- requires at least one `proxy_ingress` row

Manual schema/data check:

```bash
sqlite3 -header -column /var/lib/peekd/peekd.db "
SELECT domain, domain_source, domain_confidence, domain_status, raddr, rport
FROM connections
ORDER BY contime DESC
LIMIT 20;"
```

### 8. Roll back if needed

```bash
sudo systemctl stop peekd
sudo install -m 755 /var/backups/peekd/"$ts"/peekd.old /usr/local/sbin/peekd
sudo cp -a /var/backups/peekd/"$ts"/etc.peekd/. /etc/peekd/
sudo cp -a /var/backups/peekd/"$ts"/state.json /var/lib/peekd/state.json 2>/dev/null || true
sudo systemctl start peekd
sudo systemctl status peekd --no-pager
```

If the new daemon already migrated the DB schema, rolling back the binary does
not remove the added columns. The added columns are backward-compatible because
they have defaults and preserve the existing `connections.domain` column.

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
