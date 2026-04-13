#![allow(dead_code, unused_imports)]

//! bpf.rs: BPF program loader and kernel event source.
//!
//! Loads compiled eBPF object, attaches all programs, spawns per-CPU perf readers.
//! Kernel requirements: Linux >= 5.8, CONFIG_DEBUG_INFO_BTF=y.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use crate::types::RawEvent;
use crate::metrics::Metrics;
use aya::Ebpf;
use aya::maps::PerfEventArray;
use aya::util::online_cpus;
use aya::programs::{FExit, KProbe, UProbe};
use aya::programs::uprobe::UProbeAttachLocation;
use bytes::BytesMut;
use tokio::io::unix::AsyncFd;
use tokio::sync::broadcast;
use tracing::{info, warn, error};
use peekd_common::{SendRecvEvent, SendRecv6Event, ExecEvent, DnsEvent, DnsEvent6, ConnectEventRaw};

/// Load BPF object, attach all programs, spawn per-CPU readers.
///
/// Returns broadcast channel sender for RawEvent variants from perf buffers.
pub async fn events(metrics: Arc<Metrics>) -> anyhow::Result<broadcast::Sender<RawEvent>> {
    let bpf_bytes = include_bytes!(concat!(env!("BPF_PATH")));
    info!("embedded bytes len={}, magic={:02x}{:02x}{:02x}{:02x}",
        bpf_bytes.len(),
        bpf_bytes[0], bpf_bytes[1], bpf_bytes[2], bpf_bytes[3]);
    let mut ebpf = Ebpf::load(bpf_bytes)?;
    info!("BPF object loaded successfully");

    let btf = aya::Btf::from_sys_fs()?;
    info!("BTF loaded from /sys/kernel/btf/vmlinux");

    // Attach fexit for sock_sendmsg — covers all socket types (TCP, UDP, raw, etc.)
    if let Some(prog) = ebpf.program_mut("sock_sendmsg_ret") {
        let fexit: &mut FExit = prog.try_into()?;
        fexit.load("sock_sendmsg", &btf)?;
        fexit.attach()?;
        info!("attached fexit/sock_sendmsg_ret");
    }

    // Attach fexit for sock_recvmsg — covers all socket types
    if let Some(prog) = ebpf.program_mut("sock_recvmsg_ret") {
        let fexit: &mut FExit = prog.try_into()?;
        fexit.load("sock_recvmsg", &btf)?;
        fexit.attach()?;
        info!("attached fexit/sock_recvmsg_ret");
    }

    // Attach kretprobe for execve
    if let Some(prog) = ebpf.program_mut("exec_entry") {
        let kp: &mut KProbe = prog.try_into()?;
        kp.load()?;
        kp.attach("__x64_sys_execve", 0)?;
        info!("attached kretprobe/exec_entry");
    }

    // Attach uprobe/uretprobe for DNS (getaddrinfo in libc)
    let libc_path = _find_libc();
    if let Some(ref libc) = libc_path {
        if let Some(prog) = ebpf.program_mut("dns_entry") {
            let uprobe: &mut UProbe = prog.try_into()?;
            uprobe.load()?;
            uprobe.attach(UProbeAttachLocation::Symbol("getaddrinfo"), libc.as_str(), None)?;
            info!("attached uprobe/dns_entry");
        }

        if let Some(prog) = ebpf.program_mut("dns_return") {
            let uprobe: &mut UProbe = prog.try_into()?;
            uprobe.load()?;
            uprobe.attach(UProbeAttachLocation::Symbol("getaddrinfo"), libc.as_str(), None)?;
            info!("attached uretprobe/dns_return");
        }
    } else {
        warn!("libc not found, DNS tracking disabled");
    }

    // Attach TCP lifecycle hooks
    if let Some(prog) = ebpf.program_mut("tcp_v4_connect_entry") {
        let kp: &mut KProbe = prog.try_into()?;
        kp.load()?;
        kp.attach("tcp_v4_connect", 0)?;
        info!("attached kprobe/tcp_v4_connect_entry");
    }

    if let Some(prog) = ebpf.program_mut("tcp_v4_connect_ret") {
        let kp: &mut KProbe = prog.try_into()?;
        kp.load()?;
        kp.attach("tcp_v4_connect", 0)?;
        info!("attached kretprobe/tcp_v4_connect_ret");
    }

    if let Some(prog) = ebpf.program_mut("inet_csk_accept_ret") {
        let kp: &mut KProbe = prog.try_into()?;
        kp.load()?;
        kp.attach("inet_csk_accept", 0)?;
        info!("attached kretprobe/inet_csk_accept_ret");
    }

    if let Some(prog) = ebpf.program_mut("tcp_close_entry") {
        let kp: &mut KProbe = prog.try_into()?;
        kp.load()?;
        kp.attach("tcp_close", 0)?;
        info!("attached kprobe/tcp_close_entry");
    }

    // Keep ebpf alive with 'static lifetime
    // SAFETY: Box::leak ensures ebpf is never dropped. Required by aya for map lifetimes.
    let ebpf_ptr = Box::leak(Box::new(ebpf));

    let (tx, _) = broadcast::channel::<RawEvent>(4096);

    let cpus = online_cpus()
        .map_err(|e| anyhow::anyhow!("online_cpus failed: {:?}", e))?;
    info!("online CPUs: {}", cpus.len());

    unsafe {
        // SAFETY: ebpf_ptr is Box::leak'd — lives for the process lifetime.
        // open_map is called sequentially (no concurrent &mut aliases).
        // PerfEventArrayBuffer holds an OS FD, not a Rust borrow of Ebpf.
        // ebpf_raw is never captured by spawned tasks — only `buf`, `tx2`,
        // `label`, and `metrics2` move into tasks.
        let ebpf_raw = ebpf_ptr as *mut Ebpf;

        let open_map = |map_name: &str, decoder: fn(&[u8]) -> Option<RawEvent>| -> anyhow::Result<()> {
            let ebpf = &mut *ebpf_raw;
            let map = ebpf
                .map_mut(map_name)
                .ok_or_else(|| anyhow::anyhow!("{} map not found", map_name))?;
            info!("found map {}, converting to PerfEventArray", map_name);
            let mut perf_array = PerfEventArray::try_from(map)?;
            info!("opened perf array for {}", map_name);
            for cpu_id in cpus.clone() {
                let buf = perf_array.open(cpu_id, None)?;
                let tx2 = tx.clone();
                let label = map_name.to_string();
                let metrics2 = metrics.clone();
                tokio::spawn(async move {
                    let mut async_fd = match AsyncFd::new(buf) {
                        Ok(fd) => fd,
                        Err(e) => {
                            tracing::error!("AsyncFd error ({}): {}", label, e);
                            return;
                        }
                    };
                    let mut bufs = (0..10)
                        .map(|_| BytesMut::with_capacity(4096))
                        .collect::<Vec<_>>();
                    loop {
                        let mut guard = match async_fd.readable_mut().await {
                            Ok(g) => g,
                            Err(e) => {
                                tracing::error!("poll error ({}): {}", label, e);
                                break;
                            }
                        };
                        let inner = guard.get_inner_mut();
                        match inner.read_events(&mut bufs) {
                            Ok(events) => {
                                guard.clear_ready();
                                if events.read > 0 || events.lost > 0 {
                                    tracing::debug!("{}: read={} lost={}", label, events.read, events.lost);
                                }
                                for i in 0..events.read {
                                    if let Some(raw) = decoder(&bufs[i]) {
                                        let _ = tx2.send(raw);
                                        metrics2.events_total.fetch_add(1, Ordering::Relaxed);
                                        match label.as_str() {
                                            "SENDMSG_EVENTS" => { metrics2.events_sendv4.fetch_add(1, Ordering::Relaxed); }
                                            "RECVMSG_EVENTS" => { metrics2.events_recvv4.fetch_add(1, Ordering::Relaxed); }
                                            "EXEC_EVENTS"    => { metrics2.events_exec.fetch_add(1, Ordering::Relaxed); }
                                            "DNS_EVENTS" | "DNS6_EVENTS" => { metrics2.events_dns.fetch_add(1, Ordering::Relaxed); }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!("perf read error ({}): {}", label, e);
                                break;
                            }
                        }
                    }
                });
            }
            Ok(())
        };

        open_map("SENDMSG_EVENTS", _decode_sendv4)?;
        open_map("RECVMSG_EVENTS", _decode_recvv4)?;
        open_map("SENDMSG6_EVENTS", _decode_sendv6)?;
        open_map("RECVMSG6_EVENTS", _decode_recvv6)?;
        open_map("EXEC_EVENTS", _decode_exec)?;
        open_map("DNS_EVENTS", _decode_dns)?;
        open_map("DNS6_EVENTS", _decode_dns6)?;
        open_map("CONNECT_EVENTS", _decode_connect)?;
    }

    Ok(tx)
}

// --- Decoders ---

fn _decode_sendv4(buf: &[u8]) -> Option<RawEvent> {
    let sz = core::mem::size_of::<SendRecvEvent>();
    if buf.len() < sz { return None; }
    let e: &SendRecvEvent = bytemuck::try_from_bytes(&buf[..sz]).ok()?;
    Some(RawEvent::SendV4(*e))
}

fn _decode_recvv4(buf: &[u8]) -> Option<RawEvent> {
    let sz = core::mem::size_of::<SendRecvEvent>();
    if buf.len() < sz { return None; }
    let e: &SendRecvEvent = bytemuck::try_from_bytes(&buf[..sz]).ok()?;
    Some(RawEvent::RecvV4(*e))
}

fn _decode_sendv6(buf: &[u8]) -> Option<RawEvent> {
    let sz = core::mem::size_of::<SendRecv6Event>();
    if buf.len() < sz { return None; }
    let e: &SendRecv6Event = bytemuck::try_from_bytes(&buf[..sz]).ok()?;
    Some(RawEvent::SendV6(*e))
}

fn _decode_recvv6(buf: &[u8]) -> Option<RawEvent> {
    let sz = core::mem::size_of::<SendRecv6Event>();
    if buf.len() < sz { return None; }
    let e: &SendRecv6Event = bytemuck::try_from_bytes(&buf[..sz]).ok()?;
    Some(RawEvent::RecvV6(*e))
}

fn _decode_exec(buf: &[u8]) -> Option<RawEvent> {
    let sz = core::mem::size_of::<ExecEvent>();
    if buf.len() < sz { return None; }
    let e: &ExecEvent = bytemuck::try_from_bytes(&buf[..sz]).ok()?;
    Some(RawEvent::Exec(*e))
}

fn _decode_dns(buf: &[u8]) -> Option<RawEvent> {
    let sz = core::mem::size_of::<DnsEvent>();
    if buf.len() < sz { return None; }
    let e: &DnsEvent = bytemuck::try_from_bytes(&buf[..sz]).ok()?;
    Some(RawEvent::Dns(*e))
}

fn _decode_dns6(buf: &[u8]) -> Option<RawEvent> {
    let sz = core::mem::size_of::<DnsEvent6>();
    if buf.len() < sz { return None; }
    let e: &DnsEvent6 = bytemuck::try_from_bytes(&buf[..sz]).ok()?;
    Some(RawEvent::Dns6(*e))
}

fn _decode_connect(buf: &[u8]) -> Option<RawEvent> {
    let sz = core::mem::size_of::<ConnectEventRaw>();
    if buf.len() < sz { return None; }
    let e: &ConnectEventRaw = bytemuck::try_from_bytes(&buf[..sz]).ok()?;
    Some(RawEvent::Connect(*e))
}

/// Find libc.so path on Debian.
fn _find_libc() -> Option<String> {
    let candidates = [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/lib/libc.so.6",
    ];
    for path in &candidates {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    None
}

/// Initialize fanotify for executable file modification tracking.
pub fn init_fanotify() -> Result<i32, Box<dyn std::error::Error>> {
    unsafe {
        let fd = libc::syscall(
            libc::SYS_fanotify_init,
            libc::FAN_CLASS_NOTIF | libc::FAN_NONBLOCK,
            libc::O_RDONLY | libc::O_CLOEXEC,
        ) as i32;

        if fd < 0 {
            return Err(format!("fanotify_init failed: {}", std::io::Error::last_os_error()).into());
        }

        // Mark filesystem root for FAN_MODIFY events
        let ret = libc::syscall(
            libc::SYS_fanotify_mark,
            fd,
            libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
            libc::FAN_MODIFY as u64,
            libc::AT_FDCWD,
            b"/\0".as_ptr(),
        ) as i32;

        if ret < 0 {
            warn!("fanotify_mark failed: {}", std::io::Error::last_os_error());
        }

        Ok(fd)
    }
}
