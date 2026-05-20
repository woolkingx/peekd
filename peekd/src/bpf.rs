#![allow(dead_code, unused_imports)]

//! bpf.rs: libbpf program loader and kernel event source.
//!
//! Loads the libbpf-cargo generated skeleton, attaches probes, and polls perf
//! buffers. Kernel requirements: Linux >= 5.8, CONFIG_DEBUG_INFO_BTF=y.

use std::mem::MaybeUninit;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use crate::metrics::Metrics;
use crate::types::RawEvent;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{ErrorKind, Link, MapCore, PerfBuffer, PerfBufferBuilder, UprobeOpts};
use peekd_common::{
    BpfStatEvent, ConnectEventRaw, DnsEvent, DnsEvent6, ExecEvent, SendRecv6Event, SendRecvEvent,
};
use tokio::sync::broadcast;
use tracing::{info, warn};

mod peekd_bpf {
    include!(env!("PEEKD_BPF_SKEL"));
}

use peekd_bpf::*;

/// Load BPF object, attach all programs, spawn perf readers.
///
/// Returns broadcast channel sender for RawEvent variants from perf buffers.
pub async fn events(
    metrics: Arc<Metrics>,
    perf_ring_buffer_pages: u32,
) -> anyhow::Result<broadcast::Sender<RawEvent>> {
    let open_object = Box::leak(Box::new(MaybeUninit::uninit()));
    let open_skel = PeekdSkelBuilder::default().open(open_object)?;
    let mut skel = open_skel.load()?;

    let links = attach_programs(&mut skel)?;
    let _links = Box::leak(Box::new(links));
    let skel = Box::leak(Box::new(skel));
    info!("libbpf BPF object loaded and programs attached");

    let (tx, _) = broadcast::channel::<RawEvent>(4096);
    let pages = perf_ring_buffer_pages as usize;

    spawn_perf_reader(
        build_perf_buffer(
            &skel.maps.sendmsg_events,
            "SENDMSG_EVENTS",
            _decode_sendv4,
            tx.clone(),
            metrics.clone(),
            pages,
        )?,
        "SENDMSG_EVENTS",
    );
    spawn_perf_reader(
        build_perf_buffer(
            &skel.maps.recvmsg_events,
            "RECVMSG_EVENTS",
            _decode_recvv4,
            tx.clone(),
            metrics.clone(),
            pages,
        )?,
        "RECVMSG_EVENTS",
    );
    spawn_perf_reader(
        build_perf_buffer(
            &skel.maps.sendmsg6_events,
            "SENDMSG6_EVENTS",
            _decode_sendv6,
            tx.clone(),
            metrics.clone(),
            pages,
        )?,
        "SENDMSG6_EVENTS",
    );
    spawn_perf_reader(
        build_perf_buffer(
            &skel.maps.recvmsg6_events,
            "RECVMSG6_EVENTS",
            _decode_recvv6,
            tx.clone(),
            metrics.clone(),
            pages,
        )?,
        "RECVMSG6_EVENTS",
    );
    spawn_perf_reader(
        build_perf_buffer(
            &skel.maps.exec_events,
            "EXEC_EVENTS",
            _decode_exec,
            tx.clone(),
            metrics.clone(),
            pages,
        )?,
        "EXEC_EVENTS",
    );
    spawn_perf_reader(
        build_perf_buffer(
            &skel.maps.dns_events,
            "DNS_EVENTS",
            _decode_dns,
            tx.clone(),
            metrics.clone(),
            pages,
        )?,
        "DNS_EVENTS",
    );
    spawn_perf_reader(
        build_perf_buffer(
            &skel.maps.dns6_events,
            "DNS6_EVENTS",
            _decode_dns6,
            tx.clone(),
            metrics.clone(),
            pages,
        )?,
        "DNS6_EVENTS",
    );
    spawn_perf_reader(
        build_perf_buffer(
            &skel.maps.bpf_stats_events,
            "BPF_STATS_EVENTS",
            _decode_bpf_stat,
            tx.clone(),
            metrics.clone(),
            pages,
        )?,
        "BPF_STATS_EVENTS",
    );
    spawn_perf_reader(
        build_perf_buffer(
            &skel.maps.connect_events,
            "CONNECT_EVENTS",
            _decode_connect,
            tx.clone(),
            metrics.clone(),
            pages,
        )?,
        "CONNECT_EVENTS",
    );

    Ok(tx)
}

fn attach_programs(skel: &mut PeekdSkel<'_>) -> anyhow::Result<Vec<Link>> {
    let mut links = attach_send_recv_programs(skel)?;
    links.extend([
        skel.progs
            .exec_entry
            .attach_kprobe(true, "__x64_sys_execve")?,
        skel.progs
            .tcp_v4_connect_entry
            .attach_kprobe(false, "tcp_v4_connect")?,
        skel.progs
            .tcp_v4_connect_ret
            .attach_kprobe(true, "tcp_v4_connect")?,
        skel.progs
            .inet_csk_accept_ret
            .attach_kprobe(true, "inet_csk_accept")?,
        skel.progs
            .tcp_close_entry
            .attach_kprobe(false, "tcp_close")?,
    ]);

    if let Some(libc) = _find_libc() {
        links.extend(attach_getaddrinfo_uprobes(skel, libc.as_str())?);
    } else {
        warn!("libc not found, DNS getaddrinfo tracking disabled");
    }

    Ok(links)
}

fn attach_send_recv_programs(skel: &mut PeekdSkel<'_>) -> anyhow::Result<Vec<Link>> {
    let mut links = attach_send_programs(skel)?;
    links.extend(attach_recv_programs(skel)?);
    Ok(links)
}

fn attach_send_programs(skel: &mut PeekdSkel<'_>) -> anyhow::Result<Vec<Link>> {
    match attach_tcp_send_programs(skel) {
        Ok(links) => {
            info!("attached send probe at tcp_sendmsg");
            Ok(links)
        }
        Err(err) if should_fallback_send_recv(&err) => {
            warn!(
                "tcp_sendmsg probe unavailable: {}; falling back to sock_sendmsg",
                err
            );
            match attach_sock_send_programs(skel) {
                Ok(links) => {
                    info!("attached send probe at sock_sendmsg fallback");
                    Ok(links)
                }
                Err(err) if should_fallback_send_recv(&err) => {
                    warn!(
                        "sock_sendmsg probe unavailable: {}; falling back to inet_sendmsg",
                        err
                    );
                    let links = attach_inet_send_programs(skel)?;
                    info!("attached send probe at inet_sendmsg fallback");
                    Ok(links)
                }
                Err(err) => Err(err.into()),
            }
        }
        Err(err) => Err(err.into()),
    }
}

fn attach_recv_programs(skel: &mut PeekdSkel<'_>) -> anyhow::Result<Vec<Link>> {
    match attach_sock_recv_programs(skel) {
        Ok(links) => {
            info!("attached recv probe at sock_recvmsg");
            Ok(links)
        }
        Err(err) if should_fallback_send_recv(&err) => {
            warn!(
                "sock_recvmsg probe unavailable: {}; falling back to inet_recvmsg",
                err
            );
            let links = attach_inet_recv_programs(skel)?;
            info!("attached recv probe at inet_recvmsg fallback");
            Ok(links)
        }
        Err(err) => Err(err.into()),
    }
}

fn attach_tcp_send_programs(skel: &mut PeekdSkel<'_>) -> libbpf_rs::Result<Vec<Link>> {
    Ok(vec![
        skel.progs
            .tcp_sendmsg_entry
            .attach_kprobe(false, "tcp_sendmsg")?,
        skel.progs
            .tcp_sendmsg_ret
            .attach_kprobe(true, "tcp_sendmsg")?,
    ])
}

fn attach_sock_send_programs(skel: &mut PeekdSkel<'_>) -> libbpf_rs::Result<Vec<Link>> {
    Ok(vec![
        skel.progs
            .sock_sendmsg_entry
            .attach_kprobe(false, "sock_sendmsg")?,
        skel.progs
            .sock_sendmsg_ret
            .attach_kprobe(true, "sock_sendmsg")?,
    ])
}

fn attach_sock_recv_programs(skel: &mut PeekdSkel<'_>) -> libbpf_rs::Result<Vec<Link>> {
    Ok(vec![
        skel.progs
            .sock_recvmsg_entry
            .attach_kprobe(false, "sock_recvmsg")?,
        skel.progs
            .sock_recvmsg_ret
            .attach_kprobe(true, "sock_recvmsg")?,
    ])
}

fn attach_inet_send_programs(skel: &mut PeekdSkel<'_>) -> libbpf_rs::Result<Vec<Link>> {
    Ok(vec![
        skel.progs
            .inet_sendmsg_entry
            .attach_kprobe(false, "inet_sendmsg")?,
        skel.progs
            .inet_sendmsg_ret
            .attach_kprobe(true, "inet_sendmsg")?,
    ])
}

fn attach_inet_recv_programs(skel: &mut PeekdSkel<'_>) -> libbpf_rs::Result<Vec<Link>> {
    Ok(vec![
        skel.progs
            .inet_recvmsg_entry
            .attach_kprobe(false, "inet_recvmsg")?,
        skel.progs
            .inet_recvmsg_ret
            .attach_kprobe(true, "inet_recvmsg")?,
    ])
}

fn should_fallback_send_recv(err: &libbpf_rs::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::NotFound | ErrorKind::InvalidInput | ErrorKind::Unsupported
    )
}

fn attach_getaddrinfo_uprobes(skel: &mut PeekdSkel<'_>, libc: &str) -> anyhow::Result<Vec<Link>> {
    match attach_getaddrinfo_uprobe_multi(skel, libc) {
        Ok(links) => {
            info!("attached getaddrinfo with uprobe_multi at {}", libc);
            Ok(links)
        }
        Err(err) if should_fallback_uprobe_multi(&err) => {
            warn!(
                "uprobe_multi getaddrinfo attach unavailable at {}: {}; falling back to single uprobe",
                libc, err
            );
            let links = attach_getaddrinfo_single_uprobes(skel, libc)?;
            warn!(
                "attached getaddrinfo with single uprobe/uretprobe at {}",
                libc
            );
            Ok(links)
        }
        Err(err) => Err(err.into()),
    }
}

fn attach_getaddrinfo_uprobe_multi(
    skel: &mut PeekdSkel<'_>,
    libc: &str,
) -> libbpf_rs::Result<Vec<Link>> {
    let entry = skel
        .progs
        .dns_entry
        .attach_uprobe_multi(-1, libc, "getaddrinfo", false, false)?;
    let ret = skel
        .progs
        .dns_return
        .attach_uprobe_multi(-1, libc, "getaddrinfo", true, false)?;
    Ok(vec![entry, ret])
}

fn attach_getaddrinfo_single_uprobes(
    skel: &mut PeekdSkel<'_>,
    libc: &str,
) -> anyhow::Result<Vec<Link>> {
    let entry = skel.progs.dns_entry.attach_uprobe_with_opts(
        -1,
        libc,
        0,
        getaddrinfo_uprobe_opts(false),
    )?;
    let ret = skel.progs.dns_return.attach_uprobe_with_opts(
        -1,
        libc,
        0,
        getaddrinfo_uprobe_opts(true),
    )?;
    Ok(vec![entry, ret])
}

fn getaddrinfo_uprobe_opts(retprobe: bool) -> UprobeOpts {
    UprobeOpts {
        retprobe,
        func_name: Some("getaddrinfo".to_string()),
        ..Default::default()
    }
}

fn should_fallback_uprobe_multi(err: &libbpf_rs::Error) -> bool {
    matches!(err.kind(), ErrorKind::InvalidInput | ErrorKind::Unsupported)
}

fn build_perf_buffer<M>(
    map: &'static M,
    label: &'static str,
    decoder: fn(&[u8]) -> Option<RawEvent>,
    tx: broadcast::Sender<RawEvent>,
    metrics: Arc<Metrics>,
    pages: usize,
) -> anyhow::Result<PerfBuffer<'static>>
where
    M: MapCore,
{
    let sample_metrics = metrics.clone();
    let lost_metrics = metrics.clone();
    Ok(PerfBufferBuilder::new(map)
        .pages(pages)
        .sample_cb(move |_cpu, data| {
            handle_sample(label, data, decoder, &tx, &sample_metrics);
        })
        .lost_cb(move |_cpu, lost| {
            lost_metrics.record_perf_loss(label, lost);
        })
        .build()?)
}

fn spawn_perf_reader(perf: PerfBuffer<'static>, label: &'static str) {
    std::thread::spawn(move || loop {
        if let Err(err) = perf.poll(Duration::from_millis(100)) {
            tracing::error!("perf poll error ({}): {}", label, err);
            break;
        }
    });
}

fn handle_sample(
    label: &str,
    data: &[u8],
    decoder: fn(&[u8]) -> Option<RawEvent>,
    tx: &broadcast::Sender<RawEvent>,
    metrics: &Metrics,
) {
    let Some(raw) = decoder(data) else {
        metrics.decoder_failures.fetch_add(1, Ordering::Relaxed);
        return;
    };
    if let RawEvent::BpfStat(stat) = raw {
        metrics.record_bpf_stat(stat.kind);
        return;
    }
    let _ = tx.send(raw);
    metrics.events_total.fetch_add(1, Ordering::Relaxed);
    match label {
        "SENDMSG_EVENTS" => {
            metrics.events_sendv4.fetch_add(1, Ordering::Relaxed);
        }
        "RECVMSG_EVENTS" => {
            metrics.events_recvv4.fetch_add(1, Ordering::Relaxed);
        }
        "SENDMSG6_EVENTS" => {
            metrics.events_sendv6.fetch_add(1, Ordering::Relaxed);
        }
        "RECVMSG6_EVENTS" => {
            metrics.events_recvv6.fetch_add(1, Ordering::Relaxed);
        }
        "EXEC_EVENTS" => {
            metrics.events_exec.fetch_add(1, Ordering::Relaxed);
        }
        "DNS_EVENTS" | "DNS6_EVENTS" => {
            metrics.events_dns.fetch_add(1, Ordering::Relaxed);
        }
        "CONNECT_EVENTS" => {
            metrics.events_connect.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
}

// --- Decoders ---

fn _decode_sendv4(buf: &[u8]) -> Option<RawEvent> {
    let sz = core::mem::size_of::<SendRecvEvent>();
    if buf.len() < sz {
        return None;
    }
    Some(RawEvent::SendV4(bytemuck::pod_read_unaligned(&buf[..sz])))
}

fn _decode_recvv4(buf: &[u8]) -> Option<RawEvent> {
    let sz = core::mem::size_of::<SendRecvEvent>();
    if buf.len() < sz {
        return None;
    }
    Some(RawEvent::RecvV4(bytemuck::pod_read_unaligned(&buf[..sz])))
}

fn _decode_sendv6(buf: &[u8]) -> Option<RawEvent> {
    let sz = core::mem::size_of::<SendRecv6Event>();
    if buf.len() < sz {
        return None;
    }
    Some(RawEvent::SendV6(bytemuck::pod_read_unaligned(&buf[..sz])))
}

fn _decode_recvv6(buf: &[u8]) -> Option<RawEvent> {
    let sz = core::mem::size_of::<SendRecv6Event>();
    if buf.len() < sz {
        return None;
    }
    Some(RawEvent::RecvV6(bytemuck::pod_read_unaligned(&buf[..sz])))
}

fn _decode_exec(buf: &[u8]) -> Option<RawEvent> {
    let sz = core::mem::size_of::<ExecEvent>();
    if buf.len() < sz {
        return None;
    }
    Some(RawEvent::Exec(bytemuck::pod_read_unaligned(&buf[..sz])))
}

fn _decode_dns(buf: &[u8]) -> Option<RawEvent> {
    let sz = core::mem::size_of::<DnsEvent>();
    if buf.len() < sz {
        return None;
    }
    Some(RawEvent::Dns(bytemuck::pod_read_unaligned(&buf[..sz])))
}

fn _decode_dns6(buf: &[u8]) -> Option<RawEvent> {
    let sz = core::mem::size_of::<DnsEvent6>();
    if buf.len() < sz {
        return None;
    }
    Some(RawEvent::Dns6(bytemuck::pod_read_unaligned(&buf[..sz])))
}

fn _decode_connect(buf: &[u8]) -> Option<RawEvent> {
    let sz = core::mem::size_of::<ConnectEventRaw>();
    if buf.len() < sz {
        return None;
    }
    Some(RawEvent::Connect(bytemuck::pod_read_unaligned(&buf[..sz])))
}

fn _decode_bpf_stat(buf: &[u8]) -> Option<RawEvent> {
    let sz = core::mem::size_of::<BpfStatEvent>();
    if buf.len() < sz {
        return None;
    }
    Some(RawEvent::BpfStat(bytemuck::pod_read_unaligned(&buf[..sz])))
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
            return Err(
                format!("fanotify_init failed: {}", std::io::Error::last_os_error()).into(),
            );
        }

        let ret = libc::syscall(
            libc::SYS_fanotify_mark,
            fd,
            libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
            libc::FAN_MODIFY,
            libc::AT_FDCWD,
            c"/".as_ptr(),
        ) as i32;

        if ret < 0 {
            warn!("fanotify_mark failed: {}", std::io::Error::last_os_error());
        }

        Ok(fd)
    }
}

#[cfg(test)]
mod tests_bpf {
    use super::*;

    #[test]
    fn uprobe_multi_fallback_is_limited_to_kernel_feature_errors() {
        let invalid = libbpf_rs::Error::from_raw_os_error(libc::EINVAL);
        let denied = libbpf_rs::Error::from_raw_os_error(libc::EPERM);

        assert!(should_fallback_uprobe_multi(&invalid));
        assert!(!should_fallback_uprobe_multi(&denied));
    }

    #[test]
    fn send_recv_fallback_is_limited_to_attach_compatibility_errors() {
        let missing = libbpf_rs::Error::from_raw_os_error(libc::ENOENT);
        let invalid = libbpf_rs::Error::from_raw_os_error(libc::EINVAL);
        let denied = libbpf_rs::Error::from_raw_os_error(libc::EPERM);

        assert!(should_fallback_send_recv(&missing));
        assert!(should_fallback_send_recv(&invalid));
        assert!(!should_fallback_send_recv(&denied));
    }
}
