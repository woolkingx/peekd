#![no_std]
#![no_main]
#![allow(dead_code, unused_imports)]

//! peekd-ebpf: Kernel BPF programs for network event capture.
//!
//! BPF LLVM restriction: helper functions cannot return aggregates (Result/tuple/enum).
//! All helpers return i64 (0=ok, negative=error) and write via out-pointers.
//!
//! Hook points:
//! - kprobe+kretprobe/tcp_sendmsg — TCP send bytes (BCC tcptop pattern)
//! - fexit/sock_recvmsg — network recv (IPv4 + IPv6)
//! - kretprobe/__x64_sys_execve — process execution
//! - uprobe/uretprobe on libc getaddrinfo — DNS resolution
//! - kprobe/kretprobe for TCP connect, accept, close — connection lifecycle

use aya_ebpf::macros::{fexit, kprobe, kretprobe, uprobe, uretprobe};
use aya_ebpf::programs::{FExitContext, ProbeContext, RetProbeContext};
use aya_ebpf::helpers::{
    bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
    bpf_probe_read_kernel, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
};

mod bindings;
mod events;
mod maps;
mod socket_util;
mod process_util;

use events::*;
use maps::*;
use socket_util::*;
use process_util::*;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

// ============================================================================
// fexit/sock_sendmsg — capture ALL send bytes (TCP, UDP, raw, broadcast, etc.)
// Symmetric with fexit/sock_recvmsg. Covers every socket type via single hook.
// arg(0) = struct socket*, arg(3) = int ret
// ============================================================================

#[fexit(function = "sock_sendmsg")]
pub fn sock_sendmsg_ret(ctx: FExitContext) -> i32 {
    unsafe { _sock_sendmsg_ret(&ctx) };
    0
}

unsafe fn _sock_sendmsg_ret(ctx: &FExitContext) {
    let ret: i32 = ctx.arg(2);  // sock_sendmsg(socket*, msghdr*) — 2 params, ret = arg(2)
    if ret <= 0 { return; }
    let bytes = ret as u32;
    let sock_ptr: *const u8 = ctx.arg(0);
    let family = read_socket_family(sock_ptr);
    if family == 2 { _emit_sendrecv_v4(ctx, sock_ptr, bytes, true); }
    else if family == 10 { _emit_sendrecv_v6(ctx, sock_ptr, bytes, true); }
}

// ============================================================================
// fexit/sock_recvmsg
// ============================================================================

#[fexit(function = "sock_recvmsg")]
pub fn sock_recvmsg_ret(ctx: FExitContext) -> i32 {
    unsafe { _sock_recvmsg_ret(&ctx) };
    0
}

unsafe fn _sock_recvmsg_ret(ctx: &FExitContext) {
    let ret: i32 = ctx.arg(3);  // kernel returns int; zero-extend would corrupt sign
    if ret <= 0 { return; }
    let bytes = ret as u32;
    let sock_ptr: *const u8 = ctx.arg(0);
    let family = read_socket_family(sock_ptr);
    if family == 2 { _emit_sendrecv_v4(ctx, sock_ptr, bytes, false); }
    else if family == 10 { _emit_sendrecv_v6(ctx, sock_ptr, bytes, false); }
}

// ============================================================================
// kretprobe/__x64_sys_execve
// ============================================================================

#[kretprobe]
pub fn exec_entry(ctx: RetProbeContext) -> u32 {
    unsafe { _execve_entry(&ctx) };
    0
}

unsafe fn _execve_entry(ctx: &RetProbeContext) {
    let ret: i32 = ctx.ret();
    if ret != 0 { return; }

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let mut event = ExecEvent::zeroed();
    event.pid = pid_tgid as u32;
    event.uid = uid_gid as u32;

    read_current_task_comm(&mut event.comm);

    let mut dev: u32 = 0; let mut ino: u64 = 0;
    read_current_task_inode(&mut dev, &mut ino);
    event.dev = dev as u64; event.ino = ino;

    let mut ppid: u32 = 0; let mut pdev: u32 = 0; let mut pino: u64 = 0;
    read_parent_process_info(&mut ppid, &mut pdev, &mut pino);
    event.ppid = ppid; event.pdev = pdev as u64; event.pino = pino;

    read_parent_task_comm(&mut event.pcomm);

    EXEC_EVENTS.output(ctx, &event, 0);
}

// ============================================================================
// uprobe/uretprobe — getaddrinfo DNS capture
// ============================================================================

#[uprobe]
pub fn dns_entry(ctx: ProbeContext) -> u32 {
    unsafe { _getaddrinfo_entry(&ctx) };
    0
}

unsafe fn _getaddrinfo_entry(ctx: &ProbeContext) {
    let pid_tgid = bpf_get_current_pid_tgid();

    let nodename_ptr: *const u8 = match ctx.arg(0) { Some(v) => v, None => return };
    let res_ptr: *const u8 = ctx.arg::<*const u8>(3).unwrap_or(core::ptr::null());

    let dns_arg = DnsArg { nodename_ptr, results_ptr: res_ptr as *mut () };
    let _ = DNS_ARGS.insert(&pid_tgid, &dns_arg, 0);
}

#[uretprobe]
pub fn dns_return(ctx: RetProbeContext) -> u32 {
    unsafe { _getaddrinfo_return(&ctx) };
    0
}

unsafe fn _getaddrinfo_return(ctx: &RetProbeContext) {
    let ret: i32 = ctx.ret();
    if ret != 0 { return; }

    let pid_tgid = bpf_get_current_pid_tgid();

    let dns_arg = match DNS_ARGS.get(&pid_tgid) { Some(a) => *a, None => return };

    let mut current: *const u8 = core::ptr::null();
    if !dns_arg.results_ptr.is_null() {
        current = bpf_probe_read_user(dns_arg.results_ptr as *const *const u8).unwrap_or(core::ptr::null());
    }

    let pid = pid_tgid as u32;
    // Manual unroll: 8 iterations (BPF verifier cannot handle loops)
    _dns_walk_one(ctx, pid, &dns_arg, &mut current);
    _dns_walk_one(ctx, pid, &dns_arg, &mut current);
    _dns_walk_one(ctx, pid, &dns_arg, &mut current);
    _dns_walk_one(ctx, pid, &dns_arg, &mut current);
    _dns_walk_one(ctx, pid, &dns_arg, &mut current);
    _dns_walk_one(ctx, pid, &dns_arg, &mut current);
    _dns_walk_one(ctx, pid, &dns_arg, &mut current);
    _dns_walk_one(ctx, pid, &dns_arg, &mut current);

    let _ = DNS_ARGS.remove(&pid_tgid);
}

/// Walk one addrinfo node (userspace struct — use bpf_probe_read_user).
/// Returns void — no aggregate return.
unsafe fn _dns_walk_one(
    ctx: &RetProbeContext,
    pid: u32,
    dns_arg: &DnsArg,
    current: &mut *const u8,
) {
    if (*current).is_null() { return; }

    // x86_64 glibc struct addrinfo layout:
    // ai_flags(0) ai_family(4) ai_socktype(8) ai_protocol(12) ai_addrlen(16) pad(20) ai_addr(24) ai_canonname(32) ai_next(40)
    let ai_family: i32 = bpf_probe_read_user((*current).add(4) as *const i32).unwrap_or(0);
    let ai_addr: *const u8 = bpf_probe_read_user((*current).add(24) as *const *const u8).unwrap_or(core::ptr::null());
    let ai_next: *const u8 = bpf_probe_read_user((*current).add(40) as *const *const u8).unwrap_or(core::ptr::null());

    if ai_family == 2 && !ai_addr.is_null() { // AF_INET
        let daddr: u32 = bpf_probe_read_user(ai_addr.add(4) as *const u32).unwrap_or(0);
        let dport: u16 = bpf_probe_read_user(ai_addr.add(2) as *const u16).unwrap_or(0);
        if daddr != 0 {
            // Use per-CPU scratch to avoid 272-byte stack allocation
            if let Some(event) = DNS_SCRATCH.get_ptr_mut(0) {
                (*event).pid = pid; (*event).daddr = daddr; (*event).dport = dport;
                (*event).saddr = 0; (*event).sport = 0;
                if !dns_arg.nodename_ptr.is_null() {
                    let _ = bpf_probe_read_user_str_bytes(dns_arg.nodename_ptr, &mut (*event).name);
                }
                DNS_EVENTS.output(ctx, &*event, 0);
            }
        }
    } else if ai_family == 10 && !ai_addr.is_null() { // AF_INET6
        let dport: u16 = bpf_probe_read_user(ai_addr.add(2) as *const u16).unwrap_or(0);
        let daddr: u128 = bpf_probe_read_user(ai_addr.add(8) as *const u128).unwrap_or(0);
        if daddr != 0 {
            // Use per-CPU scratch to avoid 296-byte stack allocation
            if let Some(event) = DNS6_SCRATCH.get_ptr_mut(0) {
                (*event).pid = pid; (*event).daddr = daddr; (*event).dport = dport;
                (*event).saddr = 0; (*event).sport = 0;
                if !dns_arg.nodename_ptr.is_null() {
                    let _ = bpf_probe_read_user_str_bytes(dns_arg.nodename_ptr, &mut (*event).name);
                }
                DNS6_EVENTS.output(ctx, &*event, 0);
            }
        }
    }

    *current = ai_next;
}

// ============================================================================
// TCP connection lifecycle
// ============================================================================

/// kprobe entry: stash sock ptr for G5 fix (IP/port all-zero at kretprobe)
#[kprobe]
pub fn tcp_v4_connect_entry(ctx: ProbeContext) -> u32 {
    if let Some(sk) = ctx.arg::<*const u8>(0) {
        if !sk.is_null() {
            let pid_tgid = bpf_get_current_pid_tgid();
            let _ = TCP_CONNECT_ARGS.insert(&pid_tgid, &(sk as u64), 0);
        }
    }
    0
}

#[kretprobe]
pub fn tcp_v4_connect_ret(ctx: RetProbeContext) -> u32 {
    unsafe { _tcp_connect_ret(&ctx, 0) };
    0
}

#[kretprobe]
pub fn inet_csk_accept_ret(ctx: RetProbeContext) -> u32 {
    unsafe { _tcp_accept_ret(&ctx) };
    0
}

#[kprobe]
pub fn tcp_close_entry(ctx: ProbeContext) -> u32 {
    unsafe { _tcp_close(&ctx) };
    0
}

unsafe fn _tcp_connect_ret(ctx: &RetProbeContext, direction: u8) {
    let ret: i32 = ctx.ret();
    let pid_tgid = bpf_get_current_pid_tgid();
    let sk_u64 = TCP_CONNECT_ARGS.get(&pid_tgid).map(|v| *v).unwrap_or(0);
    let _ = TCP_CONNECT_ARGS.remove(&pid_tgid);
    if ret != 0 || sk_u64 == 0 { return; }

    let sk = sk_u64 as *const u8;
    if read_sk_family(sk) != 2 { return; } // ConnectEventRaw only holds IPv4 addrs
    let uid_gid = bpf_get_current_uid_gid();

    let mut event = peekd_common::ConnectEventRaw {
        comm: [0u8; 16], pcomm: [0u8; 16],
        ino: 0, pino: 0,
        pid: pid_tgid as u32, ppid: 0, uid: uid_gid as u32,
        dev: 0, pdev: 0,
        saddr: 0, daddr: 0, sport: 0, dport: 0,
        direction, event_type: 0, _pad: [0u8; 2],
    };

    read_current_task_comm(&mut event.comm);

    let mut dev: u32 = 0; let mut ino: u64 = 0;
    read_current_task_inode(&mut dev, &mut ino);
    event.dev = dev; event.ino = ino;

    let mut ppid: u32 = 0; let mut pdev: u32 = 0; let mut pino: u64 = 0;
    read_parent_process_info(&mut ppid, &mut pdev, &mut pino);
    event.ppid = ppid; event.pdev = pdev; event.pino = pino;
    read_parent_task_comm(&mut event.pcomm);

    event.saddr = bpf_probe_read_kernel(sk.add(SK_SKC_RCV_SADDR_OFFSET) as *const u32).unwrap_or(0);
    event.daddr = bpf_probe_read_kernel(sk.add(SK_SKC_DADDR_OFFSET) as *const u32).unwrap_or(0);
    event.sport = bpf_probe_read_kernel(sk.add(SK_SKC_NUM_OFFSET) as *const u16).unwrap_or(0);
    event.dport = u16::from_be(bpf_probe_read_kernel(sk.add(SK_SKC_DPORT_OFFSET) as *const u16).unwrap_or(0));

    CONNECT_EVENTS.output(ctx, &event, 0);
}

unsafe fn _tcp_accept_ret(ctx: &RetProbeContext) {
    let sk: *const u8 = ctx.ret();
    if sk.is_null() { return; }
    if read_sk_family(sk) != 2 { return; } // ConnectEventRaw only holds IPv4 addrs

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let mut event = peekd_common::ConnectEventRaw {
        comm: [0u8; 16], pcomm: [0u8; 16],
        ino: 0, pino: 0,
        pid: pid_tgid as u32, ppid: 0, uid: uid_gid as u32,
        dev: 0, pdev: 0,
        saddr: 0, daddr: 0, sport: 0, dport: 0,
        direction: 1, event_type: 0, _pad: [0u8; 2],
    };

    read_current_task_comm(&mut event.comm);
    event.saddr = bpf_probe_read_kernel(sk.add(SK_SKC_RCV_SADDR_OFFSET) as *const u32).unwrap_or(0);
    event.daddr = bpf_probe_read_kernel(sk.add(SK_SKC_DADDR_OFFSET) as *const u32).unwrap_or(0);
    event.sport = bpf_probe_read_kernel(sk.add(SK_SKC_NUM_OFFSET) as *const u16).unwrap_or(0);
    event.dport = u16::from_be(bpf_probe_read_kernel(sk.add(SK_SKC_DPORT_OFFSET) as *const u16).unwrap_or(0));

    CONNECT_EVENTS.output(ctx, &event, 0);
}

unsafe fn _tcp_close(ctx: &ProbeContext) {
    let sk: *const u8 = match ctx.arg(0) { Some(v) => v, None => return };
    if sk.is_null() { return; }

    // ConnectEventRaw only has u32 addr fields — skip IPv6 sockets
    let family = read_sk_family(sk);
    if family != 2 { return; }

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let mut event = peekd_common::ConnectEventRaw {
        comm: [0u8; 16], pcomm: [0u8; 16],
        ino: 0, pino: 0,
        pid: pid_tgid as u32, ppid: 0, uid: uid_gid as u32,
        dev: 0, pdev: 0,
        saddr: 0, daddr: 0, sport: 0, dport: 0,
        direction: 0, event_type: 1, _pad: [0u8; 2],
    };

    read_current_task_comm(&mut event.comm);
    event.saddr = bpf_probe_read_kernel(sk.add(SK_SKC_RCV_SADDR_OFFSET) as *const u32).unwrap_or(0);
    event.daddr = bpf_probe_read_kernel(sk.add(SK_SKC_DADDR_OFFSET) as *const u32).unwrap_or(0);
    event.sport = bpf_probe_read_kernel(sk.add(SK_SKC_NUM_OFFSET) as *const u16).unwrap_or(0);
    event.dport = u16::from_be(bpf_probe_read_kernel(sk.add(SK_SKC_DPORT_OFFSET) as *const u16).unwrap_or(0));

    CONNECT_EVENTS.output(ctx, &event, 0);
}

// ============================================================================
// Emit helpers — void return, no aggregates
// ============================================================================

unsafe fn _emit_sendrecv_v4(ctx: &FExitContext, sock_ptr: *const u8, bytes: u32, is_send: bool) {
    let mut event = SendRecvEvent::zeroed();

    read_current_task_comm(&mut event.comm);

    let mut dev: u32 = 0; let mut ino: u64 = 0;
    read_current_task_inode(&mut dev, &mut ino);
    event.dev = dev as u64; event.ino = ino;

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    event.pid = pid_tgid as u32; event.uid = uid_gid as u32;

    let mut ppid: u32 = 0; let mut pdev: u32 = 0; let mut pino: u64 = 0;
    read_parent_process_info(&mut ppid, &mut pdev, &mut pino);
    event.ppid = ppid; event.pdev = pdev as u64; event.pino = pino;
    read_parent_task_comm(&mut event.pcomm);

    let mut saddr: u32 = 0; let mut daddr: u32 = 0;
    let mut sport: u16 = 0; let mut dport: u16 = 0;
    read_socket_addrs_v4(sock_ptr, &mut saddr, &mut daddr, &mut sport, &mut dport);
    event.saddr = saddr; event.daddr = daddr; event.sport = sport; event.dport = dport;

    event.bytes = bytes as u64;
    event.direction = if is_send { DIRECTION_SEND } else { DIRECTION_RECV };

    if is_send {
        SENDMSG_EVENTS.output(ctx, &event, 0);
    } else {
        RECVMSG_EVENTS.output(ctx, &event, 0);
    }
}

unsafe fn _emit_sendrecv_v6(ctx: &FExitContext, sock_ptr: *const u8, bytes: u32, is_send: bool) {
    let mut event = SendRecv6Event::zeroed();

    read_current_task_comm(&mut event.comm);

    let mut dev: u32 = 0; let mut ino: u64 = 0;
    read_current_task_inode(&mut dev, &mut ino);
    event.dev = dev as u64; event.ino = ino;

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    event.pid = pid_tgid as u32; event.uid = uid_gid as u32;

    let mut ppid: u32 = 0; let mut pdev: u32 = 0; let mut pino: u64 = 0;
    read_parent_process_info(&mut ppid, &mut pdev, &mut pino);
    event.ppid = ppid; event.pdev = pdev as u64; event.pino = pino;
    read_parent_task_comm(&mut event.pcomm);

    let mut saddr: u128 = 0; let mut daddr: u128 = 0;
    let mut sport: u16 = 0; let mut dport: u16 = 0;
    read_socket_addrs_v6(sock_ptr, &mut saddr, &mut daddr, &mut sport, &mut dport);
    event.saddr = saddr; event.daddr = daddr; event.sport = sport; event.dport = dport;

    event.bytes = bytes as u64;
    event.direction = if is_send { DIRECTION_SEND } else { DIRECTION_RECV };

    if is_send {
        SENDMSG6_EVENTS.output(ctx, &event, 0);
    } else {
        RECVMSG6_EVENTS.output(ctx, &event, 0);
    }
}
