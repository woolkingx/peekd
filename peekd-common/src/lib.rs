//! peekd-common: Shared kernel-userspace type definitions.
//!
//! This crate contains all types shared between the libbpf C eBPF source
//! and the userspace daemon (peekd). All types use repr(C) with explicit padding
//! for BPF verifier-safe stack alignment and build-time ABI drift checks.

#![cfg_attr(not(feature = "user"), no_std)]
#![allow(dead_code, unused_imports)]

// Direction constants for SendRecvEvent
pub const DIRECTION_SEND: u8 = 0;
pub const DIRECTION_RECV: u8 = 1;
pub const BPF_STAT_DNS_ARGS_INSERT_FAILED: u32 = 1;
pub const BPF_STAT_DNS_ARGS_REMOVE_FAILED: u32 = 2;
pub const BPF_STAT_LIFECYCLE_IPV6_SKIPPED: u32 = 3;
pub const BPF_STAT_DNS_ENTRY_SEEN: u32 = 4;
pub const BPF_STAT_DNS_RETURN_SEEN: u32 = 5;

/// SendRecvEvent for IPv4 — kernel representation of send/recv syscalls.
///
/// Shared between `peekd/src/bpf/peekd.bpf.c` and peekd via perf event buffers.
/// Size must never change without coordination.
/// Manually marked safe for transmute via bytemuck.
///
/// Field order is critical for kernel ABI compatibility.
/// Total size: 112 bytes
#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct SendRecvEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub dev: u64,
    pub ino: u64,
    pub pdev: u64,
    pub pino: u64,
    pub comm: [u8; 16],
    pub pcomm: [u8; 16],
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub bytes: u64,
    pub direction: u8,
    pub _pad: [u8; 7],
}

// SAFETY: SendRecvEvent is repr(C), zero-initialized by the BPF producer, and contains only plain data types.
unsafe impl bytemuck::Pod for SendRecvEvent {}
unsafe impl bytemuck::Zeroable for SendRecvEvent {}

// Build-time size assertion
const _: () = assert!(core::mem::size_of::<SendRecvEvent>() == 112);

/// SendRecv6Event for IPv6 — kernel representation of IPv6 send/recv syscalls.
///
/// Larger than SendRecvEvent due to 128-bit addresses.
/// Total size: 136 bytes
#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct SendRecv6Event {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub dev: u64,
    pub ino: u64,
    pub pdev: u64,
    pub pino: u64,
    pub comm: [u8; 16],
    pub pcomm: [u8; 16],
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub bytes: u64,
    pub direction: u8,
    pub _pad: [u8; 7],
}

// SAFETY: SendRecv6Event is repr(C), zero-initialized by the BPF producer, and contains only plain data types.
unsafe impl bytemuck::Pod for SendRecv6Event {}
unsafe impl bytemuck::Zeroable for SendRecv6Event {}

// Build-time size assertion
const _: () = assert!(core::mem::size_of::<SendRecv6Event>() == 136);

/// ExecEvent — kernel representation of execve syscalls.
///
/// Captured by kretprobe on __x64_sys_execve.
/// Total size: 352 bytes
#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub dev: u64,
    pub ino: u64,
    pub pdev: u64,
    pub pino: u64,
    pub comm: [u8; 16],
    pub pcomm: [u8; 16],
    pub filename: [u8; 256],
    pub _pad: [u8; 16],
}

// SAFETY: ExecEvent is repr(C), zero-initialized by the BPF producer, and contains only plain data types.
unsafe impl bytemuck::Pod for ExecEvent {}
unsafe impl bytemuck::Zeroable for ExecEvent {}

// Build-time size assertion
const _: () = assert!(core::mem::size_of::<ExecEvent>() == 352);

/// DnsEvent — kernel representation of DNS resolution events.
///
/// Internal event, consumed by resolver but not yielded to storage/query.
/// Total size: 272 bytes
#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct DnsEvent {
    pub pid: u32,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub name: [u8; 256],
}

// SAFETY: DnsEvent is repr(C), zero-initialized by the BPF producer, and contains only plain data types.
unsafe impl bytemuck::Pod for DnsEvent {}
unsafe impl bytemuck::Zeroable for DnsEvent {}

// Build-time size assertion
const _: () = assert!(core::mem::size_of::<DnsEvent>() == 272);

/// DnsEvent6 — IPv6 DNS resolution events (v2).
///
/// Same as DnsEvent but with 128-bit addresses for IPv6.
/// Total size: 296 bytes
#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct DnsEvent6 {
    pub pid: u32,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub name: [u8; 256],
}

// SAFETY: DnsEvent6 is repr(C), zero-initialized by the BPF producer, and contains only plain data types.
unsafe impl bytemuck::Pod for DnsEvent6 {}
unsafe impl bytemuck::Zeroable for DnsEvent6 {}

const _: () = assert!(core::mem::size_of::<DnsEvent6>() == 296);

/// ConnectEvent — TCP connection lifecycle event (v2).
///
/// Used for tracking connect/close events via kretprobe hooks.
/// Total size: 88 bytes
#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct ConnectEventRaw {
    pub comm: [u8; 16],
    pub pcomm: [u8; 16],
    pub ino: u64,
    pub pino: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub dev: u32,
    pub pdev: u32,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub direction: u8,  // 0 = outbound, 1 = inbound
    pub event_type: u8, // 0 = connect, 1 = close
    pub _pad: [u8; 6],
}

unsafe impl bytemuck::Pod for ConnectEventRaw {}
unsafe impl bytemuck::Zeroable for ConnectEventRaw {}

const _: () = assert!(core::mem::size_of::<ConnectEventRaw>() == 88);

/// BpfStatEvent — small kernel-to-userspace counter event.
#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct BpfStatEvent {
    pub kind: u32,
    pub _pad: u32,
}

unsafe impl bytemuck::Pod for BpfStatEvent {}
unsafe impl bytemuck::Zeroable for BpfStatEvent {}

const _: () = assert!(core::mem::size_of::<BpfStatEvent>() == 8);

#[cfg(test)]
mod abi_tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn send_recv_event_layout_is_verifier_aligned() {
        assert_eq!(size_of::<SendRecvEvent>(), 112);
        assert_eq!(align_of::<SendRecvEvent>(), 8);
        assert_eq!(offset_of!(SendRecvEvent, dev), 16);
        assert_eq!(offset_of!(SendRecvEvent, ino), 24);
        assert_eq!(offset_of!(SendRecvEvent, pdev), 32);
        assert_eq!(offset_of!(SendRecvEvent, pino), 40);
        assert_eq!(offset_of!(SendRecvEvent, bytes), 96);
        assert_eq!(offset_of!(SendRecvEvent, direction), 104);
    }

    #[test]
    fn send_recv6_event_layout_is_verifier_aligned() {
        assert_eq!(size_of::<SendRecv6Event>(), 136);
        assert_eq!(align_of::<SendRecv6Event>(), 8);
        assert_eq!(offset_of!(SendRecv6Event, dev), 16);
        assert_eq!(offset_of!(SendRecv6Event, ino), 24);
        assert_eq!(offset_of!(SendRecv6Event, pdev), 32);
        assert_eq!(offset_of!(SendRecv6Event, pino), 40);
        assert_eq!(offset_of!(SendRecv6Event, saddr), 80);
        assert_eq!(offset_of!(SendRecv6Event, daddr), 96);
        assert_eq!(offset_of!(SendRecv6Event, bytes), 120);
        assert_eq!(offset_of!(SendRecv6Event, direction), 128);
    }

    #[test]
    fn exec_event_layout_is_verifier_aligned() {
        assert_eq!(size_of::<ExecEvent>(), 352);
        assert_eq!(align_of::<ExecEvent>(), 8);
        assert_eq!(offset_of!(ExecEvent, dev), 16);
        assert_eq!(offset_of!(ExecEvent, ino), 24);
        assert_eq!(offset_of!(ExecEvent, pdev), 32);
        assert_eq!(offset_of!(ExecEvent, pino), 40);
        assert_eq!(offset_of!(ExecEvent, filename), 80);
    }

    #[test]
    fn dns_event_layout_matches_c_header() {
        assert_eq!(size_of::<DnsEvent>(), 272);
        assert_eq!(align_of::<DnsEvent>(), 4);
        assert_eq!(offset_of!(DnsEvent, name), 16);
        assert_eq!(size_of::<DnsEvent6>(), 296);
        assert_eq!(align_of::<DnsEvent6>(), 4);
        assert_eq!(offset_of!(DnsEvent6, saddr), 4);
        assert_eq!(offset_of!(DnsEvent6, daddr), 20);
        assert_eq!(offset_of!(DnsEvent6, name), 40);
    }

    #[test]
    fn connect_and_stat_layouts_match_c_header() {
        assert_eq!(size_of::<ConnectEventRaw>(), 88);
        assert_eq!(align_of::<ConnectEventRaw>(), 8);
        assert_eq!(offset_of!(ConnectEventRaw, ino), 32);
        assert_eq!(offset_of!(ConnectEventRaw, pino), 40);
        assert_eq!(offset_of!(ConnectEventRaw, pid), 48);
        assert_eq!(offset_of!(ConnectEventRaw, saddr), 68);
        assert_eq!(offset_of!(ConnectEventRaw, direction), 80);
        assert_eq!(size_of::<BpfStatEvent>(), 8);
        assert_eq!(align_of::<BpfStatEvent>(), 4);
    }
}
