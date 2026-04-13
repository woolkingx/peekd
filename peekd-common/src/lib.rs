//! peekd-common: Shared kernel-userspace type definitions.
//!
//! This crate contains all types shared between the eBPF kernel programs (peekd-ebpf)
//! and the userspace daemon (peekd). All types use repr(C, packed) for kernel ABI safety,
//! with build-time size assertions to prevent ABI drift across kernel versions.

#![cfg_attr(not(feature = "user"), no_std)]
#![allow(dead_code, unused_imports)]

// Direction constants for SendRecvEvent
pub const DIRECTION_SEND: u8 = 0;
pub const DIRECTION_RECV: u8 = 1;

/// SendRecvEvent for IPv4 — kernel representation of send/recv syscalls.
///
/// Shared between peekd-ebpf and peekd via perf event buffers.
/// Size must never change without coordination.
/// Manually marked safe for transmute via bytemuck.
///
/// Field order is critical for kernel ABI compatibility.
/// Total size: 104 bytes
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
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

// SAFETY: SendRecvEvent is repr(C, packed) and contains only plain data types
unsafe impl bytemuck::Pod for SendRecvEvent {}
unsafe impl bytemuck::Zeroable for SendRecvEvent {}

// Build-time size assertion
const _: () = assert!(core::mem::size_of::<SendRecvEvent>() == 104);

/// SendRecv6Event for IPv6 — kernel representation of IPv6 send/recv syscalls.
///
/// Larger than SendRecvEvent due to 128-bit addresses.
/// Total size: 124 bytes
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
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
    pub saddr: u128,
    pub daddr: u128,
    pub sport: u16,
    pub dport: u16,
    pub bytes: u64,
    pub direction: u8,
    pub _pad: [u8; 3],
}

// SAFETY: SendRecv6Event is repr(C, packed) and contains only plain data types
unsafe impl bytemuck::Pod for SendRecv6Event {}
unsafe impl bytemuck::Zeroable for SendRecv6Event {}

// Build-time size assertion
const _: () = assert!(core::mem::size_of::<SendRecv6Event>() == 124);

/// ExecEvent — kernel representation of execve syscalls.
///
/// Captured by kretprobe on __x64_sys_execve.
/// Total size: 344 bytes
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
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
    pub _pad: [u8; 12],
}

// SAFETY: ExecEvent is repr(C, packed) and contains only plain data types
unsafe impl bytemuck::Pod for ExecEvent {}
unsafe impl bytemuck::Zeroable for ExecEvent {}

// Build-time size assertion
const _: () = assert!(core::mem::size_of::<ExecEvent>() == 344);

/// DnsEvent — kernel representation of DNS resolution events.
///
/// Internal event, consumed by resolver but not yielded to storage/query.
/// Total size: 272 bytes
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct DnsEvent {
    pub pid: u32,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub name: [u8; 256],
}

// SAFETY: DnsEvent is repr(C, packed) and contains only plain data types
unsafe impl bytemuck::Pod for DnsEvent {}
unsafe impl bytemuck::Zeroable for DnsEvent {}

// Build-time size assertion
const _: () = assert!(core::mem::size_of::<DnsEvent>() == 272);

/// DnsEvent6 — IPv6 DNS resolution events (v2).
///
/// Same as DnsEvent but with 128-bit addresses for IPv6.
/// Total size: 296 bytes
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct DnsEvent6 {
    pub pid: u32,
    pub saddr: u128,
    pub daddr: u128,
    pub sport: u16,
    pub dport: u16,
    pub name: [u8; 256],
}

// SAFETY: DnsEvent6 is repr(C, packed) and contains only plain data types
unsafe impl bytemuck::Pod for DnsEvent6 {}
unsafe impl bytemuck::Zeroable for DnsEvent6 {}

const _: () = assert!(core::mem::size_of::<DnsEvent6>() == 296);

/// ConnectEvent — TCP connection lifecycle event (v2).
///
/// Used for tracking connect/close events via kretprobe hooks.
/// Total size: 84 bytes
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
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
    pub direction: u8,   // 0 = outbound, 1 = inbound
    pub event_type: u8,  // 0 = connect, 1 = close
    pub _pad: [u8; 2],
}

unsafe impl bytemuck::Pod for ConnectEventRaw {}
unsafe impl bytemuck::Zeroable for ConnectEventRaw {}

const _: () = assert!(core::mem::size_of::<ConnectEventRaw>() == 84);

