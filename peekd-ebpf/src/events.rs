//! Event structures shared between kernel and userspace.
//!
//! All structures are repr(C, packed) for ABI safety and support bytemuck serialization.
//! MUST match peekd-common/src/lib.rs exactly for kernel-userspace compatibility.

use core::mem;

// Direction constants for SendRecvEvent
pub const DIRECTION_SEND: u8 = 0;
pub const DIRECTION_RECV: u8 = 1;

/// SendRecvEvent for IPv4 — kernel representation of send/recv syscalls.
/// Must exactly match peekd-common::SendRecvEvent (104 bytes).
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

impl SendRecvEvent {
    pub fn zeroed() -> Self {
        unsafe { mem::zeroed() }
    }
}

// Build-time size assertion
const _: () = assert!(core::mem::size_of::<SendRecvEvent>() == 104);

/// SendRecv6Event for IPv6 — kernel representation of IPv6 send/recv syscalls.
/// Must exactly match peekd-common::SendRecv6Event (124 bytes).
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

impl SendRecv6Event {
    pub fn zeroed() -> Self {
        unsafe { mem::zeroed() }
    }
}

// Build-time size assertion
const _: () = assert!(core::mem::size_of::<SendRecv6Event>() == 124);

/// ExecEvent — kernel representation of execve syscalls.
/// Must exactly match peekd-common::ExecEvent (344 bytes).
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

impl ExecEvent {
    pub fn zeroed() -> Self {
        unsafe { mem::zeroed() }
    }
}

// Build-time size assertion
const _: () = assert!(core::mem::size_of::<ExecEvent>() == 344);

/// DnsEvent — kernel representation of getaddrinfo return values.
/// Must exactly match peekd-common::DnsEvent (272 bytes).
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

impl DnsEvent {
    pub fn zeroed() -> Self {
        unsafe { mem::zeroed() }
    }
}

// Build-time size assertion
const _: () = assert!(core::mem::size_of::<DnsEvent>() == 272);

/// DnsEvent6 — IPv6 DNS resolution events.
/// Must exactly match peekd-common::DnsEvent6 (296 bytes).
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

impl DnsEvent6 {
    pub fn zeroed() -> Self {
        unsafe { mem::zeroed() }
    }
}

const _: () = assert!(core::mem::size_of::<DnsEvent6>() == 296);

/// DnsArg: Transient state for getaddrinfo entry → return correlation.
/// SAFETY: Raw pointers are only accessed within BPF program context (single-threaded per-CPU).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DnsArg {
    pub nodename_ptr: *const u8,
    pub results_ptr: *mut (),
}

unsafe impl Send for DnsArg {}
unsafe impl Sync for DnsArg {}

/// AddrInfo: struct addrinfo from libc (partial definition for linked list walk).
#[repr(C)]
pub struct AddrInfo {
    pub ai_flags: i32,
    pub ai_family: i32,
    pub ai_socktype: i32,
    pub ai_protocol: i32,
    pub ai_addrlen: u32,
    pub ai_addr: *const SockAddr,
    pub ai_canonname: *const u8,
    pub ai_next: *const AddrInfo,
}

/// SockAddr: Base socket address structure.
#[repr(C)]
pub struct SockAddr {
    pub sa_family: u16,
    pub sa_data: [u8; 14],
}

/// SockAddrIn: IPv4 socket address.
#[repr(C)]
pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: InAddr,
    pub sin_zero: [u8; 8],
}

/// InAddr: IPv4 address.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct InAddr {
    pub s_addr: u32,
}

/// SockAddrIn6: IPv6 socket address.
#[repr(C)]
pub struct SockAddrIn6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: In6Addr,
    pub sin6_scope_id: u32,
}

/// In6Addr: IPv6 address.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct In6Addr {
    pub s6_addr: [u8; 16],
}
