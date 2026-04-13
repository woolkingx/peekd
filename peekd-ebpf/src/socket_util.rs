//! Socket utility functions for reading kernel socket structures.
//!
//! BPF LLVM restriction: functions cannot return aggregates (Result, tuple, enum).
//! All multi-value reads use out-pointer parameters and return i64 (0=ok, negative=err).
//!
//! Offsets verified via bpftool BTF dump on Debian 12 kernel 6.1.0-43-amd64.

use aya_ebpf::helpers::bpf_probe_read_kernel;

const SOCKET_SK_OFFSET: usize = 24;

pub const SK_SKC_DADDR_OFFSET: usize = 0;
pub const SK_SKC_RCV_SADDR_OFFSET: usize = 4;
pub const SK_SKC_DPORT_OFFSET: usize = 12;
pub const SK_SKC_NUM_OFFSET: usize = 14;
const SK_SKC_FAMILY_OFFSET: usize = 16;
const SK_SKC_V6_DADDR_OFFSET: usize = 56;
const SK_SKC_V6_RCV_SADDR_OFFSET: usize = 72;

/// Read socket family (AF_INET=2, AF_INET6=10). Returns family or 0 on error.
/// Returns scalar (u16 cast to i64) — no aggregate.
pub unsafe fn read_socket_family(sock_ptr: *const u8) -> i64 {
    if sock_ptr.is_null() { return -1; }
    let sk: *const u8 = match bpf_probe_read_kernel(sock_ptr.add(SOCKET_SK_OFFSET) as *const *const u8) {
        Ok(p) => p, Err(_) => return -1,
    };
    if sk.is_null() { return -1; }
    match bpf_probe_read_kernel(sk.add(SK_SKC_FAMILY_OFFSET) as *const u16) {
        Ok(f) => f as i64,
        Err(_) => -1,
    }
}

/// Read socket family directly from struct sock * (no socket→sk indirection).
pub unsafe fn read_sk_family(sk: *const u8) -> i64 {
    if sk.is_null() { return -1; }
    match bpf_probe_read_kernel(sk.add(SK_SKC_FAMILY_OFFSET) as *const u16) {
        Ok(f) => f as i64,
        Err(_) => -1,
    }
}

/// Read IPv4 addrs/ports directly from struct sock * (no socket→sk indirection).
pub unsafe fn read_sk_addrs_v4(
    sk: *const u8,
    out_saddr: &mut u32, out_daddr: &mut u32,
    out_sport: &mut u16, out_dport: &mut u16,
) -> i64 {
    if sk.is_null() { return -1; }
    *out_saddr = bpf_probe_read_kernel(sk.add(SK_SKC_RCV_SADDR_OFFSET) as *const u32).unwrap_or(0);
    *out_daddr = bpf_probe_read_kernel(sk.add(SK_SKC_DADDR_OFFSET) as *const u32).unwrap_or(0);
    *out_sport = bpf_probe_read_kernel(sk.add(SK_SKC_NUM_OFFSET) as *const u16).unwrap_or(0);
    *out_dport = u16::from_be(bpf_probe_read_kernel(sk.add(SK_SKC_DPORT_OFFSET) as *const u16).unwrap_or(0));
    0
}

/// Read IPv6 addrs/ports directly from struct sock * (no socket→sk indirection).
pub unsafe fn read_sk_addrs_v6(
    sk: *const u8,
    out_saddr: &mut u128, out_daddr: &mut u128,
    out_sport: &mut u16, out_dport: &mut u16,
) -> i64 {
    if sk.is_null() { return -1; }
    *out_sport = bpf_probe_read_kernel(sk.add(SK_SKC_NUM_OFFSET) as *const u16).unwrap_or(0);
    *out_dport = u16::from_be(bpf_probe_read_kernel(sk.add(SK_SKC_DPORT_OFFSET) as *const u16).unwrap_or(0));
    *out_saddr = bpf_probe_read_kernel(sk.add(SK_SKC_V6_RCV_SADDR_OFFSET) as *const u128).unwrap_or(0);
    *out_daddr = bpf_probe_read_kernel(sk.add(SK_SKC_V6_DADDR_OFFSET) as *const u128).unwrap_or(0);
    0
}

/// Read IPv4 addrs/ports via out-pointers. Returns 0 on success.
pub unsafe fn read_socket_addrs_v4(
    sock_ptr: *const u8,
    out_saddr: &mut u32, out_daddr: &mut u32,
    out_sport: &mut u16, out_dport: &mut u16,
) -> i64 {
    if sock_ptr.is_null() { return -1; }
    let sk: *const u8 = match bpf_probe_read_kernel(sock_ptr.add(SOCKET_SK_OFFSET) as *const *const u8) {
        Ok(p) => p, Err(_) => return -1,
    };
    if sk.is_null() { return -1; }

    *out_saddr = bpf_probe_read_kernel(sk.add(SK_SKC_RCV_SADDR_OFFSET) as *const u32).unwrap_or(0);
    *out_daddr = bpf_probe_read_kernel(sk.add(SK_SKC_DADDR_OFFSET) as *const u32).unwrap_or(0);
    *out_sport = bpf_probe_read_kernel(sk.add(SK_SKC_NUM_OFFSET) as *const u16).unwrap_or(0);
    *out_dport = u16::from_be(bpf_probe_read_kernel(sk.add(SK_SKC_DPORT_OFFSET) as *const u16).unwrap_or(0));
    0
}

/// Read IPv6 addrs/ports via out-pointers. Returns 0 on success.
pub unsafe fn read_socket_addrs_v6(
    sock_ptr: *const u8,
    out_saddr: &mut u128, out_daddr: &mut u128,
    out_sport: &mut u16, out_dport: &mut u16,
) -> i64 {
    if sock_ptr.is_null() { return -1; }
    let sk: *const u8 = match bpf_probe_read_kernel(sock_ptr.add(SOCKET_SK_OFFSET) as *const *const u8) {
        Ok(p) => p, Err(_) => return -1,
    };
    if sk.is_null() { return -1; }

    *out_sport = bpf_probe_read_kernel(sk.add(SK_SKC_NUM_OFFSET) as *const u16).unwrap_or(0);
    *out_dport = u16::from_be(bpf_probe_read_kernel(sk.add(SK_SKC_DPORT_OFFSET) as *const u16).unwrap_or(0));
    *out_saddr = bpf_probe_read_kernel(sk.add(SK_SKC_V6_RCV_SADDR_OFFSET) as *const u128).unwrap_or(0);
    *out_daddr = bpf_probe_read_kernel(sk.add(SK_SKC_V6_DADDR_OFFSET) as *const u128).unwrap_or(0);
    0
}
