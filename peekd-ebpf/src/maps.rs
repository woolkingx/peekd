//! BPF maps for kernel-to-userspace event streaming.
//!
//! Uses flat #[repr(C)] BTF-compatible map definitions that aya-obj's
//! parse_btf_map_def can parse correctly. The old wrapper struct pattern
//! (PerfEventArray { def: MapDef }) produces nested BTF that aya-obj skips,
//! resulting in map_type=0 and EINVAL from the kernel.
//!
//! Field encoding (matches libbpf/aya btf_map_def convention):
//! - type:        *const [i32; BPF_MAP_TYPE_X]     (array length = map type enum)
//! - key:         *const K                          (pointer to key type)
//! - value:       *const V                          (pointer to value type)
//! - max_entries: *const [i32; N]                   (array length = max entries)
//! - map_flags:   *const [i32; F]                   (array length = flags)

use core::ptr::{self, NonNull};
use aya_ebpf::EbpfContext;
use aya_ebpf::helpers::{
    bpf_perf_event_output, bpf_map_lookup_elem, bpf_map_update_elem, bpf_map_delete_elem,
};
use aya_ebpf::bindings::BPF_F_CURRENT_CPU;

use crate::events::{SendRecvEvent, SendRecv6Event, ExecEvent, DnsEvent, DnsEvent6, DnsArg};

// ============================================================================
// Flat BTF map struct definitions
// ============================================================================

// BPF_MAP_TYPE constants (from aya_ebpf::bindings::bpf_map_type)
const BPF_MAP_TYPE_HASH: usize = 1;
const BPF_MAP_TYPE_PERCPU_ARRAY: usize = 6;
const BPF_MAP_TYPE_PERF_EVENT_ARRAY: usize = 4;

/// Flat BTF PerfEventArray — parse_btf_map_def sees: type=4, key=u32, value=u32, max_entries=0
#[repr(C)]
pub struct BtfPerfEventArray<T> {
    r#type: *const [i32; BPF_MAP_TYPE_PERF_EVENT_ARRAY],
    key: *const u32,
    value: *const u32,
    max_entries: *const [i32; 0],
    map_flags: *const [i32; 0],
    _t: core::marker::PhantomData<T>,
}

unsafe impl<T> Sync for BtfPerfEventArray<T> {}

impl<T> BtfPerfEventArray<T> {
    pub const fn new() -> Self {
        Self {
            r#type: ptr::null(),
            key: ptr::null(),
            value: ptr::null(),
            max_entries: ptr::null(),
            map_flags: ptr::null(),
            _t: core::marker::PhantomData,
        }
    }

    #[inline(always)]
    fn as_ptr(&self) -> *mut core::ffi::c_void {
        ptr::from_ref(self).cast_mut().cast()
    }

    pub fn output<C: EbpfContext>(&self, ctx: &C, data: &T, flags: u32) {
        let flags = (u64::from(flags) << 32) | (BPF_F_CURRENT_CPU as u64);
        unsafe {
            bpf_perf_event_output(
                ctx.as_ptr(),
                self.as_ptr(),
                flags,
                ptr::from_ref(data).cast_mut().cast(),
                core::mem::size_of::<T>() as u64,
            );
        }
    }
}

/// Flat BTF HashMap<K, V>
#[repr(C)]
pub struct BtfHashMap<K, V, const MAX_ENTRIES: usize> {
    r#type: *const [i32; BPF_MAP_TYPE_HASH],
    key: *const K,
    value: *const V,
    max_entries: *const [i32; MAX_ENTRIES],
    map_flags: *const [i32; 0],
}

unsafe impl<K, V, const MAX_ENTRIES: usize> Sync for BtfHashMap<K, V, MAX_ENTRIES> {}

impl<K, V, const MAX_ENTRIES: usize> BtfHashMap<K, V, MAX_ENTRIES> {
    pub const fn new() -> Self {
        Self {
            r#type: ptr::null(),
            key: ptr::null(),
            value: ptr::null(),
            max_entries: ptr::null(),
            map_flags: ptr::null(),
        }
    }

    #[inline(always)]
    fn as_ptr(&self) -> *mut core::ffi::c_void {
        ptr::from_ref(self).cast_mut().cast()
    }

    #[inline(always)]
    pub fn get(&self, key: &K) -> Option<&V> {
        unsafe {
            let p = bpf_map_lookup_elem(self.as_ptr(), ptr::from_ref(key).cast_mut().cast());
            if p.is_null() { None } else { Some(&*(p as *const V)) }
        }
    }

    #[inline(always)]
    pub fn insert(&self, key: &K, value: &V, flags: u64) -> Result<(), i32> {
        let ret = unsafe {
            bpf_map_update_elem(
                self.as_ptr(),
                ptr::from_ref(key).cast_mut().cast(),
                ptr::from_ref(value).cast_mut().cast(),
                flags,
            )
        };
        if ret == 0 { Ok(()) } else { Err(ret as i32) }
    }

    #[inline(always)]
    pub fn remove(&self, key: &K) -> Result<(), i32> {
        let ret = unsafe {
            bpf_map_delete_elem(self.as_ptr(), ptr::from_ref(key).cast_mut().cast())
        };
        if ret == 0 { Ok(()) } else { Err(ret as i32) }
    }
}

/// Flat BTF PerCpuArray<T>
#[repr(C)]
pub struct BtfPerCpuArray<T, const MAX_ENTRIES: usize> {
    r#type: *const [i32; BPF_MAP_TYPE_PERCPU_ARRAY],
    key: *const u32,
    value: *const T,
    max_entries: *const [i32; MAX_ENTRIES],
    map_flags: *const [i32; 0],
}

unsafe impl<T, const MAX_ENTRIES: usize> Sync for BtfPerCpuArray<T, MAX_ENTRIES> {}

impl<T, const MAX_ENTRIES: usize> BtfPerCpuArray<T, MAX_ENTRIES> {
    pub const fn new() -> Self {
        Self {
            r#type: ptr::null(),
            key: ptr::null(),
            value: ptr::null(),
            max_entries: ptr::null(),
            map_flags: ptr::null(),
        }
    }

    #[inline(always)]
    fn as_ptr(&self) -> *mut core::ffi::c_void {
        ptr::from_ref(self).cast_mut().cast()
    }

    #[inline(always)]
    pub fn get(&self, index: u32) -> Option<&T> {
        unsafe {
            let p = bpf_map_lookup_elem(self.as_ptr(), ptr::from_ref(&index).cast_mut().cast());
            if p.is_null() { None } else { Some(&*(p as *const T)) }
        }
    }

    #[inline(always)]
    pub fn get_ptr_mut(&self, index: u32) -> Option<*mut T> {
        unsafe {
            let p = bpf_map_lookup_elem(self.as_ptr(), ptr::from_ref(&index).cast_mut().cast());
            if p.is_null() { None } else { Some(p as *mut T) }
        }
    }
}

// ============================================================================
// Map instances
// ============================================================================

#[unsafe(link_section = ".maps")]
#[unsafe(no_mangle)]
pub static SENDMSG_EVENTS: BtfPerfEventArray<SendRecvEvent> = BtfPerfEventArray::new();

#[unsafe(link_section = ".maps")]
#[unsafe(no_mangle)]
pub static RECVMSG_EVENTS: BtfPerfEventArray<SendRecvEvent> = BtfPerfEventArray::new();

#[unsafe(link_section = ".maps")]
#[unsafe(no_mangle)]
pub static SENDMSG6_EVENTS: BtfPerfEventArray<SendRecv6Event> = BtfPerfEventArray::new();

#[unsafe(link_section = ".maps")]
#[unsafe(no_mangle)]
pub static RECVMSG6_EVENTS: BtfPerfEventArray<SendRecv6Event> = BtfPerfEventArray::new();

#[unsafe(link_section = ".maps")]
#[unsafe(no_mangle)]
pub static EXEC_EVENTS: BtfPerfEventArray<ExecEvent> = BtfPerfEventArray::new();

#[unsafe(link_section = ".maps")]
#[unsafe(no_mangle)]
pub static DNS_EVENTS: BtfPerfEventArray<DnsEvent> = BtfPerfEventArray::new();

#[unsafe(link_section = ".maps")]
#[unsafe(no_mangle)]
pub static DNS6_EVENTS: BtfPerfEventArray<DnsEvent6> = BtfPerfEventArray::new();

#[unsafe(link_section = ".maps")]
#[unsafe(no_mangle)]
pub static CONNECT_EVENTS: BtfPerfEventArray<peekd_common::ConnectEventRaw> = BtfPerfEventArray::new();

/// Hash map for correlation of getaddrinfo entry → return.
#[unsafe(link_section = ".maps")]
#[unsafe(no_mangle)]
pub static DNS_ARGS: BtfHashMap<u64, DnsArg, 1024> = BtfHashMap::new();

/// Hash map for tcp_v4_connect entry → return correlation.
#[unsafe(link_section = ".maps")]
#[unsafe(no_mangle)]
pub static TCP_CONNECT_ARGS: BtfHashMap<u64, u64, 65536> = BtfHashMap::new();

/// Per-CPU scratch space for DnsEvent (272 bytes — too large for BPF stack).
#[unsafe(link_section = ".maps")]
#[unsafe(no_mangle)]
pub static DNS_SCRATCH: BtfPerCpuArray<DnsEvent, 1> = BtfPerCpuArray::new();

/// Per-CPU scratch space for DnsEvent6 (296 bytes — too large for BPF stack).
#[unsafe(link_section = ".maps")]
#[unsafe(no_mangle)]
pub static DNS6_SCRATCH: BtfPerCpuArray<DnsEvent6, 1> = BtfPerCpuArray::new();
