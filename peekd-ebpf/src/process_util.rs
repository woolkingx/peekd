//! Process utility functions for reading task_struct and related kernel structures.
//!
//! BPF LLVM restriction: functions cannot return aggregates (Result, tuple, enum).
//! All functions return i64 (0 = ok, negative = error) and write via out-pointers.
//!
//! Offsets verified via bpftool BTF dump on Debian 12 kernel 6.1.0-43-amd64.

use aya_ebpf::helpers::{bpf_get_current_task, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes};

// === Debian 12 / kernel 6.1.0-43-amd64 offsets (from BTF) ===

const TASK_COMM_OFFSET: usize = 2976;
const TASK_MM_OFFSET: usize = 2272;
const TASK_PARENT_OFFSET: usize = 2440;
const TASK_TGID_OFFSET: usize = 2420;
const MM_EXE_FILE_OFFSET: usize = 936;
const FILE_F_PATH_OFFSET: usize = 16;
const PATH_DENTRY_OFFSET: usize = 8;
const DENTRY_D_INODE_OFFSET: usize = 48;
const INODE_I_INO_OFFSET: usize = 64;
const INODE_I_SB_OFFSET: usize = 40;
const SB_S_DEV_OFFSET: usize = 16;

/// Read current process comm. Returns 0 on success, -1 on failure.
pub unsafe fn read_current_task_comm(comm: &mut [u8; 16]) -> i64 {
    let task = bpf_get_current_task() as *const u8;
    if task.is_null() { return -1; }
    let src = task.add(TASK_COMM_OFFSET);
    match bpf_probe_read_kernel_str_bytes(src, comm) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// Read current task inode + dev via out-pointers. Returns 0 on success.
pub unsafe fn read_current_task_inode(out_dev: &mut u32, out_ino: &mut u64) -> i64 {
    let task = bpf_get_current_task() as *const u8;
    if task.is_null() { return -1; }

    let mm_ptr: *const u8 = match bpf_probe_read_kernel(task.add(TASK_MM_OFFSET) as *const *const u8) {
        Ok(p) => p, Err(_) => return -1,
    };
    if mm_ptr.is_null() { return 0; }

    let exe_file: *const u8 = match bpf_probe_read_kernel(mm_ptr.add(MM_EXE_FILE_OFFSET) as *const *const u8) {
        Ok(p) => p, Err(_) => return -1,
    };
    if exe_file.is_null() { return 0; }

    let dentry: *const u8 = match bpf_probe_read_kernel(exe_file.add(FILE_F_PATH_OFFSET + PATH_DENTRY_OFFSET) as *const *const u8) {
        Ok(p) => p, Err(_) => return -1,
    };
    if dentry.is_null() { return 0; }

    let inode: *const u8 = match bpf_probe_read_kernel(dentry.add(DENTRY_D_INODE_OFFSET) as *const *const u8) {
        Ok(p) => p, Err(_) => return -1,
    };
    if inode.is_null() { return 0; }

    match bpf_probe_read_kernel(inode.add(INODE_I_INO_OFFSET) as *const u64) {
        Ok(v) => *out_ino = v,
        Err(_) => return -1,
    }

    let sb: *const u8 = match bpf_probe_read_kernel(inode.add(INODE_I_SB_OFFSET) as *const *const u8) {
        Ok(p) => p, Err(_) => return -1,
    };
    if !sb.is_null() {
        match bpf_probe_read_kernel(sb.add(SB_S_DEV_OFFSET) as *const u32) {
            Ok(s_dev) => *out_dev = kernel_to_glibc_dev(s_dev),
            Err(_) => {}
        }
    }
    0
}

/// Read parent process ppid/pdev/pino via out-pointers. Returns 0 on success.
pub unsafe fn read_parent_process_info(out_ppid: &mut u32, out_pdev: &mut u32, out_pino: &mut u64) -> i64 {
    let task = bpf_get_current_task() as *const u8;
    if task.is_null() { return -1; }

    let parent: *const u8 = match bpf_probe_read_kernel(task.add(TASK_PARENT_OFFSET) as *const *const u8) {
        Ok(p) => p, Err(_) => return -1,
    };
    if parent.is_null() { return 0; }

    match bpf_probe_read_kernel(parent.add(TASK_TGID_OFFSET) as *const u32) {
        Ok(v) => *out_ppid = v,
        Err(_) => return -1,
    }

    let mm: *const u8 = match bpf_probe_read_kernel(parent.add(TASK_MM_OFFSET) as *const *const u8) {
        Ok(p) => p, Err(_) => return -1,
    };
    if mm.is_null() { return 0; }

    let exe_file: *const u8 = match bpf_probe_read_kernel(mm.add(MM_EXE_FILE_OFFSET) as *const *const u8) {
        Ok(p) => p, Err(_) => return 0,
    };
    if exe_file.is_null() { return 0; }

    let dentry: *const u8 = match bpf_probe_read_kernel(exe_file.add(FILE_F_PATH_OFFSET + PATH_DENTRY_OFFSET) as *const *const u8) {
        Ok(p) => p, Err(_) => return 0,
    };
    if dentry.is_null() { return 0; }

    let inode: *const u8 = match bpf_probe_read_kernel(dentry.add(DENTRY_D_INODE_OFFSET) as *const *const u8) {
        Ok(p) => p, Err(_) => return 0,
    };
    if inode.is_null() { return 0; }

    match bpf_probe_read_kernel(inode.add(INODE_I_INO_OFFSET) as *const u64) {
        Ok(v) => *out_pino = v,
        Err(_) => return 0,
    }

    let sb: *const u8 = match bpf_probe_read_kernel(inode.add(INODE_I_SB_OFFSET) as *const *const u8) {
        Ok(p) => p, Err(_) => return 0,
    };
    if !sb.is_null() {
        if let Ok(s_dev) = bpf_probe_read_kernel(sb.add(SB_S_DEV_OFFSET) as *const u32) {
            *out_pdev = kernel_to_glibc_dev(s_dev);
        }
    }
    0
}

/// Read parent task comm. Returns 0 on success.
pub unsafe fn read_parent_task_comm(pcomm: &mut [u8; 16]) -> i64 {
    let task = bpf_get_current_task() as *const u8;
    if task.is_null() { return -1; }

    let parent: *const u8 = match bpf_probe_read_kernel(task.add(TASK_PARENT_OFFSET) as *const *const u8) {
        Ok(p) => p, Err(_) => return -1,
    };
    if parent.is_null() { return 0; }

    let src = parent.add(TASK_COMM_OFFSET);
    match bpf_probe_read_kernel_str_bytes(src, pcomm) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

fn kernel_to_glibc_dev(kernel_dev: u32) -> u32 {
    let major = (kernel_dev >> 20) & 0xfff;
    let minor = kernel_dev & 0xfffff;
    (major << 8) | (minor & 0xff)
}
