// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include "peekd.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
} sendmsg_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
} recvmsg_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
} sendmsg6_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
} recvmsg6_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
} exec_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
} dns_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
} dns6_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
} bpf_stats_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
} connect_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct peekd_probe_arg);
} inet_send_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct peekd_probe_arg);
} inet_recv_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct peekd_probe_arg);
} sock_send_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct peekd_probe_arg);
} sock_recv_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u64);
} tcp_send_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct dns_arg);
} dns_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u64);
} tcp_connect_args SEC(".maps");

static __always_inline __u32 kernel_to_glibc_dev(__u32 kernel_dev)
{
    __u32 major = (kernel_dev >> 20) & 0xfff;
    __u32 minor = kernel_dev & 0xfffff;
    return (major << 8) | (minor & 0xff);
}

static __always_inline void emit_bpf_stat(void *ctx, __u32 kind)
{
    struct bpf_stat_event event = { .kind = kind };
    bpf_perf_event_output(ctx, &bpf_stats_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

static __always_inline struct sock *socket_sk(struct socket *sock)
{
    if (!sock)
        return 0;
    return BPF_CORE_READ(sock, sk);
}

static __always_inline __u16 read_family(struct sock *sk)
{
    if (!sk)
        return 0;
    return BPF_CORE_READ(sk, __sk_common.skc_family);
}

static __always_inline void fill_task_identity(
    __u32 *pid, __u32 *ppid, __u32 *uid, __u64 *dev, __u64 *ino,
    __u64 *pdev, __u64 *pino, __u8 comm[TASK_COMM_LEN], __u8 pcomm[TASK_COMM_LEN])
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct task_struct *parent = 0;

    *pid = (__u32)pid_tgid;
    *uid = (__u32)uid_gid;
    bpf_get_current_comm(comm, TASK_COMM_LEN);
    if (!task)
        return;

    parent = BPF_CORE_READ(task, real_parent);
    if (parent) {
        *ppid = BPF_CORE_READ(parent, tgid);
        BPF_CORE_READ_STR_INTO(pcomm, parent, comm);
    }
}

static __always_inline void fill_inode_for_task(struct task_struct *task, __u64 *dev, __u64 *ino)
{
    struct mm_struct *mm = 0;
    struct file *exe_file = 0;
    struct dentry *dentry = 0;
    struct inode *inode = 0;
    struct super_block *sb = 0;
    __u32 s_dev = 0;

    if (!task)
        return;
    mm = BPF_CORE_READ(task, mm);
    if (!mm)
        return;
    exe_file = BPF_CORE_READ(mm, exe_file);
    if (!exe_file)
        return;
    dentry = BPF_CORE_READ(exe_file, f_path.dentry);
    if (!dentry)
        return;
    inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode)
        return;
    *ino = BPF_CORE_READ(inode, i_ino);
    sb = BPF_CORE_READ(inode, i_sb);
    if (!sb)
        return;
    s_dev = BPF_CORE_READ(sb, s_dev);
    *dev = kernel_to_glibc_dev(s_dev);
}

static __always_inline void fill_process_info(
    __u32 *pid, __u32 *ppid, __u32 *uid, __u64 *dev, __u64 *ino,
    __u64 *pdev, __u64 *pino, __u8 comm[TASK_COMM_LEN], __u8 pcomm[TASK_COMM_LEN])
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct task_struct *parent = 0;

    fill_task_identity(pid, ppid, uid, dev, ino, pdev, pino, comm, pcomm);
    fill_inode_for_task(task, dev, ino);
    if (task)
        parent = BPF_CORE_READ(task, real_parent);
    fill_inode_for_task(parent, pdev, pino);
}

static __always_inline void read_sock_v4(struct sock *sk, __u32 *saddr, __u32 *daddr, __u16 *sport, __u16 *dport)
{
    *saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    *daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    *sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    *dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
}

static __always_inline void read_sock_v6(struct sock *sk, __u8 saddr[16], __u8 daddr[16], __u16 *sport, __u16 *dport)
{
    BPF_CORE_READ_INTO(saddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    BPF_CORE_READ_INTO(daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    *sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    *dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
}

static __always_inline void emit_send_recv_sk(void *ctx, struct sock *sk, int ret, bool is_send)
{
    if (ret <= 0 || !sk)
        return;

    __u16 family = read_family(sk);
    if (family == AF_INET) {
        struct send_recv_event event = {};
        fill_process_info(&event.pid, &event.ppid, &event.uid, &event.dev, &event.ino,
            &event.pdev, &event.pino, event.comm, event.pcomm);
        read_sock_v4(sk, &event.saddr, &event.daddr, &event.sport, &event.dport);
        event.bytes = (__u64)ret;
        event.direction = is_send ? DIRECTION_SEND : DIRECTION_RECV;
        if (is_send) {
            bpf_perf_event_output(ctx, &sendmsg_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
        } else {
            bpf_perf_event_output(ctx, &recvmsg_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
        }
    } else if (family == AF_INET6) {
        struct send_recv6_event event = {};
        fill_process_info(&event.pid, &event.ppid, &event.uid, &event.dev, &event.ino,
            &event.pdev, &event.pino, event.comm, event.pcomm);
        read_sock_v6(sk, event.saddr, event.daddr, &event.sport, &event.dport);
        event.bytes = (__u64)ret;
        event.direction = is_send ? DIRECTION_SEND : DIRECTION_RECV;
        if (is_send) {
            bpf_perf_event_output(ctx, &sendmsg6_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
        } else {
            bpf_perf_event_output(ctx, &recvmsg6_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
        }
    }
}

static __always_inline void emit_send_recv_socket(void *ctx, struct socket *sock, int ret, bool is_send)
{
    emit_send_recv_sk(ctx, socket_sk(sock), ret, is_send);
}

SEC("kprobe/inet_sendmsg")
int BPF_KPROBE(inet_sendmsg_entry, struct socket *sock)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct peekd_probe_arg arg = { .ptr = (__u64)sock };
    bpf_map_update_elem(&inet_send_args, &pid_tgid, &arg, BPF_ANY);
    return 0;
}

SEC("kretprobe/inet_sendmsg")
int BPF_KRETPROBE(inet_sendmsg_ret, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct peekd_probe_arg *arg = bpf_map_lookup_elem(&inet_send_args, &pid_tgid);
    if (arg)
        emit_send_recv_socket(ctx, (struct socket *)arg->ptr, ret, true);
    bpf_map_delete_elem(&inet_send_args, &pid_tgid);
    return 0;
}

SEC("kprobe/inet_recvmsg")
int BPF_KPROBE(inet_recvmsg_entry, struct socket *sock)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct peekd_probe_arg arg = { .ptr = (__u64)sock };
    bpf_map_update_elem(&inet_recv_args, &pid_tgid, &arg, BPF_ANY);
    return 0;
}

SEC("kretprobe/inet_recvmsg")
int BPF_KRETPROBE(inet_recvmsg_ret, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct peekd_probe_arg *arg = bpf_map_lookup_elem(&inet_recv_args, &pid_tgid);
    if (arg)
        emit_send_recv_socket(ctx, (struct socket *)arg->ptr, ret, false);
    bpf_map_delete_elem(&inet_recv_args, &pid_tgid);
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg_entry, struct sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 ptr = (__u64)sk;
    bpf_map_update_elem(&tcp_send_args, &pid_tgid, &ptr, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(tcp_sendmsg_ret, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *ptr = bpf_map_lookup_elem(&tcp_send_args, &pid_tgid);
    if (ptr)
        emit_send_recv_sk(ctx, (struct sock *)*ptr, ret, true);
    bpf_map_delete_elem(&tcp_send_args, &pid_tgid);
    return 0;
}

SEC("kprobe/sock_sendmsg")
int BPF_KPROBE(sock_sendmsg_entry, struct socket *sock)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct peekd_probe_arg arg = { .ptr = (__u64)sock };
    bpf_map_update_elem(&sock_send_args, &pid_tgid, &arg, BPF_ANY);
    return 0;
}

SEC("kretprobe/sock_sendmsg")
int BPF_KRETPROBE(sock_sendmsg_ret, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct peekd_probe_arg *arg = bpf_map_lookup_elem(&sock_send_args, &pid_tgid);
    if (arg)
        emit_send_recv_socket(ctx, (struct socket *)arg->ptr, ret, true);
    bpf_map_delete_elem(&sock_send_args, &pid_tgid);
    return 0;
}

SEC("kprobe/sock_recvmsg")
int BPF_KPROBE(sock_recvmsg_entry, struct socket *sock)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct peekd_probe_arg arg = { .ptr = (__u64)sock };
    bpf_map_update_elem(&sock_recv_args, &pid_tgid, &arg, BPF_ANY);
    return 0;
}

SEC("kretprobe/sock_recvmsg")
int BPF_KRETPROBE(sock_recvmsg_ret, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct peekd_probe_arg *arg = bpf_map_lookup_elem(&sock_recv_args, &pid_tgid);
    if (arg)
        emit_send_recv_socket(ctx, (struct socket *)arg->ptr, ret, false);
    bpf_map_delete_elem(&sock_recv_args, &pid_tgid);
    return 0;
}

SEC("kretprobe/__x64_sys_execve")
int BPF_KRETPROBE(exec_entry, int ret)
{
    struct exec_event event = {};
    if (ret != 0)
        return 0;
    fill_process_info(&event.pid, &event.ppid, &event.uid, &event.dev, &event.ino,
        &event.pdev, &event.pino, event.comm, event.pcomm);
    bpf_perf_event_output(ctx, &exec_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("uprobe/getaddrinfo")
int BPF_KPROBE(dns_entry, const char *nodename, const char *service, const void *hints, void *res)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct dns_arg arg = { .nodename_ptr = nodename, .results_ptr = res };
    emit_bpf_stat(ctx, BPF_STAT_DNS_ENTRY_SEEN);
    if (bpf_map_update_elem(&dns_args, &pid_tgid, &arg, BPF_ANY) != 0)
        emit_bpf_stat(ctx, BPF_STAT_DNS_ARGS_INSERT_FAILED);
    return 0;
}

static __always_inline void dns_walk_one(void *ctx, __u32 pid, struct dns_arg *arg, void **current)
{
    int family = 0;
    void *ai_addr = 0;
    void *ai_next = 0;
    if (!*current)
        return;
    bpf_probe_read_user(&family, sizeof(family), (*current) + 4);
    bpf_probe_read_user(&ai_addr, sizeof(ai_addr), (*current) + 24);
    bpf_probe_read_user(&ai_next, sizeof(ai_next), (*current) + 40);
    if (family == AF_INET && ai_addr) {
        struct dns_event event = { .pid = pid };
        bpf_probe_read_user(&event.dport, sizeof(event.dport), ai_addr + 2);
        bpf_probe_read_user(&event.daddr, sizeof(event.daddr), ai_addr + 4);
        bpf_probe_read_user_str(event.name, sizeof(event.name), arg->nodename_ptr);
        bpf_perf_event_output(ctx, &dns_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    } else if (family == AF_INET6 && ai_addr) {
        struct dns6_event event = { .pid = pid };
        bpf_probe_read_user(&event.dport, sizeof(event.dport), ai_addr + 2);
        bpf_probe_read_user(event.daddr, sizeof(event.daddr), ai_addr + 8);
        bpf_probe_read_user_str(event.name, sizeof(event.name), arg->nodename_ptr);
        bpf_perf_event_output(ctx, &dns6_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }
    *current = ai_next;
}

SEC("uretprobe/getaddrinfo")
int BPF_KRETPROBE(dns_return, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct dns_arg *arg = bpf_map_lookup_elem(&dns_args, &pid_tgid);
    void *current = 0;
    emit_bpf_stat(ctx, BPF_STAT_DNS_RETURN_SEEN);
    if (!arg)
        return 0;
    if (bpf_map_delete_elem(&dns_args, &pid_tgid) != 0)
        emit_bpf_stat(ctx, BPF_STAT_DNS_ARGS_REMOVE_FAILED);
    if (ret != 0 || !arg->results_ptr)
        return 0;
    bpf_probe_read_user(&current, sizeof(current), arg->results_ptr);
    dns_walk_one(ctx, (__u32)pid_tgid, arg, &current);
    dns_walk_one(ctx, (__u32)pid_tgid, arg, &current);
    dns_walk_one(ctx, (__u32)pid_tgid, arg, &current);
    dns_walk_one(ctx, (__u32)pid_tgid, arg, &current);
    dns_walk_one(ctx, (__u32)pid_tgid, arg, &current);
    dns_walk_one(ctx, (__u32)pid_tgid, arg, &current);
    dns_walk_one(ctx, (__u32)pid_tgid, arg, &current);
    dns_walk_one(ctx, (__u32)pid_tgid, arg, &current);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect_entry, struct sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 ptr = (__u64)sk;
    bpf_map_update_elem(&tcp_connect_args, &pid_tgid, &ptr, BPF_ANY);
    return 0;
}

static __always_inline void emit_connect(void *ctx, struct sock *sk, __u8 direction, __u8 event_type)
{
    struct connect_event_raw event = {};
    __u64 dev = 0, ino = 0, pdev = 0, pino = 0;
    __u16 family = read_family(sk);
    if (!sk)
        return;
    if (family == AF_INET6) {
        emit_bpf_stat(ctx, BPF_STAT_LIFECYCLE_IPV6_SKIPPED);
        return;
    }
    if (family != AF_INET)
        return;
    fill_process_info(&event.pid, &event.ppid, &event.uid, &dev, &ino, &pdev, &pino,
        event.comm, event.pcomm);
    event.dev = (__u32)dev;
    event.ino = ino;
    event.pdev = (__u32)pdev;
    event.pino = pino;
    read_sock_v4(sk, &event.saddr, &event.daddr, &event.sport, &event.dport);
    event.direction = direction;
    event.event_type = event_type;
    bpf_perf_event_output(ctx, &connect_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_ret, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *ptr = bpf_map_lookup_elem(&tcp_connect_args, &pid_tgid);
    if (ret == 0 && ptr)
        emit_connect(ctx, (struct sock *)*ptr, 0, 0);
    bpf_map_delete_elem(&tcp_connect_args, &pid_tgid);
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept_ret, struct sock *sk)
{
    emit_connect(ctx, sk, 1, 0);
    return 0;
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(tcp_close_entry, struct sock *sk)
{
    emit_connect(ctx, sk, 0, 1);
    return 0;
}
