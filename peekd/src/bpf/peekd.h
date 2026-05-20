#ifndef PEEKD_BPF_H
#define PEEKD_BPF_H

#define TASK_COMM_LEN 16
#define DNS_NAME_LEN 256

#define AF_INET 2
#define AF_INET6 10

#define DIRECTION_SEND 0
#define DIRECTION_RECV 1

#define BPF_STAT_DNS_ARGS_INSERT_FAILED 1
#define BPF_STAT_DNS_ARGS_REMOVE_FAILED 2
#define BPF_STAT_LIFECYCLE_IPV6_SKIPPED 3
#define BPF_STAT_DNS_ENTRY_SEEN 4
#define BPF_STAT_DNS_RETURN_SEEN 5

struct send_recv_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u64 dev;
    __u64 ino;
    __u64 pdev;
    __u64 pino;
    __u8 comm[TASK_COMM_LEN];
    __u8 pcomm[TASK_COMM_LEN];
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u64 bytes;
    __u8 direction;
    __u8 _pad[7];
};

struct send_recv6_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u64 dev;
    __u64 ino;
    __u64 pdev;
    __u64 pino;
    __u8 comm[TASK_COMM_LEN];
    __u8 pcomm[TASK_COMM_LEN];
    __u8 saddr[16];
    __u8 daddr[16];
    __u16 sport;
    __u16 dport;
    __u64 bytes;
    __u8 direction;
    __u8 _pad[7];
};

struct exec_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u64 dev;
    __u64 ino;
    __u64 pdev;
    __u64 pino;
    __u8 comm[TASK_COMM_LEN];
    __u8 pcomm[TASK_COMM_LEN];
    __u8 filename[DNS_NAME_LEN];
    __u8 _pad[16];
};

struct dns_event {
    __u32 pid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 name[DNS_NAME_LEN];
};

struct dns6_event {
    __u32 pid;
    __u8 saddr[16];
    __u8 daddr[16];
    __u16 sport;
    __u16 dport;
    __u8 name[DNS_NAME_LEN];
};

struct connect_event_raw {
    __u8 comm[TASK_COMM_LEN];
    __u8 pcomm[TASK_COMM_LEN];
    __u64 ino;
    __u64 pino;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 dev;
    __u32 pdev;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 direction;
    __u8 event_type;
    __u8 _pad[6];
};

struct bpf_stat_event {
    __u32 kind;
    __u32 _pad;
};

struct peekd_probe_arg {
    __u64 ptr;
};

struct dns_arg {
    const char *nodename_ptr;
    void *results_ptr;
};

#define PEEKD_ASSERT_SIZE(type, expected) \
    typedef char peekd_assert_##type##_size[(sizeof(struct type) == (expected)) ? 1 : -1]
#define PEEKD_ASSERT_OFFSET(type, field, expected) \
    typedef char peekd_assert_##type##_##field##_offset[(__builtin_offsetof(struct type, field) == (expected)) ? 1 : -1]

PEEKD_ASSERT_SIZE(send_recv_event, 112);
PEEKD_ASSERT_OFFSET(send_recv_event, dev, 16);
PEEKD_ASSERT_OFFSET(send_recv_event, ino, 24);
PEEKD_ASSERT_OFFSET(send_recv_event, pdev, 32);
PEEKD_ASSERT_OFFSET(send_recv_event, pino, 40);
PEEKD_ASSERT_OFFSET(send_recv_event, bytes, 96);
PEEKD_ASSERT_OFFSET(send_recv_event, direction, 104);

PEEKD_ASSERT_SIZE(send_recv6_event, 136);
PEEKD_ASSERT_OFFSET(send_recv6_event, dev, 16);
PEEKD_ASSERT_OFFSET(send_recv6_event, ino, 24);
PEEKD_ASSERT_OFFSET(send_recv6_event, pdev, 32);
PEEKD_ASSERT_OFFSET(send_recv6_event, pino, 40);
PEEKD_ASSERT_OFFSET(send_recv6_event, saddr, 80);
PEEKD_ASSERT_OFFSET(send_recv6_event, daddr, 96);
PEEKD_ASSERT_OFFSET(send_recv6_event, bytes, 120);
PEEKD_ASSERT_OFFSET(send_recv6_event, direction, 128);

PEEKD_ASSERT_SIZE(exec_event, 352);
PEEKD_ASSERT_OFFSET(exec_event, dev, 16);
PEEKD_ASSERT_OFFSET(exec_event, ino, 24);
PEEKD_ASSERT_OFFSET(exec_event, pdev, 32);
PEEKD_ASSERT_OFFSET(exec_event, pino, 40);
PEEKD_ASSERT_OFFSET(exec_event, filename, 80);

PEEKD_ASSERT_SIZE(dns_event, 272);
PEEKD_ASSERT_OFFSET(dns_event, name, 16);

PEEKD_ASSERT_SIZE(dns6_event, 296);
PEEKD_ASSERT_OFFSET(dns6_event, saddr, 4);
PEEKD_ASSERT_OFFSET(dns6_event, daddr, 20);
PEEKD_ASSERT_OFFSET(dns6_event, name, 40);

PEEKD_ASSERT_SIZE(connect_event_raw, 88);
PEEKD_ASSERT_OFFSET(connect_event_raw, ino, 32);
PEEKD_ASSERT_OFFSET(connect_event_raw, pino, 40);
PEEKD_ASSERT_OFFSET(connect_event_raw, pid, 48);
PEEKD_ASSERT_OFFSET(connect_event_raw, saddr, 68);
PEEKD_ASSERT_OFFSET(connect_event_raw, direction, 80);

PEEKD_ASSERT_SIZE(bpf_stat_event, 8);

#endif
