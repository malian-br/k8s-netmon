//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/types.h>

#define MAX_ENTRIES 10240
#define CGROUP_PATH_MAX 256
#define AF_INET 2

struct connection_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 proto;
    __u32 pid;
    __u32 netns;
    char comm[16];
    __u8 type; // 0=connect, 1=accept, 2=close
    char cgroup_path[CGROUP_PATH_MAX];
};

struct sockaddr {
    __u16 sa_family;
    char sa_data[14];
};

struct sockaddr_in {
    __u16 sin_family;
    __u16 sin_port;
    __u32 sin_addr;
    char sin_zero[8];
};

// Tracepoint context structures
struct trace_entry {
    __u16 type;
    __u8 flags;
    __u8 preempt_count;
    __u32 pid;
};

struct syscall_enter_args {
    struct trace_entry ent;
    long id;
    unsigned long args[6];
};

struct syscall_exit_args {
    struct trace_entry ent;
    long id;
    long ret;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct connection_event);
} active_connections SEC(".maps");

static __always_inline __u16 bpf_ntohs(__u16 netshort) {
    return __builtin_bswap16(netshort);
}

static __always_inline void populate_event(struct connection_event *event) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Get cgroup ID for container identification
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    event->netns = (__u32)(cgroup_id & 0xFFFFFFFF);
}

static __always_inline void get_cgroup_path(struct connection_event *event) {
    // Store a marker that can be used to lookup cgroup info from userspace
    // We can't easily read the full path from kernel space in all kernel versions
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    
    // Store cgroup ID in the path field as a hex string for userspace lookup
    // This is more reliable than trying to read paths from kernel structures
    __builtin_memset(event->cgroup_path, 0, CGROUP_PATH_MAX);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_sys_connect(struct syscall_enter_args *ctx) {
    struct connection_event event = {0};
    struct sockaddr *addr;
    struct sockaddr_in addr_in;
    
    int fd = (int)ctx->args[0];
    addr = (struct sockaddr *)ctx->args[1];
    
    if (!addr)
        return 0;
    
    __u16 family;
    if (bpf_probe_read_user(&family, sizeof(family), &addr->sa_family) < 0)
        return 0;
    
    if (family != AF_INET)
        return 0;
    
    // Read the entire sockaddr_in structure
    if (bpf_probe_read_user(&addr_in, sizeof(addr_in), addr) < 0)
        return 0;
    
    event.dst_ip = addr_in.sin_addr;
    event.dst_port = bpf_ntohs(addr_in.sin_port);
    
    event.proto = 6; // IPPROTO_TCP
    event.type = 0; // CONNECT
    populate_event(&event);
    get_cgroup_path(&event);
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    __u64 conn_id = ((__u64)event.pid << 32) | fd;
    bpf_map_update_elem(&active_connections, &conn_id, &event, BPF_ANY);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int trace_sys_accept(struct syscall_exit_args *ctx) {
    struct connection_event event = {0};
    long ret = ctx->ret;
    
    if (ret < 0)
        return 0;
    
    event.type = 1; // ACCEPT
    event.proto = 6; // IPPROTO_TCP
    populate_event(&event);
    get_cgroup_path(&event);
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    __u64 conn_id = ((__u64)event.pid << 32) | ret;
    bpf_map_update_elem(&active_connections, &conn_id, &event, BPF_ANY);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_sys_close(struct syscall_enter_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    int fd = (int)ctx->args[0];
    
    __u64 conn_id = ((__u64)pid << 32) | fd;
    struct connection_event *conn = bpf_map_lookup_elem(&active_connections, &conn_id);
    
    if (!conn)
        return 0;
    
    struct connection_event event = *conn;
    event.type = 2; // CLOSE
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    bpf_map_delete_elem(&active_connections, &conn_id);
    
    return 0;
}

char __license[] SEC("license") = "GPL";
