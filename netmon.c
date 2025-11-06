//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define MAX_ENTRIES 10240
#define CGROUP_PATH_MAX 256

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

static __always_inline void populate_event(struct connection_event *event) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Get network namespace
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        // Network namespace inode number
        BPF_CORE_READ_INTO(&event->netns, task, nsproxy, net_ns, ns.inum);
    }
}

static __always_inline void get_cgroup_path(struct connection_event *event) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // Get cgroup path - this helps identify the container
    // The path typically contains container ID for Docker/containerd/CRI-O
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    
    // Try to read cgroup path from task struct
    // Note: This is a simplified approach. In production, you might want to
    // use bpf_get_current_cgroup_id() and map it to paths in userspace
    char path[CGROUP_PATH_MAX] = {0};
    
    // Use helper to get cgroup path if available (kernel 5.10+)
    #ifdef BPF_FUNC_get_current_cgroup_path
    long ret = bpf_get_current_cgroup_path(path, sizeof(path));
    if (ret >= 0) {
        __builtin_memcpy(event->cgroup_path, path, CGROUP_PATH_MAX);
        return;
    }
    #endif
    
    // Fallback: store cgroup ID which can be resolved in userspace
    // This is more reliable across kernel versions
    bpf_probe_read_kernel_str(event->cgroup_path, sizeof(event->cgroup_path), "/proc/self/cgroup");
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_sys_connect(struct trace_event_raw_sys_enter *ctx) {
    struct connection_event event = {0};
    struct sockaddr *addr;
    struct sockaddr_in *addr_in;
    
    int fd = (int)ctx->args[0];
    addr = (struct sockaddr *)ctx->args[1];
    
    if (!addr)
        return 0;
    
    __u16 family;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
    
    if (family != AF_INET)
        return 0;
    
    addr_in = (struct sockaddr_in *)addr;
    
    bpf_probe_read_user(&event.dst_ip, sizeof(event.dst_ip), &addr_in->sin_addr.s_addr);
    bpf_probe_read_user(&event.dst_port, sizeof(event.dst_port), &addr_in->sin_port);
    event.dst_port = __bpf_ntohs(event.dst_port);
    
    event.proto = IPPROTO_TCP;
    event.type = 0; // CONNECT
    populate_event(&event);
    get_cgroup_path(&event);
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    __u64 conn_id = ((__u64)event.pid << 32) | fd;
    bpf_map_update_elem(&active_connections, &conn_id, &event, BPF_ANY);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int trace_sys_accept(struct trace_event_raw_sys_exit *ctx) {
    struct connection_event event = {0};
    long ret = ctx->ret;
    
    if (ret < 0)
        return 0;
    
    event.type = 1; // ACCEPT
    event.proto = IPPROTO_TCP;
    populate_event(&event);
    get_cgroup_path(&event);
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    __u64 conn_id = ((__u64)event.pid << 32) | ret;
    bpf_map_update_elem(&active_connections, &conn_id, &event, BPF_ANY);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_sys_close(struct trace_event_raw_sys_enter *ctx) {
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