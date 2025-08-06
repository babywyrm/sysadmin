#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// Max size for argv logging
#define ARGSIZE 128

struct event {
    u32 pid;
    char comm[16];
    char argv[ARGSIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("kprobe/__x64_sys_execve")
int handle_execve(struct pt_regs *ctx) {
    struct event evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    char *filename = (char *)PT_REGS_PARM1(ctx);
    bpf_probe_read_user_str(&evt.argv, sizeof(evt.argv), filename);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

//
//
