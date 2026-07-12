
##
#
https://fedepaol.github.io/blog/2023/08/21/ebpf-journey-by-examples-ebpf-tracepoints-with-falco/
#
https://medium.com/@ridhoadya/exploring-ebpf-empowering-devops-with-falco-and-kubearmor-830669bc0fd5
#
https://medium.com/@simardeep.oberoi/falco-a-deep-dive-into-runtime-security-alerting-12ac2eb7160d
#
https://thekubeguy.com/understanding-falco-the-secret-to-bulletproof-kubernetes-security-1c85fa84f4ee
#
https://about.gitlab.com/blog/2022/01/20/securing-the-container-host-with-falco/
#

#

#
##


eBPF journey by examples: eBPF tracepoints with Falco
 August 21, 2023  7-minute read
Learning from existing projects 
This is the first post of my journey into learning eBPF by samples. My idea here is to dig into how popular projects use eBPF to solve various problems, in order to benefit from real implementations and leverage existing scenarios rather than simple tutorials.

I will proceed as follows:

I will dig into the source code of each project I am examining, trying to understand both the logic of the project itself but most importantly the ebpf bits
I will try to list the relevant code and review it
I will implement a simplified version of the relevant logic using go for the user space logic
In the spirit of covering the Pareto’s 80%, I won’t:

dig specific corner cases, special scenarios, as my intent is to get a grip on ebpf and not the specific verifier issue that was addressed
go beyond the map side of things on the user space side. I will try to limit the exploration of the userspace side of things on how the ebpf is used to solve the business problem
I already have a list of projects under my radar, which consists of some picks from those listed under ebpf.io, which I won’t disclose as I might find that the code is too complex to be explained in a single blogpost.

My bet on this activity is that the ebpf side of things will be contained enough to be easy to understand and explain, but of course I might be wrong.

The first guinea pig: Falco 
Falco (https://falco.org/) is a cloud-native security tool designed for Linux systems. It works by collecting events from the kernel and using them in a way that they can be interpreted to understand if there is some component in the system that is not behaving as it should from a security point of view.

Falco collects the events using different drivers (a kernel module based one, and two based on ebpf). Here I will focus on the modern ebpf implementation. The userspace side is implemented in C and exposed as a library that can be consumed by the external engine.

How falco collect syscalls events with EBPF 
Leaving corner cases aside, Falco uses the sys_enter / sys_exit ebpf tracepoint listeners that are invoked whenever a program enters / leaves a syscall.

There are two ebpf programs, one for sys_enter and the other for sys_exit:

SEC("tp_btf/sys_enter")
int BPF_PROG(sys_enter,
         struct pt_regs *regs,
         long syscall_id)
{
    ...
}
SEC("tp_btf/sys_exit")
int BPF_PROG(sys_exit,
         struct pt_regs *regs,
         long syscall_id)
{
    ...
}
BPF_PROG is a convenience macro to allow the programmer to explode the parameters instead of having to convert the ctx parameter to the right structure. The arguments are the ones the tracepoint is defined with. Finally, the sysdig blog has an excellent article on how to translate the pt_regs values into the real arguments passed to the syscall here.

What each entry point does, is to use the syscall_id parameter, which is the id of the syscall being invoked, in conjunction with a table binding the id and the corresponding ebpf program:

bpf_tail_call(ctx, &syscall_enter_tail_table, syscall_id);
bpf_tail_call is a bpf helper function that takes a map of type BPF_MAP_TYPE_PROG_ARRAY (map id -> bpf program) and performs a tail call invoking the program referenced by the third parameter.

The logic to fill the table is quite complex, but what we eventually get is an id - ebpf program mapping to be used by the tail call. For example, if we focus on the open syscall, the corresponding original entry is:

    [PPME_SYSCALL_OPEN_E] = {"open", EC_FILE | EC_SYSCALL, EF_CREATES_FD | EF_MODIFIES_STATE, 3, {{"name", PT_FSPATH, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, file_flags}, {"mode", PT_UINT32, PF_OCT} } },
    [PPME_SYSCALL_OPEN_X] = {"open", EC_FILE | EC_SYSCALL, EF_CREATES_FD | EF_MODIFIES_STATE, 6, {{"fd", PT_FD, PF_DEC}, {"name", PT_FSPATH, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, file_flags}, {"mode", PT_UINT32, PF_OCT}, {"dev", PT_UINT32, PF_HEX}, {"ino", PT_UINT64, PF_DEC} } },
Let’s have a look at the open handler 
The full code can be found here.

This is the sys_enter bit, the sys_exit is quite similar and contains the return value too.

SEC("tp_btf/sys_enter")
int BPF_PROG(open_e,
         struct pt_regs *regs,
         long id)
{
    struct auxiliary_map *auxmap = auxmap__get(); // (1)
    if(!auxmap)
    {
        return 0;
    }

    auxmap__preload_event_header(auxmap, PPME_SYSCALL_OPEN_E); // (2)

    /*=============================== COLLECT PARAMETERS  ===========================*/

    /* Parameter 1: name (type: PT_FSPATH) */
    unsigned long name_pointer = extract__syscall_argument(regs, 0);
    auxmap__store_charbuf_param(auxmap, name_pointer, MAX_PATH, USER);

    /* Parameter 2: flags (type: PT_FLAGS32) */
    u32 flags = (u32)extract__syscall_argument(regs, 1);
    auxmap__store_u32_param(auxmap, open_flags_to_scap(flags));

    /* Parameter 3: mode (type: PT_UINT32) */
    unsigned long mode = extract__syscall_argument(regs, 2);
    auxmap__store_u32_param(auxmap, open_modes_to_scap(flags, mode));

    /*=============================== COLLECT PARAMETERS  ===========================*/

    auxmap__finalize_event_header(auxmap);

    auxmap__submit_event(auxmap, ctx); // (3)

    return 0;
}
What the program does is:

a generic data structure auxiliary_map that is fetched from a per-cpu map (1).
a per-event header is filled (2), with generic informations such as the event type, the number of parameters, the process id and the time stamp.
the parameters of the syscall are collected from the regs parameter (the COLLECT PARAMETERS section)
the event is sent to userspace (3) via a per-cpu ringbuffer
The user space code will then collect the event from the ringbuffer and react accordingly to the configured policies.

The codebase is pretty wide, and full of helpers that facilitate the life of the developers (plus, it reflects the effort put into overcoming challenges while working with the verifier), but this should help understanding how all those events are collected and consumed in order to implement elaborate scraping logic.

I came across this article from Andrii Nakryiko’s blog, on how cool and more convenient bpf-ringbuf is compared to bpf-perfbuf.

Poor man’s version 
Here I will try to reimplement the current logic with a simple example that checks whenever a given process opens a file and sends an event to the userspace with the path, the command and the process that opened that file.

Tracepoint based implementation 
The code available at https://github.com/fedepaol/ebpfexamples/tree/main/opentracepoint.

Instead of doing the generic sys_entry / specific program via tail call jump done by falco, my example consumes directly the /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat tracepoint.

struct openat_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int __syscall_nr;
    int dfd;
    const char * filename;
    int flags;
    umode_t mode;
};

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(const struct openat_ctx *ctx) {
    struct event *event = 0;
    event = bpf_ringbuf_reserve(&ring_buffer, sizeof(struct event), 0);
    if (!event) {
        return 0;
    }
    bpf_probe_read_str(&event->path, sizeof(event->path), (void *) ctx->filename);

    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->command, sizeof(event->command));
    bpf_ringbuf_submit(event, 0);
    return 0;
}
Using the syscalls/sys_enter_openat tracepoint allows us to take the struct parameter described at /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format as context, which makes it easier to write the program as no parameter conversion is required.

The go side is copied inspired from the cilium/ebpf examples and probably less interesting (load the program, read and print from the ring buffer), but is a starting point to collect the data that might be digested by some more complex system.

KProbe based implementation 
Code available at https://github.com/fedepaol/ebpfexamples/tree/main/openkprobe.

The kprobe implementation is quite similar. The kprobe handler is architecture dependant so I had to specify the target to build the objects for. Additionally, the context in this case is struct pt_regs* and I had to use the PT_REGS_PARM2_CORE to read the openat second parameter (the filename):

SEC("kprobe/sys_openat")
int BPF_KPROBE(kprobe_openat, struct pt_regs *regs) {
    struct event *event = 0;
    event = bpf_ringbuf_reserve(&ring_buffer, sizeof(struct event), 0);
    if (!event) {
        return 0;
    }
    char *pathname;
    pathname = (char*) PT_REGS_PARM2_CORE(regs);
    bpf_probe_read_str(&event->path, sizeof(event->path), (void *) pathname);

    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->command, sizeof(event->command));
    bpf_ringbuf_submit(event, 0);
    return 0;
}
Wrapping up 
Falco’s eBPF driver leverages eBPF tracepoints to add syscalls listeners to the kernel, in order to collect the various events and feed its engine. The driver is way more complex than my examples, handles special cases, failure scenarios, multiple cpus, but I hope I got a decent understanding of how it works while digging into the code.

Also, my two eBPF kprobe and tracepoint examples are ready for consumptions (and open for reviews!).

If something is not accurate, please leave a comment and I will be more than happy to amend. I certainly learned new things along the way.
