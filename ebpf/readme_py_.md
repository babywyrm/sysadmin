The eBPF (Extended Berkeley Packet Filter) language is a low-level assembly-like language that is specifically designed for writing programs that can be loaded into the Linux kernel. These programs are typically used for networking, security, and observability tasks.

##
#
https://gist.github.com/weshouman/2c99f38fd4d22510b13d493723b13147
#
##

eBPF has its own domain-specific language (DSL), following are some information about it.

Characteristics of eBPF DSL:
Low-Level: The language is closer to assembly than to high-level languages like C.

Limited Instructions: eBPF has a limited set of instructions to ensure that programs are safe to run in the kernel space. This includes a lack of certain types of loops to prevent infinite loops in the kernel.

Type-Safe: eBPF is designed to be type-safe to prevent common programming errors that could crash or compromise the system.

JIT Compilation: eBPF programs are Just-In-Time (JIT) compiled into native machine code for performance.

Safety Checks: Before being loaded into the kernel, eBPF programs are verified for safety to ensure they don't perform illegal operations.

Note: eBPF programs run in a restricted environment with a limited set of instructions and are verified for safety before being loaded into the kernel, they offer a way to extend kernel functionality without compromising system stability or security.

Writing and Compiling eBPF Programs:
Although one can write eBPF programs directly in its assembly-like DSL, it's more common and preferred to write them in a restricted subset of C, which is then compiled into eBPF bytecode using a specialized compiler (like LLVM with eBPF support).

Following is a simple example in C that could be compiled to eBPF bytecode:

DO NOT run this example on a remote machine.

#include <linux/bpf.h>

SEC("prog")
int dangerous_hello_world(void *ctx) {
    return XDP_DROP; // Drop all packets
}
Code breakdown:

This program uses the XDP (eXpress Data Path) hook to drop all incoming packets. The program would be compiled to eBPF bytecode using a compiler with eBPF support.

Note: XDP is a high-performance, programmable network data path in the Linux kernel.

Code Explanation:
#include <linux/bpf.h>: This line includes the header file for the eBPF library, which provides the necessary data structures and function prototypes.

SEC("prog"): This is an eBPF-specific macro that specifies the section name where this eBPF program will be placed. The section name is used when loading the program into the kernel.

int dangerous_hello_world(void *ctx): This is the main function of the eBPF program. It takes a single argument ctx, which is a pointer to the context containing the packet data and metadata.

return XDP_DROP;: This line specifies the action to be taken on the packet. In this case, XDP_DROP means that the packet will be dropped, i.e., it won't be forwarded to its destination.

What are the packets the example drops?
Here "packets" refer to network packets. When a packet arrives at a network interface (like an Ethernet port), the XDP framework can process it. This eBPF program is designed to drop all incoming packets, meaning they will not be processed further or forwarded to their intended destination.

In summary, this is a very basic eBPF program that drops all incoming network packets when loaded into the Linux kernel with the XDP framework.

Sections
The section names in eBPF programs, specified using the SEC macro, are not arbitrary; they indicate the type of program you're writing and where it should be attached in the kernel. These section names are generally standardized, and they correspond to specific hooks or tracepoints where the eBPF program will be executed.

Standard Sections
Here are some standard section names commonly used:

"filter": For XDP (eXpress Data Path) programs that operate on network packets.
"classifier": For tc (Traffic Control) programs that classify or modify network packets.
"tracepoint/[subsystem]/[event]": For attaching to kernel tracepoints. The [subsystem] and [event] are specific to what you want to trace.
"fentry/[function]" and "fexit/[function]": For attaching to the entry and exit points of kernel functions, respectively.
"sockops": For socket-level operations.
"cgroup/skb": For programs that operate on network packets and are attached to cgroups.
"cgroup/sock": For programs that operate on sockets and are attached to cgroups.
Custom Sections
While the section names are generally standardized, you can sometimes use custom section names if you're using a loading utility that allows for that. However, this is less common and usually not recommended unless you have a specific need for it.

Determining Sections
The section to be used depends on:

Type of Program: What you want the eBPF program to do (e.g., packet filtering, tracing, etc.).
Attachment Point: Where in the kernel you want to attach the eBPF program (e.g., XDP for network packets, tracepoints for tracing, etc.).
For example, if you're writing an XDP program to filter network packets, you'd typically use the "filter" section. If you're writing a program to attach to a tracepoint for the sched_switch event, you'd use "tracepoint/sched/sched_switch".

The section name helps the eBPF loader to understand where to place and how to attach your eBPF program in the kernel. Therefore, it's crucial to use the correct section name for your specific use-case.

examples.md
Following are illustrative examples and may require additional context, headers, or helper functions to be fully functional.

Networking
Packet Filtering: Originally designed for this purpose, eBPF can filter, modify, or redirect packets in the kernel.
Load Balancing: eBPF can be used to implement intelligent load-balancing algorithms.
Network Monitoring: Capture and analyze network packets for monitoring and debugging.
Networking: Packet Filtering
Drop all incoming packets.
```
SEC("filter")
int drop_all_packets(struct __sk_buff *skb) {
    return XDP_DROP;
}
Networking: Load Balancing
Redirect packets to another CPU core.

SEC("filter")
int redirect_to_cpu(struct __sk_buff *skb) {
    return bpf_redirect_map(&cpu_map, target_cpu, 0);
}
Networking: Network Monitoring
Count incoming packets.

struct bpf_map_def SEC("maps") packet_count = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 1,
};

SEC("filter")
int count_packets(struct __sk_buff *skb) {
    u32 index = 0;
    u64 *value;

    value = bpf_map_lookup_elem(&packet_count, &index);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }

    return XDP_PASS;
}
```
Security
System Call Filtering: eBPF can intercept system calls and apply security policies.
Process and File Auditing: Monitor and log process execution and file accesses.
Firewalling: Implementing advanced firewall rules based on various packet or flow attributes.
Security: System Call Filtering
Block the execve system call.
```
SEC("tracepoint/syscalls/sys_enter_execve")
int block_execve(struct trace_event_raw_sys_enter *ctx) {
    return 0; // Return 0 to block the system call
}
Security: Process and File Auditing
Log file opens.

SEC("tracepoint/syscalls/sys_enter_open")
int log_open(struct trace_event_raw_sys_enter *ctx) {
    // Log the file being opened (simplified)
    bpf_trace_printk("File opened: %s\n", ctx->args[0]);
    return 0;
}
Observability
Tracing: Trace kernel and user-space function calls for debugging or performance analysis.
Profiling: Collect performance data for system optimization.
Metrics Collection: Gather and report metrics for system monitoring.
Observability: Tracing
Trace function calls in the schedule function.

SEC("fentry/__schedule")
int trace_schedule(struct pt_regs *ctx) {
    bpf_trace_printk("Schedule function called\n");
    return 0;
}
Storage
IO Operations: Monitor or modify disk IO operations.
Caching Policies: Implement custom caching logic for storage systems.
Storage: IO Operations
Monitor read operations.

SEC("tracepoint/block/block_rq_issue")
int trace_block_rq_issue(struct trace_event_raw_block_rq_issue *ctx) {
    if (ctx->rwbs[0] == 'R') { // Read operation
        bpf_trace_printk("Read operation detected\n");
    }
    return 0;
}
```

Scheduling
CPU Pinning: Control the CPU affinity of processes.
Resource Allocation: Monitor and control how system resources like CPU and memory are allocated to different tasks.
Note: CPU Pinning is generally done using user-space tools to load an eBPF program that pins tasks to CPUs, so a direct eBPF example might not be applicable for it.

Custom Kernel Features
Kernel Extensions: Write custom, loadable kernel features without modifying the kernel source code.
Custom Kernel Features: Kernel Extensions
Add custom logic to packet handling.

SEC("filter")
int custom_logic(struct __sk_buff *skb) {
    // Add custom logic here
    return XDP_PASS;
}
Running Examples
File Auditing
Following is a step-by-step guide on how to run an eBPF program for file auditing. This example shall log file open operations using a tracepoint.

Prerequisites
A Linux system with a kernel version that supports eBPF (usually 4.8 or later)
clang and llvm (for compiling the eBPF code)
bcc (BPF Compiler Collection, for loading and running the eBPF program)
Root or sudo access (for loading the eBPF program into the kernel)
Step 1: Install Required Packages
Install clang, llvm, and bcc. The exact package names and installation commands may vary depending on your Linux distribution.

For Ubuntu:

sudo apt update
sudo apt install clang llvm bpfcc-tools linux-headers-$(uname -r)
For Fedora:

sudo dnf install clang llvm bcc-tools
Step 2: Write the eBPF Code
Create a file named file_audit.c and add the following code:

#include <uapi/linux/ptrace.h>
#include <linux/audit.h>

TRACEPOINT_PROBE(syscalls, sys_enter_open)
{
    char *filename = (char *)ctx->args[0];
    bpf_trace_printk("File opened: %s\n", filename);
    return 0;
}
Step 3: Compile the eBPF Code
Compile the code into eBPF bytecode using clang:

clang -O2 -I/usr/include/x86_64-linux-gnu -target bpf -c file_audit.c -o file_audit.o
Step 4: Load and Run the eBPF Program
You can use the trace tool from the bcc package to load and run the eBPF program. Create a file named file_audit.py and add the following code:

from bcc import BPF

# Load eBPF program
b = BPF(src_file="file_audit.c")

# Attach to the tracepoint
b.attach_tracepoint(tp="syscalls:sys_enter_open", fn_name="do_trace")

# Print output
while True:
    print(b.trace_fields())
Run the Python script as root:

sudo python file_audit.py
Step 5: Verify the Program is Running
Once the Python script is running, you should see output lines like:

File opened: /some/file/path
File opened: /another/file/path
...
This indicates that the eBPF program is successfully logging file open operations.

Edits for a real-world implementation:
Reading from User Space: Here we are trying to read a filename directly from a user-space pointer (char *filename = (char *)ctx->args[0];). This is generally not safe in eBPF programs because they run in kernel space and cannot access user-space memory directly in this manner. We usually need to use helper functions like bpf_probe_read to safely copy data from user space to kernel space.
Printing Strings: bpf_trace_printk is a function that can be used for debugging purposes, but it has limitations like the length of the string it can print.
We also would need to cover error handling, filtering, and further aspects.
Blocking Execution
Following is a guide on how to run an eBPF program that blocks the execve system call. In other words, preventing new processes from being started, so use this example with caution.

Prerequisites
A Linux system with a kernel version that supports eBPF (usually 4.8 or later)
clang and llvm (for compiling the eBPF code)
bcc (BPF Compiler Collection, for loading and running the eBPF program)
Root or sudo access (for loading the eBPF program into the kernel)
Step 1: Install Required Packages
Install clang, llvm, and bcc. The exact package names and installation commands may vary depending on your Linux distribution.

For Ubuntu:

sudo apt update
sudo apt install clang llvm bpfcc-tools linux-headers-$(uname -r)
For Fedora:

sudo dnf install clang llvm bcc-tools
Step 2: Write the eBPF Code
Create a file named block_execve.c and add the following code:

#include <uapi/linux/ptrace.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int block_execve(struct trace_event_raw_sys_enter *ctx) {
    return 0; // Return 0 to block the system call
}
Step 3: Compile the eBPF Code
Compile the code into eBPF bytecode using clang:

clang -O2 -I/usr/include/x86_64-linux-gnu -target bpf -c block_execve.c -o block_execve.o
Step 4: Load and Run the eBPF Program
You can use the trace tool from the bcc package to load and run the eBPF program. Create a file named block_execve.py and add the following code:
```
from bcc import BPF

# Load eBPF program
b = BPF(src_file="block_execve.c")

# Attach to the tracepoint
b.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="block_execve")

# Keep the program running
try:
    print("Blocking execve system calls. Press Ctrl+C to stop.")
    while True:
        pass
except KeyboardInterrupt:
    print("Stopping.")
```
Run the Python script as root:

sudo python block_execve.py
Step 5: Verify the Program is Running
Once the Python script is running, you should not be able to start new processes from a different terminal. Existing processes will continue to run.

Step 6: Stop the Program
You can stop the Python script by pressing Ctrl+C.

Caution
Blocking the execve system call will prevent new processes from being started, which could and probably would disrupt system functionality. Use this example carefully and understand the implications.
