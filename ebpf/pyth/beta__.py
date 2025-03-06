#!/usr/bin/env python3

##
## https://python.org.il/en/presentations/secimport-tailor-made-ebpf-sandbox-for-python-applications
##

"""
eBPF-based Security Scanner for System Calls on Ubuntu Jammy

Installation & Prerequisites:
--------------------------------
1. **Ubuntu Jammy (22.04) or compatible**
2. **Python 3**: Ensure Python 3 is installed.
3. **BCC Library**:
   Install BCC tools and Python bindings with:
       sudo apt install bpfcc-tools libbpfcc-dev python3-bpfcc
4. **secimport Module (Optional)**:
   If you want to use secure module imports, install the hypothetical secimport module.
   (If not installed or not using it, the script will fall back to standard Python imports.)
5. **Privileges**:
   This script must be run with root privileges (e.g., via `sudo`) so that eBPF probes can be attached.

Usage:
------
    sudo ./ebpf_sec_scan.py [--pid <process_id>] [--use-secimport] [--demo-secimport]

Options:
    --pid           Monitor only the specified process ID (PID). If omitted, all syscalls are monitored.
    --use-secimport Use secimport for secure module importing.
    --demo-secimport  Run a demonstration of secimport in action.

Description:
-------------
This script attaches eBPF probes to selected system calls (e.g., ptrace, execve, socket, connect,
chmod, chown, mprotect) and prints a warning when any are detected. It demonstrates both standard 
and secure module importing via the --use-secimport option, and the --demo-secimport option shows a 
practical use of secure importing.
"""

import sys
import argparse
import importlib

# Parse early to check if we should use secure imports and run demo
early_parser = argparse.ArgumentParser(add_help=False)
early_parser.add_argument("--use-secimport", action="store_true", help="Use secimport for secure module importing")
early_parser.add_argument("--demo-secimport", action="store_true", help="Run a demonstration of secimport in action")
early_args, remaining_argv = early_parser.parse_known_args()
USE_SECIMPORT = early_args.use_secimport
DEMO_SECIMPORT = early_args.demo_secimport

def maybe_secure_import(module_name):
    """
    Conditionally import a module using secimport if USE_SECIMPORT is True.
    If secimport is not available or not used, fall back to standard import.
    """
    if USE_SECIMPORT:
        try:
            import secimport
            return secimport.secure_import(module_name)
        except ImportError:
            print(f"[!] secimport not found; falling back to standard import for {module_name}")
            return importlib.import_module(module_name)
    else:
        return importlib.import_module(module_name)

# Securely import required modules using maybe_secure_import
BPF = maybe_secure_import("bcc").BPF  # bcc.BPF is required from the bcc package
argparse = maybe_secure_import("argparse")
signal = maybe_secure_import("signal")
os = maybe_secure_import("os")  # Will be used in demo if needed

# Re-parse full arguments with our early parser as parent.
parser = argparse.ArgumentParser(
    description="eBPF-based Security Scanner: Monitor suspicious syscalls on Ubuntu Jammy.",
    parents=[early_parser]
)
parser.add_argument("--pid", type=int, default=0, help="Monitor only the specified process ID (PID).")
args = parser.parse_args()

def demo_secimport_usage():
    """
    Demonstrates the use of secimport by securely importing and using the 'os' module.
    For this demo, we print system information using os.uname().
    """
    print("[*] Running secimport demonstration...")
    try:
        # 'os' has already been imported securely above.
        sys_info = os.uname()
        print("[*] Securely imported os module. System information:")
        print(f"    System: {sys_info.sysname}")
        print(f"    Node Name: {sys_info.nodename}")
        print(f"    Release: {sys_info.release}")
        print(f"    Version: {sys_info.version}")
        print(f"    Machine: {sys_info.machine}")
    except Exception as e:
        print(f"[!] Error during secimport demo: {e}")

# If demo flag is set, run the demonstration
if DEMO_SECIMPORT:
    demo_secimport_usage()

# List of suspicious syscalls to monitor
suspicious_syscalls = [
    "ptrace",    # May indicate debugging or process injection
    "execve",    # Execution of new binaries
    "socket",    # Opening new network sockets
    "connect",   # Outgoing network connections
    "chmod",     # Changing file permissions
    "chown",    # Changing file ownership
    "mprotect",  # Memory protection changes (e.g., code injection)
]

# eBPF C program that attaches to sys_enter events and checks syscall numbers.
# In a real-world implementation, a full syscall number to name mapping might be used.
bpf_program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char syscall[16];
};

BPF_PERF_OUTPUT(events);

int trace_sys_enter(struct pt_regs *ctx, int id) {
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid();
    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Check syscall id against our suspicious syscalls.
    if (id == __NR_ptrace) {
        __builtin_memcpy(&data.syscall, "ptrace", 7);
    } else if (id == __NR_execve) {
        __builtin_memcpy(&data.syscall, "execve", 7);
    } else if (id == __NR_socket) {
        __builtin_memcpy(&data.syscall, "socket", 7);
    } else if (id == __NR_connect) {
        __builtin_memcpy(&data.syscall, "connect", 8);
    } else if (id == __NR_chmod) {
        __builtin_memcpy(&data.syscall, "chmod", 7);
    } else if (id == __NR_chown) {
        __builtin_memcpy(&data.syscall, "chown", 7);
    } else if (id == __NR_mprotect) {
        __builtin_memcpy(&data.syscall, "mprotect", 9);
    } else {
        return 0;
    }
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Create the BPF object and load the program.
b = BPF(text=bpf_program)

# Attach a kprobe for each suspicious syscall.
for name in suspicious_syscalls:
    try:
        # Attach to "sys_<name>" probe.
        b.attach_kprobe(event=f"sys_{name}", fn_name="trace_sys_enter")
    except Exception as e:
        print(f"[!] Failed to attach to sys_{name}: {e}")

print("eBPF Security Scanner running... Press Ctrl+C to exit.")
if args.pid:
    print(f"Filtering events for PID: {args.pid}")

# Callback function to handle events from the kernel.
def print_event(cpu, data, size):
    event = b["events"].event(data)
    if args.pid and event.pid != args.pid:
        return
    # Print the event details.
    print(f"Suspicious syscall detected: {event.comm.decode('utf-8', 'replace')} (PID {event.pid}) - {event.syscall.decode('utf-8', 'replace')}")

# Set up signal handler for graceful termination.
def signal_handler(sig, frame):
    print("\nExiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Open the perf buffer and poll for events.
b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break

##
##

"""
Install Prerequisites:

sudo apt update
sudo apt install bpfcc-tools libbpfcc-dev python3-bpfcc
# (Optional) Install the secimport module if available.

Run the Script:
To monitor all processes using standard imports:
sudo ./ebpf_sec_scan.py

To filter by a specific PID (e.g., 12345):
sudo ./ebpf_sec_scan.py --pid 12345

To use secure module importing:
sudo ./ebpf_sec_scan.py --use-secimport

To see the secimport demo and then run the scanner:
sudo ./ebpf_sec_scan.py --use-secimport --demo-secimport
