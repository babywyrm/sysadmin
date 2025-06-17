// exec_monitor.go
// Monitoring new process launches (execve) via eBPF + Go (BCC) .. testing ..
//
// Prerequisites:
//   - Linux kernel 4.9+ with BPF support
//   - Install BCC tools and headers:
//       sudo apt-get install -y bpfcc-tools libbcc-dev linux-headers-$(uname -r)
//   - Go modules:
//       go get github.com/iovisor/gobpf/bcc
//
// Usage:
//   go build -o exec_monitor exec_monitor.go
//   sudo ./exec_monitor [-debug]

package main

import (
    "bytes"
    "encoding/binary"
    "flag"
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"

    bpf "github.com/iovisor/gobpf/bcc"
)

// ExecEvent matches the struct defined in the eBPF program below
// It contains the PID, parent PID, and process name (comm)
type ExecEvent struct {
    Pid  uint32
    Ppid uint32
    Comm [16]byte
}

// BPF source code: attaches to the execve syscall tracepoint
const source string = `
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct exec_event {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct exec_event evt = {};
    evt.pid  = bpf_get_current_pid_tgid() >> 32;
    evt.ppid = bpf_get_current_ppid();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
`

var (
    debugMode = flag.Bool("debug", false, "enable debug logging")
)

// printEvent formats and prints an ExecEvent
func printEvent(e *ExecEvent) {
    comm := string(bytes.Trim(e.Comm[:], "\x00"))
    fmt.Printf("[exec] PID %d (PPID %d) => %s\n", e.Pid, e.Ppid, comm)
}

// handleRecord is called for each perf record received
func handleRecord(record []byte, cpu int) {
    var e ExecEvent
    if err := binary.Read(bytes.NewBuffer(record), binary.LittleEndian, &e); err != nil {
        log.Printf("ERROR: failed to parse event: %v", err)
        return
    }
    printEvent(&e)
}

func main() {
    // Parse command-line flags
    flag.Parse()
    if *debugMode {
        log.Println("Debug: starting in debug mode")
    }

    // 1) Compile & load the eBPF program
    if *debugMode {
        log.Println("Debug: loading BPF module...")
    }
    module := bpf.NewModule(source, []string{})
    defer module.Close()

    // 2) Load and attach the execve tracepoint
    tpFD, err := module.LoadTracepoint("syscalls:sys_enter_execve")
    if err != nil {
        log.Fatalf("Failed to load tracepoint: %v", err)
    }
    if err := module.AttachTracepoint("syscalls:sys_enter_execve", tpFD); err != nil {
        log.Fatalf("Failed to attach tracepoint: %v", err)
    }
    if *debugMode {
        log.Println("Debug: tracepoint sys_enter_execve attached")
    }

    // 3) Initialize perf buffer to receive events
    table := bpf.NewTable(module.TableId("events"), module)
    perfMap, err := bpf.InitPerfBuf(table, handleRecord, nil)
    if err != nil {
        log.Fatalf("Failed to init perf buffer: %v", err)
    }
    defer perfMap.Close()
    if *debugMode {
        log.Println("Debug: perf buffer initialized")
    }

    // 4) Listen for SIGINT/SIGTERM to gracefully exit
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

    // 5) Start polling in a separate goroutine
    go perfMap.Poll(nil)

    fmt.Println("Tracing execve() — press Ctrl-C to exit")
    <-sig  // wait for user to interrupt

    fmt.Println("\nReceived signal, exiting...")
}

//
//
