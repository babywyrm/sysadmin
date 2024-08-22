package main

//
//
// idk this died
//
//

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "io/ioutil"
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/perf"
    "github.com/cilium/ebpf/rlimit"
)

const bpfProgramFile = "/tmp/syscall_monitor.bpf"

// Go struct that matches the eBPF event structure
type event struct {
    PID       uint32
    SyscallNr uint32
}

func main() {
    // Allow the current process to lock memory for eBPF maps
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatalf("failed to remove memory limit: %v", err)
    }

    // Load and compile the eBPF program
    file, err := os.Open(bpfProgramFile)
    if err != nil {
        log.Fatalf("failed to open BPF program file: %v", err)
    }
    defer file.Close()

    spec, err := ebpf.LoadCollectionSpec(file)
    if err != nil {
        log.Fatalf("failed to load BPF program: %v", err)
    }

    objs := struct {
        Program *ebpf.Program `ebpf:"syscall__enter"`
        Events  *ebpf.Map     `ebpf:"events"`
    }{}

    if err := spec.LoadAndAssign(&objs, nil); err != nil {
        log.Fatalf("failed to load BPF objects: %v", err)
    }
    defer objs.Program.Close()
    defer objs.Events.Close()

    // Attach the eBPF program to the syscall entry point
    kprobe, err := link.Kprobe("sys_enter", objs.Program, nil)
    if err != nil {
        log.Fatalf("failed to attach kprobe: %v", err)
    }
    defer kprobe.Close()

    // Set up a perf reader to read events from the eBPF program
    rd, err := perf.NewReader(objs.Events, os.Getpagesize())
    if err != nil {
        log.Fatalf("failed to create perf event reader: %v", err)
    }
    defer rd.Close()

    fmt.Println("Listening for syscalls...")

    // Handle SIGINT and SIGTERM for graceful shutdown
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        <-sig
        fmt.Println("Exiting...")
        rd.Close()
        os.Exit(0)
    }()

    // Read events from the perf buffer
    for {
        record, err := rd.Read()
        if err != nil {
            if err == perf.ErrClosed {
                return
            }
            log.Fatalf("failed to read from perf reader: %v", err)
        }

        var evt event
        if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
            log.Fatalf("failed to decode received data: %v", err)
        }

        fmt.Printf("PID: %d, Syscall: %d\n", evt.PID, evt.SyscallNr)
    }
}
