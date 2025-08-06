package main

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "os"
    "os/signal"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/perf"
    "golang.org/x/sys/unix"
)

// Include compiled eBPF objects
import "exec-tracer/bpf"

type Event struct {
    PID  uint32
    Comm [16]byte
    Argv [128]byte
}

func main() {
    // Load compiled eBPF objects
    objs := bpf.TracerObjects{}
    if err := bpf.LoadTracerObjects(&objs, nil); err != nil {
        panic(err)
    }
    defer objs.Close()

    // Attach kprobe
    kp, err := link.Kprobe("execve", objs.HandleExecve, nil)
    if err != nil {
        panic(err)
    }
    defer kp.Close()

    // Open perf buffer to receive events
    reader, err := perf.NewReader(objs.Events, os.Getpagesize())
    if err != nil {
        panic(err)
    }
    defer reader.Close()

    fmt.Println("[*] Listening for execve() events...")

    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt)

    go func() {
        for {
            record, err := reader.Read()
            if err != nil {
                if err == perf.ErrClosed {
                    return
                }
                panic(err)
            }

            var evt Event
            if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &evt); err != nil {
                fmt.Println("error parsing event:", err)
                continue
            }

            fmt.Printf("[execve] pid=%d cmd=%s argv=%s\n",
                evt.PID,
                bytes.Trim(evt.Comm[:], "\x00"),
                bytes.Trim(evt.Argv[:], "\x00"))
        }
    }()

    <-sig
    fmt.Println("Exiting...")
}
