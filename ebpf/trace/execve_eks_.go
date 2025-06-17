// exec_monitor.go
// Monitoring new process launches (execve) via eBPF + Go (BCC) .. testing ..
// Kubernetes Pod context enrichment for EKS
// Prerequisites:
//   - Linux kernel 4.9+ with BPF support
//   - Install BCC tools and headers:
//       sudo apt-get install -y bpfcc-tools libbcc-dev linux-headers-$(uname -r)
//   - Go modules:
//       go get github.com/iovisor/gobpf/bcc
//       go get k8s.io/client-go@latest k8s.io/apimachinery@latest
//
// Usage:
//   go build -o exec_monitor exec_monitor.go
//   sudo ./exec_monitor [-debug] [-verbose]
//
// Note: To run inside a Kubernetes cluster, ensure your Pod has
//       RBAC permission to list Pods (ClusterRole or Role/RoleBinding).

package main

import (
    "bufio"
    "bytes"
    "context"
    "encoding/binary"
    "flag"
    "fmt"
    "log"
    "os"
    "os/signal"
    "path/filepath"
    "regexp"
    "syscall"

    bpf "github.com/iovisor/gobpf/bcc"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/rest"
)

// ExecEvent matches the struct defined in the eBPF program below
// It contains the PID, parent PID, and process name (comm)
type ExecEvent struct {
    Pid  uint32
    Ppid uint32
    Comm [16]byte
}

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
    debugMode   = flag.Bool("debug", false, "enable debug logging")
    verboseMode = flag.Bool("verbose", false, "enable verbose event output")
    // regex to extract Kubernetes Pod UID from cgroup path (e.g. pod<uid>)
    podRegex    = regexp.MustCompile(`pod([0-9a-f\-]+)`)    
)

func main() {
    // Parse CLI flags
    flag.Parse()
    if *debugMode {
        log.Println("Debug: starting in debug mode")
    }
    if *verboseMode {
        log.Println("Verbose: detailed event output enabled")
    }

    // 1) Compile & load the eBPF program
    if *debugMode {
        log.Println("Debug: loading BPF module...")
    }
    module := bpf.NewModule(source, []string{})
    defer module.Close()

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

    // 2) Set up perf buffer to receive events
    table := bpf.NewTable(module.TableId("events"), module)
    perfMap, err := bpf.InitPerfBuf(table, handleRecord, nil)
    if err != nil {
        log.Fatalf("Failed to init perf buffer: %v", err)
    }
    defer perfMap.Close()
    go perfMap.Poll(nil)
    if *debugMode {
        log.Println("Debug: perf buffer initialized")
    }

    // 3) Wait for Ctrl-C to exit
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

    fmt.Println("Tracing execve() with Pod context — press Ctrl-C to exit")
    <-sig
    fmt.Println("\nReceived signal, exiting…")
}

// handleRecord is called for each perf event record
func handleRecord(record []byte, cpu int) {
    if *verboseMode {
        log.Printf("Verbose: CPU %d record bytes: %d", cpu, len(record))
    }
    var e ExecEvent
    if err := binary.Read(bytes.NewBuffer(record), binary.LittleEndian, &e); err != nil {
        log.Printf("ERROR: failed to parse event: %v", err)
        return
    }

    // Lookup Pod info (namespace/name) via cgroup
    ns, name := getPodInfo(int(e.Pid))
    comm := string(bytes.Trim(e.Comm[:], "\x00"))
    if name != "" {
        fmt.Printf("[exec] Pod %s/%s PID %d (PPID %d) => %s\n", ns, name, e.Pid, e.Ppid, comm)
    } else {
        fmt.Printf("[exec] PID %d (PPID %d) => %s\n", e.Pid, e.Ppid, comm)
    }
}

// getPodInfo reads /proc/<pid>/cgroup to find the Pod UID and then queries the
// Kubernetes API for namespace and name. Returns empty strings on failure.
func getPodInfo(pid int) (string, string) {
    path := filepath.Join("/proc", fmt.Sprint(pid), "cgroup")
    f, err := os.Open(path)
    if err != nil {
        if *debugMode {
            log.Printf("DEBUG: open cgroup for PID %d failed: %v", pid, err)
        }
        return "", ""
    }
    defer f.Close()

    scanner := bufio.NewScanner(f)
    var podUID string
    for scanner.Scan() {
        line := scanner.Text()
        if matches := podRegex.FindStringSubmatch(line); len(matches) == 2 {
            podUID = matches[1]
            if *verboseMode {
                log.Printf("Verbose: found pod UID %s in cgroup line: %s", podUID, line)
            }
            break
        }
    }
    if podUID == "" {
        return "", ""
    }

    // In-cluster Kubernetes config
    config, err := rest.InClusterConfig()
    if err != nil {
        if *debugMode {
            log.Printf("DEBUG: InClusterConfig failed: %v", err)
        }
        return "", ""
    }
    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        if *debugMode {
            log.Printf("DEBUG: NewForConfig failed: %v", err)
        }
        return "", ""
    }

    // List pods filtered by UID
    pods, err := clientset.CoreV1().Pods(metav1.NamespaceAll).
        List(context.TODO(), metav1.ListOptions{FieldSelector: "metadata.uid=" + podUID})
    if err != nil || len(pods.Items) == 0 {
        if *debugMode {
            log.Printf("DEBUG: Pod lookup for UID %s failed or not found: %v", podUID, err)
        }
        return "", ""
    }
    pod := pods.Items[0]
    return pod.Namespace, pod.Name
}
//
//
