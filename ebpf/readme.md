
# Getting Started with eBPF in Go ..beta..

eBPF lets you run sandboxed programs in the Linux kernel without writing kernel modules or patching kernel source. Originally extended from the classic Berkeley Packet Filter, it's grown into a general-purpose kernel programmability layer used in networking, observability, tracing, and security.

This guide walks through building a minimal but real eBPF-powered Go application from scratch — one that attaches to an XDP hook and counts packets on a network interface. We'll use [`cilium/ebpf`](https://github.com/cilium/ebpf) and `bpf2go` to keep everything in pure Go, no external build orchestration needed.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Linux kernel ≥ 5.7 | Required for `bpf_link` support |
| LLVM/Clang ≥ 11 | `clang` + `llvm-strip` — check with `clang --version` |
| `libbpf` headers | `libbpf-dev` (Debian/Ubuntu) or `libbpf-devel` (Fedora) |
| Linux kernel headers | `linux-headers-amd64` (Debian) / `kernel-devel` (Fedora) |
| Go ≥ 1.21 | Any version supported by `cilium/ebpf`'s go.mod |

> **Debian/Ubuntu note:** You may need to symlink the ASM headers:
> ```bash
> ln -sf /usr/include/asm-generic/ /usr/include/asm
> ```

---

## Project Structure

```text
ebpf-counter/
├── counter.c      # eBPF C program
├── gen.go         # go:generate directive for bpf2go
├── main.go        # Go userspace application
├── go.mod
└── go.sum
```

---

## The eBPF C Program

eBPF programs are written in a restricted subset of C and compiled to eBPF bytecode. They run inside the kernel in a verified, sandboxed environment — the verifier ensures no unbounded loops, no invalid memory access, no crashing the kernel.

Save this as `counter.c`:

```c
//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// BPF_MAP_TYPE_ARRAY is a fixed-size array map residing in kernel memory.
// Userspace and the eBPF program both have read/write access to it.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_count SEC(".maps");

// SEC("xdp") tells the compiler to place this function in the "xdp" ELF
// section. The loader uses section names to determine program type and
// attach point.
SEC("xdp")
int count_packets(struct xdp_md *ctx) {
    __u32 key    = 0;

    // bpf_map_lookup_elem returns a pointer directly into kernel map memory.
    // Never dereference without a NULL check — the verifier will reject it.
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key);

    if (count) {
        // Use atomic add — multiple CPUs may hit this simultaneously.
        // eBPF on multi-core systems runs per-CPU, so races are real.
        __sync_fetch_and_add(count, 1);
    }

    // XDP_PASS hands the packet up to the normal kernel networking stack.
    // Other options: XDP_DROP (discard), XDP_TX (retransmit), XDP_REDIRECT.
    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
```

> The `//go:build ignore` tag at the top prevents the Go toolchain from trying to compile this file directly. `bpf2go` handles it instead.

---

## Compiling with `bpf2go`

`bpf2go` is a code generation tool that:
1. Compiles your eBPF C code to bytecode using `clang`
2. Embeds the compiled object file into your Go binary
3. Generates Go scaffolding (structs, loaders, map accessors) from the ELF

This means your final Go binary is fully self-contained — no external `.o` files needed at runtime.

Create `gen.go`:

```go
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go counter counter.c
```

Bootstrap the module and pull dependencies:

```bash
go mod init ebpf-counter
go mod tidy
go get github.com/cilium/ebpf/cmd/bpf2go
```

Run codegen:

```bash
go generate
```

This produces:
```text
counter_bpfel.go   # Little-endian (x86_64, ARM64)
counter_bpfeb.go   # Big-endian (s390x, MIPS)
counter_bpfel.o    # Compiled eBPF bytecode (embedded)
counter_bpfeb.o
```

The generated structs look roughly like:

```go
type counterObjects struct {
    counterPrograms
    counterMaps
}

type counterPrograms struct {
    CountPackets *ebpf.Program `ebpf:"count_packets"`
}

type counterMaps struct {
    PktCount *ebpf.Map `ebpf:"pkt_count"`
}
```

You don't write these — `bpf2go` keeps them in sync with your C code automatically.

---

## The Go Userspace Application

The userspace side is responsible for:
- Loading the compiled eBPF bytecode into the kernel
- Attaching the program to a hook point
- Communicating with the running program via maps

Save this as `main.go`:

```go
package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// On kernels < 5.11, eBPF map memory counts against the process's
	// locked memory limit (RLIMIT_MEMLOCK). Remove the limit to avoid
	// EPERM on map creation. Kernels >= 5.11 use memcg accounting instead.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// loadCounterObjects is generated by bpf2go. It loads the embedded eBPF
	// ELF, creates all maps, and loads the program into the kernel.
	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	ifname := "eth0" // Change to your interface — use `ip link` to list them.
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// AttachXDP creates a bpf_link attaching our program to the XDP hook
	// on the given interface. bpf_link is ref-counted in the kernel —
	// the program stays attached as long as the link object is open.
	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer lnk.Close()

	log.Printf("Counting incoming packets on %s — press Ctrl+C to stop.", ifname)

	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	for {
		select {
		case <-tick.C:
			var count uint64
			// Lookup reads a value from the BPF map by key.
			// The map lives in kernel memory; this triggers a syscall.
			if err := objs.PktCount.Lookup(uint32(0), &count); err != nil {
				log.Fatal("Map lookup:", err)
			}
			log.Printf("Received %d packets", count)

		case <-stop:
			log.Println("Caught interrupt, detaching and exiting.")
			return
		}
	}
}
```

---

## Build and Run

```bash
go generate && go build -o ebpf-counter && sudo ./ebpf-counter
```

Generate some traffic on your interface (`ping`, `curl`, whatever) and watch the counter climb:

```text
2026/06/02 04:00:01 Counting incoming packets on eth0 — press Ctrl+C to stop.
2026/06/02 04:00:02 Received 42 packets
2026/06/02 04:00:03 Received 99 packets
2026/06/02 04:00:04 Received 153 packets
```

---

## Iteration Workflow

When you modify `counter.c`, always re-run codegen before building. The generated Go files must stay in sync with the C:

```bash
go generate && go build -o ebpf-counter && sudo ./ebpf-counter
```

---

## How It All Fits Together

```text
counter.c
    │
    │  clang (via bpf2go)
    ▼
counter_bpfel.o  ──embedded──▶  Go binary
                                    │
                          loadCounterObjects()
                                    │
                          ┌─────────┴──────────┐
                          │    Linux Kernel     │
                          │                     │
                          │  [BPF Verifier]     │
                          │       │             │
                          │  [XDP Hook]◀── NIC  │
                          │       │             │
                          │  [pkt_count map]    │
                          └─────────┬───────────┘
                                    │
                          objs.PktCount.Lookup()
                                    │
                               log.Printf()
```

---

## Going Further

| Topic | Where to look |
|---|---|
| More eBPF program types (TC, kprobes, tracepoints) | [`cilium/ebpf` examples](https://github.com/cilium/ebpf/tree/main/examples) |
| BTF and CO-RE (portable eBPF) | [kernel.org BPF docs](https://www.kernel.org/doc/html/latest/bpf/) |
| `sk_lookup` for socket redirection | [`sklookup-go`](https://github.com/zoidyzoidzoid/awesome-ebpf) |
| Production-grade eBPF tooling | [Cilium](https://cilium.io), [Falco](https://falco.org), [Katran](https://github.com/facebookincubator/katran) |
| Curated eBPF resources | [awesome-ebpf](https://github.com/zoidyzoidzoid/awesome-ebpf) |

---

> **Note on `sk_lookup`:** If you need to redirect TCP connections to a socket listening on a different port or IP — say, for a legacy app you can't modify — look into `BPF_PROG_TYPE_SK_LOOKUP`. It runs just before the kernel assigns an incoming connection to a receive buffer, making it ideal for transparent socket steering without `iptables` or `SO_REUSEPORT` hacks.
