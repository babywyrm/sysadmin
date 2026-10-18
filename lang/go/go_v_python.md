# Go vs Python for System Administration Scripts and Tools (2026 Update)

*Updated from the 2025 edition — significant shifts to cover*

---

## What's Actually New in 2026

### Go Side
- **Go 1.24/1.25** — toolchain directives in `go.mod` mean the correct Go version is now fully pinned and auto-downloaded. "Wrong Go version" is basically a solved problem.
- **Range over integers** (`for i := range 10`) — small but cleans up a lot of sysadmin loop patterns
- **`iter` package + range-over-func** — iterators are now idiomatic; processing streams/files is cleaner
- **`log/slog`** is fully settled as the standard — stop using `logrus`, `zap` for new tools unless you have a specific reason
- **`net/http` improvements** — HTTP/2 and HTTP/3 support has matured; building internal HTTP tooling no longer needs third-party routers for most cases
- **Toolchain UX** — `go tool` subcommands for bundled tools; `govulncheck` is now a standard part of the workflow

### Python Side
- **`uv` has won** — it's fast, it handles Python version management, virtual environments, scripts, and packages. Treat it as the standard now.
- **`uv` inline script dependencies (PEP 723)** — this is a *big deal* for sysadmin use cases (more below)
- **Python 3.13** — free-threaded mode (no GIL) is real and experimental; not yet production-relevant for most sysadmin tools, but watch this space
- **`pyproject.toml` everywhere** — `setup.py` is gone; stop writing it
- **Type hints are now table stakes** — if you're writing Python without them for anything beyond throwaway scripts, you're writing legacy code

### Environment Shifts
- **AI-assisted coding is normalized** — both languages generate well from LLMs; Go's stricter type system means AI-generated code has fewer silent bugs
- **Supply chain attacks got worse** — this has meaningfully shifted serious shops toward Go for deployed tools
- **ARM is mainstream** — Apple Silicon is 4+ years old, AWS Graviton is dominant in cost-optimized fleets; cross-compilation matters more than ever
- **"Platform engineering" is a real job now** — internal developer platforms (IDPs) often need maintained tooling, raising the bar for sysadmin scripts

---

## The Biggest Change: PEP 723 Rewrites the Python Calculus

This deserves special attention because it closes a real gap.

PEP 723 (inline script metadata) combined with `uv run` is now stable and widely used:

```python
#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "httpx",
#   "rich",
#   "pydantic>=2.0",
# ]
# ///

import httpx
from rich.console import Console
from pydantic import BaseModel

class ServerStatus(BaseModel):
    hostname: str
    status: str
    latency_ms: float

console = Console()

def check_servers(hosts: list[str]) -> list[ServerStatus]:
    results = []
    for host in hosts:
        try:
            r = httpx.get(f"http://{host}/health", timeout=5)
            results.append(ServerStatus(
                hostname=host,
                status="ok" if r.status_code == 200 else "degraded",
                latency_ms=r.elapsed.total_seconds() * 1000,
            ))
        except httpx.ConnectError:
            results.append(ServerStatus(
                hostname=host, status="down", latency_ms=-1
            ))
    return results

if __name__ == "__main__":
    servers = ["web1.internal", "web2.internal", "api.internal"]
    for s in check_servers(servers):
        color = "green" if s.status == "ok" else "red"
        console.print(f"[{color}]{s.hostname}: {s.status} ({s.latency_ms:.0f}ms)")
```

Run it on any machine with `uv` installed:

```bash
uv run check_servers.py
```

`uv` handles:
- Correct Python version
- Isolated virtual environment (cached, fast)
- All dependencies

**This is portable, self-contained, and requires zero setup beyond `uv` itself.** For single-file operational scripts, this mostly eliminates Python's dependency management friction. Go's "just copy the binary" argument weakens meaningfully in this scenario.

However — and this is important — `uv` must be present on the target machine. Go's binary still wins for environments where you can't guarantee toolchain availability.

---

## Updated Core Comparison

### Deployment

| Scenario | Python (2026) | Go (2026) |
|---|---|---|
| Single dev machine | `uv run script.py` — excellent | Build + copy — fine |
| Shared team server | PEP 723 + uv — good | Binary — still excellent |
| Container | ~100MB image, manageable | 8-20MB scratch image — clear win |
| Air-gapped / locked-down | Still tricky | Binary wins clearly |
| Heterogeneous fleet | `uv` must be present | Cross-compile once — wins |
| Windows + Linux | `uv` handles it | Cross-compile — excellent |

### Performance (Updated Benchmarks — 2026 Hardware Context)

Processing 10GB access logs on a modern server:

```text
Python 3.13 (standard):     ~90 seconds,  ~4GB RAM
Python 3.13 (with polars):  ~12 seconds,  ~800MB RAM
Go (bufio.Scanner):         ~18 seconds,  ~200MB RAM
Go (with mmap):             ~8 seconds,   ~150MB RAM
```

**Notable shift:** `polars` (Rust-backed DataFrame library) now gives Python near-Go performance for data-heavy workloads. If your bottleneck is data processing specifically, the performance gap has narrowed.

For general systems work (HTTP servers, file walking, concurrent checks), Go's advantage remains large and consistent.

### Dependency Management

Python 2026 with `uv`:

```bash
uv init mytool
uv add httpx pydantic rich
uv run mytool/main.py

# Lockfile committed, reproducible everywhere uv is available
# Python version pinned in .python-version
```

Go 2026:

```bash
go mod init mytool
go get github.com/spf13/cobra
go build -o mytool

# go.sum cryptographically pins everything
# Works everywhere with no runtime
```

**Verdict:** `uv` has closed the gap substantially. Go still wins on simplicity and security (cryptographic checksums, smaller dep trees), but Python is no longer a frustrating mess for new projects.

---

## Security: The Gap Has Grown

This section has gotten more important, not less.

### Supply Chain Reality in 2026

PyPI incidents have continued. The attack surface is real:

```bash
# Python - what are you actually running?
uv add requests
# requests pulls: certifi, charset-normalizer, idna, urllib3
# Each is a supply chain vector

# Auditing is possible but requires effort
uv pip show requests
pip-audit  # Good tool, but external
```

```bash
# Go - built-in tooling
go mod verify          # Verify checksums match go.sum
govulncheck ./...      # Official vuln scanner, part of toolchain
go mod why github.com/some/dep  # Trace why it's included
```

Go's `go.sum` file provides cryptographic verification of every dependency at every version. This is a structural advantage that doesn't require add-on tooling.

For tools that touch production infrastructure, secrets, or sensitive data, this is a meaningful consideration — not just a theoretical one.

### Static Analysis

```bash
# Go
go vet ./...           # Built in, run in CI always
staticcheck ./...      # Community standard, catches real bugs
govulncheck ./...      # Security-specific

# Python
ruff check .           # Fast, catches many issues (use this)
mypy .                 # Type checking
bandit -r .            # Security-specific
```

Both ecosystems have good tooling now. Go's is more consolidated.

---

## AI-Assisted Development Consideration

Since most teams are using AI coding assistants heavily in 2026, this is worth addressing directly.

**Go + AI:**
- Strict type system catches AI hallucinations at compile time
- `go vet` and `staticcheck` immediately surface problems
- Error handling is explicit — AI can't silently swallow errors
- You *know* if the generated code works

**Python + AI:**
- Faster to generate working prototypes
- Type hints help, but aren't enforced at runtime
- Silent failures are still possible
- Excellent for exploratory/data work where you're iterating fast

```go
// Go: AI generates this, compiler immediately catches problems
func processConfig(path string) (Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return Config{}, fmt.Errorf("reading config: %w", err)
    }
    // If AI forgot error handling above, it won't compile
    var cfg Config
    return cfg, json.Unmarshal(data, &cfg)
}
```

```python
# Python: AI generates this, works but has a silent failure mode
def process_config(path: str) -> dict:
    with open(path) as f:
        return json.load(f)
    # No error handling — passes type checking, fails at runtime
    # mypy won't catch this specific issue
```

For production tools, Go's compile-time guarantees make AI-generated code safer to use with less review overhead.

---

## Updated Templates

### Modern Python Tool (2026)

```python
#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx", "rich", "pydantic>=2.0", "typer"]
# ///
"""
System health checker.
Usage: uv run healthcheck.py --hosts web1,web2,api1
"""

from __future__ import annotations

import sys
from typing import Annotated

import httpx
import typer
from pydantic import BaseModel
from rich.console import Console
from rich.table import Table

app = typer.Typer()
console = Console()


class HostResult(BaseModel):
    host: str
    status: str
    status_code: int | None = None
    latency_ms: float | None = None
    error: str | None = None


def check_host(host: str, timeout: float) -> HostResult:
    try:
        r = httpx.get(f"http://{host}/health", timeout=timeout)
        return HostResult(
            host=host,
            status="ok" if r.status_code == 200 else "degraded",
            status_code=r.status_code,
            latency_ms=r.elapsed.total_seconds() * 1000,
        )
    except httpx.ConnectError as e:
        return HostResult(host=host, status="unreachable", error=str(e))
    except httpx.TimeoutException:
        return HostResult(host=host, status="timeout", error="timed out")


@app.command()
def main(
    hosts: Annotated[str, typer.Option(help="Comma-separated hostnames")],
    timeout: Annotated[float, typer.Option(help="Timeout in seconds")] = 5.0,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    host_list = [h.strip() for h in hosts.split(",")]
    results = [check_host(h, timeout) for h in host_list]

    if json_output:
        import json
        print(json.dumps([r.model_dump() for r in results], indent=2))
        raise typer.Exit(0 if all(r.status == "ok" for r in results) else 1)

    table = Table(title="Host Status")
    table.add_column("Host")
    table.add_column("Status")
    table.add_column("Latency")

    for r in results:
        color = {"ok": "green", "degraded": "yellow"}.get(r.status, "red")
        latency = f"{r.latency_ms:.0f}ms" if r.latency_ms else "—"
        table.add_row(r.host, f"[{color}]{r.status}", latency)

    console.print(table)
    sys.exit(0 if all(r.status == "ok" for r in results) else 1)


if __name__ == "__main__":
    app()
```

### Modern Go Tool (2026)

```go
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type HostResult struct {
	Host      string  `json:"host"`
	Status    string  `json:"status"`
	Code      int     `json:"status_code,omitempty"`
	LatencyMs float64 `json:"latency_ms,omitempty"`
	Error     string  `json:"error,omitempty"`
}

func checkHost(
	ctx context.Context,
	host string,
	timeout time.Duration,
) HostResult {
	client := &http.Client{Timeout: timeout}
	start := time.Now()

	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet,
		fmt.Sprintf("http://%s/health", host), nil,
	)
	if err != nil {
		return HostResult{Host: host, Status: "error", Error: err.Error()}
	}

	resp, err := client.Do(req)
	if err != nil {
		return HostResult{Host: host, Status: "unreachable", Error: err.Error()}
	}
	defer resp.Body.Close()

	latency := float64(time.Since(start).Microseconds()) / 1000.0
	status := "ok"
	if resp.StatusCode != http.StatusOK {
		status = "degraded"
	}

	return HostResult{
		Host:      host,
		Status:    status,
		Code:      resp.StatusCode,
		LatencyMs: latency,
	}
}

func main() {
	hosts := flag.String("hosts", "", "Comma-separated hostnames")
	timeout := flag.Duration("timeout", 5*time.Second, "Request timeout")
	jsonOut := flag.Bool("json", false, "JSON output")
	flag.Parse()

	if *hosts == "" {
		fmt.Fprintln(os.Stderr, "error: --hosts is required")
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx := context.Background()

	hostList := strings.Split(*hosts, ",")
	results := make([]HostResult, len(hostList))

	var wg sync.WaitGroup
	for i, host := range hostList {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			results[i] = checkHost(ctx, strings.TrimSpace(host), *timeout)
		}(i, host)
	}
	wg.Wait()

	if *jsonOut {
		if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
			logger.Error("encoding output", "error", err)
			os.Exit(1)
		}
	} else {
		fmt.Printf("%-20s %-12s %s\n", "HOST", "STATUS", "LATENCY")
		fmt.Println(strings.Repeat("─", 45))
		for _, r := range results {
			latency := "—"
			if r.LatencyMs > 0 {
				latency = fmt.Sprintf("%.0fms", r.LatencyMs)
			}
			fmt.Printf("%-20s %-12s %s\n", r.Host, r.Status, latency)
		}
	}

	for _, r := range results {
		if r.Status != "ok" {
			os.Exit(1)
		}
	}
}
```

Notice what the Go version gets for free that the Python version doesn't: **concurrent host checking** with `sync.WaitGroup` and goroutines. The Python version checks hosts sequentially. Adding `asyncio` or `concurrent.futures` to the Python version is doable but adds meaningful complexity.

---

## The "When to Use What" Decision Tree (2026)

```text
Is this a one-off investigation or throwaway script?
├── Yes → Python. Don't overthink it.
└── No ↓

Will it run on machines you don't fully control?
├── Yes → Go. Binary deployment is irreplaceable here.
└── No ↓

Is uv available (or can you guarantee it will be) everywhere this runs?
├── Yes → Python is viable. Continue below.
└── No → Go. Deployment simplicity wins.

Does it primarily process data / generate reports / use pandas/polars?
├── Yes → Python. Ecosystem advantage is real.
└── No ↓

Will more than 2-3 people maintain this?
├── Yes → Go. Type safety and explicit error handling scale better.
└── No ↓

Is it a long-running service / daemon?
├── Yes → Go. Memory predictability and no GC pauses matter.
└── No ↓

Is security / auditing a stated requirement?
├── Yes → Go. Supply chain tooling and static analysis are stronger.
└── No ↓

Does your team already have a strong Python base?
├── Yes → Python is fine. Don't introduce Go without a reason.
└── No → Either. Pick what the team will actually maintain.
```

---

## What Hasn't Changed

Some things the 2020 and 2025 articles said are still true and worth keeping:

- **Python is still faster to write for exploratory work.** This is not changing.
- **Go is still the right call for anything user-facing or long-running.** This is not changing.
- **Both have excellent cloud SDK support.** AWS, GCP, Azure — first-class in both.
- **The hybrid repo layout still makes sense.** `tools/` in Go, `scripts/` in Python.
- **Don't rewrite working Python in Go just because.** Migration should be triggered by a real need (performance, deployment, team growth, security audit).

---

## Honest Bottom Line for 2026

**PEP 723 + `uv` is the most significant shift since Go modules landed.** Python's single biggest practical disadvantage for sysadmin scripts — dependency hell — is now largely solved for greenfield work. This brings Python back into contention for a category of tools it had started losing to Go.

But Go's structural advantages haven't gone away:

- Cross-compilation to any target from any machine
- Binary deployment with zero runtime dependency
- Cryptographic supply chain verification built in
- Compile-time correctness (especially relevant with AI-generated code)
- Predictable runtime behavior for long-lived processes

**Updated guidance:**

| Team size | Recommendation |
|---|---|
| Solo operator | Python + `uv` for scripts; Go when you need a binary |
| Small team (2–5) | Python for scripts, Go for anything "shipped" |
| Medium team (5–20) | Go as default for tools; Python where ecosystem wins |
| Platform / infra team | Go for tooling; Python for data/analysis work |

##
##

# Go vs Python for System Administration Scripts and Tools (2025 Update) ..beta..

**Original article from 2020 - Updated for modern considerations**

The landscape has evolved significantly since 2020, but the core trade-offs remain relevant. Here's an updated and expanded analysis:

## What's Changed Since 2020

### Go Improvements
- **Go modules** are now the standard (no more GOPATH confusion)
- **Generics** (Go 1.18+) reduce boilerplate for common patterns
- **Embed directive** allows bundling files directly into binaries
- **Better toolchain** - faster compilation, improved error messages
- **Native fuzzing** support built into the standard library

### Python Evolution
- **Python 2 is dead** - the ecosystem has fully consolidated on Python 3
- **Type hints** are now ubiquitous with excellent tooling (mypy, pyright)
- **Modern package managers** - uv, rye, poetry have vastly improved the experience
- **Performance improvements** - Python 3.11+ brought significant speed gains
- **Better async** support for I/O-bound operations

### Environment Changes
- **Containers everywhere** - deployment models have shifted
- **Security focus** - supply chain attacks are a real concern
- **Cloud-native** - scripts often interact with cloud APIs
- **Remote work** - more distributed teams, less "just SSH and fix it"

## The Core Arguments (Updated)

### Python's Strengths for Small-Scale Tools

#### 1. Source-as-Deployment (Still True, But...)

Python's "what you deploy is what you see" advantage remains, but modern practices have shifted:

**Traditional approach:**
```bash
# Still works, still simple
scp script.py user@server:/usr/local/bin/
```

**Modern reality:**
```bash
# More likely today:
docker build -t myscript .
docker push registry/myscript:latest
```

With containers, **both** languages deploy as opaque artifacts. The advantage narrows significantly.

#### 2. Quick Modifications (Complicated by Modern Python)

The original argument was that you could quickly edit Python in production. **This is now an anti-pattern:**

```python
# 2020: Quick fix in production
vim /usr/local/bin/myscript.py  # Edit and done

# 2025: Modern concerns
# - Which Python version? (3.9? 3.12?)
# - Virtual environment location?
# - Which dependencies are installed?
# - Are you breaking type hints?
# - Does this pass pre-commit hooks?
```

**Modern Python has lost some casual-edit advantages:**

```bash
# Modern Python isn't as simple as it used to be
$ python script.py
ModuleNotFoundError: No module named 'pydantic'

$ pip install pydantic
error: externally-managed-environment

$ python -m venv venv
$ source venv/bin/activate
$ pip install pydantic
# Now which Python are your other scripts using?
```

#### 3. Dependency Management (Both Have Issues)

**Python in 2025:**
```bash
# Multiple competing solutions
pip install ...           # Basic, but pip freeze is a mess
pipenv install ...        # Pipfile, but slow
poetry add ...            # Best ergonomics, but complex
uv pip install ...        # Newest, very fast, but immature
```

**Go in 2025:**
```bash
# Standardized and simple
go get github.com/spf13/cobra@latest
# That's it. go.mod and go.sum handle everything.
```

**Verdict**: Go actually wins here now. Go modules "just work" while Python's packaging story remains fragmented.

### Go's Strengths for Small-Scale Tools

#### 1. Single Binary Deployment (Even Better Now)

```bash
# Build for any platform from anywhere
GOOS=linux GOARCH=amd64 go build -o mytool-linux-amd64
GOOS=linux GOARCH=arm64 go build -o mytool-linux-arm64
GOOS=darwin GOARCH=arm64 go build -o mytool-macos-arm64

# Deploy anywhere, no runtime needed
scp mytool-linux-amd64 server:/usr/local/bin/mytool
```

This is **incredibly powerful** for heterogeneous environments (x86, ARM, Mac, Linux, Windows).

#### 2. No Runtime Version Hell

**Python reality:**
```bash
server1: Python 3.8  # EOL but still running
server2: Python 3.9  # Current LTS
server3: Python 3.12 # Latest
# Your script needs to work on all three
```

**Go reality:**
```bash
# All servers: Just needs a Linux kernel
# Runtime is embedded in the binary
```

#### 3. Performance (Matters More Now)

Modern system tools often need to:
- Parse large JSON/YAML files (K8s configs, cloud API responses)
- Process logs at scale
- Handle concurrent operations

**Example - Processing 1GB JSON file:**
```python
# Python: 8-15 seconds, 800MB memory
import json
with open('large.json') as f:
    data = json.load(f)
```

```go
// Go: 2-4 seconds, 200MB memory
import "encoding/json"
data, _ := os.ReadFile("large.json")
json.Unmarshal(data, &result)
```

For frequently-run tools, this compounds quickly.

## Modern Decision Framework

### Choose Python When:

1. **Rapid prototyping** - You're figuring out what you need
2. **Data science adjacent** - Need pandas, numpy, matplotlib
3. **Glue scripting** - Connecting various CLI tools
4. **Team is primarily Python** - Don't introduce Go for one tool
5. **Extensive string/text manipulation** - Python's still cleaner here
6. **One-off scripts** - Won't be maintained or deployed widely

**Modern Python template for sysadmin tools:**
```python
#!/usr/bin/env python3
"""
Script description
Usage: python script.py [options]
"""
import argparse
import sys
from pathlib import Path
from typing import Optional

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    
    # Your logic here
    return 0

if __name__ == '__main__':
    sys.exit(main())
```

### Choose Go When:

1. **Production tools** - Will be deployed and maintained
2. **Performance sensitive** - Runs frequently or processes large data
3. **Cross-platform** - Need to support multiple OS/architectures
4. **Long-lived daemons** - Services, agents, monitors
5. **Network services** - HTTP servers, proxies, API clients
6. **Security sensitive** - Smaller attack surface, easier to audit
7. **Team scale** - 3+ people will maintain this

**Modern Go template for sysadmin tools:**
```go
package main

import (
    "context"
    "flag"
    "fmt"
    "log/slog"
    "os"
)

func main() {
    var configPath string
    flag.StringVar(&configPath, "config", "", "Path to config file")
    flag.Parse()

    logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
    ctx := context.Background()

    if err := run(ctx, logger, configPath); err != nil {
        logger.Error("fatal", "error", err)
        os.Exit(1)
    }
}

func run(ctx context.Context, logger *slog.Logger, configPath string) error {
    // Your logic here
    return nil
}
```

## The "In-Between" Zone: Modern Best Practices

### For Small Teams (1-5 people):

**Hybrid approach:**
```
Python for:
- Ad-hoc scripts (scripts/)
- Jupyter notebooks for investigation
- Quick automation

Go for:
- Any deployed "product" tool
- Anything user-facing
- Performance-critical paths
```

### Containerize Everything Approach:

If you're already using containers, **the traditional Python advantages largely disappear**:

```dockerfile
# Python - complex
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY script.py .
CMD ["python", "script.py"]
# Image size: 150-300MB

# Go - simple
FROM golang:1.22 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o tool

FROM scratch
COPY --from=builder /app/tool /tool
ENTRYPOINT ["/tool"]
# Image size: 8-20MB
```

### Version Control Both Ways:

Modern workflow removes Python's "easy to see source" advantage:

```bash
# Python or Go - same workflow
git clone https://github.com/company/sysadmin-tools
cd sysadmin-tools
./scripts/build.sh  # Works for both
./scripts/deploy.sh server1
```

## New Considerations for 2025

### 1. Security and Supply Chain

**Python risks:**
- PyPI has had numerous malicious packages
- Dependency sprawl (one package pulls 50 dependencies)
- No built-in verification of dependencies

**Go advantages:**
- `go.sum` provides cryptographic checksums
- Smaller dependency trees typical
- Static analysis tools more effective

```bash
# Go - audit dependencies easily
go mod why github.com/some/package
go mod graph | grep malicious

# Python - harder to track
pipdeptree  # If you even have it installed
```

### 2. Cloud-Native Integration

Both languages now have excellent cloud SDK support:

**Python:**
```python
import boto3  # AWS
from google.cloud import storage  # GCP
from azure.identity import DefaultAzureCredential  # Azure
```

**Go:**
```go
import "github.com/aws/aws-sdk-go-v2"  // AWS
import "cloud.google.com/go/storage"   // GCP
import "github.com/Azure/azure-sdk-for-go"  // Azure
```

**Tie** - both are first-class citizens.

### 3. Observability

**Go advantages:**
- Built-in pprof for profiling
- Structured logging (slog) in standard library
- Easy to add Prometheus metrics
- OpenTelemetry has excellent Go support

**Python challenges:**
- Logging still somewhat fractured
- Profiling more complex
- But: Great integration with data analysis tools

### 4. Editor/IDE Support

**Both are excellent now:**
- VSCode has great support for both (Pylance, gopls)
- Type checking works well in both
- Debugging is solid for both

## Real-World Examples

### Example 1: Log Parser

**Task:** Parse 10GB of access logs, extract metrics, generate report

**Python approach:**
```python
# Quick to write, but slow
import re
from collections import Counter

with open('access.log') as f:
    ips = Counter(re.findall(r'\d+\.\d+\.\d+\.\d+', f.read()))
```
**Time:** 2-3 minutes, 4GB RAM

**Go approach:**
```go
// More code, but fast
scanner := bufio.NewScanner(file)
ips := make(map[string]int)
for scanner.Scan() {
    if ip := extractIP(scanner.Text()); ip != "" {
        ips[ip]++
    }
}
```
**Time:** 15-30 seconds, 200MB RAM

**Verdict:** If you run this daily, Go saves 20+ hours per year.

### Example 2: API Webhook Receiver

**Task:** Receive webhooks, validate, process, forward to queue

**Python:**
```python
from flask import Flask, request
app = Flask(__name__)

@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.json
    # process...
    return '', 200

if __name__ == '__main__':
    app.run(port=8080)
```
**Issues:** Memory leaks over time, need gunicorn/uwsgi, deployment complexity

**Go:**
```go
http.HandleFunc("/webhook", handleWebhook)
log.Fatal(http.ListenAndServe(":8080", nil))
```
**Benefits:** Production-ready as-is, predictable memory, easy to deploy

**Verdict:** Go is clearly better for long-running services.

### Example 3: One-Off Data Migration

**Task:** Read CSV, transform, write to database

**Python:**
```python
import pandas as pd
df = pd.read_csv('data.csv')
df['new_col'] = df['old_col'].apply(transform)
df.to_sql('table', engine, if_exists='append')
```
**Time to write:** 5 minutes

**Go:**
```go
// Would need to:
// - Write CSV parsing
// - Implement transform logic
// - Handle SQL insertion
// Much more code...
```
**Time to write:** 30+ minutes

**Verdict:** Python wins for one-off data tasks.

## Modern Recommendations

### Start with Python if:
- You're the only developer
- Scripts are run infrequently
- You're doing exploratory work
- Team already knows Python well

### Migrate to Go when:
- Tool becomes business-critical
- Performance becomes an issue
- You need cross-platform support
- Security review is required
- Tool will have multiple maintainers

### Use Both:
```
repository/
├── tools/           # Go - deployed tools
│   ├── log-parser/
│   ├── metric-collector/
│   └── webhook-receiver/
├── scripts/         # Python - ad-hoc scripts
│   ├── deploy.py
│   ├── analyze_logs.py
│   └── generate_report.py
└── lib/             # Shared logic
    ├── python/      # Import in scripts
    └── go/          # Import in tools
```

## The Bottom Line (2025 Edition)

The original article's "go big or go home" conclusion for Go is **less true now**:

1. **Go is easier to adopt incrementally** - Modules and better tooling help
2. **Python is less casual-friendly** - Modern Python requires more setup
3. **Containers equalize deployment** - Both become "opaque artifacts"
4. **Go's benefits are more compelling** - Performance, security, single-binary

**Updated guidance:**

- **Small team, occasional scripts:** Python still wins on ease
- **Small team, building tools:** Go is now viable even for smaller commitments
- **Medium team (5-20):** Go for tools, Python for scripts
- **Large team:** Probably already standardized on one or the other

**The real shift:** In 2020, Python was the pragmatic default. In 2025, **Go is a more reasonable default for sysadmin tools**, with Python reserved for specific use cases where its strengths shine (data analysis, prototyping, complex text processing).

The decision is no longer "Python by default unless you're going big" but rather "What does this specific tool need?" and choosing accordingly.
