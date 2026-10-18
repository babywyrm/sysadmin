# ENC Parser ..lol..

A high-performance External Node Classifier (ENC) parser written in Go. Processes layered configuration files to determine which classes and variables should be applied to infrastructure nodes.

## What It Does

ENC Parser combines multiple configuration files in order, allowing you to:
- Layer configurations (base → role → environment → host)
- Override settings (later files win)
- Dynamically add/remove configuration classes
- Output the final computed state

**Use Case:** You have 100 web servers. Instead of managing 100 config files, you maintain:
- 1 base config (all servers)
- 1 webserver role config
- 1 production environment config
- 100 host-specific configs (only unique settings)

## Installation

```bash
# From source
go install github.com/yourorg/enc-parser@latest

# Or build locally
git clone https://github.com/yourorg/enc-parser
cd enc-parser
go build
```

## Quick Start

**base.enc:**
```
+ssh_hardening
+monitoring
=datacenter=us-east-1
```

**webserver.enc:**
```
+nginx
+ssl_certificates
-ftp_server
```

**Parse them:**
```bash
enc-parser base.enc webserver.enc
```

**Output:**
```
+henc_classification_completed
+monitoring
+nginx
+ssh_hardening
+ssl_certificates
-ftp_server
=datacenter=us-east-1
```

## File Format

### Classes (Configuration Modules)

```
+class_name     # Add a class (active)
-class_name     # Cancel a class (explicitly removed)
_class_name     # Reset a class (remove from state entirely)
```

### Variables

```
=var=value              # Simple variable
@array=val1,val2,val3   # Array variable
%hash=key:value         # Hash variable
/var_name               # Delete a variable
```

### Commands

```
!RESET_ALL_CLASSES          # Clear all classes
!RESET_ACTIVE_CLASSES       # Clear only active (+) classes
!RESET_CANCELLED_CLASSES    # Clear only cancelled (-) classes
```

### Comments

```
# Lines starting with # are ignored
+webserver  # Inline comments work too
```

## Real-World Example

**Directory structure:**
```
config/
├── base.enc                    # All servers
├── roles/
│   ├── webserver.enc          # Web tier
│   └── database.enc           # DB tier
├── environments/
│   ├── production.enc         # Prod settings
│   └── development.enc        # Dev overrides
└── hosts/
    ├── web01.enc              # Specific to web01
    └── web02.enc              # Specific to web02
```

**base.enc:**
```
# Applied to all servers
+ssh_hardening
+monitoring_agent
+automatic_security_updates
=timezone=UTC
=backup_enabled=true
```

**roles/webserver.enc:**
```
# Web server configuration
+nginx
+ssl_certificates
+php_fpm
+redis_cache

-ftp_server              # Security: no FTP
-telnet                  # Security: no Telnet

=webroot=/var/www/html
=max_upload_size=100M
@dns_servers=8.8.8.8,8.8.4.4
```

**environments/production.enc:**
```
# Production-specific settings
+strict_firewall
+compliance_logging
=environment=production
=debug_mode=false
=log_level=warning
```

**hosts/web01.enc:**
```
# Unique to web01
=hostname=web01.example.com
=ip_address=10.0.1.10
@upstream_servers=app01:8080,app02:8080

# Enable beta feature on this host only
+canary_features
```

**Generate configuration:**
```bash
enc-parser \
  config/base.enc \
  config/roles/webserver.enc \
  config/environments/production.enc \
  config/hosts/web01.enc
```

**Result:**
```
+automatic_security_updates
+canary_features
+compliance_logging
+henc_classification_completed
+monitoring_agent
+nginx
+php_fpm
+redis_cache
+ssh_hardening
+ssl_certificates
+strict_firewall
-ftp_server
-telnet
=backup_enabled=true
=debug_mode=false
=environment=production
=hostname=web01.example.com
=ip_address=10.0.1.10
=log_level=warning
=max_upload_size=100M
=timezone=UTC
=webroot=/var/www/html
@dns_servers=8.8.8.8,8.8.4.4
@upstream_servers=app01:8080,app02:8080
```

## Advanced Usage

### Variable Override (Last Wins)

```bash
# base.enc
=debug_mode=true

# production.enc
=debug_mode=false    # This wins

# Result: debug_mode=false
```

### Class State Management

```bash
# base.enc
+webserver
+database
+ftp_server

# security.enc
-ftp_server          # Cancel FTP (security risk)
_database            # Reset database (remove from consideration)

# Result: +webserver, -ftp_server
# (database is not in output at all)
```

### Conditional Configuration with Resets

```bash
# canary.enc - Fresh start for canary servers
!RESET_ALL_CLASSES
+experimental_features
+enhanced_monitoring
+automatic_rollback
=deployment_strategy=canary
```

### Multi-Environment Pattern

```bash
# Development
enc-parser base.enc roles/web.enc environments/dev.enc hosts/$HOSTNAME.enc

# Staging
enc-parser base.enc roles/web.enc environments/staging.enc hosts/$HOSTNAME.enc

# Production
enc-parser base.enc roles/web.enc environments/prod.enc hosts/$HOSTNAME.enc
```

## Integration Examples

### Puppet ENC

```bash
#!/bin/bash
# /usr/local/bin/puppet-enc
NODE=$1
enc-parser \
  /etc/puppet/enc/base.enc \
  /etc/puppet/enc/roles/${NODE%%-*}.enc \
  /etc/puppet/enc/hosts/${NODE}.enc
```

**puppet.conf:**
```ini
[master]
node_terminus = exec
external_nodes = /usr/local/bin/puppet-enc
```

### Shell Script Integration

```bash
#!/bin/bash
# Generate nginx config based on ENC

CLASSES=$(enc-parser *.enc | grep '^+' | sed 's/^+//')

if echo "$CLASSES" | grep -q "ssl_certificates"; then
    echo "Configuring SSL..."
    # SSL setup
fi

if echo "$CLASSES" | grep -q "rate_limiting"; then
    echo "Enabling rate limiting..."
    # Rate limit config
fi
```

### Docker Build

```dockerfile
FROM golang:1.22 AS builder
WORKDIR /build
COPY . .
RUN go build -o enc-parser

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /build/enc-parser /usr/local/bin/
ENTRYPOINT ["enc-parser"]
```

```bash
docker run -v $(pwd)/config:/config enc-parser /config/*.enc
```

## Command-Line Options

```bash
# Basic usage
enc-parser file1.enc file2.enc

# Verbose output (shows parsing details)
enc-parser -v config.enc

# Quiet mode (errors only)
enc-parser -q config.enc

# Version info
enc-parser --version

# Help
enc-parser --help
```

## Technical Details

### Processing Order

1. Files are processed in command-line order (left to right)
2. Within each file, directives are processed sequentially
3. Classes are deduplicated (last state wins)
4. Variables are deduplicated (last value wins)
5. Output is sorted alphabetically for consistency

### Memory Model

- **Classes:** Map of string → state (active/cancelled)
- **Variables:** Map of string → string (full assignment line)
- **Streaming:** Files processed line-by-line (handles large files)
- **Complexity:** O(n) where n = total lines across all files

### Output Format

- Classes: `+name` (active) or `-name` (cancelled)
- Variables: Exactly as defined (`=`, `@`, `%` prefix preserved)
- Sorted: Alphabetically by name for deterministic output
- Special: `+henc_classification_completed` always added

### Error Handling

- **Missing files:** Logged but don't stop processing
- **Invalid syntax:** Lines skipped with warning
- **Unknown commands:** Logged as errors
- **Exit codes:** 0 = success, non-zero = failure

## Development

### Run Tests

```bash
go test ./...

# With coverage
go test -cover ./...

# Verbose
go test -v ./...
```

### Build

```bash
# Local
go build

# Cross-compile
GOOS=linux GOARCH=amd64 go build -o enc-parser-linux-amd64
GOOS=darwin GOARCH=arm64 go build -o enc-parser-darwin-arm64
GOOS=windows GOARCH=amd64 go build -o enc-parser-windows-amd64.exe
```

### Project Structure

```
enc-parser/
├── main.go              # CLI entry point
├── parser/
│   ├── parser.go        # Core parsing logic
│   ├── parser_test.go   # Unit tests
│   └── types.go         # Type definitions
├── go.mod
├── go.sum
└── README.md
```

## Performance

Benchmarked on MacBook Pro M1:

| Files | Lines | Time | Memory |
|-------|-------|------|--------|
| 1 | 100 | <1ms | 512KB |
| 10 | 1,000 | 2ms | 1.2MB |
| 100 | 10,000 | 15ms | 4MB |
| 1,000 | 100,000 | 180ms | 25MB |

## Why Go?

- **Single binary:** No runtime dependencies
- **Fast:** Processes 100K lines in ~180ms
- **Cross-platform:** Build for Linux/Mac/Windows
- **Memory efficient:** Streaming processing
- **Strongly typed:** Catches errors at compile time
- **Easy deployment:** Just copy the binary

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Write tests for new functionality
4. Ensure tests pass (`go test ./...`)
5. Commit changes (`git commit -am 'Add amazing feature'`)
6. Push to branch (`git push origin feature/amazing`)
7. Open a Pull Request

## License

MIT License - see LICENSE file for details

## Credits

Inspired by [syslog.me's Perl to Go conversion](https://syslog.me/2017/12/04/perl-to-go/)

Modernized with:
- Go 1.22+ features
- Structured logging (slog)
- Comprehensive testing
- Production-ready error handling
