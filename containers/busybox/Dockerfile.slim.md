
## Ultra-Slim BusyBox Container

### Dockerfile.slim
```dockerfile
# Ultra-minimal BusyBox container for tar export
FROM scratch

# Copy static busybox binary (single file!)
COPY --from=busybox:1.36-musl /bin/busybox /bin/busybox

# Create minimal directory structure
RUN ["/bin/busybox", "mkdir", "-p", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/tmp", "/etc", "/proc", "/sys", "/dev"]

# Install busybox links (creates all the utility symlinks)
RUN ["/bin/busybox", "--install", "-s"]

# Minimal config files
RUN ["/bin/busybox", "sh", "-c", "echo 'root:x:0:0:root:/:/bin/sh' > /etc/passwd"]
RUN ["/bin/busybox", "sh", "-c", "echo 'root:x:0:' > /etc/group"]
RUN ["/bin/busybox", "sh", "-c", "echo 'nameserver 8.8.8.8' > /etc/resolv.conf"]

# Set working directory and shell
WORKDIR /
CMD ["/bin/sh"]
```

## Even Slimmer: Single Stage

### Dockerfile.micro
```dockerfile
FROM busybox:1.36-musl

# Remove unnecessary files to minimize size
RUN rm -rf /var /usr/share /tmp/* /etc/ssl/certs

# Add minimal essentials only
RUN echo 'root:x:0:0:root:/:/bin/sh' > /etc/passwd && \
    echo 'root:x:0:' > /etc/group && \
    echo 'PS1="[\u@\h \W]# "' > /root/.profile

# Create essential directories
RUN mkdir -p /tmp /proc /sys /dev

WORKDIR /
CMD ["/bin/sh"]
```

## Build Scripts

### build-slim.sh
```bash
#!/bin/bash
# Build ultra-slim BusyBox container

echo "[*] Building slim BusyBox container..."

# Build the image
docker build -f Dockerfile.micro -t busybox-slim .

# Check the size
echo "[*] Image size:"
docker images busybox-slim --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"

# Export as tar
echo "[*] Exporting to tar..."
docker save busybox-slim:latest | gzip > busybox-slim.tar.gz

# Get final size
ls -lh busybox-slim.tar.gz

echo "[+] Done! Ultra-slim BusyBox container exported to busybox-slim.tar.gz"
```

## Multi-Architecture Slim Builder

### Dockerfile.multiarch
```dockerfile
FROM --platform=$BUILDPLATFORM tonistiigi/binfmt:latest AS binfmt
FROM --platform=$BUILDPLATFORM busybox:1.36-musl AS busybox-source

FROM scratch
ARG TARGETPLATFORM
ARG BUILDPLATFORM

# Copy just the busybox binary (statically linked)
COPY --from=busybox-source /bin/busybox /bin/busybox

# Minimal filesystem
RUN ["/bin/busybox", "mkdir", "-p", "/bin", "/tmp", "/etc"]
RUN ["/bin/busybox", "--install", "-s"]

# Bare minimum config
RUN ["/bin/busybox", "sh", "-c", "echo root::0:0:root:/:/bin/sh > /etc/passwd"]

CMD ["/bin/sh"]
```

## Custom Minimal with Security Tools

### Dockerfile.security
```dockerfile
FROM busybox:1.36-musl AS base

# Keep only security-relevant tools
RUN busybox --list | grep -E "(nc|wget|unshare|nsenter|mount|chroot|su|id|ps|netstat)" > /tmp/keep-tools

# Create minimal image with just security tools
FROM scratch
COPY --from=base /bin/busybox /bin/busybox

# Install only the tools we want
RUN ["/bin/busybox", "mkdir", "-p", "/bin", "/tmp"]
RUN ["/bin/busybox", "sh", "-c", "cd /bin && ln -s busybox unshare"]
RUN ["/bin/busybox", "sh", "-c", "cd /bin && ln -s busybox nc"]  
RUN ["/bin/busybox", "sh", "-c", "cd /bin && ln -s busybox wget"]
RUN ["/bin/busybox", "sh", "-c", "cd /bin && ln -s busybox sh"]
RUN ["/bin/busybox", "sh", "-c", "cd /bin && ln -s busybox mount"]
RUN ["/bin/busybox", "sh", "-c", "cd /bin && ln -s busybox id"]

CMD ["/bin/sh"]
```

## Size Comparison Script

### compare-sizes.sh
```bash
#!/bin/bash
echo "=== BusyBox Container Size Comparison ==="

# Build all variants
docker build -f Dockerfile.micro -t busybox-micro .
docker build -f Dockerfile.security -t busybox-security .

# Standard busybox
docker pull busybox:1.36-musl

# Compare sizes
echo -e "\nImage Sizes:"
docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" | grep -E "(busybox|REPOSITORY)"

# Export all and compare tar sizes
echo -e "\nTar Export Sizes:"
docker save busybox:1.36-musl | gzip > busybox-standard.tar.gz
docker save busybox-micro:latest | gzip > busybox-micro.tar.gz  
docker save busybox-security:latest | gzip > busybox-security.tar.gz

ls -lh *.tar.gz
```

## Ultra-Minimal: Just the Binary

### create-minimal.sh
```bash
#!/bin/bash
# Create absolute minimal container - just busybox binary

echo "[*] Creating ultra-minimal BusyBox tar..."

# Create minimal filesystem
mkdir -p minimal-fs/{bin,tmp}

# Extract just the busybox binary
docker create --name temp-busybox busybox:1.36-musl
docker cp temp-busybox:/bin/busybox minimal-fs/bin/busybox
docker rm temp-busybox

# Create basic structure
cd minimal-fs
chmod +x bin/busybox

# Create tar
tar -czf ../busybox-minimal.tar.gz .
cd ..
rm -rf minimal-fs

echo "[+] Created busybox-minimal.tar.gz ($(ls -lh busybox-minimal.tar.gz | awk '{print $5}'))"
```

## Expected Sizes:

- **Standard BusyBox**: ~2-4MB  
- **Micro build**: ~1-2MB
- **Security-only**: ~500KB-1MB
- **Minimal tar**: ~300-500KB

## Import Usage:

```bash
# Import the slim container
docker load < busybox-slim.tar.gz

# Or gunzip first if needed
gunzip -c busybox-slim.tar.gz | docker load

# Run it
docker run -it busybox-slim:latest
```

