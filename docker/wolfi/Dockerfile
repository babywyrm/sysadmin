# ==============================================================================
# Wolfi Web Server - Production Dockerfile
# ==============================================================================
# This multi-stage Dockerfile creates a secure, minimal web server using:
# - Wolfi Linux (glibc-based, minimal CVEs)
# - Flask web framework
# - Gunicorn WSGI server
# - Non-root user execution
# - Security hardening best practices
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Builder Stage
# ------------------------------------------------------------------------------
# Purpose: Compile and install Python dependencies in isolation
# This stage includes build tools that won't be in the final image
# ------------------------------------------------------------------------------
FROM cgr.dev/chainguard/wolfi-base:latest AS builder

# Update package database and install build-time dependencies
# - python3: Python interpreter
# - py3-pip: Python package installer
# - py3-wheel: For building wheel distributions
# - py3-setuptools: Package development tools
# - build-base: Essential compilation tools (gcc, make, etc.)
# - python3-dev: Python C headers for native extensions
RUN apk update && apk add --no-cache \
    python3 \
    py3-pip \
    py3-wheel \
    py3-setuptools \
    build-base \
    python3-dev

# Create isolated virtual environment
# This prevents conflicts with system packages and enables clean copying
RUN python3 -m venv /opt/venv

# Add virtual environment to PATH for subsequent RUN commands
ENV PATH="/opt/venv/bin:$PATH"

# Copy only requirements first (Docker layer caching optimization)
# Changes to app code won't invalidate this layer
COPY requirements.txt /tmp/
WORKDIR /tmp

# Install Python dependencies into virtual environment
# --no-cache-dir: Don't store pip cache (reduces image size)
# --upgrade pip: Ensure latest pip for security patches
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ------------------------------------------------------------------------------
# Stage 2: Production Runtime Stage
# ------------------------------------------------------------------------------
# Purpose: Minimal runtime environment with only necessary dependencies
# Security: No build tools, minimal attack surface
# ------------------------------------------------------------------------------
FROM cgr.dev/chainguard/wolfi-base:latest

# Add image metadata using OCI labels
# These labels help with image management and security scanning
LABEL maintainer="your-team@example.com" \
      org.opencontainers.image.title="Wolfi Web Server" \
      org.opencontainers.image.description="Secure Flask web server on Wolfi" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="Your Organization" \
      org.opencontainers.image.base.name="cgr.dev/chainguard/wolfi-base"

# Install ONLY runtime dependencies (no build tools)
# - python3: Python runtime
# - py3-pip: Needed for installed packages to work
# - bash: Shell for debugging (consider removing in ultra-hardened setups)
# - curl: For health checks
# - ca-certificates: SSL/TLS certificate validation
# - tini: Lightweight init system for proper signal handling
RUN apk update && apk add --no-cache \
    python3 \
    py3-pip \
    bash \
    curl \
    ca-certificates \
    tini && \
    # Clean up apk cache to reduce image size
    rm -rf /var/cache/apk/*

# Copy virtual environment from builder stage
# This includes all Python packages without build dependencies
COPY --from=builder /opt/venv /opt/venv

# Configure environment variables for security and performance
ENV PATH="/opt/venv/bin:$PATH" \
    # Prevent Python from buffering stdout/stderr (better logging)
    PYTHONUNBUFFERED=1 \
    # Don't write .pyc files (reduces disk I/O and attack surface)
    PYTHONDONTWRITEBYTECODE=1 \
    # Disable pip version check (reduces network calls)
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # Don't cache pip downloads
    PIP_NO_CACHE_DIR=1 \
    # Flask configuration
    FLASK_APP=app.py \
    FLASK_ENV=production \
    # Application port
    APP_PORT=6699

# Set working directory
WORKDIR /app

# Copy application code with proper ownership
# Files are owned by non-root user (UID 65532) from the start
COPY --chown=65532:65532 ./app /app

# Create necessary directories with proper permissions
# /app/logs: Application logs
# /app/tmp: Temporary files (Gunicorn needs this)
# /app/static: Static assets (if needed later)
# /app/uploads: User uploads (if needed later)
RUN mkdir -p /app/logs /app/tmp /app/static /app/uploads && \
    chown -R 65532:65532 /app && \
    # Make directories read-only except tmp and logs
    chmod 755 /app && \
    chmod 755 /app/static /app/uploads && \
    chmod 775 /app/tmp /app/logs

# Security: Switch to non-root user
# UID 65532 is a standard "nobody" user in many distros
# This prevents privilege escalation attacks
USER 65532

# Document the port the application will listen on
# This doesn't actually publish the port (use -p flag for that)
EXPOSE 6699

# Configure Docker health check
# Docker/Kubernetes will use this to determine container health
# --interval: Time between checks
# --timeout: Max time for check to complete
# --start-period: Grace period before first check
# --retries: Consecutive failures before marking unhealthy
HEALTHCHECK --interval=30s \
            --timeout=3s \
            --start-period=10s \
            --retries=3 \
    CMD curl -f http://localhost:6699/health || exit 1

# Security: Use tini as PID 1
# Tini properly handles:
# - Zombie process reaping
# - Signal forwarding (SIGTERM, SIGINT)
# - Graceful shutdown
ENTRYPOINT ["/usr/bin/tini", "--"]

# Production command using Gunicorn WSGI server
# Security and performance optimizations:
# --bind 0.0.0.0:6699: Listen on all interfaces, port 6699
# --workers 4: Number of worker processes (adjust based on CPU cores)
# --threads 2: Threads per worker (hybrid worker model)
# --worker-class gthread: Use threaded workers for I/O-bound apps
# --worker-tmp-dir /dev/shm: Use memory for worker heartbeat (faster)
# --timeout 30: Worker timeout in seconds
# --graceful-timeout 30: Time to wait for graceful shutdown
# --max-requests 1000: Restart workers after N requests (prevent memory leaks)
# --max-requests-jitter 50: Add randomness to prevent thundering herd
# --access-logfile -: Log access to stdout (Docker best practice)
# --error-logfile -: Log errors to stderr (Docker best practice)
# --log-level info: Logging verbosity
# --preload: Load application before forking workers (saves memory)
CMD ["gunicorn", \
     "--bind", "0.0.0.0:6699", \
     "--workers", "4", \
     "--threads", "2", \
     "--worker-class", "gthread", \
     "--worker-tmp-dir", "/dev/shm", \
     "--timeout", "30", \
     "--graceful-timeout", "30", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "50", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "info", \
     "--preload", \
     "app:app"]

# ==============================================================================
# Security Notes:
# ==============================================================================
# 1. Non-root user (UID 65532) - Prevents privilege escalation
# 2. Minimal packages - Reduced attack surface
# 3. No build tools in final image - Can't compile malicious code
# 4. Read-only filesystem recommended - Add --read-only flag when running
# 5. Drop capabilities - Use --cap-drop=ALL --cap-add=NET_BIND_SERVICE
# 6. Network isolation - Use Docker networks to limit connectivity
# 7. Resource limits - Set memory/CPU limits in production
# 8. Secrets management - Never hardcode secrets, use Docker secrets/env vars
# 9. Regular updates - Rebuild image regularly for security patches
# 10. Scan for vulnerabilities - Use trivy/grype before deploying
# ==============================================================================

# ==============================================================================
# Build and Run Examples:
# ==============================================================================
# Build:
#   docker build -t wolfi-webserver:1.0.0 .
#
# Run (basic):
#   docker run -d --name wolfi-web -p 6699:6699 wolfi-webserver:1.0.0
#
# Run (hardened):
#   docker run -d \
#     --name wolfi-web \
#     -p 6699:6699 \
#     --read-only \
#     --tmpfs /tmp:rw,noexec,nosuid,size=64m \
#     --tmpfs /app/tmp:rw,noexec,nosuid,size=128m \
#     --cap-drop=ALL \
#     --cap-add=NET_BIND_SERVICE \
#     --security-opt=no-new-privileges:true \
#     --memory=512m \
#     --cpus=1.0 \
#     --restart=unless-stopped \
#     wolfi-webserver:1.0.0
# ==============================================================================
