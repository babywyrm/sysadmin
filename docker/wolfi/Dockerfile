# Multi-stage build for a production Flask web server on Wolfi ..beta edition..

# Stage 1: Builder stage
FROM cgr.dev/chainguard/wolfi-base:latest AS builder

# Install build dependencies
RUN apk update && apk add --no-cache \
    python3 \
    py3-pip \
    py3-wheel \
    py3-setuptools \
    build-base \
    python3-dev

# Create virtual environment for better dependency isolation
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements file
COPY requirements.txt /tmp/
WORKDIR /tmp

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Stage 2: Production runtime
FROM cgr.dev/chainguard/wolfi-base:latest

# Install only runtime dependencies
RUN apk update && apk add --no-cache \
    python3 \
    py3-pip \
    bash \
    curl \
    ca-certificates \
    tini

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Set environment variables
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FLASK_APP=app.py \
    FLASK_ENV=production

# Create app directory and set permissions
WORKDIR /app

# Copy application code
COPY --chown=65532:65532 ./app /app

# Create non-root user directories
RUN mkdir -p /app/logs /app/tmp && \
    chown -R 65532:65532 /app

# Switch to non-root user
USER 65532

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Use tini as init system for proper signal handling
ENTRYPOINT ["/usr/bin/tini", "--"]

# Run with gunicorn for production
CMD ["gunicorn", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "4", \
     "--threads", "2", \
     "--worker-class", "gthread", \
     "--worker-tmp-dir", "/dev/shm", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "info", \
     "app:app"]
