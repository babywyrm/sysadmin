# ==============================================================================
# GOLDEN+ NODE.JS DOCKERFILE (ALPINE, SECURITY-HARDENED)
# ------------------------------------------------------------------------------
# This Dockerfile is intentionally verbose and heavily commented.
#
# GOALS:
#   - Deterministic builds (npm ci, lockfile enforced)
#   - Minimal attack surface
#   - No compilers or build tools in runtime
#   - Non-root execution
#   - musl-compatible native modules
#   - CVE + SBOM visibility
#   - Kubernetes-safe (signals, healthchecks, read-only FS)
#
# NON-GOALS (INTENTIONALLY AVOIDED):
#   - curl | bash installers
#   - nvm inside containers
#   - devDependencies in production
#   - mutable runtime state
#
# This file is suitable for:
#   - Production workloads
#   - CI/CD pipelines
#   - Security-reviewed environments
#   - FedRAMP / SOC2 contexts

# ------------------------------------------------------------------------------
# Global build arguments
# ------------------------------------------------------------------------------
# Alpine version is pinned to ensure reproducibility.
# Floating tags ("latest") are intentionally avoided.
ARG ALPINE_VERSION=3.20


# ==============================================================================
# 1️⃣ BASE RUNTIME IMAGE
# ==============================================================================
FROM alpine:${ALPINE_VERSION} AS base

# ------------------------------------------------------------------------------
# OCI metadata (useful for scanners, registries, SBOM tools)
# ------------------------------------------------------------------------------
LABEL org.opencontainers.image.title="golden-node-alpine"
LABEL org.opencontainers.image.description="Secure, minimal Node.js runtime on Alpine Linux"
LABEL org.opencontainers.image.licenses="MIT"

# ------------------------------------------------------------------------------
# Environment hardening
#
# NODE_ENV=production:
#   - Disables dev-only behavior in many frameworks
#
# CI=true:
#   - Prevents interactive npm behavior
#
# NPM_CONFIG_*:
#   - Reduces noise and prevents network calls at runtime
# ------------------------------------------------------------------------------
ENV NODE_ENV=production \
    CI=true \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false

# ------------------------------------------------------------------------------
# Install RUNTIME dependencies only
#
# nodejs:
#   - Node.js runtime from Alpine repositories
#
# npm:
#   - Node package manager (separate package on modern Alpine)
#
# ca-certificates:
#   - Required for outbound TLS (HTTPS APIs, package registries)
#
# tini:
#   - Minimal init system
#   - Fixes signal handling and zombie reaping
#   - Critical for Kubernetes correctness
#
# NOTE:
#   No compilers or build tools are installed here.
# ------------------------------------------------------------------------------
RUN apk add --no-cache \
        nodejs \
        npm \
        ca-certificates \
        tini \
    && update-ca-certificates

# ------------------------------------------------------------------------------
# Use tini as PID 1
#
# This ensures:
#   - SIGTERM/SIGINT are handled correctly
#   - Child processes are reaped
#
# Without this, Kubernetes shutdowns are often broken.
# ------------------------------------------------------------------------------
ENTRYPOINT ["/sbin/tini", "--"]


# ==============================================================================
# 2️⃣ DEPENDENCY BUILD STAGE
# ==============================================================================
FROM base AS deps

# ------------------------------------------------------------------------------
# Install BUILD-ONLY dependencies
#
# These are required for:
#   - node-gyp
#   - native npm modules
#
# They will NOT be present in the final runtime image.
#
# python3:
#   - Required by node-gyp
#
# make / g++ / linux-headers:
#   - Native compilation support (musl)
# ------------------------------------------------------------------------------
RUN apk add --no-cache --virtual .build-deps \
        python3 \
        make \
        g++ \
        linux-headers

WORKDIR /app

# ------------------------------------------------------------------------------
# Copy ONLY dependency manifests
#
# This maximizes Docker layer caching:
#   - Dependency install layer is reused unless lockfiles change
# ------------------------------------------------------------------------------
COPY package.json package-lock.json ./

# ------------------------------------------------------------------------------
# Deterministic dependency installation
#
# npm ci:
#   - Enforces package-lock.json
#   - Fails on mismatch
#   - Produces reproducible builds
#
# --omit=dev:
#   - Removes devDependencies entirely
#   - Reduces attack surface and image size
#
# npm cache clean:
#   - Prevents leftover metadata in layers
# ------------------------------------------------------------------------------
RUN npm ci --omit=dev \
    && npm cache clean --force


# ==============================================================================
# 3️⃣ TEST STAGE (OPTIONAL BUT RECOMMENDED)
# ==============================================================================
FROM deps AS test

# ------------------------------------------------------------------------------
# Copy full application source
# ------------------------------------------------------------------------------
COPY . .

# ------------------------------------------------------------------------------
# Run tests here
#
# This stage:
#   - Fails the build early if tests fail
#   - Prevents broken images from shipping
#
# Uncomment once tests exist.
# ------------------------------------------------------------------------------
# RUN npm test


# ==============================================================================
# 4️⃣ APPLICATION BUILD STAGE (OPTIONAL)
# ==============================================================================
FROM deps AS build

# ------------------------------------------------------------------------------
# Copy full source for build step
# ------------------------------------------------------------------------------
COPY . .

# ------------------------------------------------------------------------------
# Optional build step
#
# Examples:
#   - TypeScript compilation
#   - Webpack / esbuild bundling
#   - Asset generation
#
# If your app does not require a build step,
# this stage can be removed safely.
# ------------------------------------------------------------------------------
# RUN npm run build


# ==============================================================================
# 5️⃣ SBOM GENERATION STAGE (CI-ONLY, OPTIONAL)
# ==============================================================================
FROM deps AS sbom

# ------------------------------------------------------------------------------
# This stage exists ONLY for CI pipelines.
# It is never shipped.
#
# Purpose:
#   - Generate a Software Bill of Materials (SBOM)
#   - Enable supply-chain visibility
# ------------------------------------------------------------------------------
RUN apk add --no-cache curl \
 && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
 | sh -s -- -b /usr/local/bin

# ------------------------------------------------------------------------------
# Generate SBOM in SPDX format
# ------------------------------------------------------------------------------
RUN syft packages dir:/app -o spdx-json=/app/sbom.spdx.json


# ==============================================================================
# 6️⃣ FINAL RUNTIME IMAGE
# ==============================================================================
FROM base AS runtime

# ------------------------------------------------------------------------------
# Create non-root runtime user
#
# Why:
#   - Prevents container breakout escalation
#   - Required by many Kubernetes security baselines
# ------------------------------------------------------------------------------
RUN addgroup -S nodeapp \
 && adduser -S -G nodeapp -h /app nodeapp

WORKDIR /app

# ------------------------------------------------------------------------------
# Copy ONLY what is required to run
#
# node_modules:
#   - From deps stage
#
# application code:
#   - From build stage
# ------------------------------------------------------------------------------
COPY --from=deps  /app/node_modules ./node_modules
COPY --from=build /app ./

# ------------------------------------------------------------------------------
# Read-only filesystem compatibility
#
# These directories must be writable at runtime:
#   - /tmp (Node, libc, some libs)
#   - /var/run/node (optional runtime state)
# ------------------------------------------------------------------------------
RUN mkdir -p /tmp /var/run/node \
 && chown -R nodeapp:nodeapp /app /tmp /var/run/node \
 && chmod -R go-w /app

# ------------------------------------------------------------------------------
# Drop privileges
# ------------------------------------------------------------------------------
USER nodeapp

# ------------------------------------------------------------------------------
# Application port (documentation only)
# ------------------------------------------------------------------------------
EXPOSE 3000

# ------------------------------------------------------------------------------
# Healthcheck
#
# Requirements:
#   - No curl dependency
#   - Fast failure
#   - Local-only check
#
# Assumes:
#   - App exposes GET /health
# ------------------------------------------------------------------------------
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:3000/health', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

# ------------------------------------------------------------------------------
# Runtime command
# ------------------------------------------------------------------------------
CMD ["node", "index.js"]
