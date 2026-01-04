# ==============================================================================
# GOLDEN NODE.JS DOCKERFILE (ALPINE)
# ------------------------------------------------------------------------------
# Goals:
#   - Secure by default
#   - Reproducible builds
#   - Minimal runtime surface
#   - CVE / SBOM friendly
#   - musl-compatible
#
# Target use:
#   - Production workloads
#   - CI/CD pipelines
#   - Security-reviewed environments
#
# Alpine version intentionally pinned for reproducibility.
# Node.js comes from Alpine repos (NOT curl | bash).
# ==============================================================================

############################
# 1️⃣ BASE METADATA STAGE
############################
FROM alpine:3.20 AS base

LABEL org.opencontainers.image.title="golden-node-alpine"
LABEL org.opencontainers.image.description="Secure, minimal Node.js runtime on Alpine"
LABEL org.opencontainers.image.source="internal"
LABEL org.opencontainers.image.licenses="MIT"

# Prevent interactive prompts & reduce noise
ENV CI=true \
    NODE_ENV=production

# ------------------------------------------------------------------------------
# Install runtime dependencies ONLY
#   - nodejs + npm from Alpine repos
#   - ca-certificates for TLS
#   - tini for signal handling (PID 1 correctness)
# ------------------------------------------------------------------------------
RUN apk add --no-cache \
        nodejs \
        npm \
        ca-certificates \
        tini \
    && update-ca-certificates

# Use tini as PID 1 to correctly handle SIGTERM/SIGINT
ENTRYPOINT ["/sbin/tini", "--"]

############################
# 2️⃣ DEPENDENCY BUILD STAGE
############################
FROM base AS deps

# ------------------------------------------------------------------------------
# Build-only dependencies
# These are REQUIRED for node-gyp / native modules
# They will NOT exist in the final image.
# ------------------------------------------------------------------------------
RUN apk add --no-cache --virtual .build-deps \
        python3 \
        make \
        g++ \
        linux-headers

WORKDIR /app

# ------------------------------------------------------------------------------
# Copy only dependency manifests
# This maximizes Docker layer cache efficiency.
# ------------------------------------------------------------------------------
COPY package.json package-lock.json ./

# ------------------------------------------------------------------------------
# Install dependencies in a deterministic way
#   - npm ci = reproducible, lockfile enforced
#   - --omit=dev = no devDependencies
#   - --ignore-scripts can be enabled if supply-chain risk is high
# ------------------------------------------------------------------------------
RUN npm ci --omit=dev \
    && npm cache clean --force

############################
# 3️⃣ APPLICATION BUILD STAGE (OPTIONAL)
############################
# If your app requires a build step (TypeScript, bundling, etc),
# keep it HERE so the runtime stays clean.
#
# If not needed, this stage can be removed safely.
############################
FROM deps AS build

# Copy application source
COPY . .

# Example build step (uncomment if applicable)
# RUN npm run build

############################
# 4️⃣ FINAL RUNTIME STAGE
############################
FROM base AS runtime

# ------------------------------------------------------------------------------
# Create non-root user
# ------------------------------------------------------------------------------
RUN addgroup -S nodeapp \
    && adduser -S -G nodeapp -h /app nodeapp

WORKDIR /app

# ------------------------------------------------------------------------------
# Copy only what is needed to run
#   - node_modules from deps
#   - built artifacts OR source
# ------------------------------------------------------------------------------
COPY --from=deps /app/node_modules ./node_modules
COPY --from=build /app ./ 

# ------------------------------------------------------------------------------
# Security hardening
# ------------------------------------------------------------------------------
RUN chown -R nodeapp:nodeapp /app \
    && chmod -R go-w /app

USER nodeapp

# ------------------------------------------------------------------------------
# Network hygiene
# ------------------------------------------------------------------------------
EXPOSE 3000

# ------------------------------------------------------------------------------
# Runtime command
# ------------------------------------------------------------------------------
CMD ["node", "index.js"]
