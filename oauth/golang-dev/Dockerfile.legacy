# Step 1: Build Stage
FROM golang:1.20-alpine AS builder

# Install necessary build tools
RUN apk add --no-cache git

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files for dependency resolution
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the application
RUN go build -o oauth2-server .

# Step 2: Runtime Stage
FROM alpine:3.18

# Install certificates for HTTPS communication
RUN apk add --no-cache ca-certificates

# Set a non-root user for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set the working directory for the runtime container
WORKDIR /app

# Copy the binary from the build stage
COPY --from=builder /app/oauth2-server /app/oauth2-server

# Change ownership to the non-root user
RUN chown appuser:appgroup /app/oauth2-server

# Switch to the non-root user
USER appuser

# Expose the application's port (configurable via env)
EXPOSE 8080

# Define entrypoint with optional port override
ENTRYPOINT ["./oauth2-server"]
CMD []

