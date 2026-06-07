FROM alpine:latest

# Install dependencies
RUN apk add --no-cache wasmtime

# Create a non-root user for running the application
RUN addgroup -S wasmgroup && adduser -S wasmuser -G wasmgroup

# Set working directory
WORKDIR /app

# Copy the WASM module into the container
COPY ./pkg /app/pkg

# Set permissions
RUN chown -R wasmuser:wasmgroup /app

# Switch to the non-root user
USER wasmuser

# Secure volume mount point
VOLUME /secure_js

# Entrypoint to run the WASM module
ENTRYPOINT ["sh", "-c", "wasmtime /app/pkg/wasm_app_bg.wasm --invoke run_js_code \"$(cat /secure_js/custom.js)\""]

##
##
