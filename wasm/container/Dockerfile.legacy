##
##

# Use a base image with Wasmer installed or install Wasmer yourself
FROM debian:bullseye-slim

# Install Wasmer dependencies
RUN apt-get update && apt-get install -y curl

# Download and install Wasmer
RUN curl https://get.wasmer.io -sSfL | sh

# Set Wasmer binary path
ENV PATH="/root/.wasmer/bin:$PATH"

# Create the application directory
WORKDIR /app

# Copy the WASM module into the container
COPY my_module.wasm /app/my_module.wasm

# Copy any other necessary files (e.g., a run script)
COPY run.sh /app/run.sh
RUN chmod +x /app/run.sh

# Define the entrypoint to run the WASM module
ENTRYPOINT ["/app/run.sh"]

##
##
