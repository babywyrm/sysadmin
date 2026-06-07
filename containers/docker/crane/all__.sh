#!/bin/bash

# Docker Image Inspector using Crane
# Usage: ./image-inspector.sh <image:tag>

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

print_section() {
    echo -e "${YELLOW}--- $1 ---${NC}"
}

print_value() {
    echo -e "${GREEN}$1:${NC} $2"
}

print_error() {
    echo -e "${RED}ERROR: $1${NC}" >&2
}

# Check if crane is installed
if ! command -v crane &> /dev/null; then
    print_error "crane is not installed. Install it with: go install github.com/google/go-containerregistry/cmd/crane@latest"
    exit 1
fi

# Check if image argument is provided
if [ $# -eq 0 ]; then
    print_error "Usage: $0 <image:tag>"
    print_error "Example: $0 nginx:latest"
    exit 1
fi

IMAGE="$1"
echo -e "${CYAN}Inspecting image: $IMAGE${NC}"
echo

# Get basic image info
print_header "IMAGE OVERVIEW"

# Get manifest digest
print_section "Manifest Information"
MANIFEST_DIGEST=$(crane digest "$IMAGE" 2>/dev/null || echo "N/A")
print_value "Manifest Digest" "$MANIFEST_DIGEST"

# Get manifest content
MANIFEST=$(crane manifest "$IMAGE" 2>/dev/null || echo "{}")
MANIFEST_TYPE=$(echo "$MANIFEST" | jq -r '.mediaType // "N/A"' 2>/dev/null || echo "N/A")
print_value "Manifest Type" "$MANIFEST_TYPE"

# Get schema version
SCHEMA_VERSION=$(echo "$MANIFEST" | jq -r '.schemaVersion // "N/A"' 2>/dev/null || echo "N/A")
print_value "Schema Version" "$SCHEMA_VERSION"

echo

# Get config information
print_section "Config Information"
CONFIG_DIGEST=$(echo "$MANIFEST" | jq -r '.config.digest // "N/A"' 2>/dev/null || echo "N/A")
print_value "Config Digest" "$CONFIG_DIGEST"

CONFIG_SIZE=$(echo "$MANIFEST" | jq -r '.config.size // "N/A"' 2>/dev/null || echo "N/A")
print_value "Config Size" "$CONFIG_SIZE bytes"

CONFIG_MEDIA_TYPE=$(echo "$MANIFEST" | jq -r '.config.mediaType // "N/A"' 2>/dev/null || echo "N/A")
print_value "Config Media Type" "$CONFIG_MEDIA_TYPE"

echo

# Get actual config content
print_section "Image Configuration"
CONFIG_CONTENT=$(crane config "$IMAGE" 2>/dev/null || echo "{}")

# Extract key config details
IMAGE_ID=$(echo "$CONFIG_CONTENT" | jq -r '.config.Image // "N/A"' 2>/dev/null || echo "N/A")
print_value "Image ID" "$IMAGE_ID"

ARCHITECTURE=$(echo "$CONFIG_CONTENT" | jq -r '.architecture // "N/A"' 2>/dev/null || echo "N/A")
print_value "Architecture" "$ARCHITECTURE"

OS=$(echo "$CONFIG_CONTENT" | jq -r '.os // "N/A"' 2>/dev/null || echo "N/A")
print_value "OS" "$OS"

CREATED=$(echo "$CONFIG_CONTENT" | jq -r '.created // "N/A"' 2>/dev/null || echo "N/A")
print_value "Created" "$CREATED"

AUTHOR=$(echo "$CONFIG_CONTENT" | jq -r '.author // "N/A"' 2>/dev/null || echo "N/A")
print_value "Author" "$AUTHOR"

echo

# Get layer information
print_header "LAYER ANALYSIS"

# Count layers
LAYER_COUNT=$(echo "$MANIFEST" | jq '.layers | length' 2>/dev/null || echo "0")
print_value "Total Layers" "$LAYER_COUNT"

echo
print_section "Layer Details"

# Loop through layers
echo "$MANIFEST" | jq -r '.layers[]? | "\(.digest)|\(.size)|\(.mediaType)"' 2>/dev/null | while IFS='|' read -r digest size media_type; do
    echo -e "${PURPLE}Layer:${NC} $digest"
    echo -e "  ${GREEN}Size:${NC} $size bytes ($(numfmt --to=iec --suffix=B $size 2>/dev/null || echo "$size bytes"))"
    echo -e "  ${GREEN}Media Type:${NC} $media_type"
    echo
done

# Get history information
print_section "Build History"
HISTORY=$(echo "$CONFIG_CONTENT" | jq -r '.history[]? | "\(.created_by // "N/A")|\(.created // "N/A")"' 2>/dev/null)

if [ -n "$HISTORY" ]; then
    echo "$HISTORY" | while IFS='|' read -r created_by created; do
        echo -e "${PURPLE}Command:${NC} $created_by"
        echo -e "  ${GREEN}Created:${NC} $created"
        echo
    done
else
    echo "No build history available"
fi

# Get environment variables
print_section "Environment Variables"
ENV_VARS=$(echo "$CONFIG_CONTENT" | jq -r '.config.Env[]? // empty' 2>/dev/null)
if [ -n "$ENV_VARS" ]; then
    echo "$ENV_VARS" | while read -r env_var; do
        echo -e "${GREEN}$env_var${NC}"
    done
else
    echo "No environment variables set"
fi

echo

# Get exposed ports
print_section "Exposed Ports"
EXPOSED_PORTS=$(echo "$CONFIG_CONTENT" | jq -r '.config.ExposedPorts // {} | keys[]?' 2>/dev/null)
if [ -n "$EXPOSED_PORTS" ]; then
    echo "$EXPOSED_PORTS" | while read -r port; do
        echo -e "${GREEN}$port${NC}"
    done
else
    echo "No exposed ports"
fi

echo

# Get volumes
print_section "Volumes"
VOLUMES=$(echo "$CONFIG_CONTENT" | jq -r '.config.Volumes // {} | keys[]?' 2>/dev/null)
if [ -n "$VOLUMES" ]; then
    echo "$VOLUMES" | while read -r volume; do
        echo -e "${GREEN}$volume${NC}"
    done
else
    echo "No volumes defined"
fi

echo

# Get working directory
print_section "Runtime Configuration"
WORKDIR=$(echo "$CONFIG_CONTENT" | jq -r '.config.WorkingDir // "N/A"' 2>/dev/null || echo "N/A")
print_value "Working Directory" "$WORKDIR"

USER=$(echo "$CONFIG_CONTENT" | jq -r '.config.User // "N/A"' 2>/dev/null || echo "N/A")
print_value "User" "$USER"

ENTRYPOINT=$(echo "$CONFIG_CONTENT" | jq -r '.config.Entrypoint[]? // empty' 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
print_value "Entrypoint" "${ENTRYPOINT:-N/A}"

CMD=$(echo "$CONFIG_CONTENT" | jq -r '.config.Cmd[]? // empty' 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
print_value "Command" "${CMD:-N/A}"

echo

# Get labels
print_section "Labels"
LABELS=$(echo "$CONFIG_CONTENT" | jq -r '.config.Labels // {} | to_entries[] | "\(.key)=\(.value)"' 2>/dev/null)
if [ -n "$LABELS" ]; then
    echo "$LABELS" | while read -r label; do
        echo -e "${GREEN}$label${NC}"
    done
else
    echo "No labels defined"
fi

echo

# Calculate total size
print_header "SIZE ANALYSIS"
TOTAL_SIZE=$(echo "$MANIFEST" | jq '[.layers[]?.size] | add' 2>/dev/null || echo "0")
print_value "Total Compressed Size" "$TOTAL_SIZE bytes ($(numfmt --to=iec --suffix=B $TOTAL_SIZE 2>/dev/null || echo "$TOTAL_SIZE bytes"))"

CONFIG_SIZE_BYTES=$(echo "$MANIFEST" | jq -r '.config.size // 0' 2>/dev/null || echo "0")
print_value "Config Size" "$CONFIG_SIZE_BYTES bytes"

echo

# Get platform information
print_header "PLATFORM INFORMATION"
PLATFORM=$(echo "$MANIFEST" | jq -r '.platform // "N/A"' 2>/dev/null || echo "N/A")
print_value "Platform" "$PLATFORM"

OS_VERSION=$(echo "$CONFIG_CONTENT" | jq -r '.os.version // "N/A"' 2>/dev/null || echo "N/A")
print_value "OS Version" "$OS_VERSION"

OS_FEATURES=$(echo "$CONFIG_CONTENT" | jq -r '.os.features[]? // empty' 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
print_value "OS Features" "${OS_FEATURES:-N/A}"

VARIANT=$(echo "$CONFIG_CONTENT" | jq -r '.variant // "N/A"' 2>/dev/null || echo "N/A")
print_value "Variant" "$VARIANT"

echo

# Summary
print_header "SUMMARY"
echo -e "${CYAN}Image:${NC} $IMAGE"
echo -e "${CYAN}Manifest Digest:${NC} $MANIFEST_DIGEST"
echo -e "${CYAN}Config Digest:${NC} $CONFIG_DIGEST"
echo -e "${CYAN}Architecture:${NC} $ARCHITECTURE"
echo -e "${CYAN}OS:${NC} $OS"
echo -e "${CYAN}Layers:${NC} $LAYER_COUNT"
echo -e "${CYAN}Total Size:${NC} $(numfmt --to=iec --suffix=B $TOTAL_SIZE 2>/dev/null || echo "$TOTAL_SIZE bytes")"

echo -e "\n${GREEN}Analysis complete!${NC}"
