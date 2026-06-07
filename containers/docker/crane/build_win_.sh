#!/bin/bash

# Windows Container Builder using Crane
# Usage: ./windows-container-builder.sh [options]

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default values
APP_PATH=""
BASE_IMAGE="mcr.microsoft.com/dotnet/aspnet:8.0-windowsservercore-ltsc2022"
IMAGE_NAME=""
IMAGE_TAG="latest"
OUTPUT_TAR=""
PUSH_TO_REGISTRY=false
WORKDIR=""
CMD=""
ENTRYPOINT=""
PLATFORM="windows/amd64"
BUILD_CONFIG="Release"
FRAMEWORK=""
CLEANUP=true

print_usage() {
    cat << EOF
Windows Container Builder using Crane

Usage: $0 [OPTIONS]

Required:
  -a, --app-path PATH          Path to application source code
  -i, --image-name NAME        Name for the output image

Optional:
  -b, --base-image IMAGE       Base image (default: mcr.microsoft.com/dotnet/aspnet:8.0-windowsservercore-ltsc2022)
  -t, --tag TAG               Image tag (default: latest)
  -o, --output-tar FILE       Save as tar file instead of pushing
  -p, --push                  Push to registry (requires docker login)
  -w, --workdir PATH          Set working directory in container
  -c, --cmd COMMAND           Set default command
  -e, --entrypoint COMMAND    Set entrypoint
  --platform PLATFORM        Platform (default: windows/amd64)
  --build-config CONFIG       Build configuration (default: Release)
  --framework FRAMEWORK       Target framework (e.g., net8.0)
  --no-cleanup               Don't cleanup temporary files
  -h, --help                  Show this help

Examples:
  # Build .NET app and save as tar
  $0 -a ./myapp -i myapp -t 1.0.0 -o myapp.tar

  # Build and push to registry
  $0 -a ./myapp -i myregistry.azurecr.io/myapp -t 1.0.0 -p

  # Build with custom configuration
  $0 -a ./myapp -i myapp -w "C:\\app" -c "dotnet myapp.dll" --framework net8.0

EOF
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

cleanup_temp_files() {
    if [ "$CLEANUP" = true ]; then
        log_info "Cleaning up temporary files..."
        rm -f layer.tar build.tar
        rm -rf temp_build
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -a|--app-path)
            APP_PATH="$2"
            shift 2
            ;;
        -i|--image-name)
            IMAGE_NAME="$2"
            shift 2
            ;;
        -b|--base-image)
            BASE_IMAGE="$2"
            shift 2
            ;;
        -t|--tag)
            IMAGE_TAG="$2"
            shift 2
            ;;
        -o|--output-tar)
            OUTPUT_TAR="$2"
            shift 2
            ;;
        -p|--push)
            PUSH_TO_REGISTRY=true
            shift
            ;;
        -w|--workdir)
            WORKDIR="$2"
            shift 2
            ;;
        -c|--cmd)
            CMD="$2"
            shift 2
            ;;
        -e|--entrypoint)
            ENTRYPOINT="$2"
            shift 2
            ;;
        --platform)
            PLATFORM="$2"
            shift 2
            ;;
        --build-config)
            BUILD_CONFIG="$2"
            shift 2
            ;;
        --framework)
            FRAMEWORK="$2"
            shift 2
            ;;
        --no-cleanup)
            CLEANUP=false
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# Validate required parameters
if [ -z "$APP_PATH" ] || [ -z "$IMAGE_NAME" ]; then
    log_error "Missing required parameters"
    print_usage
    exit 1
fi

if [ ! -d "$APP_PATH" ]; then
    log_error "Application path does not exist: $APP_PATH"
    exit 1
fi

# Check if crane is installed
if ! command -v crane &> /dev/null; then
    log_error "crane is not installed. Install it with:"
    echo "  go install github.com/google/go-containerregistry/cmd/crane@latest"
    exit 1
fi

# Set up trap for cleanup
trap cleanup_temp_files EXIT

FULL_IMAGE_NAME="${IMAGE_NAME}:${IMAGE_TAG}"

log_info "Starting Windows container build process..."
log_info "App Path: $APP_PATH"
log_info "Base Image: $BASE_IMAGE"
log_info "Output Image: $FULL_IMAGE_NAME"
log_info "Platform: $PLATFORM"

# Step 1: Build the application
log_info "Building application..."
cd "$APP_PATH"

# Detect project type
if [ -f "*.csproj" ] || [ -f "*.sln" ]; then
    # .NET project
    BUILD_CMD="dotnet publish -c $BUILD_CONFIG -o ./app"
    if [ -n "$FRAMEWORK" ]; then
        BUILD_CMD="$BUILD_CMD -f $FRAMEWORK"
    fi
    
    log_info "Detected .NET project, running: $BUILD_CMD"
    eval $BUILD_CMD
    
    if [ ! -d "./app" ]; then
        log_error "Build output directory './app' not found"
        exit 1
    fi
    
    APP_DIR="./app"
    
elif [ -f "package.json" ]; then
    # Node.js project
    log_info "Detected Node.js project"
    if [ -f "package-lock.json" ]; then
        npm ci
    else
        npm install
    fi
    
    if npm run build 2>/dev/null; then
        log_info "Build script executed successfully"
    fi
    
    APP_DIR="."
    
elif [ -f "go.mod" ]; then
    # Go project
    log_info "Detected Go project"
    GOOS=windows GOARCH=amd64 go build -o ./app/
    APP_DIR="./app"
    
else
    log_warning "Unknown project type, using entire directory"
    APP_DIR="."
fi

# Step 2: Create application layer
log_info "Creating application layer..."
tar -cf ../layer.tar -C "$APP_DIR" .

cd ..

# Step 3: Build the container image
log_info "Assembling container image with crane..."

CRANE_CMD="crane append --platform=$PLATFORM -f layer.tar -t $FULL_IMAGE_NAME -b $BASE_IMAGE"

if [ -n "$OUTPUT_TAR" ]; then
    CRANE_CMD="$CRANE_CMD -o $OUTPUT_TAR"
    log_info "Saving image as: $OUTPUT_TAR"
else
    log_info "Building image: $FULL_IMAGE_NAME"
fi

eval $CRANE_CMD

if [ $? -eq 0 ]; then
    log_success "Image assembled successfully!"
else
    log_error "Failed to assemble image"
    exit 1
fi

# Step 4: Configure runtime settings
TEMP_IMAGE="$FULL_IMAGE_NAME"
if [ -n "$OUTPUT_TAR" ]; then
    TEMP_IMAGE="$OUTPUT_TAR"
fi

if [ -n "$WORKDIR" ] || [ -n "$CMD" ] || [ -n "$ENTRYPOINT" ]; then
    log_info "Applying runtime configuration..."
    
    MUTATE_CMD="crane mutate"
    
    if [ -n "$WORKDIR" ]; then
        MUTATE_CMD="$MUTATE_CMD --workdir=$WORKDIR"
        log_info "Setting working directory: $WORKDIR"
    fi
    
    if [ -n "$CMD" ]; then
        MUTATE_CMD="$MUTATE_CMD --cmd=$CMD"
        log_info "Setting command: $CMD"
    fi
    
    if [ -n "$ENTRYPOINT" ]; then
        MUTATE_CMD="$MUTATE_CMD --entrypoint=$ENTRYPOINT"
        log_info "Setting entrypoint: $ENTRYPOINT"
    fi
    
    if [ -n "$OUTPUT_TAR" ]; then
        # For tar files, we need to work with a temporary image
        crane push "$OUTPUT_TAR" "temp-$FULL_IMAGE_NAME"
        eval "$MUTATE_CMD temp-$FULL_IMAGE_NAME"
        crane pull "temp-$FULL_IMAGE_NAME" "$OUTPUT_TAR"
        crane delete "temp-$FULL_IMAGE_NAME" 2>/dev/null || true
    else
        eval "$MUTATE_CMD $TEMP_IMAGE"
    fi
fi

# Step 5: Push to registry if requested
if [ "$PUSH_TO_REGISTRY" = true ] && [ -z "$OUTPUT_TAR" ]; then
    log_info "Image already pushed to registry during build"
elif [ "$PUSH_TO_REGISTRY" = true ] && [ -n "$OUTPUT_TAR" ]; then
    log_info "Pushing image to registry..."
    crane push "$OUTPUT_TAR" "$FULL_IMAGE_NAME"
fi

# Summary
log_success "Windows container build completed!"
echo
echo "Summary:"
echo "  Source: $APP_PATH"
echo "  Base Image: $BASE_IMAGE"
echo "  Output Image: $FULL_IMAGE_NAME"
echo "  Platform: $PLATFORM"

if [ -n "$OUTPUT_TAR" ]; then
    echo "  Saved as: $OUTPUT_TAR"
    echo
    echo "To load into Docker:"
    echo "  docker load -i $OUTPUT_TAR"
fi

if [ "$PUSH_TO_REGISTRY" = true ]; then
    echo "  Pushed to registry: Yes"
fi

echo
echo "To run the container:"
if [ -n "$WORKDIR" ] && [ -n "$CMD" ]; then
    echo "  docker run --rm -it -p 8080:80 $FULL_IMAGE_NAME"
else
    echo "  docker run --rm -it -p 8080:80 --workdir c:\\app $FULL_IMAGE_NAME dotnet your-app.dll"
fi

log_success "Done!"
