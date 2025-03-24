#!/bin/bash

##
## https://medium.com/@reefland/cri-purge-kubernetes-cleanup-of-cached-images-b7087af3bf1d
##

# Enable strict error handling
set -euo pipefail
IFS=$'\n\t'

# Script metadata
readonly SCRIPT_NAME=$(basename "${0}")
readonly AUTHOR="Richard J. Durso"
readonly RELDATE="06/10/2024"
readonly VERSION="0.1.3"

# Command configuration
readonly CRI_CMD="crictl"
readonly CRIINFO_CMD="crio-status"

# Image configuration
readonly IMAGE_VERSION_REGEX="^\S+\s+[\w\-_\.\d]+\s+.*"

# Logging levels
declare -r LOG_ERROR=0
declare -r LOG_WARN=1
declare -r LOG_INFO=2
declare -r LOG_DEBUG=3

# Global variables
declare DRY_RUN=0
declare LOG_LEVEL=${LOG_DEBUG}
declare IMAGE_STORE=""

# Temporary files
declare -g CRI_IMAGES=""
declare -g CRI_IMAGES_SKIP=""
declare -g UNIQUE_CRI_IMAGE_NAMES=""

log() {
    local level=$1
    shift
    local message="$*"
    
    if [[ ${level} -le ${LOG_LEVEL} ]]; then
        case ${level} in
            ${LOG_ERROR}) echo "[ERROR] ${message}" >&2 ;;
            ${LOG_WARN})  echo "[WARN]  ${message}" >&2 ;;
            ${LOG_INFO})  echo "[INFO]  ${message}" ;;
            ${LOG_DEBUG}) echo "[DEBUG] ${message}" ;;
        esac
    fi
}

cleanup() {
    local exit_code=$?
    
    # Remove temporary files
    rm -f "${CRI_IMAGES}" "${CRI_IMAGES_SKIP}" "${UNIQUE_CRI_IMAGE_NAMES}" 2>/dev/null || true
    
    # Log exit status if not successful
    if [[ ${exit_code} -ne 0 ]]; then
        log ${LOG_ERROR} "Script exited with status ${exit_code}"
    fi
    
    exit ${exit_code}
}

init_temp_files() {
    CRI_IMAGES=$(mktemp "/tmp/${SCRIPT_NAME}.XXXXXX")
    CRI_IMAGES_SKIP=$(mktemp "/tmp/${SCRIPT_NAME}.XXXXXX")
    UNIQUE_CRI_IMAGE_NAMES=$(mktemp "/tmp/${SCRIPT_NAME}.XXXXXX")
    
    # Ensure temp files are created successfully
    if [[ ! -f "${CRI_IMAGES}" ]] || [[ ! -f "${CRI_IMAGES_SKIP}" ]] || [[ ! -f "${UNIQUE_CRI_IMAGE_NAMES}" ]]; then
        log ${LOG_ERROR} "Failed to create temporary files"
        exit 1
    }
    
    # Set appropriate permissions
    chmod 600 "${CRI_IMAGES}" "${CRI_IMAGES_SKIP}" "${UNIQUE_CRI_IMAGE_NAMES}"
}

check_prerequisites() {
    # Check for root privileges
    if [[ $(id -u) -ne 0 ]]; then
        log ${LOG_ERROR} "ROOT privileges required to access CRICTL binaries"
        exit 1
    }
    
    # Check for required commands
    if ! command -v "${CRI_CMD}" >/dev/null 2>&1 && ! command -v "${CRIINFO_CMD}" >/dev/null 2>&1; then
        log ${LOG_ERROR} "${CRI_CMD}/${CRIINFO_CMD} commands not found"
        exit 1
    }
}

determine_containerd_root_dir() {
    # Try crictl info first
    IMAGE_STORE=$(${CRI_CMD} info 2>/dev/null | awk -F'"' '/containerdRootDir/{print $4}' || true)
    
    # Fall back to crio-status if needed
    if [[ -z "${IMAGE_STORE}" ]]; then
        IMAGE_STORE=$(${CRIINFO_CMD} info 2>/dev/null | awk -F'storage root: ' '/storage root:/ {print $2}' || true)
    fi
    
    if [[ ! -d "${IMAGE_STORE}" ]]; then
        log ${LOG_WARN} "Unable to determine containerd root directory"
        return 1
    fi
    
    return 0
}

# ... (remaining functions would be updated similarly)

main() {
    trap cleanup EXIT
    
    check_prerequisites
    init_temp_files
    
    # Process command line arguments
    if [[ $# -eq 0 ]]; then
        usage
        exit 1
    fi
    
    determine_containerd_root_dir
    
    # ... (rest of main logic)
}

main "$@"
