#!/usr/bin/env bash

###############################################################################
# mega_docker_ecr_login.sh
#
# Purpose:
#   Batch login script for multiple AWS ECR registries.
#
# Features:
#   - Supports control file OR in-script registry list
#   - Uses aws-cli v2 secure password retrieval (no credentials written to disk)
#   - Graceful error handling with exit codes
#   - Optional parallel login mode (--parallel)
#   - Optional quiet mode (--quiet)
#   - Structured logging with timestamps
#   - Minimal dependencies: bash >=4, aws-cli v2, docker
#
# Usage:
#   ./mega_docker_ecr_login.sh
#   ./mega_docker_ecr_login.sh -f path/to/registries.txt
#   ./mega_docker_ecr_login.sh -f path/to/registries.txt --parallel
#
# File Format (control file):
#   PROFILE ACCOUNT_ID REGION
#   Example:
#     dev 123456789012 us-east-1
#     prod 987654321098 eu-west-1
###############################################################################

set -euo pipefail
IFS=$'\n\t'

# ----------------------------------------------------------------------------- #
# Default configuration
# ----------------------------------------------------------------------------- #

# Fallback registries if no file is provided
REGISTRIES=(
  "my-profile1 111111111111 us-obfuscated-1"
  "my-profile2 222222222222 eu-obfuscated-2"
  "my-profile3 333333333333 us-obfuscated-3"
)

CONTROL_FILE=""
PARALLEL=false
QUIET=false
LOGFILE="./ecr_login_$(date +'%Y%m%d_%H%M%S').log"

# ----------------------------------------------------------------------------- #
# Helper Functions
# ----------------------------------------------------------------------------- #

log() {
  # Print to both stdout and logfile unless quiet mode is enabled
  local msg="[$(date +'%Y-%m-%d %H:%M:%S')] $*"
  [[ "${QUIET}" == "false" ]] && echo "${msg}"
  echo "${msg}" >> "${LOGFILE}"
}

usage() {
  cat <<EOF
Usage: $(basename "$0") [-f <control_file>] [--parallel] [--quiet] [-h]

Options:
  -f <control_file>   Specify control file (one 'PROFILE ACCOUNT_ID REGION' per line)
  --parallel          Enable parallel logins (faster, but AWS API-heavy)
  --quiet             Suppress console output (only logs to file)
  -h                  Show help and exit

Examples:
  $(basename "$0")                    # Use builtin REGISTRIES
  $(basename "$0") -f registries.txt  # Use external control file
  $(basename "$0") -f registries.txt --parallel
EOF
  exit 0
}

check_dependencies() {
  local deps=("aws" "docker")
  for dep in "${deps[@]}"; do
    if ! command -v "$dep" &>/dev/null; then
      echo "Error: '$dep' command not found. Please install it."
      exit 1
    fi
  done
}

# ----------------------------------------------------------------------------- #
# Core Functionality
# ----------------------------------------------------------------------------- #

login_to_ecr() {
  local profile="$1" account_id="$2" region="$3"
  local registry_url="${account_id}.dkr.ecr.${region}.amazonaws.com"

  log "Starting ECR login: profile='${profile}', registry='${registry_url}'"

  if ! aws ecr get-login-password --profile "${profile}" --region "${region}" \
    | docker login --username AWS --password-stdin "${registry_url}" >>"${LOGFILE}" 2>&1; then
    log "Login failed for ${registry_url} (profile: ${profile})"
    return 1
  fi

  log "Successful ECR login for ${registry_url}"
}

process_registries() {
  local -a entries=("${@}")

  if [[ "${PARALLEL}" == "true" ]]; then
    log "Parallel mode: executing logins concurrently..."
    for entry in "${entries[@]}"; do
      # shellcheck disable=SC2086
      set -- $entry
      login_to_ecr "$1" "$2" "$3" &
    done
    wait
  else
    for entry in "${entries[@]}"; do
      # shellcheck disable=SC2086
      set -- $entry
      login_to_ecr "$1" "$2" "$3"
    done
  fi
}

# ----------------------------------------------------------------------------- #
# Script Entry
# ----------------------------------------------------------------------------- #

check_dependencies

# Parse arguments
while (( "$#" )); do
  case "$1" in
    -f)
      CONTROL_FILE="$2"; shift 2 ;;
    --parallel)
      PARALLEL=true; shift ;;
    --quiet)
      QUIET=true; shift ;;
    -h|--help)
      usage ;;
    *)
      echo "Unknown option: $1"; usage ;;
  esac
done

log "Mega ECR Login Script Started"
log "Log file: ${LOGFILE}"

# Populate registry list
declare -a REGISTRY_DATA

if [[ -n "$CONTROL_FILE" && -f "$CONTROL_FILE" ]]; then
  log "Using control file: ${CONTROL_FILE}"
  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^# ]] && continue
    REGISTRY_DATA+=("$line")
  done < "$CONTROL_FILE"
else
  log "No control file found; using default registry array"
  REGISTRY_DATA=("${REGISTRIES[@]}")
fi

process_registries "${REGISTRY_DATA[@]}"

log "All ECR logins completed successfully"
log "End of script"
