#!/usr/bin/env bash

###############################################################################
# A chunky script to log into multiple ECR registries
# 
#  - Reads registry info from an optional control file, or uses an
#    in-script array if no file is provided.
#  - Uses `aws ecr get-login-password` to avoid passing the password
#    through command-line arguments.
#  - Exits if a Docker login fails for any registry.
#  - Obfuscates actual region/profile/account details with placeholders.
#
# Usage:
#   ./mega_docker_ecr_login.sh                # use in-script array
#   ./mega_docker_ecr_login.sh -f <filename>  # use control file
###############################################################################

set -euo pipefail

# Default array of registries to fall back on if no control file is used
# Format: "PROFILE ACCOUNT_ID REGION"
REGISTRIES=(
  "my-obfuscated-profile1 111111111111 us-obfuscated-1"
  "my-obfuscated-profile2 222222222222 eu-obfuscated-2"
  "my-obfuscated-profile3 333333333333 us-obfuscated-3"
)

CONTROL_FILE=""   # will hold the path to the optional control file

###############################################################################
# Print usage/help
###############################################################################
usage() {
  echo "Usage: $0 [-f <control_file>]"
  echo ""
  echo "  -f <control_file>   Specify a file containing registry info"
  echo "                      (one 'PROFILE ACCOUNT_ID REGION' per line)"
  echo "                      Lines starting with '#' or blank lines are ignored."
  echo "  -h                  Show this help message"
  exit 1
}

###############################################################################
# Parse command-line arguments
###############################################################################
while getopts ":f:h" opt; do
  case $opt in
    f)
      CONTROL_FILE="$OPTARG"
      ;;
    h)
      usage
      ;;
    *)
      usage
      ;;
  esac
done
shift $((OPTIND - 1))

###############################################################################
# Function to process a single line of registry data
#   line format: "PROFILE ACCOUNT_ID REGION"
###############################################################################
login_to_ecr() {
  local profile="$1"
  local account_id="$2"
  local region="$3"
  
  local registry_url="${account_id}.dkr.ecr.${region}.amazonaws.com"

  echo "Attempting ECR login for profile='${profile}', registry='${registry_url}'..."

  # Retrieve ECR password from AWS CLI (v2+), then pipe into docker login
  if ! aws ecr get-login-password --profile "${profile}" --region "${region}" \
      | docker login -u AWS --password-stdin "${registry_url}"; then
    echo "ERROR: Failed to log into ${registry_url} using profile '${profile}'"
    exit 1
  fi

  echo "Successfully logged into ${registry_url}"
  echo "--------------------------------------------------------"
}

###############################################################################
# If a control file is specified, read from that file; else use the in-script array
###############################################################################
if [[ -n "$CONTROL_FILE" && -f "$CONTROL_FILE" ]]; then
  echo "Using control file: ${CONTROL_FILE}"
  while IFS= read -r line; do
    # Skip blank lines or lines starting with '#'
    [[ -z "$line" || "$line" =~ ^# ]] && continue
    
    # shellcheck disable=SC2086
    set -- $line
    login_to_ecr "$1" "$2" "$3"
  done < "$CONTROL_FILE"
else
  echo "No (valid) control file supplied, using in-script REGISTRIES array..."
  for reg_info in "${REGISTRIES[@]}"; do
    # shellcheck disable=SC2086
    set -- $reg_info
    login_to_ecr "$1" "$2" "$3"
  done
fi

echo "All ECR logins completed!"

##
##
