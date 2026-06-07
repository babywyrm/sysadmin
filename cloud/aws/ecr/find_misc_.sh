#!/usr/bin/env bash
# find-ecr-image.sh
#
# Modern ECR image existence checker for private and public ECR.
#
# Features:
#   - private ECR and public ECR support
#   - lookup by tag or digest
#   - optional region and registry ID
#   - text, json, or quiet output
#   - CI-friendly exit codes
#   - safer Bash defaults
#
# Exit codes:
#   0 = image found
#   1 = image not found
#   2 = usage / dependency / configuration error
#   3 = AWS CLI/API failure
#
# Examples:
#   ./find-ecr-image.sh --repository foo/bar --tag mytag
#   ./find-ecr-image.sh -r foo/bar -t mytag --json
#   ./find-ecr-image.sh -r foo/bar --digest sha256:abcd...
#   ./find-ecr-image.sh -r public/repo -t latest --public
#   ./find-ecr-image.sh -r foo/bar -t mytag --region us-west-2 --registry-id 123456789012
#   ./find-ecr-image.sh -r foo/bar -t mytag --quiet

set -o errexit
set -o nounset
set -o pipefail

readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"

usage() {
  cat <<'EOF'
find-ecr-image.sh - Check whether an image exists in AWS ECR

Usage:
  find-ecr-image.sh --repository NAME (--tag TAG | --digest DIGEST) [options]

Required:
  -r, --repository NAME        ECR repository name
  -t, --tag TAG                Image tag to search for
  -d, --digest DIGEST          Image digest to search for (example: sha256:...)

Options:
      --public                 Query Amazon ECR Public instead of private ECR
      --region REGION          AWS region for private ECR
      --registry-id ID         AWS account registry ID for private ECR
      --profile PROFILE        AWS CLI profile to use
      --json                   Emit structured JSON
  -q, --quiet                  No stdout output; rely on exit code only
  -v, --verbose                Emit diagnostic messages to stderr
  -h, --help                   Show this help

Notes:
  - For ECR Public, AWS CLI operations are typically run against us-east-1.
  - Exit code 0 means found, 1 means not found.
  - Exit code 3 means AWS/API failure rather than "not found".

Examples:
  find-ecr-image.sh -r foo/bar -t mytag
  find-ecr-image.sh -r foo/bar -d sha256:deadbeef
  find-ecr-image.sh -r public/repo -t latest --public
  find-ecr-image.sh -r foo/bar -t mytag --json
EOF
}

log() {
  if [[ "${VERBOSE}" == "true" ]]; then
    printf '[*] %s\n' "$*" >&2
  fi
}

warn() {
  printf '[!] %s\n' "$*" >&2
}

die() {
  warn "$1"
  exit "${2:-2}"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1" 2
}

json_escape() {
  local s=${1//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

emit_text_found() {
  if [[ "${QUIET}" == "true" ]]; then
    return 0
  fi

  if [[ -n "${TAG}" ]]; then
    printf '%s:%s found\n' "${REPOSITORY}" "${TAG}"
  else
    printf '%s@%s found\n' "${REPOSITORY}" "${DIGEST}"
  fi
}

emit_text_not_found() {
  if [[ "${QUIET}" == "true" ]]; then
    return 0
  fi

  if [[ -n "${TAG}" ]]; then
    printf '%s:%s not found\n' "${REPOSITORY}" "${TAG}"
  else
    printf '%s@%s not found\n' "${REPOSITORY}" "${DIGEST}"
  fi
}

emit_json() {
  local found="$1"
  local image_ref=""
  local repo_escaped detail_escaped

  if [[ -n "${TAG}" ]]; then
    image_ref="${REPOSITORY}:${TAG}"
  else
    image_ref="${REPOSITORY}@${DIGEST}"
  fi

  repo_escaped="$(json_escape "${REPOSITORY}")"
  detail_escaped="$(json_escape "${image_ref}")"

  cat <<EOF
{
  "found": ${found},
  "repository": "${repo_escaped}",
  "image": "${detail_escaped}",
  "lookup": {
    "tag": ${TAG_JSON},
    "digest": ${DIGEST_JSON}
  },
  "public": ${PUBLIC},
  "region": ${REGION_JSON},
  "registry_id": ${REGISTRY_ID_JSON}
}
EOF
}

emit_found() {
  if [[ "${OUTPUT_JSON}" == "true" ]]; then
    emit_json "true"
  else
    emit_text_found
  fi
}

emit_not_found() {
  if [[ "${OUTPUT_JSON}" == "true" ]]; then
    emit_json "false"
  else
    emit_text_not_found
  fi
}

build_aws_base_cmd() {
  AWS_BASE_CMD=(aws)

  if [[ -n "${PROFILE}" ]]; then
    AWS_BASE_CMD+=(--profile "${PROFILE}")
  fi

  if [[ "${PUBLIC}" == "true" ]]; then
    AWS_BASE_CMD+=(ecr-public)
    # Public ECR endpoints are typically handled in us-east-1.
    AWS_BASE_CMD+=(--region "us-east-1")
  else
    AWS_BASE_CMD+=(ecr)
    if [[ -n "${REGION}" ]]; then
      AWS_BASE_CMD+=(--region "${REGION}")
    fi
  fi
}

build_describe_cmd() {
  DESCRIBE_CMD=("${AWS_BASE_CMD[@]}" describe-images --repository-name "${REPOSITORY}")

  if [[ -n "${REGISTRY_ID}" && "${PUBLIC}" != "true" ]]; then
    DESCRIBE_CMD+=(--registry-id "${REGISTRY_ID}")
  fi

  if [[ -n "${TAG}" ]]; then
    DESCRIBE_CMD+=(--image-ids "imageTag=${TAG}")
  else
    DESCRIBE_CMD+=(--image-ids "imageDigest=${DIGEST}")
  fi

  DESCRIBE_CMD+=(--output json)
}

validate_args() {
  [[ -n "${REPOSITORY}" ]] || die "Missing --repository" 2

  if [[ -n "${TAG}" && -n "${DIGEST}" ]]; then
    die "Use either --tag or --digest, not both" 2
  fi

  if [[ -z "${TAG}" && -z "${DIGEST}" ]]; then
    die "You must provide either --tag or --digest" 2
  fi

  if [[ -n "${REGISTRY_ID}" && "${PUBLIC}" == "true" ]]; then
    die "--registry-id is only valid for private ECR" 2
  fi
}

normalize_json_fields() {
  if [[ -n "${TAG}" ]]; then
    TAG_JSON="\"$(json_escape "${TAG}")\""
  else
    TAG_JSON="null"
  fi

  if [[ -n "${DIGEST}" ]]; then
    DIGEST_JSON="\"$(json_escape "${DIGEST}")\""
  else
    DIGEST_JSON="null"
  fi

  if [[ -n "${REGION}" ]]; then
    REGION_JSON="\"$(json_escape "${REGION}")\""
  else
    REGION_JSON="null"
  fi

  if [[ -n "${REGISTRY_ID}" ]]; then
    REGISTRY_ID_JSON="\"$(json_escape "${REGISTRY_ID}")\""
  else
    REGISTRY_ID_JSON="null"
  fi
}

main() {
  REPOSITORY=""
  TAG=""
  DIGEST=""
  REGION=""
  REGISTRY_ID=""
  PROFILE=""
  PUBLIC="false"
  OUTPUT_JSON="false"
  QUIET="false"
  VERBOSE="false"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -r|--repository)
        [[ $# -ge 2 ]] || die "Missing value for $1" 2
        REPOSITORY="$2"
        shift 2
        ;;
      -t|--tag)
        [[ $# -ge 2 ]] || die "Missing value for $1" 2
        TAG="$2"
        shift 2
        ;;
      -d|--digest)
        [[ $# -ge 2 ]] || die "Missing value for $1" 2
        DIGEST="$2"
        shift 2
        ;;
      --region)
        [[ $# -ge 2 ]] || die "Missing value for $1" 2
        REGION="$2"
        shift 2
        ;;
      --registry-id)
        [[ $# -ge 2 ]] || die "Missing value for $1" 2
        REGISTRY_ID="$2"
        shift 2
        ;;
      --profile)
        [[ $# -ge 2 ]] || die "Missing value for $1" 2
        PROFILE="$2"
        shift 2
        ;;
      --public)
        PUBLIC="true"
        shift
        ;;
      --json)
        OUTPUT_JSON="true"
        shift
        ;;
      -q|--quiet)
        QUIET="true"
        shift
        ;;
      -v|--verbose)
        VERBOSE="true"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown argument: $1" 2
        ;;
    esac
  done

  require_cmd aws
  validate_args
  normalize_json_fields
  build_aws_base_cmd
  build_describe_cmd

  log "Repository: ${REPOSITORY}"
  log "Lookup mode: $([[ -n "${TAG}" ]] && printf 'tag=%s' "${TAG}" || printf 'digest=%s' "${DIGEST}")"
  log "Public ECR: ${PUBLIC}"
  [[ -n "${REGION}" ]] && log "Region: ${REGION}"
  [[ -n "${REGISTRY_ID}" ]] && log "Registry ID: ${REGISTRY_ID}"
  [[ -n "${PROFILE}" ]] && log "Profile: ${PROFILE}"

  local output=""
  local status=0

  set +o errexit
  output="$("${DESCRIBE_CMD[@]}" 2>&1)"
  status=$?
  set -o errexit

  if [[ ${status} -eq 0 ]]; then
    emit_found
    exit 0
  fi

  # Treat common "image not found" cases as a clean negative result.
  # Other failures should remain real failures.
  if grep -qiE 'ImageNotFoundException|Requested image not found|image does not exist' <<<"${output}"; then
    emit_not_found
    exit 1
  fi

  # Repo not found, auth issues, bad region, CLI issues, etc.
  if [[ "${QUIET}" != "true" ]]; then
    warn "AWS CLI/API failure while checking image existence"
    warn "${output}"
  fi
  exit 3
}

main "$@"
