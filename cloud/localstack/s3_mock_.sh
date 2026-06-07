#!/usr/bin/env bash
#
# Start LocalStack with S3 enabled and create a test bucket.
# Requires: pip3, Docker.
#
# Usage:
#   export BUCKET_NAME=my-test-bucket
#   ./s3_localstack.sh
#

set -euo pipefail

BUCKET_NAME=${BUCKET_NAME:-my-test-bucket}
MAX_WAIT=10
SLEEP_SEC=3

# --- helpers ---------------------------------------------------------------
die() { echo "[!] $*" >&2; exit 1; }

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"
}

# --- prerequisite checks ---------------------------------------------------
need_cmd pip3
need_cmd docker

if ! command -v localstack >/dev/null 2>&1; then
    echo "[*] Installing localstack..."
    pip3 install -q localstack
fi

if ! command -v awslocal >/dev/null 2>&1; then
    echo "[*] Installing awscli-local..."
    pip3 install -q awscli-local
fi

# --- variables -------------------------------------------------------------
CLI=$(command -v awslocal)
LOCALSTACK=$(command -v localstack)

echo "[*] Using bucket name: ${BUCKET_NAME}"
echo "[*] LocalStack executable: ${LOCALSTACK}"
echo "[*] awslocal: ${CLI}"

# --- wait for LocalStack to be ready --------------------------------------
wait_for_ls() {
    local count=0
    until ${CLI} s3 ls >/dev/null 2>&1; do
        echo "Waiting for LocalStack S3..."
        sleep "${SLEEP_SEC}"
        ((count++))
        if (( count >= MAX_WAIT )); then
            echo "Timed out waiting for LocalStack."
            return 1
        fi
    done
    return 0
}

create_bucket() {
    echo "[*] Creating bucket ${BUCKET_NAME}..."
    ${CLI} s3api create-bucket --bucket "${BUCKET_NAME}" >/dev/null
    ${CLI} s3api put-bucket-acl --bucket "${BUCKET_NAME}" --acl public-read >/dev/null
    echo "[+] Bucket ${BUCKET_NAME} created and marked public‑read."
}

# --- start localstack ------------------------------------------------------
# modern form: use single consolidated port (4566)
SERVICES=s3 START_WEB=0 ${LOCALSTACK} start -d

echo "[*] Waiting for S3 service..."
wait_for_ls || die "LocalStack did not become ready in time"
create_bucket

echo "[✓] LocalStack S3 ready on http://localhost:4566"
echo "[✓] Bucket '$BUCKET_NAME' available"
echo "[*] Press Ctrl‑C to stop LocalStack container."

# keep process alive so logs are visible
docker logs -f localstack_main 2>/dev/null || true
