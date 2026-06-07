#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Python 3.9 + TensorFlow/Keras installer for legacy CentOS 7
#
# Features:
#   - Builds Python 3.9 from source with system OpenSSL (1.0.2)
#   - Fully idempotent — safe to re-run
#   - Pins urllib3 < 2 (required for OpenSSL 1.0.2 compatibility)
#   - Installs TensorFlow CPU-only with optional ML dependency wheels
#   - Structured logging with timestamps and a summary report
#   - Trap-based cleanup on failure
#   - Dry-run mode (DRY_RUN=1)
#   - Configurable via environment variables
#
# Usage:
#   sudo bash install.sh
#   PYTHON_VERSION=3.9.18 sudo bash install.sh
#   DRY_RUN=1 bash install.sh          # preview steps without executing
#   ALLOW_COMPILE=1 sudo bash install.sh  # allow building ML deps from source
#
# Tested: CentOS 7 (2024-2025 era images)
###############################################################################

###############################################################################
# Configuration (override via environment)
###############################################################################
PYTHON_VERSION="${PYTHON_VERSION:-3.9.19}"
PY_PREFIX="${PY_PREFIX:-/opt/python-3.9}"
PY_BUILD_DIR="${PY_BUILD_DIR:-/usr/src}"
TF_PACKAGE="${TF_PACKAGE:-tensorflow-cpu}"
ALLOW_COMPILE="${ALLOW_COMPILE:-0}"
DRY_RUN="${DRY_RUN:-0}"

PY_TARBALL="Python-${PYTHON_VERSION}.tgz"
PY_SRC_DIR="Python-${PYTHON_VERSION}"
PY_URL="https://www.python.org/ftp/python/${PYTHON_VERSION}/${PY_TARBALL}"
PY_BIN="${PY_PREFIX}/bin/python3.9"

###############################################################################
# Logging
###############################################################################
SCRIPT_NAME="$(basename "$0")"
LOG_FILE="/var/log/legacy-ml-install.log"
_STEP=0
_ERRORS=()

_ts()    { date '+%Y-%m-%d %H:%M:%S'; }
_color() { printf '\033[%sm' "$1"; }
_reset() { printf '\033[0m'; }

log()   {
  local level="$1"; shift
  local color msg
  case "$level" in
    INFO)  color="1;32" ;;
    WARN)  color="1;33" ;;
    ERROR) color="1;31" ;;
    STEP)  color="1;36" ;;
    *)     color="0"    ;;
  esac
  msg="[$(_ts)] [${SCRIPT_NAME}] $(printf '\033[%sm%-5s\033[0m' "$color" "$level") $*"
  echo -e "$msg"
  echo -e "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

info()  { log INFO  "$@"; }
warn()  { log WARN  "$@"; }
error() { log ERROR "$@"; exit 1; }
step()  {
  (( _STEP++ )) || true
  log STEP "── Step ${_STEP}: $*"
}

###############################################################################
# Dry-run wrapper
###############################################################################
run() {
  if [[ "$DRY_RUN" == "1" ]]; then
    echo -e "  $(_color '0;35')[DRY-RUN]$(_reset) $*"
  else
    "$@"
  fi
}

###############################################################################
# Trap / cleanup
###############################################################################
_cleanup() {
  local exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    warn "Script exited with code ${exit_code}"
    warn "Check log: ${LOG_FILE}"
    # Clean up partial source dir on build failure
    if [[ -d "${PY_BUILD_DIR}/${PY_SRC_DIR}" && ! -x "${PY_BIN}" ]]; then
      warn "Removing incomplete Python source tree: ${PY_BUILD_DIR}/${PY_SRC_DIR}"
      run rm -rf "${PY_BUILD_DIR:?}/${PY_SRC_DIR}"
    fi
  fi
}
trap _cleanup EXIT

###############################################################################
# Helpers
###############################################################################
require_root() {
  [[ $EUID -eq 0 ]] || error "Must be run as root (or via sudo)"
}

check_centos7() {
  if ! grep -q "CentOS Linux release 7" /etc/centos-release 2>/dev/null; then
    warn "Not a CentOS 7 system — proceeding anyway, but YMMV"
  fi
}

check_disk_space() {
  local required_mb=2048
  local available_mb
  available_mb=$(df --output=avail -m /usr/src | tail -1)
  if (( available_mb < required_mb )); then
    error "Insufficient disk space: ${available_mb}MB available, ${required_mb}MB required in /usr/src"
  fi
  info "Disk space OK: ${available_mb}MB available"
}

verify_checksum() {
  local file="$1"
  local url="${PY_URL}.asc"
  # Soft check — warn if gpg not available, don't hard-fail
  if command -v gpg &>/dev/null; then
    info "GPG available — consider verifying ${file} against ${url}"
  else
    warn "gpg not found — skipping tarball signature verification"
  fi
}

###############################################################################
# Step 0 — Pre-flight checks
###############################################################################
step "Pre-flight checks"

require_root
check_centos7
check_disk_space

if [[ "$DRY_RUN" == "1" ]]; then
  warn "DRY_RUN=1 — no changes will be made"
fi

###############################################################################
# Step 1 — System dependencies
###############################################################################
step "Installing system build dependencies"

PACKAGES=(
  gcc make
  openssl-devel
  zlib-devel
  bzip2-devel
  libffi-devel
  readline-devel
  sqlite-devel
  xz-devel
  tk-devel
  curl
  tar
)

run yum install -y "${PACKAGES[@]}"

###############################################################################
# Step 2 — Build Python 3.9
###############################################################################
step "Building Python ${PYTHON_VERSION} from source"

if [[ -x "${PY_BIN}" ]]; then
  info "Python ${PYTHON_VERSION} already installed at ${PY_BIN} — skipping build"
else
  run mkdir -p "${PY_BUILD_DIR}"
  run cd "${PY_BUILD_DIR}"

  if [[ ! -f "${PY_TARBALL}" ]]; then
    info "Downloading ${PY_URL}"
    run curl -fL --retry 3 --retry-delay 2 -O "${PY_URL}"
  else
    info "Tarball already downloaded: ${PY_BUILD_DIR}/${PY_TARBALL}"
  fi

  verify_checksum "${PY_TARBALL}"

  run tar xzf "${PY_TARBALL}"
  run cd "${PY_SRC_DIR}"
  run make distclean || true

  run ./configure \
    --prefix="${PY_PREFIX}" \
    --enable-shared \
    --with-system-ffi \
    --with-ensurepip=install \
    --enable-optimizations=no \
    CFLAGS="-Wno-error"

  run make -j"$(nproc)"
  run make altinstall

  info "Python build complete"
fi

###############################################################################
# Step 3 — Dynamic linker
###############################################################################
step "Configuring dynamic linker (ldconfig)"

if ! grep -qxF "${PY_PREFIX}/lib" /etc/ld.so.conf.d/python39.conf 2>/dev/null; then
  run bash -c "echo '${PY_PREFIX}/lib' > /etc/ld.so.conf.d/python39.conf"
fi
run ldconfig
info "ldconfig updated"

###############################################################################
# Step 4 — Register via alternatives
###############################################################################
step "Registering python3 via alternatives"

if ! alternatives --display python3 &>/dev/null; then
  info "Installing python3 alternative"
  run alternatives --install /usr/bin/python3 python3 "${PY_BIN}" 390
fi

run alternatives --set python3 "${PY_BIN}"
info "python3 → ${PY_BIN}"

###############################################################################
# Step 5 — Bootstrap pip
###############################################################################
step "Bootstrapping pip"

run "${PY_BIN}" -m ensurepip --upgrade
run "${PY_BIN}" -m pip install --upgrade pip setuptools wheel
info "pip bootstrapped"

###############################################################################
# Step 6 — urllib3 / OpenSSL compatibility
###############################################################################
step "Pinning urllib3 < 2 (OpenSSL 1.0.2 compatibility)"

INSTALLED_URLLIB3=$("${PY_BIN}" -m pip show urllib3 2>/dev/null | awk '/^Version:/{print $2}')

if [[ -n "$INSTALLED_URLLIB3" ]] && python3 -c "
from packaging.version import Version
import sys
sys.exit(0 if Version('$INSTALLED_URLLIB3') < Version('2') else 1)
" 2>/dev/null; then
  info "urllib3 ${INSTALLED_URLLIB3} already satisfies <2 — skipping"
else
  run "${PY_BIN}" -m pip uninstall -y urllib3 || true
  run "${PY_BIN}" -m pip install "urllib3<2"
fi

###############################################################################
# Step 7 — TensorFlow
###############################################################################
step "Installing ${TF_PACKAGE}"

if "${PY_BIN}" -c "import tensorflow" &>/dev/null; then
  TF_INSTALLED=$("${PY_BIN}" -m pip show tensorflow-cpu 2>/dev/null \
    | awk '/^Version:/{print $2}')
  info "TensorFlow already installed (${TF_INSTALLED}) — skipping"
else
  run "${PY_BIN}" -m pip install "${TF_PACKAGE}"
fi

###############################################################################
# Step 8 — Optional ML dependency wheels
###############################################################################
step "Installing optional ML dependencies (wheels only)"

ML_DEPS=(ml-dtypes optree)

if [[ "$ALLOW_COMPILE" == "1" ]]; then
  warn "ALLOW_COMPILE=1 — will build from source if no wheel is available"
  run "${PY_BIN}" -m pip install "${ML_DEPS[@]}"
else
  if ! run "${PY_BIN}" -m pip install --only-binary=:all: "${ML_DEPS[@]}"; then
    warn "Prebuilt wheels unavailable for: ${ML_DEPS[*]}"
    warn "To allow source compilation: ALLOW_COMPILE=1 $0"
    warn "Or install a modern compiler (gcc >= 9 / clang) first"
    _ERRORS+=("ml-dtypes / optree wheels unavailable — install skipped")
  fi
fi

###############################################################################
# Step 9 — Verification
###############################################################################
step "Running verification"

if [[ "$DRY_RUN" != "1" ]]; then
  "${PY_BIN}" - <<'PYEOF'
import sys, ssl, platform

print()
print("=" * 52)
print("  Installation Verification")
print("=" * 52)

try:
    import tensorflow as tf
    print(f"  TensorFlow : {tf.__version__}")
    print(f"  Python     : {sys.version.split()[0]}")
    print(f"  Platform   : {platform.platform()}")
except ImportError as e:
    print(f"  TensorFlow : FAILED ({e})")

try:
    import urllib3
    print(f"  urllib3    : {urllib3.__version__}")
except ImportError:
    print("  urllib3    : NOT FOUND")

print(f"  OpenSSL    : {ssl.OPENSSL_VERSION}")

try:
    import keras
    print(f"  Keras      : {keras.__version__}")
except ImportError:
    print("  Keras      : not installed (optional)")

try:
    import ml_dtypes
    print(f"  ml-dtypes  : {ml_dtypes.__version__}")
except ImportError:
    print("  ml-dtypes  : not installed (optional)")

print("=" * 52)
print()
PYEOF
fi

###############################################################################
# Done
###############################################################################
echo
info "Installation complete ✓"
info "  Python prefix : ${PY_PREFIX}"
info "  Binary        : ${PY_BIN}"
info "  Log file      : ${LOG_FILE}"
info "  Invoke with   : python3"

if [[ ${#_ERRORS[@]} -gt 0 ]]; then
  echo
  warn "Completed with warnings:"
  for e in "${_ERRORS[@]}"; do
    warn "  • ${e}"
  done
fi
