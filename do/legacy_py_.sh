#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Python 3.9 + TensorFlow/Keras installer for legacy CentOS 7 .. bc reasons ..
#
# - Builds Python 3.9 with system OpenSSL (1.0.2)
# - Fixes ldconfig for shared libpython
# - Pins urllib3 < 2 (required for OpenSSL 1.0.2)
# - Installs TensorFlow/Keras safely
# - Avoids compiling ML deps unless explicitly allowed
#
# Tested: CentOS 7 (2024–2025 era images)
###############################################################################

PYTHON_VERSION="3.9.19"
PY_PREFIX="/opt/python-3.9"
PY_TARBALL="Python-${PYTHON_VERSION}.tgz"
PY_SRC_DIR="Python-${PYTHON_VERSION}"
PY_URL="https://www.python.org/ftp/python/${PYTHON_VERSION}/${PY_TARBALL}"

LOG_PREFIX="[legacy-ml-install]"

info()  { echo -e "${LOG_PREFIX} \033[1;32mINFO\033[0m  $*"; }
warn()  { echo -e "${LOG_PREFIX} \033[1;33mWARN\033[0m  $*"; }
error() { echo -e "${LOG_PREFIX} \033[1;31mERROR\033[0m $*"; exit 1; }

require_root() {
  [[ $EUID -eq 0 ]] || error "Must be run as root"
}

###############################################################################
# 0. Sanity checks
###############################################################################
require_root

if ! grep -q "CentOS Linux release 7" /etc/centos-release 2>/dev/null; then
  warn "This script is intended for CentOS 7 / RHEL 7–era systems"
fi

###############################################################################
# 1. System dependencies
###############################################################################
info "Installing build dependencies"

yum install -y \
  gcc make \
  openssl-devel \
  zlib-devel \
  bzip2-devel \
  libffi-devel \
  readline-devel \
  sqlite-devel \
  xz-devel \
  tk-devel \
  curl

###############################################################################
# 2. Build Python 3.9 (if not already installed)
###############################################################################
if [[ -x "${PY_PREFIX}/bin/python3.9" ]]; then
  info "Python ${PYTHON_VERSION} already installed at ${PY_PREFIX}"
else
  info "Building Python ${PYTHON_VERSION} from source"

  cd /usr/src
  [[ -f "${PY_TARBALL}" ]] || curl -LO "${PY_URL}"
  tar xzf "${PY_TARBALL}"
  cd "${PY_SRC_DIR}"

  make distclean || true

  ./configure \
    --prefix="${PY_PREFIX}" \
    --enable-shared \
    --enable-optimizations=no

  make -j"$(nproc)"
  make install
fi

###############################################################################
# 3. Fix dynamic linker
###############################################################################
info "Configuring dynamic linker for libpython"

echo "${PY_PREFIX}/lib" > /etc/ld.so.conf.d/python39.conf
ldconfig

###############################################################################
# 4. Register python3 via alternatives
###############################################################################
if ! alternatives --display python3 >/dev/null 2>&1; then
  info "Registering python3 alternative"
  alternatives --install /usr/bin/python3 python3 "${PY_PREFIX}/bin/python3.9" 390
fi

alternatives --set python3 "${PY_PREFIX}/bin/python3.9"

###############################################################################
# 5. Bootstrap pip
###############################################################################
info "Bootstrapping pip"

python3 -m ensurepip --upgrade
python3 -m pip install --upgrade pip setuptools wheel

###############################################################################
# 6. Fix urllib3 / OpenSSL incompatibility
###############################################################################
info "Pinning urllib3 to OpenSSL-compatible version (<2)"

python3 -m pip uninstall -y urllib3 || true
python3 -m pip install "urllib3<2"

###############################################################################
# 7. Install TensorFlow (CPU)
###############################################################################
info "Installing TensorFlow (CPU-only)"

python3 -m pip install tensorflow

###############################################################################
# 8. Optional: install ML deps as wheels only
###############################################################################
info "Attempting to install ml-dtypes / optree via wheels only"

if ! python3 -m pip install --only-binary=:all: ml-dtypes optree; then
  warn "Prebuilt wheels not available."
  warn "If you *must* compile, install a modern compiler (clang/gcc >=9) manually."
fi

###############################################################################
# 9. Final verification
###############################################################################
info "Running final verification"

python3 - <<'EOF'
import ssl
import tensorflow as tf
import urllib3

print("Python:", tf.sysconfig.get_build_info()["python_version"])
print("TensorFlow:", tf.__version__)
print("OpenSSL:", ssl.OPENSSL_VERSION)
print("urllib3:", urllib3.__version__)
EOF

info "Installation complete"
info "Python prefix: ${PY_PREFIX}"
info "Use: python3"
