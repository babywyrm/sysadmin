
# 🛠️ Runbook: Installing Python + Modern ML Tools on Legacy CentOS 7 ..beta..

> **Scope:**
> This guide documents how to install a *working* Python + TensorFlow/Keras stack on **CentOS 7** (or similar legacy RHEL 7 systems) in 2025+, despite:
>
> * EOL OpenSSL
> * Old GCC toolchains
> * Missing SCL repos
> * Modern Python / ML dependency expectations

This is **not theoretical** — it’s distilled from real-world failures and fixes.

---

## 🧠 Executive Summary (TL;DR)

| Layer             | Reality on CentOS 7   |
| ----------------- | --------------------- |
| System Python     | ❌ Too old             |
| OpenSSL           | ❌ 1.0.2 only          |
| GCC               | ❌ 4.8.5 (no C++17/20) |
| Python ≥3.10      | ❌ Pain                |
| **Python 3.9**    | ✅ Sweet spot          |
| TensorFlow        | ✅ With constraints    |
| Keras             | ✅ Via TensorFlow      |
| urllib3 v2        | ❌ Must pin            |
| Compiling ML deps | ❌ Avoid if possible   |

**Golden rules:**

* Use **Python 3.9**
* Prefer **prebuilt wheels**
* Pin **urllib3 < 2**
* Do **not** fight the OS more than necessary
* Containers are the long-term answer

---

## 1️⃣ Build Python 3.9 (SSL-compatible)

CentOS 7 ships **OpenSSL 1.0.2**, which is:

* ❌ incompatible with Python 3.10+
* ✅ compatible with Python 3.9

### Install build dependencies

```bash
yum install -y \
  gcc make \
  openssl-devel \
  zlib-devel \
  bzip2-devel \
  libffi-devel \
  readline-devel \
  sqlite-devel \
  xz-devel \
  tk-devel
```

---

### Build Python 3.9 from source

```bash
cd /usr/src
curl -LO https://www.python.org/ftp/python/3.9.19/Python-3.9.19.tgz
tar xzf Python-3.9.19.tgz
cd Python-3.9.19
```

Configure **without PGO**:

```bash
make distclean || true

./configure \
  --prefix=/opt/python-3.9 \
  --enable-shared \
  --enable-optimizations=no
```

Build and install:

```bash
make -j$(nproc)
make install
```

---

### Fix dynamic linker (CRITICAL)

```bash
echo "/opt/python-3.9/lib" > /etc/ld.so.conf.d/python39.conf
ldconfig
```

Verify:

```bash
/opt/python-3.9/bin/python3.9 - <<'EOF'
import ssl
print(ssl.OPENSSL_VERSION)
EOF
```

Expected:

```
OpenSSL 1.0.2k-fips
```

---

## 2️⃣ Make Python 3.9 the default `python3`

Use `alternatives` (safe + reversible):

```bash
alternatives --install /usr/bin/python3 python3 /opt/python-3.9/bin/python3.9 390
alternatives --config python3
```

Verify:

```bash
python3 -V
```

---

## 3️⃣ Bootstrap pip (properly)

Never use raw `pip3` on legacy systems.

```bash
python3 -m ensurepip --upgrade
python3 -m pip install --upgrade pip setuptools wheel
```

---

## 4️⃣ Install ML tooling (the safe way)

### ⚠️ Key constraint: OpenSSL vs urllib3

Modern `urllib3` **v2.x requires OpenSSL ≥1.1.1**, which CentOS 7 does not have.

### Fix: pin urllib3

```bash
python3 -m pip uninstall -y urllib3
python3 -m pip install "urllib3<2"
```

Verify:

```bash
python3 - <<'EOF'
import urllib3, ssl
print("urllib3:", urllib3.__version__)
print("SSL:", ssl.OPENSSL_VERSION)
EOF
```

---

## 5️⃣ Install TensorFlow / Keras

**Do not install standalone `keras` first.**

Correct order:

```bash
python3 -m pip install tensorflow
```

TensorFlow vendors Keras internally.

---

## 6️⃣ Avoid compiling ML dependencies (GCC is too old)

CentOS 7 ships **GCC 4.8.5**, which:

* ❌ cannot compile C++17 / C++20
* ❌ breaks `ml-dtypes`, `optree`, etc.

### Best practice: wheels only

```bash
python3 -m pip install --only-binary=:all: ml-dtypes optree
```

If wheels exist → success
If wheels do not exist → **do not fight it**

---

## 7️⃣ If compilation is unavoidable (last resort)

When SCL / devtoolset repos are **missing** (common in 2025):

### Use prebuilt Clang (no yum required)

```bash
cd /opt
curl -LO https://github.com/llvm/llvm-project/releases/download/llvmorg-17.0.6/clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-20.04.tar.xz
tar xf clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-20.04.tar.xz
mv clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-20.04 llvm
```

Use it only for pip builds:

```bash
export CC=/opt/llvm/bin/clang
export CXX=/opt/llvm/bin/clang++
```

Then retry install.

---

## 8️⃣ Common runtime warnings (safe to ignore)

| Message                       | Meaning             |
| ----------------------------- | ------------------- |
| `Could not find cuda drivers` | CPU-only TensorFlow |
| `failed call to cuInit`       | No GPU              |
| `AVX2 FMA available`          | Info only           |
| `input_shape warning`         | Keras style warning |

None are fatal.

---

## 9️⃣ Why models “don’t print”

Keras does **not print models automatically**.

To see structure:

```python
model.summary()
```

Saving a model:

```python
model.save("model.h5")
```

➡️ Output is **the file**, not stdout.

---

## 🔐 Security / CTF Notes

* Lambda layers execute **during training and load**
* Payloads persist in `.h5`
* Serialization is unsafe by default
* Real-world mitigation:

  * `compile=False`
  * `safe_mode=True` (newer TF)
  * avoid untrusted models entirely

---

## 🧭 Final Recommendations

### Short term (legacy boxes)

* Python 3.9
* `urllib3<2`
* Prebuilt wheels only
* Minimal system changes

### Long term

* Rocky 8 / Alma 8 / Ubuntu 22.04
* Or containerize ML tooling
* Treat CentOS 7 as **hostile terrain**

---

## ✅ One-line sanity check

```bash
python3 - <<'EOF'
import tensorflow as tf, ssl
print(tf.__version__)
print(ssl.OPENSSL_VERSION)
EOF
```

If this works, **you’re good**. .. (probably) ..

---

##
##
