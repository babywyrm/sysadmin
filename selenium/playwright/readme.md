
# Compare

| Feature                     | Selenium                                                 | Playwright                                              |
| --------------------------- | -------------------------------------------------------- | ------------------------------------------------------- |
| **Language Support**        | Java, Python, C#, JavaScript, Ruby                       | Python, JavaScript/TypeScript, Java, C#                 |
| **Browsers Supported**      | Chrome, Firefox, Edge, Safari                            | Chromium (Chrome/Edge), Firefox, WebKit (Safari engine) |
| **Installation**            | Needs separate WebDriver binaries (e.g., `chromedriver`) | Ships with bundled browsers (`playwright install`)      |
| **Speed**                   | Slower (multiple protocol hops)                          | Faster (direct browser bindings, one API)               |
| **Parallel Execution**      | Possible, but heavier                                    | Built-in parallelism with isolated browser contexts     |
| **Cross-Browser API**       | Not fully unified (browser-specific quirks)              | Fully unified API across Chromium, Firefox, WebKit      |
| **Headless Mode**           | Supported                                                | Supported (optimized, lightweight)                      |
| **Mobile Emulation**        | Limited                                                  | Built-in device emulation (iPhone, Pixel, etc.)         |
| **Auto-Wait / Smart Waits** | Manual handling required                                 | Built-in auto-wait for elements, actions                |
| **Selectors**               | Standard CSS/XPath                                       | CSS, XPath, text selectors, regex, role selectors       |
| **Debugging Tools**         | Good, but manual                                         | Inspector, Codegen, Trace Viewer built-in               |
| **Use in CI/CD**            | Requires drivers installed                               | Self-contained (`playwright install --with-deps`)       |
| **Community & Ecosystem**   | Mature, large ecosystem (since 2004)                     | Newer (since 2019), fast-growing, backed by Microsoft   |


##
##

# Install
# 📖 Playwright How-To Install & Environment Setup (..beta..)

## 1. **System Prerequisites**

On Ubuntu/Debian-style systems:

```bash
apt update && apt install -y \
    curl wget git unzip \
    python3 python3-pip python3-venv \
    libnss3 libx11-6 libx11-xcb1 libxcomposite1 \
    libxcursor1 libxdamage1 libxi6 libxtst6 \
    libglib2.0-0 libdrm2 libgbm1 libatk1.0-0 libatk-bridge2.0-0 \
    libxrandr2 libxss1 libasound2 libpangocairo-1.0-0 \
    libpango-1.0-0 libcairo2 libatspi2.0-0
```

👉 This installs **all the shared libraries** Chromium/WebKit/Firefox need.
If you skip this, you’ll see errors like `libatk-1.0.so.0: cannot open shared object file`.

---

## 2. **Install Playwright (Python)**

```bash
pip3 install playwright
```

---

## 3. **Download Browser Binaries**

Playwright manages its own patched browser builds. After pip install:

```bash
playwright install
```

This fetches:

* Chromium
* Firefox
* WebKit

✅ These live in `~/.cache/ms-playwright/`.

---

## 4. **Quick Sanity Check**

```bash
python3 - <<'EOF'
import asyncio
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto("https://example.com")
        print(await page.title())
        await browser.close()

asyncio.run(main())
EOF
```

Expected output:

```
Example Domain
```

---

## 5. **(Optional) Use System Chrome Instead of Bundled**

If you want Playwright to drive **Google Chrome Stable** already on your box:

```bash
apt install -y google-chrome-stable
```

Then in Python:

```python
browser = await p.chromium.launch(executable_path="/usr/bin/google-chrome", headless=True)
```

---

## 6. **Running in Containers / K3s Nodes**

If you’re in K8s or Docker:

* Add missing libs via Dockerfile:

  ```dockerfile
  FROM python:3.10-slim
  RUN apt-get update && apt-get install -y \
      libnss3 libx11-xcb1 libxcomposite1 libxcursor1 libxdamage1 libxi6 libxtst6 \
      libglib2.0-0 libdrm2 libgbm1 libatk1.0-0 libatk-bridge2.0-0 libxrandr2 \
      libxss1 libasound2 libpangocairo-1.0-0 libpango-1.0-0 libcairo2 libatspi2.0-0 \
      && rm -rf /var/lib/apt/lists/*
  RUN pip install playwright && playwright install
  ```

* For **K3s** ephemeral pods, mount a PVC or preload images so Playwright’s browser cache (`~/.cache/ms-playwright`) doesn’t get garbage-collected.

---

## 7. **Troubleshooting**

* `TargetClosedError` right after launch → usually missing system library (`libatk`, `libgbm`, `libx11`).
* `Executable doesn’t exist at …/headless_shell` → run `playwright install`.
* Container image garbage-collects Playwright browsers → bake them into the image (`playwright install --with-deps` in Dockerfile).


##
##




# 📖 Playwright Setup & Environment Guide .. cross-platform ..

Playwright is a cross-browser automation framework supporting **Chromium, Firefox, and WebKit**.
This guide ensures a clean environment across **Linux, macOS, and Windows**.

---

## 🔹 1. Linux (Debian/Ubuntu)

### Install dependencies

```bash
sudo apt update && sudo apt install -y \
  curl wget git unzip python3 python3-pip python3-venv \
  libnss3 libx11-6 libx11-xcb1 libxcomposite1 libxcursor1 \
  libxdamage1 libxi6 libxtst6 libglib2.0-0 libdrm2 libgbm1 \
  libatk1.0-0 libatk-bridge2.0-0 libxrandr2 libxss1 libasound2 \
  libpangocairo-1.0-0 libpango-1.0-0 libcairo2 libatspi2.0-0
```

### Install Playwright (Python)

```bash
pip3 install playwright
playwright install
```

---

## 🔹 2. Linux (Fedora/CentOS/RHEL)

### Install dependencies

```bash
sudo dnf install -y \
  python3 python3-pip python3-virtualenv \
  nss libX11 libXcomposite libXcursor libXdamage libXtst \
  libdrm mesa-libgbm atk at-spi2-atk cairo pango alsa-lib
```

### Install Playwright

```bash
pip3 install playwright
playwright install
```

---

## 🔹 3. macOS (Intel & Apple Silicon)

macOS comes with most libraries bundled.

### Install Python & Playwright

```bash
brew install python
pip3 install playwright
playwright install
```

👉 Notes:

* On Apple Silicon (M1/M2), Playwright automatically downloads ARM builds.
* No extra system libs needed.

---

## 🔹 4. Windows 10/11

### Install prerequisites

1. Install [Python 3](https://www.python.org/downloads/windows/)
   → Make sure to check **“Add Python to PATH”** during install.
2. Install Git (optional but recommended).

### Install Playwright

Open **PowerShell** or **Command Prompt**:

```powershell
pip install playwright
playwright install
```

### Run a test

```powershell
python -m playwright codegen https://example.com
```

---

## 🔹 5. Containers / K8s

In minimal images (e.g., Debian slim, Alpine), Playwright browsers need extra system libraries.

**Dockerfile example:**

```dockerfile
FROM python:3.10-slim

# Install system deps for Chromium/WebKit/Firefox
RUN apt-get update && apt-get install -y \
    libnss3 libx11-xcb1 libxcomposite1 libxcursor1 libxdamage1 \
    libxi6 libxtst6 libglib2.0-0 libdrm2 libgbm1 libatk1.0-0 \
    libatk-bridge2.0-0 libxrandr2 libxss1 libasound2 libpangocairo-1.0-0 \
    libpango-1.0-0 libcairo2 libatspi2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Python deps
RUN pip install playwright

# Download browser binaries into image
RUN playwright install --with-deps

WORKDIR /app
```

---

## 🔹 6. Sanity Test

```python
import asyncio
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto("https://example.com")
        print(await page.title())
        await browser.close()

asyncio.run(main())
```

Run:

```bash
python3 test_playwright.py
```

Expected output:

```
Example Domain
```

---

## 🔹 7. Troubleshooting

* **`Executable doesn’t exist … headless_shell`** → run `playwright install`.
* **`error while loading shared libraries: libatk-1.0.so.0`** → missing Linux libs (see section 1/2).
* **Container image deletes browsers** → bake them into the image with `playwright install --with-deps`.
* **Using system Chrome**:

  ```python
  browser = await p.chromium.launch(
      executable_path="/usr/bin/google-chrome", headless=True
  )
  ```

##
##
