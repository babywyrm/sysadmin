

# Install

# 📖 Playwright How-To Install & Environment Setup (..orchestration..)

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

Do you want me to turn this into a **Markdown README.md** format for `/opt/chromedriver` so it sits alongside your `play.py` and `loop.py` as documentation?

