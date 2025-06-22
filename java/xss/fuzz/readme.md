
```
xss_engine/
├── __main__.py
├── core.py
├── loaders/
│   ├── config_loader.py
│   └── payload_loader.py
├── scanners/
│   ├── http_scanner.py
│   └── browser_scanner.py
├── reporters/
│   ├── console_reporter.py
│   └── json_reporter.py
├── payloads/
│   └── default_payloads.yaml
└── examples/
    └── config.yaml
```

# XSS Engine ( Beta )

A flexible, config-driven toolkit for discovering reflected, stored and DOM-based XSS in JSON APIs, HTML endpoints and JavaScript apps.  
Ideal for CTF challenges, pentests or smoke-testing your own services (e.g. WordPress/cms → Flask/Golang/Etc RCE chains).

---

## 🌟 Features

- **JSON fuzzing**  
  Inject XSS payloads into arbitrary JSON fields (e.g. `/api/messages`) and look for reflections.
- **Reflected HTML scans**  
  Hit reflected endpoints (e.g. `/search?q={payload}`) and detect injected alerts/dialogs.
- **DOM-based checks**  
  Drive a headless browser (Playwright) to catch XSS that only appears at render-time.
- **CORS testing**  
  Optionally send an `Origin` header to verify your service permits cross-site requests.
- **Modular payload library**  
  Built-in defaults plus the ability to define your own payload lists in YAML.
- **Pluggable reporters**  
  Console output or JSON file for easy CI integration and dashboards.

---

## 🚀 Quickstart

### 1. Clone & Install

```bash
git clone https://github.com/yourorg/xss_engine.git
cd xss_engine

# create a venv (optional but recommended)
python3 -m venv .venv
source .venv/bin/activate

# install dependencies
pip install -r requirements.txt

# install Playwright browsers
playwright install chromium
