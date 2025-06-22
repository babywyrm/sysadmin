
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

# Example Conf

```
base_url: http://localhost:8080        # Your target host:port or domain

endpoints:
  - method: POST
    path: /api/system/check
    json_fields: [ host ]

  - method: POST
    path: /api/messages
    json_fields: [ from, to, content ]

  - method: GET
    path: /search?q={payload}
    type: reflected            # for reflected HTML endpoints

scan_options:
  timeout: 5                   # seconds per request
  concurrency: 10              # parallel threads (future use)
  cors_test: true              # send Origin:* header to test CORS

payloads: []                   # empty → use defaults in payloads/default_payloads.yaml

report:
  format: console              # or "json"
  output_file: findings.json
```
