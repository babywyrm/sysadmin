
# FREEZETIME Site Monitoring (( Beta )) 

This repository demonstrates a Python-based site monitoring tool with:

- HTTP uptime checks (with retries, timing, and backoff)  
- TLS and cipher analysis (handshake inspection, certificate parsing, security scoring)  
- A pytest suite for comprehensive, parameterized tests  
- Freezegun for deterministic, time-dependent test scenarios  

---

## Repository Layout

```

FREEZETIME/
├── site\_monitor.py
├── test\_site\_monitoring.py
├── conftest.py
├── requirements.txt
├── .pytest\_cache/
└── **pycache**/

```

- **site_monitor.py**  
  Implements `SiteMonitor`, which provides:  
  - `check_uptime()`: performs an HTTP GET, measures response time with `time.perf_counter_ns()`, enforces a minimum non-zero value, and retries on failure.  
  - `check_tls_ciphers()`: opens an SSL socket, retrieves cipher information, loads the certificate in DER form, and calls helper methods to analyze ciphers and certificate details.  
  - `_is_modern_cipher()`, `_has_weak_cipher()`: determine cipher quality against defined lists.  
  - `_analyze_certificate()`: extracts validity period, issuer, subject alternative names, key size, and computes days until expiry.  
  - `_calculate_security_score()`: combines TLS version, cipher strength, certificate freshness, and key size into a 0–100 score.  
  - `full_check()`: runs both uptime and TLS checks in a single call, returning a combined result.

- **test_site_monitoring.py**  
  A pytest suite that exercises every feature of `SiteMonitor`:  
  - Fixtures for default URLs (`google.com`, `github.com`, `httpbin.org`) and a CLI override (`--url`).  
  - Tests for uptime success, retry logic, non-HTTPS handling, invalid URLs.  
  - TLS tests for modern vs. weak ciphers, certificate analysis, security score thresholds.  
  - Integration tests via `full_check()`.  
  - Freezegun-powered tests that freeze `datetime.now()` to verify timestamp fields and certificate expiry logic in a deterministic manner.

- **conftest.py**  
  Extends pytest with:  
  - A `--url` command-line option (`pytest_addoption`) to override test targets.  
  - A `cli_url` fixture to supply the override to tests.  
  - Basic logging configuration at DEBUG level for the `site_monitor` logger.

- **requirements.txt**  
  Lists third-party dependencies:  
```

requests
cryptography
pytest
freezegun

````

---

## Setup

1. Create a Python virtual environment and activate it:
 ```bash
 python3 -m venv .venv
 source .venv/bin/activate
````

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

### Manual Check

Run a quick, one-off check from the command line:

```bash
python - <<EOF
from site_monitor import SiteMonitor
result = SiteMonitor("https://example.com").full_check()
print(result)
EOF
```

The output will include:

* `uptime`: status (`up`/`down`), HTTP status code, `response_time`, and `timestamp`.
* `tls`: TLS version, cipher suite, modern/weak flags, certificate details, `security_score`.
* `overall_timestamp`: when the combined check completed.

### Running Tests

* **Default targets** (Google, GitHub, HTTPBin):

  ```bash
  pytest -q
  ```
* **Override target** (all tests against a single URL):

  ```bash
  pytest -q --url=https://your-site.example
  ```

---

## Components Interaction

1. **`SiteMonitor` Core**

   * Provides the monitoring logic.
   * Uses `requests` for HTTP and `ssl`/`socket` modules for TLS handshakes.
   * Parses certificates with `cryptography.x509`.

2. **Pytest Configuration (`conftest.py`)**

   * Defines command-line options and fixtures.
   * Configures logging to capture retry/backoff messages during tests.

3. **Test Suite (`test_site_monitoring.py`)**

   * Uses fixtures to supply URLs and the `SiteMonitor` instance.
   * Applies `@freeze_time` decorators so tests can assert on exact timestamps and expiry calculations.
   * Verifies both functional behavior (HTTP/TLS) and time-dependent logic.

4. **Freezegun**

   * Freezes `datetime.now()` within test functions.
   * Ensures that assertions involving timestamps (e.g., `"timestamp".startswith(...)`) and certificate expiry (`days_until_expiry`) remain stable and reproducible.

---

## Why Freeze Time?

* Guarantees that tests relying on “current time” do not flake.
* Allows simulation of edge cases (e.g., near-certificate-expiry) without waiting.
* Makes timestamp assertions predictable across all environments and CI runs.

---

## TO-DO, lol

* Replace live HTTP/TLS calls with mocks (`requests-mock` or `vcrpy`) for faster and offline-capable tests.
* Add more parameterized tests for additional cipher suites and error conditions.
* Integrate coverage reporting (`pytest-cov`) and set up CI pipelines.
* Extend monitoring capabilities (HTML content checks, JSON health endpoints, alerting integrations).

