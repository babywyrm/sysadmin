
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

## TO-DO lol zone

* Replace live HTTP/TLS calls with mocks (`requests-mock` or `vcrpy`) for faster and offline-capable tests.
* Add more parameterized tests for additional cipher suites and error conditions.
* Integrate coverage reporting (`pytest-cov`) and set up CI pipelines.
* Extend monitoring capabilities (HTML content checks, JSON health endpoints, alerting integrations).


## Next Steps

| Done | Task                                                                                       | Notes                                                          |
|:----:|--------------------------------------------------------------------------------------------|----------------------------------------------------------------|
| [ ]  | Add HTTP/TLS mocks (`requests-mock` or `vcrpy`)                                            | Remove external dependencies; record and replay real traffic   |
| [ ]  | Parameterize additional cipher suites and versions                                         | Cover edge ciphers (e.g. legacy TLS1.0, experimental suites)   |
| [ ]  | Write tests for certificate-expiry edge cases                                              | Freeze at dates just before, on, and after expiry              |
| [ ]  | Mock retry/backoff timings and validate exponential delays                                 | Use `caplog` to assert logged backoff intervals                |
| [ ]  | Integrate `pytest-cov` for coverage reporting                                              | Enforce minimum coverage in CI                                 |
| [ ]  | Add CI pipeline configuration (GitHub Actions, GitLab CI, etc.)                            | Run lint, tests, and coverage on every push                    |
| [ ]  | Extend `site_monitor` with content checks                                                  | HTML element presence, JSON health-endpoint assertions         |
| [ ]  | Develop alerting hooks or plugins                                                          | Email, Slack, or webhook notifications based on failures       |
| [ ]  | Create a dedicated test module for time-based SLAs and window triggers                     | Simulate midnight rollovers, SLA deadlines                     |
| [ ]  | Document “how to add a new test case” in README                                            | Guide contributors on writing fixtures, markers, and freezegun |


##
##

## Magical Extended Goals

- **Offline Test Mode**  
  - Package recorded HTTP/TLS sessions (via `vcrpy`) and switch between “live” and “replay” modes.  
  - Allow CI to run without Internet access.

- **Health-Endpoint Assertions**  
  - Add `check_health_json()` that fetches a JSON health endpoint and asserts on fields (e.g. `"status":"ok"`, latency, error counts).  
  - Write pytest fixtures for sample JSON schemas and edge-case payloads.

- **Content Validation**  
  - Implement HTML checks (e.g. presence of specific tags, title matches a regex).  
  - Use `BeautifulSoup` in tests to verify page structure.

- **CLI Tooling & Packaging**  
  - Expose `site_monitor` as a CLI (`python -m site_monitor`) with subcommands: `uptime`, `tls`, `full`.  
  - Add entry points in `setup.py`/`pyproject.toml` and publish to PyPI for internal reuse.

- **Metric Reporting & Dashboards**  
  - Emit Prometheus metrics (response time, TLS score) via a client library.  
  - Build a simple Grafana dashboard to track historic trends.

- **Alerting Integrations**  
  - Add hooks to send Slack/webhook/email alerts on failures or low-security scores.  
  - Parameterize alert thresholds and channels in config.

- **Dynamic Configuration**  
  - Load targets and thresholds from a YAML/JSON config file.  
  - Write tests that spin up multiple monitor instances based on config fixtures.

- **Plugin Architecture**  
  - Define a plugin API so teams can drop in custom checks (e.g. DNS resolution, certificate transparency logs).  
  - Test plugin loading and failure isolation.

- **Performance & Load Testing**  
  - Measure throughput by running many monitors in parallel (using `asyncio`, `threading`, or `multiprocessing`).  
  - Assert stable performance under load.

- **Security Audit Hooks**  
  - Integrate OWASP ZAP or other scanners as optional modules.  
  - Write tests that invoke ZAP against a local demo service and assert on zero high-severity findings.

- **Continuous Compliance Checks**  
  - Schedule periodic runs (via cron or a scheduler) and compare current results against a historic baseline.  
  - Alert on regressions or new SSL/TLS vulnerabilities.

- **Documentation & Onboarding**  
  - Create a CONTRIBUTING.md with guidelines on adding new tests, fixtures, and Freezegun scenarios.  
  - Provide example notebooks or demo scripts to walk new contributors through the suite.


