

# FIN — Advanced Vulnerability Intelligence & Normalization Scanner

**FIN** (Fast Intelligence Normalizer) is an advanced Python 3 vulnerability intelligence tool that queries multiple security data sources (NVD, OSV, and GitHub Security Advisories) and consolidates the results into a unified, relevance-scored report.  
It is designed for researchers, defenders, and vulnerability management teams who want a single view of known CVEs, exploit activity, and patch context for a given technology, library, or package.

---

## 🚀 Features

- **Multi-source enrichment**
  - Queries [NVD](https://nvd.nist.gov/), [OSV](https://osv.dev/), and [GitHub Advisories](https://github.com/advisories)
  - Merges and deduplicates results automatically
- **Risk scoring intelligence**
  - Calculates contextual risk based on severity, CVSS score, exploit presence, and active exploitation
- **Confidence & relevance ranking**
  - Relevance weighting ensures only vulnerabilities related to your target technology are surfaced
- **Caching and HTTP trace**
  - Optional local cache (`.vuln_cache/`) and trace archive (`.vuln_trace/`) for reproducibility
- **CSV and JSON exports**
  - Ready-to-ingest output for JIRA, Splunk, or vulnerability dashboards
- **Debugging support**
  - `--debug` flag enables detailed logging and HTTP tracing for troubleshooting
- **Async and efficient**
  - Uses `aiohttp` for concurrent API queries with retry and backoff logic

---

## 📦 Installation

You’ll need **Python 3.9+** and the following dependencies:

```bash
pip install aiohttp
````

Optionally, install dependencies into a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install aiohttp
```

Then clone the repository:

```bash
git clone https://github.com/<your-username>/FIN
cd FIN
```

---

## ⚙️ Usage

### Basic scan

```bash
python3 FIN.py -t wordpress
```

### Verbose scan (includes detailed CVE descriptions)

```bash
python3 FIN.py -t "apache httpd" -v
```

### Export to JSON or CSV

```bash
python3 FIN.py -t nginx --export json
python3 FIN.py -t openssl --export csv --export-file openssl_vulns.csv
```

### Enable debug mode (with trace capture)

```bash
python3 FIN.py -t starbox --debug -v
```

Debug mode creates a `.vuln_trace/` directory containing raw API responses for inspection.

---

## 🧠 Output Example

```
CONSOLIDATED VULNERABILITY REPORT
Total unique vulnerabilities: 6
================================================================================

1. [CVE-2024-0256] Starbox WordPress plugin — Stored XSS
   Risk Score: 10.00/10 | Severity: MEDIUM
   Description: The Starbox plugin for WordPress is vulnerable to Stored Cross-Site Scripting via ...
   URL: https://nvd.nist.gov/vuln/detail/CVE-2024-0256

2. [CVE-2024-0366] Starbox Author Box plugin — IDOR
   Risk Score: 7.22/10 | Severity: MEDIUM
   Description: Insecure Direct Object Reference in versions <=3.4.7 allows subscribers to access ...
   URL: https://nvd.nist.gov/vuln/detail/CVE-2024-0366
```

---

## 🔍 Command Reference

| Option                     | Description                                                |
| -------------------------- | ---------------------------------------------------------- |
| `-t, --tech`               | **(Required)** Target technology, library, or package name |
| `-e, --ecosystem`          | Optional ecosystem hint (`npm`, `PyPI`, `Go`, etc.)        |
| `-v, --verbose`            | Show full descriptions for each vulnerability              |
| `--limit <n>`              | Limit number of results displayed                          |
| `--export {json,csv}`      | Export output to a file (default: JSON)                    |
| `--export-file <filename>` | Custom filename for exported data                          |
| `--github-token`           | GitHub API token (optional for higher rate limits)         |
| `--nvd-api-key`            | NVD API key (optional for rate limits)                     |
| `--debug`                  | Enable verbose HTTP logging and trace saving               |

---

## 🧩 Architecture Overview

```
FIN.py
 ├── VulnerabilityResult               → Represents a single CVE or advisory
 ├── ConsolidatedVulnerability         → Unified record after normalization
 ├── VulnerabilityIntelligence         → Core logic for scoring and relevance
 ├── AdvancedVulnerabilityScanner
 │    ├── query_nvd()                  → Fetch from NVD
 │    ├── query_osv()                  → Fetch from OSV
 │    ├── query_github_advisories()    → Fetch from GitHub
 │    ├── consolidate_vulnerabilities()
 │    └── export_results()
 └── main()                            → CLI entrypoint (argparse)
```

---

## 🛡️ Example Use Cases

* Quickly evaluate whether a new library (e.g. `log4j`, `openssl`) has known CVEs
* Generate consolidated reports for inclusion in a vulnerability management workflow
* Feed consolidated JSON output into dashboards or JIRA automations
* Validate scanner results by comparing across independent sources (NVD vs OSV vs GitHub)

---

## 🧰 Future Enhancements

* Add exploit feed enrichment (Exploit-DB, Vulners, CISA KEV)
* Integrate MITRE ATT&CK mapping for exploit techniques
* Extend support for local SBOM JSON input (Trivy/Grype output)
* Interactive TUI mode for vulnerability triage

---

## 📜 License

MIT License © 2025 [Your Name]

---

## 🤝 Contributing

Pull requests are welcome!
Please open an issue before making changes if you plan to add a new data source or output format.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-enhancement`
3. Commit changes with clear messages
4. Submit a pull request

---

## 🧩 Example GitHub Directory Structure

```
FIN/
├── FIN.py
├── README.md
├── .vuln_cache/
└── .vuln_trace/
```

---

## 💡 Tip

If you’re scanning frequently or querying large keyword sets,
get an [NVD API key](https://nvd.nist.gov/developers/request-an-api-key)
and export it once for convenience:

```bash
export NVD_API_KEY="your-key"
```

Then FIN will automatically include it during requests.

---

**FIN** — turning fragmented CVE data into actionable, normalized intelligence.


