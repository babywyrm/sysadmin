#!/usr/bin/env python3

import argparse

# Import helper to load and validate your YAML configuration
from loaders.config_loader import load_config

# Import each scanner class you’ve implemented
from scanners.http_scanner import HTTPScanner
from scanners.browser_scanner import BrowserScanner
from scanners.injection_scanner import InjectionScanner

# Import your reporting modules
from reporters.console_reporter import ConsoleReporter
from reporters.json_reporter import JsonReporter


def main():
    """
    Entry point for the XSS Engine.
    1. Parse command-line arguments.
    2. Load the YAML config file into a Python dict.
    3. Instantiate each scanner, run scans, and collect findings.
    4. Pass findings to the chosen reporter (console or JSON).
    """

    # 1) Parse CLI arguments
    parser = argparse.ArgumentParser(
        description="XSS Engine - test for XSS, command-injection, SQLi, etc."
    )
    parser.add_argument(
        "--config", "-c",
        required=True,
        help="Path to your YAML config file"
    )
    args = parser.parse_args()

    # 2) Load the YAML configuration
    #    After this call, `config` is a dict with keys like:
    #      - base_url
    #      - endpoints
    #      - scan_options
    #      - payloads
    #      - report
    config = load_config(args.config)

    # 3) Run scanners in sequence, gather all findings in one list
    findings = []

    # 3a) JSON-based XSS & reflected scans
    http_scanner = HTTPScanner(config)
    findings.extend(http_scanner.run_json_scans())

    # 3b) DOM-based scans using a headless browser
    browser_scanner = BrowserScanner(config)
    findings.extend(browser_scanner.run_dom_scans())

    # 3c) Command-injection (and other injection) scans
    injection_scanner = InjectionScanner(config)
    findings.extend(injection_scanner.run())

    # 4) Reporting: choose console or JSON based on config
    report_cfg = config.get("report", {})

    if report_cfg.get("format") == "json":
        # Write findings to a JSON file
        json_reporter = JsonReporter(report_cfg)
        json_reporter.report(findings)

    else:
        # Print a human-readable summary to stdout
        console_reporter = ConsoleReporter()
        console_reporter.report(findings)

    # Return zero for success
    return 0


if __name__ == "__main__":
    # When invoked directly, run main() and exit with its return code
    exit(main())
