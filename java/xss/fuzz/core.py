import argparse
from loaders.config_loader import load_config
from scanners.http_scanner import HTTPScanner
from scanners.browser_scanner import BrowserScanner
from reporters.console_reporter import ConsoleReporter
from reporters.json_reporter import JsonReporter

def main():
    p = argparse.ArgumentParser(description="XSS Engine")
    p.add_argument("--config", "-c", required=True, help="Path to config.yaml")
    args = p.parse_args()

    cfg = load_config(args.config)
    findings = []

    # JSON/reflected scans
    findings += HTTPScanner(cfg).run_json_scans()
    # stored and DOM-based
    findings += BrowserScanner(cfg).run_dom_scans()

    # Reporting
    if cfg["report"]["format"] == "json":
        JsonReporter(cfg).report(findings)
    else:
        ConsoleReporter().report(findings)

    return 0
  
