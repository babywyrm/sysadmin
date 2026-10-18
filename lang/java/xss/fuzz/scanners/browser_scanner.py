from playwright.sync_api import sync_playwright
from loaders.payload_loader import load_payloads

class BrowserScanner:
    def __init__(self, cfg):
        self.base = cfg["base_url"]
        self.endpoints = cfg["endpoints"]
        self.payloads = load_payloads(cfg.get("payloads"))
        self.timeout = cfg.get("scan_options", {}).get("timeout", 5)

    def run_dom_scans(self):
        findings = []
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            for ep in self.endpoints:
                if ep.get("type") not in ("reflected", "stored_dom"):
                    continue
                for pld in self.payloads:
                    url = self.base + ep["path"].format(payload=pld)
                    page.goto(url, timeout=self.timeout * 1000)
                    try:
                        page.wait_for_event("dialog", timeout=2000)
                        findings.append({
                            "type": "dom",
                            "endpoint": ep["path"],
                            "payload": pld
                        })
                    except:
                        pass
            browser.close()
        return findings
