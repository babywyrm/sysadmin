import requests
from loaders.payload_loader import load_payloads

class HTTPScanner:
    def __init__(self, cfg):
        self.base = cfg["base_url"]
        self.endpoints = cfg["endpoints"]
        self.payloads = load_payloads(cfg.get("payloads"))
        self.timeout = cfg.get("scan_options", {}).get("timeout", 5)
        self.cors = cfg.get("scan_options", {}).get("cors_test", False)

    def run_json_scans(self):
        results = []
        headers = {"Origin": "*"} if self.cors else {}
        for ep in self.endpoints:
            if "json_fields" not in ep:
                continue
            for field in ep["json_fields"]:
                for p in self.payloads:
                    body = {f: f"test" for f in ep["json_fields"]}
                    body[field] = p
                    url = self.base + ep["path"]
                    r = requests.request(
                        ep["method"], url,
                        json=body,
                        timeout=self.timeout,
                        headers=headers
                    )
                    if p in r.text:
                        results.append({
                            "type": "json",
                            "endpoint": ep["path"],
                            "field": field,
                            "payload": p
                        })
        return results
