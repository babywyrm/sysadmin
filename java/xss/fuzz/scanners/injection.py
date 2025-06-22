import requests
from loaders.payload_loader import load_payloads

class InjectionScanner:
    def __init__(self, cfg):
        self.base = cfg["base_url"]
        # filter endpoints of type 'injection'
        self.endpoints = [ep for ep in cfg["endpoints"] if ep["type"] == "injection"]
        self.payloads = load_payloads(cfg["payloads"].get("injection"))
        self.timeout = cfg.get("scan_options", {}).get("timeout", 5)

    def run(self):
        findings = []
        for ep in self.endpoints:
            for field in ep["json_fields"]:
                for payload in self.payloads:
                    # build JSON body with payload in the target field
                    body = {f: "test" for f in ep["json_fields"]}
                    body[field] = payload
                    url = self.base + ep["path"]
                    resp = requests.request(
                        ep["method"], url, json=body, timeout=self.timeout
                    )
                    text = resp.text.lower()
                    # simple success detection: look for command output patterns
                    if "uid=" in text or "gid=" in text or "root:" in text:
                        findings.append({
                            "endpoint": ep["path"],
                            "field": field,
                            "payload": payload,
                            "evidence": resp.text.strip()[:200]
                        })
                    # detect errors indicating injection (shell syntax errors)
                    elif any(err in text for err in ["syntax error", "cannot find", "bash:"]):
                        findings.append({
                            "endpoint": ep["path"],
                            "field": field,
                            "payload": payload,
                            "evidence": resp.text.strip()[:200]
                        })
        return findings
