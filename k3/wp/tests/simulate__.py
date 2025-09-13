#!/usr/bin/env python3
"""
WordPress/Nginx/Apache Stress Tester ..beta..
------------------------------------
Quick script to measure response times under different scenarios:
- steady requests
- burst requests
- randomized paths (like a fuzzer would do)
"""

import time
import random
import string
import urllib.request

TARGET = "http://127.0.0.1/"   # change to http://things.edu/ if resolving works
RUNTIME = 30                   # seconds per test
BURST_CONCURRENCY = 5          # how many requests in a burst
FUZZ_PATHS = ["wp-login.php", "xmlrpc.php", "admin-ajax.php"]


def do_request(url):
    start = time.time()
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            resp.read(128)  # only read a little
    except Exception as e:
        return (time.time() - start, f"ERROR: {e}")
    return (time.time() - start, "OK")


def steady_test():
    print("=== Steady Test ===")
    end = time.time() + RUNTIME
    while time.time() < end:
        dur, status = do_request(TARGET)
        print(f"[{time.strftime('%H:%M:%S')}] Steady {status} {dur:.3f}s")
        time.sleep(1)


def burst_test():
    print("=== Burst Test ===")
    end = time.time() + RUNTIME
    while time.time() < end:
        start = time.time()
        results = [do_request(TARGET) for _ in range(BURST_CONCURRENCY)]
        for dur, status in results:
            print(f"[{time.strftime('%H:%M:%S')}] Burst {status} {dur:.3f}s")
        wait = max(0, 1 - (time.time() - start))
        time.sleep(wait)


def fuzz_test():
    print("=== Fuzz Test ===")
    end = time.time() + RUNTIME
    while time.time() < end:
        # random path: pick known or generate noise
        if random.random() < 0.5:
            path = random.choice(FUZZ_PATHS)
        else:
            path = ''.join(random.choices(string.ascii_lowercase, k=8))
        url = TARGET.rstrip("/") + "/" + path
        dur, status = do_request(url)
        print(f"[{time.strftime('%H:%M:%S')}] Fuzz {path} {status} {dur:.3f}s")
        time.sleep(0.5)


if __name__ == "__main__":
    print("Starting tests...")
    steady_test()
    burst_test()
    fuzz_test()
    print("Done.")
