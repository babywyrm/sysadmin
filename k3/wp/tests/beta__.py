#!/usr/bin/env python3
import argparse
import requests
import time
import concurrent.futures

def send_request(session, url):
    try:
        resp = session.get(url, timeout=5)
        return resp.status_code
    except requests.exceptions.RequestException:
        return "ERR"

def run_load_test(target, qps, duration, concurrency):
    session = requests.Session()
    results = []
    start = time.time()
    end = start + duration

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        while time.time() < end:
            futures = []
            for _ in range(qps):
                futures.append(executor.submit(send_request, session, target))

            for f in futures:
                results.append(f.result())

            # keep ~1s pacing
            time.sleep(1)

    return results

def main():
    parser = argparse.ArgumentParser(description="Ingress boundary test tool")
    parser.add_argument("target", help="Target URL (e.g., http://wordpress.example.com/wp-login.php)")
    parser.add_argument("--qps", type=int, default=20, help="Requests per second (default: 20)")
    parser.add_argument("--duration", type=int, default=30, help="Test duration in seconds (default: 30)")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrent workers (default: 10)")
    args = parser.parse_args()

    print(f"[*] Starting load test against {args.target}")
    print(f"    QPS={args.qps}, Duration={args.duration}s, Concurrency={args.concurrency}\n")

    results = run_load_test(args.target, args.qps, args.duration, args.concurrency)

    total = len(results)
    success = results.count(200)
    errors = total - success

    print(f"\n=== Load Test Report ===")
    print(f"Target:          {args.target}")
    print(f"Total Requests:  {total}")
    print(f"HTTP 200 OK:     {success}")
    print(f"Errors/Other:    {errors}")
    print(f"Breakdown:       {dict((x, results.count(x)) for x in set(results))}")

if __name__ == "__main__":
    main()
