
import json
import requests
import subprocess
import time
import os,sys,re

##
##

# Configuration Variables
burp_jar_path = "/path/to/burpsuite_pro.jar"
project_file = "myproject.burp"
config_file = "burp_config.json"
burp_api_url = "http://localhost:1337/v0.1/"
headers = {"Content-Type": "application/json"}
seed_endpoints = ["http://example.com/api/endpoint1", "http://example.com/api/endpoint2"]

# Step 1: Generate Burp JSON Configuration for Headless Authentication
def generate_config_file():
    config_data = {
        "target": {
            "scope": {
                "include": [{"url": "http://example.com"}]
            }
        },
        "authentication": {
            "enabled": True,
            "login_url": "http://example.com/login",
            "credentials": {
                "username": "myUsername",
                "password": "myPassword"
            },
            "session_rules": [
                {
                    "rule_name": "Auth Session Handling",
                    "scope": "in-scope only",
                    "macro": [
                        {
                            "request": {
                                "method": "POST",
                                "url": "http://example.com/login",
                                "body": "username=myUsername&password=myPassword"
                            },
                            "response_extraction": {
                                "token_name": "sessionid",
                                "match_type": "regex",
                                "regex": "sessionid=([a-zA-Z0-9]+);"
                            }
                        }
                    ]
                }
            ]
        },
        "scanner": {
            "active_scan": True,
            "scan_config": "full_scan"
        }
    }

    with open(config_file, 'w') as f:
        json.dump(config_data, f, indent=4)
    print(f"Configuration file '{config_file}' created.")

# Step 2: Start Burp Suite in Headless Mode
def start_burp_headless():
    print("Starting Burp Suite in headless mode...")
    subprocess.Popen([
        "java", "-jar", burp_jar_path,
        "--project-file=" + project_file,
        "--config-file=" + config_file
    ])
    print("Burp Suite started in headless mode.")

# Step 3: Start a Scan for Each Endpoint
def start_scan(endpoint_url):
    scan_config = {
        "urls": [endpoint_url],
        "scan_config": "full_scan"
    }
    response = requests.post(burp_api_url + "scan", headers=headers, data=json.dumps(scan_config))
    response.raise_for_status()
    scan_id = response.json().get("scan_id")
    print(f"Started scan for {endpoint_url}, Scan ID: {scan_id}")
    return scan_id

# Step 4: Monitor Scans until Completion
def monitor_scans(scan_ids):
    print("Monitoring scan progress...")
    while True:
        all_done = True
        for scan_id in scan_ids:
            response = requests.get(f"{burp_api_url}scan/{scan_id}", headers=headers)
            response.raise_for_status()
            status = response.json().get("status")
            if status != "completed":
                print(f"Scan ID {scan_id} is still in progress...")
                all_done = False
            else:
                print(f"Scan ID {scan_id} is completed.")
        if all_done:
            print("All scans completed.")
            break
        time.sleep(30)  # Poll every 30 seconds

# Step 5: Retrieve and Save Scan Results
def save_scan_results(scan_ids):
    for scan_id in scan_ids:
        response = requests.get(f"{burp_api_url}scan/{scan_id}/report", headers=headers)
        response.raise_for_status()
        report_path = f"scan_report_{scan_id}.html"
        with open(report_path, "wb") as report_file:
            report_file.write(response.content)
        print(f"Saved report for Scan ID {scan_id} to {report_path}")

# Main Function to Run All Steps
def main():
    generate_config_file()
    start_burp_headless()
    time.sleep(30)  # Wait for Burp to initialize

    # Start scans for each endpoint and collect scan IDs
    scan_ids = [start_scan(endpoint) for endpoint in seed_endpoints]

    # Monitor scans until they complete
    monitor_scans(scan_ids)

    # Retrieve and save scan results
    save_scan_results(scan_ids)

    print("All scans completed and reports saved.")

if __name__ == "__main__":
    main()

##
##
