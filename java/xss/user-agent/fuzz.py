import os,sys,re
import requests

##
##

def send_request(user_agent):
    url = "http://thing.edu:6969/support"
    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "http://thing.edu:6969",
        "DNT": "1",
        "Connection": "close",
        "Cookie": "iconSize=32x32; is_admin=XXX",
        "Upgrade-Insecure-Requests": "1"
    }
    data = {
        "fname": "aa",
        "lname": "aa",
        "email": "tot@fr.fr",
        "phone": "aa",
        "message": "<>"
    }
    response = requests.post(url, headers=headers, data=data)
    return response.text

def main():
    # Load wordlist for fuzzing User-Agent header
    with open("user_agents.txt", "r") as f:
        user_agents = f.readlines()
    
    # Iterate over each user-agent in the wordlist
    for user_agent in user_agents:
        user_agent = user_agent.strip()  # Remove newline characters
        response = send_request(user_agent)
        print(response)

if __name__ == "__main__":
    main()

##
##
##
##

import os,sys,re
import requests
import time

def send_request(user_agent):
    url = "http://thing.edu:6969/support"
    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "http://thing.edu:6969",
        "DNT": "1",
        "Connection": "close",
        "Cookie": "iconSize=32x32; is_admin=XXX",
        "Upgrade-Insecure-Requests": "1"
    }
    data = {
        "fname": "aa",
        "lname": "aa",
        "email": "tot@fr.fr",
        "phone": "aa",
        "message": "<>"
    }
    response = requests.post(url, headers=headers, data=data)
    content_length = len(response.content)
    response_code = response.status_code
    return content_length, response_code

def main():
    # Load wordlist for fuzzing User-Agent header
    with open("user_agents.txt", "r") as f:
        user_agents = f.readlines()
    
    # Iterate over each user-agent in the wordlist
    for user_agent in user_agents:
        user_agent = user_agent.strip()  # Remove newline characters
        content_length, response_code = send_request(user_agent)
        print(f"User-Agent: {user_agent}")
        print(f"Content Length: {content_length}")
        print(f"Response Code: {response_code}")
        print("="*50)
        time.sleep(1)  # Wait for 1 second before sending the next request

if __name__ == "__main__":
    main()

##
##

