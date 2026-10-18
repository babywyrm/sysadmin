#!/usr/bin/python3

##
##

import os,sys,re
import requests
import time

# Global variables
BASE_URL = "https://api.thousandeyes.com"
USERNAME = "your_username"
PASSWORD = "your_password"
API_TOKEN = None


def get_api_token():
    global API_TOKEN
    auth_endpoint = BASE_URL + "/v6/auth/login"
    data = {
        "username": USERNAME,
        "password": PASSWORD
    }

    try:
        response = requests.post(auth_endpoint, json=data)
        response.raise_for_status()
        token = response.json().get("token")
        if token:
            API_TOKEN = token
            print("New API token obtained.")
        else:
            print("Failed to obtain API token.")
    except requests.exceptions.RequestException as e:
        print("Error occurred during API token retrieval:", e)


def revoke_api_token():
    global API_TOKEN
    if API_TOKEN:
        revoke_endpoint = BASE_URL + "/v6/auth/logout"
        headers = {
            "Authorization": "Bearer " + API_TOKEN
        }

        try:
            response = requests.post(revoke_endpoint, headers=headers)
            response.raise_for_status()
            print("API token revoked.")
            API_TOKEN = None
        except requests.exceptions.RequestException as e:
            print("API token revocation failed:", e)


def test_api_token():
    if API_TOKEN:
        test_endpoint = BASE_URL + "/v6/account"
        headers = {
            "Authorization": "Bearer " + API_TOKEN
        }

        try:
            response = requests.get(test_endpoint, headers=headers)
            response.raise_for_status()
            print("API token is still valid.")
        except requests.exceptions.RequestException as e:
            print("API token test failed:", e)
            get_api_token()
    else:
        print("API token is not available. Please obtain a new token.")


def main():
    while True:
        test_api_token()
        time.sleep(300)  # Sleep for 5 minutes (300 seconds)
        revoke_api_token()
        get_api_token()
        test_api_token()
        time.sleep(120)  # Sleep for 2 minutes (120 seconds)


if __name__ == "__main__":
    get_api_token()
    main()

##
##
  
##
## In this updated script, I've added two additional functions:
##
## revoke_api_token(): Revokes the current API token by making a POST request to the /auth/logout endpoint.
## main(): The main function now includes the revocation process. After testing the API token every 5 minutes, it revokes the token, obtains a new one, and tests the new token again.
##
