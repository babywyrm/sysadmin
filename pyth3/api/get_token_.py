#!/usr/bin/python3

import os,sys,re
import requests
import time

##
##

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
            print("API token successfully obtained.")
        else:
            print("Failed to obtain API token.")
    except requests.exceptions.RequestException as e:
        print("Error occurred during API token retrieval:", e)


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


if __name__ == "__main__":
    get_api_token()
    main()

##
##
