
##
##

import requests
import json

# Set up API request parameters
base_url = "https://your.okta.domain/api/v1"
app_id = "your_app_id"
headers = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "Authorization": "SSWS your_api_key"
}

# Get all users assigned to the app
url = f"{base_url}/apps/{app_id}/users"
response = requests.get(url, headers=headers)
users = json.loads(response.text)

# Create a list to store user information
user_list = []

# Loop through each user and get their app-specific permissions
for user in users:
    user_id = user["id"]
    url = f"{base_url}/apps/{app_id}/users/{user_id}/roles"
    response = requests.get(url, headers=headers)
    permissions = json.loads(response.text)
    
    # Create a dictionary to store user information
    user_dict = {
        "firstName": user["profile"]["firstName"],
        "lastName": user["profile"]["lastName"],
        "permissions": [permission["type"] for permission in permissions]
    }
    
    # Add the user dictionary to the list
    user_list.append(user_dict)

# Save the user list to a JSON file
with open("user_permissions.json", "w") as file:
    json.dump(user_list, file, indent=4)

##
##
