#!/bin/bash

# Set the Okta API token and org URL

##
##

export OKTA_API_TOKEN=<your_api_token>
export OKTA_ORG_URL=<your_org_url>

# Authenticate with your Okta account
okta auth token ${OKTA_API_TOKEN} ${OKTA_ORG_URL}

# Get a list of all users in your organization
users=$(okta users:list --format json)

# Loop through each user and get their assigned applications with permissions
for row in $(echo "${users}" | jq -r '.[] | @base64'); do
  # Parse the user data
  user=$(echo ${row} | base64 --decode | jq -r '.id')
  echo "User: ${user}"

  # Get a list of apps for the user with permissions
  apps=$(curl -s "${OKTA_ORG_URL}/api/v1/users/${user}/appLinks" \
         -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
         -H "Accept: application/json" \
         | jq '[.[] | {appName: .appName, linkUrl: .linkUrl, permissions: .scope}]')

  # Output the list of apps for the user with permissions
  echo "${apps}"
done | jq -s . > okta_users_apps_permissions.json

####
####


###################

To install the Okta CLI on macOS, you can use Homebrew, a popular package manager for macOS:

Open the Terminal app on your macOS.
Install Homebrew by running the following command:
bash
Copy code
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
After Homebrew is installed, run the following command to install the Okta CLI:
Copy code
brew install okta
Once the installation is complete, you can verify the installation by running the following command:
Copy code
okta version
This should display the version of the Okta CLI that you just installed.

You'll also need to have an Okta account and API token to use the Okta CLI. You can obtain an API token from your Okta account by following these steps:

Log in to your Okta account.
Click on your user profile icon in the top-right corner and select "API" from the dropdown menu.
Click on the "Create Token" button and follow the prompts to create a new API token.
Once you have an API token, you can use it to authenticate with the Okta CLI.


###################
