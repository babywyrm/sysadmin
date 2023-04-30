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


