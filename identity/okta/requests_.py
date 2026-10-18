
##
##

import okta
import requests

# Set up the Okta client
org_url = 'https://your_okta_domain.okta.com'
api_key = 'your_api_key_here'
client = okta.Client(org_url, api_key)

# Retrieve a list of all users
users, _, err = client.list_users()
if err:
    raise Exception(f"Error retrieving user list: {err}")

# Iterate over the list of users and retrieve their assigned applications
for user in users:
    # Retrieve the list of assigned applications for the current user
    user_id = user.id
    app_assignments, _, err = client.list_application_user_assignments(user_id)
    if err:
        raise Exception(f"Error retrieving application assignments for user {user_id}: {err}")

    # Print the user's name and the list of assigned applications
    print(f"User: {user.profile.login}")
    if app_assignments:
        for app_assignment in app_assignments:
            app_name = app_assignment.application.label
            print(f"  Assigned application: {app_name}")
    else:
        print("  No assigned applications")
        
##
##
