import requests
from keycloak import KeycloakAdmin
from keycloak.exceptions import KeycloakGetError

##
##

# Configuration for your Keycloak server
KEYCLOAK_URL = "http://things.edu/"  # Change to your Keycloak server URL
ADMIN_USERNAME = "person____"  # Replace with your Keycloak admin username
ADMIN_PASSWORD = "ZZZZZZZZZZ"  # Replace with your Keycloak admin password
##
##REALM_NAME = "master"  # Replace with the realm you want to manage
##

# The token URL for Keycloak
TOKEN_URL = f"{KEYCLOAK_URL}realms/master/protocol/openid-connect/token"

def get_access_token():
    """Get an access token from Keycloak using admin credentials."""
    data = {
        'grant_type': 'password',
        'client_id': 'admin-cli',
        'username': ADMIN_USERNAME,
        'password': ADMIN_PASSWORD,
    }

    response = requests.post(TOKEN_URL, data=data)
    
    if response.status_code == 200:
        access_token = response.json().get('access_token')
        if access_token:
            return access_token
        else:
            print("Failed to retrieve access token.")
    else:
        print(f"Error fetching token: {response.status_code}, {response.text}")
    return None

def list_realms_and_configs(keycloak_admin):
    """List all realms and their configurations."""
    try:
        realms = keycloak_admin.get_realms()
        print("\nRealms and Configurations:\n")
        for realm in realms:
            print(f"Realm: {realm['realm']}")
            print(f"  Enabled: {realm['enabled']}")
            print(f"  SSL Required: {realm['sslRequired']}")
            print(f"  Access Token Lifespan: {realm.get('accessTokenLifespan', 'Not set')}")
            print(f"  Registration Allowed: {realm.get('registrationAllowed', 'Not set')}")
            print("-" * 40)
        return [realm['realm'] for realm in realms]
    except KeycloakAuthenticationError as e:
        print(f"Keycloak API Error: {e}")
    except Exception as e:
        print(f"Error fetching realms: {e}")
    return []

def list_master_keys(access_token, realm_name):
    """List all master keys configured for a realm and their types."""
    try:
        url = f"{KEYCLOAK_URL}admin/realms/{realm_name}/keys"
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            keys = response.json()
            print(f"\nMaster Keys for Realm: {realm_name}\n")
            for key in keys.get("keys", []):
                print(f"  Kid: {key['kid']}")
                print(f"  Algorithm: {key['algorithm']}")
                print(f"  Provider: {key['providerId']}")
                print(f"  Type: {key['type']}")
                print("-" * 40)
        else:
            print(f"Error fetching keys for realm {realm_name}: {response.status_code}: {response.text}")
    except Exception as e:
        print(f"Error fetching keys for realm {realm_name}: {e}")

def main():
    access_token = get_access_token()
    if not access_token:
        print("Failed to authenticate to Keycloak.")
        return

    keycloak_admin = KeycloakAdmin(server_url=KEYCLOAK_URL,
                                   username=ADMIN_USERNAME,
                                   password=ADMIN_PASSWORD,
                                   realm_name="master",
                                   verify=True)
    
    print("Successfully connected to Keycloak.")

    # List all realms and their configurations
    realms = list_realms_and_configs(keycloak_admin)

    # List master keys for each realm
    for realm_name in realms:
        list_master_keys(access_token, realm_name)

if __name__ == "__main__":
    main()

##
##
