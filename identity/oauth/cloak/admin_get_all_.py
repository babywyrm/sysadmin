import requests
import getpass
import os,sys,re
import urllib3

##

# Suppress InsecureRequestWarning for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default timeout for requests
REQUEST_TIMEOUT = 10

def get_admin_token(base_url, admin_username, admin_password, admin_realm="master", verify_ssl=True):
    """
    Authenticate with Keycloak and retrieve an admin access token.

    Args:
        base_url (str): The base URL of the Keycloak server.
        admin_username (str): The admin username.
        admin_password (str): The admin password.
        admin_realm (str): The realm used for admin authentication.
        verify_ssl (bool): Whether to verify SSL certificates.

    Returns:
        str: The access token.
    """
    # Ensure the base URL does not end with a slash
    base_url = base_url.rstrip('/')
    token_url = f"{base_url}/realms/{admin_realm}/protocol/openid-connect/token"
    print(f"Debug: Using token URL: {token_url}")  # Debugging line
    payload = {
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": admin_username,
        "password": admin_password
    }

    try:
        response = requests.post(token_url, data=payload, verify=verify_ssl, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response.json().get("access_token")
    except requests.exceptions.Timeout:
        print("Error: Request to Keycloak server timed out.")
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        print(f"Response: {response.text}")
    except ValueError:
        print("Failed to decode JSON. Raw response content:")
        print(response.text)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    raise Exception("Failed to retrieve the admin token.")

def get_all_realms(base_url, token, verify_ssl=True):
    """
    Fetch all realms from Keycloak.

    Args:
        base_url (str): The base URL of the Keycloak server.
        token (str): The admin access token.
        verify_ssl (bool): Whether to verify SSL certificates.

    Returns:
        list: A list of realm names.
    """
    headers = {"Authorization": f"Bearer {token}"}
    realms_url = f"{base_url.rstrip('/')}/admin/realms"
    try:
        response = requests.get(realms_url, headers=headers, verify=verify_ssl, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.Timeout:
        print("Error: Request to Keycloak server timed out.")
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        print(f"Response: {response.text}")
    except ValueError:
        print("Failed to decode JSON. Raw response content:")
        print(response.text)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    raise Exception("Failed to fetch realms.")

def get_users_in_realm(base_url, token, realm, verify_ssl=True):
    """
    Fetch all users in a specified realm.

    Args:
        base_url (str): The base URL of the Keycloak server.
        token (str): The admin access token.
        realm (str): The realm name.
        verify_ssl (bool): Whether to verify SSL certificates.

    Returns:
        list: A list of users in the realm.
    """
    headers = {"Authorization": f"Bearer {token}"}
    users_url = f"{base_url.rstrip('/')}/admin/realms/{realm}/users"
    try:
        response = requests.get(users_url, headers=headers, verify=verify_ssl, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.Timeout:
        print(f"Error: Request to Keycloak server timed out for realm {realm}.")
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        print(f"Response: {response.text}")
    except ValueError:
        print("Failed to decode JSON. Raw response content:")
        print(response.text)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    raise Exception(f"Failed to fetch users for realm {realm}.")

def get_realm_details(base_url, token, realm, verify_ssl=True):
    """
    Fetch additional details for a specified realm, including clients, roles, groups, and settings.

    Args:
        base_url (str): The base URL of the Keycloak server.
        token (str): The admin access token.
        realm (str): The realm name.
        verify_ssl (bool): Whether to verify SSL certificates.

    Returns:
        dict: Details of the realm.
    """
    headers = {"Authorization": f"Bearer {token}"}
    details = {}

    endpoints = {
        "clients": f"{base_url.rstrip('/')}/admin/realms/{realm}/clients",
        "roles": f"{base_url.rstrip('/')}/admin/realms/{realm}/roles",
        "groups": f"{base_url.rstrip('/')}/admin/realms/{realm}/groups",
        "settings": f"{base_url.rstrip('/')}/admin/realms/{realm}"
    }

    for key, url in endpoints.items():
        try:
            response = requests.get(url, headers=headers, verify=verify_ssl, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            details[key] = response.json()
        except requests.exceptions.HTTPError as http_err:
            print(f"Error fetching {key} for realm {realm}: {http_err}")
            details[key] = None
        except Exception as e:
            print(f"Unexpected error fetching {key} for realm {realm}: {e}")
            details[key] = None

    return details

def main():
    """Main entry point for the script."""
    base_url = input("Enter the Keycloak base URL (e.g., https://keycloak.example.com/auth): ").strip()
    admin_username = input("Enter the admin username: ").strip()
    admin_password = getpass.getpass("Enter the admin password: ").strip()
    admin_realm = input("Enter the admin realm (default: master): ").strip() or "master"

    verify_ssl = input("Verify SSL certificates? (yes/no): ").strip().lower() == "yes"

    try:
        print("Authenticating...")
        token = get_admin_token(base_url, admin_username, admin_password, admin_realm, verify_ssl=verify_ssl)
        print("Successfully authenticated.")

        print("Fetching realms...")
        realms = get_all_realms(base_url, token, verify_ssl=verify_ssl)
        print("Realms:")
        for realm in realms:
            print(f"  - {realm['realm']}")

        for realm in realms:
            realm_name = realm['realm']
            print(f"\nFetching details for realm: {realm_name}")
            users = get_users_in_realm(base_url, token, realm_name, verify_ssl=verify_ssl)
            details = get_realm_details(base_url, token, realm_name, verify_ssl=verify_ssl)

            print(f"Users in realm '{realm_name}':")
            for user in users:
                print(f"  - {user['username']} ({user.get('email', 'No email')})")

            print(f"Details for realm '{realm_name}':")
            for key, value in details.items():
                print(f"  {key.capitalize()}: {len(value) if value else 'No data'}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

##
