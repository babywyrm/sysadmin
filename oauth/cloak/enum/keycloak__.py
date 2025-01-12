import requests
import os,sys,re
from urllib.parse import urljoin

######
######

def fetch_openid_configuration(base_url, realm_name, verify_ssl=True):
    """
    Fetches the OpenID Connect configuration for a given Keycloak realm.
    """
    openid_config_url = urljoin(base_url, f"realms/{realm_name}/.well-known/openid-configuration")
    try:
        print(f"[INFO] Fetching OpenID configuration from: {openid_config_url}")
        response = requests.get(openid_config_url, timeout=10, verify=verify_ssl)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.SSLError:
        print(f"[ERROR] SSL Certificate verification failed for: {openid_config_url}")
        if not verify_ssl:
            print("[INFO] SSL verification was bypassed but still failed. Check your server's configuration.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to fetch OpenID configuration: {e}")
        return None


def extract_realm_details(openid_config):
    """
    Extracts key details from the OpenID Connect configuration.
    """
    print("\n[INFO] Extracted Realm Details:")
    details = {
        "Issuer": openid_config.get("issuer"),
        "Authorization Endpoint": openid_config.get("authorization_endpoint"),
        "Token Endpoint": openid_config.get("token_endpoint"),
        "Introspection Endpoint": openid_config.get("introspection_endpoint"),
        "Userinfo Endpoint": openid_config.get("userinfo_endpoint"),
        "JWKS URI": openid_config.get("jwks_uri"),
        "End Session Endpoint": openid_config.get("end_session_endpoint"),
        "Grant Types Supported": openid_config.get("grant_types_supported"),
        "ACR Values Supported": openid_config.get("acr_values_supported"),
        "Claims Supported": openid_config.get("claims_supported"),
    }

    for key, value in details.items():
        print(f"{key}: {value}")


def main():
    if len(sys.argv) < 3:
        print("Usage: python keycloak_enum.py <base_url> <realm_name> [--insecure]")
        print("Example: python keycloak_enum.py https://something.edu daddy-hq --insecure")
        sys.exit(1)

    base_url = sys.argv[1]
    realm_name = sys.argv[2]
    verify_ssl = "--insecure" not in sys.argv  # Check for the '--insecure' flag

    if not verify_ssl:
        print("[WARNING] SSL verification is disabled. This may expose you to MITM attacks.")

    # Fetch OpenID Connect configuration
    openid_config = fetch_openid_configuration(base_url, realm_name, verify_ssl=verify_ssl)
    if not openid_config:
        print("[ERROR] Unable to retrieve OpenID configuration. Exiting.")
        sys.exit(1)

    # Extract and display details
    extract_realm_details(openid_config)


if __name__ == "__main__":
    main()
