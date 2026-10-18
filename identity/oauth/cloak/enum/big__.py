import requests
import json
import jwt
import os,sys,re
from urllib.parse import urljoin
import argparse

##
##

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
    Extracts key details from the OpenID Connect configuration and prints them.
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

def brute_force_realms(base_url, wordlist, verify_ssl=True):
    """
    Attempts to discover valid realms by brute-forcing common names.
    """
    print("[INFO] Starting realm brute-force...")
    valid_realms = []

    try:
        with open(wordlist, "r") as file:
            realms = file.read().splitlines()
        for realm in realms:
            openid_config_url = urljoin(base_url, f"realms/{realm}/.well-known/openid-configuration")
            try:
                response = requests.get(openid_config_url, timeout=5, verify=verify_ssl)
                if response.status_code == 200:
                    print(f"[VALID] Realm found: {realm} ({openid_config_url})")
                    valid_realms.append(realm)
            except requests.exceptions.RequestException:
                pass
    except FileNotFoundError:
        print(f"[ERROR] Wordlist not found: {wordlist}")

    return valid_realms

def introspect_token(base_url, realm_name, token, client_id, client_secret, verify_ssl=True):
    """
    Introspects a token using the Keycloak introspection endpoint.
    """
    introspection_url = urljoin(base_url, f"realms/{realm_name}/protocol/openid-connect/token/introspect")
    print(f"[INFO] Introspecting token at: {introspection_url}")
    data = {"token": token, "client_id": client_id, "client_secret": client_secret}
    try:
        response = requests.post(introspection_url, data=data, verify=verify_ssl, timeout=10)
        response.raise_for_status()
        print("[INFO] Token Introspection Result:")
        print(json.dumps(response.json(), indent=4))
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to introspect token: {e}")

def decode_jwt(token):
    """
    Decodes and displays a JWT.
    """
    try:
        header, payload, signature = token.split(".")
        decoded_header = jwt.utils.base64url_decode(header.encode()).decode()
        decoded_payload = jwt.utils.base64url_decode(payload.encode()).decode()
        print("\n[INFO] Decoded JWT:")
        print(f"Header: {decoded_header}")
        print(f"Payload: {decoded_payload}")
    except Exception as e:
        print(f"[ERROR] Failed to decode JWT: {e}")

def save_results_to_file(data, output_file):
    """
    Saves results to a specified output file.
    """
    try:
        with open(output_file, "w") as file:
            file.write(json.dumps(data, indent=4))
        print(f"[INFO] Results saved to: {output_file}")
    except IOError as e:
        print(f"[ERROR] Failed to save results: {e}")

def parse_args():
    """
    Parses command-line arguments.
    """
    parser = argparse.ArgumentParser(description="Keycloak Enumeration Script")
    parser.add_argument("base_url", help="Base URL of the Keycloak server")
    parser.add_argument("realm_name", nargs="?", help="Realm name to enumerate")
    parser.add_argument("--insecure", action="store_true", help="Bypass SSL verification")
    parser.add_argument("--introspect", help="Introspect a token")
    parser.add_argument("--client-id", help="Client ID for introspection")
    parser.add_argument("--client-secret", help="Client Secret for introspection")
    parser.add_argument("--decode", help="Decode a JWT token")
    parser.add_argument("--output", help="Save results to a file")
    parser.add_argument("--realms", action="store_true", help="Enumerate all realms")
    parser.add_argument("--wordlist", help="Wordlist for brute-forcing realms")
    return parser.parse_args()

def main():
    args = parse_args()
    verify_ssl = not args.insecure

    if args.decode:
        decode_jwt(args.decode)
        return

    if args.introspect:
        if not args.client_id or not args.client_secret:
            print("[ERROR] Client ID and Client Secret are required for token introspection.")
            return
        introspect_token(args.base_url, args.realm_name, args.introspect, args.client_id, args.client_secret, verify_ssl)
        return

    if args.realms:
        if not args.wordlist:
            print("[ERROR] A wordlist is required for brute-forcing realms.")
            return
        valid_realms = brute_force_realms(args.base_url, args.wordlist, verify_ssl)
        if args.output:
            save_results_to_file(valid_realms, args.output)
        return

    if args.realm_name:
        openid_config = fetch_openid_configuration(args.base_url, args.realm_name, verify_ssl)
        if openid_config:
            extract_realm_details(openid_config)
            if args.output:
                save_results_to_file(openid_config, args.output)

if __name__ == "__main__":
    main()

##
##

