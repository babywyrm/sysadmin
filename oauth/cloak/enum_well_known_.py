#!/usr/bin/env python3

import argparse
import requests
from urllib.parse import urlencode, urlparse
import logging
import json
import yaml
import webbrowser
from pathlib import Path
import os,sys,re

# Define common redirect paths
COMMON_REDIRECT_PATHS = [
    "/callback",
    "/oauth2/callback",
    "/auth/redirect",
    "/signin",
    "/login/callback",
    "/account",
    "/realms/{realm}/account",
    "/realms/{realm}/callback",
    "/realms/{realm}/auth/redirect"
]

def setup_logging(verbose: bool):
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='[%(levelname)s] %(message)s')

def load_config(config_path: str):
    """Load configuration from a JSON or YAML file."""
    path = Path(config_path)
    if not path.is_file():
        logging.error(f"Configuration file not found: {config_path}")
        sys.exit(1)
    
    try:
        if path.suffix in ['.yaml', '.yml']:
            with open(path, 'r') as file:
                config = yaml.safe_load(file)
        elif path.suffix == '.json':
            with open(path, 'r') as file:
                config = json.load(file)
        else:
            logging.error("Unsupported configuration file format. Use JSON or YAML.")
            sys.exit(1)
    except Exception as e:
        logging.error(f"Failed to load configuration: {e}")
        sys.exit(1)
    
    logging.debug(f"Configuration loaded: {config}")
    return config

def fetch_openid_config(discovery_url: str, verify_ssl: bool):
    """Fetch the OpenID Connect discovery document."""
    try:
        logging.info(f"Fetching OpenID configuration from: {discovery_url}")
        response = requests.get(discovery_url, verify=verify_ssl, timeout=10)
        response.raise_for_status()
        config = response.json()
        logging.debug(f"OpenID configuration: {config}")
        return config
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch OpenID configuration: {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON response from discovery URL: {e}")
        sys.exit(1)

def construct_auth_url(config: dict, params: dict):
    """Construct the authorization URL based on the discovery config and parameters."""
    auth_endpoint = config.get('authorization_endpoint')
    if not auth_endpoint:
        logging.error("Authorization endpoint not found in OpenID configuration.")
        sys.exit(1)
    
    query = urlencode(params)
    auth_url = f"{auth_endpoint}?{query}"
    logging.info(f"Authorization URL constructed: {auth_url}")
    return auth_url

def validate_scopes(scopes: str):
    """Validate and format scopes."""
    # Basic validation: ensure scopes are space-separated
    return ' '.join(scopes.strip().split())

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate an OAuth 2.0 Authorization URL based on OpenID Connect discovery."
    )
    parser.add_argument(
        'discovery_url',
        type=str,
        help="URL to the OpenID Connect discovery document (e.g., https://auth.example.com/.well-known/openid-configuration)"
    )
    parser.add_argument(
        '--client-id',
        type=str,
        required=True,
        help="Client ID registered with the authorization server."
    )
    parser.add_argument(
        '--response-type',
        type=str,
        choices=['code', 'token', 'id_token', 'code token', 'code id_token', 'token id_token', 'code token id_token'],
        default='code',
        help="OAuth 2.0 response type (default: code)"
    )
    parser.add_argument(
        '--scope',
        type=str,
        default='openid',
        help="Space-separated list of scopes (default: 'openid')"
    )
    parser.add_argument(
        '--redirect-uri',
        type=str,
        required=True,
        help="Redirect URI registered with the authorization server."
    )
    parser.add_argument(
        '--state',
        type=str,
        default='xyzABC123',
        help="An opaque value used by the client to maintain state between the request and callback (default: 'xyzABC123')"
    )
    parser.add_argument(
        '--config',
        type=str,
        help="Path to a configuration file (JSON or YAML) containing parameters."
    )
    parser.add_argument(
        '--open',
        action='store_true',
        help="Open the constructed authorization URL in the default web browser."
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help="Enable verbose (DEBUG level) logging."
    )
    parser.add_argument(
        '--insecure',
        action='store_true',
        help="Disable SSL certificate verification (not recommended for production)."
    )
    return parser.parse_args()

def introspect_token(introspect_url: str, token: str, client_id: str, client_secret: str, verify_ssl: bool):
    """Perform token introspection using the provided credentials."""
    try:
        data = {
            'token': token,
            'client_id': client_id,
            'client_secret': client_secret
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        logging.info("Performing token introspection...")
        response = requests.post(introspect_url, data=data, headers=headers, verify=verify_ssl, timeout=10)
        response.raise_for_status()
        introspect_resp = response.json()
        logging.debug(f"Introspection response: {introspect_resp}")
        return introspect_resp
    except requests.exceptions.RequestException as e:
        logging.error(f"Token introspection failed: {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON response from introspection endpoint: {e}")
        sys.exit(1)

def guess_redirect_uri(keycloak_domain: str, realm: str):
    """Generate potential redirect_uri candidates based on common patterns."""
    for path in COMMON_REDIRECT_PATHS:
        uri = path.format(realm=realm)
        redirect_uri = f"https://{keycloak_domain}{uri}"
        yield redirect_uri

def discover_redirect_uri_from_patterns(config: dict, client_id: str, keycloak_domain: str, realm: str, verify_ssl: bool):
    """Attempt to discover redirect_uri by guessing common patterns."""
    for redirect_uri in guess_redirect_uri(keycloak_domain, realm):
        params = {
            'client_id': client_id,
            'response_type': 'code',
            'scope': 'openid',
            'redirect_uri': redirect_uri,
            'state': 'xyzABC123'
        }
        auth_url = f"{config['authorization_endpoint']}?{urlencode(params)}"
        logging.info(f"Attempting redirect_uri: {redirect_uri}")
        try:
            response = requests.get(auth_url, verify=verify_ssl, timeout=10, allow_redirects=False)
            logging.debug(f"Response Status Code for {redirect_uri}: {response.status_code}")
            logging.debug(f"Response Headers for {redirect_uri}: {response.headers}")
            if response.status_code == 400:
                # Try parsing as JSON
                try:
                    error_resp = response.json()
                    error_description = error_resp.get('error_description', '')
                    match = re.search(r'Expected\s+(https?://[^\s]+)', error_description, re.IGNORECASE)
                    if match:
                        discovered_redirect_uri = match.group(1)
                        logging.info(f"Discovered redirect_uri from JSON error message: {discovered_redirect_uri}")
                        return discovered_redirect_uri
                    else:
                        logging.debug(f"No match in JSON error description: {error_description}")
                except json.JSONDecodeError:
                    # Fallback to regex on plain text
                    error_message = response.text
                    logging.debug(f"Error response for {redirect_uri}: {error_message}")
                    match = re.search(r'Expected\s+(https?://[^\s]+)', error_message, re.IGNORECASE)
                    if match:
                        discovered_redirect_uri = match.group(1)
                        logging.info(f"Discovered redirect_uri from plain text error message: {discovered_redirect_uri}")
                        return discovered_redirect_uri
                    else:
                        logging.warning(f"Failed to extract redirect_uri from error message for {redirect_uri}.")
            elif response.status_code == 302:
                # Redirect indicates that the redirect_uri is valid
                logging.info(f"Valid redirect_uri found: {redirect_uri}")
                return redirect_uri
            else:
                logging.debug(f"Unexpected status code {response.status_code} for redirect_uri: {redirect_uri}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed for redirect_uri {redirect_uri}: {e}")
    logging.warning("Failed to discover redirect_uri through pattern guessing.")
    return None

def discover_redirect_uri(auth_endpoint: str, client_id: str, verify_ssl: bool):
    """Attempt to discover the redirect_uri by inducing error messages."""
    invalid_redirect_uri = "https://invalid.com/callback"
    params = {
        'client_id': client_id,
        'response_type': 'code',
        'scope': 'openid',
        'redirect_uri': invalid_redirect_uri,
        'state': 'xyzABC123'
    }
    
    query = urlencode(params)
    auth_url = f"{auth_endpoint}?{query}"
    
    logging.info(f"Sending request to discover redirect_uri: {auth_url}")
    
    try:
        response = requests.get(auth_url, verify=verify_ssl, timeout=10)
        logging.debug(f"Response Status Code: {response.status_code}")
        logging.debug(f"Response Headers: {response.headers}")
        if response.status_code == 400:
            # Try parsing as JSON
            try:
                error_resp = response.json()
                error_description = error_resp.get('error_description', '')
                match = re.search(r'Expected\s+(https?://[^\s]+)', error_description, re.IGNORECASE)
                if match:
                    discovered_redirect_uri = match.group(1)
                    logging.info(f"Discovered redirect_uri from JSON error message: {discovered_redirect_uri}")
                    return discovered_redirect_uri
                else:
                    logging.warning("Failed to extract redirect_uri from JSON error message.")
            except json.JSONDecodeError:
                # Fallback to regex on plain text
                error_message = response.text
                logging.debug(f"Error response: {error_message}")
                match = re.search(r'Expected\s+(https?://[^\s]+)', error_message, re.IGNORECASE)
                if match:
                    discovered_redirect_uri = match.group(1)
                    logging.info(f"Discovered redirect_uri from plain text error message: {discovered_redirect_uri}")
                    return discovered_redirect_uri
                else:
                    logging.warning("Failed to extract redirect_uri from plain text error message.")
        else:
            logging.warning(f"Unexpected response status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to send discovery request: {e}")
    
    return None

def main():
    args = parse_arguments()
    setup_logging(args.verbose)
    
    # Load additional config if provided
    if args.config:
        config_params = load_config(args.config)
        # Override command-line arguments with config file values if present
        client_id = config_params.get('client_id', args.client_id)
        response_type = config_params.get('response_type', args.response_type)
        scope = config_params.get('scope', args.scope)
        redirect_uri = config_params.get('redirect_uri', args.redirect_uri)
        state = config_params.get('state', args.state)
        open_browser = config_params.get('open', args.open)
        verbose = config_params.get('verbose', args.verbose)
        verify_ssl = not config_params.get('insecure', args.insecure)
    else:
        client_id = args.client_id
        response_type = args.response_type
        scope = args.scope
        redirect_uri = args.redirect_uri
        state = args.state
        open_browser = args.open
        verbose = args.verbose
        verify_ssl = not args.insecure
    
    # Validate and format scopes
    scope = validate_scopes(scope)
    
    # Fetch OpenID configuration
    config = fetch_openid_config(args.discovery_url, verify_ssl)
    
    # Extract Keycloak domain and realm from discovery URL
    # Assuming discovery_url is of the form https://<domain>/realms/<realm>/.well-known/openid-configuration
    try:
        parsed_url = urlparse(args.discovery_url)
        path_parts = parsed_url.path.strip("/").split("/")
        if len(path_parts) < 3 or path_parts[0] != "realms":
            logging.error("Invalid discovery URL format. Expected format: https://<domain>/realms/<realm>/.well-known/openid-configuration")
            sys.exit(1)
        realm = path_parts[1]
        keycloak_domain = parsed_url.netloc
    except Exception as e:
        logging.error(f"Failed to parse discovery URL: {e}")
        sys.exit(1)
    
    # Optionally attempt to discover redirect_uri
    discover_choice = input("Do you want to attempt discovering the redirect_uri? (y/n): ").strip().lower()
    if discover_choice == 'y':
        # First, try error message discovery
        discovered_redirect_uri = discover_redirect_uri(config['authorization_endpoint'], client_id, verify_ssl)
        if discovered_redirect_uri:
            redirect_uri = discovered_redirect_uri
            logging.info(f"Using discovered redirect_uri: {redirect_uri}")
        else:
            # If failed, try pattern guessing
            discovered_redirect_uri = discover_redirect_uri_from_patterns(config, client_id, keycloak_domain, realm, verify_ssl)
            if discovered_redirect_uri:
                redirect_uri = discovered_redirect_uri
                logging.info(f"Using discovered redirect_uri: {redirect_uri}")
            else:
                logging.error("Failed to discover redirect_uri. Please provide it manually.")
                sys.exit(1)
    
    # Define authorization parameters
    params = {
        'client_id': client_id,
        'response_type': response_type,
        'scope': scope,
        'redirect_uri': redirect_uri,
        'state': state
    }
    
    # Construct authorization URL
    auth_url = construct_auth_url(config, params)
    
    # Print the authorization URL
    print("\n=== Authorization URL ===")
    print(auth_url)
    print("==========================\n")
    
    # Optionally open the URL in a web browser
    if open_browser:
        try:
            webbrowser.open(auth_url)
            logging.info("Authorization URL opened in the default web browser.")
        except Exception as e:
            logging.error(f"Failed to open web browser: {e}")
    
    # Example of additional functionality: Token Introspection (if token is provided)
    introspect_choice = input("Do you want to introspect a token? (y/n): ").strip().lower()
    if introspect_choice == 'y':
        token = input("Enter the access token to introspect: ").strip()
        introspect_url = config.get('introspection_endpoint')
        if not introspect_url:
            logging.error("Introspection endpoint not found in OpenID configuration.")
            sys.exit(1)
        
        # Prompt for client credentials
        print("\nTo perform introspection, provide credentials of a confidential client.")
        introspect_client_id = input("Client ID: ").strip()
        introspect_client_secret = input("Client Secret: ").strip()
        
        introspect_resp = introspect_token(introspect_url, token, introspect_client_id, introspect_client_secret, verify_ssl)
        
        if introspect_resp.get('active'):
            print("\n=== Token is Active ===")
            print(json.dumps(introspect_resp, indent=4))
            print("========================\n")
        else:
            print("\n=== Token is Inactive or Invalid ===\n")

if __name__ == "__main__":
    main()

##
##
