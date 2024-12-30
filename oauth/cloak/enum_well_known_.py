#!/usr/bin/env python3

##
##

import argparse
import requests
from urllib.parse import urlencode
import os,sys,re
import logging
import json
import yaml
import webbrowser
from pathlib import Path

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

def fetch_openid_config(discovery_url: str):
    """Fetch the OpenID Connect discovery document."""
    try:
        logging.info(f"Fetching OpenID configuration from: {discovery_url}")
        response = requests.get(discovery_url, verify=False, timeout=10)
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
        help="URL to the OpenID Connect discovery document (e.g., https://keycloak.example.com/.well-known/openid-configuration)"
    )
    parser.add_argument(
        '--client-id',
        type=str,
        default='fleet-api',
        help="Client ID registered with the authorization server (default: fleet-api)"
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
        default='openid public command classified',
        help="Space-separated list of scopes (default: 'openid public command classified')"
    )
    parser.add_argument(
        '--redirect-uri',
        type=str,
        default='https://keycloak.warbird.htb/realms/fleet-hq/account',
        help="Redirect URI registered with the authorization server (default: https://keycloak.warbird.htb/realms/fleet-hq/account)"
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
    return parser.parse_args()

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
    else:
        client_id = args.client_id
        response_type = args.response_type
        scope = args.scope
        redirect_uri = args.redirect_uri
        state = args.state
    
    # Validate and format scopes
    scope = validate_scopes(scope)
    
    # Fetch OpenID configuration
    config = fetch_openid_config(args.discovery_url)
    
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
    if args.open:
        try:
            webbrowser.open(auth_url)
            logging.info("Authorization URL opened in the default web browser.")
        except Exception as e:
            logging.error(f"Failed to open web browser: {e}")

if __name__ == "__main__":
    main()

##
##
