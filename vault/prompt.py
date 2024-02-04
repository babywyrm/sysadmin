import hvac
import os,sys,re

##
##

def connect_to_vault(vault_address, vault_token):
    client = hvac.Client(url=vault_address, token=vault_token)

    # Check if the connection to Vault is successful
    if client.is_authenticated():
        print("Successfully connected to Vault")
        return client
    else:
        print("Failed to connect to Vault")
        return None

def make_vault_request(client, path):
    try:
        # Make a request to the specified path in Vault
        response = client.read(path)

        if response and 'data' in response:
            return response['data']
        else:
            print(f"Failed to make request to Vault path: {path}")
            return None
    except Exception as e:
        print(f"Error making request to Vault: {e}")
        return None

if __name__ == "__main__":
    # Replace these values with your Vault address and token
    vault_address = "http://things.edu"
    vault_token = "hsdfnaksdfXxxXxxxxxxxxxxxxxxx"


    client = connect_to_vault(vault_address, vault_token)

    if client:
        while True:
            # Prompt the user for a Vault path
            vault_path = input("Enter a Vault path (or type 'exit' to quit): ")

            if vault_path.lower() == 'exit':
                break

            # Make a request to the specified path in Vault
            result = make_vault_request(client, vault_path)

            if result:
                print(f"Vault Response: {result}")

##
##
