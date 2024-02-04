import hvac
import os,sys,re

##
##

# Initialize the Vault client
def initialize_vault_client(vault_addr, token):
    client = hvac.Client(url=vault_addr, token=token)
    return client

# Function to store a password in Vault
def insert(vault_addr, token, password):
    try:
        client = initialize_vault_client(vault_addr, token)
        # Write the password to Vault
        client.secrets.kv.v2.create_or_update_secret(
            path='passwords',
            secret=dict(devopsschool=password)
        )
        return True, "Password stored successfully"
    except Exception as e:
        return False, f"Error storing password: {str(e)}"

# Function to read a password from Vault using a token
def display(vault_addr, token):
    try:
        client = initialize_vault_client(vault_addr, token)
        # Read the password from Vault
        result = client.secrets.kv.v2.read_secret_version(path='passwords')
        if result is not None and 'data' in result:
            password = result['data']['data'].get('devopsschool', None)
            if password:
                return True, password
        return False, "Password not found"
    except Exception as e:
        return False, f"Error reading password: {str(e)}"

# Example usage
if __name__ == "__main__":
    vault_addr = "http://127.0.0.1:8200"
    token = "hvs.BSu6lCAKvGRotgSI3FvsdLje"
    password = "ILOVEBHARAT"

    # Store the password
    success, message = insert(vault_addr, token, password)
    print(message)

    # Retrieve the password
    success, retrieved_password = display(vault_addr, token)
    if success:
        print(f"Retrieved password: {retrieved_password}")
    else:
        print(retrieved_password)
