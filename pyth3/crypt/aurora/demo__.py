import boto3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import pymysql

# --- AWS KMS Configuration ---
REGION = 'us-east-1'  # Replace with your AWS region
kms_client = boto3.client('kms', region_name=REGION)

# --- Database Configuration ---
DB_HOST = 'your-aurora-endpoint.rds.amazonaws.com' 
DB_USER = 'your_user'
DB_PASSWORD = 'your_password'
DB_NAME = 'your_database'

# --- SaaS Configuration ---
CUSTOMER_KEYS_TABLE = "customer_unique_keys" 
DATA_TABLE = "sensitive_data"  # Table for encrypted customer data


# --- Helper Functions ---

def create_customer_key(customer_id):
    """
    Create a Customer Master Key (CMK) in AWS KMS for a specific customer/organization.
    :param customer_id: Unique identifier for the customer.
    :return: Key ARN for the customer's encryption key.
    """
    alias_name = f"alias/{customer_id}-encryption-key"
    try:
        # Create a new CMK and associate an alias with it
        response = kms_client.create_key(Description=f"CMK for customer {customer_id}")
        key_id = response['KeyMetadata']['KeyId']
        kms_client.create_alias(AliasName=alias_name, TargetKeyId=key_id)
        print(f"Created key for customer {customer_id}: {alias_name}")
        return key_id
    except Exception as e:
        raise RuntimeError(f"Error creating key for customer {customer_id}: {e}")


def generate_data_key(customer_key_id):
    """
    Generate a Data Encryption Key (DEK) using the customer's CMK.
    :param customer_key_id: Key ARN or alias for the customer's encryption key.
    :return: Encrypted and plaintext data encryption key.
    """
    response = kms_client.generate_data_key(KeyId=customer_key_id, KeySpec='AES_256')
    encrypted_key = response['CiphertextBlob']  # Encrypted key to store
    plaintext_key = response['Plaintext']  # Plaintext key for encryption/decryption
    return encrypted_key, plaintext_key


def encrypt_data(plaintext, key):
    """
    Encrypt data using AES encryption.
    :param plaintext: Data to encrypt.
    :param key: Plaintext encryption key.
    :return: Base64-encoded ciphertext.
    """
    backend = default_backend()
    iv = b'\x00' * 16  # Fixed IV for simplicity; use unique IVs in production
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(encrypted_data).decode()


def decrypt_data(encrypted_data, key):
    """
    Decrypt data using AES encryption.
    :param encrypted_data: Base64-encoded ciphertext.
    :param key: Plaintext decryption key.
    :return: Decrypted plaintext.
    """
    backend = default_backend()
    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(base64.b64decode(encrypted_data)) + decryptor.finalize()
    return decrypted_data.decode()


# --- Database Operations ---

def store_encrypted_data(customer_id, name, sensitive_info):
    """
    Store encrypted data for a customer in the database.
    :param customer_id: Customer's unique identifier.
    :param name: Name of the record owner.
    :param sensitive_info: Sensitive data to encrypt and store.
    """
    # Fetch or create customer-specific encryption key
    customer_key_arn = get_or_create_customer_key(customer_id)
    encrypted_key, plaintext_key = generate_data_key(customer_key_arn)

    # Encrypt the sensitive data
    encrypted_info = encrypt_data(sensitive_info, plaintext_key)

    # Store encrypted data in the database
    connection = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
    cursor = connection.cursor()
    query = f"""
    INSERT INTO {DATA_TABLE} (customer_id, name, sensitive_info, encrypted_key)
    VALUES (%s, %s, %s, %s)
    """
    cursor.execute(query, (customer_id, name, encrypted_info, encrypted_key))
    connection.commit()
    connection.close()
    print(f"Encrypted data stored for customer {customer_id}")


def retrieve_decrypted_data(customer_id, record_id):
    """
    Retrieve and decrypt a customer's sensitive data from the database.
    :param customer_id: Customer's unique identifier.
    :param record_id: Record ID to retrieve.
    :return: Decrypted sensitive data.
    """
    connection = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
    cursor = connection.cursor()
    query = f"SELECT sensitive_info, encrypted_key FROM {DATA_TABLE} WHERE id = %s AND customer_id = %s"
    cursor.execute(query, (record_id, customer_id))
    result = cursor.fetchone()
    connection.close()

    if not result:
        raise ValueError("No record found for the given customer and record ID.")

    encrypted_info, encrypted_key = result

    # Decrypt the DEK using KMS
    plaintext_key = kms_client.decrypt(CiphertextBlob=encrypted_key)['Plaintext']

    # Decrypt the sensitive data
    decrypted_info = decrypt_data(encrypted_info, plaintext_key)
    return decrypted_info


def get_or_create_customer_key(customer_id):
    """
    Retrieve or create a customer-specific encryption key (CMK).
    :param customer_id: Customer's unique identifier.
    :return: Key ARN for the customer's encryption key.
    """
    # Check if the key exists in the database
    connection = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
    cursor = connection.cursor()
    query = f"SELECT key_arn FROM {CUSTOMER_KEYS_TABLE} WHERE customer_id = %s"
    cursor.execute(query, (customer_id,))
    result = cursor.fetchone()

    if result:
        connection.close()
        return result[0]  # Return existing key ARN

    # If not found, create a new key
    key_arn = create_customer_key(customer_id)

    # Store the new key in the database
    query = f"INSERT INTO {CUSTOMER_KEYS_TABLE} (customer_id, key_arn) VALUES (%s, %s)"
    cursor.execute(query, (customer_id, key_arn))
    connection.commit()
    connection.close()
    return key_arn


# --- Example Usage ---
if __name__ == "__main__":
    # Store sensitive data for customer "org-123"
    store_encrypted_data("org-123", "John Doe", "4111-1111-1111-1111")

    # Retrieve and decrypt sensitive data for customer "org-123"
    decrypted_info = retrieve_decrypted_data("org-123", 1)  # Assuming record ID 1
    print(f"Decrypted Info: {decrypted_info}")

##
##
