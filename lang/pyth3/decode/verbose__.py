import os,sys,re
import json
import base64
import binascii
import urllib.parse

##
##

def is_base64(s):
    """Check if the string is a valid base64 encoded string."""
    try:
        if isinstance(s, str):
            s += "=" * ((4 - len(s) % 4) % 4)
            base64.b64decode(s, validate=True)
            return True
    except binascii.Error:
        return False
    return False

def is_hex(s):
    """Check if the string is a valid hexadecimal encoded string."""
    try:
        if isinstance(s, str) and len(s) % 2 == 0:
            int(s, 16)
            return True
    except ValueError:
        return False
    return False

def is_url_encoded(s):
    """Check if the string contains URL encoded characters."""
    return '%' in s

def decode_base64(s):
    """Decode a base64 encoded string."""
    try:
        s += "=" * ((4 - len(s) % 4) % 4)
        return base64.b64decode(s).decode('utf-8')
    except Exception as e:
        return f"Error decoding base64: {e}"

def decode_hex(s):
    """Decode a hexadecimal encoded string."""
    try:
        return bytes.fromhex(s).decode('utf-8')
    except Exception as e:
        return f"Error decoding hex: {e}"

def decode_url(s):
    """Decode a URL encoded string."""
    try:
        return urllib.parse.unquote(s)
    except Exception as e:
        return f"Error decoding URL encoding: {e}"

def decode_string(value):
    """Decode a string if it's base64, hex, or URL encoded."""
    if is_base64(value):
        return decode_base64(value)
    elif is_hex(value):
        return decode_hex(value)
    elif is_url_encoded(value):
        return decode_url(value)
    else:
        return None

def process_json(data):
    """Recursively process JSON objects to find and decode encoded strings."""
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, str):
                decoded_value = decode_string(value)
                if decoded_value:
                    print(f"Decoded value for key '{key}': {decoded_value}")
            elif isinstance(value, (dict, list)):
                process_json(value)
    elif isinstance(data, list):
        for item in data:
            process_json(item)

def process_file(filepath):
    """Open and process a JSON file."""
    with open(filepath, 'r', encoding='utf-8') as file:
        try:
            data = json.load(file)
            print(f"Processing file: {filepath}")
            process_json(data)
        except json.JSONDecodeError:
            print(f"Error decoding JSON from file: {filepath}")

def process_directory(directory):
    """Process all JSON files in a directory."""
    for filename in os.listdir(directory):
        if filename.endswith('.json'):
            filepath = os.path.join(directory, filename)
            process_file(filepath)

if __name__ == "__main__":
    import argparse

    # Argument parser for handling command line arguments
    parser = argparse.ArgumentParser(description="Decode encoded strings in JSON files.")
    parser.add_argument('path', type=str, help='Path to the directory or JSON file.')
    
    args = parser.parse_args()
    path = args.path

    if os.path.isdir(path):
        process_directory(path)
    elif os.path.isfile(path) and path.endswith('.json'):
        process_file(path)
    else:
        print("Please provide a valid directory or JSON file path.")

##
##
