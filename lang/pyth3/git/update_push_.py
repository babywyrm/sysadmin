#!/usr/bin/env python3
import os,sys,re
import hashlib
import subprocess

##
##

def compute_file_hash(filepath):
    """Compute the SHA‑256 hash of the given file."""
    try:
        with open(filepath, 'rb') as f:
            file_content = f.read()
        return hashlib.sha256(file_content).hexdigest()
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        sys.exit(1)

def load_previous_hash(hash_filepath):
    """Load the previously saved hash from a file."""
    if not os.path.exists(hash_filepath):
        return None
    with open(hash_filepath, 'r') as f:
        return f.read().strip()

def save_hash(hash_filepath, hash_value):
    """Save the current hash to a file."""
    with open(hash_filepath, 'w') as f:
        f.write(hash_value)

def run_git_command(args):
    """Run a git command and return the result."""
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result

def main():
    # Set the path to your JSON file and a file to store its last known hash.
    json_filepath = "data.json"        # Change as needed.
    hash_storage = ".data_json_hash"     # This file will hold the last known hash.

    # Compute the current hash of the JSON file.
    current_hash = compute_file_hash(json_filepath)
    previous_hash = load_previous_hash(hash_storage)

    if current_hash != previous_hash:
        print(f"Change detected in {json_filepath}.")
        # Save the updated hash.
        save_hash(hash_storage, current_hash)

        # Stage the JSON file.
        result = run_git_command(["git", "add", json_filepath])
        if result.returncode != 0:
            print("Error staging the file:")
            print(result.stderr)
            sys.exit(1)

        # Create a commit with a descriptive message.
        commit_message = f"Auto‑update {json_filepath} (hash: {current_hash})"
        result = run_git_command(["git", "commit", "-m", commit_message])
        if result.returncode != 0:
            print("Error committing the changes:")
            print(result.stderr)
            sys.exit(1)

        # Force‑push the commit to the current branch.
        # Note: This may bypass branch protections if you have the required permissions.
        result = run_git_command(["git", "push", "--force"])
        if result.returncode != 0:
            print("Error pushing the changes:")
            print(result.stderr)
            sys.exit(1)

        print("Changes have been successfully committed and pushed (force‑push).")
    else:
        print(f"No changes detected in {json_filepath}.")

if __name__ == "__main__":
    main()

##
##
