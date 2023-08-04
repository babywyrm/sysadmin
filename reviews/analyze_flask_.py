import os
import subprocess

def run_command(command, cwd=None):
    """Helper function to run a shell command."""
    return subprocess.run(command, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def detect_secrets_scan(repo_path):
    """Run detect-secrets on the given repository directory."""
    print("Running detect-secrets scan...")
    command = f"detect-secrets scan --exclude-files '({repo_path}/.git/*|.*/target/.*|.*/build/.*|.*/out/.*|.*/bin/.*|.*/venv/.*|.*/node_modules/.*|.*/bower_components/.*)'"
    result = run_command(command, repo_path)
    return result.stdout

def trufflehog_scan(repo_path):
    """Run truffleHog on the given repository directory."""
    print("Running truffleHog scan...")
    command = f"trufflehog --entropy=False {repo_path}"
    result = run_command(command)
    return result.stdout

def git_leaks_scan(repo_path):
    """Run git leaks on the given repository directory."""
    print("Running git leaks scan...")
    command = f"git leaks --no-metadata -q {repo_path}"
    result = run_command(command)
    return result.stdout

def find_sensitive_strings(repo_path):
    """Search for sensitive strings in the Python files of the given repository directory."""
    print("Searching for sensitive strings...")
    sensitive_strings = []
    for root, _, files in os.walk(repo_path):
        for filename in files:
            if filename.endswith('.py'):
                file_path = os.path.join(root, filename)
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                    # Look for commonly sensitive strings in Flask applications
                    common_sensitive_strings = [
                        "SECRET_KEY",
                        "PASSWORD",
                        "API_KEY",
                        "AUTH_TOKEN",
                        "DATABASE_URI",
                        "CREDENTIALS",
                        "ACCESS_KEY",
                        "SECRET",
                        "TOKEN",
                        "PRIVATE_KEY",
                        "DB_PASSWORD",
                        "JWT_SECRET",
                    ]
                    for string in common_sensitive_strings:
                        if string in content:
                            sensitive_strings.append(f"Found '{string}' in file: {file_path}")

    return sensitive_strings

def main():
    repo_path = "/path/to/your/python/flask/app/repo"  # Replace this with the actual path to your repo

    # Run scans
    detect_secrets_output = detect_secrets_scan(repo_path)
    trufflehog_output = trufflehog_scan(repo_path)
    git_leaks_output = git_leaks_scan(repo_path)

    # Find sensitive strings
    sensitive_strings = find_sensitive_strings(repo_path)

    # Display the results
    print("\n=== Detect Secrets Scan Results ===\n")
    print(detect_secrets_output)

    print("\n=== TruffleHog Scan Results ===\n")
    print(trufflehog_output)

    print("\n=== Git Leaks Scan Results ===\n")
    print(git_leaks_output)

    print("\n=== Sensitive Strings Found ===\n")
    for sensitive_string in sensitive_strings:
        print(sensitive_string)

if __name__ == "__main__":
    main()

#################
##
##
