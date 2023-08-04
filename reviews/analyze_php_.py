import os
import subprocess

def run_command(command, cwd=None):
    """Helper function to run a shell command."""
    return subprocess.run(command, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def detect_secrets_scan(repo_path):
    # ... (unchanged) ...

def trufflehog_scan(repo_path):
    # ... (unchanged) ...

def git_leaks_scan(repo_path):
    # ... (unchanged) ...

def find_sensitive_strings(repo_path):
    # ... (unchanged) ...

def check_vulnerable_php_libraries(repo_path):
    """Check for vulnerable PHP libraries using composer."""
    print("Checking for vulnerable PHP libraries...")
    command = f"composer validate --no-check-all --no-check-publish {repo_path}"
    result = run_command(command)
    return result.stdout

def main():
    repo_path = "/path/to/your/php/webapp/repo"  # Replace this with the actual path to your repo

    # Run scans
    detect_secrets_output = detect_secrets_scan(repo_path)
    trufflehog_output = trufflehog_scan(repo_path)
    git_leaks_output = git_leaks_scan(repo_path)

    # Find sensitive strings
    sensitive_strings = find_sensitive_strings(repo_path)

    # Check for vulnerable PHP libraries
    vulnerable_libraries_output = check_vulnerable_php_libraries(repo_path)

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

    print("\n=== Vulnerable PHP Libraries ===\n")
    print(vulnerable_libraries_output)

if __name__ == "__main__":
    main()



#####################
###
###
