import os,sys,re
import ast
from bandit.core import manager as bandit_manager
from bandit.core import config as bandit_config

##
##

def find_files(directory, extensions):
    """
    Recursively find files with given extensions in a directory.
    
    Args:
        directory (str): The root directory to start the search.
        extensions (list): List of file extensions to search for.
        
    Returns:
        list: List of file paths matching the given extensions.
    """
    files = []
    for root, _, filenames in os.walk(directory):
        for filename in filenames:
            if any(filename.endswith(ext) for ext in extensions):
                files.append(os.path.join(root, filename))
    return files

def search_for_secrets(file_content):
    """
    Search for common secret patterns in file content.
    
    Args:
        file_content (str): Content of the file to be searched.
        
    Returns:
        list: List of detected secrets.
    """
    # Define regex patterns for common secrets
    patterns = [
        r'aws_secret_access_key\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'aws_access_key_id\s*=\\s*[\'"]([^\'"]+)[\'"]',
        r'api_key\s*=\\s*[\'"]([^\'"]+)[\'"]',
        r'password\s*=\s*[\'"]([^\'"]+)[\'"]',
    ]
    secrets = []
    for pattern in patterns:
        matches = re.findall(pattern, file_content, re.IGNORECASE)
        if matches:
            secrets.extend(matches)
    return secrets

def analyze_python_code(file_path):
    """
    Analyze Python code for security issues using Bandit.
    
    Args:
        file_path (str): Path to the Python file to be analyzed.
        
    Returns:
        list: List of security issues detected by Bandit.
    """
    # Set up Bandit configuration
    conf = bandit_config.BanditConfig()
    manager = bandit_manager.BanditManager(conf, 'file', True)
    manager.discover_files([file_path])
    manager.run_tests()
    return manager.get_issue_list()

def generate_report(analysis_results):
    """
    Generate a markdown report from analysis results.
    
    Args:
        analysis_results (dict): Dictionary containing analysis results for each file.
        
    Returns:
        str: Markdown formatted report.
    """
    report_lines = ["# Analysis Report", ""]
    
    for file, results in analysis_results.items():
        report_lines.append(f"## File: {file}")
        report_lines.append("")
        
        secrets = results.get("secrets", [])
        if secrets:
            report_lines.append("### Secrets Found:")
            report_lines.extend([f"- {secret}" for secret in secrets])
            report_lines.append("")
        
        flaws = results.get("flaws", [])
        if flaws:
            report_lines.append("### Potential Code Flaws:")
            for flaw in flaws:
                report_lines.append(f"- **{flaw.test_id}**: {flaw.issue_text}")
            report_lines.append("")
        
    return "\n".join(report_lines)

def main(target_directory):
    """
    Main function to orchestrate the file finding, analyzing, and report generation.
    
    Args:
        target_directory (str): Directory to be analyzed.
    """
    analysis_results = {}
    
    # Find Python and Docker files
    extensions = ['.py', 'Dockerfile']
    files = find_files(target_directory, extensions)
    
    for file_path in files:
        with open(file_path, 'r') as file:
            file_content = file.read()
        
        # Analyze file content for secrets and flaws
        results = {"secrets": [], "flaws": []}
        
        if file_path.endswith('.py'):
            # Search for secrets in Python files
            results["secrets"] = search_for_secrets(file_content)
            # Analyze Python code for security issues
            results["flaws"] = analyze_python_code(file_path)
        elif 'Dockerfile' in file_path:
            # Search for secrets in Dockerfiles
            results["secrets"] = search_for_secrets(file_content)
        
        analysis_results[file_path] = results
    
    # Generate and save the report
    report = generate_report(analysis_results)
    with open('analysis_report.md', 'w') as report_file:
        report_file.write(report)
    print("Analysis report generated: analysis_report.md")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 analysis_script.py <target_directory>")
    else:
        target_directory = sys.argv[1]
        main(target_directory)

##
##
