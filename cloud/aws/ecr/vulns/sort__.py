import os,sys,re
from collections import defaultdict
import pandas as pd

##
##

def aggregate_vulnerability_data(markdown_directory):
    """Aggregates vulnerability data from markdown files and produces a summary table by severity."""
    # Check if the provided directory exists
    if not os.path.isdir(markdown_directory):
        print(f"Error: Directory '{markdown_directory}' does not exist.")
        return

    # Initialize a dictionary to hold severity counts for each image
    vulnerability_summary = defaultdict(lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0})

    # Find all markdown files in the specified directory
    markdown_files = [f for f in os.listdir(markdown_directory) if f.endswith('.md')]

    # Check if any markdown files were found
    if not markdown_files:
        print("No markdown files found in the directory.")
        return

    # Process each markdown file to extract vulnerability data
    for markdown_file in markdown_files:
        # Extract the image name from the markdown file name
        image_name = re.sub(r"^trivy_vulns_|\.md$", "", markdown_file).replace("_", "/").replace(":", "@")

        # Open and read the markdown file
        with open(os.path.join(markdown_directory, markdown_file), 'r') as file:
            for line in file:
                # Parse rows in the markdown table (ignoring headers)
                if line.strip().startswith("|") and not line.strip().startswith("|---"):
                    columns = [col.strip() for col in line.split("|")]
                    if len(columns) > 4:
                        severity = columns[4].upper()  # Assuming severity is in the 5th column
                        if severity in vulnerability_summary[image_name]:
                            vulnerability_summary[image_name][severity] += 1

    # Create a DataFrame for better formatting of the summary
    summary_rows = []
    for image, severities in vulnerability_summary.items():
        total_vulnerabilities = sum(severities.values())
        summary_rows.append({"Image Name": image, "Total": total_vulnerabilities, **severities})

    # Convert the summary rows into a DataFrame
    summary_df = pd.DataFrame(summary_rows)
    summary_df.sort_values(by=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "Total"], ascending=[False] * 6, inplace=True)

    return summary_df

def display_vulnerability_summary(markdown_directory=None):
    """Main function to generate and display the vulnerability summary by severity."""
    # Use the current directory if no directory is specified
    if markdown_directory is None:
        markdown_directory = os.getcwd()

    # Get the vulnerability summary DataFrame
    summary_df = aggregate_vulnerability_data(markdown_directory)

    # Display the summary if it is not None
    if summary_df is not None:
        print("\nVulnerability Summary:\n")
        print(summary_df.to_string(index=False))

if __name__ == "__main__":
    import sys

    # Get the markdown directory from command line arguments or use the current directory
    markdown_directory = sys.argv[1] if len(sys.argv) > 1 else None
    display_vulnerability_summary(markdown_directory)

##
##
