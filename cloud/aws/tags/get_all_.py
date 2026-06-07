##
##

import json
import subprocess
import argparse

def list_resources_with_tags(profile=None):
    try:
        # Construct the AWS CLI command
        command = "aws resourcegroupstaggingapi get-resources --resource-type-filters ec2 s3 rds lambda"
        if profile:
            command += f" --profile {profile}"

        # Execute the AWS CLI command
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        # Check if the command was successful
        if result.returncode == 0:
            # Parse the JSON output
            output_json = json.loads(result.stdout)
            return output_json
        else:
            print("Error:", result.stderr)
            return None
    except Exception as e:
        print("An error occurred:", e)
        return None

# Main function
def main():
    parser = argparse.ArgumentParser(description="List resources with tags")
    parser.add_argument("--profile", help="AWS profile name (optional)")
    args = parser.parse_args()

    profile = args.profile if args.profile else None
    resources_with_tags = list_resources_with_tags(profile)
    if resources_with_tags:
        print(json.dumps(resources_with_tags, indent=4))

if __name__ == "__main__":
    main()

##
##
