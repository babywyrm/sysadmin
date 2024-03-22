
##
##

import os,sys,re
import json
import subprocess

def list_resources_with_tags():
    try:
        # Execute the AWS CLI command to list resources with tags for all regions
        command = "aws resourcegroupstaggingapi get-resources --resource-type-filters ec2 s3 rds lambda"
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
    resources_with_tags = list_resources_with_tags()
    if resources_with_tags:
        print(json.dumps(resources_with_tags, indent=4))

if __name__ == "__main__":
    main()

##
##
