##
##
##  https://gist.github.com/sarojrana/42303a8ffd62d47d18000b494ef34239
##  https://gist.githubusercontent.com/bdclark/23b1a81cb6eff6f36bb2882d8e19935d/raw/5fbc8019085bc307ba549c9585898198e4ce29f5/docker-login-ecr-sso.py
##
##

# Read MFA code from terminal
#
aws_mfa_code=$1

# arn:aws:iam::123456789012:mfa/user
# username=<your_username> e.g. user
# serial_number=<your_serial_number> e.g. 123456789012
# aws_registry_url=<your_aws_registry_url> e.g. https://xxxxxxxxxxxx.dkr.ecr.us-east-1.amazonaws.com

username=<your_username>
serial_number=<your_serial_number>
aws_registry_url=<your_aws_registry_url>

generate_docker_login() {
  echo "==================================Generating AWS Session=================================="
  aws_response=$(aws sts get-session-token --serial-number arn:aws:iam::$serial_number:mfa/$username --token-code $aws_mfa_code)
  
  if [ -n "${aws_response}" ]; then
    echo "Created AWS session.";
  else
    echo "Failed to created AWS session.";
    exit 1;
  fi
 
  access_key_id=$(echo "$aws_response" | jq -r '.Credentials.AccessKeyId')
  secret_access_key=$(echo "$aws_response" | jq -r '.Credentials.SecretAccessKey')
  session_token=$(echo "$aws_response" | jq -r '.Credentials.SessionToken')
  
  echo "\n============================Unsetting AWS Environment Variables==========================="
  unset AWS_ACCESS_KEY_ID
  unset AWS_SESSION_TOKEN
  unset AWS_SECRET_ACCESS_KEY
  echo "Completed unsetting the AWS environment variables."
  
  echo "\n=============================Setting AWS Environment Variables============================"
  export AWS_ACCESS_KEY_ID=$access_key_id
  export AWS_SECRET_ACCESS_KEY=$secret_access_key
  export AWS_SESSION_TOKEN=$session_token
  echo "Completed setting AWS environment variables."
  
  echo "\n==================================Generating Docker Login================================="
  echo "docker login -u AWS -p $(aws ecr get-login-password --region us-east-1) $aws_registry_url"
}

generate_docker_login

##
##

#!/usr/bin/env python

import argparse
import configparser
from shutil import which
import subprocess
import sys
import os

CONFIG_PATH = os.path.expanduser("~/.aws/config")
DOCKER_REGISTRY = "{}.dkr.ecr.{}.amazonaws.com"


def error_out(msg):
    sys.exit("Error: {}".format(msg))


def assert_command_found(cmd):
    if which(cmd) is None:
        error_out("Program '{}' not found in path".format(cmd))


def get_config_option(config, section, option):
    try:
        return config.get(section, option)
    except configparser.NoOptionError:
        error_out("Option {} not found in profile".format(option))


def run_command(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        error_out("command '{}' exited {}: {}".format(cmd[0], r.returncode, r.stderr))
    return r.stdout


# Parse CLI arguments
parser = argparse.ArgumentParser(
    description="Docker login to AWS ECR registry using SSO config profile"
)
parser.add_argument(
    "-p",
    "--profile",
    default=os.getenv("AWS_PROFILE", os.getenv("AWS_DEFAULT_PROFILE")),
    help="AWS profile (default: AWS_PROFILE or AWS_DEFAULT_PROFILE env var)",
)
parser.add_argument(
    "-r",
    "--region",
    default=os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION")),
    help="region (default: AWS_REGION or AWS_DEFAULT_REGION env var, or from profile)",
    required=False,
)
args = vars(parser.parse_args())

profile = args["profile"]
if profile is None:
    error_out(
        "--profile required if AWS_PROFILE or AWS_DEFAULT_PROFILE env var not set"
    )

# Ensure required shell commands present
assert_command_found("aws")
assert_command_found("docker")

# Parse AWS config file
if not os.path.exists(CONFIG_PATH):
    error_out("File {} not found".format(CONFIG_PATH))
config = configparser.ConfigParser()
config.read(CONFIG_PATH)

if config.has_section("profile {}".format(profile)):
    section = "profile {}".format(profile)
elif config.has_section(profile):
    section = profile
else:
    error_out("Unable to locate profile {} in AWS config".format(profile))

aws_account = get_config_option(config, section, "sso_account_id")
region = args["region"]
if region is None:
    region = get_config_option(config, section, "region")
if region is None:
    error_out("Unable to determine region from profile or CLI arg")

# Perform Docker login
password = run_command(["aws", "ecr", "get-login-password", "--region", region])
registry = "{}.dkr.ecr.{}.amazonaws.com".format(aws_account, region)
result = run_command(["docker", "login", "-u", "AWS", "-p", password, registry])
print(result)

##
##
