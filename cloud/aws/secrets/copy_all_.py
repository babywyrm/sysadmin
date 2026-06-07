#!/usr/bin/env python3

##
## https://gist.github.com/sgtoj/85061e5d3c4bd54ea9949d1ad8aea7e3
##
##

import os
import sys

import boto3
from botocore.exceptions import ClientError

# -------------------------------------------------------------------- main ---


def copy_secrets(config):
    dry_run = config["global.dryrun"]
    if dry_run:
        print(f"dry run enabled")
    src, dst = compile_config(config)
    src_secrets = pull_secrets(src["aws.session"], src["ssm.prefix"])
    dst_secrets = tranform_secrets(src["ssm.prefix"], dst["ssm.prefix"], src_secrets)
    results = push_secrets(dst["aws.session"], dst_secrets, dry_run)
    return results


# --------------------------------------------------------------------- fns ---


def pull_secrets(session, prefix):
    secrets = list_sm_secrets(session, prefix)
    for secret in secrets:
        secret_value = get_sm_secret_value(session, secret["Name"])
        yield secret_value


def push_secret(session, secret, dry_run):
    current_secret = get_sm_secret_value(session, secret["Name"])
    result = {"action": "nochange", "name": secret["Name"]}
    if current_secret is None:
        result["action"] = "created"
        if not dry_run:
            create_sm_secret(session, secret)
    elif current_secret["SecretString"] != secret["SecretString"]:
        result["action"] = "updated"
        if not dry_run:
            put_sm_secret_value(session, secret)
    return result


def push_secrets(session, secrets, dry_run):
    results = []
    for secret in secrets:
        result = push_secret(session, secret, dry_run)
        print(f'{result["action"]:<10}{result["name"]}')
        results.append(result)
    return results


def tranform_secrets(old, new, secrets):
    for secret in secrets:
        new_name = secret["Name"].replace(old, new)
        secret["Name"] = new_name
        yield secret


# --------------------------------------------------------------------- aws ---


def create_sm_secret(session, secret):
    sm = session.client("secretsmanager")
    params = {"Name": secret["Name"]}
    if "SecretString" in secret:
        params["SecretString"] = secret["SecretString"]
    else:
        params["SecretBinary"] = secret["SecretBinary"]
    response = sm.create_secret(**params)
    return response


def get_sm_secret_value(session, name):
    sm = session.client("secretsmanager")
    secret = None
    try:
        secret = sm.get_secret_value(SecretId=name)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            pass  # ignore if secret is missing
        else:
            raise err
    return secret or None


def list_sm_secrets(session, filter_prefix):
    sm = session.client("secretsmanager")
    pages = sm.get_paginator("list_secrets").paginate()
    for page in pages:
        secrets = page["SecretList"]
        for secret in secrets:
            if not secret["Name"].startswith(filter_prefix):
                continue
            yield secret


def put_sm_secret_value(session, secret):
    sm = session.client("secretsmanager")
    params = {"SecretId": secret["Name"]}
    if "SecretString" in secret:
        params["SecretString"] = secret["SecretString"]
    else:
        params["SecretBinary"] = secret["SecretBinary"]
    response = sm.put_secret_value(**params)
    return response


# ------------------------------------------------------------------ config ---


def compile_config(config):
    src = config["src"]
    dst = config["dst"]
    if src.get("ssm.prefix") is None or dst.get("ssm.prefix") is None:
        raise Exception("Must define source and destination namespace!")
    src["aws.session"] = boto3.Session(
        region_name=src["aws.region"], profile_name=src["aws.profile"]
    )
    dst["aws.session"] = boto3.Session(
        region_name=dst["aws.region"], profile_name=dst["aws.profile"]
    )
    return src, dst


def get_default_config():
    config = {
        "global.dryrun": int(os.environ.get("DRY_RUN", "1")) == 1,
        "src": {
            "aws.region": os.environ.get("SRC_AWS_REGION", "us-east-1"),
            "aws.profile": os.environ.get("SRC_AWS_PROFILE"),
            "ssm.prefix": os.environ.get("SRC_SSM_NAMESPACE"),
        },
        "dst": {
            "aws.region": os.environ.get("DST_AWS_REGION", "us-east-1"),
            "aws.profile": os.environ.get("DST_AWS_PROFILE"),
            "ssm.prefix": os.environ.get("DST_SSM_NAMESPACE"),
        },
    }
    return config


# ---------------------------------------------------------------- handlers ---


def script_handler(args):
    config = get_default_config()
    # same account copy:  script.py <src_prefix> <dst_prefix> [nodryrun]
    if len(args) in [3, 4]:
        config["src"]["ssm.prefix"] = args[1]
        config["dst"]["ssm.prefix"] = args[2]
    # cross-account copy:  script.py <src_profile> <src_prefix> <dst_profile> <dst_prefix> [nodryrun]
    elif len(args) in [5, 6]:
        config["src"]["aws.profile"] = args[1]
        config["src"]["ssm.prefix"] = args[2]
        config["dst"]["aws.profile"] = args[3]
        config["dst"]["ssm.prefix"] = args[4]
    # pass 'nodryrun' as last arg to disable dry run (or use env; see top)
    if sys.argv.pop() == "nodryrun":
        config["global.dryrun"] = False
    copy_secrets(config)


def lambda_handler(event, context):
    raise Exception("Not implemented yet!")


if __name__ == "__main__":
    script_handler(sys.argv)
    
    
    ##
    ##
    ##
    
@sgtoj
Author
sgtoj commented on Dec 8, 2019 • 
Description
Very simple script to copy Secret Manager secrets. It can be used to sync secrets within the same account or between two different accounts. The script assumes the secrets are namespaced (aka has static prefix). However, if your secrets are not namespaced, just pass an empty string -- "" -- as the respective parameters.

Usage: Script w/o Environment Variables
script runs in dry-run mode by default; add nodryrun as last parameter to disable dry-run mode

# copy list of secrets from source namespace to destination namespace in the same account
python copy_sm_secrets.py <src_prefix> <dst_prefix> [nodryrun]

# copy list of secrets from source namespace from one account to destination namespace to another account
python copy_sm_secrets.py <src_profile> <src_prefix> <dst_profile> <dst_prefix> [nodryrun]
Example Usage
copying my-app's secrets in dev's namespace to its qa's namespace within the same aws account

python3 copy_sm_secrets.py "/my-app/dev-secrets/" "/my-app/qa-secrets/" 
Prerequisites
aws sdk/cli profile setup
aws official python sdk boto3
python 3.x
