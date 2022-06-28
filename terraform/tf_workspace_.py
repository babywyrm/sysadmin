#!/usr/bin/env python3

############
## https://gist.github.com/DevBOFH/7bd65dbcb945cdfce42d21b1b6bc0e1b
############
##
##

description = 'Terraform workspace tool. This tool can be used to perform CRUD operations on Terraform Cloud via their public API.'
version = "0.0.1"

import os
import re
import sys
import requests
import argparse
import json

ORGANIZATION = "TF_CLOUD_ORG_NAME"
HEADERS = {"Content-Type": "application/vnd.api+json"}

def load_api_credentials(rc_path="~/.terraformrc"):
    with open(os.path.expanduser(rc_path)) as f:
        m = re.search(r'token = "([^"]+)"', f.read())

    if not m:
        raise RuntimeError(f"Unable to load credentials from {rc_path}")
    else:
        HEADERS["Authorization"] = f"Bearer {m.group(1)}"

def new_workspace(workspace_name):
    PAYLOAD = {'data': {'attributes': {'name': workspace_name}, 'type': 'workspaces'}}
    req = requests.post(
        f"https://app.terraform.io/api/v2/organizations/{ORGANIZATION}/workspaces",
        json=PAYLOAD,
        headers=HEADERS,
    )

    try:
        req.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print (str(err))
        sys.exit(2)

def show_workspace(workspace_name):
    req = requests.get(
        f"https://app.terraform.io/api/v2/organizations/{ORGANIZATION}/workspaces/{workspace_name}",
        headers=HEADERS,
    )

    try:
        req.raise_for_status()
    except requests.exceptions.HTTPError as err:
        sys.exit(0)

    pretty_json = json.loads(req.text)
    print (json.dumps(pretty_json, indent=2))

def configure_workspace_by_name(workspace_name):
    PAYLOAD = {"data": {"type": "workspaces", "attributes": {"operations": False}}}
    req = requests.patch(
        f"https://app.terraform.io/api/v2/organizations/{ORGANIZATION}/workspaces/{workspace_name}",
        json=PAYLOAD,
        headers=HEADERS,
    )

    try:
        req.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print (str(err))
        sys.exit(2)

def configure_workspace_by_id(workspace_id):
    PAYLOAD = {"data": {"type": "workspaces", "attributes": {"operations": False}}}
    req = requests.patch(
        f"https://app.terraform.io/api/v2/workspaces/{workspace_id}",
        json=PAYLOAD,
        headers=HEADERS,
    )

    try:
        req.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print (str(err))
        sys.exit(2)

def configure_all_workspaces():
    next_page = "https://app.terraform.io/api/v2/organizations/" + ORGANIZATION + "/workspaces"

    while next_page:
        page = requests.get(next_page, headers=HEADERS).json()

        for i in page["data"]:
            ws_id = i["id"]
            ws_name = i["attributes"]["name"]
            print(f"Updating {ws_name}")
            try:
                configure_workspace_by_id(i["id"])
            except requests.exceptions.HTTPError as exc:
                print(f"Error updating {ws_id} {ws_name}: {exc}", file=sys.stderr)

        next_page = page["links"].get("next")

def delete_workspace(workspace_name):
    PAYLOAD = {'data': {'attributes': {'name': workspace_name}, 'type': 'workspaces'}}
    req = requests.delete(
        f"https://app.terraform.io/api/v2/organizations/{ORGANIZATION}/workspaces/{workspace_name}",
        headers=HEADERS,
    )

    try:
        req.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print (str(err))
        sys.exit(2)



if __name__ == "__main__":

    # init argparse
    parser = argparse.ArgumentParser(description = description)
    parser.add_argument("-V", "--version", help="show version", action="store_true")
    parser.add_argument("-n", "--new", help="create a new workspace")
    parser.add_argument("-c", "--configure", help="configure a workspace to use local execution mode")
    parser.add_argument("-ca", "--configureall", help="configure all workspaces to use local execution mode", action="store_true")
    parser.add_argument("-d", "--delete", help="delete a workspace")
    parser.add_argument("-s", "--show", help="show details of a workspace")


    # read arguments from the command line
    args = parser.parse_args()

    # load terraform cloud api token
    load_api_credentials()

    # check for --version or -V
    if args.version:
        print("Terraform Workspace Tool " + version )

    # check for --new or -n
    if args.new:
        try:
            new_workspace(args.new)
        except AssertionError as err:
            print (str(err))
            sys.exit(2)

    # check for --show or -s
    if args.show:
        try:
            show_workspace(args.show)
        except AssertionError as err:
            print (str(err))
            sys.exit(2)

    # check for --configure or -c
    if args.configure:
        try:
            configure_workspace_by_name(args.configure)
        except AssertionError as err:
            print (str(err))
            sys.exit(2)

    # check for --configureall or -ca
    if args.configureall:
        try:
            configure_all_workspaces()
        except AssertionError as err:
            print (str(err))
            sys.exit(2)

    # check for --delete or -d
    if args.delete:
        try:
            delete_workspace(args.delete)
        except AssertionError as err:
            print (str(err))
            sys.exit(2)

####################################
##
##
