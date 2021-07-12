#!/usr/bin/env python2
"""
ansible_vault_pass
A small helper script for usage with ansible-vault and ansible-playbook
together with pass.
Written by Thomas Kerpe <toke@toke.de> - Public Domain
Say you have stored the vault-password for the current ansible playbook in pass
under the name ansible/demo/vault then either add a .pass_path file with the content
ansible/demo/vault or add a entry in the ansible.cfg:
    [pass]
    vault=ansible/demo/vault
Now you can call ansible-vault-pass to get the password for the vault.
It is especially useful like this:
    ansible-playbook site.yml --vault-password-file ~/bin/ansible-vault-pass
or
    ansible-vault edit --vault-password-file ~/bin/ansible-vault-pass example.yml
Even more practical: 
    export ANSIBLE_VAULT_PASSWORD_FILE=~/bin/ansible-vault-pass
then it will be used by default without specifying it. It is also useful in CI environments.
Source: https://gist.github.com/toke/ebc49b7dd08d7b87e23921029176d3f5
"""

import os.path
import subprocess
import ansible.constants
from ConfigParser import NoOptionError, NoSectionError


def get_vault_password():
    """
    The magic happenz
    """

    pass_name = ""

    if os.path.isfile(".pass_path"):
        with open(".pass_path") as f:
            pass_name = f.read()
    elif ansible.constants.CONFIG_FILE:
        try:
            pass_name = ansible.constants.p.get("pass", "vault")
        except NoOptionError:
            pass
        except NoSectionError:
            pass
    else:
        pass

    if pass_name:
        c = subprocess.call(["pass", pass_name])
        exit(c)

if __name__ == '__main__':
    get_vault_password()
    
##
##
################
##
