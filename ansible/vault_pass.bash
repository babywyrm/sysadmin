#!/usr/bin/env bash
##
##
################################
set -e

#
# Written by Thomas Kerpe <toke@toke.de> - Public Domain
#
# Small helper script for usage with ansible-vault and ansible-playbook
# together with [pass](https://www.passwordstore.org/)
#
# Say you have stored the vault-password for the current ansible playbook in pass
# under the name `ansible/demo/vault` then either add a .pass_path file with the content
# `ansible/demo/vault` or add a entry in the ansible.cfg:
# ```
# [pass]
# vault=ansible/demo/vault
# ```
# Now you can call ansible-vault-pass to get the password for the vault. It is especially useful
# like this:
# `ansible-playbook site.yml --vault-password-file ~/bin/ansible-vault-pass`
# or `ansible-vault edit --vault-password-file ~/bin/ansible-vault-pass example.yml`
# Even more practical: `export ANSIBLE_VAULT_PASSWORD_FILE=~/bin/ansible-vault-pass` then it will
# be used by default without specifying it.


if [ -e .pass_path ] ; then
    p=$(cat .pass_path)
elif [ -e ansible.cfg ] ; then
    p=$(git config -f ansible.cfg --get pass.vault)
else
    exit 0
fi

if [ ! -z "$p" ] ; then
    exec pass "$p"
else
    exit 1
fi
