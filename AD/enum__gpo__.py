#!/usr/bin/env python3
import os,sys,re
from impacket.ldap.ldapconnection import LDAPConnection

##
##

def main():
    if len(sys.argv) != 2:
        print("Usage: {} <domain/username:password@target>".format(sys.argv[0]))
        sys.exit(1)

    target = sys.argv[1]
    # Connect to LDAP using Impacket's LDAPConnection
    ldapConn = LDAPConnection(target, baseDN='DC=darkcorp,DC=htb', useSSL=True)
    ldapConn.login()
    
    # Define the search base and filter for GPOs
    searchBase = "CN=Policies,CN=System,DC=darkcorp,DC=htb"
    searchFilter = "(objectClass=groupPolicyContainer)"
    attributes = ["displayName", "objectGUID"]
    
    results = ldapConn.search(searchBase, searchFilter, attributes=attributes)
    
    for entry in results:
        print(f"Name: {entry.get('displayName', [''])[0]}, GUID: {entry.get('objectGUID', [''])[0]}")
    
if __name__ == '__main__':
    main()

##
##
