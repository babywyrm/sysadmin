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



'''
1. Listing All GPOs
To list all Group Policy Objects with their display names and GUIDs:

powershell

Import-Module GroupPolicy
Get-GPO -All | Format-Table DisplayName, Id
This command imports the GroupPolicy module and then lists every GPO in the domain.

2. Generating a Detailed Report
If you need a detailed report of all GPOs, you can generate an HTML or XML report. For example, to generate an HTML report:

powershell

Import-Module GroupPolicy
Get-GPOReport -All -ReportType HTML -Path "C:\Temp\GPOReport.html"
Then open the report in your web browser.

3. Enumerating Specific GPO Attributes
If you want to list specific attributes (such as file system path, functionality version, etc.), you can do:

powershell

Import-Module GroupPolicy
Get-GPO -All | Select-Object DisplayName, Id, @{Name="FileSysPath";Expression={(Get-GPOReport -Guid $_.Id -ReportType XML | Select-String "<gPCFileSysPath>(.*?)</gPCFileSysPath>" -AllMatches).Matches.Groups[1].Value}}
```
