#!/usr/bin/python3
##
##

import re
import time
import json
import tldextract

##
##
##   _work_in_progress__
##
##
####################################
print("here we go")
print("python everyone, python")
print("the best thing that happened to my life, honestly")
print("that might be a complete lie")
print("ask me again sometime")
time.sleep(2)

####################################
f = open('top_100.txt') 
##
##
Top100 = []
Top100 = f.readlines()

f.close

##print(Top100)
####################################
f = open('traffic_log.txt') 
TrafficLog = []
TrafficLog = f.readlines()

print(TrafficLog)

# Ensure you use .readlines()

# Close the file.
f.close()
####################################

BaseLogData = TrafficLog
##print(BaseLogData)

notTop100 = []
dst_IPs = []
domains = []

notInTop100 = ['Hits-'] 

for row in BaseLogData:
    domain = row[row.index("domain:") + 7:]
    if domain not in Top100:
        print('Domain {0} IS-NOT in Top100\n\n'.format(domain))
        notInTop100.append(row)

print(notInTop100)

for x in notInTop100:
    domain_start = row.index("domain:")
    domains.append(row[row.index("domain:") + 7:len(row)-1])
    dst_IP_start = row.index("dst_ip:")
    dst_IPs.append(row[row.index("dst_ip:") + 7:row.index("domain:") - 2])

print(domains)
print(dst_IPs)

######################
#host = re.compile('[^\sw\.@/]([0-9a-zA-Z\-\.]*[0-9a-zA-Z\-]+\.)(de|com|org|net|edu|DE|COM|ORG|NET|EDU')
#ipv4 = re.compile('\b((([0-2]\d[0-5])|(\d{2})|(\d))\.){3}(([0-2]\d[0-5])|(\d{2})|(\d))\b')
#
#    for row in notInTop100:
#    row.index("domain:") = host.findall(notInTop100)


#########################################
# Read artifacts.txt NOT into a list of strings


f = open('artifacts.txt')
artifacts_IOC = []
artifacts_IOC = f.readlines()

#convert-to-string
artifacts_IOC = str(artifacts_IOC)

###print(artifacts_IOC)

# Close the file
f.close()

import re

md5 = re.compile('[a-fA-F0-9]{32}')

################################

artifact_IOC = md5.findall(artifacts_IOC)
print(artifact_IOC)

################################
################################
##for artifact in artifactList:
##    hashAsList = re.findall(r'[a-f0-9]{32}', artifact)
##    if hashAsList:
##        hashStr  = hashAsList[0]
##        hashList.append(hashStr)        
##     print(hashList) 
################################
