#!/usr/bin/python3

##
##   _please_tweak_me_for_appropriate_targets__
##   _and_comparative_needful_analytics__
##   _thx__
##
#########################################

import re
import time
import json
import tldextract

print("here we go")

time.sleep(1)
#########################################
f = open('top_100s.txt')
Top100 = []
Top100 = f.readlines()

f.close
f = open('traffic_logs.txt')

TrafficLogs = []
TrafficLogs = f.readlines()

print(TrafficLogs)

# Close the file.
f.close()
#########################################

# Obvi.
# We need to iterate over the traffic_logs.
# Example LOG: host:EVOLVE\\Win10-0ezj277j src_ip:10.0.0.216 src_port:14582 dst_port:80 dst_ip:157.240.19.35 domain:facebook.com\n
#########################################
time.sleep(2)
print("######################################")

domains  = []
badhosts = []
badIPs   = []


for i in TrafficLogs: 

# Within the for-loop, we need to assign the domain field to a variable.

   domain = i.split(' ')[5].split(':')[1] # Method chains & String formatting & slicing operations

# We will then use an if statement to see if the new domain variable is in the top100
   
   if domain not in Top100: # top is the list of top domains we read from top100.txt previously

       #check if your domain is not in the trusted yourTop100List: i.e var not in var
       #append record "i" to analyze list you just made
      
       badhosts.append(i)

# You should now have a list with only records in which the domain was not in the well-known top100
# Print your list you appended the records to:

print(badhosts)
print("######################################")
##   for x in badhosts:
##   badIPs = x.split(' ')[4].split(':')[1]   

for row in badhosts:
    domains_start = row.index("domain:")
    domains.append(row[row.index("domain:") + 7:len(row)-1])
    badIPs_start = row.index("dst_ip:")
    badIPs.append(row[row.index("dst_ip:") + 7:row.index("domain:") - 2])

print(badIPs)
print("######################################")
print(domains)
print("######################################")

time.sleep(1)
######################################################
######################################################

# Read artifacts.txt NOT into a list of strings

f = open('artifacts.txt')
artifacts_IOC = []
artifacts_IOC = f.readlines()

#convert-to-string
artifacts_IOC = str(artifacts_IOC)

###print(artifacts_IOC)

# Close the file
f.close()

md5 = re.compile('[a-fA-F0-9]{32}')

################################

artifact_IOC = md5.findall(artifacts_IOC)
print(artifact_IOC)

################################
time.sleep(1)
print("######################################")
print("...............")
print("That's the stuff.  Honestly.")

